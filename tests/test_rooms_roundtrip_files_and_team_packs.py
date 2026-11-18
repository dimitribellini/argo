"""End-to-end tests for P0-3..P1-7: Multi-Bot Rooms, Round-Trip Coordinator Plans, Split Living Board, Per-User 10 MB Workspace Files & Unread Cursors, Quote Replies/Reactions, and Credential-Free Team Packs."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.db.repositories import MAX_WORKSPACE_FILE_BYTES  # noqa: E402
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class TestRoomsRoundTripFilesAndTeamPacks(unittest.TestCase):
    """Verify Rooms, round-trip plans, open_page, multi-user file isolation (10 MB), unread cursors, and Team Packs."""

    @staticmethod
    def _sso_headers(email: str = "alice@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 32.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 12.0,
                "disk_percent": 20.0,
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            workspace_files_root=str(Path(tmp) / "workspace_files"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
        )

    def test_multi_bot_room_routing_and_handoff_gate(self) -> None:
        turns_seen: list[tuple[str, str]] = []

        async def room_llm(req: LLMRequest) -> dict[str, Any]:
            turns_seen.append((req.system_prompt.splitlines()[0], req.user_prompt))
            if "Lead Coordinator" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "@content-specialist please draft the outline for this launch.",
                            "actions": [],
                        }
                    ),
                    "input_tokens": 12,
                    "output_tokens": 14,
                }
            if "Content Specialist" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Here is the launch outline covering timeline, risks, and rollout.",
                            "actions": [],
                        }
                    ),
                    "input_tokens": 12,
                    "output_tokens": 16,
                }
            return {
                "text": json.dumps({"summary": "Outsider should not run.", "actions": []}),
                "input_tokens": 5,
                "output_tokens": 5,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=room_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "lead-coord",
                        "name": "Lead Coord",
                        "role": "Coordinator",
                        "role_prompt": "Lead Coordinator",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "content-specialist",
                        "name": "Content Specialist",
                        "role": "Writer",
                        "role_prompt": "Content Specialist",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "outsider-bot",
                        "name": "Outsider Bot",
                        "role": "External",
                        "role_prompt": "Outsider",
                    },
                )

                # Reject < 2 member bots
                bad_room = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={"title": "Too Small", "member_bot_slugs": ["lead-coord"]},
                )
                self.assertIn(bad_room.status_code, (400, 422))

                # Room 1: Auto-handoff on @mention (default Grok behaviour)
                rm_auto = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Content x Coordinator",
                        "member_bot_slugs": ["lead-coord", "content-specialist"],
                        "coordinator_bot_slug": "lead-coord",
                        "ask_before_bot_handoff": False,
                    },
                )
                self.assertEqual(rm_auto.status_code, 201, rm_auto.text)
                auto_slug = rm_auto.json()["slug"]

                turn1 = client.post(
                    f"/api/rooms/{auto_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Plan next week's product launch."},
                )
                self.assertEqual(turn1.status_code, 200, turn1.text)
                msgs = turn1.json()["messages"]
                senders = [m["sender_slug"] for m in msgs if not (m.get("metadata") or {}).get("room_welcome")]
                self.assertEqual(senders, ["user", "lead-coord", "content-specialist"])
                self.assertFalse(any("Outsider" in s for s, _ in turns_seen))

                # Quote-reply targets quoted bot specifically without running coordinator first
                spec_msg_id = msgs[-1]["id"]
                turns_seen.clear()
                turn_quote = client.post(
                    f"/api/rooms/{auto_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Shorten bullet 2.", "reply_to_id": spec_msg_id},
                )
                self.assertEqual(turn_quote.status_code, 200, turn_quote.text)
                latest_bot_msg = turn_quote.json()["messages"][-1]
                self.assertEqual(latest_bot_msg["sender_slug"], "content-specialist")
                self.assertEqual(latest_bot_msg["metadata"]["reply_to"]["id"], spec_msg_id)

                # Room 2: ask_before_bot_handoff = True gates handoff until approved
                rm_gated = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Gated Review Room",
                        "member_bot_slugs": ["lead-coord", "content-specialist"],
                        "coordinator_bot_slug": "lead-coord",
                        "ask_before_bot_handoff": True,
                    },
                )
                self.assertEqual(rm_gated.status_code, 201)
                gated_slug = rm_gated.json()["slug"]

                gated_res = client.post(
                    f"/api/rooms/{gated_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Prepare launch notes"},
                )
                self.assertEqual(gated_res.status_code, 200)
                g_msgs = [
                    m for m in gated_res.json()["messages"] if not (m.get("metadata") or {}).get("room_welcome")
                ]
                self.assertEqual([m["sender_slug"] for m in g_msgs], ["user", "lead-coord"])
                handoff = g_msgs[-1]["metadata"].get("pending_room_handoff")
                self.assertIsNotNone(handoff)
                self.assertEqual(handoff["target_bot_slug"], "content-specialist")

                # Operator clicks [Let @Content Specialist reply]
                resumed = client.post(
                    f"/api/rooms/{gated_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "", "approved_handoff_bot_slug": "content-specialist"},
                )
                self.assertEqual(resumed.status_code, 200, resumed.text)
                self.assertEqual(resumed.json()["messages"][-1]["sender_slug"], "content-specialist")

    def test_roundtrip_delegation_plan_and_await_result(self) -> None:
        async def delegation_llm(req: LLMRequest) -> dict[str, Any]:
            if "Coordinator System Prompt" in req.system_prompt:
                if "Final synthesis turn" in req.system_prompt:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Combined Executive Rollup: Research + Editorial complete.",
                                "actions": [],
                            }
                        ),
                        "input_tokens": 20,
                        "output_tokens": 20,
                    }
                if "roundtrip" in req.user_prompt.lower() and "tool_observations" not in req.user_prompt:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Checking with Research Bot...",
                                "actions": [
                                    {
                                        "type": "delegate_to_bot",
                                        "target_bot": "research-spec",
                                        "instruction": "Gather key metrics.",
                                        "await_result": True,
                                    }
                                ],
                            }
                        ),
                        "input_tokens": 12,
                        "output_tokens": 15,
                    }
                if "tool_observations" in req.user_prompt:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Integrated research metrics from round-trip response.",
                                "actions": [],
                            }
                        ),
                        "input_tokens": 15,
                        "output_tokens": 15,
                    }
                return {
                    "text": json.dumps(
                        {
                            "summary": "Here is the multi-bot plan for your approval.",
                            "actions": [
                                {
                                    "type": "propose_delegation_plan",
                                    "goal": "Prepare weekly brief",
                                    "steps": [
                                        {
                                            "bot_slug": "research-spec",
                                            "task": "Collect top updates",
                                            "parallel_group": 1,
                                        },
                                        {
                                            "bot_slug": "editorial-spec",
                                            "task": "Format bullet brief",
                                            "parallel_group": 1,
                                        },
                                    ],
                                }
                            ],
                        }
                    ),
                    "input_tokens": 18,
                    "output_tokens": 22,
                }
            if "Research System Prompt" in req.system_prompt:
                return {
                    "text": json.dumps({"summary": "Collected 3 updates (99.9% uptime).", "actions": []}),
                    "input_tokens": 10,
                    "output_tokens": 12,
                }
            return {
                "text": json.dumps({"summary": "Formatted executive bullet brief.", "actions": []}),
                "input_tokens": 10,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=delegation_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "main-coord",
                        "name": "Main Coord",
                        "role": "Coordinator",
                        "role_prompt": "Coordinator System Prompt",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "research-spec",
                        "name": "Research Spec",
                        "role": "Research",
                        "role_prompt": "Research System Prompt",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "editorial-spec",
                        "name": "Editorial Spec",
                        "role": "Editorial",
                        "role_prompt": "Editorial System Prompt",
                    },
                )

                rm = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Briefing Crew",
                        "member_bot_slugs": ["main-coord", "research-spec", "editorial-spec"],
                        "coordinator_bot_slug": "main-coord",
                    },
                ).json()

                # Step 1: Coordinator proposes delegation plan
                r_plan = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Prepare our weekly brief."},
                )
                self.assertEqual(r_plan.status_code, 200, r_plan.text)
                plan_msg = r_plan.json()["messages"][-1]
                plan = plan_msg["metadata"].get("delegation_plan")
                self.assertIsNotNone(plan)
                self.assertEqual(plan["status"], "proposed")
                self.assertEqual(len(plan["steps"]), 2)

                # Step 2: Execute plan -> both specialists run & Coordinator posts 1 unified synthesis
                r_exec = client.post(
                    f"/api/rooms/{rm['slug']}/plans/{plan['id']}/execute",
                    headers=self._sso_headers(),
                    json={},
                )
                self.assertEqual(r_exec.status_code, 200, r_exec.text)
                exec_body = r_exec.json()
                self.assertEqual(exec_body["plan"]["status"], "completed")
                self.assertIn("Combined Executive Rollup", exec_body["synthesis"])

                # Step 3: Verify await_result=True 1:1 round-trip gathering
                rt = client.post(
                    "/api/bots/main-coord/messages",
                    headers=self._sso_headers(),
                    json={"text": "Run a roundtrip check with Research Spec."},
                )
                self.assertEqual(rt.status_code, 200, rt.text)
                self.assertIn("Integrated research metrics", rt.json()["messages"][-1]["text"])

    def test_conversational_open_board_and_bot_hub_board(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "operations-coordinator",
                        "name": "Operations Coordinator",
                        "role": "Manage operations and dashboards",
                    },
                )
                res = client.post(
                    "/api/bots/operations-coordinator/messages",
                    headers=self._sso_headers(),
                    json={"text": "can you open the html board?"},
                )
                self.assertEqual(res.status_code, 200, res.text)
                actions = res.json()["result"]["actions"]
                open_acts = [a for a in actions if a.get("type") == "open_page"]
                self.assertEqual(len(open_acts), 1)
                self.assertEqual(open_acts[0]["status"], "ok")
                page_slug = open_acts[0]["slug"]

                pages = client.get("/api/pages", headers=self._sso_headers()).json()
                hub_page = next((p for p in pages if p["slug"] == page_slug), None)
                self.assertIsNotNone(hub_page)
                self.assertEqual(hub_page["render_mode"], "sandboxed_html")
                self.assertIn("ARGO_LIVE_STATUS", hub_page["content_payload"])
                self.assertIn("ARGO_OPEN_ROOM", hub_page["content_payload"])
                self.assertNotIn("allow-same-origin", hub_page["content_payload"].lower())

    def test_strict_multi_user_workspace_files_10mb_cap_and_unread_cursors(self) -> None:
        alice_hdrs = self._sso_headers("alice@example.com")
        bob_hdrs = self._sso_headers("bob@example.com")

        async def file_echo_llm(req: LLMRequest) -> dict[str, Any]:
            if "file-writer" in req.system_prompt:
                return {
                    "text": json.dumps({"summary": "File reviewed.", "actions": []}),
                    "input_tokens": 10,
                    "output_tokens": 8,
                }
            return {
                "text": json.dumps({"summary": "Unread bot reply!", "actions": []}),
                "input_tokens": 10,
                "output_tokens": 8,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=file_echo_llm)
            with TestClient(app) as client:
                # 1. Raw binary upload for Alice
                up_alice = client.post(
                    "/api/files",
                    headers={
                        **alice_hdrs,
                        "Content-Type": "text/plain",
                        "X-File-Name": "alice-notes.txt",
                    },
                    content=b"Alice private project brief\nLine 2",
                )
                self.assertEqual(up_alice.status_code, 201, up_alice.text)
                alice_file = up_alice.json()
                self.assertEqual(alice_file["owner_email"], "alice@example.com")

                # 2. Bob sees ZERO files and gets 404 on Alice's file content/delete/attach
                self.assertEqual(client.get("/api/files", headers=bob_hdrs).json(), [])
                self.assertEqual(
                    client.get(f"/api/files/{alice_file['id']}/content", headers=bob_hdrs).status_code,
                    404,
                )
                self.assertEqual(
                    client.delete(f"/api/files/{alice_file['id']}", headers=bob_hdrs).status_code,
                    404,
                )
                attach_denied = client.post(
                    "/api/bots/operations-coordinator/messages",
                    headers=bob_hdrs,
                    json={"text": "Read this", "attachment_ids": [alice_file["id"]]},
                )
                self.assertEqual(attach_denied.status_code, 404)

                # 3. Bob uploads his own file -> verify isolated on-disk directory
                up_bob = client.post(
                    "/api/files",
                    headers=bob_hdrs,
                    json={
                        "filename": "bob-spec.md",
                        "mime_type": "text/markdown",
                        "text": "# Bob Spec",
                    },
                )
                self.assertEqual(up_bob.status_code, 201, up_bob.text)
                self.assertEqual(len(client.get("/api/files", headers=alice_hdrs).json()), 1)
                self.assertEqual(len(client.get("/api/files", headers=bob_hdrs).json()), 1)

                alice_dir = app.state.repo._user_files_dir("alice@example.com")[2]
                bob_dir = app.state.repo._user_files_dir("bob@example.com")[2]
                self.assertNotEqual(alice_dir, bob_dir)
                self.assertEqual(len(list(alice_dir.iterdir())), 1)
                self.assertEqual(len(list(bob_dir.iterdir())), 1)

                # 4. Enforce strict 10 MB per-file cap (HTTP 413)
                oversized = b"a" * (MAX_WORKSPACE_FILE_BYTES + 1)
                too_big = client.post(
                    "/api/files",
                    headers={
                        **alice_hdrs,
                        "Content-Type": "application/octet-stream",
                        "X-File-Name": "huge.bin",
                    },
                    content=oversized,
                )
                self.assertEqual(too_big.status_code, 413, too_big.text)

                # 5. Per-user unread cursors: trigger creates unread reply for Alice AND Bob
                client.post(
                    "/api/bots",
                    headers=alice_hdrs,
                    json={"slug": "cursor-bot", "name": "Cursor Bot", "role": "Notify"},
                )
                client.post("/api/bots/cursor-bot/trigger", headers=alice_hdrs, json={})

                status_alice_before = client.get("/api/workspace/live-status", headers=alice_hdrs).json()
                status_bob_before = client.get("/api/workspace/live-status", headers=bob_hdrs).json()
                alice_station_b = next(b for b in status_alice_before["bots"] if b["slug"] == "cursor-bot")
                bob_station_b = next(b for b in status_bob_before["bots"] if b["slug"] == "cursor-bot")
                self.assertTrue(alice_station_b["unread"])
                self.assertTrue(bob_station_b["unread"])

                # Alice opens cursor-bot messages -> cleared ONLY for Alice, Bob stays unread=True!
                msgs_alice = client.get("/api/bots/cursor-bot/messages", headers=alice_hdrs).json()
                status_alice_after = client.get("/api/workspace/live-status", headers=alice_hdrs).json()
                status_bob_after = client.get("/api/workspace/live-status", headers=bob_hdrs).json()
                self.assertFalse(
                    next(b for b in status_alice_after["bots"] if b["slug"] == "cursor-bot")["unread"]
                )
                self.assertTrue(
                    next(b for b in status_bob_after["bots"] if b["slug"] == "cursor-bot")["unread"]
                )

                # 6. Emoji reaction toggle persists per message
                target_msg_id = msgs_alice[-1]["id"]
                rx = client.post(
                    f"/api/messages/{target_msg_id}/reactions",
                    headers=alice_hdrs,
                    json={"collection": "bot_threads", "emoji": "👍"},
                )
                self.assertEqual(rx.status_code, 200, rx.text)
                self.assertIn("alice@example.com", rx.json()["reactions"]["👍"])

    def test_team_pack_starters_export_and_collision_remapping_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                starters = client.get("/api/team-packs/starters", headers=self._sso_headers()).json()
                self.assertEqual(len(starters), 3)
                first_pack = starters[0]

                # First import creates original slugs
                imp1 = client.post(
                    "/api/team-packs/import",
                    headers=self._sso_headers(),
                    json={"pack": first_pack},
                )
                self.assertEqual(imp1.status_code, 201, imp1.text)
                b1 = imp1.json()
                self.assertGreaterEqual(len(b1["bots"]), 3)
                self.assertEqual(len(b1["rooms"]), 1)

                # Export and assert zero secrets included
                room_slug = b1["rooms"][0]["slug"]
                exported = client.get(
                    f"/api/team-packs/export?room_slug={room_slug}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(exported.status_code, 200, exported.text)
                exp_json = exported.json()
                self.assertEqual(exp_json["schema_version"], "argo.team_pack.v1")
                self.assertNotIn("api_key", json.dumps(exp_json))

                # Second import must remap colliding slugs across bots and rooms cleanly
                imp2 = client.post(
                    "/api/team-packs/import",
                    headers=self._sso_headers(),
                    json={"pack": exp_json},
                )
                self.assertEqual(imp2.status_code, 201, imp2.text)
                b2 = imp2.json()
                first_slugs = {b["slug"] for b in b1["bots"]}
                second_slugs = {b["slug"] for b in b2["bots"]}
                self.assertTrue(first_slugs.isdisjoint(second_slugs))
                self.assertTrue(set(b2["rooms"][0]["member_bot_slugs"]).issubset(second_slugs))

    def test_vault_edit_empty_acl_isolation_and_clean_live_status_subtitles(self) -> None:
        async def clean_llm(_req: LLMRequest) -> dict[str, Any]:
            return {
                "text": json.dumps(
                    {"summary": "Checked latest releases and noted 2 updates.", "actions": []}
                ),
                "input_tokens": 12,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=clean_llm)
            with TestClient(app) as client:
                # 1. Create a bot and run it once (LLMRouter records summary="Completed on ...")
                bot_resp = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "clean-sub-bot",
                        "name": "Clean Subtitle Bot",
                        "role": "Summarize status",
                    },
                )
                self.assertEqual(bot_resp.status_code, 201, bot_resp.text)
                trig = client.post(
                    "/api/bots/clean-sub-bot/trigger",
                    headers=self._sso_headers(),
                    json={},
                )
                self.assertEqual(trig.status_code, 200, trig.text)

                status = client.get("/api/workspace/live-status", headers=self._sso_headers()).json()
                station = next(b for b in status["bots"] if b["slug"] == "clean-sub-bot")
                self.assertFalse(station["last_action_subtitle"].startswith("Completed on "))
                self.assertFalse(station["last_summary"].startswith("Completed on "))
                self.assertEqual(
                    station["last_action_subtitle"],
                    "Checked latest releases and noted 2 updates.",
                )

                # 2. Vault secret with allowed_bots=[] persists [] and blocks bot access
                created = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Production Linux SSH",
                        "slug": "prod-linux-ssh",
                        "secret_type": "ssh",
                        "host": "10.0.0.10",
                        "port": "22",
                        "secrets": {"username": "deploy", "password": "s3cr3t-pass-99"},
                        "allowed_bots": [],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                sec_body = created.json()
                self.assertEqual(sec_body["allowed_bots"], [])
                bot_doc = app.state.repo.get_bot("clean-sub-bot")
                self.assertFalse(app.state.bot_runner._is_vault_permitted(bot_doc, sec_body))

                # 3. PATCH edit updates metadata & allowed_bots while preserving encrypted password
                patched = client.patch(
                    "/api/vault/prod-linux-ssh",
                    headers=self._sso_headers(),
                    json={
                        "name": "Updated Linux SSH",
                        "host": "10.0.0.50",
                        "allowed_bots": ["clean-sub-bot"],
                    },
                )
                self.assertEqual(patched.status_code, 200, patched.text)
                patched_body = patched.json()
                self.assertEqual(patched_body["name"], "Updated Linux SSH")
                self.assertEqual(patched_body["host"], "10.0.0.50")
                self.assertEqual(patched_body["allowed_bots"], ["clean-sub-bot"])
                self.assertTrue(app.state.bot_runner._is_vault_permitted(bot_doc, patched_body))
                dec = app.state.repo.get_vault_secret_decrypted("prod-linux-ssh")
                self.assertEqual(dec["secrets"]["username"], "deploy")
                self.assertEqual(dec["secrets"]["password"], "s3cr3t-pass-99")

    def test_workspace_file_download_query_param_and_bot_written_attachments(self) -> None:
        alice_hdrs = self._sso_headers("alice@example.com")
        bob_hdrs = self._sso_headers("bob@example.com")

        async def writer_llm(req: LLMRequest) -> dict[str, Any]:
            return {
                "text": json.dumps(
                    {
                        "summary": "Generated your CSV export cleanly.",
                        "actions": [
                            {
                                "type": "write_workspace_file",
                                "filename": "weekly-report.csv",
                                "content": "metric,value\nok,42\n",
                            }
                        ],
                    }
                ),
                "input_tokens": 14,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=writer_llm)
            with TestClient(app) as client:
                # 1. Text/Markdown upload returns inline by default and attachment on ?download=true
                up_md = client.post(
                    "/api/files",
                    headers=alice_hdrs,
                    json={
                        "filename": "notes summary.md",
                        "mime_type": "text/markdown",
                        "text": "# Summary\nReady\n",
                    },
                )
                self.assertEqual(up_md.status_code, 201, up_md.text)
                md_doc = up_md.json()
                md_id = md_doc["id"]

                inline_resp = client.get(f"/api/files/{md_id}/content", headers=alice_hdrs)
                self.assertEqual(inline_resp.status_code, 200)
                self.assertEqual(inline_resp.headers.get("x-content-type-options"), "nosniff")
                self.assertTrue(inline_resp.headers["content-disposition"].startswith("inline;"))

                dl_resp = client.get(f"/api/files/{md_id}/content?download=true", headers=alice_hdrs)
                self.assertEqual(dl_resp.status_code, 200)
                self.assertEqual(dl_resp.headers.get("x-content-type-options"), "nosniff")
                self.assertTrue(dl_resp.headers["content-disposition"].startswith("attachment;"))
                self.assertIn(md_doc["filename"], dl_resp.headers["content-disposition"])
                self.assertIn("filename*=UTF-8''", dl_resp.headers["content-disposition"])

                # Cross-user isolation remains enforced on ?download=true
                bob_dl = client.get(f"/api/files/{md_id}/content?download=true", headers=bob_hdrs)
                self.assertEqual(bob_dl.status_code, 404)

                # 2. Active web formats (HTML / SVG) always force attachment even without ?download=true
                for fname, mime, payload in (
                    ("chart.svg", "image/svg+xml", "<svg></svg>"),
                    ("export.html", "text/html", "<!doctype html><html></html>"),
                ):
                    up_active = client.post(
                        "/api/files",
                        headers=alice_hdrs,
                        json={"filename": fname, "mime_type": mime, "text": payload},
                    )
                    self.assertEqual(up_active.status_code, 201, up_active.text)
                    res_active = client.get(
                        f"/api/files/{up_active.json()['id']}/content", headers=alice_hdrs
                    )
                    self.assertEqual(res_active.status_code, 200)
                    self.assertTrue(res_active.headers["content-disposition"].startswith("attachment;"))

                # 3. Bot write_workspace_file attaches downloadable file metadata to reply
                bot = client.post(
                    "/api/bots",
                    headers=alice_hdrs,
                    json={"slug": "csv-exporter", "name": "CSV Exporter", "role": "Report exporter"},
                ).json()
                turn = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=alice_hdrs,
                    json={"text": "Generate the weekly CSV"},
                )
                self.assertEqual(turn.status_code, 200, turn.text)
                bot_msg = turn.json()["messages"][-1]
                atts = bot_msg["metadata"].get("attachments") or []
                self.assertEqual(len(atts), 1)
                self.assertEqual(atts[0]["filename"], "weekly-report.csv")
                csv_dl = client.get(
                    f"/api/files/{atts[0]['id']}/content?download=true", headers=alice_hdrs
                )
                self.assertEqual(csv_dl.status_code, 200)
                self.assertTrue(csv_dl.headers["content-disposition"].startswith("attachment;"))
                self.assertIn("ok,42", csv_dl.text)

                # 4. Default sandboxed HTML Page declares allow-downloads while blocking allow-same-origin
                safe_pg = client.post(
                    "/api/pages",
                    headers=alice_hdrs,
                    json={"title": "Export Stage", "render_mode": "sandboxed_html"},
                )
                self.assertEqual(safe_pg.status_code, 201, safe_pg.text)
                self.assertIn("allow-downloads", safe_pg.json()["content_payload"])
                self.assertNotIn("allow-same-origin", safe_pg.json()["content_payload"])


if __name__ == "__main__":
    unittest.main()
