"""Regression tests for bare action JSON leaks, descriptive URL chips, and Edit Last Message."""

from __future__ import annotations

import asyncio
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
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.bot_runner import (  # noqa: E402
    _IncrementalSummaryExtractor,
    _build_action_chip_label,
    _extract_json_envelope_with_prose,
    _split_malformed_envelope,
)
from argo_core.security.ssrf import PublicHttpResponse  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeWebFetcher:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def fetch(
        self, url: str, headers: dict[str, str] | None = None, max_bytes: int = 10_485_760
    ) -> PublicHttpResponse:
        del headers, max_bytes
        self.urls.append(url)
        return PublicHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body="<html><head><title>Zabbix Repo</title></head><body><h1>Zabbix 8.0beta2 RPMs</h1></body></html>",
        )


class TestBareActionAndEditMessage(unittest.TestCase):
    """Verify bare action JSON normalization, URL chips, synthesis fallback, and message rewind/edit."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None, public_http_fetcher=None):
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
            public_http_fetcher=public_http_fetcher,
        )

    def test_bare_action_object_array_and_streaming_never_leak_json(self) -> None:
        # 1. Bare single action object executes normally and synthesizes cleanly.
        bare_action = '{"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/"}'
        env, prose = _extract_json_envelope_with_prose(bare_action)
        self.assertIsNotNone(env)
        self.assertEqual(env["summary"], "")
        self.assertEqual(env["actions"][0]["type"], "fetch_public_webpage")
        self.assertEqual(prose, "")

        # 2. Bare action array and singular {"action": {...}} coerce cleanly.
        env_arr, _ = _extract_json_envelope_with_prose(f"[{bare_action}]")
        self.assertIsNotNone(env_arr)
        self.assertEqual(len(env_arr["actions"]), 1)

        singular = json.dumps({"summary": "Checking repo...", "action": {"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/"}})
        env_sing, _ = _extract_json_envelope_with_prose(singular)
        self.assertIsNotNone(env_sing)
        self.assertEqual(env_sing["summary"], "Checking repo...")
        self.assertEqual(env_sing["actions"][0]["type"], "fetch_public_webpage")

        # 3. Illustrative non-action JSON (and snake_case JSON preceded by prose or JSON Schema) stay intact.
        tech_prose = 'Example config:\n```json\n{"name": "zabbix", "version": "8.0"}\n```\nSave this file.'
        self.assertIsNone(_extract_json_envelope_with_prose(tech_prose)[0])
        webhook_prose = 'Here is a sample webhook payload:\n```json\n{"type": "order_created", "id": 42}\n```'
        self.assertIsNone(_extract_json_envelope_with_prose(webhook_prose)[0])
        schema_json = '{"type": "object", "properties": {"id": {"type": "string"}}}'
        self.assertIsNone(_extract_json_envelope_with_prose(schema_json)[0])

        # 4. Future hypothetical snake_case tools work automatically with zero static registration.
        custom_action = '{"type": "custom_metric_probe", "url": "https://metrics.example.com/v1"}'
        env_custom, _ = _extract_json_envelope_with_prose(custom_action)
        self.assertIsNotNone(env_custom)
        self.assertEqual(env_custom["actions"][0]["type"], "custom_metric_probe")
        custom_lbl, custom_det = _build_action_chip_label(
            "custom_metric_probe",
            json.loads(custom_action),
        )
        self.assertEqual(custom_lbl, "Custom metric probe · metrics.example.com/v1")
        self.assertEqual(custom_det, "https://metrics.example.com/v1")

        # 4. Malformed bare action JSON is flagged as malformed instead of printing raw JSON.
        truncated = '{"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/unterminated'
        is_malformed, _, _ = _split_malformed_envelope(truncated)
        self.assertTrue(is_malformed)

        # 5. Streaming extractor suppresses bare action object & array JSON while streaming Markdown links.
        for sample in (bare_action, f"[{bare_action}]", f"```json\n[{bare_action}]\n```"):
            ext = _IncrementalSummaryExtractor()
            out = "".join(ext.feed(sample[i : i + 4]) for i in range(0, len(sample), 4)) + ext.finish()
            self.assertEqual(out.strip(), "")

        md_link = "[Zabbix Downloads](https://www.zabbix.com/download) shows the current releases."
        ext_md = _IncrementalSummaryExtractor()
        streamed_md = "".join(ext_md.feed(md_link[i : i + 5]) for i in range(0, len(md_link), 5)) + ext_md.finish()
        self.assertEqual(streamed_md, md_link)

    def test_descriptive_url_chip_labels_and_synthesis_fallback_on_bare_action(self) -> None:
        lbl1, det1 = _build_action_chip_label(
            "fetch_public_webpage",
            {"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/"},
        )
        lbl2, _ = _build_action_chip_label(
            "fetch_public_webpage",
            {"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/7.0/rhel/9/x86_64/"},
        )
        self.assertIn("repo.zabbix.com", lbl1)
        self.assertIn("9/x86_64", lbl1)
        self.assertIn("8.0", lbl1)
        self.assertNotEqual(lbl1, lbl2)
        self.assertEqual(det1, "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/")

        fetcher = _FakeWebFetcher()
        call_obs: list[list[dict[str, Any]]] = []

        async def bare_then_synth_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            obs = list(env.get("tool_observations") or [])
            call_obs.append(obs)
            if len(call_obs) == 1:
                # Turn 1: emits bare action JSON on its own
                return {
                    "text": '{"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/"}',
                    "input_tokens": 12,
                    "output_tokens": 18,
                }
            if len(call_obs) == 2:
                # Turn 2: normal follow-up turn also emits bare action JSON -> still executes cleanly!
                return {
                    "text": '{"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/7.0/rhel/9/x86_64/"}',
                    "input_tokens": 14,
                    "output_tokens": 18,
                }
            # Turn 3: returns crisp prose
            return {
                "text": "The official Zabbix repository currently lists **Zabbix 8.0beta2** RPM packages for RHEL 9.",
                "input_tokens": 18,
                "output_tokens": 22,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=bare_then_synth_llm, public_http_fetcher=fetcher)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "sysadmin-bot",
                        "name": "SysAdmin Solver",
                        "role": "Infrastructure specialist",
                        "outbound_rbac": "internal",
                    },
                )
                res = client.post(
                    "/api/bots/sysadmin-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Verify on official zabbix website"},
                ).json()["result"]

                self.assertEqual(
                    fetcher.urls,
                    [
                        "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/",
                        "https://repo.zabbix.com/zabbix/7.0/rhel/9/x86_64/",
                    ],
                )
                self.assertIn("Zabbix 8.0beta2", res["summary"])
                self.assertNotIn('"fetch_public_webpage"', res["summary"])
                chips = (res.get("metadata") or {}).get("chips") or []
                self.assertTrue(any("8.0" in str(c.get("label") or "") for c in chips))
                self.assertTrue(any("7.0" in str(c.get("label") or "") for c in chips))
                self.assertTrue(
                    any(
                        "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/" in str(c.get("detail") or "")
                        for c in chips
                    )
                )

        # Also test forced synthesis_only=True (max_steps_per_run=3 -> step checkpoint after 3 turns)
        # where the synthesis turn emits a bare action JSON instead of prose and triggers synthesis_reminder!
        synth_obs: list[list[dict[str, Any]]] = []
        synth_fetcher = _FakeWebFetcher()

        async def checkpoint_bare_synth_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            obs = list(env.get("tool_observations") or [])
            synth_obs.append(obs)
            call_num = len(synth_obs)
            if call_num <= 3:
                return {
                    "text": json.dumps(
                        {
                            "type": "fetch_public_webpage",
                            "url": f"https://repo.zabbix.com/zabbix/8.{call_num}/rhel/9/x86_64/",
                        }
                    ),
                }
            if call_num == 4:
                # Hit synthesis_only=True, mistakenly outputs bare JSON with no summary!
                return {
                    "text": '{"type": "fetch_public_webpage", "url": "https://repo.zabbix.com/zabbix/7.0/rhel/9/x86_64/"}',
                }
            return {
                "text": "Checked Zabbix repos; ready to continue when you click Continue.",
            }

        with tempfile.TemporaryDirectory() as tmp2:
            app2 = self._build_env(tmp2, llm_transport=checkpoint_bare_synth_llm, public_http_fetcher=synth_fetcher)
            with TestClient(app2) as client2:
                create_res = client2.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "synth-bot",
                        "name": "Synth Bot",
                        "role": "Infrastructure specialist",
                        "outbound_rbac": "internal",
                        "max_steps_per_run": 3,
                    },
                )
                self.assertIn(create_res.status_code, (200, 201), create_res.text)
                msg_res = client2.post(
                    "/api/bots/synth-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Verify on official zabbix website"},
                )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                res2 = msg_res.json()["result"]

                self.assertEqual(len(synth_fetcher.urls), 3)
                self.assertEqual(len(synth_obs), 5)
                self.assertEqual(synth_obs[-1][-1].get("type"), "synthesis_reminder")
                self.assertIn("Checked Zabbix repos", res2["summary"])
                self.assertNotIn('"fetch_public_webpage"', res2["summary"])

    def test_edit_last_user_message_bot_and_room_rewinds_and_resubmits(self) -> None:
        async def echo_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            trig = env.get("trigger_payload") or {}
            text = str(trig.get("input_text") or trig.get("text") or "").strip()
            if "old prompt" in text.lower():
                return {"text": json.dumps({"summary": "Old answer for old prompt.", "actions": []})}
            if "refined prompt" in text.lower():
                return {"text": json.dumps({"summary": "Updated answer for refined prompt.", "actions": []})}
            if "room old" in text.lower():
                return {"text": json.dumps({"summary": "Room old answer.", "actions": []})}
            if "room edited" in text.lower():
                return {"text": json.dumps({"summary": "Room updated answer.", "actions": []})}
            return {"text": json.dumps({"summary": f"Echo: {text}", "actions": []})}

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=echo_llm)
            with TestClient(app) as client:
                repo = app.state.repo
                bot_runner = app.state.bot_runner
                bot1 = repo.create_bot(name="Helper One", role="Assistant", outbound_rbac="draft")
                bot2 = repo.create_bot(name="Helper Two", role="Reviewer", outbound_rbac="internal")
                bot_slug = bot1["slug"]

                # Save an attachment to confirm attachments survive last-message editing.
                saved_file = repo.save_workspace_file(
                    owner_email="operator@example.com",
                    filename="check.txt",
                    mime_type="text/plain",
                    content_bytes=b"sample context",
                )

                # Send first user turn + second user turn so we can verify editing non-last message is rejected.
                first_res = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "First message"},
                )
                self.assertEqual(first_res.status_code, 200)
                second_res = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Old prompt v1", "attachment_ids": [saved_file["id"]]},
                )
                self.assertEqual(second_res.status_code, 200)

                msgs = repo.list_bot_messages(bot_slug)
                user_msgs = [m for m in msgs if m["sender"] == "user"]
                bot_msgs = [m for m in msgs if m["sender"] == "bot"]
                first_user_id = user_msgs[0]["id"]
                last_user_id = user_msgs[-1]["id"]
                last_bot_msg = bot_msgs[-1]
                corr_to_supersede = (last_bot_msg.get("metadata") or {}).get("correlation_id") or "corr_test"
                repo.create_approval(
                    correlation_id=corr_to_supersede,
                    bot_slug=bot_slug,
                    target_account_slug="tg-ops",
                    action_type="publish_telegram",
                    payload={"text": "old pending draft"},
                )

                # Reject editing an older (non-last) user message -> 400.
                older_err = client.patch(
                    f"/api/bots/{bot_slug}/messages/{first_user_id}",
                    headers=self._sso_headers(),
                    json={"text": "Try editing older"},
                )
                self.assertEqual(older_err.status_code, 400)

                # Reject editing a bot message -> 400.
                bot_err = client.patch(
                    f"/api/bots/{bot_slug}/messages/{last_bot_msg['id']}",
                    headers=self._sso_headers(),
                    json={"text": "Try editing bot"},
                )
                self.assertEqual(bot_err.status_code, 400)

                # Reject editing while thread is running -> 409.
                bot_runner._active_runs[bot_slug] = {"step": "Working", "started_at": "2026-11-20T00:00:00Z", "correlation_id": "c"}
                try:
                    busy_err = client.patch(
                        f"/api/bots/{bot_slug}/messages/{last_user_id}",
                        headers=self._sso_headers(),
                        json={"text": "Refined prompt v2"},
                    )
                    self.assertEqual(busy_err.status_code, 409)
                finally:
                    bot_runner._active_runs.pop(bot_slug, None)

                # Edit last user message -> rewinds old prompt/reply, supersedes pending approval, re-submits!
                edit_res = client.patch(
                    f"/api/bots/{bot_slug}/messages/{last_user_id}",
                    headers=self._sso_headers(),
                    json={"text": "Refined prompt v2", "async_mode": False},
                )
                self.assertEqual(edit_res.status_code, 200, edit_res.text)
                edit_body = edit_res.json()
                self.assertIn(last_user_id, edit_body["removed_message_ids"])
                self.assertIn(last_bot_msg["id"], edit_body["removed_message_ids"])
                self.assertEqual(edit_body["result"]["summary"], "Updated answer for refined prompt.")

                after_msgs = repo.list_bot_messages(bot_slug)
                after_texts = [m["text"] for m in after_msgs]
                self.assertNotIn("Old prompt v1", after_texts)
                self.assertNotIn("Old answer for old prompt.", after_texts)
                self.assertIn("First message", after_texts)
                self.assertIn("Refined prompt v2", after_texts)
                self.assertIn("Updated answer for refined prompt.", after_texts)
                edited_user = next(m for m in after_msgs if m["text"] == "Refined prompt v2")
                self.assertEqual((edited_user.get("metadata") or {}).get("attachments", [{}])[0].get("id"), saved_file["id"])
                # Pending approval from removed reply was superseded.
                self.assertEqual(repo.list_approvals(tab="pending"), [])

                # Also test Room edit-last-message end-to-end.
                room = repo.create_room(
                    title="Test Edit Room",
                    member_bot_slugs=[bot1["slug"], bot2["slug"]],
                    coordinator_bot_slug=bot1["slug"],
                )
                r_first = client.post(
                    f"/api/rooms/{room['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Room old prompt", "async_mode": False},
                )
                self.assertEqual(r_first.status_code, 200)
                room_msgs = repo.list_room_messages(room["slug"], limit=None)
                last_room_user_id = next(m["id"] for m in reversed(room_msgs) if m["sender"] == "user")
                r_edit = client.patch(
                    f"/api/rooms/{room['slug']}/messages/{last_room_user_id}",
                    headers=self._sso_headers(),
                    json={"text": "Room edited prompt", "async_mode": False},
                )
                self.assertEqual(r_edit.status_code, 200, r_edit.text)
                self.assertIn(last_room_user_id, r_edit.json()["removed_message_ids"])
                room_after = repo.list_room_messages(room["slug"], limit=None)
                room_texts = [m["text"] for m in room_after]
                self.assertNotIn("Room old prompt", room_texts)
                self.assertIn("Room edited prompt", room_texts)
                self.assertTrue(any("Room updated answer." in t for t in room_texts))
