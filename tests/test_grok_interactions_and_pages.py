"""Tests for Grok-inspired UI interactions, Skills, Blueprints, Quiet Polls, and Living Pages."""

from __future__ import annotations

import functools
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
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class TestGrokInteractionsAndLivingPages(unittest.TestCase):
    """Verify Sprint 6 Grok-inspired workflows, guardrails, and interactive Living Pages."""

    @staticmethod
    def _sso_headers() -> dict[str, str]:
        return {
            "X-Auth-Request-Email": "operator@example.com",
            "X-Auth-Request-User": "operator",
        }

    def _build_env(self, tmp: str, *, llm_transport=None, google_transport=None):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text(
            "<!doctype html><html><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 38.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 14.0,
                "disk_percent": 29.0,
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            desktop_idle_timeout_seconds=300.0,
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            google_transport=google_transport,
        )

    def test_smart_url_naming_restated_summary_boundaries_and_bot_crud(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                draft_res = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": (
                            "Fetch https://blog.zabbix.com every 15 minutes, discard case studies, "
                            "save unseen articles, and queue a short Telegram summary for review."
                        )
                    },
                )
                self.assertEqual(draft_res.status_code, 200, draft_res.text)
                body = draft_res.json()
                self.assertIn(body["draft"]["name"], ("Zabbix Blog Monitor", "Zabbix Blog Digest"))
                self.assertNotIn("Fetch Https", body["draft"]["name"])
                self.assertIsInstance(body.get("restated_summary"), dict)
                self.assertIn("job", body["restated_summary"])
                self.assertIn("schedule", body["restated_summary"])
                self.assertIn("autonomy", body["restated_summary"])
                boundaries = body["draft"].get("boundaries") or []
                self.assertTrue(
                    any("case stud" in b.lower() for b in boundaries),
                    f"Expected case studies boundary in {boundaries}",
                )

                create_res = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": body["draft"]["name"],
                        "role": "Monitor Zabbix blog releases",
                        "role_prompt": "Skip case studies.",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "model": "google:gemini-3.8-flash",
                        "daily_cap": 10,
                        "avatar_color": "blue",
                        "pinned": True,
                        "section": "Content",
                        "boundaries": ["Never include case studies"],
                        "goal_metric": "Only high-signal release summaries",
                    },
                )
                self.assertEqual(create_res.status_code, 201, create_res.text)
                bot = create_res.json()
                self.assertEqual(bot["avatar_color"], "blue")
                self.assertTrue(bot["pinned"])
                self.assertEqual(bot["section"], "Content")
                self.assertEqual(bot["boundaries"], ["Never include case studies"])
                self.assertEqual(bot["goal_metric"], "Only high-signal release summaries")

                msgs_res = client.get(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                )
                self.assertEqual(msgs_res.status_code, 200)
                welcome_text = msgs_res.json()[0]["text"]
                self.assertIn("Ready!", welcome_text)
                self.assertNotIn("declarative", welcome_text.lower())

                patch_res = client.patch(
                    f"/api/bots/{bot['slug']}",
                    headers=self._sso_headers(),
                    json={"hidden_in_sidebar": True, "pinned": False},
                )
                self.assertEqual(patch_res.status_code, 200)
                self.assertTrue(patch_res.json()["hidden_in_sidebar"])
                self.assertFalse(patch_res.json()["pinned"])

                del_res = client.delete(
                    f"/api/bots/{bot['slug']}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(del_res.status_code, 200)
                self.assertEqual(
                    client.get(f"/api/bots/{bot['slug']}", headers=self._sso_headers()).status_code,
                    404,
                )

    def test_quiet_background_cron_polls_vs_action_runs_and_routine_sync(self) -> None:
        mode = {"step": "empty_poll"}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            if mode["step"] == "empty_poll":
                return {
                    "text": json.dumps({"summary": "Checked feed, nothing unseen.", "actions": []}),
                    "input_tokens": 18,
                    "output_tokens": 12,
                }
            if mode["step"] == "configure_silent":
                return {
                    "text": json.dumps(
                        {
                            "summary": "Updated schedule to Every 1h with silent delivery and quiet hours.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "schedule": "Every 1h",
                                    "delivery_mode": "silent",
                                    "quiet_hours": "22:00-07:00",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 22,
                    "output_tokens": 24,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Saved new article and queued Telegram summary.",
                        "actions": [
                            {
                                "type": "upsert_document",
                                "collection": "zabbix_news",
                                "external_key": "https://blog.zabbix.com/8-0",
                                "doc": {"title": "Zabbix 8.0 LTS"},
                            }
                        ],
                    }
                ),
                "input_tokens": 30,
                "output_tokens": 28,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                created = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Zabbix Watcher",
                        "role": "Watch Zabbix releases",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "model": "google:gemini-3.8-flash",
                        "collections": {"read": ["zabbix_news"], "write": ["zabbix_news"]},
                        "routines": [
                            {
                                "id": "rtn-poll",
                                "type": "cron",
                                "label": "Scheduled Poll",
                                "schedule": "Every 15m",
                                "enabled": True,
                            }
                        ],
                    },
                ).json()
                slug = created["slug"]

                before_msgs = client.get(
                    f"/api/bots/{slug}/messages", headers=self._sso_headers()
                ).json()
                self.assertEqual(len(before_msgs), 1)

                # 1. Empty background cron poll stays out of 1:1 chat thread
                empty_run = client.portal.call(  # type: ignore[union-attr]
                    functools.partial(
                        app.state.bot_runner.execute_bot,
                        slug,
                        trigger_type="cron",
                        routine_id="rtn-poll",
                    )
                )
                self.assertEqual(empty_run["status"], "completed")
                after_empty_msgs = client.get(
                    f"/api/bots/{slug}/messages", headers=self._sso_headers()
                ).json()
                self.assertEqual(len(after_empty_msgs), 1)

                # 2. Cron poll with real action appends rich bot message with metadata
                mode["step"] = "action_poll"
                action_run = client.portal.call(  # type: ignore[union-attr]
                    functools.partial(
                        app.state.bot_runner.execute_bot,
                        slug,
                        trigger_type="cron",
                        routine_id="rtn-poll",
                    )
                )
                self.assertEqual(action_run["status"], "completed")
                after_action_msgs = client.get(
                    f"/api/bots/{slug}/messages", headers=self._sso_headers()
                ).json()
                self.assertEqual(len(after_action_msgs), 2)
                meta = after_action_msgs[-1].get("metadata") or {}
                self.assertGreaterEqual(len(meta.get("actions") or []), 1)
                self.assertTrue(meta.get("correlation_id"))
                self.assertGreater(meta.get("tokens_used", 0), 0)

                # 3. Conversational configure_routine syncs scheduler and respects silent mode
                mode["step"] = "configure_silent"
                chat_res = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Run every 1h silently during night hours"},
                )
                self.assertEqual(chat_res.status_code, 200, chat_res.text)
                updated_bot = client.get(
                    f"/api/bots/{slug}", headers=self._sso_headers()
                ).json()
                self.assertEqual(updated_bot["routines"][0]["schedule"], "Every 1h")
                self.assertEqual(updated_bot["routines"][0]["delivery_mode"], "silent")

                jobs = client.get("/api/scheduler/jobs", headers=self._sso_headers()).json()
                self.assertTrue(any(j["bot_slug"] == slug for j in jobs))

                count_before_silent = len(
                    client.get(f"/api/bots/{slug}/messages", headers=self._sso_headers()).json()
                )
                mode["step"] = "action_poll"
                client.portal.call(  # type: ignore[union-attr]
                    functools.partial(
                        app.state.bot_runner.execute_bot,
                        slug,
                        trigger_type="cron",
                        routine_id="rtn-poll",
                    )
                )
                count_after_silent = len(
                    client.get(f"/api/bots/{slug}/messages", headers=self._sso_headers()).json()
                )
                self.assertEqual(count_before_silent, count_after_silent)

    def test_reusable_skills_at_mentions_and_memory_import(self) -> None:
        captured_prompts: list[str] = []

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            captured_prompts.append(req.user_prompt)
            return {
                "text": json.dumps(
                    {
                        "summary": "Ran @weekly-triage checklist and saved a follow-up skill.",
                        "actions": [
                            {
                                "type": "save_skill",
                                "name": "Executive Digest",
                                "description": "Compact bullet summary",
                                "instructions": "Always start with top 3 risks.",
                            }
                        ],
                    }
                ),
                "input_tokens": 25,
                "output_tokens": 20,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                helper = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Ops Assistant",
                        "role": "Assist operations",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                ).json()
                primary = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Lead Analyst",
                        "role": "Lead analysis",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                ).json()

                skill_res = client.post(
                    "/api/skills",
                    headers=self._sso_headers(),
                    json={
                        "name": "Weekly Triage",
                        "description": "Group items by priority",
                        "instructions": "CRITICAL_SENTINEL_SKILL: Classify blockers before FYIs.",
                    },
                )
                self.assertEqual(skill_res.status_code, 201, skill_res.text)
                skill = skill_res.json()
                self.assertEqual(skill["slug"], "weekly-triage")

                msg_res = client.post(
                    f"/api/bots/{primary['slug']}/messages",
                    headers=self._sso_headers(),
                    json={
                        "text": f"@{helper['slug']} please apply @weekly-triage to today's backlog"
                    },
                )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                messages = msg_res.json()["messages"]
                user_msg = [m for m in messages if m["sender"] == "user"][-1]
                self.assertEqual(user_msg["metadata"]["mentioned_bots"], [helper["slug"]])
                self.assertEqual(user_msg["metadata"]["skill_slugs"], ["weekly-triage"])
                self.assertTrue(
                    any("CRITICAL_SENTINEL_SKILL" in p for p in captured_prompts),
                    "Active @skill instructions must be injected into the bot prompt.",
                )

                all_skills = client.get("/api/skills", headers=self._sso_headers()).json()
                self.assertTrue(any(s["slug"] == "executive-digest" for s in all_skills))

                del_skill = client.delete(
                    f"/api/skills/{skill['id']}", headers=self._sso_headers()
                )
                self.assertEqual(del_skill.status_code, 200)

                imp1 = client.post(
                    "/api/style-rules/import",
                    headers=self._sso_headers(),
                    json={
                        "raw_text": "- Keep summaries under 3 sentences\n- Never use emojis\n- Keep summaries under 3 sentences",
                        "scope_slug": "*",
                    },
                )
                self.assertEqual(imp1.status_code, 201, imp1.text)
                self.assertEqual(imp1.json()["imported_count"], 2)

                imp2 = client.post(
                    "/api/style-rules/import",
                    headers=self._sso_headers(),
                    json={
                        "raw_text": "- Keep summaries under 3 sentences\n- Never use emojis",
                        "scope_slug": "*",
                    },
                )
                self.assertEqual(imp2.status_code, 201)
                self.assertEqual(imp2.json()["imported_count"], 0)

    def test_sanitized_blueprint_export_import_and_usage_by_bot(self) -> None:
        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            return {
                "text": json.dumps({"summary": "Processed items cleanly.", "actions": []}),
                "input_tokens": 120,
                "output_tokens": 45,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                secret_token = "SUPER_SECRET_CREDENTIAL_XYZ"
                client.post(
                    "/api/integrations",
                    headers=self._sso_headers(),
                    json={
                        "slug": "tg-team",
                        "provider": "telegram",
                        "display_name": "Team Bot",
                        "account_identifier": "@team_bot",
                        "scopes": ["bot"],
                        "secrets": {"bot_token": secret_token},
                    },
                )
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Digest Publisher",
                        "role": "Publish sanitized digests",
                        "role_prompt": "Summarize releases accurately.",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "model": "google:gemini-3.8-flash",
                        "linked_accounts": ["tg-team"],
                        "boundaries": ["Never speculate on unreleased pricing"],
                    },
                ).json()
                client.post(
                    "/api/skills",
                    headers=self._sso_headers(),
                    json={
                        "name": "Release Note Format",
                        "description": "3-bullet release notes",
                        "instructions": "Format as Impact, Upgrade Path, Links.",
                        "scope_slug": bot["slug"],
                    },
                )
                client.post(
                    f"/api/bots/{bot['slug']}/trigger",
                    headers=self._sso_headers(),
                    json={"wait_for_chain": True},
                )

                models_res = client.get("/api/models", headers=self._sso_headers())
                self.assertEqual(models_res.status_code, 200)
                usage_by_bot = models_res.json().get("usage_by_bot") or []
                bot_usage = next((u for u in usage_by_bot if u["bot_slug"] == bot["slug"]), None)
                self.assertIsNotNone(bot_usage)
                self.assertGreaterEqual(bot_usage["runs_count"], 1)
                self.assertEqual(bot_usage["month_tokens"], 165)

                bp_res = client.get(
                    f"/api/bots/{bot['slug']}/blueprint", headers=self._sso_headers()
                )
                self.assertEqual(bp_res.status_code, 200, bp_res.text)
                blueprint = bp_res.json()
                self.assertEqual(blueprint["schema_version"], "argo.bot_blueprint.v1")
                self.assertIn("telegram", blueprint["required_providers"])
                self.assertEqual(len(blueprint["skills"]), 1)
                serialized = json.dumps(blueprint)
                self.assertNotIn(secret_token, serialized)
                self.assertNotIn("tg-team", serialized)

                imp_res = client.post(
                    "/api/bots/import-blueprint",
                    headers=self._sso_headers(),
                    json={"blueprint": {**blueprint, "name": "Digest Publisher Clone"}},
                )
                self.assertEqual(imp_res.status_code, 201, imp_res.text)
                clone = imp_res.json()
                self.assertEqual(clone["name"], "Digest Publisher Clone")
                self.assertEqual(clone["boundaries"], ["Never speculate on unreleased pricing"])

    def test_approval_gated_specialist_bot_and_fleet_cleanup(self) -> None:
        step = {"kind": "propose_bot"}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            if step["kind"] == "propose_bot":
                return {
                    "text": json.dumps(
                        {
                            "summary": "Proposed a new Release Monitor specialist bot for approval.",
                            "actions": [
                                {
                                    "type": "propose_specialist_bot",
                                    "name": "CVE Watchdog",
                                    "role": "Track security advisories every 1h",
                                    "prompt": "Monitor security RSS every 1h and queue summaries for review",
                                    "section": "Security",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 25,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Proposed pausing and archiving the idle CVE Watchdog bot.",
                        "actions": [
                            {
                                "type": "propose_fleet_cleanup",
                                "reason": "Archive idle specialist bot",
                                "operations": [
                                    {
                                        "bot_slug": "cve-watchdog",
                                        "enabled": False,
                                        "hidden_in_sidebar": True,
                                        "section": "Archived",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                "input_tokens": 22,
                "output_tokens": 24,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                coord = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Workspace Coordinator",
                        "role": "Coordinate bots",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                    },
                ).json()

                client.post(
                    f"/api/bots/{coord['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Hire a CVE Watchdog bot"},
                )
                pending = client.get(
                    "/api/approvals?tab=pending", headers=self._sso_headers()
                ).json()
                hire_apr = next(
                    (a for a in pending if a["action_type"] == "create_specialist_bot"),
                    None,
                )
                self.assertIsNotNone(hire_apr)
                self.assertEqual(hire_apr["target_account_slug"], "argo_workspace")

                approve_hire = client.post(
                    f"/api/approvals/{hire_apr['id']}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve"},
                )
                self.assertEqual(approve_hire.status_code, 200, approve_hire.text)
                self.assertEqual(approve_hire.json()["status"], "executed")
                self.assertEqual(
                    client.get("/api/bots/cve-watchdog", headers=self._sso_headers()).status_code,
                    200,
                )

                step["kind"] = "fleet_cleanup"
                client.post(
                    f"/api/bots/{coord['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Audit my fleet and propose cleanup"},
                )
                pending2 = client.get(
                    "/api/approvals?tab=pending", headers=self._sso_headers()
                ).json()
                cleanup_apr = next(
                    (a for a in pending2 if a["action_type"] == "fleet_cleanup"),
                    None,
                )
                self.assertIsNotNone(cleanup_apr)

                approve_cleanup = client.post(
                    f"/api/approvals/{cleanup_apr['id']}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve"},
                )
                self.assertEqual(approve_cleanup.status_code, 200, approve_cleanup.text)
                self.assertEqual(approve_cleanup.json()["status"], "executed")

                archived = client.get(
                    "/api/bots/cve-watchdog", headers=self._sso_headers()
                ).json()
                self.assertFalse(archived["enabled"])
                self.assertTrue(archived["hidden_in_sidebar"])
                self.assertEqual(archived["section"], "Archived")

    def test_living_pages_generate_edit_with_bot_and_live_status(self) -> None:
        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            return {
                "text": json.dumps(
                    {
                        "summary": "Updated the Page layout with darker header cards.",
                        "actions": [
                            {
                                "type": "upsert_page",
                                "slug": "live-bot-operations-map",
                                "title": "Live Bot Operations Map v2",
                                "description": "Side-by-side conversational revision",
                                "render_mode": "sandboxed_html",
                                "allowed_collections": ["ops_feed"],
                                "content_payload": "<!doctype html><html><body><h1>Live Map v2</h1></body></html>",
                            }
                        ],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 30,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Page Designer",
                        "role": "Build interactive pages",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["bot_threads", "ops_feed"], "write": ["ops_feed"]},
                    },
                ).json()

                for tpl_key in (
                    "live_operations_map",
                    "collection_analytics",
                    "interactive_playground",
                ):
                    gen = client.post(
                        "/api/pages/generate",
                        headers=self._sso_headers(),
                        json={
                            "prompt": f"Create {tpl_key} view",
                            "template_key": tpl_key,
                            "owner_bot_slug": bot["slug"],
                            "allowed_collections": ["ops_feed"],
                        },
                    )
                    self.assertEqual(gen.status_code, 201, gen.text)
                    page = gen.json()
                    self.assertEqual(page["render_mode"], "sandboxed_html")
                    self.assertEqual(page["owner_bot_slug"], bot["slug"])
                    self.assertNotIn("allow-same-origin", page["content_payload"].lower())
                    if tpl_key == "live_operations_map":
                        self.assertIn("ARGO_LIVE_STATUS", page["content_payload"])

                # Conversational side-by-side edit via owner bot
                edit_res = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={
                        "text": "Update this page to v2",
                        "target_page_slug": "live-bot-operations-map",
                    },
                )
                self.assertEqual(edit_res.status_code, 200, edit_res.text)
                updated_page = client.get(
                    "/api/pages/live-bot-operations-map", headers=self._sso_headers()
                ).json()
                self.assertEqual(updated_page["title"], "Live Bot Operations Map v2")
                self.assertIn("Live Map v2", updated_page["content_payload"])

                # Enqueue a pending approval and check /api/workspace/live-status
                client.post(
                    "/api/approvals",
                    headers=self._sso_headers(),
                    json={
                        "bot_slug": bot["slug"],
                        "target_account_slug": "tg-ops",
                        "action_type": "send_telegram",
                        "payload": {"text": "Ready for review"},
                    },
                )
                live_res = client.get("/api/workspace/live-status", headers=self._sso_headers())
                self.assertEqual(live_res.status_code, 200, live_res.text)
                live = live_res.json()
                station = next(b for b in live["bots"] if b["slug"] == bot["slug"])
                self.assertEqual(station["state"], "waiting_approval")
                self.assertEqual(station["pending_approvals_count"], 1)

    def test_live_bot_progress_sse_and_active_runs_status(self) -> None:
        observed_during_run: list[dict[str, Any]] = []
        app_ref: dict[str, Any] = {}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            app_obj = app_ref["app"]
            active = app_obj.state.bot_runner.active_runs()
            live = app_obj.state.repo.build_live_workspace_status(active_runs=active)
            observed_during_run.append({"active": active, "live": live})
            return {
                "text": json.dumps({"summary": "Checked mailbox and finished.", "actions": []}),
                "input_tokens": 12,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            app_ref["app"] = app
            with TestClient(app) as client:
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Progress Checker",
                        "role": "Report progress while running",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                    },
                ).json()

                events_before = len(
                    client.get("/api/activity", headers=self._sso_headers()).json()
                )

                # 1. EventBus.emit_progress pushes SSE progress event without writing events_log
                async def check_emit_progress() -> dict[str, Any]:
                    async with app.state.bus.subscribe() as q:
                        await app.state.bus.emit_progress(
                            bot["slug"], "running", "Searching Gmail...", "corr_test"
                        )
                        return await q.get()

                emitted = client.portal.call(check_emit_progress)  # type: ignore[union-attr]
                self.assertEqual(emitted.get("_sse_event"), "bot_progress")
                self.assertEqual(emitted.get("bot_slug"), bot["slug"])
                self.assertEqual(emitted.get("state"), "running")
                self.assertEqual(emitted.get("step"), "Searching Gmail...")

                events_after_progress = len(
                    client.get("/api/activity", headers=self._sso_headers()).json()
                )
                self.assertEqual(events_before, events_after_progress)

                # 2. During bot run, active_runs tracks running state + friendly step, and clears on exit
                msg_res = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Check inbox now"},
                )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                self.assertEqual(len(observed_during_run), 1)
                mid_active = observed_during_run[0]["active"]
                self.assertIn(bot["slug"], mid_active)
                self.assertEqual(mid_active[bot["slug"]]["step"], "Thinking...")

                mid_station = next(
                    s
                    for s in observed_during_run[0]["live"]["bots"]
                    if s["slug"] == bot["slug"]
                )
                self.assertEqual(mid_station["state"], "running")
                self.assertEqual(mid_station["active_step"], "Thinking...")

                self.assertEqual(app.state.bot_runner.active_runs(), {})

    def test_supervisor_bot_platform_status_and_handoff_pipeline(self) -> None:
        captured: list[dict[str, Any]] = []

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            envelope = json.loads(req.user_prompt)
            captured.append(
                {
                    "system": req.system_prompt,
                    "envelope": envelope,
                }
            )
            if "story_leads" in req.system_prompt and "Write a nice story" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Drafted story from lead and queued in Approvals.",
                            "actions": [
                                {
                                    "type": "request_human_approval",
                                    "account": "tg-ops",
                                    "action_type": "publish_telegram",
                                    "text": "Today's lead story ready for review.",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 18,
                }
            if "Check inbox for valuable leads" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Found 1 high-value email lead from Dimitri about Q4 meetup.",
                            "actions": [
                                {
                                    "type": "upsert_document",
                                    "collection": "story_leads",
                                    "external_key": "lead-dimitri-1",
                                    "search_text": "Q4 meetup from Dimitri",
                                    "doc": {"title": "Q4 meetup", "from": "dimitri@example.com"},
                                }
                            ],
                        }
                    ),
                    "input_tokens": 22,
                    "output_tokens": 25,
                }
            return {
                "text": json.dumps(
                    {"summary": "All bots checked: 2 active, 1 approval waiting.", "actions": []}
                ),
                "input_tokens": 15,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                # 1. Builder auto-wires platform_status tool and shield/indigo avatar for Supervisor bots
                sup_draft_res = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Act as a Supervisor overseeing all bots, schedules, and approvals",
                    },
                )
                self.assertEqual(sup_draft_res.status_code, 200, sup_draft_res.text)
                sup_draft = sup_draft_res.json()["draft"]
                self.assertEqual(sup_draft["avatar_icon"], "shield")
                self.assertEqual(sup_draft["avatar_color"], "indigo")
                tool_names = [t.get("name") for t in sup_draft["tools"] if isinstance(t, dict)]
                self.assertIn("platform_status", tool_names)

                sup = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Workspace Supervisor",
                        "role": sup_draft["role"],
                        "role_prompt": sup_draft["role_prompt"],
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "model": "google:gemini-4-argon",
                        "avatar_icon": "shield",
                        "avatar_color": "indigo",
                        "tools": sup_draft["tools"],
                    },
                ).json()

                # 2. Writer + Scout handoff pipeline (handoff_bot_slug)
                writer = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Story Writer",
                        "role": "Write engaging stories from Scout leads",
                        "role_prompt": "Write a nice story using story_leads.",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "avatar_icon": "pen",
                        "avatar_color": "violet",
                        "collections": {"read": ["story_leads", "bot_threads"], "write": ["bot_threads"]},
                    },
                ).json()
                scout = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Email Scout",
                        "role": "Screen emails and pass valuable leads to Story Writer",
                        "role_prompt": "Check inbox for valuable leads and save to story_leads.",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "avatar_icon": "mail",
                        "avatar_color": "blue",
                        "handoff_bot_slug": writer["slug"],
                        "collections": {"read": ["story_leads", "bot_threads"], "write": ["story_leads", "bot_threads"]},
                    },
                ).json()
                self.assertEqual(scout["handoff_bot_slug"], writer["slug"])

                # 3. Chatting with Supervisor injects platform_status & workspace_bots
                sup_msg = client.post(
                    f"/api/bots/{sup['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Give me a morning status overview"},
                )
                self.assertEqual(sup_msg.status_code, 200, sup_msg.text)
                sup_env = captured[-1]["envelope"]
                self.assertIn("platform_status", sup_env)
                self.assertIn("workspace_bots", sup_env)
                teammate_slugs = {b["slug"] for b in sup_env["workspace_bots"]}
                self.assertIn(scout["slug"], teammate_slugs)
                self.assertIn(writer["slug"], teammate_slugs)

                # 4. Running Email Scout deterministically hands off to Story Writer when a lead saves
                trig = client.post(
                    f"/api/bots/{scout['slug']}/trigger",
                    headers=self._sso_headers(),
                    json={"wait_for_chain": True},
                )
                self.assertEqual(trig.status_code, 200, trig.text)

                writer_msgs = client.get(
                    f"/api/bots/{writer['slug']}/messages",
                    headers=self._sso_headers(),
                ).json()
                handoff_reply = next(
                    (
                        m
                        for m in writer_msgs
                        if m["sender"] == "bot"
                        and (m.get("metadata") or {}).get("delegated_by") == scout["slug"]
                    ),
                    None,
                )
                self.assertIsNotNone(handoff_reply)

                pending = client.get(
                    "/api/approvals?tab=pending",
                    headers=self._sso_headers(),
                ).json()
                self.assertTrue(any(a["bot_slug"] == writer["slug"] for a in pending))

                # 5. Blueprint export/import preserves handoff_bot_slug
                bp = client.get(
                    f"/api/bots/{scout['slug']}/blueprint",
                    headers=self._sso_headers(),
                ).json()
                self.assertEqual(bp["handoff_bot_slug"], writer["slug"])

    def test_scheduled_gmail_zero_token_dedup_collections_and_dark_pages(self) -> None:
        llm_calls: list[dict[str, Any]] = []
        observed_exclude_ids: list[set[str] | None] = []
        fake_inbox: list[dict[str, Any]] = [
            {
                "id": "msg_1",
                "thread_id": "thr_1",
                "from": "Dimitri <dimitri@example.com>",
                "to": "ops@company.com",
                "subject": "Weekly Ops Update",
                "date": "Mon, 16 Nov 2026 09:00:00 +0000",
                "snippet": "Quick summary of cluster health.",
                "label_ids": ["INBOX", "UNREAD"],
            }
        ]

        class _FakeIncrementalGmailTransport:
            async def refresh_and_verify(
                self,
                *,
                client_id: str,
                client_secret: str,
                refresh_token: str,
                token_uri: str = "https://oauth2.googleapis.com/token",
            ) -> dict[str, Any]:
                del client_id, client_secret, refresh_token, token_uri
                return {
                    "access_token": "ya29.incr_test",
                    "expiry": "2099-01-01T00:00:00Z",
                    "email": "ops@company.com",
                }

            async def search_gmail_messages(
                self,
                *,
                access_token: str,
                query: str = "",
                max_results: int = 10,
                redact_list: list[str] | None = None,
                exclude_ids: set[str] | None = None,
            ) -> list[dict[str, Any]]:
                del access_token, query, redact_list
                observed_exclude_ids.append(set(exclude_ids) if exclude_ids is not None else None)
                excluded = set(exclude_ids or ())
                return [m for m in fake_inbox[:max_results] if m["id"] not in excluded]

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            unseen = env.get("unseen_ingested_entries") or []
            llm_calls.append({"unseen_count": len(unseen), "subjects": [u.get("subject") for u in unseen]})
            return {
                "text": json.dumps(
                    {
                        "summary": f"Triaged {len(unseen)} new message(s).",
                        "actions": [],
                    }
                ),
                "input_tokens": 85,
                "output_tokens": 25,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                google_transport=_FakeIncrementalGmailTransport(),
            )
            with TestClient(app) as client:
                # 1. Onboard Google + Telegram integrations and create Email bot
                app.state.repo.upsert_integration(
                    slug="business-gmail",
                    provider="google",
                    display_name="Business Gmail",
                    account_identifier="ops@company.com",
                    scopes=["gmail_read"],
                    secrets={
                        "client_id": "cid",
                        "client_secret": "csec",
                        "refresh_token": "1//test_refresh",
                        "access_token": "ya29.incr_test",
                        "expiry": "2099-01-01T00:00:00Z",
                    },
                    status="ok",
                )
                app.state.repo.upsert_integration(
                    slug="ops-tg",
                    provider="telegram",
                    display_name="Ops Telegram",
                    account_identifier="@ops_bot",
                    scopes=["bot"],
                    secrets={"bot_token": "123:abc"},
                    status="ok",
                )
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Dimiz eMail",
                        "role": "Screen unread emails and highlight important messages",
                        "role_prompt": "Check unread Gmail inbox emails and triage important notes.",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "linked_accounts": ["business-gmail"],
                        "tools": [{"type": "builtin", "name": "gmail_search"}],
                    },
                ).json()

                # 2. Collections API immediately discovers bot email collection & telegram_channel_posts
                cols = client.get("/api/collections", headers=self._sso_headers()).json()
                col_by_slug = {c["slug"]: c for c in cols}
                self.assertIn("bot_dimiz-email_items", col_by_slug)
                self.assertIn("telegram_channel_posts", col_by_slug)
                self.assertEqual(col_by_slug["bot_dimiz-email_items"]["owner_bot_slug"], bot["slug"])
                self.assertEqual(col_by_slug["bot_dimiz-email_items"]["owner_bot_name"], "Dimiz eMail")
                self.assertFalse(col_by_slug["bot_dimiz-email_items"]["is_internal"])
                self.assertTrue(col_by_slug["bot_skills"]["is_internal"])
                if "bot_threads" in col_by_slug:
                    self.assertTrue(col_by_slug["bot_threads"]["is_internal"])

                # 3. Cron Run 1 processes unseen email (calls LLM once and records external_key)
                async def _run_cron() -> dict[str, Any]:
                    return await app.state.bot_runner.execute_bot(
                        bot["slug"],
                        trigger_type="cron:rtn_email_sync",
                    )

                res1 = client.portal.call(_run_cron)  # type: ignore[union-attr]
                self.assertEqual(res1["status"], "completed")
                self.assertEqual(len(llm_calls), 1)
                self.assertEqual(llm_calls[0]["unseen_count"], 1)

                # 4. Cron Run 2 with unchanged inbox short-circuits at 0 AI tokens without calling LLM
                res2 = client.portal.call(_run_cron)  # type: ignore[union-attr]
                self.assertEqual(res2["status"], "deduplicated_noop")
                self.assertEqual(res2["tokens_used"], 0)
                self.assertEqual(len(llm_calls), 1)
                self.assertIn("msg_1", observed_exclude_ids[-1] or set())

                # 5. Cron Run 3 when a new email arrives passes exclude_ids={"msg_1"} and triages only msg_2
                fake_inbox.append(
                    {
                        "id": "msg_2",
                        "thread_id": "thr_2",
                        "from": "Alice <alice@example.com>",
                        "to": "ops@company.com",
                        "subject": "Urgent Contract Review",
                        "date": "Mon, 16 Nov 2026 09:30:00 +0000",
                        "snippet": "Please check section 4.",
                        "label_ids": ["INBOX", "UNREAD"],
                    }
                )
                res3 = client.portal.call(_run_cron)  # type: ignore[union-attr]
                self.assertEqual(res3["status"], "completed")
                self.assertEqual(len(llm_calls), 2)
                self.assertEqual(llm_calls[1]["subjects"], ["Urgent Contract Review"])

                # 6. Generated Living Pages use Light/Dark semantic CSS vars (zero gradients / unsafe flags)
                gen = client.post(
                    "/api/pages/generate",
                    headers=self._sso_headers(),
                    json={
                        "title": "Inbox Overview",
                        "prompt": "Show screened messages",
                        "owner_bot_slug": bot["slug"],
                        "allowed_collections": ["bot_dimiz-email_items"],
                        "template_key": "collection_analytics",
                    },
                )
                self.assertEqual(gen.status_code, 201, gen.text)
                html_doc = gen.json()["content_payload"]
                self.assertIn("var(--bg", html_doc)
                self.assertIn("var(--card", html_doc)
                self.assertNotIn("linear-gradient", html_doc)
                self.assertNotIn("allow-same-origin", html_doc.lower())


if __name__ == "__main__":
    unittest.main()
