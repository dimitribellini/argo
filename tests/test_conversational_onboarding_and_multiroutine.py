"""End-to-end tests for P0-1 (Proactive Conversational Onboarding & Self-Tuning) and P0-2 (Test-First -> Habit Proposal -> Multiple Named Routines)."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.scheduler import BotScheduler, parse_routine_schedule  # noqa: E402
from argo_core.security.ssrf import PublicHttpResponse, validate_public_url  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _StaticFeedFetcher:
    """In-memory RSS fetcher with configurable response."""

    def __init__(self) -> None:
        self.xml_body = (
            '<?xml version="1.0"?>'
            "<rss version='2.0'><channel><title>Release Feed</title>"
            "<item><title>Argo 2.0 Release</title><link>https://example.org/release-2</link>"
            "<description>Multi-bot rooms shipped.</description></item>"
            "</channel></rss>"
        )

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        del headers, timeout_seconds, max_redirects, max_bytes
        validate_public_url(url, resolver=lambda _host: ["93.184.216.34"])
        return PublicHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "application/rss+xml"},
            body=self.xml_body,
        )


class TestConversationalOnboardingAndMultiRoutine(unittest.TestCase):
    """Verify proactive onboarding, self-config gating, and named multi-routines."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None, http_fetcher=None):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 35.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 10.0,
                "disk_percent": 25.0,
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
            public_http_fetcher=http_fetcher,
        )

    def test_quick_hire_onboarding_interview_and_configured_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                configured = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"name": "Classic Bot", "role": "Check feeds"},
                )
                self.assertEqual(configured.status_code, 201, configured.text)
                self.assertFalse(configured.json()["onboarding_pending"])
                c_msgs = client.get(
                    f"/api/bots/{configured.json()['slug']}/messages",
                    headers=self._sso_headers(),
                ).json()
                self.assertTrue(c_msgs[0]["text"].startswith("Ready!"))

                interview = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Scout Helper",
                        "onboarding_mode": "interview",
                        "avatar_color": "blue",
                        "avatar_icon": "rss",
                    },
                )
                self.assertEqual(interview.status_code, 201, interview.text)
                bot_data = interview.json()
                self.assertTrue(bot_data["onboarding_pending"])

                msgs = client.get(
                    f"/api/bots/{bot_data['slug']}/messages",
                    headers=self._sso_headers(),
                ).json()
                self.assertEqual(len(msgs), 1)
                self.assertTrue(msgs[0]["metadata"].get("onboarding_interview"))
                self.assertGreaterEqual(len(msgs[0]["metadata"].get("quick_replies", [])), 2)
                self.assertIn("Scout Helper", msgs[0]["text"])

    def test_natural_speech_self_tuning_and_escalation_approval(self) -> None:
        async def self_tuning_llm(req: LLMRequest) -> dict[str, Any]:
            if "auto-send" in req.user_prompt.lower() or "desktop" in req.user_prompt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "I've requested permission to switch to Auto-Send and enable a Virtual Desktop.",
                            "actions": [
                                {
                                    "type": "update_self_config",
                                    "role_prompt": "Monitor release announcements and auto-post approved updates.",
                                    "add_boundaries": ["Never fabricate metrics"],
                                    "outbound_rbac": "execute",
                                    "runtime": "desktop",
                                    "onboarding_pending": False,
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
                        "summary": "Updated my role instructions, added your safety boundary, and linked handoff.",
                        "actions": [
                            {
                                "type": "update_self_config",
                                "role": "Screen tech releases and flag breaking changes",
                                "role_prompt": "Check release RSS daily and keep bullets under 3 lines.",
                                "add_boundaries": ["Never summarize press releases"],
                                "handoff_bot_slug": "partner-writer",
                                "onboarding_pending": False,
                            }
                        ],
                    }
                ),
                "input_tokens": 18,
                "output_tokens": 22,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=self_tuning_llm)
            with TestClient(app) as client:
                writer = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "partner-writer", "name": "Partner Writer", "role": "Draft posts"},
                )
                self.assertEqual(writer.status_code, 201)

                bot_res = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"name": "Release Scout", "onboarding_mode": "interview"},
                )
                self.assertEqual(bot_res.status_code, 201)
                slug = bot_res.json()["slug"]

                # Turn 1: safe conversational self-tuning applies immediately
                r1 = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={
                        "text": "Watch release RSS daily, never summarize press releases, and hand off to partner-writer."
                    },
                )
                self.assertEqual(r1.status_code, 200, r1.text)
                bot_after_1 = client.get(f"/api/bots/{slug}", headers=self._sso_headers()).json()
                self.assertEqual(bot_after_1["role"], "Screen tech releases and flag breaking changes")
                self.assertIn("Never summarize press releases", bot_after_1["boundaries"])
                self.assertEqual(bot_after_1["handoff_bot_slug"], "partner-writer")
                self.assertFalse(bot_after_1["onboarding_pending"])
                self.assertEqual(bot_after_1["outbound_rbac"], "draft")

                last_msg = r1.json()["messages"][-1]
                self.assertTrue(last_msg["metadata"].get("applied_changes"))

                # Turn 2: privilege & runtime escalation MUST queue approval in argo_workspace
                r2 = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Switch yourself to auto-send and enable a Virtual Desktop browser."},
                )
                self.assertEqual(r2.status_code, 200, r2.text)

                bot_before_approve = client.get(f"/api/bots/{slug}", headers=self._sso_headers()).json()
                self.assertEqual(bot_before_approve["outbound_rbac"], "draft")
                self.assertEqual(bot_before_approve["runtime"], "api")

                pending = client.get("/api/approvals?tab=pending", headers=self._sso_headers()).json()
                cfg_aprs = [
                    a
                    for a in pending
                    if a["target_account_slug"] == "argo_workspace"
                    and a["action_type"] == "update_bot_config"
                ]
                self.assertEqual(len(cfg_aprs), 1)
                apr_id = cfg_aprs[0]["id"]

                # Approve & Apply
                resolved = client.post(
                    f"/api/approvals/{apr_id}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve"},
                )
                self.assertEqual(resolved.status_code, 200, resolved.text)
                self.assertEqual(resolved.json()["status"], "executed")

                bot_after_approve = client.get(f"/api/bots/{slug}", headers=self._sso_headers()).json()
                self.assertEqual(bot_after_approve["outbound_rbac"], "execute")
                self.assertEqual(bot_after_approve["runtime"], "desktop")

    def test_multi_routine_calendar_timezones_stale_policy_and_habit_proposal(self) -> None:
        parsed_cal = parse_routine_schedule("Every weekday at 08:30", "America/New_York")
        self.assertEqual(
            parsed_cal,
            {
                "kind": "cron",
                "minute": "30",
                "hour": "8",
                "day": "*",
                "month": "*",
                "day_of_week": "mon-fri",
                "raw": "Every weekday at 08:30",
                "timezone": "America/New_York",
            },
        )

        # Verify APScheduler passes ZoneInfo("America/New_York")
        recorded_triggers: dict[str, Any] = {}

        class FakeScheduler:
            def __init__(self, timezone="UTC") -> None:
                pass

            def start(self) -> None:
                pass

            def shutdown(self, wait=False) -> None:
                pass

            def add_job(self, func, *, trigger, id, **kwargs) -> None:
                del func, kwargs
                recorded_triggers[id] = trigger

            def remove_job(self, job_id) -> None:
                recorded_triggers.pop(job_id, None)

        fake_ap = types.ModuleType("apscheduler")
        fake_sched = types.ModuleType("apscheduler.schedulers")
        fake_async = types.ModuleType("apscheduler.schedulers.asyncio")
        fake_trig = types.ModuleType("apscheduler.triggers")
        fake_cron = types.ModuleType("apscheduler.triggers.cron")
        fake_int = types.ModuleType("apscheduler.triggers.interval")
        fake_async.AsyncIOScheduler = FakeScheduler  # type: ignore[attr-defined]
        fake_cron.CronTrigger = lambda **kw: ("cron", kw)  # type: ignore[attr-defined]
        fake_int.IntervalTrigger = lambda **kw: ("interval", kw)  # type: ignore[attr-defined]

        fetcher = _StaticFeedFetcher()

        async def multi_routine_llm(req: LLMRequest) -> dict[str, Any]:
            if "every monday" in req.user_prompt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "Added your second named routine: Monday Morning Digest.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "operation": "upsert",
                                    "label": "Monday Morning Digest",
                                    "schedule": "Every Monday at 09:00",
                                    "timezone": "America/New_York",
                                    "prompt": "Summarize top release items for Monday standup.",
                                    "stale_data_policy": "notify_missing",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 20,
                }
            if "tool_observations" not in req.user_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Fetching the release RSS feed now...",
                            "actions": [
                                {"type": "fetch_rss_feed", "url": "https://example.org/rss.xml"}
                            ],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 15,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Found Argo 2.0 Release and saved it.",
                        "actions": [
                            {
                                "type": "upsert_document",
                                "collection": "bot_feed_watcher_items",
                                "external_key": "https://example.org/release-2",
                                "search_text": "Argo 2.0 Release",
                                "doc": {"title": "Argo 2.0 Release"},
                            }
                        ],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 18,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=multi_routine_llm, http_fetcher=fetcher)
            with TestClient(app) as client:
                created = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "feed-watcher",
                        "name": "Feed Watcher",
                        "role": "Watch RSS feed",
                        "role_prompt": "Check https://example.org/rss.xml for updates.",
                        "tools": [{"type": "builtin", "name": "fetch_rss_feed", "url": "https://example.org/rss.xml"}],
                        "routines": [
                            {
                                "id": "rtn_main",
                                "type": "cron",
                                "label": "Weekday Morning Poll",
                                "schedule": "Every weekday at 08:30",
                                "timezone": "America/New_York",
                                "stale_data_policy": "notify_missing",
                                "enabled": True,
                            }
                        ],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)

                # Step 1: Test-first interactive task emits habit_proposal
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    chat1 = client.post(
                        "/api/bots/feed-watcher/messages",
                        headers=self._sso_headers(),
                        json={"text": "Fetch https://example.org/rss.xml and save new releases."},
                    )
                self.assertEqual(chat1.status_code, 200, chat1.text)
                last_bot_msg = chat1.json()["messages"][-1]
                habit = last_bot_msg["metadata"].get("habit_proposal")
                self.assertIsNotNone(habit)
                self.assertIn("suggested_routine_label", habit)

                # Step 2: Add a second named routine conversationally
                chat2 = client.post(
                    "/api/bots/feed-watcher/messages",
                    headers=self._sso_headers(),
                    json={"text": "Run a second routine every Monday at 9am America/New_York for Monday Digest."},
                )
                self.assertEqual(chat2.status_code, 200, chat2.text)

                bot_now = client.get("/api/bots/feed-watcher", headers=self._sso_headers()).json()
                self.assertEqual(len(bot_now["routines"]), 2)
                labels = {r["label"]: r for r in bot_now["routines"]}
                self.assertIn("Monday Morning Digest", labels)
                self.assertEqual(labels["Monday Morning Digest"]["timezone"], "America/New_York")
                self.assertEqual(labels["Monday Morning Digest"]["stale_data_policy"], "notify_missing")

                # Step 3: Trigger routine once to record seen key, then second trigger sees 0 new items -> notify_missing posts 0-token notice
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    first_poll = client.post(
                        "/api/bots/feed-watcher/trigger",
                        headers=self._sso_headers(),
                        json={"routine_id": "rtn_main"},
                    )
                    self.assertEqual(first_poll.status_code, 200, first_poll.text)
                    sched_res = client.post(
                        "/api/bots/feed-watcher/trigger",
                        headers=self._sso_headers(),
                        json={"routine_id": "rtn_main"},
                    )
                self.assertEqual(sched_res.status_code, 200, sched_res.text)
                self.assertEqual(sched_res.json()["status"], "deduplicated_noop")
                self.assertEqual(sched_res.json()["tokens_used"], 0)
                thread_msgs = client.get(
                    "/api/bots/feed-watcher/messages",
                    headers=self._sso_headers(),
                ).json()
                self.assertIn("0 new items", thread_msgs[-1]["text"])

                # Verify ZoneInfo propagation in BotScheduler while FastAPI SQLite is open
                with patch.dict(
                    sys.modules,
                    {
                        "apscheduler": fake_ap,
                        "apscheduler.schedulers": fake_sched,
                        "apscheduler.schedulers.asyncio": fake_async,
                        "apscheduler.triggers": fake_trig,
                        "apscheduler.triggers.cron": fake_cron,
                        "apscheduler.triggers.interval": fake_int,
                    },
                ):
                    sched = BotScheduler(repo=app.state.repo, runner=app.state.bot_runner)
                    asyncio.run(sched.start())
                    self.assertEqual(len(recorded_triggers), 2)
                    trig_kind, trig_kwargs = recorded_triggers["feed-watcher::rtn_main"]
                    self.assertEqual(trig_kind, "cron")
                    self.assertEqual(str(trig_kwargs["timezone"]), "America/New_York")
                    self.assertEqual(trig_kwargs["day_of_week"], "mon-fri")
                    asyncio.run(sched.stop())


if __name__ == "__main__":
    unittest.main()
