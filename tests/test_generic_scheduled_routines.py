"""Tests for provider-agnostic ConnectorGateway polling, generic routine execution modes (poll/task/action), and 0-token scheduled actions."""

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
from argo_core.connectors.gateway import (  # noqa: E402
    ConnectorAdapter,
    ConnectorPollContext,
    ConnectorPollResult,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.scheduler import BotScheduler  # noqa: E402
from argo_core.runner.tool_registry import (  # noqa: E402
    all_tool_specs,
    normalize_native_tool_call,
    validate_gemini_safe_schema,
)
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _SlackStubAdapter(ConnectorAdapter):
    """Non-built-in stub connector verifying Argo core works symmetrically without provider-specific branches."""

    provider = "slack"
    display_label = "Slack capability match"
    capability_keywords = (r"\bslack\b",)
    tool_names = ("publish_slack",)
    action_types = ("publish_slack",)

    def __init__(self) -> None:
        self.probes: list[str] = []
        self.drafts: list[dict[str, Any]] = []
        self.dispatches: list[dict[str, Any]] = []
        self.inbound_messages: list[dict[str, Any]] = []
        self._draft_seq = 0

    def normalize_action_payload(
        self,
        action_type: str,
        action: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        extra, target = super().normalize_action_payload(action_type, action)
        channel = str(action.get("channel") or target or "#general").strip()
        meta = dict(extra or {})
        meta["channel"] = channel
        if action.get("thread_ts"):
            meta["thread_ts"] = str(action["thread_ts"])
        return meta, channel

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        del send_test_message
        self.probes.append(account["slug"])
        return {"status": "ok", "provider": "slack"}

    async def prepare_draft(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self._draft_seq += 1
        draft_id = f"slk_dr_{self._draft_seq}"
        self.drafts.append(
            {
                "draft_id": draft_id,
                "account": account["slug"],
                "action_type": action_type,
                "payload": dict(payload),
            }
        )
        return {"external_draft_id": draft_id}

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        entry = {
            "account": account["slug"],
            "action_type": action_type,
            "channel": payload.get("channel") or payload.get("target") or "#general",
            "text": final_text,
        }
        self.dispatches.append(entry)
        return {"provider": "slack", "target": entry["channel"], "ts": f"170000.{len(self.dispatches)}"}

    def supports_poll(
        self,
        account: dict[str, Any],
        bot: dict[str, Any],
        routine: dict[str, Any] | None = None,
    ) -> bool:
        del account, routine
        tools = {
            t.get("name") if isinstance(t, dict) else str(t)
            for t in (bot.get("tools") or [])
        }
        return "slack_poll" in tools or "publish_slack" in tools

    async def poll(
        self,
        account: dict[str, Any],
        *,
        ctx: ConnectorPollContext,
    ) -> ConnectorPollResult:
        entries: list[dict[str, Any]] = []
        fetched = 0
        for msg in self.inbound_messages:
            mid = str(msg["id"])
            ext_key = f"slack:{account['slug']}:{mid}"
            fetched += 1
            if ctx.is_seen(ext_key, include_collection=True):
                continue
            doc = {
                "source_type": "slack",
                "account_slug": account["slug"],
                "channel": msg.get("channel", "#general"),
                "text": msg.get("text", ""),
                "author": msg.get("author", "teammate"),
            }
            entries.append(
                {
                    **doc,
                    "external_key": ext_key,
                    "seen_key": ext_key,
                    "_persist": {
                        "search_text": f"{doc['channel']} {doc['author']} {doc['text']}",
                        "doc": doc,
                        "description": f"Slack message ingested for {ctx.bot_slug}",
                    },
                }
            )
        return ConnectorPollResult(
            polled=True,
            entries=entries,
            total_fetched=fetched,
            dedup_skipped=0,
        )


class _RecordingGoogleTransport:
    """In-memory Gmail transport capturing searches, drafts, and direct sends."""

    def __init__(self) -> None:
        self.gmail_messages: list[dict[str, Any]] = []
        self.created_drafts: list[dict[str, Any]] = []
        self.sent_messages: list[dict[str, Any]] = []
        self.deleted_drafts: list[str] = []
        self.search_calls = 0

    async def refresh_and_verify(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "access_token": "ya29.test_access",
            "expiry": "2099-01-01T00:00:00Z",
            "email": "dimiz.dubai@gmail.com",
        }

    async def search_gmail_messages(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.search_calls += 1
        excluded = set(kwargs.get("exclude_ids") or ())
        return [m for m in self.gmail_messages if m.get("id") not in excluded]

    async def search_drive_files(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {"files": [], "next_page_token": None}

    async def read_drive_file_excerpt(self, **kwargs: Any) -> dict[str, Any]:
        return {"id": str(kwargs.get("file_id") or ""), "excerpt": ""}

    async def list_calendar_events(self, **kwargs: Any) -> list[dict[str, Any]]:
        del kwargs
        return []

    async def create_gmail_draft(self, **kwargs: Any) -> dict[str, Any]:
        draft_id = f"dr_test_{len(self.created_drafts) + 1}"
        rec = {
            "draft_id": draft_id,
            "message_id": f"gm_{len(self.created_drafts) + 1}",
            "to": kwargs.get("to_email", ""),
            "subject": kwargs.get("subject", ""),
            "body_text": kwargs.get("body_text", ""),
        }
        self.created_drafts.append(rec)
        return rec

    async def send_gmail_message(self, **kwargs: Any) -> dict[str, Any]:
        rec = {
            "message_id": f"sent_{len(self.sent_messages) + 1}",
            "to": kwargs.get("to_email", ""),
            "subject": kwargs.get("subject", ""),
            "body_text": kwargs.get("body_text", ""),
        }
        self.sent_messages.append(rec)
        return rec

    async def delete_gmail_draft(self, **kwargs: Any) -> bool:
        self.deleted_drafts.append(str(kwargs.get("draft_id") or ""))
        return True


def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
    return {
        "X-Auth-Request-Email": email,
        "X-Auth-Request-User": email.split("@", 1)[0],
    }


def _build_app(
    tmpdir: str,
    *,
    llm_transport: Any = None,
    google_transport: Any = None,
) -> Any:
    static_dir = Path(tmpdir) / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
    settings = ArgoSettings(
        master_key=Fernet.generate_key().decode("ascii"),
        db_path=str(Path(tmpdir) / "generic_routines.db"),
        valkey_url="valkey://127.0.0.1:1/0",
        desktop_volumes_root=str(Path(tmpdir) / "desktops"),
        workspace_files_root=str(Path(tmpdir) / "workspace_files"),
        public_base_url="https://argo.example.com",
        static_dir=str(static_dir),
    )
    guard = HostResourceGuard(
        metrics_provider=lambda: {
            "ram_percent": 30.0,
            "ram_total_gb": 16.0,
            "cpu_percent": 10.0,
            "disk_percent": 20.0,
        },
        alert_cooldown_seconds=0.0,
    )
    return create_app(
        settings=settings,
        guard=guard,
        llm_transport=llm_transport,
        google_transport=google_transport,
    )


class TestGenericScheduledRoutines(unittest.TestCase):
    """Verify integration-agnostic polling, 0-token action fast-path, and task fallback."""

    def test_configure_routine_native_schema_and_normalization(self) -> None:
        cfg_spec = next(s for s in all_tool_specs() if s.name == "configure_routine")
        self.assertEqual(validate_gemini_safe_schema(cfg_spec.parameters_json_schema, tool_name="configure_routine"), [])
        self.assertIn("mode", cfg_spec.parameters_json_schema.get("properties", {}))
        self.assertIn("action_json", cfg_spec.parameters_json_schema.get("properties", {}))
        self.assertNotIn("gmail_query", cfg_spec.parameters_json_schema.get("properties", {}))
        self.assertNotIn("inbox_query", cfg_spec.parameters_json_schema.get("properties", {}))

        normalized = normalize_native_tool_call(
            "configure_routine",
            {
                "operation": "add",
                "label": "Send Standup Ping",
                "schedule": "Once at 2099-11-22 09:00",
                "timezone": "Asia/Dubai",
                "mode": "action",
                "action_json": json.dumps(
                    {
                        "action_type": "publish_slack",
                        "account": "slack-eng",
                        "channel": "#standup",
                        "text": "Good morning team!",
                    }
                ),
            },
        )
        self.assertEqual(normalized["operation"], "add")
        self.assertEqual(normalized["mode"], "action")
        self.assertEqual(normalized["action"]["action_type"], "publish_slack")
        self.assertEqual(normalized["action"]["channel"], "#standup")

    def test_custom_adapter_polling_and_zero_token_action_rbac_enforcement(self) -> None:
        slack_adapter = _SlackStubAdapter()
        slack_adapter.inbound_messages = [
            {"id": "m_1", "channel": "#alerts", "author": "alice", "text": "Build 42 passed"}
        ]
        llm_calls: list[str] = []

        async def slack_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            llm_calls.append(str(env.get("trigger_type") or ""))
            user_txt = str(env.get("task") or "")
            if "schedule standup slack ping" in user_txt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "Scheduled one-shot Slack ping.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "operation": "add",
                                    "label": "One-Time Standup Ping",
                                    "schedule": "Once at 2099-11-22 21:46",
                                    "timezone": "Asia/Dubai",
                                    "mode": "action",
                                    "action": {
                                        "action_type": "publish_slack",
                                        "account": "slack-eng",
                                        "channel": "#standup",
                                        "text": "Standup starting in 5m",
                                    },
                                }
                            ],
                        }
                    ),
                    "input_tokens": 12,
                    "output_tokens": 15,
                }
            if "bad action" in user_txt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "Attempted invalid action routine.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "operation": "add",
                                    "label": "Disallowed Shell Routine",
                                    "schedule": "Once at 2099-11-22 22:00",
                                    "mode": "action",
                                    "action": {
                                        "action_type": "ssh_exec",
                                        "vault_slug": "prod",
                                        "command": "whoami",
                                    },
                                }
                            ],
                        }
                    ),
                    "input_tokens": 8,
                    "output_tokens": 8,
                }
            return {
                "text": json.dumps({"summary": "Reviewed Slack poll updates.", "actions": []}),
                "input_tokens": 10,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(tmp, llm_transport=slack_llm)
            with TestClient(app) as client:
                app.state.connector_gateway.register(slack_adapter)
                app.state.repo.upsert_integration(
                    slug="slack-eng",
                    provider="slack",
                    display_name="Engineering Slack",
                    account_identifier="#standup",
                    secrets={"token": "xoxb-custom-stub"},
                    status="ok",
                )
                created = client.post(
                    "/api/bots",
                    headers=_sso_headers(),
                    json={
                        "slug": "slack-ops",
                        "name": "Slack Ops",
                        "role": "Monitor Slack alerts and send team reminders",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "linked_accounts_restricted": True,
                        "linked_accounts": ["slack-eng"],
                        "tools": [{"type": "builtin", "name": "publish_slack"}],
                        "routines": [
                            {
                                "id": "rtn_slack_poll",
                                "type": "cron",
                                "label": "Scheduled Sync",
                                "schedule": "Every 15m",
                                "mode": "poll",
                                "enabled": True,
                            }
                        ],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)

                # 1. Generic ConnectorGateway.poll works for custom adapter & deduplicates Run 2
                poll1 = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops",
                        trigger_type="cron:rtn_slack_poll",
                        routine_id="rtn_slack_poll",
                    )
                )
                self.assertEqual(poll1["status"], "completed")
                col = next(c for c in created.json()["collections"]["write"] if c != "bot_threads")
                self.assertIsNotNone(app.state.repo.get_document_by_external_key(col, "slack:slack-eng:m_1"))

                poll2 = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops",
                        trigger_type="cron:rtn_slack_poll",
                        routine_id="rtn_slack_poll",
                    )
                )
                self.assertEqual(poll2["status"], "deduplicated_noop")
                self.assertEqual(poll2["tokens_used"], 0)

                # 2. Schedule separate 0-token action routine via chat -> keeps rtn_slack_poll intact
                chat_res = client.post(
                    "/api/bots/slack-ops/messages",
                    headers=_sso_headers(),
                    json={"text": "Please schedule standup slack ping"},
                )
                self.assertEqual(chat_res.status_code, 200, chat_res.text)
                bot_now = client.get("/api/bots/slack-ops", headers=_sso_headers()).json()
                self.assertEqual(len(bot_now["routines"]), 2)
                action_rtn = next(r for r in bot_now["routines"] if r["label"] == "One-Time Standup Ping")
                self.assertEqual(action_rtn["mode"], "action")
                self.assertTrue(action_rtn["one_shot"])
                self.assertEqual(action_rtn["stale_data_policy"], "always_run")
                poll_rtn = next(r for r in bot_now["routines"] if r["id"] == "rtn_slack_poll")
                self.assertTrue(poll_rtn["enabled"])

                # 3. Fire one-shot action via BotScheduler under Ask First (draft) -> 0 LLM calls, queues approval + draft
                llm_calls_before = len(llm_calls)
                sched = BotScheduler(repo=app.state.repo, runner=app.state.bot_runner)
                asyncio.run(sched._run_scheduled_routine("slack-ops", action_rtn["id"]))
                self.assertEqual(len(llm_calls), llm_calls_before)
                self.assertEqual(len(slack_adapter.drafts), 1)
                self.assertEqual(slack_adapter.drafts[0]["payload"]["channel"], "#standup")
                self.assertEqual(len(slack_adapter.dispatches), 0)

                pending = client.get("/api/approvals?tab=pending", headers=_sso_headers()).json()
                self.assertEqual(len(pending), 1)
                self.assertEqual(pending[0]["action_type"], "publish_slack")
                self.assertEqual(pending[0]["payload"]["external_draft_id"], "slk_dr_1")

                bot_after = client.get("/api/bots/slack-ops", headers=_sso_headers()).json()
                done_action_rtn = next(r for r in bot_after["routines"] if r["id"] == action_rtn["id"])
                self.assertFalse(done_action_rtn["enabled"])
                self.assertTrue(done_action_rtn.get("completed_at"))
                still_poll = next(r for r in bot_after["routines"] if r["id"] == "rtn_slack_poll")
                self.assertTrue(still_poll["enabled"])

                latest_run = app.state.repo.list_bot_runs(bot_slug="slack-ops", limit=1)[0]
                self.assertEqual(latest_run["input_tokens"], 0)
                self.assertEqual(latest_run["output_tokens"], 0)
                self.assertEqual(latest_run["llm_model_used"], "deterministic:action")

                # 4. Auto-Send (execute) dispatches cleanly in 0 tokens, and secret-leak downgrades to approval
                exec_rtn_id = "rtn_exec_slack"
                leak_rtn_id = "rtn_leak_slack"
                client.patch(
                    "/api/bots/slack-ops",
                    headers=_sso_headers(),
                    json={
                        "outbound_rbac": "execute",
                        "tools": [
                            {"type": "builtin", "name": "publish_slack"},
                            {
                                "type": "account",
                                "slug": "slack-eng",
                                "capability": "execute",
                                "max_calls_per_day": 10,
                            },
                        ],
                        "routines": [
                            still_poll,
                            {
                                "id": exec_rtn_id,
                                "type": "cron",
                                "mode": "action",
                                "label": "Auto Slack Dispatch",
                                "schedule": "Every 1h",
                                "enabled": True,
                                "action": {
                                    "action_type": "publish_slack",
                                    "account": "slack-eng",
                                    "channel": "#releases",
                                    "text": "Release v1.0 healthy.",
                                },
                            },
                            {
                                "id": leak_rtn_id,
                                "type": "cron",
                                "mode": "action",
                                "label": "Leaky Action",
                                "schedule": "Every 1h",
                                "enabled": True,
                                "action": {
                                    "action_type": "publish_slack",
                                    "account": "slack-eng",
                                    "channel": "#releases",
                                    "text": "Token leak sk-secretkey1234567890abcdef",
                                },
                            },
                        ],
                    },
                )
                exec_res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type=f"cron:{exec_rtn_id}", routine_id=exec_rtn_id
                    )
                )
                self.assertEqual(exec_res["status"], "completed")
                self.assertEqual(exec_res["tokens_used"], 0)
                self.assertEqual(len(slack_adapter.dispatches), 1)
                self.assertEqual(slack_adapter.dispatches[0]["channel"], "#releases")

                leak_res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type=f"cron:{leak_rtn_id}", routine_id=leak_rtn_id
                    )
                )
                self.assertEqual(leak_res["tokens_used"], 0)
                self.assertEqual(leak_res["actions"][0]["outcome"], "downgraded_to_approval")
                self.assertEqual(len(slack_adapter.dispatches), 1)

                # 5. RBAC internal blocks 0-token action, disabled bot skips, unlinked integration blocks
                client.patch("/api/bots/slack-ops", headers=_sso_headers(), json={"outbound_rbac": "internal"})
                blocked_res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type=f"cron:{exec_rtn_id}", routine_id=exec_rtn_id
                    )
                )
                self.assertEqual(blocked_res["status"], "blocked_rbac")
                self.assertEqual(blocked_res["tokens_used"], 0)

                client.patch(
                    "/api/bots/slack-ops",
                    headers=_sso_headers(),
                    json={"outbound_rbac": "execute", "linked_accounts": []},
                )
                unlinked_res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type=f"cron:{exec_rtn_id}", routine_id=exec_rtn_id
                    )
                )
                self.assertEqual(unlinked_res["status"], "blocked_unlinked_account")
                self.assertEqual(unlinked_res["tokens_used"], 0)

                client.patch(
                    "/api/bots/slack-ops",
                    headers=_sso_headers(),
                    json={"enabled": False, "linked_accounts": ["slack-eng"]},
                )
                disabled_res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type=f"cron:{exec_rtn_id}", routine_id=exec_rtn_id
                    )
                )
                self.assertEqual(disabled_res["status"], "skipped_disabled")

                # 6. Disallowed non-connector actions (e.g. ssh_exec) blocked both in configure_routine and runtime
                client.patch("/api/bots/slack-ops", headers=_sso_headers(), json={"enabled": True})
                bad_cfg = client.post(
                    "/api/bots/slack-ops/messages",
                    headers=_sso_headers(),
                    json={"text": "bad action"},
                )
                self.assertEqual(bad_cfg.status_code, 200, bad_cfg.text)
                bad_act_res = bad_cfg.json()["messages"][-1]["metadata"]["actions"][0]
                self.assertEqual(bad_act_res["status"], "blocked_invalid_action")

                app.state.repo.update_bot(
                    "slack-ops",
                    {
                        "routines": [
                            {
                                "id": "rtn_bad_ssh",
                                "type": "cron",
                                "mode": "action",
                                "label": "Injected Non-Connector",
                                "schedule": "Manual",
                                "enabled": True,
                                "action": {"action_type": "ssh_exec", "command": "rm -rf /"},
                            }
                        ]
                    },
                )
                runtime_bad = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "slack-ops", trigger_type="cron:rtn_bad_ssh", routine_id="rtn_bad_ssh"
                    )
                )
                self.assertEqual(runtime_bad["status"], "blocked_invalid_action")
                self.assertEqual(runtime_bad["tokens_used"], 0)

    def test_scheduled_email_action_mode_and_task_fallback_on_monitoring_bot(self) -> None:
        google_transport = _RecordingGoogleTransport()
        google_transport.gmail_messages = [
            {
                "id": "gm_unread_1",
                "thread_id": "th_1",
                "from": "newsletter@example.com",
                "to": "dimiz.dubai@gmail.com",
                "subject": "Unrelated Monthly Digest",
                "snippet": "Lots of unrelated newsletters...",
                "body_excerpt": "Long email content that should not flood one-shot tasks.",
                "label_ids": ["INBOX", "UNREAD"],
            }
        ]

        captured_task_prompts: list[dict[str, Any]] = []

        async def mail_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            trig = str(env.get("trigger_type") or "")
            task_txt = str(env.get("task") or "")

            if "configure deterministic email" in task_txt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "Scheduled one-shot email.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "operation": "add",
                                    "label": "Send Test Email",
                                    "schedule": "Once at 2099-11-22 21:46",
                                    "timezone": "Asia/Dubai",
                                    "mode": "action",
                                    "action": {
                                        "action_type": "send_email",
                                        "account": "google-dimiz-dubai-gmail-com",
                                        "to": "dimitri.bellini@gmail.com",
                                        "subject": "test",
                                        "text": "test",
                                    },
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 25,
                }

            if "schedule dynamic email task" in task_txt.lower():
                return {
                    "text": json.dumps(
                        {
                            "summary": "Scheduled one-shot email task.",
                            "actions": [
                                {
                                    "type": "configure_routine",
                                    "label": "Dynamic Test Email Task",
                                    "schedule": "Once at 2099-11-22 21:50",
                                    "timezone": "Asia/Dubai",
                                    "prompt": "Send an email to dimitri.bellini@gmail.com with subject 'test-task' and body 'test-task'",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 25,
                }

            if trig.startswith("cron:") and env.get("execution_mode") == "task":
                captured_task_prompts.append(env)
                return {
                    "text": json.dumps(
                        {
                            "summary": "Prepared your scheduled email draft.",
                            "actions": [
                                {
                                    "type": "send_email",
                                    "account": "google-dimiz-dubai-gmail-com",
                                    "to": "dimitri.bellini@gmail.com",
                                    "subject": "test-task",
                                    "text": "test-task",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 20,
                }

            return {"text": json.dumps({"summary": "Inbox summary.", "actions": []})}

        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(tmp, llm_transport=mail_llm, google_transport=google_transport)
            with TestClient(app) as client:
                app.state.repo.upsert_integration(
                    slug="google-dimiz-dubai-gmail-com",
                    provider="google",
                    display_name="dimiz dubai",
                    account_identifier="Dimiz.Dubai@Gmail.Com",
                    scopes=["gmail_read", "gmail_send"],
                    secrets={
                        "client_id": "cid",
                        "client_secret": "csec",
                        "refresh_token": "1//refresh",
                        "access_token": "ya29.test_access",
                    },
                    status="ok",
                )
                created = client.post(
                    "/api/bots",
                    headers=_sso_headers(),
                    json={
                        "slug": "dimiz-email",
                        "name": "Dimiz eMail",
                        "role": "Monitor incoming emails in dimiz.dubai@gmail.com",
                        "role_prompt": "Monitor and triage incoming emails cleanly. Summarize inbox updates.",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "linked_accounts_restricted": True,
                        "linked_accounts": ["google-dimiz-dubai-gmail-com"],
                        "tools": [{"type": "builtin", "name": "gmail_search"}],
                        "routines": [
                            {
                                "id": "rtn_sync_mail",
                                "type": "cron",
                                "label": "Scheduled Sync",
                                "schedule": "Every 15m",
                                "mode": "poll",
                                "enabled": True,
                            }
                        ],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                col = next(c for c in created.json()["collections"]["write"] if c != "bot_threads")
                app.state.repo.upsert_document(
                    collection=col,
                    external_key="old_doc_1",
                    search_text="Old cached mail summary",
                    doc={"subject": "Old cached item"},
                )

                # A. Mode='action' scheduled email alongside recurring sync
                res_a = client.post(
                    "/api/bots/dimiz-email/messages",
                    headers=_sso_headers(),
                    json={"text": "configure deterministic email"},
                )
                self.assertEqual(res_a.status_code, 200, res_a.text)
                bot_a = client.get("/api/bots/dimiz-email", headers=_sso_headers()).json()
                self.assertEqual(len(bot_a["routines"]), 2)
                action_rtn = next(r for r in bot_a["routines"] if r["label"] == "Send Test Email")

                searches_before = google_transport.search_calls
                sched = BotScheduler(repo=app.state.repo, runner=app.state.bot_runner)
                asyncio.run(sched._run_scheduled_routine("dimiz-email", action_rtn["id"]))
                # Did NOT pre-poll Gmail and used 0 LLM tokens; created Approval Card + Gmail Draft
                self.assertEqual(google_transport.search_calls, searches_before)
                self.assertEqual(len(google_transport.created_drafts), 1)
                self.assertEqual(google_transport.created_drafts[0]["to"], "dimitri.bellini@gmail.com")
                self.assertEqual(google_transport.created_drafts[0]["subject"], "test")
                self.assertEqual(len(google_transport.sent_messages), 0)
                aprs = client.get("/api/approvals?tab=pending", headers=_sso_headers()).json()
                self.assertEqual(len(aprs), 1)
                self.assertEqual(aprs[0]["payload"]["gmail_draft_id"], "dr_test_1")

                # Recurring sync remained intact & enabled
                bot_b = client.get("/api/bots/dimiz-email", headers=_sso_headers()).json()
                sync_rtn = next(r for r in bot_b["routines"] if r["id"] == "rtn_sync_mail")
                self.assertTrue(sync_rtn["enabled"])

                # When Auto-Send (execute) is enabled, scheduled action sends directly
                client.patch(
                    "/api/bots/dimiz-email",
                    headers=_sso_headers(),
                    json={
                        "outbound_rbac": "execute",
                        "tools": [
                            {"type": "builtin", "name": "gmail_search"},
                            {
                                "type": "account",
                                "slug": "google-dimiz-dubai-gmail-com",
                                "capability": "execute",
                                "max_calls_per_day": 10,
                            },
                        ],
                        "routines": [
                            sync_rtn,
                            {
                                "id": "rtn_direct_mail",
                                "type": "once",
                                "one_shot": True,
                                "mode": "action",
                                "label": "Direct Test Send",
                                "schedule": "Once at 2099-11-22 21:48",
                                "enabled": True,
                                "action": {
                                    "action_type": "send_email",
                                    "account": "google-dimiz-dubai-gmail-com",
                                    "to": "dimitri.bellini@gmail.com",
                                    "subject": "direct-test",
                                    "text": "direct body",
                                },
                            },
                        ],
                    },
                )
                asyncio.run(sched._run_scheduled_routine("dimiz-email", "rtn_direct_mail"))
                self.assertEqual(len(google_transport.sent_messages), 1)
                self.assertEqual(google_transport.sent_messages[0]["subject"], "direct-test")

                # B. Mode='task' fallback (no action payload, just one-shot prompt) on Ask First bot
                client.patch(
                    "/api/bots/dimiz-email",
                    headers=_sso_headers(),
                    json={
                        "outbound_rbac": "draft",
                        "tools": [
                            {"type": "builtin", "name": "gmail_search"},
                            {
                                "type": "account",
                                "slug": "google-dimiz-dubai-gmail-com",
                                "capability": "draft",
                                "max_calls_per_day": 0,
                            },
                        ],
                    },
                )
                res_task_cfg = client.post(
                    "/api/bots/dimiz-email/messages",
                    headers=_sso_headers(),
                    json={"text": "schedule dynamic email task"},
                )
                self.assertEqual(res_task_cfg.status_code, 200, res_task_cfg.text)
                bot_c = client.get("/api/bots/dimiz-email", headers=_sso_headers()).json()
                task_rtn = next(r for r in bot_c["routines"] if r["label"] == "Dynamic Test Email Task")
                self.assertEqual(task_rtn["mode"], "task")
                self.assertEqual(task_rtn["stale_data_policy"], "always_run")

                searches_before_task = google_transport.search_calls
                task_run = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "dimiz-email",
                        trigger_type=f"cron:{task_rtn['id']}",
                        routine_id=task_rtn["id"],
                    )
                )
                self.assertEqual(task_run["status"], "completed")
                # Did NOT pre-poll Gmail inbox or dump bulk collection docs
                self.assertEqual(google_transport.search_calls, searches_before_task)
                self.assertEqual(len(captured_task_prompts), 1)
                env_keys = list(captured_task_prompts[0].keys())
                self.assertEqual(env_keys[0], "task")
                self.assertEqual(env_keys[1], "execution_mode")
                self.assertEqual(captured_task_prompts[0]["execution_mode"], "task")
                self.assertIn("dimitri.bellini@gmail.com", captured_task_prompts[0]["task"])
                self.assertEqual(captured_task_prompts[0]["unseen_ingested_entries"], [])
                self.assertEqual(captured_task_prompts[0]["permitted_collection_documents"], [])
                # Created Gmail Draft #2 cleanly on Turn 1
                self.assertEqual(len(google_transport.created_drafts), 2)
                self.assertEqual(google_transport.created_drafts[1]["subject"], "test-task")
                # Reply logged in 1:1 thread (not swallowed by skip_thread_log)
                msgs_now = client.get("/api/bots/dimiz-email/messages", headers=_sso_headers()).json()
                self.assertIn("Prepared your scheduled email draft", msgs_now[-1]["text"])


if __name__ == "__main__":
    unittest.main()
