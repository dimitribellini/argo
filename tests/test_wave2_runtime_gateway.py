"""Comprehensive Wave 2 & ConnectorGateway regression suite (Part 0, Part 1, G-03, P1-1..P1-14)."""

from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import io
import json
import sys
import tempfile
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.analytics.engine import _ingest_spreadsheet_file, _ingest_tabular_file  # noqa: E402
from argo_core.approvals.coordinator import ApprovalCoordinator  # noqa: E402
from argo_core.bus.valkey_bus import CONSUMER_GROUP, STREAM_MAXLEN, STREAM_NAME, EventBus  # noqa: E402
from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.connectors.gateway import (  # noqa: E402
    ConnectorAdapter,
    ConnectorGateway,
    build_default_connector_gateway,
)
from argo_core.connectors.google_oauth import (  # noqa: E402
    DefaultGoogleOAuthTransport,
    GoogleOAuthIntegrationError,
    GoogleOAuthService,
)
from argo_core.connectors.linkedin import LinkedInService  # noqa: E402
from argo_core.connectors.manager import ConnectorManager  # noqa: E402
from argo_core.connectors.telegram_bot import TelegramBotService  # noqa: E402
from argo_core.connectors.telegram_channels import fetch_telegram_public_channel  # noqa: E402
from argo_core.connectors.webhooks import WebhookService  # noqa: E402
from argo_core.db.repositories import ArgoRepository, NotFoundError, utc_now  # noqa: E402
from argo_core.db.sqlite import init_db  # noqa: E402
from argo_core.desktop.manager import DesktopManager, InMemoryDockerDriver  # noqa: E402
from argo_core.desktop.mcp_bridge import DesktopMCPBridge  # noqa: E402
from argo_core.llm.router import (  # noqa: E402
    BudgetExceededError,
    LLMRequest,
    LLMRouter,
    NativeToolsUnsupportedError,
)
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.bot_runner import UniversalBotRunner  # noqa: E402
from argo_core.runner.scheduler import parse_routine_schedule  # noqa: E402
from argo_core.runner.tool_registry import ToolSpec, normalize_native_tool_call  # noqa: E402
from argo_core.security.ssrf import PublicHttpResponse  # noqa: E402
from argo_core.security.vault import SecretVault  # noqa: E402
from argo_core.tools.public_web import extract_web_data  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _RecordingTelegramTransport:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.edited: list[dict[str, Any]] = []
        self.callbacks: list[dict[str, Any]] = []
        self._seq = 500

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        return {"bot_id": 8800, "username": "argo_wave2_bot", "first_name": "Wave2"}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str] | None = None,
    ) -> bool:
        return True

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._seq += 1
        self.sent.append({"chat_id": str(chat_id), "text": text, "reply_markup": reply_markup})
        return {"message_id": self._seq, "chat": {"id": chat_id}}

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.edited.append(
            {"chat_id": str(chat_id), "message_id": int(message_id), "text": text, "reply_markup": reply_markup}
        )
        return {"message_id": message_id, "text": text}

    async def answer_callback_query(
        self,
        bot_token: str,
        *,
        callback_query_id: str,
        text: str = "",
        show_alert: bool = False,
    ) -> bool:
        self.callbacks.append({"id": callback_query_id, "text": text, "show_alert": show_alert})
        return True


def _make_repo(tmpdir: str) -> tuple[ArgoRepository, EventBus, SecretVault]:
    conn = init_db(str(Path(tmpdir) / "wave2.db"))
    vault = SecretVault(Fernet.generate_key().decode("utf-8"))
    repo = ArgoRepository(conn, vault)
    bus = EventBus("valkey://127.0.0.1:1/0", repo)
    return repo, bus, vault


def _build_env_app(
    tmpdir: str,
    *,
    llm_transport: Callable[[LLMRequest], Awaitable[dict[str, Any]]] | None = None,
    telegram_transport: Any | None = None,
    linkedin_transport: Any | None = None,
    google_transport: Any | None = None,
    ssh_transport: Any | None = None,
) -> Any:
    dist_dir = ROOT / "frontend" / "dist"
    settings = ArgoSettings(
        master_key=Fernet.generate_key().decode("utf-8"),
        db_path=str(Path(tmpdir) / "wave2_app.db"),
        valkey_url="valkey://127.0.0.1:1/0",
        desktop_volumes_root=str(Path(tmpdir) / "desktops"),
        public_base_url="http://localhost:4180",
        static_dir=str(dist_dir) if dist_dir.is_dir() else "",
    )
    guard = HostResourceGuard(
        metrics_provider=lambda: {
            "cpu_percent": 15.0,
            "ram_percent": 40.0,
            "ram_total_gb": 16.0,
            "disk_percent": 30.0,
        }
    )
    return create_app(
        settings=settings,
        guard=guard,
        docker_driver=InMemoryDockerDriver(),
        llm_transport=llm_transport,
        telegram_transport=telegram_transport or _RecordingTelegramTransport(),
        linkedin_transport=linkedin_transport,
        google_transport=google_transport,
        ssh_transport=ssh_transport,
    )


def _sso_headers(email: str = "operator@argo.example") -> dict[str, str]:
    return {"X-Auth-Request-Email": email, "X-Auth-Request-User": "Operator"}


class TestWave2RuntimeAndGateway(unittest.IsolatedAsyncioTestCase):
    """Covers Part 0, Part 1 ConnectorGateway, G-03, and P1-1..P1-14."""

    async def test_part0_desktop_boot_and_mcp_ready_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, _ = _make_repo(tmp)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            guard = HostResourceGuard(
                metrics_provider=lambda: {
                    "cpu_percent": 10.0,
                    "ram_percent": 30.0,
                    "ram_total_gb": 16.0,
                    "disk_percent": 20.0,
                }
            )
            driver = InMemoryDockerDriver()
            dm = DesktopManager(
                repo=repo,
                bus=bus,
                guard=guard,
                telegram_service=tg,
                volumes_root=str(Path(tmp) / "desk"),
                driver=driver,
            )
            repo.create_bot(
                name="Chrome Worker",
                slug="chrome-worker",
                role="Browser automation",
                runtime="desktop",
                model="google:gemini-3.8-flash",
                outbound_rbac="draft",
            )
            seen_events: list[dict[str, Any]] = []
            async with bus.subscribe() as sub_q:
                await dm.start_desktop("chrome-worker", correlation_id="selkies_ws")
                while not sub_q.empty():
                    seen_events.append(sub_q.get_nowait())

                class _FakeMCPTransport:
                    async def health(
                        self,
                        bot_slug: str,
                        endpoint: str,
                        *,
                        timeout: float = 4.0,
                    ) -> dict[str, Any]:
                        return {"status": "ok", "endpoint": endpoint}

                mcp = DesktopMCPBridge(desktop_manager=dm, bus=bus, transport=_FakeMCPTransport())
                mcp._use_in_memory_simulation = lambda: False  # type: ignore[method-assign]
                health_res = await mcp.wait_until_ready("chrome-worker", correlation_id="", timeout_seconds=1.0)
                self.assertEqual(health_res["status"], "ok")
                while not sub_q.empty():
                    seen_events.append(sub_q.get_nowait())

            progress_states = [
                (ev.get("state"), ev.get("step"))
                for ev in seen_events
                if ev.get("_sse_event") == "bot_progress"
            ]
            self.assertTrue(any(st == "desktop_boot" for st, _ in progress_states))
            self.assertFalse(any(st == "working" for st, _ in progress_states))
            self.assertTrue(any(st == "desktop_ready" for st, _ in progress_states))

    async def test_part1_custom_connector_adapter_plugs_into_gateway_end_to_end(self) -> None:
        class _SlackAdapter(ConnectorAdapter):
            provider = "slack"
            display_label = "Slack capability match"
            capability_keywords = (r"\bslack\b",)
            tool_names = ("slack_post",)

            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, Any]]] = []

            async def probe(self, account: dict[str, Any], *, send_test_message: bool = False) -> dict[str, Any]:
                self.calls.append(("probe", {"slug": account["slug"], "test": send_test_message}))
                return {"provider": "slack", "status": "ok", "channel": "#ops"}

            async def prepare_draft(self, account: dict[str, Any], *, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
                self.calls.append(("prepare_draft", {"slug": account["slug"], "action": action_type}))
                return {"slack_draft_ts": "1700000001.100"}

            async def dispatch(
                self,
                account: dict[str, Any],
                *,
                action_type: str,
                payload: dict[str, Any],
                final_text: str,
            ) -> dict[str, Any]:
                self.calls.append(("dispatch", {"slug": account["slug"], "text": final_text, "ts": payload.get("slack_draft_ts")}))
                return {"provider": "slack", "ts": "1700000002.200", "text": final_text}

            async def cleanup_draft(self, account: dict[str, Any], *, action_type: str, payload: dict[str, Any]) -> None:
                self.calls.append(("cleanup_draft", {"ts": payload.get("slack_draft_ts")}))

            async def deliver_notification(
                self,
                account: dict[str, Any],
                *,
                approval: dict[str, Any],
                text: str,
                target: str | None = None,
            ) -> dict[str, Any]:
                self.calls.append(("deliver_notification", {"approval_id": approval["id"], "text": text}))
                return {"provider": "slack", "notified": True}

        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, vault = _make_repo(tmp)
            slack = _SlackAdapter()
            gateway = build_default_connector_gateway()
            gateway.register(slack)

            repo.upsert_integration(
                slug="slack-ops",
                provider="slack",
                display_name="Slack Ops",
                account_identifier="#ops",
                secrets={"token": "xoxb-test-token"},
                status="ok",
            )
            router = LLMRouter(repo=repo)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            li = LinkedInService(repo=repo, bus=bus)
            g_svc = GoogleOAuthService(repo=repo, bus=bus, vault=vault)
            wh_svc = WebhookService(repo=repo, bus=bus)
            cm = ConnectorManager(
                repo=repo,
                bus=bus,
                google_service=g_svc,
                telegram_service=tg,
                linkedin_service=li,
                webhook_service=wh_svc,
                gateway=gateway,
            )
            probe_res = await cm.probe_integration("slack-ops", send_test_message=True)
            self.assertEqual(probe_res["provider"], "slack")

            coord = ApprovalCoordinator(
                repo=repo,
                bus=bus,
                llm_router=router,
                telegram_service=tg,
                linkedin_service=li,
                connector_gateway=gateway,
            )
            b_slack = repo.create_bot(
                name="Slack Herald",
                slug="slack-herald",
                role="Post release notes to Slack",
                linked_accounts=["slack-ops"],
                tools=[{"type": "builtin", "name": "slack_post"}],
            )
            b_slack = repo.update_bot("slack-herald", {"linked_accounts_restricted": True})
            b_other = repo.create_bot(
                name="Reader Bot",
                slug="reader-bot",
                role="Read RSS",
                linked_accounts=[],
                tools=[{"type": "builtin", "name": "fetch_rss_feed"}],
            )
            b_other = repo.update_bot("reader-bot", {"linked_accounts_restricted": True})
            runner = UniversalBotRunner(
                repo=repo,
                bus=bus,
                llm_router=router,
                approval_coordinator=coord,
                connector_gateway=gateway,
            )
            routed = runner._match_unique_room_capability(
                "Please share this incident update in slack right now",
                [b_slack, b_other],
            )
            self.assertEqual(routed, ("slack-herald", "Slack capability match"))

            appr1 = await coord.enqueue_human_approval(
                correlation_id="c1",
                bot_slug="slack-herald",
                target_account_slug="slack-ops",
                action_type="slack_post",
                payload={"text": "Release 1.0 live"},
            )
            self.assertEqual(appr1["payload"].get("slack_draft_ts"), "1700000001.100")
            await coord.deliver_approval_notification(approval_id=appr1["id"], account_slug="slack-ops")
            approved = await coord.resolve_approval(appr1["id"], action="approve", actor="tester")
            self.assertEqual(approved["status"], "executed")

            appr2 = await coord.enqueue_human_approval(
                correlation_id="c2",
                bot_slug="slack-herald",
                target_account_slug="slack-ops",
                action_type="slack_post",
                payload={"text": "Cancel draft"},
            )
            rejected = await coord.resolve_approval(appr2["id"], action="reject", actor="tester")
            self.assertEqual(rejected["status"], "rejected")

            call_kinds = [c[0] for c in slack.calls]
            self.assertEqual(
                call_kinds,
                ["probe", "prepare_draft", "deliver_notification", "dispatch", "prepare_draft", "cleanup_draft"],
            )

    async def test_g03_valkey_durable_stream_isolation_maxlen_and_xack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, _ = _make_repo(tmp)
            xadd_calls: list[dict[str, Any]] = []
            xack_calls: list[tuple[str, str, str]] = []
            queued_stream_entries: list[list[Any]] = [
                [
                    (
                        "1700-1",
                        {
                            "payload_json": json.dumps(
                                {
                                    "id": "ev_1",
                                    "correlation_id": "corr_v1",
                                    "source_slug": "webhook-a",
                                    "target_slug": "activity",
                                    "event_type": "custom.ping",
                                    "payload": {"hop_count": 1, "title": "Ping"},
                                }
                            )
                        },
                    )
                ]
            ]

            class _FakeValkeyClient:
                async def ping(self) -> bool:
                    return True

                async def xgroup_create(self, *args: Any, **kwargs: Any) -> None:
                    return None

                async def xadd(self, stream: str, fields: dict[str, Any], **kwargs: Any) -> str:
                    xadd_calls.append({"stream": stream, "fields": fields, "kwargs": kwargs})
                    return "1700-2"

                async def xreadgroup(self, group: str, consumer: str, streams: dict[str, str], **kwargs: Any) -> Any:
                    if queued_stream_entries and streams.get(STREAM_NAME) == "0":
                        batch = queued_stream_entries.pop(0)
                        return [(STREAM_NAME, batch)]
                    await asyncio.sleep(0.02)
                    return []

                async def xack(self, stream: str, group: str, entry_id: str) -> int:
                    xack_calls.append((stream, group, entry_id))
                    return 1

                async def aclose(self) -> None:
                    return None

            fake_client = _FakeValkeyClient()
            fake_valkey_async = type("_FakeValkeyAsyncMod", (), {"from_url": staticmethod(lambda url, **kw: fake_client)})
            fake_valkey_pkg = type("_FakeValkeyPkg", (), {"asyncio": fake_valkey_async})

            with patch.dict(sys.modules, {"valkey": fake_valkey_pkg, "valkey.asyncio": fake_valkey_async}):
                connected = await bus.connect()
            self.assertTrue(connected)

            router = LLMRouter(repo=repo)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            coord = ApprovalCoordinator(repo=repo, bus=bus, llm_router=router, telegram_service=tg, linkedin_service=LinkedInService(repo=repo, bus=bus))
            runner = UniversalBotRunner(repo=repo, bus=bus, llm_router=router, approval_coordinator=coord)

            await bus.publish(
                correlation_id="corr_x",
                source_slug="sys",
                target_slug="activity",
                event_type="test.ev",
                payload={"ok": True},
                hop_count=1,
            )
            self.assertEqual(len(xadd_calls), 1)
            self.assertEqual(xadd_calls[0]["kwargs"].get("maxlen"), STREAM_MAXLEN)
            self.assertTrue(xadd_calls[0]["kwargs"].get("approximate"))

            async with bus.subscribe_durable(consumer_name="test-c") as dq:
                await bus.emit_ephemeral("turn_stream", {"delta": "hello"})
                self.assertTrue(dq.empty())

            await runner.start()
            try:
                await asyncio.sleep(0.08)
            finally:
                await runner.stop()
                await bus.close()

            self.assertIn((STREAM_NAME, CONSUMER_GROUP, "1700-1"), xack_calls)

    async def test_p1_1_and_p1_2_fail_closed_approval_dispatch_gmail_draft_cleanup_and_reply_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, vault = _make_repo(tmp)
            tg_tx = _RecordingTelegramTransport()
            tg_svc = TelegramBotService(repo=repo, bus=bus, transport=tg_tx)
            await tg_svc.onboard_bot(
                bot_token="999000:TEST_TOKEN_ABCDEFGHIJKLMNOPQRST",
                slug="tg-ops",
                operator_chat_id="444555",
                register_webhook=False,
            )

            deleted_drafts: list[str] = []
            sent_emails: list[dict[str, Any]] = []

            class _FakeGoogleTransport:
                async def create_gmail_draft(self, **kwargs: Any) -> dict[str, Any]:
                    return {"draft_id": "dr_123", "message_id": "gm_1"}

                async def send_gmail_message(self, **kwargs: Any) -> dict[str, Any]:
                    sent_emails.append(kwargs)
                    return {"id": "sent_1", "threadId": "th_1"}

                async def delete_gmail_draft(self, *, access_token: str, draft_id: str, redact_list: list[str] | None = None) -> bool:
                    deleted_drafts.append(draft_id)
                    return True

            g_svc = GoogleOAuthService(repo=repo, bus=bus, vault=vault, transport=_FakeGoogleTransport())
            repo.upsert_integration(
                slug="biz-gmail",
                provider="google",
                display_name="Biz Gmail",
                account_identifier="ops@acme.test",
                scopes=["gmail_read", "gmail_send"],
                secrets={
                    "client_id": "cid",
                    "client_secret": "csec",
                    "refresh_token": "1//ref",
                    "access_token": "ya29.valid",
                    "expiry": "2099-01-01T00:00:00Z",
                },
                status="ok",
            )
            fail_llm = {"should_fail": True}

            async def _llm_tx(req: LLMRequest) -> dict[str, Any]:
                if fail_llm["should_fail"]:
                    raise RuntimeError("Upstream 503 during revision")
                return {"text": "Clean revised text", "input_tokens": 5, "output_tokens": 5}

            repo.upsert_model(slug="flash", provider_type="google", model_id="google:gemini-3.8-flash", api_key="k", is_default=True)
            router = LLMRouter(repo=repo, transport=_llm_tx)
            gateway = build_default_connector_gateway(google_service=g_svc, telegram_service=tg_svc)
            coord = ApprovalCoordinator(
                repo=repo,
                bus=bus,
                llm_router=router,
                telegram_service=tg_svc,
                linkedin_service=LinkedInService(repo=repo, bus=bus),
                google_service=g_svc,
                connector_gateway=gateway,
            )

            # 1. Missing connector keeps item pending & recoverable
            missing_apr = await coord.enqueue_human_approval(
                correlation_id="m1",
                bot_slug="bot-a",
                target_account_slug="vanished-connector",
                action_type="publish_telegram",
                payload={"text": "Needs connector"},
            )
            repo.set_approval_telegram_card(missing_apr["id"], chat_id="444555", message_id=701)
            reverted = await coord.resolve_approval(missing_apr["id"], action="approve", actor="op")
            self.assertEqual(reverted["status"], "pending")
            self.assertIn("not found", str(reverted.get("error_message") or "").lower())
            self.assertEqual(tg_tx.edited, [])

            # 2. Failed reply revision must NOT supersede original approval
            g_apr = await coord.enqueue_human_approval(
                correlation_id="g1",
                bot_slug="bot-a",
                target_account_slug="biz-gmail",
                action_type="send_email",
                payload={"to": "client@acme.test", "subject": "Hello", "text": "Draft body"},
            )
            self.assertEqual(g_apr["payload"].get("gmail_draft_id"), "dr_123")
            repo.set_approval_telegram_card(g_apr["id"], chat_id="444555", message_id=702)
            rev_res = await coord.handle_telegram_reply_revision(
                chat_id="444555",
                reply_to_message_id=702,
                instruction_text="make it shorter",
                actor="op",
                telegram_account_slug="tg-ops",
            )
            self.assertIsNone(rev_res)
            self.assertEqual(repo.get_approval(g_apr["id"])["status"], "pending")

            # 3. Approving Gmail email deletes its draft after sending
            sent_res = await coord.resolve_approval(g_apr["id"], action="approve", actor="op")
            self.assertEqual(sent_res["status"], "executed")
            self.assertEqual(deleted_drafts, ["dr_123"])
            self.assertEqual(len(sent_emails), 1)

            # 4. Rejecting Gmail email cleans up its draft
            g_apr2 = await coord.enqueue_human_approval(
                correlation_id="g2",
                bot_slug="bot-a",
                target_account_slug="biz-gmail",
                action_type="send_email",
                payload={"to": "client@acme.test", "subject": "Drop", "text": "Drop body"},
            )
            await coord.resolve_approval(g_apr2["id"], action="reject", actor="op")
            self.assertEqual(deleted_drafts, ["dr_123", "dr_123"])

    async def test_p1_3_and_p1_5_sibling_budget_snapshot_match_compaction_and_tool_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, _ = _make_repo(tmp)
            parent = repo.upsert_model(
                slug="google-flash",
                provider_type="google",
                model_id="google:gemini-3.8-flash",
                api_key="AIzaTestKey123",
                is_default=True,
                daily_token_limit=100,
                monthly_budget_usd=10.0,
                input_price_per_million=1.0,
                output_price_per_million=2.0,
            )
            repo.upsert_model(
                slug="fallback-argon",
                provider_type="google",
                model_id="google:gemini-4-argon",
                api_key="AIzaTestKey123",
            )
            router = LLMRouter(repo=repo)

            # Sibling ephemeral resolution inherits parent budget caps & aggregates usage
            sibling_cands = router._select_candidates(
                requested_model="google:gemini-3.8-flash-lite",
                strict_provider=False,
            )
            self.assertTrue(any(c.get("budget_parent_model_id") == parent["model_id"] for c in sibling_cands))
            repo.record_bot_run(
                correlation_id="c_ephem",
                bot_slug="b1",
                trigger_type="chat_message",
                hop_count=1,
                llm_model_used="google:gemini-3.8-flash-lite",
                input_tokens=120,
                output_tokens=0,
                estimated_cost_usd=0.0,
                status="success",
                summary="ephemeral run",
                started_at=utc_now(),
                finished_at=utc_now(),
            )
            totals = repo.provider_type_ephemeral_usage_totals("google", parent_model_id=parent["model_id"])
            self.assertEqual(totals["today_tokens"], 120)
            with self.assertRaises(BudgetExceededError):
                await router.complete(
                    bot_slug="b1",
                    prompt="Hi",
                    requested_model="google:gemini-3.8-flash-lite",
                    strict_provider=True,
                )

            # Dated snapshot suffix matching
            candidates = [
                {"provider_type": "openai", "model_id": "openai:gpt-4o"},
                {"provider_type": "anthropic", "model_id": "anthropic:claude-3-7-sonnet"},
            ]
            self.assertEqual(router._match_response_model(candidates, "gpt-4o-2024-08-06"), "openai:gpt-4o")
            self.assertEqual(
                router._match_response_model(candidates, "anthropic:claude-3-7-sonnet-20250219"),
                "anthropic:claude-3-7-sonnet",
            )

            # Generic compaction preserves arbitrary list keys & omits interactive_elements
            compacted = LLMRouter._compact_tool_return_value(
                {
                    "type": "gmail_search",
                    "status": "ok",
                    "messages": [{"id": f"m{i}", "subject": f"S{i}"} for i in range(8)],
                    "interactive_elements": [{"index": 0}],
                }
            )
            self.assertEqual(len(compacted["messages"]), 5)
            self.assertEqual(compacted["messages_truncated_from"], 8)
            self.assertNotIn("interactive_elements", compacted)

            # Only the failing candidate named in the error enters _non_tool_models
            router._non_tool_models.clear()
            repo2, _, _ = _make_repo(tmp + "/sub")
            Path(tmp + "/sub").mkdir(exist_ok=True)
            m_no_tools = repo2.upsert_model(
                slug="no-tools",
                provider_type="google",
                model_id="google:no-tools-model",
                api_key="AIzaTestKey123",
                is_default=True,
            )
            m_fallback = repo2.upsert_model(
                slug="fallback-m",
                provider_type="google",
                model_id="google:gemini-4-argon",
                api_key="AIzaTestKey123",
            )
            r2 = LLMRouter(repo=repo2)
            with patch.object(
                r2,
                "_run_native_with_pydantic_ai",
                side_effect=NativeToolsUnsupportedError("no-tools-model does not support function calling"),
            ):
                with self.assertRaises(NativeToolsUnsupportedError):
                    await r2.complete(
                        bot_slug="b1",
                        prompt="hi",
                        requested_model=m_no_tools["model_id"],
                        tools=[
                            ToolSpec(
                                name="ping",
                                description="Ping tool",
                                parameters_json_schema={"type": "object", "properties": {}},
                            )
                        ],
                    )
            self.assertIn(m_no_tools["model_id"], r2._non_tool_models)
            self.assertNotIn(m_fallback["model_id"], r2._non_tool_models)

    async def test_p1_4_room_skills_disabled_bots_handoff_instruction_and_delegation_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, _ = _make_repo(tmp)
            prompts_seen: list[dict[str, Any]] = []
            delay_event = asyncio.Event()

            async def _llm_tx(req: LLMRequest) -> dict[str, Any]:
                env = json.loads(req.user_prompt)
                prompts_seen.append(env)
                if "Slow step" in str((env.get("trigger_payload") or {}).get("input_text") or ""):
                    await asyncio.sleep(0.06)
                return {"text": json.dumps({"summary": "Done", "actions": []}), "input_tokens": 5, "output_tokens": 5}

            repo.upsert_model(slug="flash", provider_type="google", model_id="google:gemini-3.8-flash", api_key="k", is_default=True)
            router = LLMRouter(repo=repo, transport=_llm_tx)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            coord = ApprovalCoordinator(repo=repo, bus=bus, llm_router=router, telegram_service=tg, linkedin_service=LinkedInService(repo=repo, bus=bus))
            runner = UniversalBotRunner(repo=repo, bus=bus, llm_router=router, approval_coordinator=coord)

            repo.upsert_skill(skill_slug="sql-review", name="SQL Review", description="Audit SQL queries", instructions="ALWAYS check LIMIT")
            b1 = repo.create_bot(name="Lead", slug="lead-bot", role="Coordinator", model="google:gemini-3.8-flash")
            b2 = repo.create_bot(name="Worker", slug="worker-bot", role="Worker", model="google:gemini-3.8-flash")
            repo.update_bot("worker-bot", {"enabled": False})

            room = repo.create_room(title="Ops Room", member_bot_slugs=["lead-bot", "worker-bot"], coordinator_bot_slug="lead-bot")
            repo.append_room_message(
                room["slug"],
                sender_type="bot",
                sender_slug="worker-bot",
                sender_name="Worker",
                text="Paused handoff",
                metadata={"pending_room_handoff": {"target_bot_slug": "lead-bot", "instruction": "EXACT_HANDOFF_INSTR"}},
            )
            turn_res = await runner.execute_room_turn(
                room["slug"],
                user_text="",
                approved_handoff_bot_slug="lead-bot",
                skill_slugs=["sql-review"],
            )
            self.assertEqual(turn_res["status"], "completed")
            self.assertEqual(len(turn_res["results"]), 1)
            self.assertEqual(turn_res["results"][0]["bot_slug"], "lead-bot")
            self.assertIn("EXACT_HANDOFF_INSTR", str((prompts_seen[-1].get("trigger_payload") or {}).get("input_text") or ""))
            active_sk = [s["slug"] for s in (prompts_seen[-1].get("available_skills") or [])]
            self.assertIn("sql-review", active_sk)

            # Delegation plan rejects status=='running', filters disabled bots, & supports cancel_run
            plan_running = repo.save_delegation_plan(
                {
                    "id": "plan_busy",
                    "coordinator_slug": "lead-bot",
                    "goal": "Busy",
                    "status": "running",
                    "steps": [{"id": "s1", "bot_slug": "lead-bot", "task": "Hi", "parallel_group": 1}],
                }
            )
            with self.assertRaises(ValueError):
                await runner.execute_delegation_plan(plan_running["id"])

            plan_cancel = repo.save_delegation_plan(
                {
                    "id": "plan_cancel",
                    "coordinator_slug": "lead-bot",
                    "goal": "Cancel mid-way",
                    "status": "proposed",
                    "steps": [
                        {"id": "s1", "bot_slug": "worker-bot", "task": "Should be skipped disabled", "parallel_group": 1},
                        {"id": "s2", "bot_slug": "lead-bot", "task": "Slow step one", "parallel_group": 1},
                        {"id": "s3", "bot_slug": "lead-bot", "task": "Group two never runs", "parallel_group": 2},
                    ],
                }
            )

            async def _cancel_soon() -> None:
                while not any(item.target_slug == "lead-bot" for item in runner._runs_by_id.values()):
                    await asyncio.sleep(0.01)
                for rid in list(runner._runs_by_id.keys()):
                    await runner.cancel_run(rid)

            canceller = asyncio.create_task(_cancel_soon())
            cancel_res = await runner.execute_delegation_plan(plan_cancel["id"])
            await canceller
            self.assertEqual(cancel_res["status"], "cancelled")
            self.assertEqual(repo.get_delegation_plan("plan_cancel")["status"], "cancelled")

    async def test_p1_6_relative_schedule_freezing_and_seconds_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, _ = _make_repo(tmp)
            b = repo.create_bot(
                name="OneShot Freeze",
                slug="oneshot-freeze",
                role="Tester",
                routines=[{"id": "r1", "label": "In 15m", "schedule": "In 15m", "timezone": "UTC", "enabled": True}],
            )
            self.assertRegex(b["routines"][0]["schedule"], r"^Once at \d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
            self.assertTrue(b["routines"][0]["one_shot"])

            p_sec = parse_routine_schedule("In 30s", "UTC")
            assert p_sec is not None
            self.assertRegex(p_sec["normalized"], r"^Once at \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

            p_explicit = parse_routine_schedule("Once at 2026-11-22 14:05:30", "UTC")
            assert p_explicit is not None
            self.assertEqual(p_explicit["normalized"], "Once at 2026-11-22 14:05:30")

    async def test_p1_7_atomic_lock_owner_check_and_periodic_renewal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, _ = _make_repo(tmp)
            self.assertTrue(await bus.acquire_lock("bot_run", "k1", "owner-1", ttl_seconds=60))
            self.assertFalse(await bus.renew_lock("bot_run", "k1", "wrong-owner", ttl_seconds=60))
            self.assertFalse(await bus.release_lock("bot_run", "k1", "wrong-owner"))
            self.assertTrue(await bus.renew_lock("bot_run", "k1", "owner-1", ttl_seconds=120))
            self.assertTrue(await bus.release_lock("bot_run", "k1", "owner-1"))

            # Verify periodic renew_lock during slow execute_bot
            repo.upsert_model(slug="flash", provider_type="google", model_id="google:gemini-3.8-flash", api_key="k", is_default=True)

            async def _slow_llm(req: LLMRequest) -> dict[str, Any]:
                await asyncio.sleep(0.08)
                return {"text": json.dumps({"summary": "Slept well", "actions": []}), "input_tokens": 5, "output_tokens": 5}

            router = LLMRouter(repo=repo, transport=_slow_llm)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            coord = ApprovalCoordinator(repo=repo, bus=bus, llm_router=router, telegram_service=tg, linkedin_service=LinkedInService(repo=repo, bus=bus))
            runner = UniversalBotRunner(repo=repo, bus=bus, llm_router=router, approval_coordinator=coord)
            runner.BOT_RUN_LOCK_RENEW_SECONDS = 0.02  # type: ignore[misc]
            repo.create_bot(name="Slow Bot", slug="slow-bot", role="Slow task", model="google:gemini-3.8-flash")

            renew_owners: list[str] = []
            orig_renew = bus.renew_lock

            async def _spy_renew(rt: str, rid: str, owner: str, ttl_seconds: int = 300) -> bool:
                renew_owners.append(owner)
                return await orig_renew(rt, rid, owner, ttl_seconds=ttl_seconds)

            bus.renew_lock = _spy_renew  # type: ignore[method-assign]
            res = await runner.execute_bot("slow-bot", trigger_type="chat_message", trigger_payload={"input_text": "go"})
            self.assertEqual(res["status"], "completed")
            self.assertGreaterEqual(len(renew_owners), 1)
            self.assertEqual(bus._fallback_locks, {})

    def test_p1_8_and_p1_14_deletes_blueprints_teampacks_and_vault_clear_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tg_tx = _RecordingTelegramTransport()
            app = _build_env_app(tmp, telegram_transport=tg_tx)
            with TestClient(app) as client:
                repo: ArgoRepository = app.state.repo
                client.post(
                    "/api/integrations/telegram/onboard",
                    headers=_sso_headers(),
                    json={"bot_token": "881122:TEST_TOKEN_0123456789ABCDEF", "slug": "tg-ops", "operator_chat_id": "555111", "register_webhook": False},
                )
                repo.create_bot(name="Del Target", slug="del-target", role="Will be deleted", daily_cap=0)
                repo.create_bot(name="Peer A", slug="peer-a", role="Peer A")
                repo.create_bot(name="Peer B", slug="peer-b", role="Peer B")
                room2 = repo.create_room(title="Two Bot Room", member_bot_slugs=["del-target", "peer-a"], coordinator_bot_slug="del-target")
                room3 = repo.create_room(title="Three Bot Room", member_bot_slugs=["del-target", "peer-a", "peer-b"], coordinator_bot_slug="del-target")

                apr = repo.create_approval(
                    correlation_id="cdel",
                    bot_slug="del-target",
                    target_account_slug="tg-ops",
                    action_type="publish_telegram",
                    payload={"text": "Pending card"},
                )
                repo.set_approval_telegram_card(apr["id"], chat_id="555111", message_id=909)

                closed_sids: list[str] = []
                app.state.ssh_manager.list_sessions = lambda bot_slug=None: [{"id": "ssh_s1", "bot_slug": "del-target"}] if bot_slug == "del-target" else []  # type: ignore[method-assign]

                async def _fake_close(sid: str) -> None:
                    closed_sids.append(sid)

                app.state.ssh_manager.close_session = _fake_close  # type: ignore[method-assign]

                del_res = client.delete("/api/bots/del-target", headers=_sso_headers())
                self.assertEqual(del_res.status_code, 200)
                self.assertEqual(closed_sids, ["ssh_s1"])
                self.assertEqual(len(tg_tx.edited), 1)
                self.assertEqual(tg_tx.edited[0]["message_id"], 909)
                remaining_slugs = {r["slug"] for r in repo.list_rooms()}
                self.assertNotIn(room2["slug"], remaining_slugs)
                self.assertIn(room3["slug"], remaining_slugs)

                # Collection deletion deletes analytics/<slug>
                repo.upsert_document(collection="temp-metrics", external_key="m1", search_text="temp", doc={"v": 1})
                ana_dir = repo.analytics_dir_for_collection("temp-metrics")
                ana_dir.mkdir(parents=True, exist_ok=True)
                (ana_dir / "main.parquet").write_bytes(b"PAR1")
                repo.delete_collection("temp-metrics")
                self.assertFalse(ana_dir.exists())

                # Blueprint export/import preserves daily_cap=0, skill_slugs, connector_policies
                repo.upsert_skill(skill_slug="ops-check", name="Ops Check", description="d", instructions="i", scope_slug="peer-a")
                repo.update_bot(
                    "peer-a",
                    {
                        "daily_cap": 0,
                        "routines": [{"id": "rt1", "label": "Ops", "schedule": "Manual", "skill_slugs": ["ops-check"]}],
                        "tools": [{"type": "builtin", "name": "send_email", "account": "gmail-a", "target": "lead@acme.test", "rbac": "draft"}],
                    },
                )
                bp = repo.export_bot_blueprint("peer-a")
                self.assertEqual(bp["daily_cap"], 0)
                self.assertIn("connector_policies", bp)

                # Collision Team Pack export/import remaps bot_<old>_items -> bot_<new>_items and skills
                repo.create_page(
                    title="Peer A Board",
                    owner_bot_slug="peer-a",
                    render_mode="declarative_json",
                    content_payload=json.dumps({"queries": [{"id": "q", "sql": "SELECT * FROM bot_peer-a_items LIMIT 5"}]}),
                    allowed_collections=["bot_peer-a_items"],
                )
                pack = repo.export_team_pack(room_slugs=[room3["slug"]])
                imported_pack = repo.import_team_pack(pack)
                imported_a = next(b for b in imported_pack["bots"] if b["slug"].startswith("peer-a-"))
                self.assertNotEqual(imported_a["slug"], "peer-a")
                new_items_col = f"bot_{imported_a['slug']}_items"
                self.assertIn(new_items_col, imported_a["collections"]["write"])
                imported_skills = [s["slug"] for s in repo.list_skills(scope_slug=imported_a["slug"])]
                self.assertIn(imported_a["routines"][0]["skill_slugs"][0], imported_skills)
                imported_pg = imported_pack["pages"][0]
                self.assertIn(new_items_col, imported_pg["allowed_collections"])
                self.assertIn(new_items_col, str(imported_pg.get("content_payload") or ""))

                # Vault clear_fields clears sudo_password while preserving password
                client.post(
                    "/api/vault",
                    headers=_sso_headers(),
                    json={"name": "Host A", "slug": "host-a", "secret_type": "ssh", "host": "10.0.0.1", "secrets": {"username": "root", "password": "pw1", "sudo_password": "spw"}},
                )
                patch_res = client.patch(
                    "/api/vault/host-a",
                    headers=_sso_headers(),
                    json={"secrets": {"username": "admin"}, "clear_fields": ["sudo_password"]},
                )
                self.assertEqual(patch_res.status_code, 200, patch_res.text)
                dec = repo.get_vault_secret_decrypted("host-a")
                assert dec is not None
                self.assertEqual(dec["secrets"]["username"], "admin")
                self.assertEqual(dec["secrets"]["password"], "pw1")
                self.assertNotIn("sudo_password", dec["secrets"])

    async def test_p1_9_native_schemas_skipped_invalid_action_and_mcp_actions(self) -> None:
        norm = normalize_native_tool_call(
            "request_human_approval",
            {
                "action_type": "send_email",
                "text": "Body text",
                "to": "to@acme.test",
                "cc": "cc@acme.test",
                "bcc": "bcc@acme.test",
                "subject": "Quarterly Update",
                "thread_id": "t_1",
                "in_reply_to": "<msg@acme.test>",
                "payload_json": json.dumps({"extra": "val"}),
            },
        )
        self.assertEqual(norm["bcc"], "bcc@acme.test")
        self.assertEqual(norm["to"], "to@acme.test")
        self.assertEqual(norm["payload"]["extra"], "val")

        click_norm = normalize_native_tool_call("desktop_click", {"target": "Save", "double": True})
        self.assertTrue(click_norm["double"])

        rtn_norm = normalize_native_tool_call("configure_routine", {"operation": "upsert", "label": "Mail", "schedule": "Manual", "source_query": "is:unread"})
        self.assertEqual(rtn_norm["source_query"], "is:unread")

        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, _ = _make_repo(tmp)
            tg = TelegramBotService(repo=repo, bus=bus, transport=_RecordingTelegramTransport())
            repo.create_bot(name="Desk B", slug="desk-b", role="Browser", runtime="desktop")
            mcp = DesktopMCPBridge(desktop_manager=DesktopManager(repo=repo, bus=bus, guard=HostResourceGuard(), telegram_service=tg, driver=InMemoryDockerDriver()), bus=bus)
            await mcp._desktop_manager.start_desktop("desk-b")
            foc = await mcp.execute_action("desk-b", "focus_window", {"window_id": "0x01a00003"})
            self.assertEqual(foc["status"], "ok")
            dbl = await mcp.execute_action("desk-b", "click", {"target": "Icon", "double": True})
            self.assertTrue(dbl.get("double"))

            # Invalid action with empty text -> skipped_invalid_action recorded (never fake ok)
            repo.upsert_model(slug="flash", provider_type="google", model_id="google:gemini-3.8-flash", api_key="k", is_default=True)
            router = LLMRouter(repo=repo)
            coord = ApprovalCoordinator(repo=repo, bus=bus, llm_router=router, telegram_service=tg, linkedin_service=LinkedInService(repo=repo, bus=bus))
            runner = UniversalBotRunner(repo=repo, bus=bus, llm_router=router, approval_coordinator=coord)
            bot = repo.create_bot(name="Invalid Tester", slug="inv-bot", role="Tester")
            by_call: dict[str, list[dict[str, Any]]] = {}
            exec_res = await runner._execute_actions(
                bot=bot,
                actions=[{"type": "send_email", "to": "nobody@acme.test", "_tool_call_id": "tc_bad"}],
                correlation_id="c_inv",
                hop_count=1,
                trigger_type="chat_message",
                out_results_by_call_id=by_call,
            )
            self.assertEqual(exec_res[0]["status"], "skipped_invalid_action")
            self.assertEqual(by_call["tc_bad"][0]["status"], "skipped_invalid_action")

    async def test_p1_10_analytics_limits_and_async_file_web_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "sample.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["region", "revenue"])
                writer.writerow(["EMEA", "4200"])
            derived = Path(tmp) / "derived"
            derived.mkdir()
            res = _ingest_tabular_file(csv_path, derived, file_id="f1", ext=".csv", mime_type="text/csv", vault_secrets=[])
            self.assertEqual(res["derived_datasets"][0]["row_count"], 1)

            import zipfile

            xlsx_path = Path(tmp) / "book.xlsx"
            with zipfile.ZipFile(xlsx_path, "w") as zf:
                zf.writestr(
                    "[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                    '<Default Extension="xml" ContentType="application/xml"/>'
                    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                    '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                    '</Types>',
                )
                zf.writestr(
                    "_rels/.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                    '</Relationships>',
                )
                zf.writestr(
                    "xl/workbook.xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                    '<sheets><sheet name="Orders" sheetId="1" r:id="rId1"/></sheets>'
                    '</workbook>',
                )
                zf.writestr(
                    "xl/_rels/workbook.xml.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                    '</Relationships>',
                )
                zf.writestr(
                    "xl/worksheets/sheet1.xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                    '<sheetData>'
                    '<row r="1"><c r="A1" t="inlineStr"><is><t>sku</t></is></c><c r="B1" t="inlineStr"><is><t>qty</t></is></c></row>'
                    '<row r="2"><c r="A2" t="inlineStr"><is><t>A1</t></is></c><c r="B2"><v>7</v></c></row>'
                    '</sheetData>'
                    '</worksheet>',
                )
            derived_x = Path(tmp) / "derived_x"
            derived_x.mkdir()
            x_res = _ingest_spreadsheet_file(xlsx_path, derived_x, file_id="f2", vault_secrets=[])
            self.assertEqual(x_res["derived_datasets"][0]["row_count"], 1)

            app = _build_env_app(tmp)
            with TestClient(app) as client:
                b64 = base64.b64encode(b"col1,col2\n1,2\n").decode("ascii")
                up = client.post("/api/files", headers=_sso_headers(), json={"filename": "u.csv", "mime_type": "text/csv", "content_base64": b64})
                self.assertIn(up.status_code, (200, 201), up.text)

            class _FakeFetcher:
                async def fetch(self, url: str, **kwargs: Any) -> PublicHttpResponse:
                    html_doc = (
                        "<html><body><table>"
                        "<thead><tr><th>k</th><th>v</th></tr></thead>"
                        "<tbody><tr><td>x</td><td>10</td></tr><tr><td>y</td><td>20</td></tr></tbody>"
                        "</table></body></html>"
                    )
                    return PublicHttpResponse(url=url, status_code=200, headers={"content-type": "text/html"}, body=html_doc, raw_bytes=html_doc.encode("utf-8"))

            repo, _, _ = _make_repo(tmp + "/web")
            Path(tmp + "/web").mkdir(exist_ok=True)
            ext_res = await extract_web_data(
                url="https://example.org/table.html",
                target_collection="web_tables",
                fetcher=_FakeFetcher(),
                repo=repo,
                bot_slug="collector",
            )
            self.assertEqual(ext_res["status"], "ok")

    async def test_p1_11_google_oversized_raise_pagination_and_token_refresh(self) -> None:
        # 1. Oversized HTTP response raises instead of mid-JSON truncation
        class _FakeResp:
            def __init__(self, body: bytes) -> None:
                self._buf = body
                self._pos = 0

            def read(self, n: int = -1) -> bytes:
                chunk = self._buf[self._pos : self._pos + n] if n >= 0 else self._buf[self._pos :]
                self._pos += len(chunk)
                return chunk

            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *args: Any) -> None:
                return None

        with patch("urllib.request.urlopen", return_value=_FakeResp(b"0123456789ABCDEFG")):
            with self.assertRaises(GoogleOAuthIntegrationError):
                DefaultGoogleOAuthTransport._http_google_bytes("GET", "https://gmail.googleapis.com/test", "ya29.t", max_bytes=16, allow_truncate=False)

        # 2. search_gmail_messages paginates across nextPageToken
        tx = DefaultGoogleOAuthTransport()
        pages_requested: list[str] = []

        def _fake_gmail_json(method: str, url: str, token: str, **kwargs: Any) -> dict[str, Any]:
            pages_requested.append(url)
            if "/messages?" in url and "pageToken=p2" not in url:
                return {"messages": [{"id": "seen1"}], "nextPageToken": "p2"}
            if "pageToken=p2" in url:
                return {"messages": [{"id": "fresh1"}]}
            return {
                "id": "fresh1",
                "threadId": "th_f1",
                "snippet": "Unread item",
                "payload": {"headers": [{"name": "Subject", "value": "Fresh Subj"}, {"name": "From", "value": "a@b.test"}], "body": {"data": ""}},
            }

        with patch.object(tx, "_http_gmail_json", side_effect=_fake_gmail_json):
            msgs = await tx.search_gmail_messages(access_token="t", max_results=1, exclude_ids={"seen1"})
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["id"], "fresh1")

        # 3. _ensure_access_token refreshes expired token & preserves rotated refresh_token
        with tempfile.TemporaryDirectory() as tmp:
            repo, bus, vault = _make_repo(tmp)
            class _RefreshTx:
                async def refresh_and_verify(
                    self,
                    *,
                    client_id: str,
                    client_secret: str,
                    refresh_token: str,
                    token_uri: str = "",
                ) -> dict[str, Any]:
                    return {"access_token": "ya29.new_tok", "expires_in": 3600, "refresh_token": "1//rotated_ref"}

            svc = GoogleOAuthService(repo=repo, bus=bus, vault=vault, transport=_RefreshTx())
            repo.upsert_integration(
                slug="g-exp",
                provider="google",
                display_name="Expired Google",
                secrets={
                    "client_id": "cid",
                    "client_secret": "csec",
                    "refresh_token": "1//old_ref",
                    "access_token": "ya29.old_tok",
                    "token_expiry": "2020-01-01T00:00:00Z",
                },
                status="ok",
            )
            _, new_tok, _ = await svc._ensure_access_token("g-exp")
            self.assertEqual(new_tok, "ya29.new_tok")
            stored = repo.get_integration_secrets("g-exp")["secrets"]
            self.assertEqual(stored["refresh_token"], "1//rotated_ref")

    def test_p1_12_and_p1_13_webhooks_413_dedup_linkedin_escape_and_empty_tg_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            li_payloads: list[dict[str, Any]] = []

            class _FakeLinkedInTx:
                async def create_post(
                    self,
                    access_token: str,
                    *,
                    linkedin_version: str,
                    payload: dict[str, Any],
                ) -> dict[str, Any]:
                    li_payloads.append(payload)
                    return {"id": "urn:li:share:1", "status_code": 201}

            app = _build_env_app(tmp, linkedin_transport=_FakeLinkedInTx())
            with TestClient(app) as client:
                repo: ArgoRepository = app.state.repo
                secret = "whsec_test_123456"
                repo.upsert_integration(slug="wh-in", provider="webhook", display_name="Inbound", secrets={"signing_secret": secret}, status="ok")

                body = json.dumps({"id": "evt_signed_1", "text": "hello"}).encode("utf-8")
                sig = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

                r1 = client.post("/hooks/webhook/wh-in", content=body, headers={"X-Argo-Signature-256": sig, "X-Request-Id": "spoof-1"})
                self.assertEqual(r1.status_code, 200, r1.text)
                self.assertEqual(r1.json()["status"], "accepted")

                # Different X-Request-Id but SAME signed payload -> caught as duplicate replay!
                r2 = client.post("/hooks/webhook/wh-in", content=body, headers={"X-Argo-Signature-256": sig, "X-Request-Id": "spoof-2"})
                self.assertEqual(r2.status_code, 200)
                self.assertEqual(r2.json()["status"], "duplicate_ignored")

                # Oversized body (> 1 MB) returns HTTP 413 cleanly
                huge = b"{" + (b"x" * 1_100_000) + b"}"
                r_big = client.post("/hooks/webhook/wh-in", content=huge, headers={"X-Argo-Signature-256": sig})
                self.assertEqual(r_big.status_code, 413)
                r_tg_big = client.post("/hooks/telegram/tg-missing", content=huge)
                self.assertEqual(r_tg_big.status_code, 413)

                # LinkedIn Little Text escaping
                repo.upsert_integration(slug="li-main", provider="linkedin", display_name="LinkedIn", secrets={"access_token": "tok", "author_urn": "urn:li:person:1"}, status="ok")
                li_res = asyncio.run(app.state.linkedin_service.publish_post("li-main", commentary="Hello [Team] (v2.0) *fast*!"))
                self.assertEqual(li_res["id"], "urn:li:share:1")
                self.assertIn(r"\[Team\] \(v2.0\) \*fast\*", li_payloads[0]["commentary"])

        # Empty / preview-disabled Telegram HTML does not crash lxml
        class _EmptyHtmlFetcher:
            async def fetch(self, url: str, **kwargs: Any) -> PublicHttpResponse:
                return PublicHttpResponse(url=url, status_code=200, headers={"content-type": "text/html"}, body="   ", raw_bytes=b"   ")

        posts = asyncio.run(fetch_telegram_public_channel("@emptychan", fetcher=_EmptyHtmlFetcher()))
        self.assertEqual(posts, [])
