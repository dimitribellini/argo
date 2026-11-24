"""Comprehensive test suite for Native PydanticAI Tool Calling (Step 2)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.db.sqlite import init_db  # noqa: E402
from argo_core.db.repositories import ArgoRepository  # noqa: E402
from argo_core.desktop.cdp_bridge import CDPPageSnapshot  # noqa: E402
from argo_core.desktop.manager import InMemoryDockerDriver  # noqa: E402
from argo_core.llm.router import (  # noqa: E402
    LLMExecutionError,
    LLMRequest,
    LLMRouter,
    NativeToolCall,
    NativeToolsUnsupportedError,
)
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.tool_registry import (  # noqa: E402
    all_tool_specs,
    build_bot_tool_specs,
    normalize_native_tool_call,
    validate_gemini_safe_schema,
)
from argo_core.security.ssrf import PublicHttpResponse  # noqa: E402
from argo_core.security.vault import SecretVault  # noqa: E402
from argo_core.ssh.manager import InMemorySSHTransport  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeWebFetcher:
    """Deterministic web fetcher returning Zabbix repo HTML or arbitrary page content."""

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
            body=(
                "<html><head><title>Zabbix 8.0 RHEL 9 Packages</title></head>"
                "<body><h1>zabbix-agent2-8.0.0beta2</h1><p>No final GA release yet.</p></body></html>"
            ),
        )


class _FakeTelegramTransport:
    """In-memory Telegram Bot API transport counting outbound deliveries."""

    def __init__(self) -> None:
        self.sent_messages: list[dict[str, Any]] = []
        self._seq = 500

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        del bot_token
        return {"bot_id": 991100, "username": "argo_native_tg_bot", "first_name": "Argo Native"}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str] | None = None,
    ) -> bool:
        del bot_token, url, secret_token, allowed_updates
        return True

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del bot_token
        self._seq += 1
        rec = {
            "chat_id": str(chat_id),
            "message_id": self._seq,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.sent_messages.append(rec)
        return {"message_id": self._seq, "chat_id": str(chat_id)}


class _FakeDesktopAgentTransport:
    """Minimal XFCE Desktop MCP transport returning deterministic 4x3 PNG screenshots."""

    def __init__(self) -> None:
        self.png_bytes = b"\x89PNG\r\n\x1a\nFAKE_DESKTOP_SCREENSHOT_BYTES"
        self.screenshot_calls = 0

    async def health(self, bot_slug: str, endpoint: str, *, timeout: float = 5.0) -> dict[str, Any]:
        del bot_slug, endpoint, timeout
        return {"status": "ok", "agent_version": "7"}

    async def inspect(self, bot_slug: str, endpoint: str, *, timeout: float = 10.0) -> dict[str, Any]:
        del bot_slug, endpoint, timeout
        return {"status": "ok", "agent_version": "7", "display": ":1", "windows": []}

    async def screenshot(
        self,
        bot_slug: str,
        endpoint: str,
        *,
        max_width: int = 1280,
        timeout: float = 20.0,
    ) -> tuple[bytes, dict[str, Any]]:
        del bot_slug, endpoint, max_width, timeout
        self.screenshot_calls += 1
        return self.png_bytes, {
            "width": 1280,
            "height": 720,
            "display": ":1",
            "mime_type": "image/png",
        }

    async def execute_action(
        self,
        bot_slug: str,
        endpoint: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        del bot_slug, endpoint, params, timeout
        return {"status": "ok", "action": action}


class TestNativePydanticAITools(unittest.TestCase):
    """Verify tool schemas, scoping, normalization, native runner turns, and router integration."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(
        self,
        tmp: str,
        *,
        llm_transport=None,
        public_http_fetcher=None,
        telegram_transport=None,
        docker_driver=None,
        cdp_transport=None,
        desktop_agent_transport=None,
        ssh_transport=None,
    ):
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
            ssh_audit_root=str(Path(tmp) / "ssh_audit"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            public_http_fetcher=public_http_fetcher,
            telegram_transport=telegram_transport,
            docker_driver=docker_driver,
            cdp_transport=cdp_transport,
            desktop_agent_transport=desktop_agent_transport,
            ssh_transport=ssh_transport,
        )

    def test_1_all_tool_schemas_are_gemini_safe(self) -> None:
        specs = all_tool_specs()
        self.assertGreaterEqual(len(specs), 50)
        all_errors: list[str] = []
        for spec in specs:
            all_errors.extend(
                validate_gemini_safe_schema(spec.parameters_json_schema, tool_name=spec.name)
            )
        self.assertEqual(all_errors, [])

    def test_2_dynamic_per_bot_tool_scoping(self) -> None:
        base_bot = {
            "slug": "api-worker",
            "runtime": "api",
            "outbound_rbac": "internal",
            "tools": [],
            "collections": {"read": ["news_items"], "write": ["news_items"]},
            "routines": [],
        }

        # 1. Plain API bot gets core kernel + analytics, without unrequested static web or supervisor tools
        api_names = {
            s.name
            for s in build_bot_tool_specs(
                bot=base_bot,
                read_cols=["news_items"],
                data_write_cols=["news_items"],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        self.assertIn("data_query", api_names)
        self.assertIn("ask_operator", api_names)
        self.assertNotIn("fetch_public_webpage", api_names)
        self.assertNotIn("extract_web_data", api_names)
        self.assertNotIn("fetch_rss_feed", api_names)
        self.assertNotIn("fetch_telegram_public_channel", api_names)
        self.assertNotIn("propose_specialist_bot", api_names)
        self.assertNotIn("propose_fleet_cleanup", api_names)
        self.assertFalse(any(n.startswith("desktop_") for n in api_names))
        self.assertFalse(any(n.startswith("ssh_") for n in api_names))
        self.assertNotIn("sandbox_exec", api_names)
        self.assertNotIn("gmail_search", api_names)

        # 1b. Opt-in web bot and sandbox bot receive only their declared capabilities
        opted_web_names = {
            s.name
            for s in build_bot_tool_specs(
                bot={**base_bot, "tools": ["fetch_public_webpage"]},
                read_cols=["news_items"],
                data_write_cols=["news_items"],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        self.assertIn("fetch_public_webpage", opted_web_names)

        sandbox_names = {
            s.name
            for s in build_bot_tool_specs(
                bot={**base_bot, "runtime": "sandbox"},
                read_cols=[],
                data_write_cols=[],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        self.assertIn("sandbox_exec", sandbox_names)
        self.assertNotIn("fetch_public_webpage", sandbox_names)
        self.assertFalse(any(n.startswith("desktop_") for n in sandbox_names))

        # 2. Desktop + SSH + Google bot gains those tool groups dynamically
        rich_bot = {**base_bot, "runtime": "desktop"}
        rich_names = {
            s.name
            for s in build_bot_tool_specs(
                bot=rich_bot,
                read_cols=["news_items"],
                data_write_cols=["news_items"],
                permitted_integrations=[{"slug": "work-gmail", "provider": "google"}],
                has_ssh_vault=True,
                can_control_ssh=True,
                teammate_bots=[{"slug": "helper-bot", "name": "Helper"}],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        for expected in (
            "desktop_browse",
            "desktop_browser_action",
            "desktop_exec",
            "desktop_screenshot",
            "ssh_exec",
            "ssh_wait",
            "ssh_input",
            "ssh_close",
            "ssh_session_control",
            "gmail_search",
            "gdrive_search",
            "gcal_events",
            "send_email",
            "delegate_to_bot",
            "propose_delegation_plan",
        ):
            self.assertIn(expected, rich_names)

        # 3. Background cron poll strips interactive-only tools
        cron_names = {
            s.name
            for s in build_bot_tool_specs(
                bot=base_bot,
                read_cols=["news_items"],
                data_write_cols=["news_items"],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[{"slug": "helper-bot"}],
                trigger_type="cron:daily",
                trigger_payload={},
                is_background_poll=True,
                needs_platform_status=False,
            )
        }
        for omitted in (
            "ask_operator",
            "update_self_config",
            "configure_routine",
            "run_routine",
            "propose_delegation_plan",
        ):
            self.assertNotIn(omitted, cron_names)
        self.assertIn("delegate_to_bot", cron_names)

    def test_3_normalize_native_tool_call(self) -> None:
        doc_action = normalize_native_tool_call(
            "upsert_document",
            {
                "collection": "tech_news",
                "external_key": "https://example.com/1",
                "title": "Release 8.0",
                "summary": "GA notes",
                "doc_json": json.dumps({"severity": "high"}),
            },
            tool_call_id="tc_doc",
        )
        self.assertEqual(doc_action["type"], "upsert_document")
        self.assertEqual(doc_action["_tool_call_id"], "tc_doc")
        self.assertEqual(
            doc_action["doc"],
            {"severity": "high", "title": "Release 8.0", "summary": "GA notes"},
        )

        ev_action = normalize_native_tool_call(
            "emit_event",
            {"event_type": "news.ready", "payload_json": '{"count": 4}'},
            tool_call_id="tc_ev",
        )
        self.assertEqual(ev_action["payload"], {"count": 4})

        page_action = normalize_native_tool_call(
            "upsert_page",
            {
                "slug": "ops-board",
                "title": "Ops Board",
                "template_key": "data_dashboard",
                "dashboard_spec_json": '{"kpis": [{"label": "Total"}]}',
            },
            tool_call_id="tc_pg",
        )
        self.assertEqual(page_action["template_key"], "data_dashboard")
        self.assertEqual(page_action["dashboard_spec"], {"kpis": [{"label": "Total"}]})

        cfg_action = normalize_native_tool_call(
            "update_self_config",
            {"role": "Linux Auditor", "boundaries": None},
            tool_call_id="tc_cfg",
        )
        self.assertEqual(cfg_action["role"], "Linux Auditor")
        self.assertNotIn("boundaries", cfg_action)
        self.assertNotIn("onboarding_pending", cfg_action)

        browser_action = normalize_native_tool_call(
            "desktop_browser_action",
            {"action": "scroll", "index": -1, "direction": "down"},
        )
        self.assertNotIn("index", browser_action)
        self.assertEqual(browser_action["direction"], "down")

    def test_4a_native_multiturn_webpage_streaming_and_habit_proposal(self) -> None:
        calls: list[LLMRequest] = []

        async def native_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            if len(calls) == 1:
                self.assertGreater(len(req.tools), 5)
                self.assertNotIn("Action JSON schemas", req.system_prompt)
                return {
                    "chunks": ["Let me check ", "the repository..."],
                    "tool_calls": [
                        {
                            "tool_call_id": "call_web_1",
                            "tool_name": "fetch_public_webpage",
                            "args": {
                                "url": "https://repo.zabbix.com/zabbix/8.0/rhel/9/x86_64/",
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 30,
                    "output_tokens": 12,
                }
            self.assertEqual(len(req.deferred_tool_results), 1)
            ret = req.deferred_tool_results[0]
            self.assertEqual(ret.tool_call_id, "call_web_1")
            self.assertEqual(ret.result["status"], "ok")
            self.assertIn("zabbix-agent2-8.0.0beta2", ret.result["markdown"])
            return {
                "chunks": ["Found `zabbix-agent2-8.0.0beta2`. ", "No final GA package is published yet."],
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 45,
                "output_tokens": 20,
            }

        fetcher = _FakeWebFetcher()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=native_llm, public_http_fetcher=fetcher)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "sysadmin-native",
                        "name": "SysAdmin Native",
                        "role": "Inspect Zabbix package repositories",
                    },
                )

                events: list[dict[str, Any]] = []

                async def run_chat() -> dict[str, Any]:
                    async with app.state.bus.subscribe() as queue:
                        res = await app.state.bot_runner.execute_bot(
                            "sysadmin-native",
                            trigger_type="manual",
                            trigger_payload={
                                "input_text": "Check official Zabbix RHEL9 repo for updates",
                                "text": "Check official Zabbix RHEL9 repo for updates",
                                "from_chat_thread": True,
                            },
                        )
                        while not queue.empty():
                            ev = queue.get_nowait()
                            if ev.get("_sse_event") == "turn_stream":
                                events.append(ev)
                        return res

                res = asyncio.run(run_chat())
                self.assertEqual(res["status"], "completed")
                self.assertIn("text_reset", [e.get("type") for e in events])
                chips = res["metadata"]["chips"]
                self.assertEqual(len(chips), 1)
                self.assertIn("repo.zabbix.com/zabbix/8.0/rhel/9/x86_64", chips[0]["label"])
                self.assertIn("No final GA package is published yet.", res["summary"])
                self.assertNotIn('"type":', res["summary"])
                self.assertIn("habit_proposal", res["metadata"])

    def test_4b_native_multihost_ssh_batch_pauses_without_extra_turn(self) -> None:
        calls: list[LLMRequest] = []

        async def ssh_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            return {
                "output_text": "",
                "tool_calls": [
                    {
                        "tool_call_id": "call_ssh_1",
                        "tool_name": "ssh_exec",
                        "args": {
                            "vault_slug": "prod-linux",
                            "hosts": ["10.0.0.10", "10.0.0.11"],
                            "command": "systemctl restart nginx",
                        },
                    }
                ],
                "message_history": [{"turn": 1}],
                "input_tokens": 25,
                "output_tokens": 14,
            }

        with tempfile.TemporaryDirectory() as tmp:
            ssh_transport = InMemorySSHTransport()
            ssh_transport.register_server("10.0.0.10", 22, username="ops")
            ssh_transport.register_server("10.0.0.11", 22, username="ops")
            app = self._build_env(tmp, llm_transport=ssh_llm, ssh_transport=ssh_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Prod Linux",
                        "slug": "prod-linux",
                        "secret_type": "ssh",
                        "username": "ops",
                        "secrets": {"password": "ssh-secret-password"},
                        "allowed_bots": ["*"],
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "ssh-native",
                        "name": "SSH Native",
                        "role": "Manage Linux servers",
                        "outbound_rbac": "draft",
                    },
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "ssh-native",
                        trigger_type="manual",
                        trigger_payload={
                            "input_text": "Restart nginx on 10.0.0.10 and 10.0.0.11",
                            "text": "Restart nginx on 10.0.0.10 and 10.0.0.11",
                        },
                    )
                )
                self.assertEqual(len(calls), 1)
                self.assertEqual(res["status"], "completed")
                queued_actions = [a for a in res["actions"] if a.get("status") == "queued_approval"]
                self.assertEqual(len(queued_actions), 2)
                batch_ids = {a.get("batch_id") for a in queued_actions}
                self.assertEqual(len(batch_ids), 1)
                self.assertIn("Approve All", res["summary"])

    def test_4c_native_ask_operator_pauses_immediately(self) -> None:
        calls: list[LLMRequest] = []

        async def ask_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            return {
                "output_text": "",
                "tool_calls": [
                    {
                        "tool_call_id": "call_ask_1",
                        "tool_name": "ask_operator",
                        "args": {
                            "question": "Which Zabbix version should I install?",
                            "options": [
                                {"label": "7.0 LTS", "reply": "Install Zabbix 7.0 LTS", "tone": "primary"},
                                {"label": "8.0 Beta", "reply": "Stay on 8.0 beta2", "tone": "secondary"},
                            ],
                            "allow_custom_reply": True,
                        },
                    }
                ],
                "message_history": [{"turn": 1}],
                "input_tokens": 18,
                "output_tokens": 11,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=ask_llm)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "ask-native", "name": "Ask Native", "role": "Confirm options"},
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "ask-native",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Update Zabbix", "text": "Update Zabbix"},
                    )
                )
                self.assertEqual(len(calls), 1)
                op_q = res["metadata"].get("operator_question")
                self.assertIsInstance(op_q, dict)
                self.assertEqual(len(op_q["options"]), 2)
                self.assertIn("Which Zabbix version should I install?", res["summary"])

    def test_4d_native_upsert_page_triggers_live_building_chip(self) -> None:
        turn_n = {"n": 0}

        async def page_llm(req: LLMRequest) -> dict[str, Any]:
            turn_n["n"] += 1
            if turn_n["n"] == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_page_1",
                            "tool_name": "upsert_page",
                            "args": {
                                "slug": "ops-live-page",
                                "title": "Live Ops Page",
                                "render_mode": "sandboxed_html",
                                "content_payload": "<!doctype html><html><body><h1>Live</h1></body></html>",
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 22,
                    "output_tokens": 15,
                }
            return {
                "chunks": ["Updated **Live Ops Page** cleanly."],
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 15,
                "output_tokens": 9,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=page_llm)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "page-native", "name": "Page Native", "role": "Build Pages"},
                )
                events: list[dict[str, Any]] = []

                async def run_page() -> dict[str, Any]:
                    async with app.state.bus.subscribe() as queue:
                        res = await app.state.bot_runner.execute_bot(
                            "page-native",
                            trigger_type="manual",
                            trigger_payload={
                                "input_text": "Create an ops page",
                                "text": "Create an ops page",
                                "from_chat_thread": True,
                            },
                        )
                        while not queue.empty():
                            ev = queue.get_nowait()
                            if ev.get("_sse_event") == "turn_stream":
                                events.append(ev)
                        return res

                res = asyncio.run(run_page())
                self.assertEqual(res["status"], "completed")
                started_stream_chips = [
                    e
                    for e in events
                    if e.get("type") == "chip_started" and e.get("action_type") == "stream_page"
                ]
                self.assertEqual(len(started_stream_chips), 1)
                self.assertEqual(started_stream_chips[0]["label"], "Building Page...")
                page = app.state.repo.get_page("ops-live-page")
                self.assertEqual(page["title"], "Live Ops Page")

    def test_4e_native_step_checkpoint_and_loop_guard_use_tool_choice_none(self) -> None:
        # 1. Step checkpoint at max_steps_per_run=3
        step_calls: list[LLMRequest] = []

        async def checkpoint_llm(req: LLMRequest) -> dict[str, Any]:
            step_calls.append(req)
            idx = len(step_calls)
            if idx <= 3:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": f"call_step_{idx}",
                            "tool_name": "fetch_public_webpage",
                            "args": {"url": f"https://example.org/page-{idx}"},
                        }
                    ],
                    "message_history": [{"turn": idx}],
                    "input_tokens": 10,
                    "output_tokens": 8,
                }
            self.assertEqual(req.tool_choice, "none")
            self.assertEqual(len(req.deferred_tool_results), 1)
            self.assertIn("step checkpoint", req.deferred_tool_results[0].result.get("runner_notice", "").lower())
            return {
                "output_text": "Completed 3 checks; paused at step checkpoint.",
                "tool_calls": [],
                "message_history": [{"turn": 4}],
                "input_tokens": 12,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp1:
            app1 = self._build_env(tmp1, llm_transport=checkpoint_llm, public_http_fetcher=_FakeWebFetcher())
            with TestClient(app1) as client1:
                app1.state.llm_router._native_transport_tools = True
                client1.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "chk-native",
                        "name": "Checkpoint Native",
                        "role": "Crawl pages",
                        "max_steps_per_run": 3,
                    },
                )
                res1 = asyncio.run(
                    app1.state.bot_runner.execute_bot(
                        "chk-native",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Check 5 pages", "text": "Check 5 pages"},
                    )
                )
                self.assertEqual(len(step_calls), 4)
                self.assertIn("run_checkpoint", res1["metadata"])
                self.assertIn("paused at step checkpoint", res1["summary"])

        # 2. Loop guard on 2 identical calls invokes synthesis with tool_choice="none"
        loop_calls: list[LLMRequest] = []

        async def loop_llm(req: LLMRequest) -> dict[str, Any]:
            loop_calls.append(req)
            idx = len(loop_calls)
            if idx <= 2:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": f"call_dup_{idx}",
                            "tool_name": "fetch_public_webpage",
                            "args": {"url": "https://example.org/same"},
                        }
                    ],
                    "message_history": [{"turn": idx}],
                    "input_tokens": 10,
                    "output_tokens": 8,
                }
            self.assertEqual(req.tool_choice, "none")
            self.assertEqual(len(req.deferred_tool_results), 1)
            self.assertIn("Repeated identical tool call", req.deferred_tool_results[0].result.get("runner_notice", ""))
            return {
                "output_text": "Halted duplicate web check and reported cached findings.",
                "tool_calls": [],
                "message_history": [{"turn": 3}],
                "input_tokens": 12,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp2:
            app2 = self._build_env(tmp2, llm_transport=loop_llm, public_http_fetcher=_FakeWebFetcher())
            with TestClient(app2) as client2:
                app2.state.llm_router._native_transport_tools = True
                client2.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "loop-native",
                        "name": "Loop Native",
                        "role": "Crawl pages",
                    },
                )
                res2 = asyncio.run(
                    app2.state.bot_runner.execute_bot(
                        "loop-native",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Check same page", "text": "Check same page"},
                    )
                )
                self.assertEqual(len(loop_calls), 3)
                self.assertIn("Halted duplicate web check", res2["summary"])

    def test_4f_native_desktop_action_attaches_screenshot_to_deferred_result(self) -> None:
        calls: list[LLMRequest] = []

        async def desktop_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            if len(calls) == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_desk_1",
                            "tool_name": "desktop_browse",
                            "args": {"url": "https://portal.example.com/status"},
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 20,
                    "output_tokens": 10,
                }
            self.assertEqual(len(req.deferred_tool_results), 1)
            self.assertEqual(req.deferred_tool_results[0].images, (agent_transport.png_bytes,))
            return {
                "output_text": "Inspected live desktop browser screenshot: Portal Online.",
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 22,
                "output_tokens": 12,
            }

        async def fake_cdp(bot_slug: str, cdp_endpoint: str, url: str, selector: str | None) -> CDPPageSnapshot:
            del bot_slug, cdp_endpoint, selector
            return CDPPageSnapshot(
                url=url,
                status_code=200,
                title="Partner Portal",
                text="Portal Online",
                html="<h1>Portal Online</h1>",
            )

        agent_transport = _FakeDesktopAgentTransport()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=desktop_llm,
                docker_driver=InMemoryDockerDriver(),
                cdp_transport=fake_cdp,
                desktop_agent_transport=agent_transport,
            )
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "desk-native",
                        "name": "Desktop Native",
                        "role": "Inspect portals visually",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                    },
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "desk-native",
                        trigger_type="manual",
                        trigger_payload={
                            "input_text": "Open https://portal.example.com/status",
                            "text": "Open https://portal.example.com/status",
                        },
                    )
                )
                self.assertEqual(len(calls), 2)
                self.assertGreaterEqual(agent_transport.screenshot_calls, 1)
                self.assertIn("Portal Online", res["summary"])

    def test_4g_native_telegram_event_does_not_double_send(self) -> None:
        calls: list[LLMRequest] = []

        async def tg_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            if len(calls) == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_tg_1",
                            "tool_name": "publish_telegram",
                            "args": {
                                "account": "ops-tg",
                                "text": "Server health check passed.",
                                "target": "123456",
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 16,
                    "output_tokens": 10,
                }
            return {
                "output_text": "Sent confirmation to Telegram.",
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 12,
                "output_tokens": 6,
            }

        tg_transport = _FakeTelegramTransport()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=tg_llm, telegram_transport=tg_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                app.state.repo.upsert_integration(
                    slug="ops-tg",
                    provider="telegram",
                    display_name="Ops Telegram",
                    account_identifier="argo_native_tg_bot",
                    scopes=["bot_api"],
                    secrets={"bot_token": "991100:secret", "operator_chat_id": "123456"},
                    status="ok",
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "tg-native",
                        "name": "TG Native",
                        "role": "Reply on Telegram",
                        "outbound_rbac": "execute",
                        "daily_cap": 20,
                    },
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "tg-native",
                        trigger_type="on_event:telegram.message",
                        trigger_payload={
                            "account_slug": "ops-tg",
                            "chat_id": "123456",
                            "input_text": "Status?",
                            "text": "Status?",
                        },
                    )
                )
                self.assertEqual(res["status"], "completed")
                self.assertEqual(len(tg_transport.sent_messages), 1)

    def test_4h_unsupported_tools_error_falls_back_to_text_json_and_caches_model(self) -> None:
        seen_requests: list[LLMRequest] = []

        async def ollama_fallback_llm(req: LLMRequest) -> dict[str, Any]:
            seen_requests.append(req)
            if req.tools:
                raise RuntimeError("registry.ollama.ai/library/llama3 does not support tools")
            return {
                "text": json.dumps(
                    {
                        "summary": "Fallback answer after tool schema rejection.",
                        "actions": [],
                    }
                ),
                "input_tokens": 14,
                "output_tokens": 11,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=ollama_fallback_llm)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "ollama-bot", "name": "Ollama Bot", "role": "Helper"},
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "ollama-bot",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Say hello", "text": "Say hello"},
                    )
                )
                self.assertEqual(res["status"], "completed")
                self.assertEqual(res["summary"], "Fallback answer after tool schema rejection.")
                self.assertEqual(len(seen_requests), 2)
                self.assertGreater(len(seen_requests[0].tools), 0)
                self.assertEqual(len(seen_requests[1].tools), 0)
                self.assertIn("Action JSON schemas", seen_requests[1].system_prompt)
                self.assertIn(seen_requests[0].model_id, app.state.llm_router._non_tool_models)

    def test_5_direct_pydantic_ai_native_runner_and_history_compaction(self) -> None:
        # 1. History compaction unit test (no pydantic_ai install needed)
        @dataclasses.dataclass
        class _FakeBinaryContent:
            data: bytes
            media_type: str = "image/png"

        @dataclasses.dataclass
        class _FakeToolReturnPart:
            content: Any
            tool_name: str = "fetch_public_webpage"
            tool_call_id: str = "tc"
            part_kind: str = "tool-return"

        @dataclasses.dataclass
        class _FakeUserPromptPart:
            content: Any
            part_kind: str = "user-prompt"

        @dataclasses.dataclass
        class _FakeModelResponse:
            parts: list[Any]
            thought_signature: str = "opaque-gemini-sig"
            kind: str = "response"

        @dataclasses.dataclass
        class _FakeModelRequest:
            parts: list[Any]
            kind: str = "request"

        history: list[Any] = []
        for idx in range(6):
            history.append(
                _FakeModelRequest(
                    parts=[
                        _FakeUserPromptPart(
                            content=[
                                f"Turn {idx}",
                                _FakeBinaryContent(data=f"png-{idx}".encode("ascii")),
                            ]
                        )
                    ]
                )
            )
            resp = _FakeModelResponse(parts=[SimpleNamespace(part_kind="tool-call")], thought_signature=f"sig-{idx}")
            history.append(resp)
            history.append(
                _FakeModelRequest(
                    parts=[
                        _FakeToolReturnPart(
                            content={
                                "type": "fetch_public_webpage",
                                "status": "ok",
                                "markdown": "X" * 1200,
                                "interactive_elements": [{"index": 0}, {"index": 1}],
                            },
                            tool_call_id=f"tc_{idx}",
                        )
                    ]
                )
            )

        compacted = LLMRouter._compact_native_message_history(
            history,
            keep_recent_tool_requests=4,
            keep_recent_vision_requests=2,
        )
        assert compacted is not None
        # Oldest 2 tool-return requests compacted, newest 4 untouched
        old_tool_req = compacted[2]
        self.assertTrue(old_tool_req.parts[0].content.get("compacted"))
        self.assertNotIn("interactive_elements", old_tool_req.parts[0].content)
        self.assertLess(len(old_tool_req.parts[0].content["markdown"]), 420)
        recent_tool_req = compacted[-1]
        self.assertNotIn("compacted", recent_tool_req.parts[0].content)
        self.assertEqual(len(recent_tool_req.parts[0].content["markdown"]), 1200)

        # Old vision binary replaced with text placeholder, newest 2 preserved
        self.assertIsInstance(compacted[0].parts[0].content[1], str)
        self.assertIn("omitted", compacted[0].parts[0].content[1])
        self.assertIsInstance(compacted[-3].parts[0].content[1], _FakeBinaryContent)

        # Every ModelResponse and its thought_signature remained untouched
        for idx in range(6):
            orig_resp = history[idx * 3 + 1]
            comp_resp = compacted[idx * 3 + 1]
            self.assertIs(comp_resp, orig_resp)
            self.assertEqual(comp_resp.thought_signature, f"sig-{idx}")

        # 2. Direct _run_native_with_pydantic_ai test with fake pydantic_ai package
        class _FakeExternalToolset:
            def __init__(self, tools: list[Any]) -> None:
                self.tools = tools

        class _FakeToolDefinition:
            def __init__(self, *, name: str, description: str, parameters_json_schema: dict[str, Any], kind: str) -> None:
                self.name = name
                self.description = description
                self.parameters_json_schema = parameters_json_schema
                self.kind = kind

        class _FakeDeferredToolRequests:
            def __init__(self, calls: list[Any]) -> None:
                self.calls = calls

        class _FakeDeferredToolResults:
            def __init__(self, calls: dict[str, Any]) -> None:
                self.calls = calls

        class _FakeToolReturn:
            def __init__(self, *, return_value: Any, content: list[Any]) -> None:
                self.return_value = return_value
                self.content = content

        class _FakeTextPart:
            def __init__(self, content: str) -> None:
                self.content = content

        class _FakeToolCallPart:
            def __init__(self, *, tool_name: str, tool_call_id: str, args: dict[str, Any]) -> None:
                self.tool_name = tool_name
                self.tool_call_id = tool_call_id
                self._args = args

            def args_as_dict(self) -> dict[str, Any]:
                return dict(self._args)

        class _FakeTextPartDelta:
            def __init__(self, content_delta: str) -> None:
                self.content_delta = content_delta

        class _FakePartStartEvent:
            def __init__(self, part: Any) -> None:
                self.part = part

        class _FakePartDeltaEvent:
            def __init__(self, delta: Any) -> None:
                self.delta = delta

        class _FakeModelSettings(dict):
            pass

        recorded_agent_calls: list[dict[str, Any]] = []
        cancel_gate = {"wait_for_cancel": False}

        class _FakeNode:
            def __init__(self, events: list[Any]) -> None:
                self._events = events

            def stream(self, ctx: Any):
                del ctx

                class _StreamCM:
                    def __init__(self, evs: list[Any]) -> None:
                        self._evs = evs

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *args: Any) -> None:
                        return None

                    def __aiter__(self):
                        async def _gen():
                            for ev in self._evs:
                                if cancel_gate["wait_for_cancel"]:
                                    await asyncio.sleep(0.5)
                                yield ev

                        return _gen()

                    def get(self):
                        return SimpleNamespace(model_name="gemini-3.8-flash")

                return _StreamCM(self._events)

        class _FakeAgent:
            def __init__(self, *, model: Any, instructions: Any, toolsets: list[Any], output_type: Any, model_settings: Any) -> None:
                self.model = model
                self.instructions = instructions
                self.toolsets = toolsets
                self.output_type = output_type
                self.model_settings = model_settings

            @staticmethod
            def is_model_request_node(node: Any) -> bool:
                return isinstance(node, _FakeNode)

            def iter(self, run_input: Any, *, message_history: Any = None, deferred_tool_results: Any = None):
                recorded_agent_calls.append(
                    {
                        "run_input": run_input,
                        "message_history": message_history,
                        "deferred_tool_results": deferred_tool_results,
                        "toolsets": self.toolsets,
                        "model_settings": self.model_settings,
                    }
                )
                is_turn_2 = deferred_tool_results is not None
                call_part = _FakeToolCallPart(
                    tool_name="fetch_public_webpage",
                    tool_call_id="tc_real_1",
                    args={"url": "https://example.org"},
                )
                evs = (
                    [
                        _FakePartStartEvent(_FakeTextPart("Final ")),
                        _FakePartDeltaEvent(_FakeTextPartDelta("report.")),
                    ]
                    if is_turn_2
                    else [
                        _FakePartStartEvent(_FakeTextPart("Looking up...")),
                        _FakePartStartEvent(call_part),
                    ]
                )
                out_obj = "Final report." if is_turn_2 else _FakeDeferredToolRequests([call_part])
                hist_obj = [*(message_history or []), _FakeModelResponse(parts=[call_part])]
                res_obj = SimpleNamespace(
                    output=out_obj,
                    usage=lambda: SimpleNamespace(input_tokens=21, output_tokens=9),
                    response=SimpleNamespace(model_name="gemini-3.8-flash"),
                    all_messages=lambda: hist_obj,
                )

                class _IterCM:
                    def __init__(self) -> None:
                        self.ctx = SimpleNamespace()
                        self.result = None

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *args: Any) -> None:
                        return None

                    def __aiter__(self):
                        async def _nodes():
                            yield _FakeNode(evs)
                            self.result = res_obj

                        return _nodes()

                return _IterCM()

        fake_root = types.ModuleType("pydantic_ai")
        fake_root.Agent = _FakeAgent
        fake_root.BinaryContent = _FakeBinaryContent
        fake_root.DeferredToolRequests = _FakeDeferredToolRequests
        fake_root.DeferredToolResults = _FakeDeferredToolResults
        fake_root.ExternalToolset = _FakeExternalToolset
        fake_root.ToolDefinition = _FakeToolDefinition
        fake_root.ToolReturn = _FakeToolReturn

        fake_msgs = types.ModuleType("pydantic_ai.messages")
        fake_msgs.PartDeltaEvent = _FakePartDeltaEvent
        fake_msgs.PartStartEvent = _FakePartStartEvent
        fake_msgs.TextPart = _FakeTextPart
        fake_msgs.TextPartDelta = _FakeTextPartDelta
        fake_msgs.ToolCallPart = _FakeToolCallPart

        fake_models = types.ModuleType("pydantic_ai.models")
        fake_fallback = types.ModuleType("pydantic_ai.models.fallback")
        fake_fallback.FallbackModel = lambda *args: args[0]
        fake_google_mod = types.ModuleType("pydantic_ai.models.google")
        fake_google_mod.GoogleModel = lambda name, provider=None: SimpleNamespace(name=name, provider=provider)
        fake_providers = types.ModuleType("pydantic_ai.providers")
        fake_google_prov = types.ModuleType("pydantic_ai.providers.google")
        fake_google_prov.GoogleProvider = lambda **kwargs: SimpleNamespace(**kwargs)
        fake_settings = types.ModuleType("pydantic_ai.settings")
        fake_settings.ModelSettings = _FakeModelSettings

        stub_mods = {
            "pydantic_ai": fake_root,
            "pydantic_ai.messages": fake_msgs,
            "pydantic_ai.models": fake_models,
            "pydantic_ai.models.fallback": fake_fallback,
            "pydantic_ai.models.google": fake_google_mod,
            "pydantic_ai.providers": fake_providers,
            "pydantic_ai.providers.google": fake_google_prov,
            "pydantic_ai.settings": fake_settings,
        }

        with tempfile.TemporaryDirectory() as tmp:
            conn = init_db(Path(tmp) / "router_unit.db")
            repo = ArgoRepository(conn=conn, vault=SecretVault())
            repo.ensure_defaults()
            repo.upsert_model(
                slug="gemini-3-8",
                provider_type="google",
                model_id="google:gemini-3.8-flash",
                api_key="test-google-key",
                is_default=True,
            )
            router = LLMRouter(repo=repo, transport=None)
            specs = [s for s in all_tool_specs() if s.name == "fetch_public_webpage"]

            started_tools: list[str] = []
            deltas: list[str] = []

            async def _on_tool_start(name: str) -> None:
                started_tools.append(name)

            async def _on_delta(chunk: str) -> None:
                deltas.append(chunk)

            with patch.dict(sys.modules, stub_mods):
                async def _run_turns() -> None:
                    r1 = await router.stream(
                        bot_slug="test-bot",
                        prompt="Check example.org",
                        on_delta=_on_delta,
                        on_tool_start=_on_tool_start,
                        requested_model="google:gemini-3.8-flash",
                        tools=specs,
                    )
                    self.assertTrue(r1.native_tools_used)
                    self.assertEqual(started_tools, ["fetch_public_webpage"])
                    self.assertEqual(len(r1.tool_calls), 1)
                    self.assertEqual(r1.tool_calls[0].tool_call_id, "tc_real_1")
                    self.assertEqual(r1.tool_calls[0].args, {"url": "https://example.org"})

                    from argo_core.llm.router import NativeToolResultItem

                    deltas.clear()
                    r2 = await router.stream(
                        bot_slug="test-bot",
                        prompt="",
                        on_delta=_on_delta,
                        on_tool_start=_on_tool_start,
                        requested_model="google:gemini-3.8-flash",
                        tools=specs,
                        tool_choice="none",
                        message_history=r1.message_history,
                        deferred_tool_results=[
                            NativeToolResultItem(
                                tool_call_id="tc_real_1",
                                tool_name="fetch_public_webpage",
                                result={"status": "ok", "title": "Example Domain"},
                                images=(b"PNG_DATA",),
                            )
                        ],
                    )
                    self.assertEqual("".join(deltas), "Final report.")
                    self.assertEqual(r2.output_text, "Final report.")
                    self.assertEqual(recorded_agent_calls[1]["run_input"], None)
                    self.assertEqual(recorded_agent_calls[1]["model_settings"].get("tool_choice"), "none")
                    tr = recorded_agent_calls[1]["deferred_tool_results"].calls["tc_real_1"]
                    self.assertIsInstance(tr, _FakeToolReturn)
                    self.assertEqual(tr.content[1].data, b"PNG_DATA")

                    # Cancellation stops streaming promptly
                    cancel_gate["wait_for_cancel"] = True
                    ev = asyncio.Event()
                    loop = asyncio.get_running_loop()
                    loop.call_later(0.05, ev.set)
                    rc = await router.stream(
                        bot_slug="test-bot",
                        prompt="Cancel mid-stream",
                        cancel_event=ev,
                        requested_model="google:gemini-3.8-flash",
                        tools=specs,
                    )
                    self.assertTrue(rc.cancelled)

                asyncio.run(_run_turns())
            conn.close()

    def test_9_multihost_ssh_hosts_runs_concurrently_in_deterministic_order(self) -> None:
        calls: list[LLMRequest] = []
        turn_n = {"n": 0}

        async def ssh_concurrent_llm(req: LLMRequest) -> dict[str, Any]:
            calls.append(req)
            turn_n["n"] += 1
            if turn_n["n"] == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_ssh_multi",
                            "tool_name": "ssh_exec",
                            "args": {
                                "vault_slug": "prod-linux",
                                "hosts": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                                "command": "uptime",
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 20,
                    "output_tokens": 12,
                }
            return {
                "output_text": "All 3 hosts checked concurrently.",
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 25,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            ssh_transport = InMemorySSHTransport()
            for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
                ssh_transport.register_server(host, 22, username="ops")
            app = self._build_env(tmp, llm_transport=ssh_concurrent_llm, ssh_transport=ssh_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Prod Linux",
                        "slug": "prod-linux",
                        "secret_type": "ssh",
                        "username": "ops",
                        "secrets": {"password": "ssh-secret-password"},
                        "allowed_bots": ["*"],
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "ssh-parallel",
                        "name": "SSH Parallel",
                        "role": "Check cluster nodes",
                        "outbound_rbac": "draft",
                    },
                )

                orig_exec = app.state.ssh_manager.exec_command
                tracker = {"in_flight": 0, "max_concurrent": 0}
                delays = {"10.0.0.1": 0.09, "10.0.0.2": 0.05, "10.0.0.3": 0.01}

                async def _tracked_exec(*args: Any, **kwargs: Any) -> dict[str, Any]:
                    host = str(kwargs.get("requested_host") or "")
                    tracker["in_flight"] += 1
                    tracker["max_concurrent"] = max(tracker["max_concurrent"], tracker["in_flight"])
                    try:
                        await asyncio.sleep(delays.get(host, 0.02))
                        return await orig_exec(*args, **kwargs)
                    finally:
                        tracker["in_flight"] -= 1

                with patch.object(app.state.ssh_manager, "exec_command", side_effect=_tracked_exec):
                    res = asyncio.run(
                        app.state.bot_runner.execute_bot(
                            "ssh-parallel",
                            trigger_type="manual",
                            trigger_payload={
                                "input_text": "Check uptime on 10.0.0.1, 10.0.0.2, 10.0.0.3",
                                "text": "Check uptime on 10.0.0.1, 10.0.0.2, 10.0.0.3",
                            },
                        )
                    )

                self.assertEqual(res["status"], "completed")
                self.assertGreaterEqual(tracker["max_concurrent"], 2)
                self.assertEqual(len(calls), 2)
                deferred = calls[1].deferred_tool_results
                self.assertEqual(len(deferred), 1)
                self.assertEqual(deferred[0].tool_call_id, "call_ssh_multi")
                returned_hosts = [item["host"] for item in deferred[0].result["results"]]
                self.assertEqual(returned_hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_10_telegram_approval_timeout_and_backoff_does_not_stall_multihost_queue(self) -> None:
        class _SlowTelegramTransport(_FakeTelegramTransport):
            def __init__(self) -> None:
                super().__init__()
                self.attempts = 0

            async def send_message(
                self,
                bot_token: str,
                *,
                chat_id: str | int,
                text: str,
                reply_markup: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                del bot_token, chat_id, text, reply_markup
                self.attempts += 1
                await asyncio.sleep(5.0)
                return {"message_id": 999, "chat_id": "998877"}

        with tempfile.TemporaryDirectory() as tmp:
            slow_tg = _SlowTelegramTransport()
            app = self._build_env(tmp, telegram_transport=slow_tg)
            with TestClient(app) as client:
                app.state.approval_coordinator._telegram_notify_timeout = 0.05
                app.state.approval_coordinator._telegram_timeout_backoff = 10.0
                tg_res = client.post(
                    "/api/integrations/telegram/onboard",
                    headers=self._sso_headers(),
                    json={
                        "slug": "ops-tg",
                        "display_name": "Ops Telegram",
                        "bot_token": "123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQR",
                        "operator_chat_id": "998877",
                    },
                )
                self.assertIn(tg_res.status_code, (200, 201))

                async def _enqueue_three() -> None:
                    for idx in range(1, 4):
                        await app.state.approval_coordinator.enqueue_human_approval(
                            correlation_id=f"corr_tg_batch_{idx}",
                            bot_slug="ops-bot",
                            target_account_slug="ops-tg",
                            action_type="publish_telegram",
                            payload={"text": f"Alert #{idx}"},
                            escalation_note="Draft approval test",
                        )

                t0 = time.monotonic()
                asyncio.run(_enqueue_three())
                elapsed = time.monotonic() - t0

                self.assertLess(elapsed, 0.5)
                self.assertEqual(slow_tg.attempts, 1)
                pending = app.state.repo.list_approvals(tab="pending")
                self.assertEqual(len(pending), 3)

    def test_11_habit_proposal_suppressed_when_multiturn_ssh_pauses_on_approval(self) -> None:
        turn_n = {"n": 0}

        async def two_turn_ssh_llm(req: LLMRequest) -> dict[str, Any]:
            del req
            turn_n["n"] += 1
            if turn_n["n"] == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_ro_1",
                            "tool_name": "ssh_exec",
                            "args": {
                                "vault_slug": "prod-linux",
                                "hosts": ["10.0.0.10", "10.0.0.11"],
                                "command": "uptime",
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 20,
                    "output_tokens": 10,
                }
            return {
                "output_text": "",
                "tool_calls": [
                    {
                        "tool_call_id": "call_mut_2",
                        "tool_name": "ssh_exec",
                        "args": {
                            "vault_slug": "prod-linux",
                            "hosts": ["10.0.0.10", "10.0.0.11"],
                            "command": "cp -p /etc/hosts /tmp/hosts.bak",
                        },
                    }
                ],
                "message_history": [{"turn": 2}],
                "input_tokens": 25,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            ssh_transport = InMemorySSHTransport()
            ssh_transport.register_server("10.0.0.10", 22, username="ops")
            ssh_transport.register_server("10.0.0.11", 22, username="ops")
            app = self._build_env(tmp, llm_transport=two_turn_ssh_llm, ssh_transport=ssh_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Prod Linux",
                        "slug": "prod-linux",
                        "secret_type": "ssh",
                        "username": "ops",
                        "secrets": {"password": "ssh-secret-password"},
                        "allowed_bots": ["*"],
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "ssh-habit-check",
                        "name": "SSH Habit Check",
                        "role": "Inspect and back up servers",
                        "outbound_rbac": "draft",
                    },
                )
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "ssh-habit-check",
                        trigger_type="manual",
                        trigger_payload={
                            "input_text": "Check uptime and back up /etc/hosts on 10.0.0.10 and 10.0.0.11",
                            "text": "Check uptime and back up /etc/hosts on 10.0.0.10 and 10.0.0.11",
                        },
                    )
                )
                self.assertEqual(res["status"], "completed")
                queued = [a for a in res["actions"] if a.get("status") == "queued_approval"]
                self.assertEqual(len(queued), 2)
                self.assertNotIn("habit_proposal", res["metadata"])

    def test_12_native_continuation_turns_skip_user_prompt_and_dataset_profiling(self) -> None:
        turn_n = {"n": 0}
        seen_prompts: list[str] = []

        async def two_turn_web_llm(req: LLMRequest) -> dict[str, Any]:
            turn_n["n"] += 1
            seen_prompts.append(req.user_prompt)
            if turn_n["n"] == 1:
                return {
                    "output_text": "",
                    "tool_calls": [
                        {
                            "tool_call_id": "call_web_skip",
                            "tool_name": "fetch_public_webpage",
                            "args": {"url": "https://example.org/status"},
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 20,
                    "output_tokens": 10,
                }
            return {
                "output_text": "Status checked cleanly.",
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 25,
                "output_tokens": 8,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=two_turn_web_llm,
                public_http_fetcher=_FakeWebFetcher(),
            )
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "sys-only-bot",
                        "name": "SysOnly Bot",
                        "role": "Check web status",
                    },
                )
                app.state.repo.upsert_document(
                    collection="bot_sys-only-bot_items",
                    external_key="item-1",
                    search_text="sample metric",
                    doc={"metric": 42},
                )

                prompt_flags: list[bool] = []
                orig_build = app.state.bot_runner._build_context_isolated_prompt

                def _spy_build(*args: Any, **kwargs: Any) -> tuple[str, str]:
                    prompt_flags.append(bool(kwargs.get("system_only", False)))
                    return orig_build(*args, **kwargs)

                import argo_core.runner.bot_runner as br_mod

                profile_calls = {"n": 0}
                orig_profile = br_mod.profile_datasets

                def _spy_profile(*args: Any, **kwargs: Any) -> Any:
                    profile_calls["n"] += 1
                    return orig_profile(*args, **kwargs)

                with (
                    patch.object(app.state.bot_runner, "_build_context_isolated_prompt", side_effect=_spy_build),
                    patch.object(br_mod, "profile_datasets", side_effect=_spy_profile),
                ):
                    res = asyncio.run(
                        app.state.bot_runner.execute_bot(
                            "sys-only-bot",
                            trigger_type="manual",
                            trigger_payload={
                                "input_text": "Check https://example.org/status",
                                "text": "Check https://example.org/status",
                            },
                        )
                    )

                self.assertEqual(res["status"], "completed")
                self.assertEqual(prompt_flags, [False, True])
                self.assertTrue(bool(seen_prompts[0]))
                self.assertEqual(seen_prompts[1], "")
                self.assertEqual(profile_calls["n"], 1)

    def test_13_native_stream_timeout_aborts_stalled_provider_cleanly(self) -> None:
        class _FakeExternalToolset:
            def __init__(self, tool_defs: list[Any]) -> None:
                self.tool_defs = tool_defs

        class _FakeToolDefinition:
            def __init__(self, *, name: str, description: str, parameters_json_schema: dict[str, Any], kind: str = "external") -> None:
                self.name = name
                self.description = description
                self.parameters_json_schema = parameters_json_schema
                self.kind = kind

        class _FakeModelSettings(dict):
            pass

        class _StalledNode:
            def stream(self, ctx: Any):
                del ctx

                class _StreamCM:
                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *args: Any) -> None:
                        return None

                    def __aiter__(self):
                        async def _gen():
                            await asyncio.sleep(5.0)
                            if False:
                                yield None

                        return _gen()

                return _StreamCM()

        class _StalledAgent:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

            @staticmethod
            def is_model_request_node(node: Any) -> bool:
                return isinstance(node, _StalledNode)

            def iter(self, run_input: Any, *, message_history: Any = None, deferred_tool_results: Any = None):
                del run_input, message_history, deferred_tool_results

                class _IterCM:
                    def __init__(self) -> None:
                        self.ctx = SimpleNamespace()
                        self.result = None

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *args: Any) -> None:
                        return None

                    def __aiter__(self):
                        async def _nodes():
                            yield _StalledNode()

                        return _nodes()

                return _IterCM()

        fake_root = types.ModuleType("pydantic_ai")
        fake_root.Agent = _StalledAgent
        fake_root.BinaryContent = SimpleNamespace
        fake_root.DeferredToolRequests = type("DeferredToolRequests", (), {})
        fake_root.DeferredToolResults = type("DeferredToolResults", (), {})
        fake_root.ExternalToolset = _FakeExternalToolset
        fake_root.ToolDefinition = _FakeToolDefinition
        fake_root.ToolReturn = SimpleNamespace

        fake_msgs = types.ModuleType("pydantic_ai.messages")
        fake_msgs.PartDeltaEvent = type("PartDeltaEvent", (), {})
        fake_msgs.PartStartEvent = type("PartStartEvent", (), {})
        fake_msgs.TextPart = type("TextPart", (), {})
        fake_msgs.TextPartDelta = type("TextPartDelta", (), {})
        fake_msgs.ToolCallPart = type("ToolCallPart", (), {})

        fake_models = types.ModuleType("pydantic_ai.models")
        fake_fallback = types.ModuleType("pydantic_ai.models.fallback")
        fake_fallback.FallbackModel = lambda *args: args[0]
        fake_google_mod = types.ModuleType("pydantic_ai.models.google")
        fake_google_mod.GoogleModel = lambda name, provider=None: SimpleNamespace(name=name, provider=provider)
        fake_providers = types.ModuleType("pydantic_ai.providers")
        fake_google_prov = types.ModuleType("pydantic_ai.providers.google")
        fake_google_prov.GoogleProvider = lambda **kwargs: SimpleNamespace(**kwargs)
        fake_settings = types.ModuleType("pydantic_ai.settings")
        fake_settings.ModelSettings = _FakeModelSettings

        stub_mods = {
            "pydantic_ai": fake_root,
            "pydantic_ai.messages": fake_msgs,
            "pydantic_ai.models": fake_models,
            "pydantic_ai.models.fallback": fake_fallback,
            "pydantic_ai.models.google": fake_google_mod,
            "pydantic_ai.providers": fake_providers,
            "pydantic_ai.providers.google": fake_google_prov,
            "pydantic_ai.settings": fake_settings,
        }

        with tempfile.TemporaryDirectory() as tmp:
            conn = init_db(Path(tmp) / "timeout_unit.db")
            repo = ArgoRepository(conn=conn, vault=SecretVault())
            repo.ensure_defaults()
            repo.upsert_model(
                slug="gemini-3-8",
                provider_type="google",
                model_id="google:gemini-3.8-flash",
                api_key="test-google-key",
                is_default=True,
            )
            router = LLMRouter(repo=repo, transport=None, turn_timeout_seconds=0.05)
            specs = [s for s in all_tool_specs() if s.name == "fetch_public_webpage"]

            with patch.dict(sys.modules, stub_mods):
                t0 = time.monotonic()
                with self.assertRaises(LLMExecutionError) as ctx:
                    asyncio.run(
                        router.stream(
                            bot_slug="stalled-bot",
                            prompt="Check stalled upstream",
                            requested_model="google:gemini-3.8-flash",
                            tools=specs,
                        )
                    )
                elapsed = time.monotonic() - t0
                self.assertLess(elapsed, 0.5)
                self.assertIn("timed out", str(ctx.exception).lower())

            rows = conn.execute(
                "SELECT status, summary FROM bot_runs WHERE bot_slug = 'stalled-bot'"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "error")
            self.assertIn("timed out", rows[0]["summary"].lower())
            conn.close()


if __name__ == "__main__":
    unittest.main()
