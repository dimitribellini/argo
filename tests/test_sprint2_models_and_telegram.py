"""Sprint 2 verification tests: Multi-LLM Router, bot_runs audit, Telegram connector & Watchdog."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import sys
import tempfile
import time
import types
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from argo_core.bus.valkey_bus import EventBus
from argo_core.config import ArgoSettings
from argo_core.connectors.telegram_bot import (
    STOP_IDLE_DESKTOPS_CALLBACK,
    AiogramTelegramTransport,
    TelegramBotService,
    TelegramConfigError,
    TelegramIntegrationError,
    build_inline_keyboard,
    format_telegram_html,
    validate_callback_data,
)
from argo_core.db.repositories import ArgoRepository
from argo_core.db.sqlite import init_db
from argo_core.llm.router import (
    BudgetExceededError,
    LLMRequest,
    LLMRouter,
    ModelConfigurationError,
    _build_single_pydantic_ai_model,
    validate_model_id,
)
from argo_core.main import create_app
from argo_core.security.vault import SecretVault, redact_secrets
from argo_core.watchdog.resource_guard import HostResourceGuard


class FakeTelegramTransport:
    """In-memory Telegram Bot API double capturing getMe, alerts, callbacks, and card edits."""

    def __init__(self, *, fail_get_me: bool = False) -> None:
        self.fail_get_me = fail_get_me
        self.get_me_calls: list[str] = []
        self.sent_messages: list[dict[str, Any]] = []
        self.answered_callbacks: list[dict[str, Any]] = []
        self.edited_messages: list[dict[str, Any]] = []
        self.webhooks_set: list[dict[str, Any]] = []
        self._msg_seq = 500

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        self.get_me_calls.append(bot_token)
        if self.fail_get_me:
            raise TelegramIntegrationError(f"401 Unauthorized for bot token {bot_token}")
        return {
            "bot_id": 77112233,
            "username": "argo_ops_bot",
            "first_name": "Argo Ops Bot",
            "can_join_groups": True,
            "can_read_all_group_messages": False,
        }

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._msg_seq += 1
        record = {
            "bot_token": bot_token,
            "chat_id": str(chat_id),
            "text": text,
            "reply_markup": reply_markup,
            "message_id": self._msg_seq,
        }
        self.sent_messages.append(record)
        return {"message_id": self._msg_seq, "chat_id": str(chat_id)}

    async def answer_callback_query(
        self,
        bot_token: str,
        *,
        callback_query_id: str,
        text: str | None = None,
    ) -> bool:
        self.answered_callbacks.append(
            {"callback_query_id": callback_query_id, "text": text}
        )
        return True

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "chat_id": str(chat_id),
            "message_id": message_id,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.edited_messages.append(record)
        return {"message_id": message_id}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str],
    ) -> bool:
        self.webhooks_set.append(
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": allowed_updates,
            }
        )
        return True


class TestSprint2RouterAndTelegram(unittest.TestCase):
    """Verify PydanticAI routing, token budgets, Telegram onboarding, and Watchdog controls."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "argo_sprint2.db"
        self.master_key = Fernet.generate_key().decode("utf-8")
        self.dist_dir = REPO_ROOT / "frontend" / "dist"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _make_settings(self) -> ArgoSettings:
        return ArgoSettings(
            master_key=self.master_key,
            db_path=str(self.db_path),
            valkey_url="valkey://127.0.0.1:1/0",
            desktop_volumes_root="/srv/argo/desktops",
            public_base_url="https://argo.example.com",
            static_dir=str(self.dist_dir) if self.dist_dir.is_dir() else "",
        )

    def test_llm_router_thinking_fallback_style_injection_and_budgets(self) -> None:
        conn = init_db(self.db_path)
        vault = SecretVault(self.master_key)
        repo = ArgoRepository(conn=conn, vault=vault)
        repo.ensure_defaults()
        repo.upsert_model(
            slug="google_gemini_flash",
            provider_type="google",
            model_id="google:gemini-3.8-flash",
            api_key="sk-primary-secret-123456",
            is_default=True,
            daily_token_limit=200,
        )
        repo.upsert_model(
            slug="anthropic_claude",
            provider_type="anthropic",
            model_id="anthropic:claude-4.5-sonnet",
            api_key="sk-fallback-secret-789012",
            is_default=False,
            monthly_budget_usd=5.0,
        )
        repo.add_style_rule(
            rule_text="Strip coupon codes from community posts",
            scope_slug="editorial-reviewer",
        )

        observed_requests: list[LLMRequest] = []

        async def mock_transport(req: LLMRequest) -> tuple[str, int, int]:
            observed_requests.append(req)
            if req.model_id == "google:gemini-3.8-flash":
                raise RuntimeError("Upstream 503 with key sk-primary-secret-123456")
            return f"Reviewed cleanly via {req.model_id}", 90, 40

        router = LLMRouter(repo=repo, transport=mock_transport)

        async def scenario() -> None:
            # Primary fails -> automatic failover to Anthropic; style_memory injected.
            res1 = await router.complete(
                bot_slug="editorial-reviewer",
                prompt="Evaluate release brief",
                requested_model="google:gemini-3.8-flash",
                system_prompt="Audit release notes.",
                trigger_type="review",
            )
            self.assertTrue(res1.used_fallback)
            self.assertEqual(res1.model_used, "anthropic:claude-4.5-sonnet")
            self.assertEqual(res1.input_tokens, 90)
            self.assertEqual(res1.output_tokens, 40)
            self.assertGreater(res1.estimated_cost_usd, 0.0)
            self.assertEqual(observed_requests[0].thinking_level, "low")
            self.assertIn("Strip coupon codes from community posts", observed_requests[0].system_prompt)

            # Gemini-4 Argon uses thinking_level='high'.
            async def argon_transport(req: LLMRequest) -> tuple[str, int, int]:
                observed_requests.append(req)
                return "Argon synthesis complete", 120, 60

            argon_router = LLMRouter(repo=repo, transport=argon_transport)
            res_argon = await argon_router.complete(
                bot_slug="editorial-reviewer",
                prompt="Synthesize deeply",
                requested_model="google:gemini-4-argon",
                system_prompt="Deep audit.",
                trigger_type="review",
            )
            self.assertEqual(res_argon.model_used, "google:gemini-4-argon")
            self.assertEqual(observed_requests[-1].thinking_level, "high")

            # Enforce daily_token_limit block (200 tokens Cap reached cleanly).
            repo.upsert_model(
                slug="limited_provider",
                provider_type="google",
                model_id="google:gemini-3.8-flash",
                api_key="sk-limited-secret-000111",
                is_default=True,
                daily_token_limit=50,
            )
            repo.record_bot_run(
                correlation_id="corr_cap",
                bot_slug="collector",
                trigger_type="cron",
                llm_model_used="google:gemini-3.8-flash",
                input_tokens=40,
                output_tokens=20,
                estimated_cost_usd=0.0001,
                status="success",
            )
            with self.assertRaises(BudgetExceededError):
                await router.complete(
                    bot_slug="collector",
                    prompt="Blocked call",
                    requested_model="limited-provider",
                    strict_provider=True,
                )

            runs = repo.list_bot_runs(limit=10)
            self.assertEqual(runs[0]["status"], "blocked")
            self.assertEqual(
                redact_secrets("token bot123456:ABCDEFGHIJKLMNOPQRSTUV sk-secretvalue99999"),
                "token <REDACTED_TELEGRAM_TOKEN> <REDACTED_API_KEY>",
            )

        try:
            asyncio.run(scenario())
        finally:
            conn.close()

    def test_deprecated_model_rejection_and_model_endpoints(self) -> None:
        with self.assertRaises(ModelConfigurationError):
            validate_model_id("google:gemini-2.5-pro")

        observed: list[LLMRequest] = []

        async def mock_transport(req: LLMRequest) -> tuple[str, int, int]:
            observed.append(req)
            return f"Ready on {req.model_id}", 50, 25

        with TestClient(
            create_app(
                settings=self._make_settings(),
                guard=HostResourceGuard(
                    metrics_provider=lambda: {
                        "cpu_percent": 12.0,
                        "ram_percent": 40.0,
                        "ram_total_gb": 16.0,
                        "disk_percent": 30.0,
                    }
                ),
                llm_transport=mock_transport,
            )
        ) as client:
            # Tombstone: reject deprecated gemini-2.5-* models.
            bad_model = client.post(
                "/api/models",
                json={
                    "slug": "legacy_bad",
                    "provider_type": "google",
                    "model_id": "google:gemini-2.5-flash",
                },
            )
            self.assertEqual(bad_model.status_code, 422)

            bad_bot = client.post(
                "/api/bots",
                json={
                    "name": "Legacy Bot",
                    "role": "Invalid model check",
                    "model": "google:gemini-2.5-pro",
                },
            )
            self.assertEqual(bad_bot.status_code, 422)

            # Promote seeded google_gemini_argon to active default.
            promote = client.post("/api/models/google_gemini_argon/default")
            self.assertEqual(promote.status_code, 200)
            self.assertTrue(promote.json()["is_default"])

            # Test route records bot_runs and Activity event.
            tested = client.post("/api/models/google_gemini_argon/test", json={})
            self.assertEqual(tested.status_code, 200)
            test_data = tested.json()
            self.assertEqual(test_data["model_id"], "google:gemini-4-argon")
            self.assertEqual(test_data["input_tokens"], 50)
            self.assertEqual(test_data["output_tokens"], 25)
            self.assertEqual(observed[-1].thinking_level, "high")

            # Bot message routes through LLMRouter and records bot_runs.
            bot = client.post(
                "/api/bots",
                json={
                    "name": "Triage Worker",
                    "role": "Summarize inbound telemetry concisely.",
                    "runtime": "api",
                    "outbound_rbac": "draft",
                    "model": "google:gemini-3.8-flash",
                },
            ).json()
            msg_res = client.post(
                f"/api/bots/{bot['slug']}/messages",
                json={"text": "Run diagnostic summary"},
            )
            self.assertEqual(msg_res.status_code, 200)
            self.assertEqual(msg_res.json()["run"]["bot_slug"], bot["slug"])
            self.assertEqual(msg_res.json()["messages"][-1]["text"], "Ready on google:gemini-3.8-flash")

            models_res = client.get("/api/models").json()
            self.assertEqual(models_res["today_tokens"], 150)
            self.assertGreater(models_res["today_cost_usd"], 0.0)
            self.assertEqual(len(models_res["recent_runs"]), 2)

            runs_res = client.get(f"/api/runs?bot_slug={bot['slug']}").json()
            self.assertEqual(len(runs_res), 1)
            self.assertEqual(runs_res[0]["trigger_type"], "manual")

        # Without a custom transport, testing a model with no key returns HTTP 400.
        with TestClient(
            create_app(
                settings=self._make_settings(),
                guard=HostResourceGuard(
                    metrics_provider=lambda: {
                        "cpu_percent": 10.0,
                        "ram_percent": 35.0,
                        "ram_total_gb": 16.0,
                        "disk_percent": 25.0,
                    }
                ),
            )
        ) as strict_client:
            unconfigured_test = strict_client.post("/api/models/google_gemini_flash/test", json={})
            self.assertEqual(unconfigured_test.status_code, 400)

    def test_telegram_onboarding_webhook_and_watchdog_controls(self) -> None:
        # Callback > 64 bytes is strictly rejected by Telegram guard.
        self.assertEqual(validate_callback_data(STOP_IDLE_DESKTOPS_CALLBACK), "sys:stop_idle")
        with self.assertRaises(TelegramConfigError):
            validate_callback_data("x" * 65)
        markup = build_inline_keyboard([[("Stop Idle Desktops", STOP_IDLE_DESKTOPS_CALLBACK)]])
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], "sys:stop_idle")

        ram_value = {"pct": 45.0, "disk": 40.0}
        temp_dir = Path(self._tmpdir.name) / "http_cache"
        temp_dir.mkdir(parents=True, exist_ok=True)
        (temp_dir / "stale.tmp").write_text("temp artifact", encoding="utf-8")
        (temp_dir / "argo.db").write_text("protected name", encoding="utf-8")

        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "cpu_percent": 32.0,
                "ram_percent": ram_value["pct"],
                "ram_total_gb": 16.0,
                "disk_percent": ram_value["disk"],
            },
            alert_cooldown_seconds=600.0,
            temp_cleanup_dir=temp_dir,
        )
        tg_transport = FakeTelegramTransport()
        bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"

        with TestClient(
            create_app(
                settings=self._make_settings(),
                guard=guard,
                telegram_transport=tg_transport,
            )
        ) as client:
            # Invalid BotFather format fails with 400.
            bad_tg = client.post(
                "/api/integrations/telegram/onboard",
                json={"bot_token": "not-a-valid-telegram-token"},
            )
            self.assertEqual(bad_tg.status_code, 400)

            # Valid onboarding runs getMe, encrypts token + webhook_secret, and omits secrets from JSON.
            onboard_res = client.post(
                "/api/integrations/telegram/onboard",
                json={
                    "bot_token": bot_token,
                    "slug": "tg_ops",
                    "operator_chat_id": "99887766",
                    "admin_channels": ["zabbix_community"],
                    "public_channels": ["cloud_releases"],
                    "register_webhook": True,
                },
            )
            self.assertEqual(onboard_res.status_code, 201)
            onboarded = onboard_res.json()
            self.assertEqual(onboarded["slug"], "tg-ops")
            self.assertEqual(onboarded["account_identifier"], "@argo_ops_bot")
            self.assertTrue(onboarded["webhook_registered"])
            self.assertEqual(len(tg_transport.webhooks_set), 1)
            self.assertNotIn(bot_token, onboard_res.text)

            webhook_secret = tg_transport.webhooks_set[0]["secret_token"]

            # Create and start a desktop bot under normal RAM (<80%).
            desktop_bot = client.post(
                "/api/bots",
                json={
                    "name": "Portal Extractor",
                    "role": "Authenticated legacy portal worker",
                    "runtime": "desktop",
                    "outbound_rbac": "internal",
                },
            ).json()
            started = client.post(f"/api/desktops/{desktop_bot['slug']}/toggle")
            self.assertEqual(started.status_code, 200)
            self.assertEqual(started.json()["desktop_state"], "running")

            # Simulate 84% RAM pressure -> triggers RAM Warning Telegram alert with inline button.
            ram_value["pct"] = 84.0
            eval_warn = client.post("/api/watchdog/evaluate")
            self.assertEqual(eval_warn.status_code, 200)
            self.assertEqual(len(eval_warn.json()["telegram_deliveries"]), 1)
            last_msg = tg_transport.sent_messages[-1]
            self.assertIn("84.0%", last_msg["text"])
            self.assertEqual(
                last_msg["reply_markup"]["inline_keyboard"][0][0]["callback_data"],
                STOP_IDLE_DESKTOPS_CALLBACK,
            )

            # Webhook without or with wrong secret is rejected with 401.
            unauthorized_hook = client.post(
                "/hooks/telegram/tg-ops",
                json={"update_id": 1},
            )
            self.assertEqual(unauthorized_hook.status_code, 401)

            # Tapping [Stop Idle Desktops] answers callback, hibernates running desktop, locks card.
            hook_payload = {
                "update_id": 1001,
                "callback_query": {
                    "id": "cbq_1",
                    "from": {"id": 42, "username": "operator_dimi"},
                    "data": STOP_IDLE_DESKTOPS_CALLBACK,
                    "message": {
                        "message_id": last_msg["message_id"],
                        "chat": {"id": 99887766},
                        "text": last_msg["text"],
                    },
                },
            }
            handled = client.post(
                "/hooks/telegram/tg-ops",
                headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                json=hook_payload,
            )
            self.assertEqual(handled.status_code, 200)
            self.assertEqual(handled.json()["stopped_desktops"], [desktop_bot["slug"]])
            self.assertEqual(len(tg_transport.answered_callbacks), 1)
            self.assertEqual(len(tg_transport.edited_messages), 1)
            self.assertIn("Hibernated 1 desktop container", tg_transport.edited_messages[0]["text"])
            self.assertIsNone(tg_transport.edited_messages[0]["reply_markup"])

            # Duplicate Telegram update_id is dropped idempotently.
            dup_hook = client.post(
                "/hooks/telegram/tg-ops",
                headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                json=hook_payload,
            )
            self.assertEqual(dup_hook.status_code, 200)
            self.assertEqual(dup_hook.json()["status"], "duplicate_ignored")

            # Restart desktop under low RAM, then simulate >= 90% Critical RAM + >= 85% Disk.
            ram_value["pct"] = 42.0
            self.assertEqual(
                client.post(f"/api/desktops/{desktop_bot['slug']}/toggle").json()["desktop_state"],
                "running",
            )
            ram_value["pct"] = 93.0
            ram_value["disk"] = 88.0
            eval_crit = client.post("/api/watchdog/evaluate")
            self.assertEqual(eval_crit.status_code, 200)
            crit_data = eval_crit.json()
            self.assertEqual(crit_data["stopped_desktops"], [desktop_bot["slug"]])
            self.assertEqual(
                client.get(f"/api/bots/{desktop_bot['slug']}").json()["desktop_state"],
                "hibernated",
            )
            self.assertFalse((temp_dir / "stale.tmp").exists())
            self.assertTrue((temp_dir / "argo.db").exists())

            # Health probe failure transitions connector to 'degraded' with scrubbed error.
            tg_transport.fail_get_me = True
            failed_probe = client.post("/api/integrations/tg-ops/test", json={})
            self.assertEqual(failed_probe.status_code, 502)
            self.assertNotIn(bot_token, failed_probe.text)
            integrations = client.get("/api/integrations").json()
            self.assertEqual(integrations[0]["status"], "degraded")
            self.assertNotIn(bot_token, integrations[0]["last_error"])

            # Probe recovery restores 'ok'.
            tg_transport.fail_get_me = False
            ok_probe = client.post(
                "/api/integrations/tg-ops/test",
                json={"send_test_message": True},
            )
            self.assertEqual(ok_probe.status_code, 200)
            self.assertEqual(ok_probe.json()["status"], "ok")

        # Double-check raw SQLite never contains plaintext Telegram bot_token.
        raw_conn = sqlite3.connect(str(self.db_path))
        raw_blob = raw_conn.execute(
            "SELECT encrypted_secrets FROM oauth_accounts WHERE slug = 'tg-ops'"
        ).fetchone()[0]
        raw_conn.close()
        self.assertNotIn(bot_token.encode("utf-8"), raw_blob)

    def test_watchdog_cooldown_hysteresis_deduplication(self) -> None:
        conn = init_db(self.db_path)
        repo = ArgoRepository(conn=conn, vault=SecretVault(self.master_key))
        repo.ensure_defaults()
        bus = EventBus("valkey://127.0.0.1:1/0", repo=repo)
        tg_transport = FakeTelegramTransport()
        tg_service = TelegramBotService(repo=repo, bus=bus, transport=tg_transport)
        ram_state = {"pct": 84.0}
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "cpu_percent": 20.0,
                "ram_percent": ram_state["pct"],
                "ram_total_gb": 16.0,
                "disk_percent": 35.0,
            },
            alert_cooldown_seconds=600.0,
        )

        async def scenario() -> None:
            await tg_service.onboard_bot(
                bot_token="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345",
                slug="tg-cooldown",
                operator_chat_id="99887766",
                register_webhook=False,
            )

            first = await guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=tg_service,
                force_notify=False,
            )
            self.assertEqual(len(first["telegram_deliveries"]), 1)
            self.assertEqual(len(tg_transport.sent_messages), 1)

            # Re-evaluating within the 600s cooldown sends 0 duplicate alerts.
            second = await guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=tg_service,
                force_notify=False,
            )
            self.assertEqual(len(second["telegram_deliveries"]), 0)
            self.assertEqual(len(tg_transport.sent_messages), 1)

            # Dropping below 80% resets hysteresis state with 0 alerts.
            ram_state["pct"] = 45.0
            recovered = await guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=tg_service,
                force_notify=False,
            )
            self.assertEqual(len(recovered["telegram_deliveries"]), 0)
            self.assertEqual(recovered["actions"], [])

            # Spiking back to 84% triggers a fresh alert immediately.
            ram_state["pct"] = 84.0
            spiked = await guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=tg_service,
                force_notify=False,
            )
            self.assertEqual(len(spiked["telegram_deliveries"]), 1)
            self.assertEqual(len(tg_transport.sent_messages), 2)

        try:
            asyncio.run(scenario())
        finally:
            conn.close()

    def test_pydantic_ai_adapter_wiring_with_stub_modules(self) -> None:
        captured: dict[str, Any] = {"agent_init": None, "fallback_models": None}

        class _StubProvider:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

        class _StubModel:
            def __init__(self, model_name: str, *, provider: _StubProvider) -> None:
                self.model_name = model_name
                self.provider = provider

        class _StubFallbackModel:
            def __init__(self, *models: Any) -> None:
                self.models = models
                captured["fallback_models"] = models

        class _StubModelSettings:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

        class _StubAgent:
            def __init__(self, *, model: Any, instructions: str | None = None, model_settings: Any = None) -> None:
                captured["agent_init"] = {
                    "model": model,
                    "instructions": instructions,
                    "model_settings": model_settings,
                }

            async def run(self, user_prompt: str) -> Any:
                return SimpleNamespace(
                    output=f"Stubbed reply for: {user_prompt}",
                    usage=lambda: SimpleNamespace(input_tokens=77, output_tokens=33),
                    response=SimpleNamespace(model_name="claude-4.5-sonnet"),
                )

        def _mod(name: str, **attrs: Any) -> types.ModuleType:
            m = types.ModuleType(name)
            for k, v in attrs.items():
                setattr(m, k, v)
            return m

        stub_modules = {
            "pydantic_ai": _mod("pydantic_ai", Agent=_StubAgent),
            "pydantic_ai.models": _mod("pydantic_ai.models"),
            "pydantic_ai.models.fallback": _mod("pydantic_ai.models.fallback", FallbackModel=_StubFallbackModel),
            "pydantic_ai.settings": _mod("pydantic_ai.settings", ModelSettings=_StubModelSettings),
            "pydantic_ai.providers": _mod("pydantic_ai.providers"),
            "pydantic_ai.models.google": _mod("pydantic_ai.models.google", GoogleModel=_StubModel),
            "pydantic_ai.providers.google": _mod("pydantic_ai.providers.google", GoogleProvider=_StubProvider),
            "pydantic_ai.models.anthropic": _mod("pydantic_ai.models.anthropic", AnthropicModel=_StubModel),
            "pydantic_ai.providers.anthropic": _mod("pydantic_ai.providers.anthropic", AnthropicProvider=_StubProvider),
            "pydantic_ai.models.openai": _mod("pydantic_ai.models.openai", OpenAIChatModel=_StubModel),
            "pydantic_ai.providers.openai": _mod("pydantic_ai.providers.openai", OpenAIProvider=_StubProvider),
            "pydantic_ai.models.xai": _mod("pydantic_ai.models.xai", XaiModel=_StubModel),
            "pydantic_ai.providers.xai": _mod("pydantic_ai.providers.xai", XaiProvider=_StubProvider),
            "pydantic_ai.models.openrouter": _mod("pydantic_ai.models.openrouter", OpenRouterModel=_StubModel),
            "pydantic_ai.providers.openrouter": _mod("pydantic_ai.providers.openrouter", OpenRouterProvider=_StubProvider),
            "pydantic_ai.models.ollama": _mod("pydantic_ai.models.ollama", OllamaModel=_StubModel),
            "pydantic_ai.providers.ollama": _mod("pydantic_ai.providers.ollama", OllamaProvider=_StubProvider),
        }

        conn = init_db(self.db_path)
        repo = ArgoRepository(conn=conn, vault=SecretVault(self.master_key))
        repo.ensure_defaults()
        repo.upsert_model(
            slug="google_gemini_flash",
            provider_type="google",
            model_id="google:gemini-3.8-flash",
            api_key="sk-google-stub-123",
            is_default=True,
        )
        repo.upsert_model(
            slug="anthropic_claude",
            provider_type="anthropic",
            model_id="anthropic:claude-4.5-sonnet",
            api_key="sk-anthropic-stub-456",
            is_default=False,
        )

        async def scenario() -> None:
            provider_specs = [
                ("google", "google:gemini-4-argon", "k-g", "https://g.example", {"api_key": "k-g", "base_url": "https://g.example"}),
                ("anthropic", "anthropic:claude-4.5-sonnet", "k-a", "https://a.example", {"api_key": "k-a", "base_url": "https://a.example"}),
                ("openai", "openai:gpt-5.2", "k-o", "https://o.example", {"api_key": "k-o", "base_url": "https://o.example"}),
                ("xai", "xai:grok-4", "k-x", "https://x.example", {"api_key": "k-x", "api_host": "https://x.example"}),
                ("openrouter", "openrouter:meta/llama-4", "k-r", None, {"api_key": "k-r"}),
                ("ollama", "ollama:qwen3:14b", None, None, {"base_url": "http://localhost:11434/v1", "api_key": "ollama"}),
            ]
            for p_type, m_id, key, base, expected_kwargs in provider_specs:
                built = _build_single_pydantic_ai_model(
                    {
                        "provider_type": p_type,
                        "model_id": m_id,
                        "api_key": key,
                        "api_base": base,
                    }
                )
                self.assertEqual(built.model_name, m_id.split(":", 1)[1])
                self.assertEqual(built.provider.kwargs, expected_kwargs)

            router = LLMRouter(repo=repo, transport=None)
            res = await router.complete(
                bot_slug="editorial-reviewer",
                prompt="Check stub fallback wiring",
                requested_model="google:gemini-3.8-flash",
                system_prompt="Verify runtime adapter.",
                trigger_type="test",
            )
            self.assertIsInstance(captured["agent_init"]["model"], _StubFallbackModel)
            self.assertEqual(len(captured["fallback_models"]), 2)
            self.assertEqual(captured["agent_init"]["model_settings"].kwargs["thinking"], "low")
            self.assertTrue(res.used_fallback)
            self.assertEqual(res.model_used, "anthropic:claude-4.5-sonnet")
            self.assertEqual(res.input_tokens, 77)
            self.assertEqual(res.output_tokens, 33)
            self.assertEqual(repo.list_bot_runs(limit=1)[0]["llm_model_used"], "anthropic:claude-4.5-sonnet")

        try:
            with patch.dict(sys.modules, stub_modules):
                asyncio.run(scenario())
        finally:
            conn.close()

    def test_telegram_operator_status_commands_llm_assistant_and_custom_bot_routing(self) -> None:
        llm_requests: list[LLMRequest] = []

        async def fake_llm(req: LLMRequest) -> tuple[str, int, int]:
            llm_requests.append(req)
            if "Refine this Argo declarative bot JSON spec" in req.user_prompt:
                return (
                    json.dumps(
                        {
                            "name": "Telegram Ops Responder",
                            "role": "Answer operator Telegram requests with live job and host status",
                            "role_prompt": "Always summarize bot jobs, pending approvals, and host RAM clearly.",
                            "model": "google:gemini-3.8-flash",
                            "outbound_rbac": "execute",
                            "daily_cap": 50,
                            "collections": {"read": ["bot_threads"], "write": ["bot_threads"]},
                            "routines": [
                                {
                                    "type": "on_event",
                                    "event": "telegram.message",
                                    "label": "On Telegram Operator Message",
                                    "schedule": "on:telegram.message",
                                    "enabled": True,
                                }
                            ],
                        }
                    ),
                    20,
                    30,
                )
            parsed = json.loads(req.user_prompt)
            self.assertIn("platform_status", parsed)
            if "Argo Operator Status Assistant" in req.system_prompt:
                ram = parsed["platform_status"]["host"]["ram_percent"]
                return (f"Assistant live report: Host RAM {ram}%, 0 errors."), 45, 25
            return (
                json.dumps(
                    {
                        "summary": f"Custom bot status reply for chat query: {parsed['trigger_payload']['text']}",
                        "actions": [],
                    }
                ),
                40,
                20,
            )

        tg_transport = FakeTelegramTransport()
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "cpu_percent": 22.5,
                "ram_percent": 51.5,
                "ram_total_gb": 16.0,
                "disk_percent": 34.0,
            }
        )
        bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
        second_token = "987654321:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"

        with TestClient(
            create_app(
                settings=self._make_settings(),
                guard=guard,
                llm_transport=fake_llm,
                telegram_transport=tg_transport,
            )
        ) as client:
            # 1. Connector without operator_chat_id rejects send_test_message=true cleanly with HTTP 400.
            no_chat = client.post(
                "/api/integrations/telegram/onboard",
                json={"bot_token": second_token, "slug": "tg_nochat"},
            )
            self.assertEqual(no_chat.status_code, 201, no_chat.text)
            fail_test = client.post(
                "/api/integrations/tg-nochat/test",
                json={"send_test_message": True},
            )
            self.assertEqual(fail_test.status_code, 400, fail_test.text)

            # 2. Onboard primary Telegram operator channel with webhook and send live test message.
            onboarded = client.post(
                "/api/integrations/telegram/onboard",
                json={
                    "bot_token": bot_token,
                    "slug": "tg_ops",
                    "operator_chat_id": "99887766",
                    "register_webhook": True,
                },
            )
            self.assertEqual(onboarded.status_code, 201, onboarded.text)
            webhook_secret = tg_transport.webhooks_set[0]["secret_token"]

            live_test = client.post(
                "/api/integrations/tg-ops/test",
                json={"send_test_message": True},
            )
            self.assertEqual(live_test.status_code, 200, live_test.text)
            self.assertTrue(
                any("Send /status or ask any question" in m["text"] for m in tg_transport.sent_messages)
            )

            # Seed one pending approval item for /approvals report visibility.
            client.post(
                "/api/approvals",
                json={
                    "correlation_id": "corr_seed_apr",
                    "bot_slug": "seed-bot",
                    "target_account_slug": "tg-ops",
                    "action_type": "publish_telegram",
                    "payload": {"text": "Queued summary ready for sign-off"},
                },
            )
            sent_before_dm = len(tg_transport.sent_messages)
            llm_before_dm = len(llm_requests)

            # 3. Unauthorized chat ID is ignored safely without replying or calling LLM.
            unauth = client.post(
                "/hooks/telegram/tg-ops",
                headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                json={
                    "update_id": 2001,
                    "message": {
                        "message_id": 10,
                        "from": {"id": 555, "username": "stranger", "is_bot": False},
                        "chat": {"id": 111222333, "type": "private"},
                        "text": "/status",
                    },
                },
            )
            self.assertEqual(unauth.status_code, 200)
            self.assertEqual(unauth.json()["status"], "ignored_unauthorized_chat")
            self.assertEqual(len(tg_transport.sent_messages), sent_before_dm)
            self.assertEqual(len(llm_requests), llm_before_dm)

            # 4. Built-in slash commands reply directly with 0 LLM tokens.
            for idx, (cmd, expected_fragment) in enumerate(
                (
                    ("/help", "Argo Operator Telegram Controls"),
                    ("/status", "RAM 51.5%"),
                    ("/bots", "Argo Bots"),
                    ("/runs", "Argo Recent Bot Jobs"),
                    ("/approvals", "Queued summary ready for sign-off"),
                ),
                start=1,
            ):
                res = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                    json={
                        "update_id": 2010 + idx,
                        "message": {
                            "message_id": 20 + idx,
                            "from": {"id": 42, "username": "dimi", "is_bot": False},
                            "chat": {"id": 99887766, "type": "private"},
                            "text": cmd,
                        },
                    },
                )
                self.assertEqual(res.status_code, 200, res.text)
                self.assertEqual(res.json()["status"], "replied_command")
                self.assertIn(expected_fragment, tg_transport.sent_messages[-1]["text"])
            self.assertEqual(len(llm_requests), llm_before_dm)

            # 5. Free-form natural-language DM uses built-in LLM Operator Assistant when no bot handles telegram.message.
            nl_dm = client.post(
                "/hooks/telegram/tg-ops",
                headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                json={
                    "update_id": 2020,
                    "message": {
                        "message_id": 30,
                        "from": {"id": 42, "username": "dimi", "is_bot": False},
                        "chat": {"id": 99887766, "type": "private"},
                        "text": "What is the status of bot jobs and host RAM?",
                    },
                },
            )
            self.assertEqual(nl_dm.status_code, 200, nl_dm.text)
            self.assertEqual(nl_dm.json()["status"], "replied_assistant")
            self.assertIn("Assistant live report: Host RAM 51.5%", tg_transport.sent_messages[-1]["text"])

            # 6. Draft & create a custom Telegram responder bot via Bot Builder -> receives on_event telegram.message.
            drafted = client.post(
                "/api/bots/builder/draft",
                json={
                    "prompt": "Create a Telegram bot that answers my Telegram requests with bot job status and host details",
                },
            )
            self.assertEqual(drafted.status_code, 200, drafted.text)
            spec = drafted.json()["draft"]
            self.assertEqual(spec["outbound_rbac"], "execute")
            self.assertEqual(spec["routines"][0]["event"], "telegram.message")
            self.assertIn(
                "platform_status",
                [t.get("name") for t in spec["tools"] if isinstance(t, dict)],
            )

            created_bot = client.post("/api/bots", json=spec)
            self.assertEqual(created_bot.status_code, 201, created_bot.text)
            bot_slug = created_bot.json()["slug"]

            msg_count_before_bot = len(tg_transport.sent_messages)
            routed_dm = client.post(
                "/hooks/telegram/tg-ops",
                headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                json={
                    "update_id": 2030,
                    "message": {
                        "message_id": 40,
                        "from": {"id": 42, "username": "dimi", "is_bot": False},
                        "chat": {"id": 99887766, "type": "private"},
                        "text": "Give me the latest bot job report",
                    },
                },
            )
            self.assertEqual(routed_dm.status_code, 200, routed_dm.text)
            self.assertEqual(routed_dm.json()["status"], "dispatched_to_bot")
            self.assertIn(bot_slug, routed_dm.json()["matched_bots"])

            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and len(tg_transport.sent_messages) == msg_count_before_bot:
                client.get("/api/runs")
                time.sleep(0.02)

            self.assertGreater(len(tg_transport.sent_messages), msg_count_before_bot)
            self.assertIn(
                "Custom bot status reply for chat query: Give me the latest bot job report",
                tg_transport.sent_messages[-1]["text"],
            )

    def test_telegram_html_markdown_formatting_and_parse_mode_fallback(self) -> None:
        screenshot_markdown = (
            "📢 **Open Source & Infrastructure Update: Kubernetes Deprecating kube-proxy IPVS Mode**\n\n"
            "• **Project**: Kubernetes (SIG Network)\n"
            "• **Context**: Official roadmap update on `kube-proxy` datapaths.\n"
            "• **Technical Summary**: Kubernetes is formally scheduling the removal of the IPVS backend from "
            "`kube-proxy`. While IPVS originally provided significant scalability advantages over legacy iptables, "
            "modern developments—notably the production maturation of the `nftables` proxy backend and standard "
            "adoption of eBPF-based CNIs (Cilium, Calico eBPF)—have rendered IPVS maintenance unsustainable. "
            "Enterprise cluster operators running IPVS should evaluate migration paths toward nftables or eBPF dataplanes.\n"
            "• **Reference**: https://kubernetes.io/blog/2026/11/16/ipvs-removal/"
        )
        formatted_screenshot = format_telegram_html(screenshot_markdown)
        self.assertIn(
            "📢 <b>Open Source &amp; Infrastructure Update: Kubernetes Deprecating kube-proxy IPVS Mode</b>",
            formatted_screenshot,
        )
        self.assertIn("• <b>Project</b>: Kubernetes (SIG Network)", formatted_screenshot)
        self.assertIn("<code>kube-proxy</code>", formatted_screenshot)
        self.assertIn("<code>nftables</code>", formatted_screenshot)
        self.assertIn(
            "• <b>Reference</b>: https://kubernetes.io/blog/2026/11/16/ipvs-removal/",
            formatted_screenshot,
        )
        self.assertNotIn("**", formatted_screenshot)
        self.assertNotIn("`kube-proxy`", formatted_screenshot)

        rich_markdown = "\n".join(
            [
                "## Cluster **Summary** ###",
                "```python",
                "x = a < b and c & d",
                "```",
                "Docs: [Kubernetes **IPVS**](https://kubernetes.io/docs/kube_proxy/?a=1&b=2)",
                "Link: (https://example.com/path_with_underscores/run?x=1&y=2).",
                "Vars: snake_case_name, _italic text_, *star italic*, ~~old~~, __under__, ||secret||",
                "Alert: RAM <80% -> ok & 2 > 1",
                "> Quote line 1 with **bold**",
                "> Quote line 2 with `kubectl get svc`",
                "---",
                "- First **bullet**",
                "* Second _bullet_",
                "<b>Preserved</b> and <script>alert(1)</script>",
            ]
        )
        formatted_rich = format_telegram_html(rich_markdown)
        self.assertIn("<b>Cluster Summary</b>", formatted_rich)
        self.assertIn(
            '<pre><code class="language-python">x = a &lt; b and c &amp; d</code></pre>',
            formatted_rich,
        )
        self.assertIn(
            '<a href="https://kubernetes.io/docs/kube_proxy/?a=1&amp;b=2">Kubernetes <b>IPVS</b></a>',
            formatted_rich,
        )
        self.assertIn(
            "(https://example.com/path_with_underscores/run?x=1&amp;y=2).",
            formatted_rich,
        )
        self.assertIn("Vars: snake_case_name,", formatted_rich)
        self.assertIn("<i>italic text</i>", formatted_rich)
        self.assertIn("<i>star italic</i>", formatted_rich)
        self.assertIn("<s>old</s>", formatted_rich)
        self.assertIn("<u>under</u>", formatted_rich)
        self.assertIn("<tg-spoiler>secret</tg-spoiler>", formatted_rich)
        self.assertIn("Alert: RAM &lt;80% -&gt; ok &amp; 2 &gt; 1", formatted_rich)
        self.assertIn(
            "<blockquote>Quote line 1 with <b>bold</b>\nQuote line 2 with <code>kubectl get svc</code></blockquote>",
            formatted_rich,
        )
        self.assertIn("──────────", formatted_rich)
        self.assertIn("• First <b>bullet</b>", formatted_rich)
        self.assertIn("• Second <i>bullet</i>", formatted_rich)
        self.assertIn("<b>Preserved</b> and &lt;script&gt;alert(1)&lt;/script&gt;", formatted_rich)

        oversized = ("**word** " * 600).strip()
        bounded_html = format_telegram_html(oversized)
        self.assertLessEqual(len(bounded_html), 4096)
        self.assertEqual(bounded_html.count("<b>"), bounded_html.count("</b>"))

        transport = AiogramTelegramTransport()
        bot_token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"

        # Verify stdlib HTTPS transport branch sets parse_mode="HTML" and retries without parse_mode on entity errors.
        recorded_http_calls: list[tuple[str, dict[str, Any]]] = []
        fail_next_with_entity_error = {"active": False}

        class _FakeHTTPResponse:
            def __init__(self, body: dict[str, Any]) -> None:
                self._raw = json.dumps(body).encode("utf-8")

            def read(self) -> bytes:
                return self._raw

            def __enter__(self) -> "_FakeHTTPResponse":
                return self

            def __exit__(self, *_args: Any) -> bool:
                return False

        def _fake_urlopen(req: Any, timeout: float = 15) -> _FakeHTTPResponse:  # noqa: ARG001
            method = req.full_url.rsplit("/", 1)[-1]
            payload = json.loads(req.data.decode("utf-8"))
            recorded_http_calls.append((method, payload))
            if fail_next_with_entity_error["active"]:
                fail_next_with_entity_error["active"] = False
                err_payload = json.dumps(
                    {
                        "ok": False,
                        "description": "Bad Request: can't parse entities: Can't find end tag",
                    }
                ).encode("utf-8")
                raise urllib.error.HTTPError(
                    req.full_url,
                    400,
                    "Bad Request",
                    None,
                    io.BytesIO(err_payload),
                )
            return _FakeHTTPResponse(
                {"ok": True, "result": {"message_id": 77, "chat": {"id": 998877}}}
            )

        with (
            patch.dict(sys.modules, {"aiogram": None, "aiogram.types": None}),
            patch("urllib.request.urlopen", side_effect=_fake_urlopen),
        ):
            sent = asyncio.run(
                transport.send_message(bot_token, chat_id=998877, text="**Hello** `world`")
            )
            self.assertEqual(sent["message_id"], 77)
            self.assertEqual(recorded_http_calls[-1][0], "sendMessage")
            self.assertEqual(recorded_http_calls[-1][1]["parse_mode"], "HTML")
            self.assertEqual(recorded_http_calls[-1][1]["text"], "<b>Hello</b> <code>world</code>")

            edited = asyncio.run(
                transport.edit_message_text(
                    bot_token, chat_id=998877, message_id=77, text="Updated **card**"
                )
            )
            self.assertEqual(edited["message_id"], 77)
            self.assertEqual(recorded_http_calls[-1][0], "editMessageText")
            self.assertEqual(recorded_http_calls[-1][1]["parse_mode"], "HTML")
            self.assertEqual(recorded_http_calls[-1][1]["text"], "Updated <b>card</b>")

            fail_next_with_entity_error["active"] = True
            retried_send = asyncio.run(
                transport.send_message(bot_token, chat_id=998877, text="Plain **fallback** text")
            )
            self.assertEqual(retried_send["message_id"], 77)
            self.assertEqual(recorded_http_calls[-2][1].get("parse_mode"), "HTML")
            self.assertNotIn("parse_mode", recorded_http_calls[-1][1])
            self.assertEqual(recorded_http_calls[-1][1]["text"], "Plain **fallback** text")

            fail_next_with_entity_error["active"] = True
            retried_edit = asyncio.run(
                transport.edit_message_text(
                    bot_token, chat_id=998877, message_id=77, text="Edit **fallback** text"
                )
            )
            self.assertEqual(retried_edit["message_id"], 77)
            self.assertEqual(recorded_http_calls[-2][1].get("parse_mode"), "HTML")
            self.assertNotIn("parse_mode", recorded_http_calls[-1][1])
            self.assertEqual(recorded_http_calls[-1][1]["text"], "Edit **fallback** text")

        # Verify aiogram.Bot branch passes parse_mode="HTML" and falls back cleanly on entity errors.
        aiogram_calls: list[tuple[str, dict[str, Any]]] = []
        fail_aiogram_entity = {"active": False}

        class _FakeAiogramBot:
            def __init__(self, *, token: str) -> None:
                self.token = token

            async def __aenter__(self) -> "_FakeAiogramBot":
                return self

            async def __aexit__(self, *_args: Any) -> bool:
                return False

            async def send_message(self, **kwargs: Any) -> Any:
                aiogram_calls.append(("send_message", dict(kwargs)))
                if fail_aiogram_entity["active"]:
                    fail_aiogram_entity["active"] = False
                    raise RuntimeError("TelegramBadRequest: can't parse entities: unsupported tag")
                return SimpleNamespace(message_id=88, chat=SimpleNamespace(id=998877))

            async def edit_message_text(self, **kwargs: Any) -> Any:
                aiogram_calls.append(("edit_message_text", dict(kwargs)))
                if fail_aiogram_entity["active"]:
                    fail_aiogram_entity["active"] = False
                    raise RuntimeError("TelegramBadRequest: can't parse entities: unsupported tag")
                return SimpleNamespace(message_id=88)

        fake_aiogram = types.ModuleType("aiogram")
        fake_aiogram.Bot = _FakeAiogramBot  # type: ignore[attr-defined]
        fake_aiogram_types = types.ModuleType("aiogram.types")

        class _FakeInlineKeyboardMarkup:
            @classmethod
            def model_validate(cls, data: Any) -> Any:
                return data

        fake_aiogram_types.InlineKeyboardMarkup = _FakeInlineKeyboardMarkup  # type: ignore[attr-defined]

        with patch.dict(
            sys.modules,
            {"aiogram": fake_aiogram, "aiogram.types": fake_aiogram_types},
        ):
            aio_sent = asyncio.run(
                transport.send_message(bot_token, chat_id=998877, text="**Aiogram** `check`")
            )
            self.assertEqual(aio_sent["message_id"], 88)
            self.assertEqual(aiogram_calls[-1][0], "send_message")
            self.assertEqual(aiogram_calls[-1][1]["parse_mode"], "HTML")
            self.assertEqual(aiogram_calls[-1][1]["text"], "<b>Aiogram</b> <code>check</code>")

            aio_edited = asyncio.run(
                transport.edit_message_text(
                    bot_token, chat_id=998877, message_id=88, text="**Aiogram** edited"
                )
            )
            self.assertEqual(aio_edited["message_id"], 88)
            self.assertEqual(aiogram_calls[-1][0], "edit_message_text")
            self.assertEqual(aiogram_calls[-1][1]["parse_mode"], "HTML")
            self.assertEqual(aiogram_calls[-1][1]["text"], "<b>Aiogram</b> edited")

            fail_aiogram_entity["active"] = True
            asyncio.run(
                transport.send_message(bot_token, chat_id=998877, text="Aiogram **fallback**")
            )
            self.assertEqual(aiogram_calls[-2][1].get("parse_mode"), "HTML")
            self.assertNotIn("parse_mode", aiogram_calls[-1][1])
            self.assertEqual(aiogram_calls[-1][1]["text"], "Aiogram **fallback**")

            fail_aiogram_entity["active"] = True
            asyncio.run(
                transport.edit_message_text(
                    bot_token, chat_id=998877, message_id=88, text="Aiogram edit **fallback**"
                )
            )
            self.assertEqual(aiogram_calls[-2][1].get("parse_mode"), "HTML")
            self.assertNotIn("parse_mode", aiogram_calls[-1][1])
            self.assertEqual(aiogram_calls[-1][1]["text"], "Aiogram edit **fallback**")

    def test_model_discovery_custom_pricing_and_per_model_attribution(self) -> None:
        from unittest.mock import AsyncMock, patch
        from argo_core.llm.router import estimate_cost_usd, resolve_model_pricing

        # Verify custom pricing override takes precedence over built-in catalog.
        self.assertEqual(resolve_model_pricing("google:gemini-4-argon")["source"], "catalog")
        self.assertEqual(
            resolve_model_pricing("google:gemini-4-argon", custom_input=2.0, custom_output=8.0),
            {"input_per_million": 2.0, "output_per_million": 8.0, "source": "custom"},
        )
        self.assertAlmostEqual(
            estimate_cost_usd(
                "google:gemini-4-argon",
                500_000,
                250_000,
                input_price_per_million=2.0,
                output_price_per_million=8.0,
            ),
            3.0,
            places=5,
        )

        async def fake_transport(req):
            return {"text": f"ok:{req.model_id}", "input_tokens": 1000, "output_tokens": 500}

        with TestClient(
            create_app(
                settings=self._make_settings(),
                llm_transport=fake_transport,
            )
        ) as client:
            # Save Argon with custom input/output pricing.
            save_res = client.post(
                "/api/models",
                json={
                    "slug": "google_gemini_argon",
                    "provider_type": "google",
                    "model_id": "google:gemini-4-argon",
                    "api_key": "AIzaSyTestKey1234567890",
                    "input_price_per_million": 2.0,
                    "output_price_per_million": 8.0,
                },
            )
            self.assertEqual(save_res.status_code, 201)
            saved = save_res.json()
            self.assertEqual(saved["pricing_source"], "custom")
            self.assertEqual(saved["effective_input_price_per_million"], 2.0)
            self.assertEqual(saved["effective_output_price_per_million"], 8.0)

            # Discover endpoint forwards stored provider key when api_key is omitted.
            fake_discovery = {
                "provider_type": "google",
                "models": [
                    {
                        "model_id": "google:gemini-4-argon",
                        "display_name": "Gemini 4 Argon",
                        "context_window": 1048576,
                        "input_price_per_million": 1.25,
                        "output_price_per_million": 5.0,
                        "pricing_source": "catalog",
                    }
                ],
                "pricing_mode": "estimated",
                "source_note": "Live list",
            }
            with patch(
                "argo_core.api.routes.discover_provider_models",
                new=AsyncMock(return_value=fake_discovery),
            ) as mock_disc:
                disc_res = client.post(
                    "/api/models/discover",
                    json={"provider_type": "google", "provider_slug": "google_gemini_argon"},
                )
                self.assertEqual(disc_res.status_code, 200)
                self.assertEqual(disc_res.json()["models"][0]["model_id"], "google:gemini-4-argon")
                mock_disc.assert_awaited_once()
                self.assertEqual(mock_disc.call_args.kwargs["api_key"], "AIzaSyTestKey1234567890")

            # Seed runs across two models (including a deleted/system slug on Argon).
            repo = client.app.state.repo
            bot = client.post(
                "/api/bots",
                json={"name": "Flash Bot", "role": "Triage", "model": "google:gemini-3.8-flash"},
            ).json()
            repo.record_bot_run(
                correlation_id="corr_f1",
                bot_slug=bot["slug"],
                trigger_type="manual",
                hop_count=1,
                llm_model_used="google:gemini-3.8-flash",
                input_tokens=10000,
                output_tokens=2000,
                estimated_cost_usd=0.0027,
                status="success",
                summary="Flash run",
            )
            repo.record_bot_run(
                correlation_id="corr_a1",
                bot_slug="deleted-architect",
                trigger_type="manual",
                hop_count=1,
                llm_model_used="google:gemini-4-argon",
                input_tokens=100000,
                output_tokens=20000,
                estimated_cost_usd=0.225,
                status="success",
                summary="Argon run",
            )

            all_models = client.get("/api/models").json()
            by_slug = {b["bot_slug"]: b for b in all_models["usage_by_bot"]}
            self.assertTrue(by_slug[bot["slug"]]["exists"])
            self.assertFalse(by_slug["deleted-architect"]["exists"])
            self.assertEqual(
                by_slug["deleted-architect"]["models_used"][0]["model_id"],
                "google:gemini-4-argon",
            )

            argon_only = client.get("/api/models?model_id=google:gemini-4-argon").json()
            self.assertEqual(len(argon_only["recent_runs"]), 1)
            self.assertEqual(argon_only["recent_runs"][0]["bot_slug"], "deleted-architect")
            self.assertEqual(
                argon_only["recent_runs"][0]["llm_model_used"],
                "google:gemini-4-argon",
            )


if __name__ == "__main__":
    unittest.main()
