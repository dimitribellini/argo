"""Sprint 1 verification tests for argo-core API, Vault, Valkey bus, Resource Guard, and SPA."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from argo_core.bus.valkey_bus import EventBus, HopLimitExceededError
from argo_core.config import ArgoSettings
from argo_core.db.repositories import ArgoRepository
from argo_core.db.sqlite import init_db
from argo_core.main import create_app
from argo_core.security.vault import SecretVault
from argo_core.watchdog.resource_guard import HostResourceGuard


class TestSprint1CoreAPI(unittest.TestCase):
    """Verify Sprint 1 backend substrate, security boundaries, and workspace endpoints."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "argo_sprint1.db"
        self.master_key = Fernet.generate_key().decode("utf-8")
        self.dist_dir = REPO_ROOT / "frontend" / "dist"
        self.settings = ArgoSettings(
            master_key=self.master_key,
            db_path=str(self.db_path),
            valkey_url="valkey://127.0.0.1:1/0",
            desktop_volumes_root="/srv/argo/desktops",
            public_base_url="http://localhost:4180",
            static_dir=str(self.dist_dir) if self.dist_dir.is_dir() else "",
        )

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _make_client(
        self,
        ram_percent: float = 48.0,
        static_dir: str | None = None,
    ) -> TestClient:
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "cpu_percent": 18.0,
                "ram_percent": ram_percent,
                "ram_total_gb": 16.0,
                "disk_percent": 35.0,
            }
        )
        cfg = ArgoSettings(
            master_key=self.settings.master_key,
            db_path=self.settings.db_path,
            valkey_url=self.settings.valkey_url,
            desktop_volumes_root=self.settings.desktop_volumes_root,
            public_base_url=self.settings.public_base_url,
            static_dir=self.settings.static_dir if static_dir is None else static_dir,
        )
        return TestClient(create_app(settings=cfg, guard=guard))

    def test_health_and_sso_principal(self) -> None:
        with self._make_client() as client:
            health = client.get("/api/health")
            self.assertEqual(health.status_code, 200)
            data = health.json()
            self.assertEqual(data["status"], "ok")
            self.assertTrue(data["sqlite_wal"])
            self.assertTrue(data["vault_configured"])
            self.assertEqual(data["host"]["ram_percent"], 48.0)

            me_default = client.get("/api/me")
            self.assertEqual(me_default.status_code, 200)
            self.assertFalse(me_default.json()["authenticated"])

            me_sso = client.get(
                "/api/me",
                headers={"X-Auth-Request-Email": "reviewer@example.com"},
            )
            self.assertEqual(me_sso.status_code, 200)
            self.assertTrue(me_sso.json()["authenticated"])
            self.assertEqual(me_sso.json()["email"], "reviewer@example.com")
            self.assertEqual(me_sso.json()["actor"], "user:reviewer@example.com")

    def test_vault_redaction_on_models_and_integrations(self) -> None:
        with self._make_client() as client:
            initial_models = client.get("/api/models").json()
            model_ids = {p["model_id"] for p in initial_models["providers"]}
            self.assertIn("google:gemini-3.8-flash", model_ids)
            self.assertIn("google:gemini-4-argon", model_ids)

            model_secret = "sk-test-secret-key-98765"
            mdl_res = client.post(
                "/api/models",
                json={
                    "slug": "anthropic_claude",
                    "provider_type": "anthropic",
                    "model_id": "anthropic:claude-4.5-sonnet",
                    "api_key": model_secret,
                    "is_default": False,
                    "monthly_budget_usd": 50.0,
                },
            )
            self.assertEqual(mdl_res.status_code, 201)
            self.assertTrue(mdl_res.json()["has_api_key"])
            self.assertNotIn("encrypted_api_key", mdl_res.json())
            self.assertNotIn(model_secret, mdl_res.text)

            int_secret = "123456:telegram-bot-secret-token"
            int_res = client.post(
                "/api/integrations",
                json={
                    "slug": "tg_main",
                    "provider": "telegram",
                    "display_name": "Argo Telegram Bot",
                    "account_identifier": "@argo_ops_bot",
                    "scopes": ["channel_post", "inline_approvals"],
                    "secrets": {"bot_token": int_secret},
                },
            )
            self.assertEqual(int_res.status_code, 201)
            self.assertTrue(int_res.json()["has_secrets"])
            self.assertNotIn("encrypted_secrets", int_res.json())
            self.assertNotIn(int_secret, int_res.text)

            get_models = client.get("/api/models")
            self.assertNotIn(model_secret, get_models.text)
            get_ints = client.get("/api/integrations")
            self.assertNotIn(int_secret, get_ints.text)

        raw_conn = sqlite3.connect(str(self.db_path))
        raw_key = raw_conn.execute(
            "SELECT encrypted_api_key FROM model_providers WHERE slug = 'anthropic-claude'"
        ).fetchone()[0]
        raw_secret = raw_conn.execute(
            "SELECT encrypted_secrets FROM oauth_accounts WHERE slug = 'tg-main'"
        ).fetchone()[0]
        raw_conn.close()
        self.assertNotIn(model_secret.encode("utf-8"), raw_key)
        self.assertNotIn(int_secret.encode("utf-8"), raw_secret)

    def test_valkey_bus_locks_idempotency_hop_guard_and_sse(self) -> None:
        conn = init_db(self.db_path)
        vault = SecretVault(self.master_key)
        repo = ArgoRepository(conn=conn, vault=vault)
        repo.ensure_defaults()
        bus = EventBus(valkey_url="valkey://127.0.0.1:1/0", repo=repo)

        async def run_bus_checks() -> None:
            self.assertTrue(await bus.acquire_lock("thread", "doc_1", "bot-a", ttl_seconds=60))
            self.assertFalse(await bus.acquire_lock("thread", "doc_1", "bot-b", ttl_seconds=60))
            self.assertFalse(await bus.release_lock("thread", "doc_1", "bot-b"))
            self.assertTrue(await bus.release_lock("thread", "doc_1", "bot-a"))
            self.assertTrue(await bus.acquire_lock("thread", "doc_1", "bot-b", ttl_seconds=60))

            self.assertTrue(await bus.check_and_mark_seen("ev_unique_1", ttl_seconds=60))
            self.assertFalse(await bus.check_and_mark_seen("ev_unique_1", ttl_seconds=60))

            with self.assertRaises(HopLimitExceededError):
                await bus.publish(
                    correlation_id="corr_loop",
                    source_slug="bot-a",
                    event_type="news.reviewed",
                    payload={"summary": "Loop test"},
                    hop_count=6,
                )

        try:
            asyncio.run(run_bus_checks())
        finally:
            conn.close()

        with self._make_client() as client:
            stream_res = client.get("/api/activity/stream?max_events=1")
            self.assertEqual(stream_res.status_code, 200)
            self.assertIn("text/event-stream", stream_res.headers["content-type"])
            self.assertIn("event: connected", stream_res.text)

    def test_declarative_bots_inspector_and_threads(self) -> None:
        with self._make_client() as client:
            create_res = client.post(
                "/api/bots",
                json={
                    "name": "Release Gatekeeper",
                    "role": "Evaluates reviewed items and publishes or escalates",
                    "runtime": "api",
                    "outbound_rbac": "draft",
                    "model": "google:gemini-3.8-flash",
                    "daily_cap": 10,
                },
            )
            self.assertEqual(create_res.status_code, 201)
            bot = create_res.json()
            slug = bot["slug"]

            patch_res = client.patch(
                f"/api/bots/{slug}",
                json={
                    "outbound_rbac": "execute",
                    "daily_cap": 15,
                    "model": "google:gemini-4-argon",
                },
            )
            self.assertEqual(patch_res.status_code, 200)
            patched = patch_res.json()
            self.assertEqual(patched["outbound_rbac"], "execute")
            self.assertEqual(patched["daily_cap"], 15)
            self.assertEqual(patched["model"], "google:gemini-4-argon")

            msg_res = client.post(
                f"/api/bots/{slug}/messages",
                json={"text": "Status check on current rules"},
            )
            self.assertEqual(msg_res.status_code, 200)
            messages = msg_res.json()["messages"]
            self.assertTrue(any(m["sender"] == "user" for m in messages))
            self.assertTrue(any(m["sender"] == "bot" for m in messages))

    def test_atomic_approval_lock_and_style_memory(self) -> None:
        with self._make_client() as client:
            created = client.post(
                "/api/approvals",
                json={
                    "correlation_id": "corr_zbx_1",
                    "bot_slug": "release-gatekeeper",
                    "target_account_slug": "tg_community",
                    "action_type": "publish_telegram",
                    "payload": {
                        "title": "Zabbix 7.4 Async Poller",
                        "text": "Original draft text with coupon CODE20",
                    },
                    "source_url": "https://zabbix.com/blog/7-4",
                    "source_excerpt": "Async pollers share epoll loops.",
                    "escalation_note": "Promo code detected",
                },
            )
            self.assertEqual(created.status_code, 201)
            approval_id = created.json()["id"]

            first = client.post(
                f"/api/approvals/{approval_id}/resolve",
                json={
                    "action": "edit_approve",
                    "edited_text": "Zabbix 7.4 introduces epoll-shared async pollers.",
                    "style_rule": "Strip promotional coupon codes from release summaries",
                },
            )
            self.assertEqual(first.status_code, 200)
            self.assertEqual(first.json()["status"], "approved")

            second = client.post(
                f"/api/approvals/{approval_id}/resolve",
                json={"action": "approve"},
            )
            self.assertEqual(second.status_code, 409)

            rules = client.get("/api/style-rules").json()
            self.assertEqual(len(rules), 1)
            self.assertIn("promotional coupon codes", rules[0]["rule_text"])

    def test_pages_and_fts5_collections(self) -> None:
        with self._make_client() as client:
            p1 = client.post(
                "/api/pages",
                json={
                    "title": "Monthly Operations",
                    "description": "Role-neutral operations summary",
                    "render_mode": "declarative_json",
                },
            )
            self.assertEqual(p1.status_code, 201)
            self.assertEqual(p1.json()["render_mode"], "declarative_json")

            p2 = client.post(
                "/api/pages",
                json={
                    "title": "Telemetry Chart",
                    "description": "Sandboxed SVG chart",
                    "render_mode": "sandboxed_html",
                    "content_payload": "<html><body><p>Sandboxed View</p></body></html>",
                },
            )
            self.assertEqual(p2.status_code, 201)
            self.assertEqual(p2.json()["render_mode"], "sandboxed_html")

            doc_res = client.post(
                "/api/collections/news_items/documents",
                json={
                    "external_key": "https://example.com/zabbix-async",
                    "search_text": "Zabbix 7.4 async SNMP poller benchmarks",
                    "doc": {"title": "Zabbix 7.4 Async Poller", "score": 0.94},
                },
            )
            self.assertEqual(doc_res.status_code, 201)

            hits = client.get("/api/collections/news_items/documents?q=zabbix").json()
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["doc"]["title"], "Zabbix 7.4 Async Poller")

    def test_ram_startup_gate_blocks_desktop_above_80_pct(self) -> None:
        with self._make_client(ram_percent=84.0) as client:
            bot_res = client.post(
                "/api/bots",
                json={
                    "name": "Portal Extractor",
                    "role": "Reads partner portal via isolated Selkies container",
                    "runtime": "desktop",
                    "outbound_rbac": "draft",
                },
            )
            self.assertEqual(bot_res.status_code, 201)
            slug = bot_res.json()["slug"]

            toggle_res = client.post(f"/api/desktops/{slug}/toggle")
            self.assertEqual(toggle_res.status_code, 409)
            self.assertIn("80% RAM Startup Gate", toggle_res.json()["detail"])

            alerts = client.get("/api/activity?category=alerts").json()
            self.assertTrue(any(ev["event_type"] == "desktop.gate_blocked" for ev in alerts))

    def test_static_spa_served_from_dist(self) -> None:
        if not (self.dist_dir / "index.html").is_file():
            self.fail("frontend/dist/index.html missing; run npm run build first.")
        with self._make_client(static_dir=str(self.dist_dir)) as client:
            res = client.get("/")
            self.assertEqual(res.status_code, 200)
            self.assertIn("text/html", res.headers["content-type"])
            self.assertIn('<div id="root"></div>', res.text)


if __name__ == "__main__":
    unittest.main()
