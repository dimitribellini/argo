"""Sprint 5 tests: Runtime Bot Builder, Hybrid Pages, Per-Bot Selkies Desktops & CDP MCP Bridge."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.desktop.cdp_bridge import (  # noqa: E402
    CDPPageSnapshot,
    ChromeDevToolsBridge,
    DesktopTakeoverRequiredError,
)
from argo_core.desktop.manager import (  # noqa: E402
    DESKTOP_IMAGE,
    DESKTOP_MEM_LIMIT,
    DESKTOP_NANO_CPUS,
    DESKTOP_NETWORK,
    DESKTOP_SHM_SIZE,
    DesktopConfigError,
    DesktopRuntimeError,
    DockerSdkDriver,
    InMemoryDockerDriver,
    _build_agent_tar_archive,
)
from argo_core.desktop.mcp_bridge import (  # noqa: E402
    DESKTOP_AGENT_VERSION,
    DESKTOP_MCP_PORT,
    DesktopMCPBridge,
    _DESKTOP_AGENT_SCRIPT,
    _DefaultDesktopAgentTransport,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class FakeTelegramTransport:
    """In-memory Telegram Bot API double capturing operator notices and resource alerts."""

    def __init__(self) -> None:
        self.sent_messages: list[dict[str, object]] = []
        self._msg_seq = 900

    async def get_me(self, bot_token: str) -> dict[str, object]:
        del bot_token
        return {"bot_id": 990055, "username": "argo_ops_bot", "first_name": "Argo Ops"}

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
        reply_markup: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del bot_token
        self._msg_seq += 1
        rec = {
            "chat_id": str(chat_id),
            "message_id": self._msg_seq,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.sent_messages.append(rec)
        return {"message_id": self._msg_seq, "chat_id": str(chat_id)}


class TestSprint5BuilderPagesDesktops(unittest.TestCase):
    """Verify Sprint 5 Builder, Dual-Mode Pages, Docker/Selkies Desktops & CDP :9222."""

    @staticmethod
    def _sso_headers() -> dict[str, str]:
        return {
            "X-Auth-Request-Email": "operator@example.com",
            "X-Auth-Request-User": "operator",
        }

    def _build_env(
        self,
        tmp: str,
        *,
        ram_state: dict[str, float] | None = None,
        idle_timeout_seconds: float = 300.0,
        llm_transport=None,
        tg_transport: FakeTelegramTransport | None = None,
        docker_driver=None,
        cdp_transport=None,
        selkies_proxy_transport=None,
        desktop_agent_transport=None,
    ):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")

        metrics_state = ram_state if ram_state is not None else {
            "ram_percent": 42.0,
            "ram_total_gb": 16.0,
            "cpu_percent": 18.0,
            "disk_percent": 31.0,
        }
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": metrics_state.get("ram_percent", 42.0),
                "ram_total_gb": metrics_state.get("ram_total_gb", 16.0),
                "cpu_percent": metrics_state.get("cpu_percent", 18.0),
                "disk_percent": metrics_state.get("disk_percent", 31.0),
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            desktop_idle_timeout_seconds=idle_timeout_seconds,
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_router=None,
            llm_transport=llm_transport,
            telegram_transport=tg_transport,
            docker_driver=docker_driver,
            cdp_transport=cdp_transport,
            selkies_proxy_transport=selkies_proxy_transport,
            desktop_agent_transport=desktop_agent_transport,
        )

    def test_conversational_bot_builder_synthesis_warnings_and_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                # 1. API-First warning when user asks for desktop/browser on Gmail/Telegram/RSS
                api_first = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": (
                            "Create a News Collector bot that opens Chrome desktop browser to "
                            "watch Gmail and RSS feeds into collection news_items"
                        ),
                        "preferred_runtime": "desktop",
                    },
                )
                self.assertEqual(api_first.status_code, 200, api_first.text)
                body = api_first.json()
                self.assertFalse(body["used_llm"])
                self.assertGreaterEqual(len(body["warnings"]), 1)
                self.assertIn("API-First", body["warnings"][0])
                self.assertEqual(body["draft"]["model"], "google:gemini-3.8-flash")
                self.assertIn("news_items", body["draft"]["collections"]["write"])
                tool_names = [t.get("name") for t in body["draft"]["tools"] if isinstance(t, dict)]
                self.assertIn("fetch_rss_feed", tool_names)

                # 2. Reasoning/review keyword selects google:gemini-4-argon
                reviewer = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": (
                            "Create an Editorial Reviewer bot on_event: news.collected "
                            "to audit style_memory and send drafts for approval"
                        ),
                        "preferred_model": "google:gemini-4-argon",
                    },
                )
                self.assertEqual(reviewer.status_code, 200, reviewer.text)
                rev_draft = reviewer.json()["draft"]
                self.assertEqual(rev_draft["model"], "google:gemini-4-argon")
                self.assertEqual(rev_draft["runtime"], "api")
                self.assertEqual(rev_draft["routines"][0]["type"], "on_event")
                self.assertEqual(rev_draft["routines"][0]["event"], "news.collected")

                # 3. Legacy portal without public API selects isolated Selkies desktop
                desktop_draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Read billing status from legacy partner portal without API",
                    },
                )
                self.assertEqual(desktop_draft.status_code, 200, desktop_draft.text)
                self.assertEqual(desktop_draft.json()["draft"]["runtime"], "desktop")

                # 4. Deprecated gemini-2.5-* model rejected cleanly
                deprecated = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Summarize weekly feeds",
                        "preferred_model": "google:gemini-2.5-flash",
                    },
                )
                self.assertIn(deprecated.status_code, (400, 422), deprecated.text)

        # 5. Optional LLM refinement merges refined JSON into draft & registers via POST /api/bots
        async def fake_builder_llm(req: LLMRequest) -> dict[str, object]:
            del req
            return {
                "text": json.dumps(
                    {
                        "name": "Advisory Synthesizer",
                        "role": "Distill RSS security notices into executive-neutral briefs",
                        "role_prompt": "Always cite canonical URLs and keep role-neutral tone.",
                        "model": "google:gemini-4-argon",
                        "outbound_rbac": "draft",
                        "daily_cap": 0,
                        "collections": {"read": ["tech_news"], "write": ["release_briefs"]},
                        "routines": [
                            {
                                "type": "cron",
                                "label": "Hourly Synthesis",
                                "schedule": "Every 1h",
                                "enabled": True,
                            }
                        ],
                    }
                ),
                "input_tokens": 35,
                "output_tokens": 55,
            }

        with tempfile.TemporaryDirectory() as tmp2:
            app2 = self._build_env(tmp2, llm_transport=fake_builder_llm)
            with TestClient(app2) as client2:
                refined = client2.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={"prompt": "Synthesize hourly RSS security notices"},
                )
                self.assertEqual(refined.status_code, 200, refined.text)
                refined_body = refined.json()
                self.assertTrue(refined_body["used_llm"])
                draft = refined_body["draft"]
                self.assertEqual(draft["name"], "Advisory Synthesizer")
                self.assertEqual(draft["slug"], "advisory-synthesizer")
                self.assertEqual(draft["model"], "google:gemini-4-argon")

                created = client2.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": draft["name"],
                        "role": draft["role"],
                        "role_prompt": draft["role_prompt"],
                        "runtime": draft["runtime"],
                        "outbound_rbac": draft["outbound_rbac"],
                        "model": draft["model"],
                        "daily_cap": draft["daily_cap"],
                        "routines": draft["routines"],
                        "tools": draft["tools"],
                        "collections": draft["collections"],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                bot_slug = created.json()["slug"]
                fetched = client2.get(f"/api/bots/{bot_slug}", headers=self._sso_headers())
                self.assertEqual(fetched.status_code, 200)
                self.assertEqual(fetched.json()["name"], "Advisory Synthesizer")

    def test_dual_mode_pages_collections_acl_and_runtime_upsert_page(self) -> None:
        async def fake_runner_llm(req: LLMRequest) -> dict[str, object]:
            if "Bot slug: bad-page-bot" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Attempt unauthorized collection page.",
                            "actions": [
                                {
                                    "type": "upsert_page",
                                    "title": "Blocked Secret View",
                                    "render_mode": "declarative_json",
                                    "allowed_collections": ["private_notes"],
                                }
                            ],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 15,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Published Monthly Operations page from tech_news.",
                        "actions": [
                            {
                                "type": "upsert_page",
                                "title": "Runtime Tech Digest",
                                "render_mode": "declarative_json",
                                "allowed_collections": ["tech_news"],
                                "content_payload": {"blocks": [{"label": "Items", "value": "1"}]},
                            }
                        ],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 20,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_runner_llm)
            with TestClient(app) as client:
                repo = app.state.repo
                repo.upsert_document(
                    collection="tech_news",
                    external_key="adv-1",
                    search_text="Fedora 45 kernel hardening release note Valkey Podman",
                    doc={
                        "title": "Fedora 45 Kernel Hardening",
                        "summary": "New Valkey and Podman runtime defaults.",
                        "source_url": "https://vendor.example.org/f45",
                    },
                )
                repo.upsert_document(
                    collection="private_notes",
                    external_key="priv-1",
                    search_text="Internal unshared secret note",
                    doc={"title": "Private Note"},
                )

                # 1. Create declarative_json page with scoped allowed_collections
                created = client.post(
                    "/api/pages",
                    headers=self._sso_headers(),
                    json={
                        "title": "Monthly Operations",
                        "description": "Operational tech feed dashboard",
                        "render_mode": "declarative_json",
                        "allowed_collections": ["tech_news"],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                page_slug = created.json()["slug"]

                # 2. Live GET /data supports FTS5 q filtering and never leaks private_notes
                data_all = client.get(f"/api/pages/{page_slug}/data", headers=self._sso_headers())
                self.assertEqual(data_all.status_code, 200, data_all.text)
                self.assertEqual(data_all.json()["total_records"], 1)
                self.assertEqual(
                    data_all.json()["records"][0]["doc"]["title"],
                    "Fedora 45 Kernel Hardening",
                )
                self.assertNotIn("private_notes", data_all.json()["collections"])

                data_fts = client.get(
                    f"/api/pages/{page_slug}/data",
                    params={"q": "Valkey"},
                    headers=self._sso_headers(),
                )
                self.assertEqual(data_fts.status_code, 200)
                self.assertEqual(data_fts.json()["total_records"], 1)

                # 3. POST /query enforces allowed_collections ACL (200 vs 403)
                q_ok = client.post(
                    f"/api/pages/{page_slug}/query",
                    headers=self._sso_headers(),
                    json={"collection": "tech_news", "query": "Kernel", "limit": 10},
                )
                self.assertEqual(q_ok.status_code, 200, q_ok.text)
                self.assertEqual(len(q_ok.json()["records"]), 1)

                q_denied = client.post(
                    f"/api/pages/{page_slug}/query",
                    headers=self._sso_headers(),
                    json={"collection": "private_notes"},
                )
                self.assertEqual(q_denied.status_code, 403, q_denied.text)

                # 4. PATCH updates metadata & rejects allow-same-origin injection
                patched = client.patch(
                    f"/api/pages/{page_slug}",
                    headers=self._sso_headers(),
                    json={"title": "Monthly Operations v2"},
                )
                self.assertEqual(patched.status_code, 200, patched.text)
                self.assertEqual(patched.json()["title"], "Monthly Operations v2")

                unsafe_patch = client.patch(
                    f"/api/pages/{page_slug}",
                    headers=self._sso_headers(),
                    json={
                        "render_mode": "sandboxed_html",
                        "content_payload": '<iframe sandbox="allow-scripts allow-same-origin"></iframe>',
                    },
                )
                self.assertEqual(unsafe_patch.status_code, 400, unsafe_patch.text)

                # 5. Sandboxed HTML creation works cleanly and rejects allow-same-origin
                unsafe_create = client.post(
                    "/api/pages",
                    headers=self._sso_headers(),
                    json={
                        "title": "Unsafe Micro App",
                        "render_mode": "sandboxed_html",
                        "content_payload": "<div>allow-same-origin test</div>",
                    },
                )
                self.assertEqual(unsafe_create.status_code, 400, unsafe_create.text)

                safe_html = client.post(
                    "/api/pages",
                    headers=self._sso_headers(),
                    json={
                        "title": "Safe Micro App",
                        "description": "Isolated view",
                        "render_mode": "sandboxed_html",
                        "allowed_collections": ["tech_news"],
                    },
                )
                self.assertEqual(safe_html.status_code, 201, safe_html.text)
                self.assertNotIn("allow-same-origin", safe_html.json()["content_payload"])

                # 6. DELETE removes page cleanly
                deleted = client.delete(
                    f"/api/pages/{safe_html.json()['slug']}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(deleted.status_code, 200)
                missing = client.get(
                    f"/api/pages/{safe_html.json()['slug']}/data",
                    headers=self._sso_headers(),
                )
                self.assertEqual(missing.status_code, 404)

                # 7. Runtime bot upsert_page honors bot collections ACL
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Good Page Bot",
                        "role": "Pin digest page",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-3.8-flash",
                        "collections": {"read": ["tech_news"], "write": ["tech_news"]},
                    },
                )
                good_run = client.post(
                    "/api/bots/good-page-bot/trigger",
                    headers=self._sso_headers(),
                    json={"input_text": "Build digest page", "wait_for_chain": True},
                )
                self.assertEqual(good_run.status_code, 200, good_run.text)
                pages_after = client.get("/api/pages", headers=self._sso_headers()).json()
                self.assertTrue(any(p["slug"] == "runtime-tech-digest" for p in pages_after))

                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Bad Page Bot",
                        "role": "Try unauthorized page",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-3.8-flash",
                        "collections": {"read": ["tech_news"], "write": ["tech_news"]},
                    },
                )
                bad_run = client.post(
                    "/api/bots/bad-page-bot/trigger",
                    headers=self._sso_headers(),
                    json={"input_text": "Try private_notes page", "wait_for_chain": True},
                )
                self.assertEqual(bad_run.status_code, 200, bad_run.text)
                pages_after_bad = client.get("/api/pages", headers=self._sso_headers()).json()
                self.assertFalse(any(p["slug"] == "blocked-secret-view" for p in pages_after_bad))

    def test_docker_sdk_driver_ram_gates_and_idle_hibernation(self) -> None:
        # 1. Stub docker & docker.errors to test DockerSdkDriver container kwargs strictly
        run_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        stop_calls: list[int] = []

        class StubNotFound(Exception):
            pass

        class StubContainer:
            def __init__(self, cid: str) -> None:
                self.id = cid
                self.status = "running"

            def start(self) -> None:
                self.status = "running"

            def reload(self) -> None:
                pass

            def stop(self, *, timeout: int = 10) -> None:
                stop_calls.append(timeout)
                self.status = "exited"

        class StubContainers:
            def __init__(self) -> None:
                self.created: dict[str, StubContainer] = {}

            def get(self, name: str) -> StubContainer:
                if name not in self.created:
                    raise StubNotFound(name)
                return self.created[name]

            def run(self, *args: object, **kwargs: object) -> StubContainer:
                run_calls.append((args, kwargs))
                c = StubContainer(f"cid-{kwargs['name']}")
                self.created[str(kwargs["name"])] = c
                return c

        stub_containers = StubContainers()
        stub_client = types.SimpleNamespace(containers=stub_containers)
        fake_docker = types.ModuleType("docker")
        fake_docker.DockerClient = lambda base_url="": stub_client  # type: ignore[attr-defined]
        fake_docker_errors = types.ModuleType("docker.errors")
        fake_docker_errors.NotFound = StubNotFound  # type: ignore[attr-defined]
        fake_docker.errors = fake_docker_errors  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"docker": fake_docker, "docker.errors": fake_docker_errors}):
            sdk_driver = DockerSdkDriver(base_url="unix:///var/run/docker.sock")
            ram_state = {
                "ram_percent": 83.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 20.0,
                "disk_percent": 30.0,
            }
            tg_transport = FakeTelegramTransport()

            with tempfile.TemporaryDirectory() as tmp:
                app = self._build_env(
                    tmp,
                    ram_state=ram_state,
                    idle_timeout_seconds=10.0,
                    tg_transport=tg_transport,
                    docker_driver=sdk_driver,
                )
                with TestClient(app) as client:
                    # Seed Telegram admin/operator integration for resource alert verification
                    repo = app.state.repo
                    repo.upsert_integration(
                        slug="ops-telegram",
                        provider="telegram",
                        display_name="Ops Bot",
                        account_identifier="argo_ops_bot",
                        scopes=["bot_api"],
                        secrets={"bot_token": "99999:token", "operator_chat_id": "1001"},
                        status="ok",
                    )

                    created = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={
                            "name": "Vendor Portal Bot",
                            "role": "Handle legacy vendor portal",
                            "runtime": "desktop",
                            "outbound_rbac": "draft",
                            "model": "google:gemini-3.8-flash",
                        },
                    )
                    self.assertEqual(created.status_code, 201, created.text)
                    slug = created.json()["slug"]

                    # 2. >=80% RAM blocks launch with 409, enqueues launch, emits Activity event
                    blocked = client.post(
                        f"/api/desktops/{slug}/toggle",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(blocked.status_code, 409, blocked.text)
                    self.assertIn("80% RAM Startup Gate", blocked.json()["detail"])

                    desk_status = client.get("/api/desktops", headers=self._sso_headers()).json()
                    self.assertTrue(desk_status["host"]["ram_startup_gate_blocked"])
                    self.assertEqual(len(desk_status["queued_launches"]), 1)
                    self.assertEqual(desk_status["queued_launches"][0]["bot_slug"], slug)

                    events = client.get("/api/activity", headers=self._sso_headers()).json()
                    self.assertTrue(any(e["event_type"] == "desktop.gate_blocked" for e in events))

                    # 3. Drop RAM below 80% -> wakes desktop & inspects exact DockerSdkDriver flags
                    ram_state["ram_percent"] = 45.0
                    started = client.post(
                        f"/api/desktops/{slug}/toggle",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(started.status_code, 200, started.text)
                    self.assertEqual(started.json()["desktop_state"], "running")

                    self.assertEqual(len(run_calls), 1)
                    run_args, run_kwargs = run_calls[0]
                    self.assertEqual(run_args[0], DESKTOP_IMAGE)
                    self.assertEqual(run_kwargs["mem_limit"], DESKTOP_MEM_LIMIT)
                    self.assertEqual(run_kwargs["nano_cpus"], DESKTOP_NANO_CPUS)
                    self.assertEqual(run_kwargs["shm_size"], DESKTOP_SHM_SIZE)
                    self.assertEqual(run_kwargs["network"], DESKTOP_NETWORK)
                    self.assertNotIn("ports", run_kwargs)
                    expected_vol = str(Path(tmp) / "desktops" / slug)
                    self.assertEqual(
                        run_kwargs["volumes"],
                        {expected_vol: {"bind": "/config", "mode": "rw"}},
                    )

                    # Verify queued_launches cleared after successful launch
                    after_start = client.get("/api/desktops", headers=self._sso_headers()).json()
                    self.assertEqual(after_start["queued_launches"], [])

                    # 4. Forbidden non-Fedora image check on DockerSdkDriver
                    bad_spec = types.SimpleNamespace(
                        image="ubuntu:24.04",
                        bot_slug=slug,
                        container_name="argo-desktop-bad",
                        network="argo-net",
                        host_volume_path=expected_vol,
                        mem_limit="2g",
                        nano_cpus=1_500_000_000,
                        shm_size="1g",
                        environment={},
                    )
                    with self.assertRaises(DesktopConfigError):
                        asyncio.run(sdk_driver.ensure_started(bad_spec))  # type: ignore[arg-type]

                    # 5. Active takeover blocks idle auto-hibernation; release re-enables sweep
                    now_holder = [1000.0]
                    dm = app.state.desktop_manager
                    dm._clock = lambda: now_holder[0]
                    dm.touch_activity(slug)

                    tk_start = client.post(
                        f"/api/desktops/{slug}/takeover/start",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(tk_start.status_code, 200, tk_start.text)
                    self.assertTrue(tk_start.json()["desktop"]["takeover_active"])

                    now_holder[0] = 1020.0
                    sweep_during_takeover = client.post(
                        "/api/desktops/sweep-idle",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(sweep_during_takeover.status_code, 200)
                    self.assertEqual(sweep_during_takeover.json()["hibernated_desktops"], [])

                    tk_rel = client.post(
                        f"/api/desktops/{slug}/takeover/release",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(tk_rel.status_code, 200, tk_rel.text)
                    self.assertFalse(tk_rel.json()["desktop"]["takeover_active"])

                    now_holder[0] = 1040.0
                    sweep_after_release = client.post(
                        "/api/desktops/sweep-idle",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(sweep_after_release.status_code, 200)
                    self.assertEqual(sweep_after_release.json()["hibernated_desktops"], [slug])
                    self.assertGreaterEqual(len(stop_calls), 1)

                    # 6. >=90% Critical RAM triggers HostResourceGuard -> stop_all_desktops
                    woken = client.post(
                        f"/api/desktops/{slug}/toggle",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(woken.status_code, 200)
                    self.assertEqual(woken.json()["desktop_state"], "running")

                    ram_state["ram_percent"] = 93.0
                    asyncio.run(
                        app.state.guard.evaluate_and_enforce(
                            repo=app.state.repo,
                            bus=app.state.bus,
                            telegram=app.state.telegram_service,
                            desktop_manager=app.state.desktop_manager,
                        )
                    )
                    bot_after_crit = client.get(f"/api/bots/{slug}", headers=self._sso_headers()).json()
                    self.assertEqual(bot_after_crit["desktop_state"], "hibernated")
                    self.assertTrue(any("CRITICAL" in str(m["text"]) for m in tg_transport.sent_messages))

    def test_chrome_devtools_mcp_cdp_bridge_ssrf_takeover_and_selkies_proxy(self) -> None:
        # 1. Verify chrome-devtools-mcp config & pydantic_ai.mcp.MCPToolset + StdioTransport wiring
        cfg = ChromeDevToolsBridge.build_mcp_server_config("portal-bot")
        self.assertEqual(cfg["cdp_endpoint"], "http://argo-desktop-portal-bot:9222")
        self.assertEqual(cfg["command"], "npx")
        self.assertIn("--browserUrl=http://argo-desktop-portal-bot:9222", cfg["args"])

        fake_transports_mod = types.ModuleType("fastmcp.client.transports")

        class FakeStdioTransport:
            def __init__(self, command: str, args: list[str]) -> None:
                self.command = command
                self.args = list(args)

        fake_transports_mod.StdioTransport = FakeStdioTransport  # type: ignore[attr-defined]
        fake_client_mod = types.ModuleType("fastmcp.client")
        fake_client_mod.transports = fake_transports_mod  # type: ignore[attr-defined]
        fake_fastmcp_mod = types.ModuleType("fastmcp")
        fake_fastmcp_mod.client = fake_client_mod  # type: ignore[attr-defined]

        fake_mcp_mod = types.ModuleType("pydantic_ai.mcp")

        class FakeMCPToolset:
            def __init__(self, client: FakeStdioTransport, *, id: str | None = None) -> None:
                self.client = client
                self.id = id

        fake_mcp_mod.MCPToolset = FakeMCPToolset  # type: ignore[attr-defined]
        fake_pydantic_ai = types.ModuleType("pydantic_ai")
        fake_pydantic_ai.mcp = fake_mcp_mod  # type: ignore[attr-defined]
        with patch.dict(
            sys.modules,
            {
                "fastmcp": fake_fastmcp_mod,
                "fastmcp.client": fake_client_mod,
                "fastmcp.client.transports": fake_transports_mod,
                "pydantic_ai": fake_pydantic_ai,
                "pydantic_ai.mcp": fake_mcp_mod,
            },
        ):
            toolset = ChromeDevToolsBridge.create_pydantic_ai_mcp_toolset("portal-bot")
            self.assertEqual(toolset.id, "chrome_devtools_portal-bot")
            self.assertEqual(toolset.client.command, "npx")
            self.assertIn("--browserUrl=http://argo-desktop-portal-bot:9222", toolset.client.args)

            compat_toolset = ChromeDevToolsBridge.create_pydantic_ai_mcp_server("portal-bot")
            self.assertEqual(compat_toolset.id, "chrome_devtools_portal-bot")
            self.assertEqual(compat_toolset.client.command, "npx")
            self.assertIn(
                "--browserUrl=http://argo-desktop-portal-bot:9222",
                compat_toolset.client.args,
            )

        # 2. Prepare CDP snapshots (normal DOM vs 403 WAF & Turnstile CAPTCHA)
        snapshot_mode = {"kind": "clean"}

        async def fake_cdp_transport(
            bot_slug: str,
            cdp_endpoint: str,
            url: str,
            selector: str | None,
        ) -> CDPPageSnapshot:
            del bot_slug, cdp_endpoint, selector
            if snapshot_mode["kind"] == "http_403":
                return CDPPageSnapshot(
                    url=url,
                    status_code=403,
                    title="Access Denied",
                    text="HTTP 403 Forbidden",
                    html="<h1>403 Forbidden</h1>",
                )
            if snapshot_mode["kind"] == "captcha":
                return CDPPageSnapshot(
                    url=url,
                    status_code=200,
                    title="Attention Required! | Cloudflare",
                    text="Verify you are human",
                    html='<div class="cf-turnstile"></div>',
                )
            return CDPPageSnapshot(
                url=url,
                status_code=200,
                title="Partner Billing Portal",
                text="Invoice #INV-2026-11 Status: Paid",
                html="<main><p>Invoice #INV-2026-11 Status: Paid</p></main>",
            )

        async def fake_selkies_proxy(
            slug: str,
            subpath: str,
            query_string: str,
        ) -> tuple[int, str, bytes]:
            del query_string
            return 200, "text/html; charset=utf-8", f"<html>Selkies Stream {slug} /{subpath}</html>".encode("utf-8")

        async def fake_desktop_bot_llm(req: LLMRequest) -> dict[str, object]:
            del req
            return {
                "text": json.dumps(
                    {
                        "summary": "Navigate partner portal via CDP :9222 and save invoice.",
                        "actions": [
                            {
                                "type": "desktop_browse",
                                "url": "https://portal.example.org/invoices",
                                "selector": "main",
                                "save_to_collection": "portal_invoices",
                            }
                        ],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 20,
            }

        tg_transport = FakeTelegramTransport()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_desktop_bot_llm,
                tg_transport=tg_transport,
                docker_driver=InMemoryDockerDriver(),
                cdp_transport=fake_cdp_transport,
                selkies_proxy_transport=fake_selkies_proxy,
            )
            with TestClient(app) as client:
                repo = app.state.repo
                repo.upsert_integration(
                    slug="ops-telegram",
                    provider="telegram",
                    display_name="Ops Bot",
                    account_identifier="argo_ops_bot",
                    scopes=["bot_api"],
                    secrets={"bot_token": "88888:token", "operator_chat_id": "2002"},
                    status="ok",
                )

                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Portal Bot",
                        "role": "Read legacy vendor portal via CDP :9222",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-3.8-flash",
                        "collections": {
                            "read": ["portal_invoices"],
                            "write": ["portal_invoices"],
                        },
                    },
                )

                # 3. SSRF protection blocks internal cloud metadata URL before touching CDP
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["169.254.169.254"]):
                    ssrf_resp = client.post(
                        "/api/desktops/portal-bot/browse",
                        headers=self._sso_headers(),
                        json={"url": "http://169.254.169.254/latest/meta-data/"},
                    )
                self.assertEqual(ssrf_resp.status_code, 403, ssrf_resp.text)

                # 4. Clean CDP extraction wakes desktop & reads DOM via :9222
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    ok_resp = client.post(
                        "/api/desktops/portal-bot/browse",
                        headers=self._sso_headers(),
                        json={"url": "https://portal.example.org/invoices"},
                    )
                self.assertEqual(ok_resp.status_code, 200, ok_resp.text)
                self.assertIn("INV-2026-11", ok_resp.json()["content"])
                self.assertEqual(ok_resp.json()["cdp_endpoint"], "http://argo-desktop-portal-bot:9222")

                # 5. Runtime bot "desktop_browse" action executes cleanly via UniversalBotRunner & saves to collection
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    bot_run = client.post(
                        "/api/bots/portal-bot/trigger",
                        headers=self._sso_headers(),
                        json={"input_text": "Fetch invoice", "wait_for_chain": True},
                    )
                self.assertEqual(bot_run.status_code, 200, bot_run.text)
                docs = client.get(
                    "/api/collections/portal_invoices/documents",
                    headers=self._sso_headers(),
                )
                self.assertEqual(docs.status_code, 200, docs.text)
                self.assertGreaterEqual(len(docs.json()), 1)
                self.assertIn("INV-2026-11", docs.json()[0]["doc"]["content"])

                # 6. Selkies proxy serves :3000 HTML/WebSocket stream and rejects legacy VNC/noVNC paths
                selkies_ok = client.get(
                    "/api/desktops/portal-bot/selkies/",
                    headers=self._sso_headers(),
                )
                self.assertEqual(selkies_ok.status_code, 200, selkies_ok.text)
                self.assertIn("Selkies Stream portal-bot", selkies_ok.text)

                with client.websocket_connect("/api/desktops/portal-bot/selkies/ws") as ws:
                    ws_msg = json.loads(ws.receive_text())
                    self.assertEqual(ws_msg["type"], "selkies_fallback")

                vnc_rejected = client.get(
                    "/api/desktops/portal-bot/selkies/novnc/vnc.html",
                    headers=self._sso_headers(),
                )
                self.assertEqual(vnc_rejected.status_code, 400, vnc_rejected.text)

                # 7. Zero-bypass halt on HTTP 403 -> awaiting_takeover + Activity + Telegram notice
                snapshot_mode["kind"] = "http_403"
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    halted_403 = client.post(
                        "/api/desktops/portal-bot/browse",
                        headers=self._sso_headers(),
                        json={"url": "https://portal.example.org/waf"},
                    )
                self.assertEqual(halted_403.status_code, 409, halted_403.text)

                # 8. Zero-bypass halt on CAPTCHA Turnstile -> raises DesktopTakeoverRequiredError cleanly
                snapshot_mode["kind"] = "captcha"
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    with self.assertRaises(DesktopTakeoverRequiredError):
                        asyncio.run(
                            app.state.cdp_bridge.navigate_and_extract(
                                "portal-bot",
                                "https://portal.example.org/captcha",
                            )
                        )

                desk_info = client.get("/api/desktops", headers=self._sso_headers()).json()["desktops"][0]
                self.assertTrue(desk_info["awaiting_takeover"])
                self.assertIn("CAPTCHA", desk_info["takeover_reason"])

                events = client.get("/api/activity", headers=self._sso_headers()).json()
                self.assertTrue(any(e["event_type"] == "desktop.takeover_required" for e in events))
                self.assertTrue(
                    any("Manual Selkies Takeover Required" in str(m["text"]) for m in tg_transport.sent_messages)
                )

                # 9. Releasing takeover clears awaiting_takeover & stop-all hibernates active desktop
                released = client.post(
                    "/api/desktops/portal-bot/takeover/release",
                    headers=self._sso_headers(),
                )
                self.assertEqual(released.status_code, 200)
                self.assertFalse(released.json()["desktop"]["awaiting_takeover"])

                stopped_all = client.post("/api/desktops/stop-all", headers=self._sso_headers())
                self.assertEqual(stopped_all.status_code, 200, stopped_all.text)
                self.assertEqual(stopped_all.json()["stopped_desktops"], ["portal-bot"])

    def test_virtual_browser_compose_network_cdp_seeding_selkies_proxy_and_multiturn_runner(self) -> None:
        # 1. Verify DockerSdkDriver resolves Compose-prefixed argo_argo-net, passes seccomp=unconfined & SUBFOLDER,
        #    seeds .argo-cdp-proxy.py + .argo-launch-browser.sh + autostart, and maps Docker errors to HTTP 502.
        class StubNotFound(Exception):
            pass

        run_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        fail_state = {"fail_run": False}

        class StubContainer:
            def __init__(self, cid: str, *, networks: dict[str, object] | None = None, env: list[str] | None = None, sec: list[str] | None = None) -> None:
                self.id = cid
                self.status = "running"
                self.attrs = {
                    "Config": {"Env": env or []},
                    "HostConfig": {"SecurityOpt": sec or ["seccomp=unconfined"]},
                    "NetworkSettings": {"Networks": networks or {}},
                }

            def reload(self) -> None:
                pass

            def stop(self, *, timeout: int = 10) -> None:
                del timeout
                self.status = "exited"

            def remove(self, *, force: bool = False) -> None:
                del force

            def exec_run(self, *args: object, **kwargs: object) -> tuple[int, bytes]:
                del args, kwargs
                return 0, b""

        class StubContainers:
            def __init__(self) -> None:
                self.created: dict[str, StubContainer] = {
                    "argo-core-host": StubContainer("argo-core-host", networks={"argo_argo-net": {}})
                }

            def get(self, name: str) -> StubContainer:
                if name not in self.created:
                    raise StubNotFound(name)
                return self.created[name]

            def run(self, *args: object, **kwargs: object) -> StubContainer:
                if fail_state["fail_run"]:
                    raise RuntimeError("mock docker daemon failure")
                run_calls.append((args, kwargs))
                c = StubContainer(
                    f"cid-{kwargs['name']}",
                    networks={str(kwargs["network"]): {}},
                    env=[f"{k}={v}" for k, v in dict(kwargs.get("environment") or {}).items()],  # type: ignore[arg-type]
                    sec=list(kwargs.get("security_opt") or []),  # type: ignore[arg-type]
                )
                self.created[str(kwargs["name"])] = c
                return c

        class StubImages:
            def get(self, name: str) -> object:
                del name
                return object()

            def pull(self, name: str) -> object:
                del name
                return object()

        class StubNetworkObj:
            def connect(self, container: object) -> None:
                del container

        class StubNetworks:
            def list(self) -> list[object]:
                return [types.SimpleNamespace(name="argo_argo-net")]

            def get(self, name: str) -> StubNetworkObj:
                del name
                return StubNetworkObj()

        stub_client = types.SimpleNamespace(
            containers=StubContainers(),
            images=StubImages(),
            networks=StubNetworks(),
        )
        fake_docker = types.ModuleType("docker")
        fake_docker.DockerClient = lambda base_url="": stub_client  # type: ignore[attr-defined]
        fake_docker_errors = types.ModuleType("docker.errors")
        fake_docker_errors.NotFound = StubNotFound  # type: ignore[attr-defined]
        fake_docker.errors = fake_docker_errors  # type: ignore[attr-defined]

        # 2. Multi-turn desktop_browse (without save_to_collection) feeds extracted page content into Turn 2
        turn_prompts: list[str] = []

        async def fake_multiturn_llm(req: LLMRequest) -> dict[str, object]:
            turn_prompts.append(req.user_prompt)
            if "tool_observations" not in req.user_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Opening webpage in Virtual Browser...",
                            "actions": [
                                {"type": "desktop_browse", "url": "https://example.org/status"}
                            ],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 15,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Virtual Browser read page: All systems nominal on example.org.",
                        "actions": [],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 15,
            }

        async def fake_cdp_transport(
            bot_slug: str,
            cdp_endpoint: str,
            url: str,
            selector: str | None,
        ) -> CDPPageSnapshot:
            del bot_slug, cdp_endpoint, selector
            return CDPPageSnapshot(
                url=url,
                status_code=200,
                title="Status Page",
                text="All systems nominal on example.org",
                html="<html><body>All systems nominal on example.org</body></html>",
            )

        async def fake_selkies_proxy(
            slug: str,
            subpath: str,
            query_string: str,
        ) -> tuple[int, str, bytes]:
            del query_string
            return 200, "text/plain; charset=utf-8", f"ok:{slug}:{subpath}".encode("utf-8")

        with patch.dict(sys.modules, {"docker": fake_docker, "docker.errors": fake_docker_errors}):
            with patch.dict("os.environ", {"HOSTNAME": "argo-core-host"}):
                sdk_driver = DockerSdkDriver(base_url="unix:///var/run/docker.sock")
                with tempfile.TemporaryDirectory() as tmp:
                    app = self._build_env(
                        tmp,
                        llm_transport=fake_multiturn_llm,
                        docker_driver=sdk_driver,
                        cdp_transport=fake_cdp_transport,
                        selkies_proxy_transport=fake_selkies_proxy,
                    )
                    with TestClient(app) as client:
                        # Create as API bot first, then switch runtime -> desktop via PATCH /api/bots/{slug}
                        created = client.post(
                            "/api/bots",
                            headers=self._sso_headers(),
                            json={
                                "name": "Runtime Switch Bot",
                                "role": "Test switching runtime and virtual browser",
                                "runtime": "api",
                                "outbound_rbac": "internal",
                                "model": "google:gemini-3.8-flash",
                            },
                        )
                        self.assertEqual(created.status_code, 201, created.text)
                        slug = created.json()["slug"]
                        self.assertEqual(created.json()["runtime"], "api")

                        switched = client.patch(
                            f"/api/bots/{slug}",
                            headers=self._sso_headers(),
                            json={"runtime": "desktop"},
                        )
                        self.assertEqual(switched.status_code, 200, switched.text)
                        self.assertEqual(switched.json()["runtime"], "desktop")
                        self.assertEqual(switched.json()["desktop_state"], "hibernated")
                        tool_names = [t.get("name") for t in switched.json()["tools"] if isinstance(t, dict)]
                        self.assertIn("desktop_browse", tool_names)

                        # Verify DockerRuntimeError surfaces cleanly as HTTP 502 instead of 500
                        fail_state["fail_run"] = True
                        failed_start = client.post(
                            f"/api/desktops/{slug}/toggle",
                            headers=self._sso_headers(),
                        )
                        self.assertEqual(failed_start.status_code, 502, failed_start.text)
                        self.assertIn("mock docker daemon failure", failed_start.json()["detail"])
                        fail_state["fail_run"] = False

                        # Start desktop cleanly -> resolves argo_argo-net, passes SUBFOLDER + seccomp=unconfined, seeds files
                        started = client.post(
                            f"/api/desktops/{slug}/toggle",
                            headers=self._sso_headers(),
                        )
                        self.assertEqual(started.status_code, 200, started.text)
                        self.assertEqual(started.json()["desktop_state"], "running")

                        self.assertEqual(len(run_calls), 1)
                        _, run_kwargs = run_calls[0]
                        self.assertEqual(run_kwargs["network"], "argo_argo-net")
                        self.assertEqual(run_kwargs["security_opt"], ["seccomp=unconfined"])
                        self.assertEqual(
                            run_kwargs["environment"]["SUBFOLDER"],  # type: ignore[index]
                            f"/api/desktops/{slug}/selkies/",
                        )

                        vol_dir = Path(tmp) / "desktops" / slug
                        proxy_path = vol_dir / ".argo-cdp-proxy.py"
                        launch_path = vol_dir / ".argo-launch-browser.sh"
                        autostart_path = vol_dir / ".config" / "autostart" / "argo-chromium.desktop"
                        self.assertTrue(proxy_path.is_file())
                        self.assertTrue(launch_path.is_file())
                        self.assertTrue(autostart_path.is_file())
                        compile(proxy_path.read_text(encoding="utf-8"), str(proxy_path), "exec")

                        # Verify trailing-slash redirect on /selkies and POST method forwarding
                        no_slash = client.get(
                            f"/api/desktops/{slug}/selkies",
                            headers=self._sso_headers(),
                            follow_redirects=False,
                        )
                        self.assertEqual(no_slash.status_code, 307)
                        self.assertEqual(no_slash.headers["location"], f"/api/desktops/{slug}/selkies/")

                        post_proxy = client.post(
                            f"/api/desktops/{slug}/selkies/api/clipboard",
                            headers=self._sso_headers(),
                        )
                        self.assertEqual(post_proxy.status_code, 200)
                        self.assertEqual(post_proxy.text, f"ok:{slug}:api/clipboard")

                        # Verify multi-turn desktop_browse passes extracted page content into Turn 2 tool_observations
                        with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                            msg_res = client.post(
                                f"/api/bots/{slug}/messages",
                                headers=self._sso_headers(),
                                json={"text": "Open https://example.org/status and read it"},
                            )
                        self.assertEqual(msg_res.status_code, 200, msg_res.text)
                        self.assertEqual(len(turn_prompts), 2)
                        self.assertIn("All systems nominal on example.org", turn_prompts[1])
                        self.assertIn("All systems nominal on example.org", msg_res.json()["result"]["summary"])

    def test_embedded_desktop_mcp_agent_http_and_png_encoding(self) -> None:
        ns: dict[str, object] = {}
        exec(compile(_DESKTOP_AGENT_SCRIPT, "<desktop-agent>", "exec"), ns)

        encode_png = ns["_encode_png_rgb"]
        png_bytes = encode_png(4, 3, bytes([12, 34, 56] * 12))
        self.assertTrue(png_bytes.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", png_bytes)
        self.assertIn(b"IEND", png_bytes)

        server_cls = ns["_Server"]
        handler_cls = ns["_Handler"]
        server = server_cls(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            transport = _DefaultDesktopAgentTransport()
            endpoint = f"http://127.0.0.1:{port}"

            async def _exercise() -> None:
                health = await transport.health("test-bot", endpoint)
                self.assertEqual(health["status"], "ok")
                self.assertEqual(health["agent_version"], DESKTOP_AGENT_VERSION)

                inspected = await transport.inspect("test-bot", endpoint)
                self.assertEqual(inspected["mcp_port"], DESKTOP_MCP_PORT)
                self.assertIn("tools", inspected)

                init_resp = await transport.call_mcp("test-bot", endpoint, "initialize")
                self.assertEqual(
                    init_resp["result"]["serverInfo"]["name"],
                    "argo-desktop-mcp",
                )

                list_resp = await transport.call_mcp("test-bot", endpoint, "tools/list")
                tool_names = [t["name"] for t in list_resp["result"]["tools"]]
                for required_tool in (
                    "desktop_inspect",
                    "desktop_screenshot",
                    "desktop_check_app",
                    "desktop_launch",
                    "desktop_click",
                ):
                    self.assertIn(required_tool, tool_names)

                call_resp = await transport.call_mcp(
                    "test-bot",
                    endpoint,
                    "tools/call",
                    {"name": "desktop_check_app", "arguments": {"app": "python3"}},
                )
                parsed = json.loads(call_resp["result"]["content"][0]["text"])
                self.assertEqual(parsed["status"], "ok")
                self.assertTrue(parsed["installed"])

            asyncio.run(_exercise())
        finally:
            server.shutdown()
            server.server_close()

        # Verify PydanticAI V2 MCPToolset compatibility when removed V1 names raise ImportError
        class _FakeStreamableTransport:
            def __init__(self, url: str) -> None:
                self.url = url

        class _FakeMCPToolset:
            def __init__(self, transport: object, *, id: str) -> None:
                self.transport = transport
                self.id = id

        fake_fm = types.ModuleType("fastmcp")
        fake_fm_client = types.ModuleType("fastmcp.client")
        fake_fm_transports = types.ModuleType("fastmcp.client.transports")
        fake_fm_transports.StreamableHttpTransport = _FakeStreamableTransport  # type: ignore[attr-defined]
        fake_pai = types.ModuleType("pydantic_ai")
        fake_pai_mcp = types.ModuleType("pydantic_ai.mcp")
        fake_pai_mcp.MCPToolset = _FakeMCPToolset  # type: ignore[attr-defined]

        def _v2_removed_getattr(name: str):
            if name in {"MCPServerStreamableHTTP", "MCPServerHTTP", "MCPServerStdio"}:
                raise ImportError(f"`pydantic_ai.mcp.{name}` was removed in Pydantic AI V2")
            raise AttributeError(name)

        fake_pai_mcp.__getattr__ = _v2_removed_getattr  # type: ignore[method-assign]

        with patch.dict(
            sys.modules,
            {
                "fastmcp": fake_fm,
                "fastmcp.client": fake_fm_client,
                "fastmcp.client.transports": fake_fm_transports,
                "pydantic_ai": fake_pai,
                "pydantic_ai.mcp": fake_pai_mcp,
            },
        ):
            toolset = DesktopMCPBridge.create_pydantic_ai_mcp_toolset("smoke-test")
            self.assertEqual(toolset.id, "desktop_mcp_smoke-test")
            self.assertEqual(toolset.transport.url, f"http://argo-desktop-smoke-test:{DESKTOP_MCP_PORT}/mcp")

    def test_docker_sdk_driver_put_archive_injects_mcp_agent_even_when_running(self) -> None:
        tar_bytes = _build_agent_tar_archive()
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tf:
            names = {m.name: m for m in tf.getmembers()}
        for expected in (
            ".argo-desktop-agent.py",
            ".argo-cdp-proxy.py",
            ".argo-launch-browser.sh",
            ".argo-agent-version",
            ".config/autostart/argo-chromium.desktop",
        ):
            self.assertIn(expected, names)
            self.assertEqual(names[expected].uid, 1000)
            self.assertEqual(names[expected].gid, 1000)

        class StubNotFound(Exception):
            pass

        put_calls: list[tuple[str, bytes]] = []
        exec_calls: list[tuple[object, dict[str, object]]] = []

        class StubContainer:
            def __init__(self, cid: str, *, networks: dict[str, object] | None = None, env: list[str] | None = None) -> None:
                self.id = cid
                self.status = "running"
                self.attrs = {
                    "Config": {"Env": env or []},
                    "HostConfig": {"SecurityOpt": ["seccomp=unconfined"]},
                    "NetworkSettings": {"Networks": networks or {}},
                }

            def reload(self) -> None:
                pass

            def put_archive(self, path: str, data: bytes) -> bool:
                put_calls.append((path, data))
                return True

            def exec_run(self, cmd: object, **kwargs: object) -> tuple[int, bytes]:
                exec_calls.append((cmd, kwargs))
                return 0, b""

        class StubContainers:
            def __init__(self) -> None:
                self.created: dict[str, StubContainer] = {
                    "argo-core-host": StubContainer("argo-core-host", networks={"argo_argo-net": {}})
                }

            def get(self, name: str) -> StubContainer:
                if name not in self.created:
                    raise StubNotFound(name)
                return self.created[name]

            def run(self, *args: object, **kwargs: object) -> StubContainer:
                del args
                c = StubContainer(
                    f"cid-{kwargs['name']}",
                    networks={str(kwargs["network"]): {}},
                    env=[f"{k}={v}" for k, v in dict(kwargs.get("environment") or {}).items()],  # type: ignore[arg-type]
                )
                self.created[str(kwargs["name"])] = c
                return c

        stub_client = types.SimpleNamespace(
            containers=StubContainers(),
            images=types.SimpleNamespace(get=lambda n: object(), pull=lambda n: object()),
            networks=types.SimpleNamespace(
                list=lambda: [types.SimpleNamespace(name="argo_argo-net")],
                get=lambda n: types.SimpleNamespace(connect=lambda c: None),
            ),
        )
        fake_docker = types.ModuleType("docker")
        fake_docker.DockerClient = lambda base_url="": stub_client  # type: ignore[attr-defined]
        fake_docker_errors = types.ModuleType("docker.errors")
        fake_docker_errors.NotFound = StubNotFound  # type: ignore[attr-defined]
        fake_docker.errors = fake_docker_errors  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"docker": fake_docker, "docker.errors": fake_docker_errors}):
            with patch.dict("os.environ", {"HOSTNAME": "argo-core-host"}):
                sdk_driver = DockerSdkDriver(base_url="unix:///var/run/docker.sock")
                with tempfile.TemporaryDirectory() as tmp:
                    app = self._build_env(tmp, docker_driver=sdk_driver)
                    with TestClient(app) as client:
                        created = client.post(
                            "/api/bots",
                            headers=self._sso_headers(),
                            json={
                                "name": "Inject Bot",
                                "role": "Verify archive injection",
                                "runtime": "desktop",
                                "outbound_rbac": "internal",
                                "model": "google:gemini-3.8-flash",
                            },
                        )
                        self.assertEqual(created.status_code, 201, created.text)
                        slug = created.json()["slug"]

                        start1 = client.post(f"/api/desktops/{slug}/toggle", headers=self._sso_headers())
                        self.assertEqual(start1.status_code, 200, start1.text)
                        self.assertEqual(len(put_calls), 1)
                        self.assertEqual(put_calls[0][0], "/config")
                        self.assertEqual(len(exec_calls), 1)
                        self.assertEqual(exec_calls[0][1]["user"], "1000:1000")
                        self.assertTrue(exec_calls[0][1]["detach"])

                        # Calling start_desktop when already running must still inject v2 agent archive
                        asyncio.run(app.state.desktop_manager.start_desktop(slug))
                        self.assertEqual(len(put_calls), 2)
                        self.assertEqual(len(exec_calls), 2)

    def test_desktop_screenshot_inspect_action_endpoints_and_ssrf_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, docker_driver=InMemoryDockerDriver())
            with TestClient(app) as client:
                created = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Desktop Ops Bot",
                        "role": "Inspect desktop apps and capture frames",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-3.8-flash",
                        "tools": [],
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                bot_data = created.json()
                slug = bot_data["slug"]
                tool_names = [t.get("name") for t in bot_data["tools"] if isinstance(t, dict)]
                self.assertIn("desktop_browse", tool_names)
                self.assertIn("desktop_mcp", tool_names)

                # While sleeping and uncached, GET screenshot returns 404 without waking desktop
                no_cache = client.get(f"/api/desktops/{slug}/screenshot", headers=self._sso_headers())
                self.assertEqual(no_cache.status_code, 404)
                self.assertEqual(client.get(f"/api/bots/{slug}", headers=self._sso_headers()).json()["desktop_state"], "hibernated")

                # refresh=true captures live PNG & caches it
                shot = client.get(
                    f"/api/desktops/{slug}/screenshot?refresh=true&download=true",
                    headers=self._sso_headers(),
                )
                self.assertEqual(shot.status_code, 200, shot.text)
                self.assertEqual(shot.headers["content-type"], "image/png")
                self.assertIn("attachment; filename=", shot.headers.get("content-disposition", ""))
                self.assertTrue(shot.content.startswith(b"\x89PNG\r\n\x1a\n"))

                # Subsequent unforced GET hits cache cleanly
                cached_shot = client.get(f"/api/desktops/{slug}/screenshot", headers=self._sso_headers())
                self.assertEqual(cached_shot.status_code, 200)
                self.assertTrue(cached_shot.content.startswith(b"\x89PNG\r\n\x1a\n"))

                # Inspect endpoint exposes MCP port + running tools
                insp = client.get(f"/api/desktops/{slug}/inspect", headers=self._sso_headers())
                self.assertEqual(insp.status_code, 200, insp.text)
                insp_json = insp.json()
                self.assertEqual(insp_json["status"], "ok")
                self.assertEqual(insp_json["mcp_port"], DESKTOP_MCP_PORT)
                self.assertIn("tools", insp_json)

                # SSRF guard blocks localhost URL launches via /action
                blocked = client.post(
                    f"/api/desktops/{slug}/action",
                    headers=self._sso_headers(),
                    json={"action": "launch", "url": "http://127.0.0.1:8000/admin"},
                )
                self.assertEqual(blocked.status_code, 403)

                # Launching desktop app updates simulated windows
                launched = client.post(
                    f"/api/desktops/{slug}/action",
                    headers=self._sso_headers(),
                    json={"action": "launch", "app": "thunar"},
                )
                self.assertEqual(launched.status_code, 200, launched.text)
                self.assertEqual(launched.json()["status"], "ok")
                titles = [w.get("title", "") for w in launched.json()["windows"]]
                self.assertIn("thunar", titles)

    def test_bot_runner_turn2_error_recovery_and_multimodal_screenshot_vision(self) -> None:
        observed_requests: list[LLMRequest] = []
        turn_counter = {"n": 0}

        async def fake_recovery_llm(req: LLMRequest) -> dict[str, object]:
            observed_requests.append(req)
            turn_counter["n"] += 1
            if "tool_observations" not in req.user_prompt:
                if "screenshot" in req.user_prompt.lower():
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Capturing desktop screenshot...",
                                "actions": [{"type": "desktop_screenshot"}],
                            }
                        ),
                        "input_tokens": 10,
                        "output_tokens": 10,
                    }
                return {
                    "text": json.dumps(
                        {
                            "summary": "Optimistic turn-1 summary that should NOT win on CDP error.",
                            "actions": [{"type": "desktop_browse", "url": "https://example.org/portal"}],
                        }
                    ),
                    "input_tokens": 10,
                    "output_tokens": 10,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": f"Observed {len(req.images)} screenshot(s); handled desktop status accurately.",
                        "actions": [],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 15,
            }

        async def failing_cdp_transport(
            bot_slug: str,
            cdp_endpoint: str,
            url: str,
            selector: str | None,
        ) -> CDPPageSnapshot:
            del bot_slug, cdp_endpoint, url, selector
            raise DesktopRuntimeError("Cannot connect to host argo-desktop-test:9222")

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_recovery_llm,
                docker_driver=InMemoryDockerDriver(),
                cdp_transport=failing_cdp_transport,
            )
            with TestClient(app) as client:
                created = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Recovery Bot",
                        "role": "Handle CDP error recovery and desktop screenshots",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-3.8-flash",
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                slug = created.json()["slug"]

                # Scenario A: Turn 1 desktop_browse fails -> triggers fallback launch + screenshot -> Turn 2 receives error & image
                with patch("argo_core.security.ssrf._default_dns_resolve", return_value=["93.184.216.34"]):
                    msg_res = client.post(
                        f"/api/bots/{slug}/messages",
                        headers=self._sso_headers(),
                        json={"text": "Open https://example.org/portal"},
                    )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                self.assertEqual(len(observed_requests), 2)
                self.assertEqual(len(observed_requests[0].images), 0)
                self.assertEqual(len(observed_requests[1].images), 1)
                self.assertTrue(observed_requests[1].images[0].startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertIn("Cannot connect to host", observed_requests[1].user_prompt)
                self.assertIn("fallback_launch", observed_requests[1].user_prompt)
                self.assertNotIn("Optimistic turn-1 summary", msg_res.json()["result"]["summary"])

                # Scenario B: Explicit desktop_screenshot forwards multimodal PNG to Turn 2 & saves screenshot_url in chat metadata
                observed_requests.clear()
                shot_res = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Take a desktop screenshot now"},
                )
                self.assertEqual(shot_res.status_code, 200, shot_res.text)
                self.assertEqual(len(observed_requests), 2)
                self.assertEqual(len(observed_requests[1].images), 1)
                self.assertIn("Observed 1 screenshot(s)", shot_res.json()["result"]["summary"])

                thread_msgs = client.get(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                ).json()
                bot_replies = [m for m in thread_msgs if m.get("sender") == "bot"]
                latest_actions = bot_replies[-1]["metadata"]["actions"]
                shot_url = next(
                    (
                        a.get("screenshot_url")
                        for a in latest_actions
                        if isinstance(a.get("screenshot_url"), str)
                        and a["screenshot_url"].startswith(f"/api/desktops/{slug}/snapshots/snap_")
                    ),
                    None,
                )
                self.assertIsNotNone(shot_url, latest_actions)

                snap_res = client.get(shot_url, headers=self._sso_headers())
                self.assertEqual(snap_res.status_code, 200)
                self.assertEqual(snap_res.headers.get("content-type"), "image/png")
                self.assertIn("immutable", snap_res.headers.get("cache-control", ""))
                self.assertTrue(snap_res.content.startswith(b"\x89PNG\r\n\x1a\n"))

                # Awake idle desktop must report "idle", not stuck "running"
                live_status = app.state.repo.build_live_workspace_status(active_runs={})
                station = next(b for b in live_status["bots"] if b["slug"] == slug)
                self.assertEqual(station["desktop_state"], "running")
                self.assertEqual(station["state"], "idle")

                # Desktop bots drafted without an explicit interval default to Manual schedule
                desk_draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Use the desktop Chromium browser to inspect internal dashboard screens",
                        "preferred_runtime": "desktop",
                    },
                )
                self.assertEqual(desk_draft.status_code, 200, desk_draft.text)
                self.assertEqual(desk_draft.json()["draft"]["routines"][0]["schedule"], "Manual")


if __name__ == "__main__":
    unittest.main()
