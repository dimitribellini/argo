"""FastAPI application entrypoint for argo-core."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.requests import HTTPConnection

from argo_core import __version__
from argo_core.api.routes import hooks_router, router as api_router
from argo_core.approvals.coordinator import ApprovalCoordinator
from argo_core.bus.valkey_bus import EventBus
from argo_core.config import ArgoSettings
from argo_core.connectors.gateway import build_default_connector_gateway
from argo_core.connectors.google_oauth import GoogleOAuthService, GoogleOAuthTransport
from argo_core.connectors.linkedin import LinkedInService, LinkedInTransport
from argo_core.connectors.manager import ConnectorManager
from argo_core.connectors.mcp_client import MCPConnectorService, MCPTransport
from argo_core.connectors.telegram_bot import TelegramBotService, TelegramTransport
from argo_core.connectors.webhooks import WebhookService
from argo_core.db.repositories import ArgoRepository
from argo_core.db.sqlite import init_db
from argo_core.desktop.cdp_bridge import CDPActionTransport, CDPTransport, ChromeDevToolsBridge
from argo_core.desktop.manager import (
    DesktopManager,
    DockerDriver,
    SelkiesProxyTransport,
)
from argo_core.desktop.mcp_bridge import DesktopAgentTransport, DesktopMCPBridge
from argo_core.llm.router import LLMRouter, LLMTransport
from argo_core.runner.bot_builder import ConversationalBotBuilder
from argo_core.runner.bot_runner import UniversalBotRunner
from argo_core.runner.scheduler import BotScheduler
from argo_core.sandbox.manager import SandboxDriver, SandboxManager
from argo_core.security.auth import (
    SESSION_COOKIE_NAME,
    GoogleAuthTransport,
    GoogleLoginService,
    LoginRateLimiter,
    hash_token,
    is_valid_csrf_origin,
    seed_bootstrap_admins,
)
from argo_core.security.sso import (
    extract_sso_principal,
    is_trusted_proxy_request,
    normalize_peer_ip,
)
from argo_core.security.ssrf import PublicHttpFetcher, SafePublicHttpFetcher
from argo_core.security.tenancy import is_multi_user_enabled, normalize_email
from argo_core.security.vault import SecretVault, resolve_or_persist_master_key
from argo_core.ssh.manager import SSHManager, SSHTransport
from argo_core.watchdog.debug_buffer import DebugLogBuffer
from argo_core.watchdog.resource_guard import HostResourceGuard, HostTelemetry


_PUBLIC_AUTH_API_PATHS = frozenset(
    {
        "/api/auth/config",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/bootstrap",
        "/api/auth/google/start",
        "/api/auth/google/callback",
    }
)


class _SSOEnforcementMiddleware:
    """Fail-closed pure-ASGI middleware enforcing sso proxy headers or native session cookies."""

    def __init__(self, app: Any, *, settings: ArgoSettings) -> None:
        self.app = app
        self._settings = settings

    @staticmethod
    async def _deny(scope_type: str, send: Any, *, status: int, detail: str) -> None:
        if scope_type == "websocket":
            await send({"type": "websocket.close", "code": 4403 if status == 403 else 4401})
            return
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        if path.startswith("/hooks/") or not (path == "/api" or path.startswith("/api/")):
            await self.app(scope, receive, send)
            return
        conn = HTTPConnection(scope)
        client_host = normalize_peer_ip(str(conn.client.host if conn.client else ""))
        if path == "/api/health" and client_host in {"127.0.0.1", "::1", "testclient"}:
            await self.app(scope, receive, send)
            return

        auth_mode_fn = getattr(self._settings, "resolved_auth_mode", None)
        auth_mode = str(auth_mode_fn() if callable(auth_mode_fn) else "sso")
        app_obj = scope.get("app")
        app_state = getattr(app_obj, "state", None)
        repo = getattr(app_state, "repo", None)

        if auth_mode == "sso":
            if not self._settings.require_sso:
                await self.app(scope, receive, send)
                return
            if not is_trusted_proxy_request(conn, self._settings):
                await self._deny(scope_type, send, status=403, detail="Untrusted proxy origin.")
                return
            principal = extract_sso_principal(conn)
            if not principal.get("authenticated"):
                await self._deny(scope_type, send, status=401, detail="SSO authentication required.")
                return
            if is_multi_user_enabled(self._settings) and repo is not None:
                user_rec = repo.get_user(normalize_email(principal.get("email")))
                if user_rec is not None and not user_rec.get("active", True):
                    await self._deny(scope_type, send, status=403, detail="Account is disabled.")
                    return
            scope.setdefault("state", {})["argo_principal"] = {**principal, "auth_method": "sso"}
            await self.app(scope, receive, send)
            return

        # Local / Hybrid native cookie authentication (ignores spoofable proxy identity headers)
        if scope_type == "http":
            method = str(scope.get("method") or "GET").upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"} and not is_valid_csrf_origin(conn, self._settings):
                await self._deny(scope_type, send, status=403, detail="Cross-origin request rejected.")
                return

        if path in _PUBLIC_AUTH_API_PATHS:
            await self.app(scope, receive, send)
            return

        if repo is None:
            await self._deny(scope_type, send, status=401, detail="Authentication required.")
            return

        raw_cookie = str(conn.cookies.get(SESSION_COOKIE_NAME) or "").strip()
        if not raw_cookie:
            await self._deny(scope_type, send, status=401, detail="Authentication required.")
            return
        session = repo.get_auth_session(hash_token(raw_cookie))
        if session is None:
            await self._deny(scope_type, send, status=401, detail="Session expired or invalid.")
            return
        user_rec = repo.get_user(str(session.get("email") or ""))
        if user_rec is None or not user_rec.get("active", True):
            await self._deny(scope_type, send, status=403 if user_rec is not None else 401, detail="Account is disabled.")
            return
        if int(user_rec.get("token_version") or 1) != int(session.get("token_version") or 1):
            await self._deny(scope_type, send, status=401, detail="Session has been revoked.")
            return

        must_change = bool(user_rec.get("must_change_password", False))
        if must_change and path not in {"/api/me", "/api/auth/change-password", "/api/auth/logout"}:
            await self._deny(
                scope_type,
                send,
                status=403,
                detail="Password change required before continuing.",
            )
            return

        email = str(user_rec["email"])
        scope.setdefault("state", {})["argo_principal"] = {
            "authenticated": True,
            "email": email,
            "display_name": str(user_rec.get("display_name") or ""),
            "actor": f"user:{email}",
            "auth_method": str(session.get("auth_method") or "password"),
            "must_change_password": must_change,
        }
        await self.app(scope, receive, send)


def create_app(
    settings: ArgoSettings | None = None,
    guard: HostResourceGuard | None = None,
    llm_router: LLMRouter | None = None,
    telegram_service: TelegramBotService | None = None,
    llm_transport: LLMTransport | None = None,
    telegram_transport: TelegramTransport | None = None,
    google_transport: GoogleOAuthTransport | None = None,
    linkedin_transport: LinkedInTransport | None = None,
    public_http_fetcher: PublicHttpFetcher | None = None,
    docker_driver: DockerDriver | None = None,
    cdp_transport: CDPTransport | None = None,
    cdp_action_transport: CDPActionTransport | None = None,
    selkies_proxy_transport: SelkiesProxyTransport | None = None,
    desktop_agent_transport: DesktopAgentTransport | None = None,
    ssh_transport: SSHTransport | None = None,
    sandbox_driver: SandboxDriver | None = None,
    mcp_transport: MCPTransport | None = None,
    google_auth_transport: GoogleAuthTransport | None = None,
) -> FastAPI:
    """Create and configure the argo-core FastAPI application."""
    resolved_settings = settings or ArgoSettings.from_env()
    resolved_guard = guard or HostResourceGuard()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        debug_buffer = DebugLogBuffer(max_records=500, level=logging.INFO)
        root_logger = logging.getLogger()
        root_logger.addHandler(debug_buffer)

        conn = init_db(resolved_settings.db_path)
        effective_master_key, key_source = resolve_or_persist_master_key(
            resolved_settings.master_key,
            resolved_settings.db_path,
            conn,
        )
        vault = SecretVault(effective_master_key)
        vault.is_configured = key_source == "env"
        repo = ArgoRepository(
            conn=conn,
            vault=vault,
            workspace_files_root=resolved_settings.resolved_workspace_files_root(),
        )
        repo.ensure_defaults()
        seed_bootstrap_admins(repo, resolved_settings)
        debug_buffer.attach_secret_provider(repo.collect_all_sensitive_secrets)
        bus = EventBus(valkey_url=resolved_settings.valkey_url, repo=repo)
        await bus.connect()
        google_login_service = GoogleLoginService(transport=google_auth_transport)
        login_rate_limiter = LoginRateLimiter(bus=bus)

        resolved_fetcher = public_http_fetcher or SafePublicHttpFetcher()
        resolved_router = llm_router or LLMRouter(repo=repo, transport=llm_transport)
        resolved_telegram = telegram_service or TelegramBotService(
            repo=repo,
            bus=bus,
            transport=telegram_transport,
            public_fetcher=resolved_fetcher,
        )
        google_int_client_id, google_int_client_secret = (
            resolved_settings.resolved_google_integration_client()
        )
        google_service = GoogleOAuthService(
            repo=repo,
            bus=bus,
            vault=vault,
            transport=google_transport,
            default_client_id=google_int_client_id,
            default_client_secret=google_int_client_secret,
        )
        linkedin_service = LinkedInService(
            repo=repo,
            bus=bus,
            transport=linkedin_transport,
        )
        webhook_service = WebhookService(repo=repo, bus=bus)
        mcp_service = MCPConnectorService(
            repo=repo,
            http_fetcher=resolved_fetcher,
            transport=mcp_transport,
        )
        connector_gateway = build_default_connector_gateway(
            google_service=google_service,
            telegram_service=resolved_telegram,
            linkedin_service=linkedin_service,
            webhook_service=webhook_service,
            mcp_service=mcp_service,
        )
        connector_manager = ConnectorManager(
            repo=repo,
            bus=bus,
            google_service=google_service,
            telegram_service=resolved_telegram,
            linkedin_service=linkedin_service,
            webhook_service=webhook_service,
            gateway=connector_gateway,
        )
        approval_coordinator = ApprovalCoordinator(
            repo=repo,
            bus=bus,
            llm_router=resolved_router,
            telegram_service=resolved_telegram,
            linkedin_service=linkedin_service,
            google_service=google_service,
            connector_gateway=connector_gateway,
        )
        resolved_telegram.attach_approval_coordinator(approval_coordinator)
        desktop_manager = DesktopManager(
            repo=repo,
            bus=bus,
            guard=resolved_guard,
            telegram_service=resolved_telegram,
            volumes_root=resolved_settings.desktop_volumes_root,
            idle_timeout_seconds=resolved_settings.desktop_idle_timeout_seconds,
            driver=docker_driver,
            selkies_proxy_transport=selkies_proxy_transport,
            multi_user=resolved_settings.multi_user,
            max_active_desktops_per_user=resolved_settings.max_active_desktops_per_user,
        )
        resolved_telegram.attach_desktop_manager(desktop_manager)
        approval_coordinator.attach_desktop_manager(desktop_manager)
        cdp_bridge = ChromeDevToolsBridge(
            desktop_manager=desktop_manager,
            bus=bus,
            telegram_service=resolved_telegram,
            transport=cdp_transport,
            action_transport=cdp_action_transport,
        )
        desktop_mcp_bridge = DesktopMCPBridge(
            desktop_manager=desktop_manager,
            bus=bus,
            transport=desktop_agent_transport,
        )
        sandbox_manager = SandboxManager(
            repo=repo,
            bus=bus,
            guard=resolved_guard,
            volumes_root=resolved_settings.resolved_sandbox_volumes_root(),
            idle_timeout_seconds=resolved_settings.sandbox_idle_timeout_seconds,
            image=resolved_settings.sandbox_image,
            network=resolved_settings.sandbox_network,
            driver=sandbox_driver,
            multi_user=resolved_settings.multi_user,
            max_active_sandboxes_per_user=resolved_settings.max_active_sandboxes_per_user,
        )
        ssh_manager = SSHManager(
            repo=repo,
            bus=bus,
            settings=resolved_settings,
            transport=ssh_transport,
        )
        approval_coordinator.attach_sandbox_manager(sandbox_manager)
        approval_coordinator.attach_ssh_manager(ssh_manager)
        bot_builder = ConversationalBotBuilder(repo=repo, llm_router=resolved_router)
        bot_runner = UniversalBotRunner(
            repo=repo,
            bus=bus,
            llm_router=resolved_router,
            approval_coordinator=approval_coordinator,
            http_fetcher=resolved_fetcher,
            desktop_manager=desktop_manager,
            cdp_bridge=cdp_bridge,
            desktop_mcp_bridge=desktop_mcp_bridge,
            sandbox_manager=sandbox_manager,
            ssh_manager=ssh_manager,
            guard=resolved_guard,
            google_service=google_service,
            connector_gateway=connector_gateway,
            debug_buffer=debug_buffer,
            settings=resolved_settings,
        )
        bot_scheduler = BotScheduler(repo=repo, runner=bot_runner)
        bot_runner.attach_scheduler(bot_scheduler)
        approval_coordinator.attach_scheduler(bot_scheduler)
        approval_coordinator.attach_bot_runner(bot_runner)
        resolved_telegram.attach_platform_services(
            llm_router=resolved_router,
            guard=resolved_guard,
            bot_scheduler=bot_scheduler,
        )

        application.state.settings = resolved_settings
        application.state.db_conn = conn
        application.state.vault = vault
        application.state.repo = repo
        application.state.bus = bus
        application.state.guard = resolved_guard
        application.state.public_http_fetcher = resolved_fetcher
        application.state.llm_router = resolved_router
        application.state.telegram_service = resolved_telegram
        application.state.google_oauth_service = google_service
        application.state.linkedin_service = linkedin_service
        application.state.webhook_service = webhook_service
        application.state.connector_gateway = connector_gateway
        application.state.connector_manager = connector_manager
        application.state.mcp_service = mcp_service
        application.state.approval_coordinator = approval_coordinator
        application.state.desktop_manager = desktop_manager
        application.state.cdp_bridge = cdp_bridge
        application.state.desktop_mcp_bridge = desktop_mcp_bridge
        application.state.sandbox_manager = sandbox_manager
        application.state.ssh_manager = ssh_manager
        application.state.bot_builder = bot_builder
        application.state.bot_runner = bot_runner
        application.state.bot_scheduler = bot_scheduler
        application.state.debug_buffer = debug_buffer
        application.state.google_login_service = google_login_service
        application.state.login_rate_limiter = login_rate_limiter

        await bot_runner.start()
        await bot_scheduler.start()

        async def _on_threshold(_telemetry: HostTelemetry) -> None:
            await resolved_guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=resolved_telegram,
                desktop_manager=desktop_manager,
                sandbox_manager=sandbox_manager,
            )

        watchdog_task = asyncio.create_task(
            resolved_guard.run_periodic(30.0, on_threshold=_on_threshold)
        )
        connector_probe_task = asyncio.create_task(
            connector_manager.run_periodic_probes(900.0)
        )
        desktop_idle_task = asyncio.create_task(
            desktop_manager.run_periodic_idle_sweep(30.0)
        )
        sandbox_idle_task = asyncio.create_task(
            sandbox_manager.run_periodic_idle_sweep(30.0)
        )
        ssh_maintenance_task = asyncio.create_task(
            ssh_manager.run_periodic_maintenance(60.0)
        )

        async def _run_chat_retention_loop(interval_seconds: float = 3600.0) -> None:
            while True:
                await asyncio.sleep(interval_seconds)
                try:
                    pruned = repo.prune_expired_chat_messages()
                    if pruned["pruned_total"] > 0:
                        await bus.publish(
                            correlation_id="chat_retention_sweep",
                            source_slug="system",
                            target_slug="*",
                            event_type="thread.cleared",
                            payload={
                                "target_type": "all",
                                "slug": "*",
                                "deleted_count": pruned["pruned_total"],
                                "retention_days": pruned["retention_days"],
                            },
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logging.getLogger(__name__).warning(
                        "Periodic chat retention sweep failed", exc_info=True
                    )

        chat_retention_task = asyncio.create_task(_run_chat_retention_loop(3600.0))
        try:
            yield
        finally:
            await bot_scheduler.stop()
            await bot_runner.stop()
            await ssh_manager.close_all()
            watchdog_task.cancel()
            connector_probe_task.cancel()
            desktop_idle_task.cancel()
            sandbox_idle_task.cancel()
            ssh_maintenance_task.cancel()
            chat_retention_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog_task
            with contextlib.suppress(asyncio.CancelledError):
                await connector_probe_task
            with contextlib.suppress(asyncio.CancelledError):
                await desktop_idle_task
            with contextlib.suppress(asyncio.CancelledError):
                await sandbox_idle_task
            with contextlib.suppress(asyncio.CancelledError):
                await ssh_maintenance_task
            with contextlib.suppress(asyncio.CancelledError):
                await chat_retention_task
            await bus.close()
            conn.close()
            root_logger.removeHandler(debug_buffer)

    application = FastAPI(
        title="Argo Core",
        version=__version__,
        lifespan=lifespan,
    )
    application.add_middleware(_SSOEnforcementMiddleware, settings=resolved_settings)
    application.include_router(api_router)
    application.include_router(hooks_router)

    if resolved_settings.static_dir and Path(resolved_settings.static_dir).is_dir():
        application.mount(
            "/",
            StaticFiles(directory=resolved_settings.static_dir, html=True),
            name="static",
        )

    return application


app = create_app()
