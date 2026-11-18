"""FastAPI application entrypoint for argo-core."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from argo_core import __version__
from argo_core.api.routes import hooks_router, router as api_router
from argo_core.approvals.coordinator import ApprovalCoordinator
from argo_core.bus.valkey_bus import EventBus
from argo_core.config import ArgoSettings
from argo_core.connectors.google_oauth import GoogleOAuthService, GoogleOAuthTransport
from argo_core.connectors.linkedin import LinkedInService, LinkedInTransport
from argo_core.connectors.manager import ConnectorManager
from argo_core.connectors.telegram_bot import TelegramBotService, TelegramTransport
from argo_core.connectors.webhooks import WebhookService
from argo_core.db.repositories import ArgoRepository
from argo_core.db.sqlite import init_db
from argo_core.desktop.cdp_bridge import CDPTransport, ChromeDevToolsBridge
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
from argo_core.security.ssrf import PublicHttpFetcher, SafePublicHttpFetcher
from argo_core.security.vault import SecretVault
from argo_core.watchdog.debug_buffer import DebugLogBuffer
from argo_core.watchdog.resource_guard import HostResourceGuard, HostTelemetry


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
    selkies_proxy_transport: SelkiesProxyTransport | None = None,
    desktop_agent_transport: DesktopAgentTransport | None = None,
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
        vault = SecretVault(resolved_settings.master_key)
        repo = ArgoRepository(
            conn=conn,
            vault=vault,
            workspace_files_root=resolved_settings.resolved_workspace_files_root(),
        )
        repo.ensure_defaults()
        bus = EventBus(valkey_url=resolved_settings.valkey_url, repo=repo)
        await bus.connect()

        resolved_fetcher = public_http_fetcher or SafePublicHttpFetcher()
        resolved_router = llm_router or LLMRouter(repo=repo, transport=llm_transport)
        resolved_telegram = telegram_service or TelegramBotService(
            repo=repo,
            bus=bus,
            transport=telegram_transport,
            public_fetcher=resolved_fetcher,
        )
        google_service = GoogleOAuthService(
            repo=repo,
            bus=bus,
            vault=vault,
            transport=google_transport,
            default_client_id=resolved_settings.google_client_id,
            default_client_secret=resolved_settings.google_client_secret,
        )
        linkedin_service = LinkedInService(
            repo=repo,
            bus=bus,
            transport=linkedin_transport,
        )
        webhook_service = WebhookService(repo=repo, bus=bus)
        connector_manager = ConnectorManager(
            repo=repo,
            bus=bus,
            google_service=google_service,
            telegram_service=resolved_telegram,
            linkedin_service=linkedin_service,
            webhook_service=webhook_service,
        )
        approval_coordinator = ApprovalCoordinator(
            repo=repo,
            bus=bus,
            llm_router=resolved_router,
            telegram_service=resolved_telegram,
            linkedin_service=linkedin_service,
            google_service=google_service,
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
        )
        resolved_telegram.attach_desktop_manager(desktop_manager)
        approval_coordinator.attach_desktop_manager(desktop_manager)
        cdp_bridge = ChromeDevToolsBridge(
            desktop_manager=desktop_manager,
            bus=bus,
            telegram_service=resolved_telegram,
            transport=cdp_transport,
        )
        desktop_mcp_bridge = DesktopMCPBridge(
            desktop_manager=desktop_manager,
            bus=bus,
            transport=desktop_agent_transport,
        )
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
            guard=resolved_guard,
            google_service=google_service,
            debug_buffer=debug_buffer,
        )
        bot_scheduler = BotScheduler(repo=repo, runner=bot_runner)
        bot_runner.attach_scheduler(bot_scheduler)
        approval_coordinator.attach_scheduler(bot_scheduler)
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
        application.state.connector_manager = connector_manager
        application.state.approval_coordinator = approval_coordinator
        application.state.desktop_manager = desktop_manager
        application.state.cdp_bridge = cdp_bridge
        application.state.desktop_mcp_bridge = desktop_mcp_bridge
        application.state.bot_builder = bot_builder
        application.state.bot_runner = bot_runner
        application.state.bot_scheduler = bot_scheduler
        application.state.debug_buffer = debug_buffer

        await bot_runner.start()
        await bot_scheduler.start()

        async def _on_threshold(_telemetry: HostTelemetry) -> None:
            await resolved_guard.evaluate_and_enforce(
                repo=repo,
                bus=bus,
                telegram=resolved_telegram,
                desktop_manager=desktop_manager,
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
        try:
            yield
        finally:
            await bot_scheduler.stop()
            await bot_runner.stop()
            watchdog_task.cancel()
            connector_probe_task.cancel()
            desktop_idle_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watchdog_task
            with contextlib.suppress(asyncio.CancelledError):
                await connector_probe_task
            with contextlib.suppress(asyncio.CancelledError):
                await desktop_idle_task
            await bus.close()
            conn.close()
            root_logger.removeHandler(debug_buffer)

    application = FastAPI(
        title="Argo Core",
        version=__version__,
        lifespan=lifespan,
    )
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
