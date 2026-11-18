"""Unified connector health dispatcher and periodic 15m probe runner."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from argo_core.bus.valkey_bus import EventBus
from argo_core.connectors.google_oauth import GoogleOAuthService
from argo_core.connectors.linkedin import LinkedInService
from argo_core.connectors.telegram_bot import TelegramBotService
from argo_core.connectors.webhooks import WebhookConfigError, WebhookService
from argo_core.db.repositories import ArgoRepository, make_id

logger = logging.getLogger(__name__)


class ConnectorManager:
    """Routes per-connector health checks across Google, Telegram, LinkedIn, Webhooks, and MCP."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        google_service: GoogleOAuthService,
        telegram_service: TelegramBotService,
        linkedin_service: LinkedInService,
        webhook_service: WebhookService,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self.google = google_service
        self.telegram = telegram_service
        self.linkedin = linkedin_service
        self.webhook = webhook_service

    async def probe_integration(
        self,
        slug: str,
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        """Probe a single integration account by slug and return its updated health record."""
        account = self._repo.get_integration_secrets(slug)
        provider = account["provider"]
        if provider == "google":
            return await self.google.probe_account(account["slug"])
        if provider == "telegram":
            return await self.telegram.probe_account(
                account["slug"],
                send_test_message=send_test_message,
            )
        if provider == "linkedin":
            return await self.linkedin.probe_account(account["slug"])
        if provider == "webhook":
            return await self.webhook.probe_account(account["slug"])

        if account["has_secrets"] or account.get("account_identifier"):
            return self._repo.update_integration_health(
                account["slug"], status="ok", last_error=None
            )
        self._repo.update_integration_health(
            account["slug"],
            status="degraded",
            last_error="Connector configuration has neither endpoint identifier nor secrets.",
        )
        raise WebhookConfigError(
            f"Connector '{account['slug']}' lacks endpoint identifier and credentials."
        )

    async def probe_all_integrations(self) -> dict[str, Any]:
        """Probe every registered connector and emit Activity telemetry if any degrade."""
        accounts = self._repo.list_integrations()
        results: list[dict[str, Any]] = []
        ok_count = 0
        degraded_count = 0
        expired_count = 0
        degraded_slugs: list[str] = []

        for item in accounts:
            slug = str(item["slug"])
            provider = str(item["provider"])
            try:
                updated = await self.probe_integration(slug)
                status = str(updated["status"])
                results.append(
                    {
                        "slug": slug,
                        "provider": provider,
                        "status": status,
                        "last_error": updated.get("last_error"),
                    }
                )
            except Exception as exc:
                refreshed = self._repo.get_integration_secrets(slug)
                status = str(refreshed["status"])
                results.append(
                    {
                        "slug": slug,
                        "provider": provider,
                        "status": status,
                        "last_error": refreshed.get("last_error") or str(exc),
                    }
                )

            last_status = results[-1]["status"]
            if last_status == "ok":
                ok_count += 1
            elif last_status == "expired":
                expired_count += 1
                degraded_slugs.append(slug)
            else:
                degraded_count += 1
                degraded_slugs.append(slug)

        if degraded_slugs:
            await self._bus.publish(
                correlation_id=make_id("corr"),
                source_slug="integrations-probe",
                target_slug=None,
                event_type="integrations.health_degraded",
                payload={
                    "category": "alerts",
                    "title": "Connector Health Probe Attention Needed",
                    "badge": f"{degraded_count + expired_count} Issue(s)",
                    "badge_tone": "amber",
                    "summary": (
                        f"Degraded or expired connectors detected during health sweep: "
                        f"{', '.join(degraded_slugs)}."
                    ),
                    "meta": f"Checked {len(accounts)} connector(s)",
                },
                hop_count=1,
            )

        return {
            "total": len(accounts),
            "ok": ok_count,
            "degraded": degraded_count,
            "expired": expired_count,
            "results": results,
        }

    async def run_periodic_probes(self, interval_seconds: float = 900.0) -> None:
        """Execute periodic connector health probes every 15 minutes."""
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await self.probe_all_integrations()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Periodic connector health probe loop error: %s", exc)
