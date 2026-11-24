"""Signed inbound HMAC-SHA256 webhook connector and verification service."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, collection_slug, make_id, slugify, utc_now

MAX_WEBHOOK_BODY_BYTES = 1_048_576
_EVENT_TYPE_RE = re.compile(r"^[a-z0-9_.-]{3,80}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class WebhookConfigError(ValueError):
    """Raised when webhook onboarding settings or inbound payloads are malformed."""


class WebhookSignatureError(PermissionError):
    """Raised when an inbound webhook fails constant-time HMAC-SHA256 verification."""


def compute_hmac_sha256(secret: str, raw_body: bytes) -> str:
    """Compute canonical 'sha256=<hex>' HMAC signature over raw webhook request bytes."""
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_hmac_sha256(secret: str, raw_body: bytes, signature_header: str | None) -> bool:
    """Verify an X-Argo-Signature-256 / X-Hub-Signature-256 header in constant time."""
    if not secret or not signature_header:
        return False
    candidate = signature_header.strip().lower()
    if candidate.startswith("sha256="):
        candidate = candidate[7:].strip()
    if not _HEX64_RE.match(candidate):
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(candidate, expected)


class WebhookService:
    """Manages HMAC-SHA256 webhook endpoints, replay deduplication, and bus dispatch."""

    def __init__(self, *, repo: ArgoRepository, bus: EventBus) -> None:
        self._repo = repo
        self._bus = bus

    async def onboard_webhook(
        self,
        *,
        display_name: str,
        slug: str | None = None,
        signing_secret: str | None = None,
        event_type: str = "webhook.received",
        target_collection: str | None = "webhook_events",
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register an inbound signed webhook connector and return its URL (+ generated secret once)."""
        clean_name = display_name.strip()
        if not clean_name:
            raise WebhookConfigError("Webhook display_name is required.")

        clean_event = event_type.strip().lower()
        if not _EVENT_TYPE_RE.match(clean_event):
            raise WebhookConfigError(
                "Invalid webhook event_type; expected lowercase alphanumeric, '.', '_', or '-'."
            )

        generated = False
        if signing_secret and signing_secret.strip():
            clean_secret = signing_secret.strip()
            if len(clean_secret) < 16:
                raise WebhookConfigError(
                    "Webhook signing_secret must be at least 16 characters."
                )
        else:
            clean_secret = secrets.token_hex(32)
            generated = True

        resolved_slug = slugify(slug or clean_name)
        clean_collection = (
            collection_slug(target_collection)
            if target_collection and target_collection.strip()
            else None
        )
        webhook_path = f"/hooks/webhook/{resolved_slug}"

        record = self._repo.upsert_integration(
            slug=resolved_slug,
            provider="webhook",
            display_name=clean_name,
            account_identifier=webhook_path,
            scopes=["hmac_sha256", f"event:{clean_event}"],
            secrets={
                "signing_secret": clean_secret,
                "event_type": clean_event,
                "target_collection": clean_collection,
            },
            owner_email=owner_email,
            visibility=visibility,
            allowed_groups=allowed_groups,
            status="ok",
        )

        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug="integrations",
            target_slug=resolved_slug,
            event_type="integration.webhook.connected",
            payload={
                "category": "alerts",
                "title": f"Registered Signed Webhook {clean_name}",
                "badge": "HMAC-SHA256 · Listening",
                "badge_tone": "emerald",
                "summary": (
                    f"Signed webhook endpoint ready at {webhook_path} emitting "
                    f"'{clean_event}' events."
                ),
                "meta": (
                    f"Collection: {clean_collection}"
                    if clean_collection
                    else "EventBus only"
                ),
            },
            hop_count=1,
        )

        return {
            **record,
            "webhook_path": webhook_path,
            "event_type": clean_event,
            "target_collection": clean_collection,
            "signing_secret_once": clean_secret if generated else None,
        }

    async def handle_inbound(
        self,
        slug: str,
        *,
        raw_body: bytes,
        signature_header: str | None,
        delivery_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify HMAC signature, deduplicate delivery, persist payload, and emit EventBus event."""
        if len(raw_body) > MAX_WEBHOOK_BODY_BYTES:
            raise WebhookConfigError("Webhook payload exceeds 1 MB limit.")

        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "webhook":
            raise WebhookConfigError(f"Integration '{slug}' is not a webhook connector.")

        sec = account["secrets"]
        signing_secret = str(sec.get("signing_secret") or "")
        if not verify_hmac_sha256(signing_secret, raw_body, signature_header):
            raise WebhookSignatureError("Invalid or missing HMAC-SHA256 webhook signature.")

        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            raise WebhookConfigError("Webhook request body must be valid UTF-8 JSON.") from exc
        if not isinstance(parsed, (dict, list)):
            raise WebhookConfigError("Webhook JSON payload must be an object or array.")

        body_digest = hashlib.sha256(raw_body).hexdigest()[:24]
        body_event_id = (
            str(parsed["id"]).strip()
            if isinstance(parsed, dict) and parsed.get("id") is not None and str(parsed["id"]).strip()
            else ""
        )
        replay_key = f"id:{body_event_id}" if body_event_id else f"sha256:{body_digest}"
        resolved_delivery_id = body_event_id or (delivery_id or "").strip() or body_digest

        is_fresh = await self._bus.check_and_mark_seen(
            f"wh:{account['slug']}:{replay_key}"
        )
        if not is_fresh:
            return {
                "status": "duplicate_ignored",
                "delivery_id": resolved_delivery_id,
            }

        event_type = str(sec.get("event_type") or "webhook.received")
        target_collection = sec.get("target_collection")
        preview = json.dumps(parsed, ensure_ascii=False)[:500]
        if target_collection:
            self._repo.upsert_document(
                collection=str(target_collection),
                external_key=f"wh:{account['slug']}:{resolved_delivery_id}",
                search_text=f"{account['slug']} {event_type} {preview}",
                doc={
                    "webhook_slug": account["slug"],
                    "delivery_id": resolved_delivery_id,
                    "event_type": event_type,
                    "payload": parsed,
                    "received_at": utc_now(),
                },
                description="Signed inbound HMAC webhook deliveries",
            )

        self._repo.update_integration_health(account["slug"], status="ok", last_error=None)
        event_record = await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug=f"webhook:{account['slug']}",
            target_slug=None,
            event_type=event_type,
            payload={
                "category": "reviews",
                "title": f"Signed Webhook Received ({account['display_name']})",
                "badge": f"HMAC-SHA256 · {event_type}",
                "badge_tone": "emerald",
                "summary": preview,
                "meta": f"Delivery: {resolved_delivery_id}",
                "webhook_slug": account["slug"],
                "delivery_id": resolved_delivery_id,
                "data": parsed,
            },
            hop_count=1,
        )
        return {
            "status": "accepted",
            "delivery_id": resolved_delivery_id,
            "event_id": event_record["id"],
            "event_type": event_type,
        }

    async def probe_account(self, slug: str) -> dict[str, Any]:
        """Verify that stored webhook HMAC signing secret is intact."""
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "webhook":
            return self._repo.update_integration_health(
                account["slug"], status="ok", last_error=None
            )

        signing_secret = str(account["secrets"].get("signing_secret") or "")
        if len(signing_secret) < 16:
            err = "Stored webhook signing_secret is missing or shorter than 16 characters."
            self._repo.update_integration_health(
                account["slug"],
                status="degraded",
                last_error=err,
            )
            raise WebhookConfigError(err)

        return self._repo.update_integration_health(
            account["slug"],
            status="ok",
            last_error=None,
        )
