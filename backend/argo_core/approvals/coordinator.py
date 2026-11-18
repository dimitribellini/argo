"""Deterministic Python connector RBAC gate & atomic Web/Telegram approval sync."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import urllib.request
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from argo_core.bus.valkey_bus import MAX_HOP_COUNT, EventBus
from argo_core.connectors.linkedin import LinkedInService
from argo_core.connectors.telegram_bot import TelegramBotService, build_inline_keyboard
from argo_core.db.repositories import (
    ArgoRepository,
    derive_style_rule_from_diff,
    make_id,
    slugify,
    utc_now,
)
from argo_core.llm.router import LLMRouter
from argo_core.security.ssrf import validate_public_url

logger = logging.getLogger(__name__)

APPROVAL_OK_PREFIX = "apr:ok:"
APPROVAL_NO_PREFIX = "apr:no:"

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI/API token pattern", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("Anthropic API key pattern", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b")),
    ("Google OAuth access token", re.compile(r"\bya29\.[A-Za-z0-9._-]{16,}\b")),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{12,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Bearer credential header", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("US SSN pattern", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


class ConnectorPermissionError(PermissionError):
    """Raised when a bot's RBAC policy forbids an outbound connector action."""


def check_outbound_safety(text: str) -> str | None:
    """Detect raw credentials, tokens, or SSN-like PII before direct connector execution."""
    candidate = text or ""
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(candidate):
            return label
    return None


def _apply_local_revision(original_text: str, instruction_text: str) -> str:
    """Deterministic fallback draft revision when no live LLM key is configured."""
    instr = instruction_text.strip()
    lower = instr.lower()
    revised = original_text.strip()

    if any(word in lower for word in ("remove url", "no link", "without url", "strip link")):
        revised = re.sub(r"https?://\S+", "", revised)
    if "cvss" in lower and any(w in lower for w in ("remove", "omit", "drop", "no ")):
        revised = re.sub(r"\(?CVSS[:\s]*[0-9.]+\)?", "", revised, flags=re.IGNORECASE)
    if any(word in lower for word in ("shorter", "concise", "punchier", "brief")):
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", revised) if s.strip()]
        if len(sentences) > 2:
            revised = " ".join(sentences[:2])

    revised = re.sub(r"[ \t]{2,}", " ", revised).strip()
    if not revised or revised == original_text.strip():
        revised = f"{original_text.strip()}\n\n[Revised per note: {instr}]"
    return revised


class ApprovalCoordinator:
    """Enforces Python connector RBAC and synchronizes Web UI Approvals & Telegram cards."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        llm_router: LLMRouter,
        telegram_service: TelegramBotService,
        linkedin_service: LinkedInService,
        google_service: Any | None = None,
        webhook_transport: Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._llm_router = llm_router
        self._telegram = telegram_service
        self._linkedin = linkedin_service
        self._google = google_service
        self._webhook_transport = webhook_transport
        self._bot_scheduler: Any | None = None
        self._desktop_manager: Any | None = None

    def attach_scheduler(self, scheduler: Any) -> None:
        """Bind BotScheduler so approved workspace changes sync cron jobs immediately."""
        self._bot_scheduler = scheduler

    def attach_desktop_manager(self, desktop_manager: Any) -> None:
        """Bind DesktopManager so approved fleet cleanup deletions destroy orphaned desktops."""
        self._desktop_manager = desktop_manager

    def _has_approval_event_subscribers(self) -> bool:
        """Return True if at least one enabled bot subscribes to 'approval.queued'."""
        for bot in self._repo.list_bots():
            if not bot.get("enabled"):
                continue
            for routine in bot.get("routines") or []:
                if not isinstance(routine, dict) or not routine.get("enabled", True):
                    continue
                ev = str(
                    routine.get("event")
                    or routine.get("trigger")
                    or routine.get("topic")
                    or ""
                ).strip()
                if ev == "approval.queued":
                    return True
        return False

    def _select_operator_telegram_account(
        self,
        target_account_slug: str,
        *,
        chat_id: str | int | None = None,
    ) -> dict[str, Any] | None:
        """Select a Telegram account strictly scoped to target_account_slug (or matching chat_id when locking)."""
        candidates = self._repo.list_telegram_integrations()
        if chat_id is not None:
            chat_str = str(chat_id)
            for acc in candidates:
                sec = acc.get("secrets") or {}
                if (
                    acc["status"] != "expired"
                    and sec.get("bot_token")
                    and (
                        str(sec.get("operator_chat_id") or "") == chat_str
                        or chat_str in {str(c) for c in (sec.get("admin_channels") or [])}
                    )
                ):
                    return acc

        target_acc = self._repo.find_integration_secrets(target_account_slug)
        if target_acc and target_acc["provider"] == "telegram" and target_acc["status"] != "expired":
            sec = target_acc.get("secrets") or {}
            if sec.get("bot_token") and sec.get("operator_chat_id"):
                return target_acc
        return None

    @staticmethod
    def _format_permission_card_text(approval: dict[str, Any]) -> str:
        payload = approval.get("payload") or {}
        target = payload.get("target") or payload.get("to") or approval["target_account_slug"]
        lines = [
            f"[Argo Approval · {approval['id']}]",
            f"Bot: {approval['bot_slug']} · Action: {approval['action_type']}",
            f"Target: {target} ({approval['target_account_slug']})",
        ]
        recipient = str(payload.get("to") or "").strip()
        subject = str(payload.get("subject") or "").strip()
        if recipient:
            lines.append(f"To: {recipient}")
        if subject:
            lines.append(f"Subject: {subject}")
        if approval.get("escalation_note"):
            lines.append(f"Reason: {approval['escalation_note']}")
        if approval.get("source_url"):
            lines.append(f"Source: {approval['source_url']}")
        draft_text = str(payload.get("text") or "").strip()
        if draft_text:
            lines.append("")
            lines.append(draft_text[:2800])
        lines.append("")
        lines.append("Reply to this message with revision instructions to regenerate & save a style rule.")
        return "\n".join(lines)[:3900]

    async def _lock_telegram_card(
        self,
        approval: dict[str, Any],
        *,
        status_line: str,
    ) -> None:
        """Edit the Telegram permission card to remove inline buttons and stamp outcome."""
        chat_id = approval.get("telegram_chat_id")
        message_id = approval.get("telegram_message_id")
        if not chat_id or message_id is None:
            return
        account = self._select_operator_telegram_account(
            approval["target_account_slug"],
            chat_id=chat_id,
        )
        if account is None:
            return
        base_text = self._format_permission_card_text(approval)
        final_payload = approval.get("edited_payload") or approval.get("payload") or {}
        if approval.get("edited_payload") and final_payload.get("text"):
            base_text = (
                f"[Argo Approval · {approval['id']}]\n"
                f"Bot: {approval['bot_slug']} · Target: {approval['target_account_slug']}\n\n"
                f"{str(final_payload['text'])[:2800]}"
            )
        locked_text = f"{base_text}\n\nStatus: {status_line}"[:4000]
        try:
            await self._telegram.edit_operator_message(
                account["slug"],
                chat_id=chat_id,
                message_id=int(message_id),
                text=locked_text,
                reply_markup=None,
            )
        except Exception as exc:
            logger.warning(
                "Failed to edit Telegram card for approval %s: %s",
                approval["id"],
                exc,
            )

    async def enqueue_human_approval(
        self,
        *,
        correlation_id: str,
        bot_slug: str,
        target_account_slug: str,
        action_type: str,
        payload: dict[str, Any],
        source_url: str | None = None,
        source_excerpt: str | None = None,
        escalation_note: str | None = None,
        hop_count: int = 1,
    ) -> dict[str, Any]:
        """Persist a pending approval row, save Gmail draft when applicable, and notify Telegram/SSE."""
        payload_to_store = dict(payload)
        if (
            self._google is not None
            and action_type in {"send_email", "gmail_draft", "reply_email"}
            and payload_to_store.get("to")
            and not payload_to_store.get("gmail_draft_id")
        ):
            target_account = self._repo.find_integration_secrets(target_account_slug)
            if target_account and target_account.get("provider") == "google":
                try:
                    draft_res = await self._google.create_draft(
                        target_account_slug,
                        to_email=str(payload_to_store["to"]).strip(),
                        subject=str(payload_to_store.get("subject") or "(No subject)").strip(),
                        body_text=str(payload_to_store.get("text") or "").strip(),
                        cc_email=payload_to_store.get("cc"),
                        thread_id=payload_to_store.get("thread_id"),
                        in_reply_to=payload_to_store.get("in_reply_to"),
                    )
                    if draft_res.get("draft_id"):
                        payload_to_store["gmail_draft_id"] = draft_res["draft_id"]
                except Exception as exc:
                    logger.warning(
                        "Best-effort Gmail draft creation failed for %s: %s",
                        target_account_slug,
                        exc,
                    )

        created = self._repo.create_approval(
            correlation_id=correlation_id,
            bot_slug=bot_slug,
            target_account_slug=target_account_slug,
            action_type=action_type,
            payload=payload_to_store,
            source_url=source_url,
            source_excerpt=source_excerpt,
            escalation_note=escalation_note,
        )

        tg_account = (
            None
            if self._has_approval_event_subscribers()
            else self._select_operator_telegram_account(target_account_slug)
        )
        if tg_account is not None:
            op_chat_id = str(tg_account["secrets"]["operator_chat_id"])
            card_text = self._format_permission_card_text(created)
            markup = build_inline_keyboard(
                [
                    [
                        ("Approve & Publish", f"{APPROVAL_OK_PREFIX}{created['id']}"),
                        ("Reject", f"{APPROVAL_NO_PREFIX}{created['id']}"),
                    ]
                ]
            )
            try:
                sent = await self._telegram.publish_message(
                    tg_account["slug"],
                    chat_id=op_chat_id,
                    text=card_text,
                    reply_markup=markup,
                )
                created = self._repo.set_approval_telegram_card(
                    created["id"],
                    chat_id=str(sent.get("chat_id") or op_chat_id),
                    message_id=int(sent["message_id"]),
                )
            except Exception as exc:
                logger.error(
                    "Unable to send Telegram approval card for %s: %s",
                    created["id"],
                    exc,
                )

        safe_hop = min(MAX_HOP_COUNT, max(1, int(hop_count)))
        target_label = payload.get("target") or target_account_slug
        await self._bus.publish(
            correlation_id=correlation_id,
            source_slug=bot_slug,
            target_slug="approvals",
            event_type="approval.queued",
            payload={
                "category": "reviews",
                "title": f"Queued {action_type} for {target_label}",
                "badge": "Pending Human Approval",
                "badge_tone": "amber",
                "summary": str(payload.get("text") or "")[:240],
                "meta": escalation_note or f"Approval {created['id']}",
                "hop_count": safe_hop,
                "approval_id": created["id"],
                "bot_slug": bot_slug,
                "target_account_slug": target_account_slug,
                "action_type": action_type,
                "draft_text": str(payload_to_store.get("text") or "")[:2800],
                "to": payload_to_store.get("to"),
                "subject": payload_to_store.get("subject"),
                "source_url": source_url,
                "escalation_note": escalation_note,
            },
            hop_count=safe_hop,
        )
        return created

    async def deliver_approval_notification(
        self,
        *,
        approval_id: str,
        account_slug: str,
        text: str | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Deliver a human approval notification (and interactive card on Telegram) via account_slug."""
        approval = self._repo.get_approval(approval_id)
        account = self._repo.find_integration_secrets(account_slug)
        if account is None:
            raise RuntimeError(f"Notification integration '{account_slug}' is not onboarded.")
        if account["status"] == "expired":
            raise RuntimeError(f"Notification integration '{account['slug']}' is expired.")

        provider = account["provider"]
        secrets = account.get("secrets") or {}
        if provider == "telegram":
            dest_chat = (
                str(target).strip()
                if target and str(target).strip()
                else str(secrets.get("operator_chat_id") or "").strip()
            )
            if not dest_chat:
                admin_channels = list(secrets.get("admin_channels") or [])
                dest_chat = str(admin_channels[0]).strip() if admin_channels else ""
            if not dest_chat:
                raise RuntimeError(
                    f"Telegram connector '{account['slug']}' has no operator_chat_id or target channel."
                )
            card_text = (text or "").strip() or self._format_permission_card_text(approval)
            markup = build_inline_keyboard(
                [
                    [
                        ("Approve & Publish", f"{APPROVAL_OK_PREFIX}{approval['id']}"),
                        ("Reject", f"{APPROVAL_NO_PREFIX}{approval['id']}"),
                    ]
                ]
            )
            sent = await self._telegram.publish_message(
                account["slug"],
                chat_id=dest_chat,
                text=card_text,
                reply_markup=markup,
            )
            self._repo.set_approval_telegram_card(
                approval["id"],
                chat_id=str(sent.get("chat_id") or dest_chat),
                message_id=int(sent["message_id"]),
            )
            return {"provider": "telegram", "approval_id": approval["id"], **sent}

        msg_text = (text or "").strip() or self._format_permission_card_text(approval)
        dispatch_payload: dict[str, Any] = {
            "approval_id": approval["id"],
            "bot_slug": approval["bot_slug"],
            "action_type": approval["action_type"],
            "target": target or None,
            "to": (target or secrets.get("operator_email") or secrets.get("email") or ""),
            "subject": f"[Argo Approval] {approval['action_type']} from {approval['bot_slug']}",
        }
        return await self._dispatch_outbound(
            account,
            action_type=f"notify_{approval['action_type']}",
            payload=dispatch_payload,
            final_text=msg_text,
        )

    async def _dispatch_outbound(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        """Deliver an approved or execute-permitted payload via the configured connector."""
        provider = account["provider"]
        secrets = account.get("secrets") or {}

        if provider == "telegram":
            admin_channels = list(secrets.get("admin_channels") or [])
            raw_target = str(payload.get("target") or "").strip()
            bot_identities = {
                str(secrets.get("username") or "").lstrip("@").strip().lower(),
                str(account.get("account_identifier") or "").lstrip("@").strip().lower(),
                str(account.get("slug") or "").strip().lower(),
                str(account.get("display_name") or "").strip().lower(),
            }
            bot_identities.discard("")
            if raw_target.lstrip("@").strip().lower() in bot_identities:
                raw_target = ""
            dest_chat = (
                raw_target
                or (str(admin_channels[0]).strip() if admin_channels else "")
                or str(secrets.get("operator_chat_id") or "").strip()
            )
            if not dest_chat:
                raise RuntimeError(
                    f"Telegram connector '{account['slug']}' has no target channel or operator_chat_id."
                )
            sent = await self._telegram.publish_message(
                account["slug"],
                chat_id=dest_chat,
                text=final_text,
            )
            return {"provider": "telegram", "target": dest_chat, **sent}

        if provider == "linkedin":
            res = await self._linkedin.publish_post(
                account["slug"],
                commentary=final_text,
                visibility=payload.get("visibility", "PUBLIC"),
                article_url=payload.get("article_url"),
                article_title=payload.get("article_title"),
            )
            return {"provider": "linkedin", **res}

        if provider == "google":
            if account["status"] == "expired":
                raise RuntimeError(
                    f"Google connector '{account['slug']}' is expired and requires re-auth."
                )
            if self._google is None:
                raise RuntimeError(
                    "GoogleOAuthService is not attached to ApprovalCoordinator."
                )
            to_email = str(payload.get("to") or payload.get("target") or "").strip()
            subject = str(payload.get("subject") or "(No subject)").strip()
            if not to_email:
                raise RuntimeError(
                    f"Email action '{action_type}' on '{account['slug']}' is missing recipient 'to'."
                )
            if action_type == "gmail_draft":
                res = await self._google.create_draft(
                    account["slug"],
                    to_email=to_email,
                    subject=subject,
                    body_text=final_text,
                    cc_email=payload.get("cc"),
                    thread_id=payload.get("thread_id"),
                    in_reply_to=payload.get("in_reply_to"),
                )
                return {
                    "provider": "google",
                    "action_type": action_type,
                    "target": to_email,
                    **res,
                }
            res = await self._google.send_email(
                account["slug"],
                to_email=to_email,
                subject=subject,
                body_text=final_text,
                cc_email=payload.get("cc"),
                thread_id=payload.get("thread_id"),
                in_reply_to=payload.get("in_reply_to"),
            )
            return {
                "provider": "google",
                "action_type": action_type,
                "target": to_email,
                **res,
            }

        if account["status"] == "expired":
            raise RuntimeError(
                f"Connector '{account['slug']}' ({provider}) is expired and requires re-auth."
            )

        if provider == "webhook":
            raw_token = str(secrets.get("token") or "").strip()
            raw_target = str(payload.get("target") or "").strip()
            target_url = str(
                (raw_target if raw_target.startswith(("http://", "https://")) else "")
                or secrets.get("target_url")
                or secrets.get("webhook_url")
                or secrets.get("outbound_url")
                or account.get("account_identifier")
                or (raw_token if raw_token.startswith(("http://", "https://")) else "")
            ).strip()
            if target_url.startswith(("http://", "https://")):
                cleaned_url, _ = validate_public_url(target_url)
                webhook_body = {
                    "text": final_text,
                    "action_type": action_type,
                    "approval_id": payload.get("approval_id"),
                    "bot_slug": payload.get("bot_slug"),
                }
                req_headers = {"Content-Type": "application/json"}
                if self._webhook_transport is not None:
                    post_res = await self._webhook_transport(cleaned_url, webhook_body, req_headers)
                    return {
                        "provider": "webhook",
                        "account_slug": account["slug"],
                        "target": cleaned_url,
                        "status_code": post_res.get("status_code", 200),
                        "delivered_at": utc_now(),
                    }

                def _sync_post() -> int:
                    req = urllib.request.Request(
                        cleaned_url,
                        data=json.dumps(webhook_body, ensure_ascii=False).encode("utf-8"),
                        headers=req_headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=15.0) as resp:
                        return int(resp.status)

                status_code = await asyncio.to_thread(_sync_post)
                return {
                    "provider": "webhook",
                    "account_slug": account["slug"],
                    "target": cleaned_url,
                    "status_code": status_code,
                    "delivered_at": utc_now(),
                }

        return {
            "provider": provider,
            "account_slug": account["slug"],
            "action_type": action_type,
            "target": payload.get("target") or account.get("account_identifier") or account["slug"],
            "delivered_at": utc_now(),
        }

    async def resolve_approval(
        self,
        approval_id: str,
        *,
        action: Literal["approve", "reject", "edit_approve"],
        actor: str,
        edited_text: str | None = None,
        style_rule: str | None = None,
    ) -> dict[str, Any]:
        """Atomically approve/edit/reject an approval, execute live connectors, and lock Telegram."""
        resolved = self._repo.resolve_approval(
            approval_id=approval_id,
            action=action,
            actor=actor,
            edited_text=edited_text,
            style_rule=style_rule,
        )

        status_line = f"Rejected by {actor} at {resolved['resolved_at']}"
        if resolved["status"] == "approved":
            effective_payload = resolved.get("edited_payload") or resolved.get("payload") or {}
            final_text = str(effective_payload.get("text") or "").strip()

            if resolved["target_account_slug"] == "argo_workspace":
                try:
                    if resolved["action_type"] == "create_specialist_bot":
                        spec = dict(effective_payload.get("bot_spec") or {})
                        created_bot = self._repo.create_bot(
                            name=str(spec.get("name") or "Specialist Bot"),
                            role=str(spec.get("role") or "Specialist automation bot"),
                            runtime=str(spec.get("runtime") or "api"),
                            outbound_rbac=str(spec.get("outbound_rbac") or "draft"),
                            model=str(spec.get("model") or "google:gemini-3.8-flash"),
                            daily_cap=int(spec.get("daily_cap") or 10),
                            role_prompt=spec.get("role_prompt"),
                            routines=spec.get("routines"),
                            tools=spec.get("tools"),
                            collections=spec.get("collections"),
                            linked_accounts=spec.get("linked_accounts"),
                            avatar_color=str(spec.get("avatar_color") or "indigo"),
                            avatar_icon=str(spec.get("avatar_icon") or "bot"),
                            section=str(spec.get("section") or ""),
                            boundaries=spec.get("boundaries"),
                        )
                        if self._bot_scheduler is not None:
                            self._bot_scheduler.sync_bots()
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=True,
                        )
                        status_line = f"Created bot '{created_bot['name']}' by {actor}"
                    elif resolved["action_type"] == "fleet_cleanup":
                        applied = 0
                        for op in effective_payload.get("operations") or []:
                            if not isinstance(op, dict):
                                continue
                            b_slug = str(op.get("bot_slug") or "").strip()
                            if not b_slug:
                                continue
                            if op.get("delete"):
                                deleted_bot = self._repo.delete_bot(b_slug)
                                dm = getattr(self, "_desktop_manager", None)
                                if dm is not None:
                                    with contextlib.suppress(Exception):
                                        await dm.destroy_desktop(str(deleted_bot.get("slug") or b_slug))
                                applied += 1
                                continue
                            patch: dict[str, Any] = {}
                            for key in ("enabled", "hidden_in_sidebar", "section", "pinned"):
                                if key in op and op[key] is not None:
                                    patch[key] = op[key]
                            if patch:
                                self._repo.update_bot(b_slug, patch)
                                applied += 1
                        if self._bot_scheduler is not None:
                            self._bot_scheduler.sync_bots()
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=True,
                        )
                        status_line = f"Applied {applied} fleet change(s) by {actor}"
                    elif resolved["action_type"] == "update_bot_config":
                        target_bot_slug = str(
                            effective_payload.get("bot_slug") or resolved["bot_slug"]
                        ).strip()
                        raw_updates = dict(effective_payload.get("updates") or {})
                        allowed_keys = {
                            "outbound_rbac",
                            "daily_cap",
                            "runtime",
                            "linked_accounts",
                            "boundaries",
                            "role",
                            "role_prompt",
                            "handoff_bot_slug",
                            "model",
                            "section",
                            "goal_metric",
                            "onboarding_pending",
                        }
                        clean_patch = {
                            k: v for k, v in raw_updates.items() if k in allowed_keys and v is not None
                        }
                        if clean_patch:
                            self._repo.update_bot(target_bot_slug, clean_patch)
                        if self._bot_scheduler is not None:
                            self._bot_scheduler.sync_bots()
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=True,
                        )
                        status_line = f"Applied bot configuration update on '{target_bot_slug}' by {actor}"
                    else:
                        status_line = f"Approved by {actor} at {resolved['resolved_at']}"
                except Exception as exc:
                    resolved = self._repo.mark_approval_dispatch_result(
                        approval_id,
                        executed=False,
                        error_message=str(exc)[:500],
                    )
                    status_line = f"Approved (workspace error: {str(exc)[:120]})"
            else:
                account = self._repo.find_integration_secrets(resolved["target_account_slug"])

                if account is None:
                    status_line = f"Approved by {actor} at {resolved['resolved_at']}"
                else:
                    try:
                        await self._dispatch_outbound(
                            account,
                            action_type=resolved["action_type"],
                            payload=effective_payload,
                            final_text=final_text,
                        )
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=True,
                        )
                        status_line = f"Executed by {actor} at {resolved['resolved_at']}"
                    except Exception as exc:
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=False,
                            error_message=str(exc)[:500],
                        )
                        status_line = f"Approved (delivery error: {str(exc)[:120]})"

        await self._lock_telegram_card(resolved, status_line=status_line)

        badge_map = {
            "executed": ("Executed", "emerald"),
            "approved": ("Approved", "emerald"),
            "rejected": ("Rejected", "slate"),
        }
        badge_text, badge_tone = badge_map.get(resolved["status"], (resolved["status"], "slate"))
        await self._bus.publish(
            correlation_id=resolved["correlation_id"],
            source_slug=actor,
            target_slug=resolved["bot_slug"],
            event_type="approval.resolved",
            payload={
                "category": "reviews",
                "title": f"Approval {resolved['id']} -> {resolved['status']}",
                "badge": badge_text,
                "badge_tone": badge_tone,
                "summary": f"{resolved['action_type']} to {resolved['target_account_slug']} ({status_line})",
                "meta": resolved.get("error_message") or f"Resolved by {actor}",
                "approval_id": resolved["id"],
                "approval_status": resolved["status"],
            },
            hop_count=1,
        )
        return resolved

    async def handle_telegram_reply_revision(
        self,
        *,
        chat_id: str | int,
        reply_to_message_id: int,
        instruction_text: str,
        actor: str,
        telegram_account_slug: str,
    ) -> dict[str, Any] | None:
        """Handle operator Telegram reply_to_message: revise draft, save style_memory, re-queue."""
        old = self._repo.get_pending_approval_by_telegram_message(
            chat_id=chat_id,
            message_id=reply_to_message_id,
        )
        if old is None:
            return None

        superseded = self._repo.supersede_approval(old["id"], actor=actor)
        orig_payload = dict(superseded.get("payload") or {})
        orig_text = str(orig_payload.get("text") or "")

        try:
            bot = self._repo.get_bot(superseded["bot_slug"])
            model_id = bot["model"]
            sys_prompt = (
                f"{bot['role_prompt']}\n"
                "Revise the outbound draft strictly following the operator feedback below. "
                "Return ONLY the revised publishable message text without markdown fences or chatter."
            )
            outbound_rbac = bot["outbound_rbac"]
        except Exception:
            model_id = None
            sys_prompt = (
                "Revise the outbound draft strictly following the operator feedback. "
                "Return ONLY the revised message text."
            )
            outbound_rbac = "draft"

        revision_prompt = (
            f"Original Draft:\n{orig_text}\n\n"
            f"Operator Revision Request:\n{instruction_text.strip()}\n\n"
            "Return the complete revised draft text."
        )
        llm_res = await self._llm_router.complete(
            bot_slug=superseded["bot_slug"],
            prompt=revision_prompt,
            requested_model=model_id,
            system_prompt=sys_prompt,
            trigger_type="telegram_revision",
            correlation_id=superseded["correlation_id"],
            hop_count=1,
            outbound_rbac=outbound_rbac,
        )
        if llm_res.unconfigured_local or not llm_res.output_text.strip():
            revised_text = _apply_local_revision(orig_text, instruction_text)
        else:
            revised_text = llm_res.output_text.strip()

        rule_text = derive_style_rule_from_diff(
            orig_text,
            revised_text,
            instruction=instruction_text,
        )
        if rule_text:
            self._repo.add_style_rule(
                rule_text=rule_text,
                scope_slug=superseded["bot_slug"],
                example_diff={"before": orig_text, "after": revised_text},
            )

        await self._lock_telegram_card(
            superseded,
            status_line=f"Superseded by revised draft ({actor}) · Style rule saved",
        )

        new_payload = {**orig_payload, "text": revised_text}
        new_approval = await self.enqueue_human_approval(
            correlation_id=superseded["correlation_id"],
            bot_slug=superseded["bot_slug"],
            target_account_slug=superseded["target_account_slug"],
            action_type=superseded["action_type"],
            payload=new_payload,
            source_url=superseded.get("source_url"),
            source_excerpt=superseded.get("source_excerpt"),
            escalation_note=f"Revised from {superseded['id']}: {instruction_text.strip()[:140]}",
            hop_count=1,
        )

        await self._bus.publish(
            correlation_id=superseded["correlation_id"],
            source_slug=actor,
            target_slug=superseded["bot_slug"],
            event_type="approval.superseded",
            payload={
                "category": "reviews",
                "title": f"Superseded {superseded['id']} -> {new_approval['id']}",
                "badge": f"Telegram {telegram_account_slug}",
                "badge_tone": "sky",
                "summary": f"Saved style rule '{rule_text}' and dispatched revised Telegram card.",
                "meta": f"Replaces {superseded['id']}",
                "superseded_id": superseded["id"],
                "new_approval_id": new_approval["id"],
            },
            hop_count=1,
        )
        return {
            "superseded_id": superseded["id"],
            "new_approval": new_approval,
            "style_rule": rule_text,
        }

    def _find_tool_policy(self, bot: dict[str, Any], account_slug: str) -> dict[str, Any] | None:
        wanted = slugify(account_slug)
        for tool in bot.get("tools", []):
            if not isinstance(tool, dict):
                continue
            cand = slugify(str(tool.get("account") or tool.get("slug") or ""))
            if cand and (cand == wanted or str(tool.get("account") or "") == account_slug):
                return tool
        return None

    async def execute_or_queue_outbound(
        self,
        *,
        bot: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        account_slug: str,
        action_type: str,
        text: str,
        target: str | None = None,
        source_url: str | None = None,
        source_excerpt: str | None = None,
        extra_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Enforce deterministic Python connector RBAC (internal/read | draft | execute + caps)."""
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("Outbound message text cannot be empty.")

        tool_policy = self._find_tool_policy(bot, account_slug)
        bot_rbac = str(bot.get("outbound_rbac") or "draft").lower()
        tool_cap_mode = (
            str(tool_policy.get("capability") or tool_policy.get("rbac") or "").lower()
            if tool_policy
            else ""
        )

        if bot_rbac == "internal" or tool_cap_mode == "read":
            reason = (
                f"Bot '{bot['slug']}' is restricted to '{bot_rbac}' / tool '{tool_cap_mode or 'read'}' "
                f"and cannot perform outbound '{action_type}'."
            )
            await self._bus.publish(
                correlation_id=correlation_id,
                source_slug=bot["slug"],
                target_slug=account_slug,
                event_type="connector.blocked",
                payload={
                    "category": "alerts",
                    "title": f"Blocked Outbound {action_type} by {bot['name']}",
                    "badge": "RBAC Blocked",
                    "badge_tone": "red",
                    "summary": reason,
                    "meta": f"Policy: {bot_rbac}",
                },
                hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
            )
            raise ConnectorPermissionError(reason)

        payload_dict: dict[str, Any] = {
            **(extra_payload or {}),
            "text": clean_text,
        }
        if target and target.strip():
            payload_dict["target"] = target.strip()
        elif tool_policy and tool_policy.get("target"):
            payload_dict["target"] = str(tool_policy["target"]).strip()

        if bot_rbac == "draft" or tool_cap_mode == "draft":
            approval = await self.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug=account_slug,
                action_type=action_type,
                payload=payload_dict,
                source_url=source_url,
                source_excerpt=source_excerpt,
                escalation_note="Connector RBAC is set to 'draft'; queued deterministically for human review.",
                hop_count=hop_count,
            )
            return {"outcome": "queued_approval", "approval": approval}

        # Execute mode — check safety filter, allowlist, daily cap, and live connector availability
        safety_issue = check_outbound_safety(clean_text)
        downgrade_reason: str | None = None
        if safety_issue is not None:
            downgrade_reason = f"Safety leak filter triggered ({safety_issue}); routed for human approval."

        if downgrade_reason is None and tool_policy is not None:
            allowed_target = str(tool_policy.get("target") or "").strip()
            allowed_targets = [
                str(t).strip().lower()
                for t in (tool_policy.get("targets") or [])
                if str(t).strip()
            ]
            if allowed_target:
                allowed_targets.append(allowed_target.lower())
            resolved_dest = str(payload_dict.get("target") or "").strip().lower()
            if allowed_targets and resolved_dest and resolved_dest not in allowed_targets:
                downgrade_reason = (
                    f"Destination '{payload_dict.get('target')}' is outside allowed targets "
                    f"{', '.join(allowed_targets)}."
                )

        account = self._repo.find_integration_secrets(account_slug)
        if downgrade_reason is None and account is None:
            downgrade_reason = f"Connector account '{account_slug}' is not onboarded; queued for review."

        bot_cap = int(bot.get("daily_cap", 0))
        tool_max = (
            int(tool_policy["max_calls_per_day"])
            if tool_policy and tool_policy.get("max_calls_per_day") is not None
            else None
        )
        if bot_cap > 0 and tool_max is not None:
            effective_cap = min(bot_cap, tool_max)
        elif tool_max is not None:
            effective_cap = tool_max
        else:
            effective_cap = bot_cap

        count_target_slug = account["slug"] if account is not None else account_slug
        calls_today = self._repo.count_bot_outbound_executions_today(
            bot["slug"],
            count_target_slug,
        )
        if downgrade_reason is None and (effective_cap <= 0 or calls_today >= effective_cap):
            downgrade_reason = (
                f"Daily cap reached ({calls_today}/{effective_cap}); downgraded from execute to human approval."
            )

        if downgrade_reason is not None:
            approval = await self.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug=account["slug"] if account is not None else account_slug,
                action_type=action_type,
                payload=payload_dict,
                source_url=source_url,
                source_excerpt=source_excerpt,
                escalation_note=downgrade_reason,
                hop_count=hop_count,
            )
            return {
                "outcome": "downgraded_to_approval",
                "reason": downgrade_reason,
                "approval": approval,
            }

        assert account is not None
        try:
            dispatch_res = await self._dispatch_outbound(
                account,
                action_type=action_type,
                payload=payload_dict,
                final_text=clean_text,
            )
        except Exception as exc:
            err_reason = f"Direct connector execution failed ({exc}); downgraded for manual review."
            approval = await self.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug=account["slug"],
                action_type=action_type,
                payload=payload_dict,
                source_url=source_url,
                source_excerpt=source_excerpt,
                escalation_note=err_reason,
                hop_count=hop_count,
            )
            return {
                "outcome": "downgraded_to_approval",
                "reason": err_reason,
                "approval": approval,
            }

        dest_label = dispatch_res.get("target") or payload_dict.get("target") or account["slug"]
        await self._bus.publish(
            correlation_id=correlation_id,
            source_slug=bot["slug"],
            target_slug=account["slug"],
            event_type="connector.executed",
            payload={
                "category": "reviews",
                "title": f"Executed {action_type} -> {dest_label}",
                "badge": f"RBAC Execute · {calls_today + 1}/{effective_cap} today",
                "badge_tone": "emerald",
                "summary": clean_text[:240],
                "meta": f"Connector: {account['slug']}",
            },
            hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
        )
        return {
            "outcome": "executed",
            "calls_today": calls_today + 1,
            "daily_cap": effective_cap,
            "result": dispatch_res,
        }
