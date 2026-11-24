"""Deterministic Python connector RBAC gate & atomic Web/Telegram approval sync."""

from __future__ import annotations

import asyncio
import contextlib
import email.utils
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from argo_core.bus.valkey_bus import MAX_HOP_COUNT, EventBus
from argo_core.connectors.gateway import ConnectorGateway, build_default_connector_gateway
from argo_core.connectors.linkedin import LinkedInService
from argo_core.connectors.telegram_bot import TelegramBotService, build_inline_keyboard
from argo_core.db.repositories import (
    _READ_FORBIDDEN_SYSTEM_COLLECTIONS,
    ArgoRepository,
    NotFoundError,
    collection_slug,
    derive_style_rule_from_diff,
    make_id,
    slugify,
    utc_now,
)
from argo_core.llm.router import LLMRouter
from argo_core.security.ssrf import SafePublicHttpFetcher, validate_public_url
from argo_core.security.vault import redact_secrets
from argo_core.ssh.manager import (
    extract_suggested_trust_prefixes,
    format_ssh_terminal_summary,
)

logger = logging.getLogger(__name__)

APPROVAL_OK_PREFIX = "apr:ok:"
APPROVAL_NO_PREFIX = "apr:no:"
DEFAULT_TELEGRAM_APPROVAL_TIMEOUT_SECONDS = 8.0
DEFAULT_TELEGRAM_TIMEOUT_BACKOFF_SECONDS = 30.0

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
        connector_gateway: ConnectorGateway | None = None,
        webhook_transport: Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None = None,
        telegram_notify_timeout: float = DEFAULT_TELEGRAM_APPROVAL_TIMEOUT_SECONDS,
        telegram_timeout_backoff: float = DEFAULT_TELEGRAM_TIMEOUT_BACKOFF_SECONDS,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._llm_router = llm_router
        self._telegram = telegram_service
        self._linkedin = linkedin_service
        self._google = google_service
        self._webhook_transport = webhook_transport
        self._gateway = connector_gateway or build_default_connector_gateway(
            google_service=google_service,
            telegram_service=telegram_service,
            linkedin_service=linkedin_service,
            webhook_transport_getter=lambda: self._webhook_transport,
        )
        webhook_adapter = self._gateway.get("webhook")
        if webhook_adapter is not None:
            if getattr(webhook_adapter, "_webhook_transport_getter", None) is None:
                webhook_adapter._webhook_transport_getter = lambda: self._webhook_transport
            if getattr(webhook_adapter, "_url_validator", None) is None:
                webhook_adapter._url_validator = lambda url: validate_public_url(url)
        self._telegram_notify_timeout = float(telegram_notify_timeout)
        self._telegram_timeout_backoff = float(telegram_timeout_backoff)
        self._telegram_timeout_until: dict[str, float] = {}
        self._bot_scheduler: Any | None = None
        self._desktop_manager: Any | None = None
        self._sandbox_manager: Any | None = None
        self._ssh_manager: Any | None = None
        self._bot_runner: Any | None = None

    def attach_scheduler(self, scheduler: Any) -> None:
        """Bind BotScheduler so approved workspace changes sync cron jobs immediately."""
        self._bot_scheduler = scheduler

    def attach_desktop_manager(self, desktop_manager: Any) -> None:
        """Bind DesktopManager so approved fleet cleanup deletions destroy orphaned desktops."""
        self._desktop_manager = desktop_manager

    def attach_sandbox_manager(self, sandbox_manager: Any) -> None:
        """Bind SandboxManager so approved fleet cleanup & runtime changes manage sandboxes."""
        self._sandbox_manager = sandbox_manager

    def attach_ssh_manager(self, ssh_manager: Any) -> None:
        """Bind SSHManager so approved/edited SSH commands and prompts execute on live PTYs."""
        self._ssh_manager = ssh_manager

    def attach_bot_runner(self, bot_runner: Any) -> None:
        """Bind UniversalBotRunner so executed SSH approvals stream output & analysis into chat."""
        self._bot_runner = bot_runner

    def _post_ssh_chat_notice(
        self,
        *,
        bot_slug: str,
        room_slug: str | None,
        text: str,
        metadata: dict[str, Any],
    ) -> None:
        """Append an SSH approval outcome notice to the originating 1:1 bot or Room thread."""
        clean_room = str(room_slug or "").strip()
        if clean_room:
            try:
                bot_cfg = self._repo.get_bot(bot_slug)
                bot_name = str(bot_cfg.get("name") or bot_slug)
                self._repo.append_room_message(
                    clean_room,
                    sender_type="bot",
                    sender_slug=bot_slug,
                    sender_name=bot_name,
                    text=text,
                    metadata={"room_slug": clean_room, **metadata},
                )
                return
            except Exception:
                logger.debug("Unable to append SSH notice to room %s", clean_room, exc_info=True)
        try:
            self._repo.append_bot_message(
                bot_slug,
                "bot",
                text,
                metadata=metadata,
            )
        except Exception:
            logger.debug("Unable to append SSH notice to bot %s", bot_slug, exc_info=True)

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
        target_account = self._repo.find_integration_secrets(target_account_slug)
        if target_account is not None:
            draft_meta = await self._gateway.prepare_draft(
                target_account,
                action_type=action_type,
                payload=payload_to_store,
            )
            if draft_meta:
                payload_to_store.update(draft_meta)

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
            tg_slug = str(tg_account["slug"])
            now_mono = time.monotonic()
            backoff_until = self._telegram_timeout_until.get(tg_slug, 0.0)
            if now_mono < backoff_until:
                logger.debug(
                    "Skipping Telegram approval card for %s during timeout backoff (%.1fs remaining)",
                    created["id"],
                    backoff_until - now_mono,
                )
            else:
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
                    publish_coro = self._telegram.publish_message(
                        tg_slug,
                        chat_id=op_chat_id,
                        text=card_text,
                        reply_markup=markup,
                    )
                    if self._telegram_notify_timeout > 0:
                        sent = await asyncio.wait_for(
                            publish_coro,
                            timeout=self._telegram_notify_timeout,
                        )
                    else:
                        sent = await publish_coro
                    self._telegram_timeout_until.pop(tg_slug, None)
                    created = self._repo.set_approval_telegram_card(
                        created["id"],
                        chat_id=str(sent.get("chat_id") or op_chat_id),
                        message_id=int(sent["message_id"]),
                    )
                except asyncio.TimeoutError:
                    if self._telegram_timeout_backoff > 0:
                        self._telegram_timeout_until[tg_slug] = (
                            time.monotonic() + self._telegram_timeout_backoff
                        )
                    logger.warning(
                        "Timed out sending Telegram approval card for %s after %.1fs; skipping Telegram backoff for %.0fs",
                        created["id"],
                        self._telegram_notify_timeout,
                        self._telegram_timeout_backoff,
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
        """Deliver a human approval notification through ConnectorGateway."""
        approval = self._repo.get_approval(approval_id)
        account = self._repo.find_integration_secrets(account_slug)
        if account is None:
            raise RuntimeError(f"Notification integration '{account_slug}' is not onboarded.")
        msg_text = (text or "").strip() or self._format_permission_card_text(approval)
        res = await self._gateway.deliver_notification(
            account,
            approval=approval,
            text=msg_text,
            target=target,
        )
        tg_card = res.pop("telegram_card", None)
        if isinstance(tg_card, dict) and tg_card.get("message_id") is not None:
            self._repo.set_approval_telegram_card(
                approval["id"],
                chat_id=str(tg_card.get("chat_id") or ""),
                message_id=int(tg_card["message_id"]),
            )
        return res

    async def _dispatch_outbound(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        """Deliver an approved or execute-permitted payload via ConnectorGateway."""
        return await self._gateway.dispatch(
            account,
            action_type=action_type,
            payload=payload,
            final_text=final_text,
        )

    def _maybe_enqueue_batch_followup(
        self,
        resolved: dict[str, Any],
        *,
        current_exec_summary: dict[str, Any] | None = None,
    ) -> bool:
        """Queue one bot follow-up after all siblings sharing batch_id (if any) have settled."""
        eff = resolved.get("edited_payload") or resolved.get("payload") or {}
        batch_id = str(eff.get("batch_id") or "").strip()
        orig_req = str(eff.get("original_request") or "").strip()
        orig_room = str(eff.get("room_slug") or "").strip() or None

        if batch_id:
            siblings = self._repo.list_approvals_by_correlation(
                resolved["correlation_id"],
                bot_slug=resolved["bot_slug"],
                batch_id=batch_id,
            )
            if any(str(s.get("status") or "") == "pending" for s in siblings):
                return False
            exec_results: list[dict[str, Any]] = []
            rejected_items: list[dict[str, Any]] = []
            for sib in siblings:
                s_status = str(sib.get("status") or "")
                s_payload = sib.get("edited_payload") or sib.get("payload") or {}
                s_base_payload = sib.get("payload") or {}
                if s_status == "executed":
                    ex_res = s_base_payload.get("execution_result") or s_payload.get("execution_result")
                    if isinstance(ex_res, dict):
                        exec_results.append(dict(ex_res))
                    elif current_exec_summary is not None and sib.get("id") == resolved.get("id"):
                        exec_results.append(dict(current_exec_summary))
                elif s_status == "rejected":
                    rejected_items.append(
                        {
                            "type": sib.get("action_type") or "ssh_exec",
                            "status": "rejected",
                            "approval_id": sib.get("id"),
                            "vault_slug": s_payload.get("vault_slug") or sib.get("target_account_slug"),
                            "host": s_payload.get("host"),
                            "command": s_payload.get("command") or s_payload.get("text") or "",
                            "detail": "Rejected by operator.",
                        }
                    )
            if not exec_results:
                return False
            if self._bot_runner is not None:
                self._bot_runner.enqueue_ssh_approval_followup(
                    bot_slug=resolved["bot_slug"],
                    correlation_id=resolved["correlation_id"],
                    approval_id=resolved["id"],
                    execution_results=exec_results,
                    rejected_items=rejected_items,
                    original_request=orig_req,
                    room_slug=orig_room,
                )
            else:
                combined_txt = "\n\n".join(format_ssh_terminal_summary(ex) for ex in exec_results)
                self._post_ssh_chat_notice(
                    bot_slug=resolved["bot_slug"],
                    room_slug=orig_room,
                    text=combined_txt,
                    metadata={
                        "correlation_id": resolved["correlation_id"],
                        "approval_id": resolved["id"],
                        "batch_id": batch_id,
                    },
                )
            return True

        if current_exec_summary is None:
            return False
        if self._bot_runner is not None:
            self._bot_runner.enqueue_ssh_approval_followup(
                bot_slug=resolved["bot_slug"],
                correlation_id=resolved["correlation_id"],
                approval_id=resolved["id"],
                execution_result=current_exec_summary,
                original_request=orig_req,
                room_slug=orig_room,
            )
        else:
            self._post_ssh_chat_notice(
                bot_slug=resolved["bot_slug"],
                room_slug=orig_room,
                text=format_ssh_terminal_summary(current_exec_summary),
                metadata={
                    "correlation_id": resolved["correlation_id"],
                    "approval_id": resolved["id"],
                },
            )
        return True

    async def resolve_approval(
        self,
        approval_id: str,
        *,
        action: Literal["approve", "reject", "edit_approve"],
        actor: str,
        edited_text: str | None = None,
        style_rule: str | None = None,
        trust_command: bool = False,
        trust_prefixes: list[str] | None = None,
        defer_followup: bool = False,
    ) -> dict[str, Any]:
        """Atomically approve/edit/reject an approval, execute live connectors, and lock Telegram."""
        resolved = self._repo.resolve_approval(
            approval_id=approval_id,
            action=action,
            actor=actor,
            edited_text=edited_text,
            style_rule=style_rule,
        )
        added_trust_prefixes: list[str] = []

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
                                clean_deleted = str(deleted_bot.get("slug") or b_slug)
                                dm = getattr(self, "_desktop_manager", None)
                                if dm is not None:
                                    with contextlib.suppress(Exception):
                                        await dm.destroy_desktop(clean_deleted)
                                sm = getattr(self, "_sandbox_manager", None)
                                if sm is not None:
                                    with contextlib.suppress(Exception):
                                        await sm.destroy_sandbox(clean_deleted)
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
                            "collections",
                        }
                        clean_patch = {
                            k: v for k, v in raw_updates.items() if k in allowed_keys and v is not None
                        }
                        if isinstance(raw_updates.get("linked_accounts"), list):
                            target_bot_for_links = self._repo.get_bot(target_bot_slug)
                            cur_links = [
                                slugify(str(a))
                                for a in (target_bot_for_links.get("linked_accounts") or [])
                                if str(a).strip()
                            ]
                            valid_accounts = {
                                slugify(str(acc.get("slug") or ""))
                                for acc in self._repo.list_integrations()
                                if str(acc.get("slug") or "").strip()
                            }
                            req_links = [
                                slugify(str(a))
                                for a in raw_updates["linked_accounts"]
                                if str(a).strip() and slugify(str(a)) in valid_accounts
                            ]
                            clean_patch["linked_accounts"] = list(
                                dict.fromkeys([*cur_links, *req_links])
                            )
                        req_read_cols: list[str] = []
                        if isinstance(raw_updates.get("read_collections"), list):
                            req_read_cols.extend(str(c) for c in raw_updates["read_collections"])
                        if isinstance(raw_updates.get("collections"), dict):
                            req_read_cols.extend(
                                str(c) for c in (raw_updates["collections"].get("read") or [])
                            )
                        if req_read_cols:
                            target_bot = self._repo.get_bot(target_bot_slug)
                            existing_cols = target_bot.get("collections") or {}
                            cur_read = [
                                collection_slug(str(c))
                                for c in (existing_cols.get("read") or [])
                                if str(c).strip()
                            ]
                            cur_write = [
                                collection_slug(str(c))
                                for c in (existing_cols.get("write") or [])
                                if str(c).strip()
                            ]
                            extra_read = [
                                clean_c
                                for raw_c in req_read_cols
                                if str(raw_c).strip()
                                for clean_c in (collection_slug(str(raw_c)),)
                                if clean_c not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
                            ]
                            merged_read = list(dict.fromkeys([*cur_read, *extra_read]))
                            clean_patch["collections"] = {
                                "read": merged_read,
                                "write": cur_write,
                            }
                        if clean_patch:
                            if "runtime" in clean_patch:
                                prev_target = self._repo.get_bot(target_bot_slug)
                                if clean_patch["runtime"] != prev_target.get("runtime"):
                                    if prev_target.get("runtime") == "sandbox":
                                        sm = getattr(self, "_sandbox_manager", None)
                                        if sm is not None:
                                            with contextlib.suppress(Exception):
                                                if prev_target.get("sandbox_state") == "running":
                                                    await sm.stop_sandbox(
                                                        target_bot_slug, reason="runtime_changed"
                                                    )
                                                else:
                                                    await sm._driver.ensure_stopped(
                                                        f"argo-sandbox-{target_bot_slug}"
                                                    )
                                    elif prev_target.get("runtime") == "desktop":
                                        dm = getattr(self, "_desktop_manager", None)
                                        if dm is not None:
                                            with contextlib.suppress(Exception):
                                                if prev_target.get("desktop_state") == "running":
                                                    await dm.hibernate_desktop(
                                                        target_bot_slug, reason="runtime_changed"
                                                    )
                                                else:
                                                    await dm._driver.ensure_stopped(
                                                        f"argo-desktop-{target_bot_slug}"
                                                    )
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
            elif resolved["action_type"] in {"ssh_exec", "ssh_input"}:
                if self._ssh_manager is None:
                    resolved = self._repo.mark_approval_dispatch_result(
                        approval_id,
                        executed=False,
                        error_message="SSHManager is not attached.",
                    )
                    status_line = "Approved (SSH unavailable)"
                else:
                    try:
                        if resolved["action_type"] == "ssh_exec":
                            cmd_to_run = final_text or str(effective_payload.get("command") or "").strip()
                            ssh_res = await self._ssh_manager.exec_command(
                                bot_slug=resolved["bot_slug"],
                                vault_slug=str(
                                    effective_payload.get("vault_slug")
                                    or resolved["target_account_slug"]
                                ),
                                command=cmd_to_run,
                                requested_host=effective_payload.get("host"),
                                requested_port=effective_payload.get("port"),
                                correlation_id=resolved["correlation_id"],
                                rbac_mode="execute",
                                trusted_operator_texts=[
                                    str(effective_payload.get("host") or ""),
                                    str(effective_payload.get("trusted_host") or ""),
                                ],
                                session_id=effective_payload.get("session_id"),
                                timeout_seconds=45.0,
                                max_duration_seconds=300.0,
                                approved_by_human=True,
                            )
                        else:
                            sid = str(effective_payload.get("session_id") or "").strip()
                            exp_seq_raw = effective_payload.get("expected_completed_seq")
                            exp_seq = int(exp_seq_raw) if exp_seq_raw is not None else None
                            if effective_payload.get("sudo_inject") and not resolved.get("edited_payload"):
                                ssh_res = await self._ssh_manager.send_input(
                                    session_id=sid,
                                    bot_slug=resolved["bot_slug"],
                                    rbac_mode="execute",
                                    timeout_seconds=45.0,
                                    max_duration_seconds=300.0,
                                    approved_by_human=True,
                                    inject_vault_sudo=True,
                                    expected_completed_seq=exp_seq,
                                )
                            else:
                                ssh_res = await self._ssh_manager.send_input(
                                    session_id=sid,
                                    bot_slug=resolved["bot_slug"],
                                    text=final_text,
                                    rbac_mode="execute",
                                    timeout_seconds=45.0,
                                    max_duration_seconds=300.0,
                                    approved_by_human=True,
                                    expected_completed_seq=exp_seq,
                                )
                        if ssh_res.get("status") in {
                            "blocked_catastrophic",
                            "blocked_rbac",
                            "operator_active",
                            "paused",
                            "closed",
                            "error",
                        }:
                            raise RuntimeError(str(ssh_res.get("detail") or ssh_res.get("status")))
                        vault_ref = str(
                            effective_payload.get("vault_slug")
                            or resolved["target_account_slug"]
                        )
                        if trust_command and resolved["action_type"] == "ssh_exec":
                            raw_pref = (
                                list(trust_prefixes)
                                if trust_prefixes is not None
                                else extract_suggested_trust_prefixes(cmd_to_run)
                            )
                            if raw_pref:
                                with contextlib.suppress(NotFoundError):
                                    _, added_trust_prefixes = self._repo.add_vault_trusted_command_prefixes(
                                        vault_ref,
                                        raw_pref,
                                    )
                        scrub_vals = self._repo.collect_all_vault_secret_values()
                        raw_screen = str(ssh_res.get("screen_text") or "")
                        if len(raw_screen) > 12000:
                            raw_screen = raw_screen[-12000:]
                        scrubbed_screen = redact_secrets(raw_screen, scrub_vals)
                        executed_cmd = (
                            cmd_to_run
                            if resolved["action_type"] == "ssh_exec"
                            else str(
                                effective_payload.get("command")
                                or (
                                    "sudo password (RAM)"
                                    if effective_payload.get("sudo_inject")
                                    and not resolved.get("edited_payload")
                                    else final_text
                                )
                            )
                        )
                        exec_summary: dict[str, Any] = {
                            "action_type": resolved["action_type"],
                            "session_id": ssh_res.get("session_id"),
                            "vault_slug": vault_ref,
                            "host": ssh_res.get("host") or effective_payload.get("host"),
                            "port": ssh_res.get("port") or effective_payload.get("port"),
                            "command": redact_secrets(executed_cmd, scrub_vals),
                            "status": str(ssh_res.get("status") or "completed"),
                            "exit_code": ssh_res.get("exit_code"),
                            "prompt_line": redact_secrets(
                                str(ssh_res.get("prompt_line") or ""),
                                scrub_vals,
                            ),
                            "screen_text": scrubbed_screen,
                        }
                        if added_trust_prefixes:
                            exec_summary["trusted_prefixes_added"] = list(added_trust_prefixes)
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=True,
                            execution_result=exec_summary,
                        )
                        if added_trust_prefixes:
                            resolved["trusted_prefixes_added"] = list(added_trust_prefixes)
                        orig_req = str(effective_payload.get("original_request") or "").strip()
                        orig_room = str(effective_payload.get("room_slug") or "").strip() or None
                        batch_id = str(effective_payload.get("batch_id") or "").strip() or None
                        is_sudo_prompt = bool(ssh_res.get("sudo_prompt"))
                        bot_cfg = self._repo.get_bot(resolved["bot_slug"]) or {}
                        bot_rbac = str(bot_cfg.get("outbound_rbac") or "draft").lower()
                        needs_followup_approval = ssh_res.get("status") == "awaiting_sudo_approval" or (
                            ssh_res.get("status") == "awaiting_input" and bot_rbac == "draft"
                        )
                        if needs_followup_approval:
                            followup_payload: dict[str, Any] = {
                                "title": f"SSH prompt waiting on {ssh_res.get('host')}",
                                "text": (
                                    "Inject saved Vault sudo password in RAM"
                                    if is_sudo_prompt
                                    else "Y"
                                ),
                                "command": exec_summary["command"],
                                "original_request": orig_req,
                                "room_slug": orig_room,
                                "session_id": ssh_res.get("session_id"),
                                "vault_slug": vault_ref,
                                "host": ssh_res.get("host"),
                                "port": ssh_res.get("port"),
                                "prompt_line": ssh_res.get("prompt_line") or "",
                                "screen_excerpt": ssh_res.get("screen_text") or "",
                                "sudo_inject": is_sudo_prompt,
                                "completed_seq": ssh_res.get("completed_seq"),
                                "expected_completed_seq": ssh_res.get("completed_seq"),
                                "takeover_bot_slug": resolved["bot_slug"],
                            }
                            if batch_id:
                                followup_payload["batch_id"] = batch_id
                            followup_apr = await self.enqueue_human_approval(
                                correlation_id=resolved["correlation_id"],
                                bot_slug=resolved["bot_slug"],
                                target_account_slug=vault_ref,
                                action_type="ssh_input",
                                payload=followup_payload,
                                escalation_note="Terminal paused waiting for confirmation before continuing.",
                            )
                            paused_msg = format_ssh_terminal_summary(
                                exec_summary,
                                paused_note=(
                                    f"Paused waiting for confirmation (`{exec_summary['prompt_line'] or 'interactive prompt'}`). "
                                    "Approve the next step below or in **Approvals**, or open **Details -> Computer** to take over live."
                                ),
                            )
                            self._post_ssh_chat_notice(
                                bot_slug=resolved["bot_slug"],
                                room_slug=orig_room,
                                text=paused_msg,
                                metadata={
                                    "correlation_id": resolved["correlation_id"],
                                    "approval_id": approval_id,
                                    "actions": [
                                        {
                                            "type": "ssh_input",
                                            "status": "queued_approval",
                                            "approval_id": followup_apr["id"],
                                            "session_id": exec_summary.get("session_id"),
                                        }
                                    ],
                                },
                            )
                        elif not defer_followup:
                            self._maybe_enqueue_batch_followup(
                                resolved,
                                current_exec_summary=exec_summary,
                            )
                        status_line = f"Executed SSH action ({ssh_res.get('status')}) by {actor}"
                    except Exception as exc:
                        scrub_vals = self._repo.collect_all_vault_secret_values()
                        err_msg = redact_secrets(str(exc), scrub_vals)[:500]
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=False,
                            error_message=err_msg,
                        )
                        orig_room = str(effective_payload.get("room_slug") or "").strip() or None
                        host_lbl = str(effective_payload.get("host") or resolved["target_account_slug"])
                        self._post_ssh_chat_notice(
                            bot_slug=resolved["bot_slug"],
                            room_slug=orig_room,
                            text=f"SSH action on `{host_lbl}` could not complete: {err_msg}",
                            metadata={
                                "correlation_id": resolved["correlation_id"],
                                "approval_id": approval_id,
                            },
                        )
                        status_line = f"Approved (SSH error: {err_msg[:120]})"
            else:
                account = self._repo.find_integration_secrets(resolved["target_account_slug"])

                if account is None:
                    err_msg = (
                        f"Target connector '{resolved['target_account_slug']}' not found or was deleted."
                    )
                    resolved = self._repo.mark_approval_dispatch_result(
                        approval_id,
                        executed=False,
                        error_message=err_msg,
                        revert_to_pending=True,
                    )
                    status_line = f"Delivery blocked (kept pending): {err_msg}"
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
                        scrub_vals = self._repo.collect_all_sensitive_secrets()
                        safe_err = redact_secrets(str(exc), scrub_vals)[:500]
                        resolved = self._repo.mark_approval_dispatch_result(
                            approval_id,
                            executed=False,
                            error_message=safe_err,
                            revert_to_pending=True,
                        )
                        status_line = f"Delivery failed (kept pending for retry): {safe_err[:120]}"
        elif resolved["status"] == "rejected":
            if resolved["action_type"] in {"ssh_exec", "ssh_input"}:
                if resolved["action_type"] == "ssh_input" and self._ssh_manager is not None:
                    rej_payload = resolved.get("payload") or {}
                    sid = str(rej_payload.get("session_id") or "").strip()
                    if sid:
                        self._ssh_manager.abort_prompt_sync_or_async(sid)
                if not defer_followup:
                    self._maybe_enqueue_batch_followup(resolved, current_exec_summary=None)
            elif resolved["target_account_slug"] != "argo_workspace":
                rej_account = self._repo.find_integration_secrets(resolved["target_account_slug"])
                if rej_account is not None:
                    rej_payload = resolved.get("edited_payload") or resolved.get("payload") or {}
                    await self._gateway.cleanup_draft(
                        rej_account,
                        action_type=resolved["action_type"],
                        payload=rej_payload,
                    )

        if resolved["status"] != "pending":
            await self._lock_telegram_card(resolved, status_line=status_line)

        badge_map = {
            "executed": ("Executed", "emerald"),
            "approved": ("Approved", "emerald"),
            "rejected": ("Rejected", "slate"),
            "pending": ("Delivery Failed · Retry", "amber"),
        }
        badge_text, badge_tone = badge_map.get(resolved["status"], (resolved["status"], "slate"))
        event_type_out = "approval.dispatch_failed" if resolved["status"] == "pending" else "approval.resolved"
        await self._bus.publish(
            correlation_id=resolved["correlation_id"],
            source_slug=actor,
            target_slug=resolved["bot_slug"],
            event_type=event_type_out,
            payload={
                "category": "reviews",
                "title": f"Approval {resolved['id']} -> {resolved['status']}",
                "badge": badge_text,
                "badge_tone": badge_tone,
                "summary": f"{resolved['action_type']} to {resolved['target_account_slug']} ({status_line})",
                "meta": resolved.get("error_message") or f"Resolved by {actor}",
                "approval_id": resolved["id"],
                "approval_status": resolved["status"],
                **({"error_message": resolved.get("error_message")} if resolved.get("error_message") else {}),
            },
            hop_count=1,
        )
        return resolved

    async def resolve_approval_batch(
        self,
        *,
        approval_ids: list[str],
        action: Literal["approve", "reject"],
        actor: str,
        trust_command: bool = False,
    ) -> dict[str, Any]:
        """Resolve multiple approvals concurrently across distinct SSH targets and enqueue one follow-up per batch."""
        dedup_ids: list[str] = []
        seen_ids: set[str] = set()
        for raw_id in approval_ids:
            clean_id = str(raw_id or "").strip()
            if clean_id and clean_id not in seen_ids:
                seen_ids.add(clean_id)
                dedup_ids.append(clean_id)

        sem = asyncio.Semaphore(5)

        async def _run_one(apr_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
            async with sem:
                try:
                    res = await self.resolve_approval(
                        approval_id=apr_id,
                        action=action,
                        actor=actor,
                        trust_command=trust_command,
                        defer_followup=True,
                    )
                    return res, None
                except (AlreadyResolvedError, NotFoundError) as exc:
                    return None, {"approval_id": apr_id, "detail": str(exc)}
                except Exception as exc:
                    return None, {"approval_id": apr_id, "detail": str(exc)[:300]}

        pair_results = await asyncio.gather(*[_run_one(aid) for aid in dedup_ids])
        resolved_items: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        added_prefixes: list[str] = []
        seen_prefixes: set[str] = set()
        for res, err in pair_results:
            if res is not None:
                resolved_items.append(res)
                for pref in res.get("trusted_prefixes_added") or []:
                    p_str = str(pref or "").strip()
                    if p_str and p_str.lower() not in seen_prefixes:
                        seen_prefixes.add(p_str.lower())
                        added_prefixes.append(p_str)
            if err is not None:
                errors.append(err)

        batch_representatives: dict[tuple[str, str, str], dict[str, Any]] = {}
        single_no_batch: list[dict[str, Any]] = []
        for res in resolved_items:
            if res.get("action_type") not in {"ssh_exec", "ssh_input"}:
                continue
            eff = res.get("edited_payload") or res.get("payload") or {}
            base_payload = res.get("payload") or {}
            ex_res = base_payload.get("execution_result") or eff.get("execution_result")
            if isinstance(ex_res, dict) and ex_res.get("status") in {
                "awaiting_input",
                "awaiting_sudo_approval",
            }:
                continue
            batch_id = str(eff.get("batch_id") or base_payload.get("batch_id") or "").strip()
            if batch_id:
                key = (str(res["bot_slug"]), str(res["correlation_id"]), batch_id)
                batch_representatives[key] = res
            elif res.get("status") == "executed" and isinstance(ex_res, dict):
                single_no_batch.append(res)

        for rep in batch_representatives.values():
            eff = rep.get("edited_payload") or rep.get("payload") or {}
            base_payload = rep.get("payload") or {}
            ex_res = base_payload.get("execution_result") or eff.get("execution_result")
            self._maybe_enqueue_batch_followup(
                rep,
                current_exec_summary=ex_res if isinstance(ex_res, dict) else None,
            )
        for single in single_no_batch:
            eff = single.get("edited_payload") or single.get("payload") or {}
            base_payload = single.get("payload") or {}
            ex_res = base_payload.get("execution_result") or eff.get("execution_result")
            if isinstance(ex_res, dict):
                self._maybe_enqueue_batch_followup(single, current_exec_summary=ex_res)

        return {
            "items": resolved_items,
            "resolved_count": len(resolved_items),
            "errors": errors,
            "trusted_prefixes_added": added_prefixes,
        }

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

        orig_payload = dict(old.get("edited_payload") or old.get("payload") or {})
        orig_text = str(orig_payload.get("text") or "")

        try:
            bot = self._repo.get_bot(old["bot_slug"])
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
        try:
            llm_res = await self._llm_router.complete(
                bot_slug=old["bot_slug"],
                prompt=revision_prompt,
                requested_model=model_id,
                system_prompt=sys_prompt,
                trigger_type="telegram_revision",
                correlation_id=old["correlation_id"],
                hop_count=1,
                outbound_rbac=outbound_rbac,
            )
            if llm_res.unconfigured_local or not llm_res.output_text.strip():
                revised_text = _apply_local_revision(orig_text, instruction_text)
            else:
                revised_text = llm_res.output_text.strip()
        except Exception as exc:
            logger.warning(
                "Telegram revision LLM call failed for approval %s (%s); keeping original pending approval untouched.",
                old["id"],
                exc,
            )
            return None

        superseded = self._repo.supersede_approval(old["id"], actor=actor)
        old_account = self._repo.find_integration_secrets(superseded["target_account_slug"])
        if old_account is not None:
            await self._gateway.cleanup_draft(
                old_account,
                action_type=superseded["action_type"],
                payload=orig_payload,
            )

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
        new_payload.pop("gmail_draft_id", None)
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

        account = self._repo.find_integration_secrets(account_slug)

        def _parse_email_addrs(raw: Any) -> list[str]:
            if raw is None:
                return []
            items = [str(x) for x in raw] if isinstance(raw, (list, tuple, set)) else [str(raw)]
            return [addr.strip().lower() for _, addr in email.utils.getaddresses(items) if addr and addr.strip()]

        def _has_nonempty(raw: Any) -> bool:
            if isinstance(raw, (list, tuple, set)):
                return any(str(x).strip() for x in raw)
            return bool(str(raw or "").strip())

        if downgrade_reason is None and tool_policy is not None:
            allowed_target = str(tool_policy.get("target") or "").strip()
            allowed_targets = [
                str(t).strip().lower()
                for t in (tool_policy.get("targets") or [])
                if str(t).strip()
            ]
            if allowed_target:
                allowed_targets.append(allowed_target.lower())

            if allowed_targets:
                is_email_action = action_type in {"send_email", "reply_email", "gmail_draft"} or any(
                    _has_nonempty(payload_dict.get(f)) for f in ("to", "cc", "bcc")
                )
                if is_email_action:
                    payload_dict = dict(payload_dict)
                    to_addrs = _parse_email_addrs(payload_dict.get("to"))
                    target_addrs = _parse_email_addrs(payload_dict.get("target"))
                    cc_addrs = _parse_email_addrs(payload_dict.get("cc"))
                    bcc_addrs = _parse_email_addrs(payload_dict.get("bcc"))
                    unparseable = (
                        (_has_nonempty(payload_dict.get("to")) and not to_addrs)
                        or (_has_nonempty(payload_dict.get("target")) and not target_addrs)
                        or (_has_nonempty(payload_dict.get("cc")) and not cc_addrs)
                        or (_has_nonempty(payload_dict.get("bcc")) and not bcc_addrs)
                    )
                    effective_dests = [*to_addrs, *target_addrs, *cc_addrs, *bcc_addrs]
                    disallowed = [d for d in effective_dests if d not in allowed_targets]
                    if unparseable or not effective_dests:
                        downgrade_reason = (
                            "Email recipient could not be validated against allowed targets "
                            f"{', '.join(allowed_targets)}."
                        )
                    elif disallowed:
                        downgrade_reason = (
                            f"Destination '{', '.join(disallowed)}' is outside allowed targets "
                            f"{', '.join(allowed_targets)}."
                        )
                    else:
                        if to_addrs:
                            payload_dict["to"] = ", ".join(to_addrs)
                        if target_addrs:
                            payload_dict["target"] = ", ".join(target_addrs)
                        if cc_addrs:
                            payload_dict["cc"] = ", ".join(cc_addrs)
                else:
                    explicit_dest = str(payload_dict.get("target") or "").strip().lower()
                    if explicit_dest:
                        effective_dests = [explicit_dest]
                    elif account is not None:
                        acct_secrets = account.get("secrets") or {}
                        default_dest = str(
                            acct_secrets.get("target_url")
                            or acct_secrets.get("webhook_url")
                            or acct_secrets.get("outbound_url")
                            or acct_secrets.get("chat_id")
                            or acct_secrets.get("channel_id")
                            or account.get("account_identifier")
                            or ""
                        ).strip().lower()
                        effective_dests = [default_dest] if default_dest else []
                    else:
                        effective_dests = []
                    disallowed = [d for d in effective_dests if d not in allowed_targets]
                    if not effective_dests or disallowed:
                        shown = ", ".join(disallowed) if disallowed else str(payload_dict.get("target") or "(empty)")
                        downgrade_reason = (
                            f"Destination '{shown}' is outside allowed targets "
                            f"{', '.join(allowed_targets)}."
                        )

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
