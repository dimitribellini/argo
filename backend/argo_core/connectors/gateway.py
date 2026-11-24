"""Integration-agnostic Connector Gateway & Adapter Registry for Argo's router/brain."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from argo_core.db.repositories import utc_now
from argo_core.security.ssrf import SafePublicHttpFetcher, validate_public_url
from argo_core.tool_schema import ToolSpec

if TYPE_CHECKING:
    from argo_core.connectors.mcp_client import MCPConnectorService

logger = logging.getLogger(__name__)


@dataclass
class ConnectorPollContext:
    """Provider-agnostic context passed into ConnectorAdapter.poll()."""

    bot: dict[str, Any]
    bot_slug: str
    routine: dict[str, Any] | None = None
    query: str = ""
    existing_external_keys: set[str] = field(default_factory=set)
    seen_cursor_keys: set[str] = field(default_factory=set)
    is_seen: Callable[..., bool] = field(default=lambda _k, **_kw: False)
    get_existing_doc: Callable[[str], dict[str, Any] | None] = field(default=lambda _k: None)
    mark_seen: Callable[[list[str]], None] = field(default=lambda _keys: None)


@dataclass
class ConnectorPollResult:
    """Provider-agnostic result returned from ConnectorAdapter.poll()."""

    polled: bool = False
    entries: list[dict[str, Any]] = field(default_factory=list)
    total_fetched: int = 0
    dedup_skipped: int = 0


@dataclass
class ConnectorToolContext:
    """Provider-agnostic runtime context passed into ConnectorAdapter.execute_tool()."""

    bot: dict[str, Any]
    account: dict[str, Any]
    correlation_id: str
    hop_count: int
    data_write_cols: list[str] = field(default_factory=list)
    upsert_doc: Callable[..., Any] = field(default=lambda **_kw: None)
    mark_seen: Callable[[list[str]], None] = field(default=lambda _keys: None)
    scrub_text: Callable[[str], str] = field(default=lambda text: text)
    execute_or_queue_outbound: Callable[..., Awaitable[dict[str, Any]]] | None = None
    is_internal_bot: bool = False
    trigger_type: str = "manual"


class ConnectorAdapter:
    """Base adapter contract allowing arbitrary connectors to plug into Argo's core gateway."""

    provider: str = ""
    display_label: str = ""
    capability_keywords: tuple[str, ...] = ()
    tool_names: tuple[str, ...] = ()
    action_types: tuple[str, ...] = ()

    def normalize_action_payload(
        self,
        action_type: str,
        action: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Extract connector-specific payload metadata and target destination."""
        del action_type
        payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        extra_payload: dict[str, Any] | None = (
            dict(action["extra_payload"])
            if isinstance(action.get("extra_payload"), dict)
            else None
        )
        target_dest = action.get("target") or payload_obj.get("target")
        clean_target = (
            str(target_dest).strip()
            if target_dest is not None and str(target_dest).strip()
            else None
        )
        return extra_payload, clean_target

    def supports_poll(
        self,
        account: dict[str, Any],
        bot: dict[str, Any],
        routine: dict[str, Any] | None = None,
    ) -> bool:
        """Return True when this adapter can poll the given account for this bot/routine."""
        del account, bot, routine
        return False

    async def poll(
        self,
        account: dict[str, Any],
        *,
        ctx: ConnectorPollContext,
    ) -> ConnectorPollResult:
        """Fetch unseen incremental records for scheduled monitoring routines."""
        del account, ctx
        return ConnectorPollResult()

    async def get_tool_specs(
        self,
        account: dict[str, Any],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        """Return ToolSpecs owned and executed dynamically by this connector adapter."""
        from argo_core.runner.tool_registry import get_tool_spec

        del bot
        specs: list[ToolSpec] = []
        acc_slug = str(account.get("slug") or "")
        for tname in dict.fromkeys((*self.tool_names, *self.action_types)):
            base = get_tool_spec(tname)
            if base is not None:
                specs.append(base)
        del acc_slug
        return specs

    def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
        """Return True if this adapter handles executing tool_name via execute_tool()."""
        del account
        clean = str(tool_name or "").strip()
        return clean in (set(self.tool_names) - set(self.action_types))

    async def execute_tool(
        self,
        *,
        tool_name: str,
        action: dict[str, Any],
        ctx: ConnectorToolContext,
    ) -> dict[str, Any] | None:
        """Execute an adapter-owned read or dynamic tool call, returning result dict or None."""
        del tool_name, action, ctx
        return None

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        """Verify connector credentials and update health status."""
        raise NotImplementedError(f"Adapter for '{self.provider}' does not implement probe().")

    async def prepare_draft(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Optional hook creating an external preview draft before human approval."""
        return {}

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        """Execute an approved or auto-send outbound action on the external connector."""
        return {
            "provider": self.provider or str(account.get("provider") or "custom"),
            "account_slug": account["slug"],
            "action_type": action_type,
            "target": payload.get("target") or account.get("account_identifier") or account["slug"],
            "delivered_at": utc_now(),
        }

    async def cleanup_draft(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> None:
        """Optional best-effort cleanup when a queued approval is rejected or superseded."""
        return None

    async def deliver_notification(
        self,
        account: dict[str, Any],
        *,
        approval: dict[str, Any],
        text: str,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Deliver an approval notification over this connector (defaults to dispatch)."""
        secrets = account.get("secrets") or {}
        dispatch_payload: dict[str, Any] = {
            "approval_id": approval["id"],
            "bot_slug": approval["bot_slug"],
            "action_type": approval["action_type"],
            "target": target or None,
            "to": (target or secrets.get("operator_email") or secrets.get("email") or ""),
            "subject": f"[Argo Approval] {approval['action_type']} from {approval['bot_slug']}",
        }
        return await self.dispatch(
            account,
            action_type=f"notify_{approval['action_type']}",
            payload=dispatch_payload,
            final_text=text,
        )


class GoogleConnectorAdapter(ConnectorAdapter):
    """Adapter bridging Google Workspace (Gmail/Drive/Calendar) into ConnectorGateway."""

    provider = "google"
    display_label = "Gmail capability match"
    capability_keywords = (r"\b(gmail|inbox|unread email|emails?)\b",)
    tool_names = ("gmail_search", "gdrive_search", "gcal_events")
    action_types = ("send_email", "gmail_draft", "reply_email")

    def __init__(self, service: Any | None) -> None:
        self._service = service

    @staticmethod
    def gmail_msg_to_doc(
        account_slug: str,
        msg: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        mid = str(msg.get("id") or msg.get("message_id") or "").strip()
        ext_key = f"gmail:{account_slug}:{mid}"
        body_excerpt = str(msg.get("body_excerpt") or "")[:4000]
        snippet = str(msg.get("snippet") or "")
        subject = str(msg.get("subject") or "(No subject)")
        sender = str(msg.get("from") or "")
        search_text = f"{subject} {sender} {snippet} {body_excerpt[:400]}"[:1000]
        doc: dict[str, Any] = {
            "source_type": "gmail",
            "account_slug": account_slug,
            "message_id": mid,
            "thread_id": msg.get("thread_id"),
            "from": sender,
            "to": msg.get("to", ""),
            "cc": msg.get("cc", ""),
            "bcc": msg.get("bcc", ""),
            "reply_to": msg.get("reply_to", ""),
            "subject": subject,
            "date": msg.get("date", ""),
            "message_id_header": msg.get("message_id_header", ""),
            "in_reply_to": msg.get("in_reply_to", ""),
            "internal_date_ms": msg.get("internal_date_ms"),
            "size_estimate": msg.get("size_estimate", 0),
            "label_ids": list(msg.get("label_ids") or []),
            "is_unread": bool(msg.get("is_unread", "UNREAD" in (msg.get("label_ids") or []))),
            "history_id": msg.get("history_id", ""),
            "has_attachments": bool(msg.get("has_attachments", bool(msg.get("attachments")))),
            "attachments": list(msg.get("attachments") or []),
            "body_excerpt": body_excerpt,
            "snippet": snippet,
        }
        return ext_key, search_text, doc

    @staticmethod
    def gdrive_file_to_doc(
        account_slug: str,
        file_obj: dict[str, Any],
    ) -> tuple[str, str, str, dict[str, Any]]:
        fid = str(file_obj.get("id") or file_obj.get("file_id") or "").strip()
        modified = str(file_obj.get("modifiedTime") or "").strip()
        ext_key = f"gdrive:{account_slug}:{fid}"
        seen_key = f"{ext_key}:{modified}" if modified else ext_key
        name = str(file_obj.get("name") or "")
        mime_type = str(file_obj.get("mimeType") or "")
        desc = str(file_obj.get("description") or "")
        owners = list(file_obj.get("owners") or [])
        owner_str = " ".join(
            f"{o.get('displayName', '')} {o.get('emailAddress', '')}"
            for o in owners
            if isinstance(o, dict)
        )
        search_text = f"{name} {mime_type} {owner_str} {desc}"[:1000]
        clean_raw = {k: v for k, v in file_obj.items() if k not in {"external_key", "seen_key"}}
        doc: dict[str, Any] = {
            **clean_raw,
            "source_type": "gdrive",
            "account_slug": account_slug,
            "file_id": fid,
        }
        return ext_key, seen_key, search_text, doc

    @staticmethod
    def gcal_event_to_doc(
        account_slug: str,
        calendar_id: str,
        event_obj: dict[str, Any],
    ) -> tuple[str, str, str, dict[str, Any]]:
        eid = str(event_obj.get("id") or event_obj.get("event_id") or "").strip()
        updated = str(event_obj.get("updated") or "").strip()
        ext_key = f"gcal:{account_slug}:{eid}"
        seen_key = f"{ext_key}:{updated}" if updated else ext_key
        summary = str(event_obj.get("summary") or "(No title)")
        location = str(event_obj.get("location") or "")
        desc = str(event_obj.get("description") or "")
        attendee_str = " ".join(
            str(a.get("email") or a.get("displayName") or "")
            for a in (event_obj.get("attendees") or [])
            if isinstance(a, dict)
        )
        search_text = f"{summary} {location} {attendee_str} {desc[:300]}"[:1000]
        clean_raw = {k: v for k, v in event_obj.items() if k not in {"external_key", "seen_key"}}
        doc: dict[str, Any] = {
            **clean_raw,
            "source_type": "gcal",
            "account_slug": account_slug,
            "calendar_id": calendar_id,
            "event_id": eid,
        }
        return ext_key, seen_key, search_text, doc

    def normalize_action_payload(
        self,
        action_type: str,
        action: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        extra_payload, target_dest = super().normalize_action_payload(action_type, action)
        payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
        if action_type in {"send_email", "gmail_draft", "reply_email"} or any(
            action.get(k) or payload_obj.get(k)
            for k in ("to", "recipient", "subject", "cc", "bcc", "thread_id", "in_reply_to")
        ):
            to_email = str(
                action.get("to")
                or action.get("recipient")
                or payload_obj.get("to")
                or payload_obj.get("recipient")
                or target_dest
                or ""
            ).strip()
            subject = str(
                action.get("subject") or payload_obj.get("subject") or "(No subject)"
            ).strip()
            email_meta: dict[str, Any] = {
                **(extra_payload or {}),
                "to": to_email,
                "subject": subject,
            }
            for opt_key in ("cc", "bcc", "thread_id", "in_reply_to"):
                opt_val = action.get(opt_key) or payload_obj.get(opt_key)
                if opt_val:
                    email_meta[opt_key] = opt_val
            extra_payload = email_meta
            target_dest = target_dest or to_email or None
        return extra_payload, target_dest

    def _resolve_poll_plan(
        self,
        account: dict[str, Any],
        bot: dict[str, Any],
        routine: dict[str, Any] | None,
        *,
        query_override: str = "",
    ) -> dict[str, Any]:
        if (
            self._service is None
            or account.get("status") == "expired"
            or bot.get("runtime", "api") != "api"
        ):
            return {"gmail": False, "gdrive": False, "gcal": False}

        tool_names: set[str] = set()
        gmail_query = ""
        drive_query = ""
        cal_query = ""
        cal_id = "primary"
        for tool in bot.get("tools") or []:
            if isinstance(tool, dict):
                name = str(tool.get("name") or "")
                if name:
                    tool_names.add(name)
                if name == "gmail_search" and str(tool.get("query") or "").strip():
                    gmail_query = str(tool.get("query")).strip()
                elif name == "gdrive_search" and str(tool.get("query") or "").strip():
                    drive_query = str(tool.get("query")).strip()
                elif name == "gcal_events":
                    if str(tool.get("query") or "").strip():
                        cal_query = str(tool.get("query")).strip()
                    if str(tool.get("calendar_id") or "").strip():
                        cal_id = str(tool.get("calendar_id")).strip()
            elif isinstance(tool, str) and tool.strip():
                tool_names.add(tool.strip())

        is_on_event_routine = False
        routines_to_scan = (
            [routine]
            if isinstance(routine, dict)
            else [
                r
                for r in (bot.get("routines") or [])
                if isinstance(r, dict) and r.get("enabled", True)
            ]
        )
        for r in routines_to_scan:
            if (
                str(r.get("trigger_type") or "") == "on_event"
                or str(r.get("type") or "") == "on_event"
                or bool(r.get("event"))
            ):
                is_on_event_routine = True
            r_src_q = str(
                r.get("source_query")
                or r.get("gmail_query")
                or r.get("inbox_query")
                or ""
            ).strip()
            if r_src_q:
                gmail_query = r_src_q
            if str(r.get("drive_query") or "").strip():
                drive_query = str(r.get("drive_query")).strip()
            if str(r.get("calendar_query") or "").strip():
                cal_query = str(r.get("calendar_query")).strip()
            if str(r.get("calendar_id") or "").strip():
                cal_id = str(r.get("calendar_id")).strip()

        if query_override.strip():
            gmail_query = query_override.strip()

        lower_prompt = str(bot.get("role_prompt") or "").lower()
        uses_gmail = ("gmail_search" in tool_names) or (
            not is_on_event_routine
            and any(kw in lower_prompt for kw in ("gmail", "email", "inbox", "mail"))
        )
        uses_gdrive = ("gdrive_search" in tool_names) or (
            not is_on_event_routine
            and any(kw in lower_prompt for kw in ("google drive", "gdrive", "google docs", "google sheets"))
        )
        uses_gcal = ("gcal_events" in tool_names) or (
            not is_on_event_routine
            and any(kw in lower_prompt for kw in ("google calendar", "gcal"))
        )
        acc_scopes = {str(s).lower() for s in (account.get("scopes") or [])}
        return {
            "gmail": bool(
                uses_gmail
                and (
                    not acc_scopes
                    or any("gmail" in s or s == "default" or "mail.google" in s for s in acc_scopes)
                )
            ),
            "gmail_query": gmail_query,
            "gdrive": bool(
                uses_gdrive
                and (
                    "gdrive_search" in tool_names
                    or any("drive" in s or "documents" in s or "spreadsheets" in s for s in acc_scopes)
                )
            ),
            "drive_query": drive_query,
            "gcal": bool(
                uses_gcal
                and ("gcal_events" in tool_names or any("calendar" in s for s in acc_scopes))
            ),
            "cal_query": cal_query,
            "cal_id": cal_id,
        }

    def supports_poll(
        self,
        account: dict[str, Any],
        bot: dict[str, Any],
        routine: dict[str, Any] | None = None,
    ) -> bool:
        plan = self._resolve_poll_plan(account, bot, routine)
        return bool(plan.get("gmail") or plan.get("gdrive") or plan.get("gcal"))

    async def poll(
        self,
        account: dict[str, Any],
        *,
        ctx: ConnectorPollContext,
    ) -> ConnectorPollResult:
        plan = self._resolve_poll_plan(
            account,
            ctx.bot,
            ctx.routine,
            query_override=ctx.query,
        )
        if not (plan.get("gmail") or plan.get("gdrive") or plan.get("gcal")):
            return ConnectorPollResult()

        assert self._service is not None
        acc_slug = account["slug"]
        bot_name = str(ctx.bot.get("name") or ctx.bot_slug)
        entries: list[dict[str, Any]] = []
        total_fetched = 0
        dedup_skipped = 0
        any_probe_ok = False

        if plan["gmail"]:
            prefix = f"gmail:{acc_slug}:"
            cursor_prefix = f"{ctx.bot_slug}:{prefix}"
            exclude_ids = {
                k[len(prefix) :]
                for k in ctx.existing_external_keys
                if k.startswith(prefix) and len(k) > len(prefix)
            } | {
                k[len(cursor_prefix) :]
                for k in ctx.seen_cursor_keys
                if k.startswith(cursor_prefix) and len(k) > len(cursor_prefix)
            }
            try:
                search_res = await self._service.search_messages(
                    acc_slug,
                    query=str(plan.get("gmail_query") or ""),
                    max_results=15,
                    exclude_ids=exclude_ids or None,
                )
                any_probe_ok = True
                msgs = list(search_res.get("messages") or [])
                if not msgs and exclude_ids:
                    dedup_skipped += len(exclude_ids)
                for msg in msgs:
                    mid = str(msg.get("id") or "").strip()
                    if not mid:
                        continue
                    ext_key, search_text, doc = self.gmail_msg_to_doc(acc_slug, msg)
                    total_fetched += 1
                    if ctx.is_seen(ext_key, include_collection=True):
                        continue
                    entries.append(
                        {
                            **doc,
                            "external_key": ext_key,
                            "seen_key": ext_key,
                            "_persist": {
                                "search_text": search_text,
                                "doc": doc,
                                "description": f"Processed Gmail message for {bot_name}",
                            },
                        }
                    )
            except Exception:
                logger.debug(
                    "Scheduled Gmail pre-poll skipped for %s/%s",
                    ctx.bot_slug,
                    acc_slug,
                    exc_info=True,
                )

        if plan["gdrive"]:
            try:
                drive_res = await self._service.search_drive_files(
                    acc_slug,
                    query=str(plan.get("drive_query") or ""),
                    page_size=25,
                )
                any_probe_ok = True
                for fobj in drive_res.get("files") or []:
                    fid = str((fobj or {}).get("id") or "").strip()
                    if not fid:
                        continue
                    ext_key, seen_key, search_text, doc = self.gdrive_file_to_doc(acc_slug, fobj)
                    total_fetched += 1
                    if ctx.is_seen(seen_key):
                        continue
                    existing_doc = ctx.get_existing_doc(ext_key)
                    if (
                        existing_doc is not None
                        and (existing_doc.get("doc") or {}).get("modifiedTime") == fobj.get("modifiedTime")
                        and fobj.get("modifiedTime")
                    ):
                        ctx.mark_seen([seen_key])
                        continue
                    entries.append(
                        {
                            **doc,
                            "external_key": ext_key,
                            "seen_key": seen_key,
                            "_persist": {
                                "search_text": search_text,
                                "doc": doc,
                                "description": f"Processed Google Drive file for {bot_name}",
                            },
                        }
                    )
            except Exception:
                logger.debug(
                    "Scheduled Google Drive pre-poll skipped for %s/%s",
                    ctx.bot_slug,
                    acc_slug,
                    exc_info=True,
                )

        if plan["gcal"]:
            cal_id = str(plan.get("cal_id") or "primary")
            try:
                cal_res = await self._service.list_calendar_events(
                    acc_slug,
                    calendar_id=cal_id,
                    query=str(plan.get("cal_query") or ""),
                    max_results=25,
                )
                any_probe_ok = True
                for ev in cal_res.get("events") or []:
                    eid = str((ev or {}).get("id") or "").strip()
                    if not eid:
                        continue
                    ext_key, seen_key, search_text, doc = self.gcal_event_to_doc(acc_slug, cal_id, ev)
                    total_fetched += 1
                    if ctx.is_seen(seen_key):
                        continue
                    existing_doc = ctx.get_existing_doc(ext_key)
                    if (
                        existing_doc is not None
                        and (existing_doc.get("doc") or {}).get("updated") == ev.get("updated")
                        and ev.get("updated")
                    ):
                        ctx.mark_seen([seen_key])
                        continue
                    entries.append(
                        {
                            **doc,
                            "external_key": ext_key,
                            "seen_key": seen_key,
                            "_persist": {
                                "search_text": search_text,
                                "doc": doc,
                                "description": f"Processed Google Calendar event for {bot_name}",
                            },
                        }
                    )
            except Exception:
                logger.debug(
                    "Scheduled Google Calendar pre-poll skipped for %s/%s",
                    ctx.bot_slug,
                    acc_slug,
                    exc_info=True,
                )

        return ConnectorPollResult(
            polled=any_probe_ok,
            entries=entries,
            total_fetched=total_fetched,
            dedup_skipped=dedup_skipped,
        )

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("GoogleOAuthService is not attached to ConnectorGateway.")
        return await self._service.probe_account(account["slug"])

    async def get_tool_specs(
        self,
        account: dict[str, Any],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        from argo_core.runner.tool_registry import get_tool_spec

        del account, bot
        ordered = (
            "gmail_search",
            "gdrive_search",
            "gdrive_read_file",
            "gcal_events",
            "send_email",
            "gmail_draft",
            "reply_email",
        )
        return [spec for name in ordered if (spec := get_tool_spec(name)) is not None]

    def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
        del account
        return tool_name in {"gmail_search", "gdrive_search", "gdrive_read_file", "gcal_events"}

    async def execute_tool(
        self,
        *,
        tool_name: str,
        action: dict[str, Any],
        ctx: ConnectorToolContext,
    ) -> dict[str, Any] | None:
        if self._service is None or not self.owns_tool(tool_name, ctx.account):
            return None
        account_slug = ctx.account["slug"]
        bot_name = str(ctx.bot.get("name") or ctx.bot.get("slug") or "")
        target_col = ctx.data_write_cols[0] if ctx.data_write_cols else None

        if tool_name == "gmail_search":
            try:
                search_res = await self._service.search_messages(
                    account_slug,
                    query=str(action.get("query") or ""),
                    max_results=int(action.get("max_results") or 10),
                )
                fetched_msgs = list(search_res.get("messages") or [])
                if target_col:
                    for msg in fetched_msgs:
                        mid = str(msg.get("id") or "").strip()
                        if not mid:
                            continue
                        ext_key, search_text, doc = self.gmail_msg_to_doc(account_slug, msg)
                        ctx.upsert_doc(
                            collection=target_col,
                            external_key=ext_key,
                            search_text=search_text,
                            doc=doc,
                            description=f"Mirrored Gmail messages for {bot_name}",
                        )
                return {
                    "type": tool_name,
                    "status": "ok",
                    "account": account_slug,
                    "query": search_res.get("query") or "",
                    "messages": fetched_msgs,
                }
            except Exception as exc:
                return {
                    "type": tool_name,
                    "status": "error",
                    "account": account_slug,
                    "detail": ctx.scrub_text(str(exc)),
                }

        if tool_name == "gdrive_search":
            try:
                drive_res = await self._service.search_drive_files(
                    account_slug,
                    query=str(action.get("query") or ""),
                    page_size=int(action.get("page_size") or action.get("max_results") or 25),
                    page_token=str(action["page_token"]) if action.get("page_token") else None,
                )
                files_list = list(drive_res.get("files") or [])
                seen_keys: list[str] = []
                if target_col:
                    for fobj in files_list:
                        fid = str((fobj or {}).get("id") or "").strip()
                        if not fid:
                            continue
                        ext_key, seen_key, search_text, doc = self.gdrive_file_to_doc(account_slug, fobj)
                        ctx.upsert_doc(
                            collection=target_col,
                            external_key=ext_key,
                            search_text=search_text,
                            doc=doc,
                            description=f"Mirrored Google Drive files for {bot_name}",
                        )
                        seen_keys.append(seen_key)
                if seen_keys:
                    ctx.mark_seen(seen_keys)
                return {
                    "type": tool_name,
                    "status": "ok",
                    "account": account_slug,
                    "query": drive_res.get("query") or "",
                    "files": files_list,
                    "next_page_token": drive_res.get("next_page_token"),
                }
            except Exception as exc:
                return {
                    "type": tool_name,
                    "status": "error",
                    "account": account_slug,
                    "detail": ctx.scrub_text(str(exc)),
                }

        if tool_name == "gdrive_read_file":
            file_id = str(action.get("file_id") or action.get("id") or "").strip()
            if not file_id:
                return {
                    "type": tool_name,
                    "status": "skipped_invalid_action",
                    "detail": "Missing file_id for gdrive_read_file.",
                }
            try:
                file_res = await self._service.read_drive_file_excerpt(
                    account_slug,
                    file_id=file_id,
                    max_chars=int(action.get("max_chars") or 16000),
                )
                if target_col:
                    ext_key, seen_key, search_text, doc = self.gdrive_file_to_doc(account_slug, file_res)
                    ctx.upsert_doc(
                        collection=target_col,
                        external_key=ext_key,
                        search_text=search_text,
                        doc=doc,
                        description=f"Mirrored Google Drive files for {bot_name}",
                    )
                    ctx.mark_seen([seen_key])
                return {"type": tool_name, "status": "ok", "account": account_slug, "file": file_res}
            except Exception as exc:
                return {
                    "type": tool_name,
                    "status": "error",
                    "account": account_slug,
                    "detail": ctx.scrub_text(str(exc)),
                }

        if tool_name == "gcal_events":
            cal_id = str(action.get("calendar_id") or "primary").strip() or "primary"
            try:
                cal_res = await self._service.list_calendar_events(
                    account_slug,
                    calendar_id=cal_id,
                    time_min=str(action["time_min"]) if action.get("time_min") else None,
                    time_max=str(action["time_max"]) if action.get("time_max") else None,
                    query=str(action.get("query") or ""),
                    max_results=int(action.get("max_results") or 25),
                )
                events_list = list(cal_res.get("events") or [])
                seen_keys = []
                if target_col:
                    for ev in events_list:
                        eid = str((ev or {}).get("id") or "").strip()
                        if not eid:
                            continue
                        ext_key, seen_key, search_text, doc = self.gcal_event_to_doc(
                            account_slug, cal_id, ev
                        )
                        ctx.upsert_doc(
                            collection=target_col,
                            external_key=ext_key,
                            search_text=search_text,
                            doc=doc,
                            description=f"Mirrored Google Calendar events for {bot_name}",
                        )
                        seen_keys.append(seen_key)
                if seen_keys:
                    ctx.mark_seen(seen_keys)
                return {
                    "type": tool_name,
                    "status": "ok",
                    "account": account_slug,
                    "calendar_id": cal_id,
                    "events": events_list,
                }
            except Exception as exc:
                return {
                    "type": tool_name,
                    "status": "error",
                    "account": account_slug,
                    "detail": ctx.scrub_text(str(exc)),
                }

        return None

    async def prepare_draft(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if (
            self._service is None
            or action_type not in {"send_email", "gmail_draft", "reply_email"}
            or not payload.get("to")
            or payload.get("gmail_draft_id")
        ):
            return {}
        try:
            draft_res = await self._service.create_draft(
                account["slug"],
                to_email=str(payload["to"]).strip(),
                subject=str(payload.get("subject") or "(No subject)").strip(),
                body_text=str(payload.get("text") or "").strip(),
                cc_email=payload.get("cc"),
                thread_id=payload.get("thread_id"),
                in_reply_to=payload.get("in_reply_to"),
                **({"bcc_email": payload.get("bcc")} if payload.get("bcc") else {}),
            )
            draft_id = draft_res.get("draft_id")
            return {"gmail_draft_id": draft_id} if draft_id else {}
        except Exception as exc:
            logger.warning(
                "Best-effort Gmail draft creation failed for %s: %s",
                account["slug"],
                exc,
            )
            return {}

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("GoogleOAuthService is not attached to ConnectorGateway.")
        to_email = str(payload.get("to") or payload.get("target") or "").strip()
        subject = str(payload.get("subject") or "(No subject)").strip()
        if not to_email:
            raise RuntimeError(
                f"Email action '{action_type}' on '{account['slug']}' is missing recipient 'to'."
            )
        if action_type == "gmail_draft":
            res = await self._service.create_draft(
                account["slug"],
                to_email=to_email,
                subject=subject,
                body_text=final_text,
                cc_email=payload.get("cc"),
                thread_id=payload.get("thread_id"),
                in_reply_to=payload.get("in_reply_to"),
                **({"bcc_email": payload.get("bcc")} if payload.get("bcc") else {}),
            )
            return {
                "provider": "google",
                "action_type": action_type,
                "target": to_email,
                **res,
            }
        res = await self._service.send_email(
            account["slug"],
            to_email=to_email,
            subject=subject,
            body_text=final_text,
            cc_email=payload.get("cc"),
            thread_id=payload.get("thread_id"),
            in_reply_to=payload.get("in_reply_to"),
            **({"bcc_email": payload.get("bcc")} if payload.get("bcc") else {}),
        )
        draft_id = str(payload.get("gmail_draft_id") or "").strip()
        if draft_id and hasattr(self._service, "delete_draft"):
            try:
                await self._service.delete_draft(account["slug"], draft_id=draft_id)
            except Exception as exc:
                logger.debug(
                    "Best-effort Gmail draft cleanup after send failed (%s/%s): %s",
                    account["slug"],
                    draft_id,
                    exc,
                )
        return {
            "provider": "google",
            "action_type": action_type,
            "target": to_email,
            **res,
        }

    async def cleanup_draft(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> None:
        if self._service is None or not hasattr(self._service, "delete_draft"):
            return
        draft_id = str(payload.get("gmail_draft_id") or "").strip()
        if not draft_id:
            return
        try:
            await self._service.delete_draft(account["slug"], draft_id=draft_id)
        except Exception as exc:
            logger.debug(
                "Best-effort Gmail draft cleanup failed (%s/%s): %s",
                account["slug"],
                draft_id,
                exc,
            )


class TelegramConnectorAdapter(ConnectorAdapter):
    """Adapter bridging Telegram Bot API into ConnectorGateway."""

    provider = "telegram"
    display_label = "Telegram capability match"
    capability_keywords = (r"\b(telegram|t\.me)\b",)
    tool_names = ("fetch_telegram_public_channel", "publish_telegram")
    action_types = ("publish_telegram",)

    def __init__(self, service: Any | None) -> None:
        self._service = service

    def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
        """Telegram adapter dispatches outbound messages only via action_types."""
        del tool_name, account
        return False

    async def get_tool_specs(
        self,
        account: dict[str, Any],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        from argo_core.runner.tool_registry import get_tool_spec

        del account, bot
        spec = get_tool_spec("publish_telegram")
        return [spec] if spec is not None else []

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("TelegramBotService is not attached to ConnectorGateway.")
        return await self._service.probe_account(
            account["slug"], send_test_message=send_test_message
        )

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("TelegramBotService is not attached to ConnectorGateway.")
        secrets = account.get("secrets") or {}
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
        sent = await self._service.publish_message(
            account["slug"],
            chat_id=dest_chat,
            text=final_text,
        )
        return {"provider": "telegram", "target": dest_chat, **sent}

    async def deliver_notification(
        self,
        account: dict[str, Any],
        *,
        approval: dict[str, Any],
        text: str,
        target: str | None = None,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("TelegramBotService is not attached to ConnectorGateway.")
        from argo_core.connectors.telegram_bot import build_inline_keyboard

        secrets = account.get("secrets") or {}
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
        markup = build_inline_keyboard(
            [
                [
                    ("Approve & Publish", f"apr:ok:{approval['id']}"),
                    ("Reject", f"apr:no:{approval['id']}"),
                ]
            ]
        )
        sent = await self._service.publish_message(
            account["slug"],
            chat_id=dest_chat,
            text=text,
            reply_markup=markup,
        )
        card_chat_id = str(sent.get("chat_id") or dest_chat)
        return {
            "provider": "telegram",
            "approval_id": approval["id"],
            "telegram_card": {
                "chat_id": card_chat_id,
                "message_id": int(sent["message_id"]),
            },
            **sent,
        }


class LinkedInConnectorAdapter(ConnectorAdapter):
    """Adapter bridging LinkedIn /rest/posts API into ConnectorGateway."""

    provider = "linkedin"
    display_label = "LinkedIn capability match"
    capability_keywords = (r"\blinkedin\b",)
    tool_names = ("publish_linkedin",)
    action_types = ("publish_linkedin",)

    def __init__(self, service: Any | None) -> None:
        self._service = service

    def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
        """LinkedIn adapter dispatches outbound posts only via action_types."""
        del tool_name, account
        return False

    async def get_tool_specs(
        self,
        account: dict[str, Any],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        from argo_core.runner.tool_registry import get_tool_spec

        del account, bot
        spec = get_tool_spec("publish_linkedin")
        return [spec] if spec is not None else []

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("LinkedInService is not attached to ConnectorGateway.")
        return await self._service.probe_account(account["slug"])

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("LinkedInService is not attached to ConnectorGateway.")
        res = await self._service.publish_post(
            account["slug"],
            commentary=final_text,
            visibility=payload.get("visibility", "PUBLIC"),
            article_url=payload.get("article_url"),
            article_title=payload.get("article_title"),
        )
        return {"provider": "linkedin", **res}


class WebhookConnectorAdapter(ConnectorAdapter):
    """Adapter bridging inbound/outbound signed HMAC webhooks into ConnectorGateway."""

    provider = "webhook"
    display_label = "Webhook capability match"
    action_types = ("publish_webhook",)

    def __init__(
        self,
        service: Any | None = None,
        *,
        webhook_transport: Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None = None,
        webhook_transport_getter: Callable[[], Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None] | None = None,
        url_validator: Callable[[str], tuple[str, list[str]]] | None = None,
    ) -> None:
        self._service = service
        self._webhook_transport = webhook_transport
        self._webhook_transport_getter = webhook_transport_getter
        self._url_validator = url_validator

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("WebhookService is not attached to ConnectorGateway.")
        return await self._service.probe_account(account["slug"])

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        secrets = account.get("secrets") or {}
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
            validator = self._url_validator or validate_public_url
            cleaned_url, _ = validator(target_url)
            webhook_body = {
                "text": final_text,
                "action_type": action_type,
                "approval_id": payload.get("approval_id"),
                "bot_slug": payload.get("bot_slug"),
            }
            req_headers = {"Content-Type": "application/json"}
            transport = (
                self._webhook_transport_getter()
                if self._webhook_transport_getter is not None
                else None
            ) or self._webhook_transport
            if transport is not None:
                post_res = await transport(cleaned_url, webhook_body, req_headers)
                return {
                    "provider": "webhook",
                    "account_slug": account["slug"],
                    "target": cleaned_url,
                    "status_code": post_res.get("status_code", 200),
                    "delivered_at": utc_now(),
                }
            resp = await SafePublicHttpFetcher().post_json(
                cleaned_url,
                webhook_body,
                headers=req_headers,
                timeout_seconds=15.0,
            )
            return {
                "provider": "webhook",
                "account_slug": account["slug"],
                "target": cleaned_url,
                "status_code": resp.status_code,
                "delivered_at": utc_now(),
            }

        return await super().dispatch(
            account,
            action_type=action_type,
            payload=payload,
            final_text=final_text,
        )


class MCPConnectorAdapter(ConnectorAdapter):
    """Dynamic Streamable HTTP JSON-RPC 2.0 MCP server adapter with read/write RBAC gating."""

    provider = "mcp"
    display_label = "MCP server capability match"
    capability_keywords = (r"\bmcp\b",)

    def __init__(self, service: MCPConnectorService | None = None) -> None:
        self._service = service

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        del send_test_message
        if self._service is None:
            raise RuntimeError("MCPConnectorService is not attached to ConnectorGateway.")
        return await self._service.probe(account)

    async def get_tool_specs(
        self,
        account: dict[str, Any],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        del bot
        if self._service is None or account.get("status") == "expired":
            return []
        try:
            return await self._service.list_tool_specs(account)
        except Exception as exc:
            logger.warning(
                "Skipping MCP tool discovery for '%s': %s",
                account.get("slug"),
                exc,
            )
            return []

    def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
        acc_slug = str(account.get("slug") or "")
        if not acc_slug:
            return False
        if self._service is not None and self._service.resolve_cached_tool(acc_slug, tool_name) is not None:
            return True
        clean_acc = "".join(c if c.isalnum() or c == "_" else "_" for c in acc_slug).strip("_") or "mcp"
        return str(tool_name or "").startswith(f"mcp__{clean_acc}__")

    async def execute_tool(
        self,
        *,
        tool_name: str,
        action: dict[str, Any],
        ctx: ConnectorToolContext,
    ) -> dict[str, Any] | None:
        if self._service is None or not self.owns_tool(tool_name, ctx.account):
            return None
        tool_meta = await self._service.resolve_tool(ctx.account, tool_name)
        if tool_meta is None:
            return {
                "type": tool_name,
                "status": "not_found",
                "account": ctx.account["slug"],
                "detail": f"MCP tool '{tool_name}' was not found on '{ctx.account['slug']}'.",
            }
        tool_args = {k: v for k, v in action.items() if k not in {"type", "_tool_call_id"}}
        remote_name = str(tool_meta["remote_name"])
        if bool(tool_meta.get("readonly")):
            res = await self._service.call_tool(
                ctx.account,
                remote_name=remote_name,
                arguments=tool_args,
            )
            return {
                "type": tool_name,
                "status": "ok",
                "account": ctx.account["slug"],
                "remote_tool": remote_name,
                "result": res,
            }

        if ctx.execute_or_queue_outbound is None:
            return {
                "type": tool_name,
                "status": "error",
                "account": ctx.account["slug"],
                "detail": "Approval coordinator callback missing for mutating MCP tool.",
            }
        gate_res = await ctx.execute_or_queue_outbound(
            account_slug=ctx.account["slug"],
            action_type=tool_name,
            text=json.dumps(tool_args, ensure_ascii=False),
            target=remote_name,
            extra_payload={
                "mcp_remote_tool": remote_name,
                "mcp_arguments": tool_args,
            },
        )
        out: dict[str, Any] = {
            "type": tool_name,
            **gate_res,
            "status": gate_res.get("status") or gate_res.get("outcome") or "ok",
        }
        approval_obj = gate_res.get("approval")
        if isinstance(approval_obj, dict) and approval_obj.get("id"):
            out["approval_id"] = approval_obj["id"]
        return out

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        if self._service is None:
            raise RuntimeError("MCPConnectorService is not attached to ConnectorGateway.")
        remote_name = str(payload.get("mcp_remote_tool") or payload.get("target") or "").strip()
        raw_args = payload.get("mcp_arguments")
        if not isinstance(raw_args, dict):
            try:
                parsed = json.loads(final_text) if final_text else {}
                raw_args = parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                raw_args = {}
        if not remote_name:
            resolved = await self._service.resolve_tool(account, action_type)
            if resolved is not None:
                remote_name = str(resolved["remote_name"])
        if not remote_name:
            raise RuntimeError(f"Missing mcp_remote_tool for MCP dispatch '{action_type}'.")
        res = await self._service.call_tool(
            account,
            remote_name=remote_name,
            arguments=raw_args,
        )
        return {
            "provider": "mcp",
            "account_slug": account["slug"],
            "action_type": action_type,
            "target": remote_name,
            "delivered_at": utc_now(),
            **res,
        }


class ConnectorGateway:
    """Extensible provider registry decoupling Argo's core router/brain from concrete connectors."""

    def __init__(self, adapters: list[ConnectorAdapter] | None = None) -> None:
        self._adapters: dict[str, ConnectorAdapter] = {}
        for adapter in adapters or ():
            self.register(adapter)

    def register(self, adapter: ConnectorAdapter) -> None:
        """Register or replace an adapter by lowercase provider name."""
        key = str(adapter.provider or "").strip().lower()
        if not key:
            raise ValueError("ConnectorAdapter.provider cannot be empty.")
        self._adapters[key] = adapter

    def get(self, provider: str) -> ConnectorAdapter | None:
        return self._adapters.get(str(provider or "").strip().lower())

    def list_adapters(self) -> list[ConnectorAdapter]:
        return list(self._adapters.values())

    def resolve_provider_for_action(self, action_type: str) -> str | None:
        """Resolve which connector provider handles action_type, if any adapter declares it."""
        clean_type = str(action_type or "").strip().lower()
        if not clean_type:
            return None
        for adapter in self._adapters.values():
            declared = {str(t).strip().lower() for t in (adapter.action_types or ()) if str(t).strip()}
            if clean_type in declared:
                return adapter.provider
        return None

    def all_action_types(self) -> set[str]:
        """Return 'connector_publish' unioned with all registered adapters' action_types."""
        supported: set[str] = {"connector_publish"}
        for adapter in self._adapters.values():
            for raw_t in adapter.action_types or ():
                cleaned = str(raw_t).strip().lower()
                if cleaned:
                    supported.add(cleaned)
        return supported

    def normalize_action_payload(
        self,
        *,
        provider: str | None = None,
        action_type: str,
        action: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Delegate action payload & target normalization to the matching connector adapter."""
        clean_provider = str(provider or "").strip().lower() or self.resolve_provider_for_action(
            action_type
        )
        adapter = self.get(clean_provider) if clean_provider else None
        if adapter is not None:
            return adapter.normalize_action_payload(action_type, action)
        return ConnectorAdapter().normalize_action_payload(action_type, action)

    def supports_poll(
        self,
        account: dict[str, Any],
        bot: dict[str, Any],
        routine: dict[str, Any] | None = None,
    ) -> bool:
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is None:
            return False
        return bool(adapter.supports_poll(account, bot, routine))

    async def poll(
        self,
        account: dict[str, Any],
        *,
        ctx: ConnectorPollContext,
    ) -> ConnectorPollResult:
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is None:
            return ConnectorPollResult()
        return await adapter.poll(account, ctx=ctx)

    async def probe(
        self,
        account: dict[str, Any],
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any] | None:
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is None:
            return None
        return await adapter.probe(account, send_test_message=send_test_message)

    async def prepare_draft(
        self,
        account: dict[str, Any] | None,
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if account is None:
            return {}
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is None:
            return {}
        return await adapter.prepare_draft(
            account,
            action_type=action_type,
            payload=payload,
        )

    async def dispatch(
        self,
        account: dict[str, Any],
        *,
        action_type: str,
        payload: dict[str, Any],
        final_text: str,
    ) -> dict[str, Any]:
        provider = str(account.get("provider") or "").strip().lower()
        if account.get("status") == "expired":
            raise RuntimeError(
                f"Connector '{account['slug']}' ({provider}) is expired and requires re-auth."
            )
        adapter = self.get(provider)
        if adapter is not None:
            return await adapter.dispatch(
                account,
                action_type=action_type,
                payload=payload,
                final_text=final_text,
            )
        return {
            "provider": provider or "custom",
            "account_slug": account["slug"],
            "action_type": action_type,
            "target": payload.get("target") or account.get("account_identifier") or account["slug"],
            "delivered_at": utc_now(),
        }

    async def cleanup_draft(
        self,
        account: dict[str, Any] | None,
        *,
        action_type: str,
        payload: dict[str, Any],
    ) -> None:
        if account is None:
            return
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is not None:
            await adapter.cleanup_draft(
                account,
                action_type=action_type,
                payload=payload,
            )

    async def deliver_notification(
        self,
        account: dict[str, Any],
        *,
        approval: dict[str, Any],
        text: str,
        target: str | None = None,
    ) -> dict[str, Any]:
        if account.get("status") == "expired":
            raise RuntimeError(
                f"Notification integration '{account['slug']}' is expired."
            )
        adapter = self.get(str(account.get("provider") or ""))
        if adapter is not None:
            return await adapter.deliver_notification(
                account,
                approval=approval,
                text=text,
                target=target,
            )
        fallback_adapter = ConnectorAdapter()
        return await fallback_adapter.deliver_notification(
            account,
            approval=approval,
            text=text,
            target=target,
        )

    async def get_dynamic_tool_specs(
        self,
        permitted_integrations: list[dict[str, Any]],
        *,
        bot: dict[str, Any] | None = None,
    ) -> list[ToolSpec]:
        """Collect adapter-owned ToolSpecs across all permitted integrations for this bot."""
        collected: list[ToolSpec] = []
        seen_names: set[str] = set()
        for acc in permitted_integrations:
            provider = str(acc.get("provider") or "").strip().lower()
            adapter = self.get(provider)
            if adapter is None:
                continue
            for spec in await adapter.get_tool_specs(acc, bot=bot):
                if spec.name not in seen_names:
                    collected.append(spec)
                    seen_names.add(spec.name)
        return collected

    def resolve_tool_account(
        self,
        tool_name: str,
        integrations: list[dict[str, Any]],
        *,
        account_hint: str | None = None,
    ) -> tuple[ConnectorAdapter, dict[str, Any]] | None:
        """Resolve which (adapter, integration_account) owns tool_name."""
        clean_tool = str(tool_name or "").strip()
        if not clean_tool:
            return None
        clean_hint = str(account_hint or "").strip().lower()
        ordered = (
            sorted(
                integrations,
                key=lambda acc: 0 if str(acc.get("slug") or "").lower() == clean_hint else 1,
            )
            if clean_hint
            else integrations
        )
        for acc in ordered:
            provider = str(acc.get("provider") or "").strip().lower()
            adapter = self.get(provider)
            if adapter is not None and adapter.owns_tool(clean_tool, acc):
                return adapter, acc
        return None

    async def execute_tool(
        self,
        adapter: ConnectorAdapter,
        *,
        tool_name: str,
        action: dict[str, Any],
        ctx: ConnectorToolContext,
    ) -> dict[str, Any] | None:
        """Execute an adapter-owned tool call against its matched integration account."""
        return await adapter.execute_tool(tool_name=tool_name, action=action, ctx=ctx)


def build_default_connector_gateway(
    *,
    google_service: Any | None = None,
    telegram_service: Any | None = None,
    linkedin_service: Any | None = None,
    webhook_service: Any | None = None,
    mcp_service: MCPConnectorService | None = None,
    webhook_transport: Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None = None,
    webhook_transport_getter: Callable[[], Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]] | None] | None = None,
    url_validator: Callable[[str], tuple[str, list[str]]] | None = None,
) -> ConnectorGateway:
    """Create the default ConnectorGateway populated with Argo's pluggable adapters."""
    gateway = ConnectorGateway()
    gateway.register(GoogleConnectorAdapter(google_service))
    gateway.register(TelegramConnectorAdapter(telegram_service))
    gateway.register(LinkedInConnectorAdapter(linkedin_service))
    gateway.register(
        WebhookConnectorAdapter(
            webhook_service,
            webhook_transport=webhook_transport,
            webhook_transport_getter=webhook_transport_getter,
            url_validator=url_validator,
        )
    )
    gateway.register(MCPConnectorAdapter(mcp_service))
    return gateway
