"""Universal declarative Bot Runner executing JSON bots over Argo's 5 Core Primitives."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from argo_core.approvals.coordinator import ApprovalCoordinator, ConnectorPermissionError
from argo_core.bus.valkey_bus import MAX_HOP_COUNT, EventBus
from argo_core.connectors.telegram_channels import fetch_telegram_public_channel
from argo_core.db.repositories import (
    _INTERNAL_SYSTEM_COLLECTIONS,
    ArgoRepository,
    collection_slug,
    make_id,
    slugify,
    utc_now,
)
from argo_core.desktop.cdp_bridge import ChromeDevToolsBridge, DesktopTakeoverRequiredError
from argo_core.desktop.manager import (
    DesktopManager,
    DesktopRuntimeError,
    DesktopStartupBlockedError,
)
from argo_core.desktop.mcp_bridge import DesktopMCPBridge, DesktopMCPError
from argo_core.llm.router import LLMRouter
from argo_core.security.ssrf import PublicHttpFetcher, SafePublicHttpFetcher
from argo_core.security.vault import redact_secrets
from argo_core.tools.public_web import fetch_public_webpage, fetch_rss_feed

logger = logging.getLogger(__name__)

MAX_TOOL_TURNS = 5
MAX_DESKTOP_GUI_TURNS = 8
_URL_RE = re.compile(r"https?://[^\s<>'\"`)\]]+", re.IGNORECASE)
_DISCOVERY_ONLY_ACTIONS = {
    "fetch_public_webpage",
    "fetch_rss_feed",
    "fetch_telegram_public_channel",
    "gmail_search",
    "list_workspace_files",
    "read_workspace_file",
}
_OPEN_BOARD_RE = re.compile(
    r"\b(?:open|show|dock|pop\s+open)\s+(?:the\s+|my\s+|our\s+)?(?:[a-z0-9_-]+\s+)?(?:html\s+)?(?:board|hub(?:\s+page)?|dashboard)\b",
    re.IGNORECASE,
)
_BOARD_EDIT_VERBS_RE = re.compile(
    r"\b(?:build|create|make|design|redesign|update|edit|change|modify|add|remove|fix)\b",
    re.IGNORECASE,
)
_SUBSTANTIVE_HABIT_ACTION_TYPES = frozenset(
    {
        "fetch_rss_feed",
        "fetch_public_webpage",
        "fetch_telegram_public_channel",
        "gmail_search",
        "desktop_browse",
        "desktop_exec",
        "desktop_launch",
        "desktop_click",
        "upsert_document",
        "upsert_page",
        "write_workspace_file",
        "delegate_to_bot",
        "publish_telegram",
        "publish_linkedin",
        "send_email",
        "gmail_draft",
        "request_human_approval",
    }
)
_DESKTOP_MCP_DISCOVERY_ACTIONS = {
    "desktop_inspect",
    "desktop_screenshot",
    "desktop_check_app",
}
_DESKTOP_MCP_INTERACTIVE_ACTIONS = {
    "desktop_launch",
    "desktop_focus_window",
    "desktop_click",
    "desktop_type",
    "desktop_key",
    "desktop_scroll",
    "desktop_exec",
}
_ALL_DESKTOP_MCP_ACTIONS = _DESKTOP_MCP_DISCOVERY_ACTIONS | _DESKTOP_MCP_INTERACTIVE_ACTIONS
_ACTION_TYPE_ALIASES: dict[str, str] = {
    "send_telegram": "publish_telegram",
    "telegram_send": "publish_telegram",
    "telegram_message": "publish_telegram",
    "telegram_post": "publish_telegram",
    "telegram_summary": "publish_telegram",
    "post_telegram": "publish_telegram",
    "post_linkedin": "publish_linkedin",
    "send_linkedin": "publish_linkedin",
    "save_document": "upsert_document",
    "store_document": "upsert_document",
    "insert_document": "upsert_document",
    "write_document": "upsert_document",
    "queue_approval": "request_human_approval",
    "human_approval": "request_human_approval",
    "request_approval": "request_human_approval",
    "screenshot_desktop": "desktop_screenshot",
    "take_screenshot": "desktop_screenshot",
    "capture_screenshot": "desktop_screenshot",
    "inspect_desktop": "desktop_inspect",
    "desktop_status": "desktop_inspect",
    "open_app": "desktop_launch",
    "launch_app": "desktop_launch",
    "check_app": "desktop_check_app",
    "run_command": "desktop_exec",
    "desktop_shell": "desktop_exec",
    "desktop_command": "desktop_exec",
    "desktop_bash": "desktop_exec",
    "shell_exec": "desktop_exec",
    "execute_command": "desktop_exec",
    "run_ssh": "desktop_exec",
    "forward_approval": "notify_approval",
    "send_approval_card": "notify_approval",
    "deliver_approval": "notify_approval",
    "self_update": "update_self_config",
    "update_config": "update_self_config",
    "update_self": "update_self_config",
    "dock_page": "open_page",
    "show_board": "open_page",
    "open_board": "open_page",
    "propose_plan": "propose_delegation_plan",
    "delegation_plan": "propose_delegation_plan",
    "list_files": "list_workspace_files",
    "read_file": "read_workspace_file",
    "write_file": "write_workspace_file",
}

_INTERNAL_EVENT_PREFIXES = (
    "bot.",
    "approval.superseded",
    "approval.resolved",
    "connector.",
    "desktop.",
    "integration.",
    "page.",
    "telegram.public_channel_synced",
    "telegram.assistant_replied",
    "telegram.command_handled",
    "web.fetch.",
)
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL | re.IGNORECASE)

_FRIENDLY_ACTION_STEP: dict[str, str] = {
    "gmail_search": "Searching Gmail...",
    "create_draft": "Saving Gmail draft...",
    "gmail_draft": "Saving Gmail draft...",
    "send_email": "Preparing email...",
    "reply_email": "Preparing email...",
    "fetch_rss_feed": "Checking RSS feed...",
    "fetch_public_webpage": "Reading webpage...",
    "fetch_telegram_public_channel": "Checking Telegram channel...",
    "desktop_browse": "Browsing in Virtual Desktop...",
    "desktop_inspect": "Inspecting Virtual Desktop status...",
    "desktop_screenshot": "Capturing Virtual Desktop screenshot...",
    "desktop_check_app": "Checking app in Virtual Desktop...",
    "desktop_launch": "Launching app in Virtual Desktop...",
    "desktop_focus_window": "Switching Virtual Desktop window...",
    "desktop_click": "Clicking in Virtual Desktop...",
    "desktop_type": "Typing in Virtual Desktop...",
    "desktop_key": "Sending key in Virtual Desktop...",
    "desktop_scroll": "Scrolling in Virtual Desktop...",
    "desktop_exec": "Running command in Virtual Desktop...",
    "publish_telegram": "Preparing Telegram message...",
    "publish_linkedin": "Preparing LinkedIn post...",
    "linkedin_post": "Preparing LinkedIn post...",
    "request_human_approval": "Sending draft to Approvals...",
    "notify_approval": "Sending approval notification...",
    "upsert_page": "Updating Page...",
    "upsert_document": "Saving items...",
    "delegate_to_bot": "Delegating to bot...",
    "propose_delegation_plan": "Preparing multi-bot plan...",
    "update_self_config": "Updating bot configuration...",
    "configure_routine": "Updating routine schedule...",
    "open_page": "Opening board...",
    "list_workspace_files": "Checking workspace files...",
    "read_workspace_file": "Reading workspace file...",
    "write_workspace_file": "Saving workspace file...",
    "propose_specialist_bot": "Preparing proposal...",
    "propose_fleet_cleanup": "Preparing proposal...",
}


_CHIP_LABELS: dict[str, str] = {
    "gmail_search": "Searching Gmail",
    "create_draft": "Saving Gmail draft",
    "gmail_draft": "Saving Gmail draft",
    "send_email": "Preparing email",
    "reply_email": "Preparing email",
    "fetch_rss_feed": "Checking RSS feed",
    "fetch_public_webpage": "Checking website",
    "fetch_telegram_public_channel": "Checking Telegram channel",
    "desktop_browse": "Browsing in Virtual Desktop",
    "desktop_inspect": "Inspecting Virtual Desktop",
    "desktop_screenshot": "Taking screenshot",
    "desktop_check_app": "Checking desktop app",
    "desktop_launch": "Launching desktop app",
    "desktop_focus_window": "Switching window",
    "desktop_click": "Clicking in Virtual Desktop",
    "desktop_type": "Typing in Virtual Desktop",
    "desktop_key": "Sending key",
    "desktop_scroll": "Scrolling in Virtual Desktop",
    "desktop_exec": "Running desktop command",
    "publish_telegram": "Preparing Telegram message",
    "publish_linkedin": "Preparing LinkedIn post",
    "linkedin_post": "Preparing LinkedIn post",
    "request_human_approval": "Sending draft to Approvals",
    "notify_approval": "Sending approval notification",
    "upsert_page": "Updating Page",
    "upsert_document": "Saving items",
    "delegate_to_bot": "Delegating to bot",
    "propose_delegation_plan": "Preparing multi-bot plan",
    "update_self_config": "Updating bot configuration",
    "configure_routine": "Updating routine schedule",
    "open_page": "Opening board",
    "list_workspace_files": "Checking workspace files",
    "read_workspace_file": "Reading workspace file",
    "write_workspace_file": "Saving workspace file",
    "remember_rule": "Saving writing rule",
    "save_skill": "Saving reusable skill",
    "propose_specialist_bot": "Preparing bot proposal",
    "propose_fleet_cleanup": "Preparing cleanup proposal",
}


class _IncrementalSummaryExtractor:
    """Stateful incremental parser emitting only top-level JSON `"summary"` prose cleanly."""

    def __init__(self) -> None:
        self._mode = "init"  # init | fence_hdr | plain | json_key_seek | key | after_key | colon | str_wait | summary | after_summary | done
        self._depth = 0
        self._lead_buf = ""
        self._in_string = False
        self._escape = False
        self._in_unicode = False
        self._unicode_buf = ""
        self._high_surrogate: int | None = None
        self._key_buf = ""
        self._last_top_key = ""
        self._out_buf: list[str] = []

    def _emit_char(self, ch: str) -> None:
        if self._high_surrogate is not None:
            # Unpaired high surrogate followed by normal character -> replace safely.
            self._out_buf.append("\ufffd")
            self._high_surrogate = None
        self._out_buf.append(ch)

    def _handle_unicode_escape(self, ch: str) -> None:
        self._unicode_buf += ch
        if len(self._unicode_buf) < 4:
            return
        hex_code = self._unicode_buf
        self._unicode_buf = ""
        self._escape = False
        try:
            code_pt = int(hex_code, 16)
        except ValueError:
            self._emit_char("\\")
            self._emit_char("u")
            for c in hex_code:
                self._emit_char(c)
            return

        if 0xD800 <= code_pt <= 0xDBFF:
            if self._high_surrogate is not None:
                self._out_buf.append("\ufffd")
            self._high_surrogate = code_pt
            return
        if 0xDC00 <= code_pt <= 0xDFFF and self._high_surrogate is not None:
            combined = 0x10000 + ((self._high_surrogate - 0xD800) << 10) + (code_pt - 0xDC00)
            self._high_surrogate = None
            self._out_buf.append(chr(combined))
            return
        if self._high_surrogate is not None:
            self._out_buf.append("\ufffd")
            self._high_surrogate = None
        if 0xD800 <= code_pt <= 0xDFFF:
            self._out_buf.append("\ufffd")
        else:
            self._out_buf.append(chr(code_pt))

    def _handle_escape_char(self, ch: str) -> None:
        if self._unicode_buf or ch == "u":
            if not self._unicode_buf and ch == "u":
                # Wait for 4 hex digits
                self._unicode_buf = ""
                # Use sentinel flag by checking self._in_unicode
                return
        esc_map = {
            '"': '"',
            "\\": "\\",
            "/": "/",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
        }
        self._escape = False
        self._emit_char(esc_map.get(ch, ch))

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        self._out_buf.clear()
        for ch in chunk:
            if self._mode == "done":
                continue

            if self._mode == "plain":
                self._out_buf.append(ch)
                continue

            if self._mode == "init":
                if ch.isspace():
                    self._lead_buf += ch
                    continue
                if ch == "{":
                    self._lead_buf = ""
                    self._depth = 1
                    self._mode = "json_key_seek"
                    continue
                if ch == "`":
                    self._lead_buf += ch
                    if len(self._lead_buf.lstrip()) >= 3 and self._lead_buf.lstrip().startswith("```"):
                        self._mode = "fence_hdr"
                    continue
                # Plain text output (not JSON envelope)
                self._out_buf.append(self._lead_buf + ch)
                self._lead_buf = ""
                self._mode = "plain"
                continue

            if self._mode == "fence_hdr":
                if ch == "{":
                    self._lead_buf = ""
                    self._depth = 1
                    self._mode = "json_key_seek"
                    continue
                if ch == "\n":
                    self._lead_buf += ch
                    continue
                self._lead_buf += ch
                stripped = self._lead_buf.strip()
                if stripped.startswith("```") and len(stripped) > 12 and "{" not in stripped:
                    # Non-JSON fenced output
                    self._out_buf.append(self._lead_buf)
                    self._lead_buf = ""
                    self._mode = "plain"
                continue

            if self._mode == "summary":
                if getattr(self, "_in_unicode", False):
                    self._unicode_buf += ch
                    if len(self._unicode_buf) == 4:
                        self._in_unicode = False
                        self._handle_unicode_escape("")
                    continue
                if self._escape:
                    if ch == "u":
                        self._in_unicode = True
                        self._unicode_buf = ""
                    else:
                        self._handle_escape_char(ch)
                    continue
                if ch == "\\":
                    self._escape = True
                    continue
                if ch == '"':
                    if self._high_surrogate is not None:
                        self._out_buf.append("\ufffd")
                        self._high_surrogate = None
                    self._mode = "done"
                    continue
                self._emit_char(ch)
                continue

            # JSON_SCAN states at various depths
            if self._in_string:
                if self._escape:
                    self._escape = False
                    if self._mode == "key":
                        self._key_buf += {'"': '"', "\\": "\\", "/": "/", "n": "\n", "t": "\t"}.get(ch, ch)
                    continue
                if ch == "\\":
                    self._escape = True
                    continue
                if ch == '"':
                    self._in_string = False
                    if self._mode == "key":
                        self._last_top_key = self._key_buf
                        self._key_buf = ""
                        self._mode = "after_key"
                    continue
                if self._mode == "key":
                    self._key_buf += ch
                continue

            # Outside string inside JSON
            if ch.isspace():
                continue
            if ch == '"':
                if self._depth == 1 and self._mode == "json_key_seek":
                    self._in_string = True
                    self._key_buf = ""
                    self._mode = "key"
                elif self._depth == 1 and self._mode == "colon" and self._last_top_key == "summary":
                    self._mode = "summary"
                    self._escape = False
                    self._in_unicode = False
                else:
                    self._in_string = True
                    if self._depth == 1 and self._mode == "colon":
                        self._mode = "json_key_seek"
                continue
            if ch == ":":
                if self._depth == 1 and self._mode == "after_key":
                    self._mode = "colon"
                continue
            if ch in "{[":
                self._depth += 1
                self._mode = "json_key_seek"
                continue
            if ch in "}]":
                self._depth = max(0, self._depth - 1)
                if self._depth == 0:
                    self._mode = "done"
                elif self._depth == 1:
                    self._mode = "json_key_seek"
                continue
            if ch == "," and self._depth == 1:
                self._last_top_key = ""
                self._mode = "json_key_seek"
                continue
            if self._depth == 1 and self._mode == "colon":
                # Non-string value for top-level key (e.g., actions: [...])
                self._mode = "json_key_seek"

        return "".join(self._out_buf)

    def finish(self) -> str:
        out: list[str] = []
        if self._mode in {"init", "fence_hdr"} and self._lead_buf:
            out.append(self._lead_buf)
            self._lead_buf = ""
        if self._high_surrogate is not None:
            out.append("\ufffd")
            self._high_surrogate = None
        return "".join(out)


@dataclass(slots=True)
class QueuedTurnItem:
    """Tracked async chat/Room execution unit supporting live streaming, follow-up queueing & cancellation."""

    run_id: str
    thread_key: str
    target_type: str  # "bot" | "room"
    target_slug: str
    correlation_id: str
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    done_event: asyncio.Event = field(default_factory=asyncio.Event)
    status: str = "queued"
    bot_slug: str = ""
    bot_name: str = ""
    routed_reason: str = ""
    routing_source: str = ""
    partial_text: str = ""
    chips: list[dict[str, Any]] = field(default_factory=list)
    message_id: str | None = None
    work: Callable[[QueuedTurnItem], Awaitable[dict[str, Any]]] | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


def _extract_json_envelope(raw_text: str) -> dict[str, Any] | None:
    cleaned = (raw_text or "").strip()
    if not cleaned:
        return None
    candidates = [cleaned]
    fence_match = _JSON_FENCE_RE.search(cleaned)
    if fence_match:
        candidates.insert(0, fence_match.group(1).strip())
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidates.append(cleaned[first_brace : last_brace + 1])

    for cand in candidates:
        try:
            parsed = json.loads(cand)
            if isinstance(parsed, dict) and (
                "actions" in parsed or "summary" in parsed or "emit_event" in parsed
            ):
                return parsed
        except Exception:
            continue
    return None


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _normalize_action_type(raw_type: Any) -> str:
    cleaned = str(raw_type or "").strip().lower()
    return _ACTION_TYPE_ALIASES.get(cleaned, cleaned)


def _extract_action_text(action: dict[str, Any]) -> str:
    keys = ("text", "message", "summary", "body", "content", "draft", "commentary")
    for key in keys:
        val = str(action.get(key) or "").strip()
        if val:
            return val
    payload_obj = action.get("payload")
    if isinstance(payload_obj, dict):
        for key in keys:
            val = str(payload_obj.get(key) or "").strip()
            if val:
                return val
    return ""


class UniversalBotRunner:
    """Executes declarative JSON bots with mutex locks, context isolation, and hop_count <= 5."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        llm_router: LLMRouter,
        approval_coordinator: ApprovalCoordinator,
        http_fetcher: PublicHttpFetcher | None = None,
        desktop_manager: DesktopManager | None = None,
        cdp_bridge: ChromeDevToolsBridge | None = None,
        desktop_mcp_bridge: DesktopMCPBridge | None = None,
        guard: Any = None,
        google_service: Any | None = None,
        debug_buffer: Any | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._llm_router = llm_router
        self._approvals = approval_coordinator
        self._http_fetcher: PublicHttpFetcher = http_fetcher or SafePublicHttpFetcher()
        self._desktop_manager = desktop_manager
        self._cdp_bridge = cdp_bridge
        self._desktop_mcp = desktop_mcp_bridge or (
            DesktopMCPBridge(desktop_manager, bus=bus) if desktop_manager is not None else None
        )
        self._guard = guard
        self._google = google_service
        self._debug_buffer = debug_buffer
        self._bot_scheduler: Any = None

        self._running = False
        self._consumer_task: asyncio.Task[None] | None = None
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._sub_queue: asyncio.Queue[dict[str, Any]] | None = None
        self._inflight = 0
        self._idle_event = asyncio.Event()
        self._idle_event.set()
        self._ready_event = asyncio.Event()
        self._active_runs: dict[str, dict[str, str]] = {}
        self._runs_by_id: dict[str, QueuedTurnItem] = {}
        self._thread_queues: dict[str, asyncio.Queue[QueuedTurnItem]] = {}
        self._thread_workers: dict[str, asyncio.Task[None]] = {}
        self._active_run_by_thread: dict[str, QueuedTurnItem] = {}

    def attach_scheduler(self, scheduler: Any) -> None:
        """Bind BotScheduler so platform_status context includes live scheduled jobs."""
        self._bot_scheduler = scheduler

    def active_runs(self) -> dict[str, dict[str, str]]:
        """Return currently running bot execution states keyed by bot slug."""
        return dict(self._active_runs)

    async def _emit_turn_stream(self, event_payload: dict[str, Any]) -> None:
        emit_eph = getattr(self._bus, "emit_ephemeral", None)
        if callable(emit_eph):
            try:
                await emit_eph("turn_stream", event_payload)
            except Exception:
                logger.debug("Unable to emit turn_stream event", exc_info=True)

    def _prune_finished_runs(self) -> None:
        if len(self._runs_by_id) <= 120:
            return
        finished_ids = [
            rid
            for rid, item in self._runs_by_id.items()
            if item.status in {"completed", "cancelled", "error"}
        ]
        for rid in finished_ids[:-60]:
            self._runs_by_id.pop(rid, None)

    def enqueue_thread_turn(
        self,
        *,
        thread_key: str,
        target_type: str,
        target_slug: str,
        correlation_id: str,
        bot_slug: str,
        bot_name: str,
        work: Callable[[QueuedTurnItem], Awaitable[dict[str, Any]]],
    ) -> tuple[QueuedTurnItem, int]:
        """Enqueue a non-blocking chat or Room turn sequentially under thread_key."""
        queue = self._thread_queues.setdefault(thread_key, asyncio.Queue())
        active_item = self._active_run_by_thread.get(thread_key)
        queued_behind = queue.qsize() + (1 if active_item is not None else 0)
        run_item = QueuedTurnItem(
            run_id=make_id("run"),
            thread_key=thread_key,
            target_type=target_type,
            target_slug=target_slug,
            correlation_id=correlation_id,
            bot_slug=bot_slug,
            bot_name=bot_name,
            work=work,
        )
        self._runs_by_id[run_item.run_id] = run_item
        self._prune_finished_runs()
        self._inc_inflight()
        queue.put_nowait(run_item)
        if thread_key not in self._thread_workers or self._thread_workers[thread_key].done():
            worker = asyncio.create_task(self._thread_worker_loop(thread_key))
            self._thread_workers[thread_key] = worker
            self._active_tasks.add(worker)
            worker.add_done_callback(self._active_tasks.discard)
        return run_item, queued_behind

    async def _thread_worker_loop(self, thread_key: str) -> None:
        queue = self._thread_queues.get(thread_key)
        if queue is None:
            return
        try:
            while self._running or not queue.empty():
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    if queue.empty():
                        break
                    continue

                if item.cancel_event.is_set():
                    item.status = "cancelled"
                    await self._emit_turn_stream(
                        {
                            "type": "run_cancelled",
                            "run_id": item.run_id,
                            "thread_key": item.thread_key,
                            "target_type": item.target_type,
                            "target_slug": item.target_slug,
                            "bot_slug": item.bot_slug,
                            "message_id": item.message_id,
                            "status": "cancelled",
                        }
                    )
                    item.done_event.set()
                    queue.task_done()
                    self._dec_inflight()
                    continue

                self._active_run_by_thread[thread_key] = item
                item.status = "running"
                try:
                    if item.target_type == "bot":
                        await self._emit_turn_stream(
                            {
                                "type": "run_started",
                                "run_id": item.run_id,
                                "thread_key": item.thread_key,
                                "target_type": item.target_type,
                                "target_slug": item.target_slug,
                                "bot_slug": item.bot_slug,
                                "bot_name": item.bot_name,
                                "routed_reason": item.routed_reason,
                                "routing_source": item.routing_source,
                            }
                        )
                    assert item.work is not None
                    res = await item.work(item)
                    item.result = res
                    if item.cancel_event.is_set() or res.get("status") == "cancelled":
                        item.status = "cancelled"
                        await self._emit_turn_stream(
                            {
                                "type": "run_cancelled",
                                "run_id": item.run_id,
                                "thread_key": item.thread_key,
                                "target_type": item.target_type,
                                "target_slug": item.target_slug,
                                "bot_slug": item.bot_slug,
                                "message_id": item.message_id,
                                "status": "cancelled",
                            }
                        )
                    else:
                        item.status = "completed"
                        await self._emit_turn_stream(
                            {
                                "type": "run_finished",
                                "run_id": item.run_id,
                                "thread_key": item.thread_key,
                                "target_type": item.target_type,
                                "target_slug": item.target_slug,
                                "bot_slug": item.bot_slug,
                                "message_id": item.message_id,
                                "status": str(res.get("status") or "completed"),
                            }
                        )
                except asyncio.CancelledError:
                    item.status = "cancelled"
                    await self._emit_turn_stream(
                        {
                            "type": "run_cancelled",
                            "run_id": item.run_id,
                            "thread_key": item.thread_key,
                            "target_type": item.target_type,
                            "target_slug": item.target_slug,
                            "bot_slug": item.bot_slug,
                            "message_id": item.message_id,
                            "status": "cancelled",
                        }
                    )
                    raise
                except Exception as exc:
                    item.status = "error"
                    item.error = redact_secrets(str(exc), self._repo.collect_all_vault_secret_values())
                    logger.exception("Queued turn %s failed: %s", item.run_id, item.error)
                    await self._emit_turn_stream(
                        {
                            "type": "run_finished",
                            "run_id": item.run_id,
                            "thread_key": item.thread_key,
                            "target_type": item.target_type,
                            "target_slug": item.target_slug,
                            "bot_slug": item.bot_slug,
                            "message_id": item.message_id,
                            "status": "error",
                            "error": item.error,
                        }
                    )
                finally:
                    if self._active_run_by_thread.get(thread_key) is item:
                        self._active_run_by_thread.pop(thread_key, None)
                    item.done_event.set()
                    queue.task_done()
                    self._dec_inflight()
        finally:
            if self._thread_workers.get(thread_key) is asyncio.current_task():
                self._thread_workers.pop(thread_key, None)

    async def cancel_run(self, run_id: str, *, wait_timeout: float = 2.0) -> QueuedTurnItem | None:
        """Signal cancellation on an active or queued run and await clean teardown."""
        item = self._runs_by_id.get(run_id)
        if item is None:
            return None
        item.cancel_event.set()
        if not item.done_event.is_set():
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(item.done_event.wait(), timeout=wait_timeout)
        return item

    async def cancel_thread_runs(self, thread_key: str) -> None:
        """Cancel active and queued turns belonging to a deleted bot or room thread."""
        active = self._active_run_by_thread.get(thread_key)
        if active is not None:
            active.cancel_event.set()
        for item in list(self._runs_by_id.values()):
            if item.thread_key == thread_key and item.status in {"queued", "running"}:
                item.cancel_event.set()
        if active is not None and not active.done_event.is_set():
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(active.done_event.wait(), timeout=1.5)

    async def _emit_progress(
        self,
        bot_slug: str,
        state: str,
        step: str,
        correlation_id: str,
    ) -> None:
        if state == "running":
            self._active_runs[bot_slug] = {
                "step": step,
                "started_at": utc_now(),
                "correlation_id": correlation_id,
            }
        else:
            self._active_runs.pop(bot_slug, None)
        emit_fn = getattr(self._bus, "emit_progress", None)
        if callable(emit_fn):
            try:
                await emit_fn(bot_slug, state, step, correlation_id)
            except Exception:
                logger.debug("Unable to emit progress for %s", bot_slug, exc_info=True)

    def _inc_inflight(self) -> None:
        self._inflight += 1
        self._idle_event.clear()

    def _dec_inflight(self) -> None:
        self._inflight = max(0, self._inflight - 1)
        if self._inflight == 0:
            self._idle_event.set()

    async def start(self) -> None:
        """Start the background EventBus subscriber for composable on_event chains."""
        if self._running:
            return
        self._running = True
        self._ready_event.clear()
        self._consumer_task = asyncio.create_task(self._event_loop())
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._ready_event.wait(), timeout=2.0)

    async def stop(self) -> None:
        """Stop the EventBus consumer and cancel/drain in-flight bot tasks."""
        self._running = False
        for item in list(self._runs_by_id.values()):
            if item.status in {"queued", "running"}:
                item.cancel_event.set()
        if self._consumer_task is not None:
            self._consumer_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._consumer_task
            self._consumer_task = None
        for task in list(self._active_tasks):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        self._active_tasks.clear()
        self._thread_workers.clear()
        self._active_run_by_thread.clear()
        self._inflight = 0
        self._sub_queue = None
        self._idle_event.set()

    async def wait_for_idle(self, timeout: float = 10.0) -> bool:
        """Wait until all queued EventBus events and chained bot runs finish."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            await asyncio.sleep(0)
            queue_pending = self._sub_queue is not None and not self._sub_queue.empty()
            if self._inflight == 0 and not queue_pending:
                return True
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            if self._inflight > 0:
                try:
                    await asyncio.wait_for(self._idle_event.wait(), timeout=min(0.1, remaining))
                except asyncio.TimeoutError:
                    pass
            else:
                await asyncio.sleep(min(0.01, remaining))

    async def _event_loop(self) -> None:
        async with self._bus.subscribe() as queue:
            self._sub_queue = queue
            self._ready_event.set()
            try:
                while self._running:
                    event = await queue.get()
                    self._dispatch_event(event)
                    while not queue.empty():
                        self._dispatch_event(queue.get_nowait())
            except asyncio.CancelledError:
                raise
            finally:
                self._sub_queue = None

    def _find_matching_bots(self, event: dict[str, Any]) -> list[tuple[dict[str, Any], str, str | None]]:
        if event.get("_sse_event"):
            return []
        event_type = str(event.get("event_type") or "")
        if not event_type or event_type.startswith(_INTERNAL_EVENT_PREFIXES):
            return []

        source_slug = str(event.get("source_slug") or "")
        target_slug = event.get("target_slug")
        matches: list[tuple[dict[str, Any], str, str | None]] = []

        for bot in self._repo.list_bots():
            if not bot["enabled"] or bot["slug"] == source_slug:
                continue

            if event_type == "operator.instruction":
                if target_slug == bot["slug"]:
                    matches.append((bot, "operator_event", None))
                continue

            for routine in bot.get("routines", []):
                if not isinstance(routine, dict) or not routine.get("enabled", True):
                    continue
                r_type = str(routine.get("type") or "")
                r_event = str(
                    routine.get("event")
                    or routine.get("trigger")
                    or routine.get("topic")
                    or ""
                ).strip()
                if (r_type == "on_event" or r_event) and r_event == event_type:
                    if event_type == "approval.queued":
                        ev_payload = event.get("payload") or {}
                        if str(ev_payload.get("source_notifier") or "") == bot["slug"]:
                            continue
                    matches.append((bot, f"on_event:{event_type}", routine.get("id")))
                    break
        return matches

    def _dispatch_event(self, event: dict[str, Any]) -> None:
        matches = self._find_matching_bots(event)
        if not matches:
            return
        payload = event.get("payload") or {}
        hop_count = int(payload.get("hop_count") or 1)
        corr_id = str(event.get("correlation_id") or make_id("corr"))

        for bot, trigger_type, routine_id in matches:
            self._inc_inflight()
            task = asyncio.create_task(
                self._run_chained_bot(
                    bot_slug=bot["slug"],
                    trigger_type=trigger_type,
                    correlation_id=corr_id,
                    hop_count=hop_count,
                    trigger_payload=payload,
                    routine_id=routine_id,
                )
            )
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)

    async def _run_chained_bot(
        self,
        *,
        bot_slug: str,
        trigger_type: str,
        correlation_id: str,
        hop_count: int,
        trigger_payload: dict[str, Any],
        routine_id: str | None,
    ) -> None:
        try:
            await self.execute_bot(
                bot_slug,
                trigger_type=trigger_type,
                correlation_id=correlation_id,
                hop_count=hop_count,
                trigger_payload=trigger_payload,
                routine_id=routine_id,
            )
        except Exception as exc:
            logger.exception("Chained bot '%s' failed: %s", bot_slug, exc)
        finally:
            self._dec_inflight()

    @staticmethod
    def _is_account_permitted(bot: dict[str, Any], account_slug: str) -> bool:
        """Restrict bots to explicitly linked accounts when linked_accounts/tools are configured."""
        clean_target = slugify(account_slug)
        account_tools = {
            slugify(str(t.get("slug") or t.get("account") or ""))
            for t in (bot.get("tools") or [])
            if isinstance(t, dict)
            and t.get("type") in {"account", "connector"}
            and str(t.get("slug") or t.get("account") or "").strip()
        }
        explicit_linked = bot.get("linked_accounts")
        if bot.get("linked_accounts_restricted") and isinstance(explicit_linked, list):
            allowed = {slugify(str(a)) for a in explicit_linked if str(a).strip()} | account_tools
            return clean_target in allowed
        if account_tools:
            return clean_target in account_tools
        return True

    async def _publish_unlinked_account_block(
        self,
        *,
        bot: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        action_type: str,
        account_slug: str,
    ) -> dict[str, Any]:
        allowed = list(bot.get("linked_accounts") or [])
        msg = (
            f"Bot '{bot['slug']}' is not linked to integration '{account_slug}' "
            f"(linked accounts: {', '.join(allowed) or 'none'})."
        )
        await self._bus.publish(
            correlation_id=correlation_id,
            source_slug=bot["slug"],
            target_slug=account_slug,
            event_type="connector.blocked",
            payload={
                "category": "alerts",
                "title": f"Account Isolation Blocked ({bot['name']})",
                "badge": "Account Isolation",
                "badge_tone": "red",
                "summary": msg,
                "meta": f"Action: {action_type}",
            },
            hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
        )
        return {
            "type": action_type,
            "status": "blocked_unlinked_account",
            "account": account_slug,
            "detail": msg,
        }

    _VAULT_ENV_PREFIX_RE = re.compile(r"\$(?:\{)?ARGO_VAULT_([A-Z0-9_]+?)_[A-Z0-9_]+\}?")
    _VAULT_TYPE_TEMPLATE_RE = re.compile(r"\{\{vault:([a-z0-9-]+)\.([a-z0-9_]+)\}\}", re.IGNORECASE)
    _VAULT_MENTION_RE = re.compile(r"@(?:vault:)?([a-z0-9][a-z0-9-]{0,62})\b", re.IGNORECASE)

    @staticmethod
    def _is_vault_permitted(bot: dict[str, Any], vault_meta: dict[str, Any]) -> bool:
        raw_allowed = vault_meta.get("allowed_bots")
        if raw_allowed is None:
            return True
        if not isinstance(raw_allowed, list):
            return False
        allowed = [str(b).strip() for b in raw_allowed if str(b).strip()]
        return "*" in allowed or bot["slug"] in allowed

    def _permitted_vault_secrets(self, bot: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            item for item in self._repo.list_vault_secrets() if self._is_vault_permitted(bot, item)
        ]

    @staticmethod
    def _scrub_vault_observation(res: dict[str, Any], secrets_to_scrub: list[str]) -> dict[str, Any]:
        if not secrets_to_scrub:
            return res
        cleaned = dict(res)
        for key in ("stdout", "stderr", "detail", "failed_command", "command"):
            if isinstance(cleaned.get(key), str) and cleaned[key]:
                cleaned[key] = redact_secrets(cleaned[key], secrets_to_scrub)
        if isinstance(cleaned.get("steps"), list):
            new_steps: list[Any] = []
            for step in cleaned["steps"]:
                if isinstance(step, dict):
                    s = dict(step)
                    for k in ("stdout", "stderr", "command"):
                        if isinstance(s.get(k), str) and s[k]:
                            s[k] = redact_secrets(s[k], secrets_to_scrub)
                    new_steps.append(s)
                else:
                    new_steps.append(step)
            cleaned["steps"] = new_steps
        return cleaned

    async def _resolve_vault_for_desktop_action(
        self,
        *,
        bot: dict[str, Any],
        a_type: str,
        action: dict[str, Any],
        correlation_id: str,
        hop_count: int,
    ) -> tuple[dict[str, str], dict[str, str], list[str], dict[str, Any] | None]:
        all_vault = self._repo.list_vault_secrets()
        by_slug = {v["slug"]: v for v in all_vault}
        prefix_to_slug = {
            ArgoRepository.vault_env_prefix(v["slug"]).removeprefix("ARGO_VAULT_"): v["slug"]
            for v in all_vault
        }

        requested_slugs: list[str] = []
        raw_explicit = action.get("vault_secrets")
        if isinstance(raw_explicit, list):
            for s in raw_explicit:
                if str(s).strip():
                    requested_slugs.append(slugify(str(s)))
        elif isinstance(raw_explicit, str) and raw_explicit.strip():
            requested_slugs.append(slugify(raw_explicit))

        cmd_parts: list[str] = []
        if isinstance(action.get("command"), str):
            cmd_parts.append(action["command"])
        if isinstance(action.get("commands"), list):
            cmd_parts.extend(str(c) for c in action["commands"] if c)
        combined_cmds = "\n".join(cmd_parts)
        for m in self._VAULT_ENV_PREFIX_RE.finditer(combined_cmds):
            pref = m.group(1)
            for candidate_pref, cand_slug in sorted(prefix_to_slug.items(), key=lambda kv: -len(kv[0])):
                if pref == candidate_pref or pref.startswith(candidate_pref + "_"):
                    requested_slugs.append(cand_slug)
                    break

        text_val = str(action.get("text") or "")
        for m in self._VAULT_TYPE_TEMPLATE_RE.finditer(text_val):
            requested_slugs.append(slugify(m.group(1)))

        requested_slugs = list(dict.fromkeys(s for s in requested_slugs if s))
        env_vars: dict[str, str] = {}
        placeholder_values: dict[str, str] = {}
        secret_values: list[str] = []

        for v_slug in requested_slugs:
            meta = by_slug.get(v_slug)
            if meta is None:
                continue
            if not self._is_vault_permitted(bot, meta):
                msg = (
                    f"Bot '{bot['slug']}' does not have permission to use Vault secret '@{v_slug}'."
                )
                await self._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=v_slug,
                    event_type="connector.blocked",
                    payload={
                        "category": "alerts",
                        "title": f"Vault Access Blocked ({bot['name']})",
                        "badge": "Vault ACL",
                        "badge_tone": "red",
                        "summary": msg,
                        "meta": f"Action: {a_type}",
                    },
                    hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                )
                return {}, {}, [], {"type": a_type, "status": "blocked_vault_acl", "vault_slug": v_slug, "detail": msg}

            decrypted = self._repo.get_vault_secret_decrypted(v_slug)
            if decrypted is None:
                continue
            prefix = ArgoRepository.vault_env_prefix(v_slug)
            if decrypted.get("host"):
                env_vars[f"{prefix}_HOST"] = str(decrypted["host"])
            if decrypted.get("port"):
                env_vars[f"{prefix}_PORT"] = str(decrypted["port"])
            if decrypted.get("url"):
                env_vars[f"{prefix}_URL"] = str(decrypted["url"])
            for k, raw_val in (decrypted.get("secrets") or {}).items():
                val = str(raw_val)
                if not val:
                    continue
                k_clean = str(k).strip().lower()
                k_upper = re.sub(r"[^A-Z0-9]+", "_", k_clean.upper()).strip("_")
                env_vars[f"{prefix}_{k_upper}"] = val
                if k_clean in {"username", "user"}:
                    env_vars[f"{prefix}_USER"] = val
                    env_vars[f"{prefix}_USERNAME"] = val
                if k_clean == "password":
                    env_vars.setdefault("SSHPASS", val)
                placeholder_values[f"{v_slug}.{k_clean}"] = val
                if len(val.strip()) >= 4:
                    secret_values.append(val.strip())

        return env_vars, placeholder_values, secret_values, None

    def _resolve_action_account_slug(
        self,
        bot: dict[str, Any],
        action: dict[str, Any],
        *,
        preferred_provider: str | None = None,
    ) -> tuple[str, bool]:
        """Resolve an integration slug from explicit aliases/handles or bot's permitted connectors."""
        raw_candidate = str(
            action.get("account")
            or action.get("account_slug")
            or action.get("target_account_slug")
            or action.get("integration")
            or ""
        ).strip()
        if not raw_candidate and isinstance(action.get("payload"), dict):
            nested = action["payload"]
            raw_candidate = str(
                nested.get("account")
                or nested.get("account_slug")
                or nested.get("target_account_slug")
                or nested.get("integration")
                or ""
            ).strip()

        all_integrations = self._repo.list_integrations()

        if raw_candidate:
            raw_lower = raw_candidate.lower().lstrip("@")
            raw_slug = slugify(raw_candidate)

            def _matches(acc: dict[str, Any]) -> bool:
                acc_slug = str(acc.get("slug") or "")
                disp = str(acc.get("display_name") or "")
                ident = str(acc.get("account_identifier") or "")
                return (
                    acc_slug == raw_candidate
                    or slugify(acc_slug) == raw_slug
                    or disp.strip().lower() == raw_candidate.lower()
                    or slugify(disp) == raw_slug
                    or (bool(ident) and ident.strip().lower().lstrip("@") == raw_lower)
                    or (bool(ident) and slugify(ident) == raw_slug)
                )

            permitted_matches = [
                acc
                for acc in all_integrations
                if _matches(acc) and self._is_account_permitted(bot, acc["slug"])
            ]
            if permitted_matches:
                return permitted_matches[0]["slug"], True
            any_matches = [acc for acc in all_integrations if _matches(acc)]
            if any_matches:
                return any_matches[0]["slug"], True
            return raw_candidate, True

        permitted = [
            acc for acc in all_integrations if self._is_account_permitted(bot, acc["slug"])
        ]
        if preferred_provider:
            candidates = [acc for acc in permitted if acc["provider"] == preferred_provider]
            non_expired = [acc for acc in candidates if acc["status"] != "expired"]
            candidates = non_expired or candidates
        else:
            non_expired = [acc for acc in permitted if acc["status"] != "expired"]
            candidates = non_expired or permitted

        if candidates:
            return candidates[0]["slug"], False

        if preferred_provider == "telegram" and not bot.get("linked_accounts_restricted"):
            tg_candidates = [
                acc
                for acc in all_integrations
                if acc["provider"] == "telegram" and acc["status"] != "expired"
            ]
            if tg_candidates:
                return tg_candidates[0]["slug"], False

        return "", False

    def _collect_ingestion_sources(
        self,
        bot: dict[str, Any],
        *,
        routine_id: str | None,
        trigger_payload: dict[str, Any],
    ) -> dict[str, list[str]]:
        if trigger_payload.get("from_chat_thread"):
            return {"feeds": [], "webpages": [], "tg_channels": []}

        feeds: list[str] = []
        webpages: list[str] = []
        tg_channels: list[str] = []

        feeds.extend(_str_list(trigger_payload.get("feed_url")))
        feeds.extend(_str_list(trigger_payload.get("feed_urls")))
        webpages.extend(_str_list(trigger_payload.get("webpage_url")))
        webpages.extend(_str_list(trigger_payload.get("webpage_urls")))
        tg_channels.extend(_str_list(trigger_payload.get("public_channel")))
        tg_channels.extend(_str_list(trigger_payload.get("telegram_public_channels")))

        is_on_event_routine = False
        for routine in bot.get("routines", []):
            if not isinstance(routine, dict) or not routine.get("enabled", True):
                continue
            if routine_id is not None and routine.get("id") != routine_id:
                continue
            if (
                str(routine.get("trigger_type") or "") == "on_event"
                or str(routine.get("type") or "") == "on_event"
                or bool(routine.get("event"))
            ):
                is_on_event_routine = True
            feeds.extend(_str_list(routine.get("feed_url")))
            feeds.extend(_str_list(routine.get("feed_urls")))
            webpages.extend(_str_list(routine.get("webpage_url")))
            webpages.extend(_str_list(routine.get("webpage_urls")))
            tg_channels.extend(_str_list(routine.get("public_channel")))
            tg_channels.extend(_str_list(routine.get("telegram_public_channels")))

        gmail_accounts: list[dict[str, str]] = []
        explicit_gmail_query = ""
        for tool in bot.get("tools", []):
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "")
            if name == "fetch_rss_feed":
                feeds.extend(_str_list(tool.get("url")))
                feeds.extend(_str_list(tool.get("urls")))
            elif name == "fetch_public_webpage":
                webpages.extend(_str_list(tool.get("url")))
                webpages.extend(_str_list(tool.get("urls")))
            elif name == "fetch_telegram_public_channel":
                tg_channels.extend(_str_list(tool.get("channel")))
                tg_channels.extend(_str_list(tool.get("channels")))
            elif name == "gmail_search" and str(tool.get("query") or "").strip():
                explicit_gmail_query = str(tool.get("query")).strip()

        for routine in bot.get("routines", []):
            if not isinstance(routine, dict) or not routine.get("enabled", True):
                continue
            if routine_id is not None and routine.get("id") != routine_id:
                continue
            if str(routine.get("gmail_query") or "").strip():
                explicit_gmail_query = str(routine.get("gmail_query")).strip()

        if not feeds and not webpages and not is_on_event_routine and not trigger_payload:
            for raw_url in _URL_RE.findall(str(bot.get("role_prompt") or "")):
                cleaned = raw_url.rstrip(".,;:!?)")
                lowered = cleaned.lower()
                if (
                    lowered.endswith((".xml", ".rss", ".atom"))
                    or "/feed" in lowered
                    or "/rss" in lowered
                ):
                    feeds.append(cleaned)
                else:
                    webpages.append(cleaned)

        lower_prompt = str(bot.get("role_prompt") or "").lower()
        uses_gmail = any(
            isinstance(t, dict) and t.get("name") == "gmail_search"
            for t in (bot.get("tools") or [])
        ) or (
            not is_on_event_routine
            and any(kw in lower_prompt for kw in ("gmail", "email", "inbox", "mail"))
        )
        if uses_gmail and self._google is not None and bot.get("runtime", "api") == "api":
            for acc in self._repo.list_integrations():
                if (
                    acc.get("provider") == "google"
                    and acc.get("status") != "expired"
                    and self._is_account_permitted(bot, acc["slug"])
                ):
                    gmail_accounts.append(
                        {
                            "account_slug": acc["slug"],
                            "query": explicit_gmail_query,
                        }
                    )

        return {
            "feeds": list(dict.fromkeys(feeds)),
            "webpages": list(dict.fromkeys(webpages)),
            "tg_channels": list(dict.fromkeys(tg_channels)),
            "gmail_accounts": gmail_accounts,
        }

    async def _poll_ingestion_sources(
        self,
        *,
        bot: dict[str, Any],
        bot_slug: str,
        correlation_id: str,
        sources: dict[str, Any],
        write_collections: list[str],
        is_background_poll: bool = False,
    ) -> tuple[bool, list[dict[str, Any]], int]:
        """Fetch RSS, webpage (with RSS auto-discovery), public Telegram, and incremental Gmail sources."""
        gmail_accounts = (
            list(sources.get("gmail_accounts") or []) if is_background_poll else []
        )
        had_sources = bool(
            sources.get("feeds")
            or sources.get("webpages")
            or sources.get("tg_channels")
            or gmail_accounts
        )
        unseen_entries: list[dict[str, Any]] = []
        total_fetched = 0
        dedup_skipped = 0
        primary_write_col = write_collections[0] if write_collections else None
        seen_feed_urls: set[str] = set()

        async def _ingest_rss(feed_url: str, *, source_type: str, page_url: str | None = None) -> None:
            nonlocal total_fetched
            if feed_url in seen_feed_urls:
                return
            seen_feed_urls.add(feed_url)
            feed_res = await fetch_rss_feed(
                feed_url,
                repo=self._repo,
                bus=self._bus,
                fetcher=self._http_fetcher,
                correlation_id=correlation_id,
                source_slug=bot_slug,
            )
            for entry in feed_res.get("entries", []):
                total_fetched += 1
                ext_key = str(entry.get("external_key") or "")
                if ext_key and self._repo.is_ingestion_key_seen(
                    bot_slug, ext_key, primary_write_col
                ):
                    continue
                item = {"source_type": source_type, "feed_url": feed_url, **entry}
                if page_url:
                    item["page_url"] = page_url
                unseen_entries.append(item)

        for feed_url in sources["feeds"]:
            await _ingest_rss(feed_url, source_type="rss")

        for page_url in sources["webpages"]:
            fetched = await fetch_public_webpage(
                page_url,
                repo=self._repo,
                bus=self._bus,
                fetcher=self._http_fetcher,
                correlation_id=correlation_id,
                source_slug=bot_slug,
            )
            discovered_feeds = list(fetched.get("discovered_feeds") or [])
            if discovered_feeds:
                await _ingest_rss(
                    discovered_feeds[0],
                    source_type="rss_autodiscovered",
                    page_url=fetched["url"],
                )
            else:
                total_fetched += 1
                if fetched.get("not_modified"):
                    continue
                content_hash = str(fetched.get("content_hash") or "")
                ext_key = (
                    f"web:{fetched['url']}:{content_hash}"
                    if content_hash
                    else f"web:{fetched['url']}"
                )
                legacy_key = f"web:{fetched['url']}"
                already_seen = self._repo.is_ingestion_key_seen(
                    bot_slug, ext_key, primary_write_col
                ) or (
                    bool(content_hash)
                    and self._repo.is_ingestion_key_seen(
                        bot_slug, legacy_key, primary_write_col
                    )
                )
                if not already_seen:
                    unseen_entries.append(
                        {
                            "source_type": "webpage",
                            "external_key": ext_key,
                            "url": fetched["url"],
                            "title": fetched["title"],
                            "markdown": fetched["markdown"][:4000],
                        }
                    )

        for channel in sources["tg_channels"]:
            posts = await fetch_telegram_public_channel(
                channel,
                fetcher=self._http_fetcher,
                limit=20,
            )
            for post in posts:
                total_fetched += 1
                ext_key = f"tg:{post['channel']}:{post['message_id']}"
                if self._repo.is_ingestion_key_seen(bot_slug, ext_key, primary_write_col):
                    continue
                unseen_entries.append({"source_type": "telegram_public", "external_key": ext_key, **post})

        if gmail_accounts and self._google is not None:
            existing_keys = (
                self._repo.list_collection_external_keys(primary_write_col)
                if primary_write_col
                else set()
            )
            seen_cursor_keys = self._repo.list_collection_external_keys("ingestion_seen_keys")
            bot_cursor_prefix = f"{bot_slug}:"
            gmail_probe_ok = False
            for g_acc in gmail_accounts:
                acc_slug = g_acc["account_slug"]
                query = str(g_acc.get("query") or "")
                prefix = f"gmail:{acc_slug}:"
                cursor_prefix = f"{bot_cursor_prefix}{prefix}"
                exclude_ids = {
                    k[len(prefix) :]
                    for k in existing_keys
                    if k.startswith(prefix) and len(k) > len(prefix)
                } | {
                    k[len(cursor_prefix) :]
                    for k in seen_cursor_keys
                    if k.startswith(cursor_prefix) and len(k) > len(cursor_prefix)
                }
                try:
                    search_res = await self._google.search_messages(
                        acc_slug,
                        query=query,
                        max_results=15,
                        exclude_ids=exclude_ids or None,
                    )
                    gmail_probe_ok = True
                    msgs = list(search_res.get("messages") or [])
                    if not msgs and exclude_ids:
                        dedup_skipped += len(exclude_ids)
                    for msg in msgs:
                        mid = str(msg.get("id") or "").strip()
                        if not mid:
                            continue
                        ext_key = f"gmail:{acc_slug}:{mid}"
                        total_fetched += 1
                        if self._repo.is_ingestion_key_seen(bot_slug, ext_key, primary_write_col):
                            continue
                        unseen_entries.append(
                            {
                                "source_type": "gmail",
                                "external_key": ext_key,
                                "account_slug": acc_slug,
                                "message_id": mid,
                                "thread_id": msg.get("thread_id"),
                                "from": msg.get("from", ""),
                                "to": msg.get("to", ""),
                                "subject": msg.get("subject", "(No subject)"),
                                "date": msg.get("date", ""),
                                "snippet": msg.get("snippet", ""),
                                "label_ids": msg.get("label_ids") or [],
                            }
                        )
                except Exception:
                    logger.debug(
                        "Scheduled Gmail pre-poll skipped for %s/%s",
                        bot_slug,
                        acc_slug,
                        exc_info=True,
                    )
            if not gmail_probe_ok and not (
                sources.get("feeds") or sources.get("webpages") or sources.get("tg_channels")
            ):
                had_sources = False

        return had_sources, unseen_entries, dedup_skipped + max(0, total_fetched - len(unseen_entries))

    def _resolve_target_page_slug(
        self,
        bot: dict[str, Any],
        trigger_payload: dict[str, Any],
    ) -> str:
        """Resolve an existing Page slug for in-place redesign/updates during chat or page edits."""
        explicit = str(trigger_payload.get("target_page_slug") or "").strip()
        if explicit:
            try:
                return self._repo.get_page(explicit)["slug"]
            except Exception:
                return explicit

        if not trigger_payload.get("from_chat_thread"):
            return ""

        owned_pages = [
            p for p in self._repo.list_pages() if p.get("owner_bot_slug") == bot["slug"]
        ]
        if not owned_pages:
            return ""

        user_text = str(trigger_payload.get("input_text") or "").strip().lower()
        if not user_text:
            return ""
        if re.search(
            r"\b(new page|another page|second page|separate page|create a new page|build a new page|nuova pagina|altra pagina)\b",
            user_text,
        ):
            return ""

        for page_rec in owned_pages:
            p_title = str(page_rec.get("title") or "").strip().lower()
            p_slug = str(page_rec.get("slug") or "").strip().lower()
            if (p_title and p_title in user_text) or (p_slug and p_slug in user_text):
                return str(page_rec["slug"])

        wants_edit = bool(
            re.search(
                r"\b(tweak|redesign|update|edit|modify|refine|change|fix|adjust|improve|translate|rewrite|refresh|add|remove|aggiorna|modifica|cambia|sistema|ridisegna)\b",
                user_text,
            )
        )
        mentions_page = bool(
            re.search(
                r"\b(page|dashboard|pagina|view|layout|header|card|kpi|chart|table|filter|title|color|theme|design)\b",
                user_text,
            )
        )
        if wants_edit and mentions_page:
            return str(owned_pages[0]["slug"])
        return ""

    def _build_context_isolated_prompt(
        self,
        *,
        bot: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        trigger_type: str,
        trigger_payload: dict[str, Any],
        unseen_entries: list[dict[str, Any]],
        tool_observations: list[dict[str, Any]] | None = None,
        target_page_slug: str | None = None,
        synthesis_only: bool = False,
    ) -> tuple[str, str]:
        is_background_poll = trigger_type.startswith("cron") or trigger_type == "scheduled"
        read_cols = [
            collection_slug(c)
            for c in (bot.get("collections", {}).get("read") or [])
            if collection_slug(c) != "bot_threads"
        ]
        raw_write_cols = [
            collection_slug(c) for c in (bot.get("collections", {}).get("write") or [])
        ]
        data_write_cols = [c for c in raw_write_cols if c != "bot_threads"] or raw_write_cols

        context_docs: list[dict[str, Any]] = []
        ref_col = trigger_payload.get("collection")
        ref_key = trigger_payload.get("external_key")
        if ref_col and ref_key and collection_slug(str(ref_col)) in read_cols:
            matched = self._repo.get_document_by_external_key(str(ref_col), str(ref_key))
            if matched is not None:
                context_docs.append(matched)

        if not context_docs:
            write_set = set(data_write_cols)
            for col in read_cols:
                if is_background_poll and unseen_entries and col in write_set:
                    continue
                for doc in self._repo.search_documents(col, limit=5):
                    context_docs.append(doc)

        allowed_tools = [
            (
                f"{t.get('name') or t.get('slug') or t.get('account')} ({t.get('capability') or t.get('type') or 'builtin'})"
                if isinstance(t, dict)
                else str(t)
            )
            for t in (bot.get("tools") or [])
        ]
        if bot.get("runtime") == "desktop":
            if not any("desktop_browse" in item for item in allowed_tools):
                allowed_tools.append("desktop_browse (builtin)")
            if not any("desktop_mcp" in item for item in allowed_tools):
                allowed_tools.append("desktop_mcp (mcp)")

        all_integrations = self._repo.list_integrations()
        if bot.get("linked_accounts_restricted") or any(
            isinstance(t, dict) and t.get("type") in {"account", "connector"}
            for t in (bot.get("tools") or [])
        ):
            permitted_integrations = [
                acc for acc in all_integrations if self._is_account_permitted(bot, acc["slug"])
            ]
        else:
            permitted_integrations = all_integrations

        linked_integration_views = [
            {
                "slug": acc["slug"],
                "provider": acc["provider"],
                "display_name": acc["display_name"],
                "account_identifier": acc.get("account_identifier"),
                "status": acc["status"],
            }
            for acc in permitted_integrations
        ]

        style_rules = [
            r["rule_text"]
            for r in self._repo.list_style_rules()
            if r.get("scope_slug") in {bot["slug"], "*"}
        ][:15]
        recent_thread = (
            []
            if is_background_poll
            else [
                {"sender": msg["sender"], "text": msg["text"][:600]}
                for msg in self._repo.list_bot_messages(bot["slug"], limit=8)
            ]
        )

        skills_for_bot = self._repo.list_skills(scope_slug=bot["slug"])
        active_skills_payload = trigger_payload.get("active_skills") or []
        boundaries = [str(b).strip() for b in (bot.get("boundaries") or []) if str(b).strip()]
        boundaries_block = (
            "Strict Boundaries (Never Do Autonomously):\n"
            + "\n".join(f"- {b}" for b in boundaries)
            + "\n\n"
            if boundaries
            else ""
        )

        teammate_bots = [
            {
                "slug": b["slug"],
                "name": b["name"],
                "role": str(b.get("role") or "")[:160],
                "goal_metric": str(b.get("goal_metric") or "")[:120],
                "boundaries": list(b.get("boundaries") or [])[:4],
                "runtime": b.get("runtime", "api"),
            }
            for b in self._repo.list_bots()
            if b.get("enabled") and b["slug"] != bot["slug"]
        ]
        handoff_slug = str(bot.get("handoff_bot_slug") or "").strip()
        handoff_active = any(b["slug"] == handoff_slug for b in teammate_bots)

        needs_platform_status = (
            trigger_type == "on_event:telegram.message"
            or bool(trigger_payload.get("include_platform_status"))
            or any(
                (isinstance(t, dict) and str(t.get("name") or "") == "platform_status")
                or t == "platform_status"
                for t in (bot.get("tools") or [])
            )
        )

        isolation_note = (
            "- Strict account isolation: ONLY access integrations listed in linked_integrations.\n"
            if bot.get("linked_accounts_restricted")
            else ""
        )
        is_desktop = bot.get("runtime") == "desktop"
        desktop_note = (
            f"- Virtual Desktop active: this bot owns isolated Fedora XFCE container "
            f"'argo-desktop-{bot['slug']}'. You can control Chromium via desktop_browse (CDP :9222) "
            "AND control the full desktop, shell commands, apps, windows, screenshots, and mouse/keyboard via Desktop MCP (:9223): "
            "desktop_exec, desktop_inspect, desktop_screenshot, desktop_check_app, desktop_launch, "
            "desktop_focus_window, desktop_click, desktop_type, desktop_key, desktop_scroll.\n"
            "- Shell commands & installs: ALWAYS use desktop_exec for running shell commands or package installs "
            "(it shows live output on desktop AND returns exact exit_code, stdout, stderr, and failed_command) "
            "instead of typing blindly via desktop_type into a terminal.\n"
            if is_desktop
            else ""
        )
        handoff_note = (
            f"- Configured Handoff Target: '{handoff_slug}'. Whenever you find relevant/valuable items "
            f"matching your instructions, emit a delegate_to_bot action targeting '{handoff_slug}' "
            "with the full extracted details so it can craft the follow-up output. Do NOT delegate when nothing relevant was found.\n"
            if handoff_active
            else ""
        )
        onboarding_note = (
            "- Conversational Onboarding Active: the operator is shaping your setup in plain English. "
            "When they describe your job, sources, boundaries, handoff partner, or action mode, emit "
            "`update_self_config` (setting `onboarding_pending: false` once the role is clear), summarize what you updated, "
            "and offer to run a quick test in chat before scheduling a routine.\n"
            if (not is_background_poll and bot.get("onboarding_pending"))
            else ""
        )
        room_ctx = trigger_payload.get("room_context")
        room_note = (
            f"- Multi-Bot Group Room ('{room_ctx.get('room_title', room_ctx.get('room_slug', 'Room'))}'): "
            "Reply concisely directly in the Room. Stay strictly inside your own specialist role. "
            "Tag `@<member_slug>` ONLY when handing off the next stage to a teammate in `room_context.members`; "
            "do NOT message external bots unprompted.\n"
            if isinstance(room_ctx, dict)
            else ""
        )
        desktop_schemas = (
            '  * desktop_exec: {"type": "desktop_exec", "commands": ["..."], "cwd": "/config", "continue_on_error": false} '
            "(runs bash commands sequentially and returns exit_code, stdout, stderr, failed_command, and per-step status)\n"
            '  * desktop_browse: {"type": "desktop_browse", "url": "https://...", '
            '"selector": "<optional_css>", "save_to_collection": "<optional_write_collection>"}\n'
            '  * desktop_inspect: {"type": "desktop_inspect"} (inspects display, open windows, running apps, provisioning state, and Chromium status)\n'
            '  * desktop_screenshot: {"type": "desktop_screenshot", "max_width": 1280} (captures PNG screenshot and attaches visual screen to next turn)\n'
            '  * desktop_check_app: {"type": "desktop_check_app", "app": "chromium|firefox|thunar|xfce4-terminal|..."}\n'
            '  * desktop_launch: {"type": "desktop_launch", "app": "chromium|firefox|xfce4-terminal|...", "url": "<optional_public_url>", "args": [...]}\n'
            '  * desktop_focus_window / desktop_click / desktop_type / desktop_key: '
            '{"type": "desktop_click", "x": 640, "y": 420} or {"type": "desktop_type", "text": "..."} '
            'or {"type": "desktop_key", "keys": "Return|ctrl+l|..."}\n'
            if is_desktop
            else ""
        )
        fleet_schemas = (
            '  * propose_specialist_bot: {"type": "propose_specialist_bot", "name": "...", "role": "...", "prompt": "..."}\n'
            '  * propose_fleet_cleanup: {"type": "propose_fleet_cleanup", "operations": [{"bot_slug": "...", "enabled": false, "hidden_in_sidebar": true, "section": "..."}], "reason": "..."}\n'
            if (not is_background_poll or needs_platform_status)
            else ""
        )
        self_tuning_schemas = (
            '  * update_self_config: {"type": "update_self_config", "role": "<optional>", "role_prompt": "<optional>", "add_boundaries": ["..."], "handoff_bot_slug": "<optional>", "outbound_rbac": "<internal|draft|execute>", "runtime": "<api|desktop>", "onboarding_pending": false}\n'
            '  * configure_routine: {"type": "configure_routine", "operation": "upsert|update|delete", "routine_id": "<optional>", "label": "Weekday 8:30 AM Check", "schedule": "Every weekday at 08:30", "timezone": "UTC", "prompt": "<task_instructions>", "skill_slugs": ["<optional_skill>"], "stale_data_policy": "skip_quietly|notify_missing|always_run"}\n'
            '  * open_page: {"type": "open_page", "slug": "<page_slug_from_workspace_pages>", "mode": "split"}\n'
            '  * propose_delegation_plan: {"type": "propose_delegation_plan", "goal": "...", "steps": [{"bot_slug": "<teammate>", "task": "...", "parallel_group": 1}]}\n'
            '  * list_workspace_files / read_workspace_file / write_workspace_file: {"type": "write_workspace_file", "filename": "summary.md", "content": "..."}\n'
            if not is_background_poll
            else ""
        )
        supported_actions_list = (
            "upsert_document, fetch_public_webpage, fetch_rss_feed, fetch_telegram_public_channel, "
            "gmail_search, send_email, gmail_draft, reply_email, "
            + (
                "desktop_exec, desktop_browse, desktop_inspect, desktop_screenshot, "
                "desktop_check_app, desktop_launch, desktop_focus_window, desktop_click, "
                "desktop_type, desktop_key, desktop_scroll, "
                if is_desktop
                else ""
            )
            + "upsert_page, open_page, emit_event, connector_publish, publish_telegram, publish_linkedin, "
            "request_human_approval, notify_approval, remember_rule, update_self_config, configure_routine, "
            "save_skill, delegate_to_bot, propose_delegation_plan, list_workspace_files, read_workspace_file, write_workspace_file"
            + (", propose_specialist_bot, propose_fleet_cleanup" if (not is_background_poll or needs_platform_status) else "")
        )
        permitted_vault = self._permitted_vault_secrets(bot)
        vault_note = (
            "- Secrets Vault (Zero-AI Exposure): credentials exist only inside Argo's encrypted Vault and are NEVER shown to you. "
            "NEVER ask the operator for a plaintext password or SSH secret if a matching entry is listed in available_vault_secrets (@<slug>). "
            'When using desktop_exec, include "vault_secrets": ["<slug>"] and reference env vars from env_placeholders '
            '(for SSH use sshpass -e ssh -o StrictHostKeyChecking=accept-new -p "$ARGO_VAULT_<SLUG>_PORT" '
            '"$ARGO_VAULT_<SLUG>_USER@$ARGO_VAULT_<SLUG>_HOST" "<command>", or -i "$ARGO_VAULT_<SLUG>_KEY_PATH" for private keys). '
            "When using desktop_type, reference {{vault:<slug>.username}} or {{vault:<slug>.password}}.\n"
            if permitted_vault
            else ""
        )
        approval_relay_note = (
            "- Approval Notification Handler: you received an 'approval.queued' event. Emit 'notify_approval' "
            '({"type": "notify_approval", "account": "<integration_slug>", "approval_id": "<approval_id>", "text": "<optional_formatted_card>"}) '
            "pointing to your linked Telegram, Webhook (e.g. Slack), or Email integration to deliver the notification.\n"
            if trigger_type == "on_event:approval.queued"
            else ""
        )
        page_rules = (
            "- Pages, Not Paragraphs: whenever the operator asks to visualize data, build an interactive "
            "dashboard/playground/map, or maintain a living digest, use upsert_page (never use same-origin sandbox relaxations). "
            "Use clean professional UI design (#161920 canvas, #1e232c cards, #2d3440 borders, >= 12px high-contrast sans-serif typography, no fluorescent/neon/cyberpunk colors or gradients).\n"
            "- In-place Page updates: when target_page is provided or tweaking/redesigning an existing Page in owned_pages, "
            "MUST emit upsert_page with slug set to target_page.slug so the existing Page updates in-place instead of creating a duplicate.\n"
            "- Live data & client exports on Pages: bind allowed_collections to your data collection(s); inside sandboxed_html, "
            "post window.parent.postMessage({type:'ARGO_READY'}, '*') on load and handle ARGO_PAGE_DATA (event.data.records). "
            "Living Pages run with downloads enabled, so client-side exports (<a download>, Blob, canvas.toBlob, MediaRecorder) "
            "and window.parent.postMessage({type:'ARGO_DOWNLOAD_FILE', filename, mimeType, data}, '*') work directly; delay URL.revokeObjectURL by 15s (setTimeout(..., 15000)).\n"
            if not is_background_poll
            else ""
        )
        synthesis_note = (
            "- Final synthesis turn: summarize the tool_observations and results accurately with \"actions\": [].\n"
            if synthesis_only
            else ""
        )
        self_config_note = ""
        if not is_background_poll:
            routines_summary = [
                f"{r.get('id')}:{r.get('label')} ({r.get('schedule')} {r.get('timezone', 'UTC')}, enabled={bool(r.get('enabled', True))})"
                for r in (bot.get("routines") or [])
                if isinstance(r, dict)
            ]
            self_config_note = (
                f"- Self-config snapshot: runtime={bot.get('runtime', 'api')} · "
                f"handoff_bot_slug={bot.get('handoff_bot_slug') or 'none'} · "
                f"onboarding_pending={bool(bot.get('onboarding_pending', False))} · "
                f"routines={routines_summary}\n"
            )
        system_prompt = (
            f"{bot['role_prompt']}\n\n"
            f"{boundaries_block}"
            "Execution Contract:\n"
            f"- Bot slug: {bot['slug']} · RBAC: {bot['outbound_rbac']} · Daily cap: {bot['daily_cap']}\n"
            f"{self_config_note}"
            f"- Allowed collections read={read_cols}, write={data_write_cols}\n"
            f"- Permitted tools={allowed_tools}\n"
            f"{isolation_note}"
            f"{desktop_note}"
            f"{vault_note}"
            f"{approval_relay_note}"
            f"{handoff_note}"
            f"{onboarding_note}"
            f"{room_note}"
            "- When performing workspace actions, return a JSON object: "
            '{"summary": "...", "actions": [...]}.\n'
            f"- Supported action types: {supported_actions_list}.\n"
            "- Action JSON schemas (use exact keys):\n"
            '  * upsert_document: {"type": "upsert_document", "collection": "<write_collection>", '
            '"external_key": "<url_or_unique_id>", "search_text": "<title_and_summary>", '
            '"doc": {"title": "...", "url": "...", "summary": "..."}}\n'
            f"{desktop_schemas}"
            '  * publish_telegram: {"type": "publish_telegram", "account": "<telegram_slug>", '
            '"text": "<message_text>", "source_url": "<optional_url>"} '
            "(under draft RBAC, this queues a pending card in Web UI Approvals; any notification bot subscribed to approval.queued handles channel delivery)\n"
            '  * notify_approval: {"type": "notify_approval", "account": "<telegram|webhook|google_slug>", '
            '"approval_id": "<approval_id>", "text": "<optional_message>", "target": "<optional_target>"}\n'
            '  * request_human_approval: {"type": "request_human_approval", "account": "<integration_slug>", '
            '"action_type": "publish_telegram", "text": "<draft_text>", "source_url": "<optional_url>"}\n'
            '  * send_email / gmail_draft / reply_email: {"type": "send_email", "account": "<google_slug>", '
            '"to": "<recipient>", "subject": "<subject>", "text": "<body>"}\n'
            '  * save_skill: {"type": "save_skill", "name": "...", "description": "...", "instructions": "..."}\n'
            '  * delegate_to_bot: {"type": "delegate_to_bot", "target_bot": "<bot_slug>", "instruction": "...", "await_result": false}\n'
            f"{fleet_schemas}"
            f"{self_tuning_schemas}"
            '  * upsert_page: {"type": "upsert_page", "slug": "<page_slug>", "title": "...", "render_mode": "sandboxed_html", "allowed_collections": [...], "content_payload": "<html>...</html>"}\n'
            f"{page_rules}"
            "- Multi-step execution: if you need external data or desktop inspection/commands/screenshots first via fetch_*, gmail_search, "
            "or desktop_* tools, return only those discovery actions (with \"summary\": \"\") so the next turn receives tool_observations (and screenshots); then "
            "synthesize and write collections or outbound drafts.\n"
            + (
                "- Desktop GUI & Skill Replay: when replaying a recorded workflow or driving a multi-step desktop UI (click -> type -> key -> click), "
                "execute ALL remaining steps cleanly to the final goal rather than stopping after the first input. You may batch 2–4 sequential deterministic steps "
                "(e.g., desktop_click + desktop_type + desktop_key) in one turn when their order is certain, then verify the post-turn screenshot.\n"
                if is_desktop
                else ""
            )
            + "- Incremental pre-polled items: if unseen_ingested_entries already contains source_type='gmail' messages, "
            "analyze them directly on Turn 1 without redundantly re-running gmail_search unless extra search filters are needed.\n"
            "- Truthful error reporting: if any discovery or desktop action returns status != 'ok' (e.g. command_failed, timeout, error) "
            "or a provisioning message in tool_observations, report the exact failed command, exit_code, and stderr/error details — never claim success when status != 'ok'.\n"
            f"{synthesis_note}"
            "- For 'remember this' tone/preference instructions, emit remember_rule with rule_text."
        )

        prompt_envelope: dict[str, Any] = {
            "correlation_id": correlation_id,
            "hop_count": hop_count,
            "max_hop_count": MAX_HOP_COUNT,
            "trigger_type": trigger_type,
            "trigger_payload": trigger_payload,
            "linked_integrations": linked_integration_views,
            "style_and_memory_rules": style_rules,
            "unseen_ingested_entries": unseen_entries,
            "permitted_collection_documents": context_docs,
        }
        if skills_for_bot or active_skills_payload:
            prompt_envelope["available_skills"] = active_skills_payload or [
                {
                    "slug": s["slug"],
                    "name": s["name"],
                    "description": s["description"],
                    "instructions": s["instructions"],
                }
                for s in skills_for_bot
            ]
        if permitted_vault:
            prompt_envelope["available_vault_secrets"] = [
                {
                    "slug": v["slug"],
                    "handle": f"@{v['slug']}",
                    "name": v["name"],
                    "secret_type": v["secret_type"],
                    "host": v["host"],
                    "port": v["port"],
                    "url": v["url"],
                    "secret_keys": v["secret_keys"],
                    "env_placeholders": v["env_placeholders"],
                }
                for v in permitted_vault
            ]
        raw_input_text = str(trigger_payload.get("text") or trigger_payload.get("input_text") or "")
        if raw_input_text:
            all_vault_by_slug = {v["slug"]: v for v in self._repo.list_vault_secrets()}
            denied_vault = []
            for m in self._VAULT_MENTION_RE.finditer(raw_input_text):
                cand = slugify(m.group(1))
                v_meta = all_vault_by_slug.get(cand)
                if v_meta and not self._is_vault_permitted(bot, v_meta):
                    denied_vault.append(cand)
            if denied_vault:
                prompt_envelope["unpermitted_vault_mentions"] = list(dict.fromkeys(denied_vault))
        resolved_page_slug = (
            target_page_slug
            if target_page_slug is not None
            else self._resolve_target_page_slug(bot, trigger_payload)
        )
        if not is_background_poll:
            owned_pages = [
                {
                    "slug": p["slug"],
                    "title": p["title"],
                    "render_mode": p["render_mode"],
                    "allowed_collections": p["allowed_collections"],
                }
                for p in self._repo.list_pages()
                if p.get("owner_bot_slug") == bot["slug"]
            ]
            if owned_pages:
                prompt_envelope["owned_pages"] = owned_pages
        if resolved_page_slug:
            try:
                page_obj = self._repo.get_page(resolved_page_slug)
                prompt_envelope["target_page"] = {
                    "slug": page_obj["slug"],
                    "title": page_obj["title"],
                    "render_mode": page_obj["render_mode"],
                    "allowed_collections": page_obj["allowed_collections"],
                    "content_preview": str(page_obj["content_payload"] or "")[:16000],
                }
            except Exception:
                pass
        if recent_thread:
            prompt_envelope["recent_thread_messages"] = recent_thread
        if not is_background_poll:
            all_pages = [
                {
                    "slug": p["slug"],
                    "title": p["title"],
                    "owner_bot_slug": p["owner_bot_slug"],
                }
                for p in self._repo.list_pages()
            ]
            if all_pages:
                prompt_envelope["workspace_pages"] = all_pages
        if trigger_payload.get("quoted_message"):
            prompt_envelope["quoted_message"] = trigger_payload["quoted_message"]
        if trigger_payload.get("attached_files"):
            prompt_envelope["attached_files"] = trigger_payload["attached_files"]
        if trigger_payload.get("room_context"):
            prompt_envelope["room_context"] = trigger_payload["room_context"]
        if trigger_payload.get("specialist_results"):
            prompt_envelope["specialist_results"] = trigger_payload["specialist_results"]
        if trigger_payload.get("routine_prompt"):
            prompt_envelope["routine_prompt"] = trigger_payload["routine_prompt"]
        if teammate_bots and (not is_background_poll or handoff_active or needs_platform_status):
            prompt_envelope["workspace_bots"] = teammate_bots
        if tool_observations:
            prompt_envelope["tool_observations"] = tool_observations
        if needs_platform_status:
            host_telemetry = self._guard.sample().to_dict() if self._guard is not None else None
            scheduled_jobs = (
                self._bot_scheduler.list_scheduled_jobs()
                if self._bot_scheduler is not None
                else None
            )
            prompt_envelope["platform_status"] = self._repo.build_platform_status_snapshot(
                host_telemetry=host_telemetry,
                scheduled_jobs=scheduled_jobs,
            )
        user_prompt = json.dumps(prompt_envelope, ensure_ascii=False)
        return system_prompt, user_prompt

    def _save_snapshot_url(
        self,
        bot_slug: str,
        png_bytes: bytes,
        *,
        caption: str = "",
        url: str = "",
    ) -> str | None:
        if not png_bytes:
            return None
        try:
            snap_id = self._repo.save_desktop_snapshot(
                bot_slug,
                png_base64=base64.b64encode(png_bytes).decode("ascii"),
                caption=caption,
                url=url,
            )
            return f"/api/desktops/{bot_slug}/snapshots/{snap_id}"
        except Exception:
            logger.debug("Unable to persist snapshot for %s", bot_slug, exc_info=True)
            return None

    async def _execute_desktop_mcp_action(
        self,
        *,
        bot: dict[str, Any],
        a_type: str,
        action: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        turn_screenshots: list[bytes] | None = None,
    ) -> dict[str, Any]:
        if bot["runtime"] != "desktop" or self._desktop_mcp is None:
            msg = f"Bot '{bot['slug']}' runs in API-only mode and cannot invoke {a_type}."
            await self._bus.publish(
                correlation_id=correlation_id,
                source_slug=bot["slug"],
                target_slug="desktop",
                event_type="connector.blocked",
                payload={
                    "category": "alerts",
                    "title": f"Blocked Desktop Action ({bot['name']})",
                    "badge": "Desktop Policy",
                    "badge_tone": "red",
                    "summary": msg,
                    "meta": "runtime='desktop' required",
                },
                hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
            )
            return {"type": a_type, "status": "blocked_desktop_policy", "detail": msg}

        try:
            if a_type == "desktop_inspect":
                res = await self._desktop_mcp.inspect_desktop(
                    bot["slug"], correlation_id=correlation_id
                )
                return {"type": a_type, **res, "status": res.get("status", "ok")}

            if a_type == "desktop_screenshot":
                max_w = int(action.get("max_width") or 1280)
                png_bytes, meta = await self._desktop_mcp.capture_screenshot(
                    bot["slug"], max_width=max_w, correlation_id=correlation_id
                )
                if turn_screenshots is not None:
                    turn_screenshots.append(png_bytes)
                clean_meta = {k: v for k, v in meta.items() if k != "screenshot_url"}
                return {"type": a_type, "status": "ok", **clean_meta}

            short_act = a_type.removeprefix("desktop_")
            params = {k: v for k, v in action.items() if k not in {"type", "vault_secrets"}}
            env_vars, placeholder_vals, secret_values, vault_err = (
                await self._resolve_vault_for_desktop_action(
                    bot=bot,
                    a_type=a_type,
                    action=action,
                    correlation_id=correlation_id,
                    hop_count=hop_count,
                )
            )
            if vault_err is not None:
                return vault_err
            if short_act == "exec" and env_vars:
                existing_env = dict(params.get("env") or {}) if isinstance(params.get("env"), dict) else {}
                params["env"] = {**existing_env, **env_vars}
            if short_act == "type" and placeholder_vals and isinstance(params.get("text"), str):
                resolved_text = params["text"]
                for k_path, secret_val in placeholder_vals.items():
                    resolved_text = re.sub(
                        re.escape(f"{{{{vault:{k_path}}}}}"),
                        lambda _m, v=secret_val: v,
                        resolved_text,
                        flags=re.IGNORECASE,
                    )
                params["text"] = resolved_text

            res = await self._desktop_mcp.execute_action(
                bot["slug"], short_act, params, correlation_id=correlation_id
            )
            all_scrub = list(dict.fromkeys([*secret_values, *self._repo.collect_all_vault_secret_values()]))
            cleaned_res = self._scrub_vault_observation(res, all_scrub)
            return {"type": a_type, **cleaned_res, "status": cleaned_res.get("status", "ok")}
        except DesktopStartupBlockedError as exc:
            return {"type": a_type, "status": "queued_ram_gate", "detail": str(exc)}
        except (DesktopRuntimeError, DesktopMCPError) as exc:
            all_scrub = self._repo.collect_all_vault_secret_values()
            return {"type": a_type, "status": "error", "detail": redact_secrets(str(exc), all_scrub)}

    @staticmethod
    async def _run_cancellable_action(
        coro: Awaitable[Any],
        cancel_event: asyncio.Event | None,
    ) -> tuple[bool, Any]:
        """Run an action coroutine while honoring an active cancellation event promptly."""
        if cancel_event is None:
            return False, await coro
        if cancel_event.is_set():
            if asyncio.iscoroutine(coro):
                coro.close()
            return True, None
        task = asyncio.ensure_future(coro)
        cancel_wait = asyncio.create_task(cancel_event.wait())
        try:
            done, _ = await asyncio.wait(
                {task, cancel_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_wait in done and cancel_event.is_set():
                task.cancel()
                with suppress(BaseException):
                    await task
                return True, None
            return False, await task
        finally:
            cancel_wait.cancel()
            with suppress(BaseException):
                await cancel_wait

    async def _execute_actions(
        self,
        *,
        bot: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        actions: list[dict[str, Any]],
        turn_screenshots: list[bytes] | None = None,
        target_page_slug: str = "",
        trigger_type: str = "",
        trigger_payload: dict[str, Any] | None = None,
        run_item: QueuedTurnItem | None = None,
    ) -> list[dict[str, Any]]:
        raw_write_cols = [
            collection_slug(c) for c in (bot.get("collections", {}).get("write") or [])
        ]
        allowed_write = set(raw_write_cols)
        data_write_cols = [c for c in raw_write_cols if c != "bot_threads"]
        results: list[dict[str, Any]] = []
        await_delegations: list[dict[str, Any]] = []
        t_payload = trigger_payload or {}
        operator_email = str(t_payload.get("operator_email") or "").strip().lower() or None
        file_owner_email = operator_email or f"_bot_{bot['slug']}@local"
        in_room_turn = isinstance(t_payload.get("room_context"), dict)
        cancel_event = run_item.cancel_event if run_item is not None else None

        for action in actions:
            if not isinstance(action, dict):
                continue
            if cancel_event is not None and cancel_event.is_set():
                break
            a_type = _normalize_action_type(action.get("type"))
            friendly_step = _FRIENDLY_ACTION_STEP.get(a_type)
            if friendly_step:
                await self._emit_progress(bot["slug"], "running", friendly_step, correlation_id)

            chip_id = make_id("chip")
            chip_label = _CHIP_LABELS.get(a_type) or (
                a_type.replace("_", " ").capitalize() if a_type else "Running action"
            )
            chip_t0 = time.monotonic()
            chip_rec: dict[str, Any] | None = None
            if run_item is not None:
                chip_rec = {
                    "chip_id": chip_id,
                    "action_type": a_type or "unknown",
                    "label": chip_label,
                    "status": "running",
                    "elapsed_ms": 0,
                    "detail": "",
                }
                run_item.chips.append(chip_rec)
                await self._emit_turn_stream(
                    {
                        "type": "chip_started",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": bot["slug"],
                        "chip_id": chip_id,
                        "action_type": a_type or "unknown",
                        "label": chip_label,
                        "status": "running",
                    }
                )

            results_len_before = len(results)
            cancelled_during_step, _ = await self._run_cancellable_action(
                self._execute_single_action(
                    bot=bot,
                    a_type=a_type,
                    action=action,
                    correlation_id=correlation_id,
                    hop_count=hop_count,
                    allowed_write=allowed_write,
                    data_write_cols=data_write_cols,
                    operator_email=operator_email,
                    file_owner_email=file_owner_email,
                    in_room_turn=in_room_turn,
                    target_page_slug=target_page_slug,
                    trigger_type=trigger_type,
                    t_payload=t_payload,
                    turn_screenshots=turn_screenshots,
                    results=results,
                    await_delegations=await_delegations,
                ),
                cancel_event,
            )

            if run_item is not None and chip_rec is not None:
                elapsed_ms = max(0, int((time.monotonic() - chip_t0) * 1000))
                last_res = results[-1] if len(results) > results_len_before else None
                res_status = str((last_res or {}).get("status") or "ok").lower()
                if cancelled_during_step or (cancel_event is not None and cancel_event.is_set()):
                    chip_status = "stopped"
                elif res_status in {"ok", "executed", "proposed", "queued_approval"}:
                    chip_status = "done"
                elif a_type == "delegate_to_bot" and bool(action.get("await_result")):
                    chip_status = "done"
                else:
                    chip_status = "warning"
                detail_txt = str((last_res or {}).get("detail") or (last_res or {}).get("title") or "")[:140]
                chip_rec["status"] = chip_status
                chip_rec["elapsed_ms"] = elapsed_ms
                chip_rec["detail"] = detail_txt
                await self._emit_turn_stream(
                    {
                        "type": "chip_finished",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": bot["slug"],
                        "chip_id": chip_id,
                        "action_type": a_type or "unknown",
                        "label": chip_label,
                        "status": chip_status,
                        "elapsed_ms": elapsed_ms,
                        "detail": detail_txt,
                    }
                )
            if cancelled_during_step or (cancel_event is not None and cancel_event.is_set()):
                break

        if await_delegations and not (cancel_event is not None and cancel_event.is_set()):
            names = ", ".join(d["target_name"] for d in await_delegations)
            await self._emit_progress(bot["slug"], "running", f"Waiting on {names}...", correlation_id)

            async def _run_subtask(spec: dict[str, Any]) -> dict[str, Any]:
                try:
                    child_res = await self.execute_bot(
                        spec["target_bot"],
                        trigger_type="delegation_roundtrip",
                        correlation_id=correlation_id,
                        hop_count=spec["next_hop"],
                        trigger_payload={
                            "input_text": spec["instruction"],
                            "delegated_by": bot["slug"],
                            "operator_email": operator_email,
                            "suppress_1to1_thread": True,
                        },
                    )
                    return {
                        "type": "delegate_to_bot",
                        "await_result": True,
                        "status": "ok" if child_res.get("status") == "completed" else child_res.get("status", "error"),
                        "target_bot": spec["target_bot"],
                        "target_name": spec["target_name"],
                        "hop_count": spec["next_hop"],
                        "summary": child_res.get("summary", ""),
                        "actions": child_res.get("actions", []),
                    }
                except Exception as exc:
                    return {
                        "type": "delegate_to_bot",
                        "await_result": True,
                        "status": "error",
                        "target_bot": spec["target_bot"],
                        "target_name": spec["target_name"],
                        "detail": redact_secrets(str(exc)),
                    }

            _, gathered = await self._run_cancellable_action(
                asyncio.gather(*(_run_subtask(d) for d in await_delegations)),
                cancel_event,
            )
            if isinstance(gathered, list):
                results.extend(gathered)

        if (
            not (cancel_event is not None and cancel_event.is_set())
            and turn_screenshots is not None
            and not turn_screenshots
            and bot.get("runtime") == "desktop"
            and self._desktop_mcp is not None
            and any(
                (r.get("type") == "desktop_browse" or r.get("type") in _DESKTOP_MCP_INTERACTIVE_ACTIONS)
                and r.get("status") in {"ok", "error", "command_failed", "timeout"}
                for r in results
            )
        ):
            with suppress(Exception):
                png_bytes, _ = await self._desktop_mcp.capture_screenshot(
                    bot["slug"],
                    correlation_id=correlation_id,
                    ready_timeout_seconds=2.5,
                )
                turn_screenshots.append(png_bytes)

        return results

    async def _execute_single_action(
        self,
        *,
        bot: dict[str, Any],
        a_type: str,
        action: dict[str, Any],
        correlation_id: str,
        hop_count: int,
        allowed_write: set[str],
        data_write_cols: list[str],
        operator_email: str | None,
        file_owner_email: str,
        in_room_turn: bool,
        target_page_slug: str,
        trigger_type: str,
        t_payload: dict[str, Any],
        turn_screenshots: list[bytes] | None,
        results: list[dict[str, Any]],
        await_delegations: list[dict[str, Any]],
    ) -> None:
        for _once in (0,):

            if a_type == "upsert_document":
                raw_col = str(action.get("collection") or "").strip()
                target_col = (
                    collection_slug(raw_col)
                    if raw_col
                    else (data_write_cols[0] if data_write_cols else "")
                )
                if target_col not in allowed_write:
                    msg = f"Bot '{bot['slug']}' lacks write permission on collection '{target_col}'."
                    await self._bus.publish(
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                        target_slug=target_col,
                        event_type="connector.blocked",
                        payload={
                            "category": "alerts",
                            "title": f"Blocked Collection Write ({bot['name']})",
                            "badge": "Collection ACL",
                            "badge_tone": "red",
                            "summary": msg,
                            "meta": f"Allowed write: {sorted(allowed_write)}",
                        },
                        hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                    )
                    results.append({"type": a_type, "status": "blocked_collection_acl", "detail": msg})
                    continue

                ext_key = action.get("external_key")
                doc = (
                    action.get("doc")
                    if isinstance(action.get("doc"), dict)
                    else (
                        action.get("document")
                        if isinstance(action.get("document"), dict)
                        else (
                            action.get("data")
                            if isinstance(action.get("data"), dict)
                            else {
                                k: v
                                for k, v in action.items()
                                if k not in {"type", "collection", "external_key", "search_text"}
                            }
                        )
                    )
                )
                saved = self._repo.upsert_document(
                    collection=target_col,
                    external_key=str(ext_key) if ext_key is not None else None,
                    search_text=str(action.get("search_text") or json.dumps(doc))[:1000],
                    doc=doc,
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "collection": saved["collection"],
                        "external_key": saved["external_key"],
                        "id": saved["id"],
                    }
                )

            elif a_type == "fetch_public_webpage":
                url = str(action.get("url") or "").strip()
                if url:
                    fetched = await fetch_public_webpage(
                        url,
                        bus=self._bus,
                        fetcher=self._http_fetcher,
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                    )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "url": fetched["url"],
                            "title": fetched["title"],
                            "discovered_feeds": fetched.get("discovered_feeds") or [],
                            "markdown": str(fetched.get("markdown") or "")[:4000],
                        }
                    )

            elif a_type == "fetch_rss_feed":
                url = str(action.get("url") or "").strip()
                if url:
                    fetched = await fetch_rss_feed(
                        url,
                        repo=self._repo,
                        bus=self._bus,
                        fetcher=self._http_fetcher,
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                    )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "url": fetched["url"],
                            "feed_title": fetched.get("feed_title") or "",
                            "entries": len(fetched["entries"]),
                            "items": [
                                {
                                    "external_key": e.get("external_key"),
                                    "title": e.get("title"),
                                    "url": e.get("url"),
                                    "published": e.get("published"),
                                    "summary": str(e.get("summary") or "")[:300],
                                }
                                for e in fetched.get("entries", [])[:10]
                            ],
                        }
                    )

            elif a_type == "fetch_telegram_public_channel":
                channel = str(action.get("channel") or action.get("target") or "").strip()
                if channel:
                    posts = await fetch_telegram_public_channel(
                        channel,
                        fetcher=self._http_fetcher,
                        limit=int(action.get("limit") or 15),
                    )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "channel": channel,
                            "posts": posts[:15],
                        }
                    )

            elif a_type == "gmail_search":
                account_slug, _ = self._resolve_action_account_slug(
                    bot, action, preferred_provider="google"
                )
                if not account_slug:
                    results.append(
                        {
                            "type": a_type,
                            "status": "skipped_invalid_action",
                            "detail": "No linked Google integration available for gmail_search.",
                        }
                    )
                    continue
                if not self._is_account_permitted(bot, account_slug):
                    results.append(
                        await self._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=correlation_id,
                            hop_count=hop_count,
                            action_type=a_type,
                            account_slug=account_slug,
                        )
                    )
                    continue
                if self._google is None:
                    results.append(
                        {
                            "type": a_type,
                            "status": "error",
                            "account": account_slug,
                            "detail": "GoogleOAuthService is not configured.",
                        }
                    )
                    continue
                try:
                    search_res = await self._google.search_messages(
                        account_slug,
                        query=str(action.get("query") or ""),
                        max_results=int(action.get("max_results") or 10),
                    )
                    fetched_msgs = list(search_res.get("messages") or [])
                    non_thread_write = [
                        collection_slug(c)
                        for c in (bot.get("collections", {}).get("write") or [])
                        if collection_slug(c) != "bot_threads"
                    ]
                    target_email_col = non_thread_write[0] if non_thread_write else None
                    if target_email_col:
                        for msg in fetched_msgs:
                            mid = str(msg.get("id") or "").strip()
                            if not mid:
                                continue
                            self._repo.upsert_document(
                                collection=target_email_col,
                                external_key=f"gmail:{account_slug}:{mid}",
                                search_text=(
                                    f"{msg.get('subject', '')} {msg.get('from', '')} "
                                    f"{msg.get('snippet', '')}"
                                )[:1000],
                                doc={
                                    "source_type": "gmail",
                                    "account_slug": account_slug,
                                    "message_id": mid,
                                    "thread_id": msg.get("thread_id"),
                                    "from": msg.get("from", ""),
                                    "to": msg.get("to", ""),
                                    "subject": msg.get("subject", "(No subject)"),
                                    "date": msg.get("date", ""),
                                    "snippet": msg.get("snippet", ""),
                                    "label_ids": msg.get("label_ids") or [],
                                },
                                description=f"Mirrored Gmail messages for {bot['name']}",
                            )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "account": account_slug,
                            "query": search_res.get("query") or "",
                            "messages": fetched_msgs,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "type": a_type,
                            "status": "error",
                            "account": account_slug,
                            "detail": redact_secrets(str(exc)),
                        }
                    )

            elif a_type == "emit_event":
                ev_type = str(action.get("event_type") or "").strip()
                if not ev_type:
                    continue
                next_hop = hop_count + 1
                if next_hop > MAX_HOP_COUNT:
                    await self._bus.publish(
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                        target_slug=action.get("target_slug"),
                        event_type="bot.hop_limit_halted",
                        payload={
                            "category": "alerts",
                            "title": f"Loop Guard Halted Event Chain ({bot['name']})",
                            "badge": f"Halted · Hop {next_hop}/{MAX_HOP_COUNT}",
                            "badge_tone": "amber",
                            "summary": f"Halted '{ev_type}' emit because hop {next_hop} exceeds limit {MAX_HOP_COUNT}.",
                            "meta": f"Correlation: {correlation_id}",
                            "attempted_event": ev_type,
                            "attempted_hop_count": next_hop,
                        },
                        hop_count=MAX_HOP_COUNT,
                    )
                    results.append({"type": a_type, "status": "halted_hop_limit", "event_type": ev_type})
                    continue

                ev_payload = dict(action.get("payload") or {})
                ev_payload.setdefault("category", "reviews")
                ev_payload.setdefault("title", f"{bot['name']} -> {ev_type}")
                ev_payload.setdefault("badge", f"Hop {next_hop}/{MAX_HOP_COUNT}")
                ev_payload.setdefault("badge_tone", "sky")
                ev_payload.setdefault(
                    "summary",
                    f"Emitted {ev_type} from {bot['slug']} for downstream subscribers.",
                )
                emitted = await self._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=action.get("target_slug"),
                    event_type=ev_type,
                    payload=ev_payload,
                    hop_count=next_hop,
                )
                results.append(
                    {"type": a_type, "status": "ok", "event_type": ev_type, "event_id": emitted["id"], "hop_count": next_hop}
                )

            elif a_type == "notify_approval" or (
                trigger_type == "on_event:approval.queued"
                and a_type in {"connector_publish", "publish_telegram", "publish_linkedin", "send_email"}
                and bool(action.get("approval_id") or (trigger_payload or {}).get("approval_id"))
            ):
                approval_id = str(
                    action.get("approval_id") or (trigger_payload or {}).get("approval_id") or ""
                ).strip()
                pref = (
                    "telegram"
                    if a_type == "publish_telegram"
                    else ("linkedin" if a_type == "publish_linkedin" else ("google" if a_type == "send_email" else None))
                )
                account_slug, _ = self._resolve_action_account_slug(bot, action, preferred_provider=pref)
                if not approval_id or not account_slug:
                    results.append(
                        {
                            "type": "notify_approval",
                            "status": "skipped_invalid_action",
                            "detail": "Missing approval_id or linked notification account.",
                        }
                    )
                    continue
                if not self._is_account_permitted(bot, account_slug):
                    results.append(
                        await self._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=correlation_id,
                            hop_count=hop_count,
                            action_type="notify_approval",
                            account_slug=account_slug,
                        )
                    )
                    continue
                if str(bot.get("outbound_rbac") or "draft").lower() != "execute":
                    results.append(
                        {
                            "type": "notify_approval",
                            "status": "blocked_rbac",
                            "detail": "Approval notification bots must be set to Auto-Send (execute) to deliver notifications without recursive approval loops.",
                        }
                    )
                    continue
                try:
                    deliv = await self._approvals.deliver_approval_notification(
                        approval_id=approval_id,
                        account_slug=account_slug,
                        text=_extract_action_text(action) or None,
                        target=str(action.get("target") or "").strip() or None,
                    )
                    results.append(
                        {
                            "type": "notify_approval",
                            "status": "ok",
                            "approval_id": approval_id,
                            "account": account_slug,
                            **deliv,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "type": "notify_approval",
                            "status": "error",
                            "approval_id": approval_id,
                            "account": account_slug,
                            "detail": redact_secrets(str(exc)),
                        }
                    )

            elif a_type in {
                "connector_publish",
                "publish_telegram",
                "publish_linkedin",
                "send_email",
                "gmail_draft",
                "reply_email",
            }:
                raw_action_type = str(action.get("action_type") or "").strip()
                resolved_action = (
                    _normalize_action_type(raw_action_type)
                    if raw_action_type
                    else ("connector_publish" if a_type == "connector_publish" else a_type)
                )
                preferred_provider = (
                    "telegram"
                    if (a_type == "publish_telegram" or resolved_action == "publish_telegram")
                    else (
                        "linkedin"
                        if (a_type == "publish_linkedin" or resolved_action == "publish_linkedin")
                        else (
                            "google"
                            if a_type in {"send_email", "gmail_draft", "reply_email"}
                            or resolved_action in {"send_email", "gmail_draft", "reply_email"}
                            else None
                        )
                    )
                )
                account_slug, _ = self._resolve_action_account_slug(
                    bot, action, preferred_provider=preferred_provider
                )
                text = _extract_action_text(action)
                payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
                source_url = (
                    action.get("source_url")
                    or action.get("url")
                    or payload_obj.get("source_url")
                )
                source_excerpt = action.get("source_excerpt") or payload_obj.get("source_excerpt")
                if not account_slug or not text:
                    missing = "account" if not account_slug else "text"
                    results.append(
                        {
                            "type": a_type,
                            "status": "skipped_invalid_action",
                            "detail": f"Missing {missing} for {a_type}.",
                        }
                    )
                    continue
                if not self._is_account_permitted(bot, account_slug):
                    results.append(
                        await self._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=correlation_id,
                            hop_count=hop_count,
                            action_type=resolved_action,
                            account_slug=account_slug,
                        )
                    )
                    continue

                extra_payload: dict[str, Any] | None = (
                    dict(action["extra_payload"])
                    if isinstance(action.get("extra_payload"), dict)
                    else None
                )
                target_dest = action.get("target") or payload_obj.get("target")
                if a_type in {"send_email", "gmail_draft", "reply_email"}:
                    to_email = str(
                        action.get("to") or action.get("recipient") or target_dest or ""
                    ).strip()
                    subject = str(action.get("subject") or "(No subject)").strip()
                    email_meta: dict[str, Any] = {
                        **(extra_payload or {}),
                        "to": to_email,
                        "subject": subject,
                    }
                    for opt_key in ("cc", "thread_id", "in_reply_to"):
                        if action.get(opt_key):
                            email_meta[opt_key] = action[opt_key]
                    extra_payload = email_meta
                    target_dest = target_dest or to_email or None

                try:
                    if (
                        trigger_type == "on_event:approval.queued"
                        and str(bot.get("outbound_rbac") or "draft").lower() != "execute"
                    ):
                        results.append(
                            {
                                "type": a_type,
                                "status": "blocked_rbac",
                                "detail": "Approval handler bots cannot queue recursive approvals; enable Auto-Send (execute).",
                            }
                        )
                        continue
                    gate_res = await self._approvals.execute_or_queue_outbound(
                        bot=bot,
                        correlation_id=correlation_id,
                        hop_count=hop_count,
                        account_slug=account_slug,
                        action_type=resolved_action,
                        text=text,
                        target=target_dest,
                        source_url=source_url,
                        source_excerpt=source_excerpt,
                        extra_payload=extra_payload,
                    )
                    results.append({"type": a_type, **gate_res})
                except ConnectorPermissionError as exc:
                    results.append({"type": a_type, "status": "blocked_rbac", "detail": str(exc)})

            elif a_type == "request_human_approval":
                resolved_action = (
                    _normalize_action_type(action.get("action_type") or "publish_telegram")
                    or "publish_telegram"
                )
                preferred_provider = (
                    "google"
                    if resolved_action in {"send_email", "gmail_draft", "reply_email"}
                    else ("linkedin" if resolved_action == "publish_linkedin" else "telegram")
                )
                account_slug, was_explicit = self._resolve_action_account_slug(
                    bot, action, preferred_provider=preferred_provider
                )
                if not account_slug:
                    account_slug = "tg-ops"
                text = _extract_action_text(action)
                if not text:
                    results.append(
                        {
                            "type": a_type,
                            "status": "skipped_invalid_action",
                            "detail": f"Missing text for {a_type}.",
                        }
                    )
                    continue
                if (
                    (was_explicit or bot.get("linked_accounts_restricted"))
                    and account_slug != "tg-ops"
                    and not self._is_account_permitted(bot, account_slug)
                ):
                    results.append(
                        await self._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=correlation_id,
                            hop_count=hop_count,
                            action_type=resolved_action,
                            account_slug=account_slug,
                        )
                    )
                    continue
                payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
                payload_dict: dict[str, Any] = {"text": text}
                target_val = action.get("target") or payload_obj.get("target")
                if target_val:
                    payload_dict["target"] = target_val
                for opt_key in ("to", "subject", "cc", "thread_id", "in_reply_to"):
                    opt_val = action.get(opt_key) or payload_obj.get(opt_key)
                    if opt_val:
                        payload_dict[opt_key] = opt_val
                source_url = (
                    action.get("source_url")
                    or action.get("url")
                    or payload_obj.get("source_url")
                )
                source_excerpt = action.get("source_excerpt") or payload_obj.get("source_excerpt")
                queued = await self._approvals.enqueue_human_approval(
                    correlation_id=correlation_id,
                    bot_slug=bot["slug"],
                    target_account_slug=account_slug,
                    action_type=resolved_action,
                    payload=payload_dict,
                    source_url=source_url,
                    source_excerpt=source_excerpt,
                    escalation_note=str(
                        action.get("escalation_note")
                        or f"Explicit request_human_approval escalation by {bot['slug']}."
                    ),
                    hop_count=hop_count,
                )
                results.append({"type": a_type, "status": "queued_approval", "approval_id": queued["id"]})

            elif a_type == "remember_rule":
                rule_text = str(action.get("rule_text") or action.get("rule") or "").strip()
                if not rule_text:
                    continue
                scope = str(action.get("scope_slug") or bot["slug"]).strip() or bot["slug"]
                saved_rule = self._repo.add_style_rule(rule_text=rule_text, scope_slug=scope)
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "rule_id": saved_rule["id"],
                        "rule_text": saved_rule["rule_text"],
                        "scope_slug": saved_rule["scope_slug"],
                    }
                )

            elif a_type == "update_self_config":
                safe_patch: dict[str, Any] = {}
                gated_patch: dict[str, Any] = {}
                escalation_reasons: list[str] = []

                if action.get("role"):
                    safe_patch["role"] = str(action["role"]).strip()[:2000]
                if action.get("role_prompt") is not None:
                    safe_patch["role_prompt"] = str(action["role_prompt"]).strip()[:8000]
                if action.get("goal_metric") is not None:
                    safe_patch["goal_metric"] = str(action["goal_metric"]).strip()[:300]
                if action.get("section") is not None:
                    safe_patch["section"] = str(action["section"]).strip()[:80]
                if "handoff_bot_slug" in action and action.get("handoff_bot_slug") is not None:
                    raw_ho = str(action["handoff_bot_slug"]).strip()
                    safe_patch["handoff_bot_slug"] = slugify(raw_ho) if raw_ho else ""
                if action.get("model"):
                    cand_model = str(action["model"]).strip()
                    if ":" in cand_model and "gemini-2.5" not in cand_model.lower():
                        safe_patch["model"] = cand_model
                if "onboarding_pending" in action and action.get("onboarding_pending") is not None:
                    safe_patch["onboarding_pending"] = bool(action["onboarding_pending"])
                elif bot.get("onboarding_pending") and (safe_patch or action.get("add_boundaries")):
                    safe_patch["onboarding_pending"] = False

                current_boundaries = [str(b).strip() for b in (bot.get("boundaries") or []) if str(b).strip()]
                if isinstance(action.get("add_boundaries"), list):
                    merged_b = list(current_boundaries)
                    for item in action["add_boundaries"]:
                        clean_b = str(item).strip()
                        if clean_b and clean_b not in merged_b:
                            merged_b.append(clean_b)
                    if merged_b != current_boundaries:
                        safe_patch["boundaries"] = merged_b
                if isinstance(action.get("boundaries"), list):
                    next_b = [str(item).strip() for item in action["boundaries"] if str(item).strip()]
                    removed_b = [b for b in current_boundaries if b not in next_b]
                    if removed_b:
                        gated_patch["boundaries"] = next_b
                        escalation_reasons.append(f"Remove boundary rule(s): {', '.join(removed_b)}")
                    elif next_b != current_boundaries:
                        safe_patch["boundaries"] = next_b

                rbac_rank = {"internal": 0, "draft": 1, "execute": 2}
                cur_rbac = str(bot.get("outbound_rbac") or "draft").lower()
                if action.get("outbound_rbac") in rbac_rank:
                    req_rbac = str(action["outbound_rbac"]).lower()
                    if rbac_rank[req_rbac] > rbac_rank.get(cur_rbac, 1):
                        gated_patch["outbound_rbac"] = req_rbac
                        escalation_reasons.append(f"Raise sending permission from '{cur_rbac}' to '{req_rbac}'")
                    elif req_rbac != cur_rbac:
                        safe_patch["outbound_rbac"] = req_rbac

                if action.get("runtime") in {"api", "desktop"}:
                    req_rt = str(action["runtime"])
                    if req_rt == "desktop" and bot.get("runtime") != "desktop":
                        gated_patch["runtime"] = "desktop"
                        escalation_reasons.append("Enable dedicated Virtual Desktop container (2 GB RAM)")
                    elif req_rt == "api" and bot.get("runtime") == "desktop":
                        safe_patch["runtime"] = "api"

                if isinstance(action.get("daily_cap"), int):
                    req_cap = max(0, min(500, int(action["daily_cap"])))
                    if req_cap > int(bot.get("daily_cap") or 0) and (gated_patch.get("outbound_rbac") or cur_rbac) == "execute":
                        gated_patch["daily_cap"] = req_cap
                        escalation_reasons.append(f"Raise daily auto-send limit to {req_cap}")
                    else:
                        safe_patch["daily_cap"] = req_cap

                if isinstance(action.get("linked_accounts"), list):
                    req_acc = [slugify(str(a)) for a in action["linked_accounts"] if str(a).strip()]
                    cur_acc = set(bot.get("linked_accounts") or [])
                    if any(a not in cur_acc for a in req_acc):
                        gated_patch["linked_accounts"] = req_acc
                        escalation_reasons.append(f"Grant access to integration(s): {', '.join(req_acc)}")

                if safe_patch:
                    self._repo.update_bot(bot["slug"], safe_patch)
                    bot = self._repo.get_bot(bot["slug"])
                    if self._bot_scheduler is not None:
                        self._bot_scheduler.sync_bots()

                approval_id = None
                if gated_patch:
                    queued = await self._approvals.enqueue_human_approval(
                        correlation_id=correlation_id,
                        bot_slug=bot["slug"],
                        target_account_slug="argo_workspace",
                        action_type="update_bot_config",
                        payload={
                            "title": f"Update Bot Setup: {bot['name']}",
                            "text": "\n".join(f"- {r}" for r in escalation_reasons) or json.dumps(gated_patch),
                            "bot_slug": bot["slug"],
                            "updates": gated_patch,
                        },
                        escalation_note="; ".join(escalation_reasons)[:300],
                        hop_count=hop_count,
                    )
                    approval_id = queued["id"]

                results.append(
                    {
                        "type": a_type,
                        "status": "queued_approval" if (gated_patch and not safe_patch) else "ok",
                        "applied_changes": safe_patch,
                        "gated_changes": gated_patch,
                        "approval_id": approval_id,
                    }
                )

            elif a_type == "configure_routine":
                operation = str(action.get("operation") or "upsert").strip().lower()
                target_rtn_id = str(action.get("routine_id") or "").strip()
                label = str(action.get("label") or action.get("name") or "").strip()
                schedule = str(action.get("schedule") or "").strip()
                timezone_name = str(action.get("timezone") or "").strip()
                prompt_val = action.get("prompt")
                skill_slugs_val = action.get("skill_slugs")
                stale_policy_val = str(action.get("stale_data_policy") or "").strip()
                enabled_val = action.get("enabled")
                delivery_mode = str(action.get("delivery_mode") or "").strip()
                quiet_hours = str(action.get("quiet_hours") or "").strip()
                inbox_query = str(action.get("inbox_query") or "").strip()
                routines = [dict(r) for r in (bot.get("routines") or []) if isinstance(r, dict)]

                def _apply_fields(target_r: dict[str, Any]) -> None:
                    if label:
                        target_r["label"] = label
                    if schedule:
                        target_r["schedule"] = schedule
                        target_r["type"] = "manual_trigger" if schedule.lower() == "manual" else "cron"
                    if timezone_name:
                        target_r["timezone"] = timezone_name
                    if prompt_val is not None:
                        target_r["prompt"] = str(prompt_val).strip()
                    if isinstance(skill_slugs_val, list):
                        target_r["skill_slugs"] = [slugify(str(s)) for s in skill_slugs_val if str(s).strip()]
                    if stale_policy_val in {"skip_quietly", "notify_missing", "always_run"}:
                        target_r["stale_data_policy"] = stale_policy_val
                    if enabled_val is not None:
                        target_r["enabled"] = bool(enabled_val)
                    if delivery_mode:
                        target_r["delivery_mode"] = delivery_mode
                    if quiet_hours:
                        target_r["quiet_hours"] = quiet_hours
                    if inbox_query:
                        target_r["inbox_query"] = inbox_query

                if operation == "delete":
                    before_len = len(routines)
                    routines = [
                        r
                        for r in routines
                        if not (
                            (target_rtn_id and r.get("id") == target_rtn_id)
                            or (label and str(r.get("label") or "").strip().lower() == label.lower())
                        )
                    ]
                    self._repo.update_bot(bot["slug"], {"routines": routines})
                    if self._bot_scheduler is not None:
                        self._bot_scheduler.sync_bots()
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok" if len(routines) < before_len else "not_found",
                            "operation": "delete",
                        }
                    )
                    continue

                matched_idx = -1
                if target_rtn_id:
                    matched_idx = next(
                        (i for i, r in enumerate(routines) if r.get("id") == target_rtn_id),
                        -1,
                    )
                elif label:
                    matched_idx = next(
                        (
                            i
                            for i, r in enumerate(routines)
                            if str(r.get("label") or "").strip().lower() == label.lower()
                        ),
                        -1,
                    )
                    if matched_idx == -1 and operation != "add" and len(routines) == 1:
                        only_r = routines[0]
                        if only_r.get("type") != "on_event" and str(only_r.get("label") or "") in {
                            "Manual Run",
                            "Scheduled Sync",
                            f"{bot['name']} Sync",
                        } and not only_r.get("prompt"):
                            matched_idx = 0
                else:
                    matched_idx = next(
                        (i for i, r in enumerate(routines) if r.get("type") != "on_event"),
                        -1,
                    )

                if matched_idx >= 0 and operation != "add":
                    _apply_fields(routines[matched_idx])
                    saved_routine = routines[matched_idx]
                else:
                    new_r: dict[str, Any] = {
                        "id": make_id("rtn"),
                        "type": "manual_trigger" if (schedule or "Manual").lower() == "manual" else "cron",
                        "label": label or "Configured Routine",
                        "schedule": schedule or "Manual",
                        "timezone": timezone_name or "UTC",
                        "enabled": True if enabled_val is None else bool(enabled_val),
                    }
                    _apply_fields(new_r)
                    routines.append(new_r)
                    saved_routine = new_r

                self._repo.update_bot(bot["slug"], {"routines": routines})
                if self._bot_scheduler is not None:
                    self._bot_scheduler.sync_bots()
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "routine_id": saved_routine.get("id"),
                        "label": saved_routine.get("label"),
                        "schedule": saved_routine.get("schedule") or schedule or "unchanged",
                        "timezone": saved_routine.get("timezone", "UTC"),
                    }
                )

            elif a_type == "open_page":
                raw_slug = str(action.get("slug") or action.get("page") or action.get("title") or "").strip()
                mode = "full" if str(action.get("mode") or "").lower() == "full" else "split"
                pages = self._repo.list_pages()
                target_page_rec: dict[str, Any] | None = None
                if raw_slug:
                    cand_s = slugify(raw_slug)
                    target_page_rec = next(
                        (
                            p
                            for p in pages
                            if p["slug"] == cand_s
                            or p["slug"] == raw_slug
                            or p["title"].strip().lower() == raw_slug.lower()
                        ),
                        None,
                    )
                    if target_page_rec is None:
                        target_page_rec = next(
                            (p for p in pages if raw_slug.lower() in p["title"].lower() or cand_s in p["slug"]),
                            None,
                        )
                if target_page_rec is None and pages:
                    target_page_rec = next(
                        (p for p in pages if p["owner_bot_slug"] == bot["slug"]),
                        pages[0],
                    )
                if target_page_rec is None:
                    hub_html = self._repo.build_interactive_page_html(
                        template_key="bot_hub_board",
                        title="Bot Hub Board",
                        description="Live workspace board across bots, rooms, and pending approvals",
                        allowed_collections=[],
                    )
                    target_page_rec = self._repo.create_page(
                        title="Bot Hub Board",
                        description="Live workspace board across bots, rooms, and pending approvals",
                        render_mode="sandboxed_html",
                        content_payload=hub_html,
                        allowed_collections=[],
                        owner_bot_slug=bot["slug"],
                    )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "slug": target_page_rec["slug"],
                        "page_slug": target_page_rec["slug"],
                        "title": target_page_rec["title"],
                        "mode": mode,
                    }
                )

            elif a_type == "list_workspace_files":
                files = self._repo.list_workspace_files(file_owner_email)
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "files": [
                            {
                                "id": f["id"],
                                "filename": f["filename"],
                                "mime_type": f["mime_type"],
                                "size_bytes": f["size_bytes"],
                                "updated_at": f["updated_at"],
                            }
                            for f in files[:30]
                        ],
                    }
                )

            elif a_type == "read_workspace_file":
                key = str(action.get("file_id") or action.get("id") or action.get("filename") or "").strip()
                if not key:
                    results.append({"type": a_type, "status": "skipped_invalid_action", "detail": "Missing file_id or filename."})
                    continue
                try:
                    meta, fpath = self._repo.get_workspace_file(key, owner_email=file_owner_email)
                    text_body = meta.get("text_preview") or ""
                    if not text_body and not meta.get("is_image"):
                        raw_bytes = fpath.read_bytes()[:64_000]
                        text_body = redact_secrets(
                            raw_bytes.decode("utf-8", errors="replace"),
                            self._repo.collect_all_vault_secret_values(),
                        )[:16_000]
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "file_id": meta["id"],
                            "filename": meta["filename"],
                            "mime_type": meta["mime_type"],
                            "size_bytes": meta["size_bytes"],
                            "content": text_body[:16_000],
                        }
                    )
                except Exception as exc:
                    results.append({"type": a_type, "status": "not_found", "detail": str(exc)})

            elif a_type == "write_workspace_file":
                fname = str(action.get("filename") or action.get("name") or "output.md").strip()
                content = str(action.get("content") or action.get("text") or "").encode("utf-8")
                scrubbed_text = redact_secrets(
                    content.decode("utf-8", errors="replace"),
                    self._repo.collect_all_vault_secret_values(),
                ).encode("utf-8")
                lower_fn = fname.lower()
                mime_guess = (
                    "text/html"
                    if lower_fn.endswith((".html", ".htm"))
                    else (
                        "image/svg+xml"
                        if lower_fn.endswith(".svg")
                        else (
                            "text/markdown"
                            if lower_fn.endswith(".md")
                            else (
                                "text/csv"
                                if lower_fn.endswith(".csv")
                                else (
                                    "application/json"
                                    if lower_fn.endswith(".json")
                                    else "text/plain"
                                )
                            )
                        )
                    )
                )
                try:
                    saved_f = self._repo.save_workspace_file(
                        owner_email=file_owner_email,
                        filename=fname,
                        mime_type=str(action.get("mime_type") or mime_guess),
                        content_bytes=scrubbed_text,
                        uploaded_by=f"bot:{bot['slug']}",
                    )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "file": saved_f,
                        }
                    )
                except Exception as exc:
                    results.append({"type": a_type, "status": "error", "detail": str(exc)})

            elif a_type == "propose_delegation_plan":
                goal = str(action.get("goal") or action.get("summary") or "Multi-bot delegation plan").strip()
                raw_steps = [s for s in (action.get("steps") or []) if isinstance(s, dict)]
                clean_steps: list[dict[str, Any]] = []
                bots_by_slug = {b["slug"]: b for b in self._repo.list_bots()}
                for idx, st in enumerate(raw_steps[:8]):
                    b_slug = slugify(str(st.get("bot_slug") or st.get("target_bot") or ""))
                    task_txt = str(st.get("task") or st.get("instruction") or "").strip()
                    if not b_slug or not task_txt or b_slug not in bots_by_slug:
                        continue
                    clean_steps.append(
                        {
                            "id": str(st.get("id") or f"step_{idx + 1}"),
                            "bot_slug": b_slug,
                            "bot_name": bots_by_slug[b_slug]["name"],
                            "task": task_txt,
                            "parallel_group": int(st.get("parallel_group") or 1),
                        }
                    )
                if not clean_steps:
                    results.append({"type": a_type, "status": "skipped_invalid_action", "detail": "No valid specialist steps provided."})
                    continue
                plan_doc = self._repo.save_delegation_plan(
                    {
                        "id": make_id("plan"),
                        "coordinator_slug": bot["slug"],
                        "coordinator_name": bot["name"],
                        "correlation_id": correlation_id,
                        "room_slug": (t_payload.get("room_context") or {}).get("room_slug") if in_room_turn else None,
                        "goal": goal,
                        "status": "proposed",
                        "steps": clean_steps,
                        "results": [],
                    }
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "proposed",
                        "plan": plan_doc,
                    }
                )

            elif a_type == "save_skill":
                skill_name = str(action.get("name") or "").strip()
                instructions = str(action.get("instructions") or "").strip()
                if not skill_name or not instructions:
                    continue
                scope = str(action.get("scope_slug") or bot["slug"]).strip() or bot["slug"]
                saved_skill = self._repo.upsert_skill(
                    name=skill_name,
                    description=str(action.get("description") or "").strip(),
                    instructions=instructions,
                    scope_slug=scope,
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "skill": saved_skill,
                    }
                )

            elif a_type == "delegate_to_bot":
                target_bot = slugify(str(action.get("target_bot") or action.get("bot_slug") or ""))
                instruction = str(action.get("instruction") or action.get("text") or "").strip()
                if not target_bot or not instruction:
                    continue
                next_hop = hop_count + 1
                if next_hop > MAX_HOP_COUNT:
                    results.append(
                        {"type": a_type, "status": "halted_hop_limit", "target_bot": target_bot}
                    )
                    continue
                try:
                    target_rec = self._repo.get_bot(target_bot)
                except Exception:
                    results.append(
                        {"type": a_type, "status": "not_found", "target_bot": target_bot}
                    )
                    continue
                if not target_rec["enabled"]:
                    results.append(
                        {"type": a_type, "status": "skipped_disabled", "target_bot": target_bot}
                    )
                    continue
                if bool(action.get("await_result")):
                    await_delegations.append(
                        {
                            "target_bot": target_bot,
                            "target_name": target_rec["name"],
                            "instruction": instruction,
                            "next_hop": next_hop,
                        }
                    )
                    continue
                if in_room_turn:
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "target_bot": target_bot,
                            "instruction": instruction,
                            "hop_count": next_hop,
                            "in_room_handoff": True,
                        }
                    )
                    continue
                await self._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=target_bot,
                    event_type="operator.instruction",
                    payload={
                        "category": "reviews",
                        "title": f"{bot['name']} -> {target_rec['name']}",
                        "badge": f"Delegation · Hop {next_hop}/{MAX_HOP_COUNT}",
                        "badge_tone": "indigo",
                        "summary": instruction[:240],
                        "input_text": instruction,
                        "delegated_by": bot["slug"],
                        "hop_count": next_hop,
                    },
                    hop_count=next_hop,
                )
                results.append(
                    {"type": a_type, "status": "ok", "target_bot": target_bot, "hop_count": next_hop}
                )

            elif a_type == "propose_specialist_bot":
                spec_prompt = str(
                    action.get("prompt") or action.get("role") or action.get("name") or ""
                ).strip()
                if not spec_prompt:
                    continue
                from argo_core.runner.bot_builder import ConversationalBotBuilder

                builder = ConversationalBotBuilder(repo=self._repo)
                drafted = await builder.draft_bot_spec(spec_prompt)
                bot_spec = dict(drafted["draft"])
                if action.get("name"):
                    bot_spec["name"] = str(action["name"]).strip()[:120]
                    bot_spec["slug"] = slugify(bot_spec["name"])
                if action.get("role"):
                    bot_spec["role"] = str(action["role"]).strip()[:2000]
                if action.get("section"):
                    bot_spec["section"] = str(action["section"]).strip()[:80]
                queued = await self._approvals.enqueue_human_approval(
                    correlation_id=correlation_id,
                    bot_slug=bot["slug"],
                    target_account_slug="argo_workspace",
                    action_type="create_specialist_bot",
                    payload={
                        "title": f"Create Specialist Bot: {bot_spec['name']}",
                        "text": f"Role: {bot_spec['role']}\nSchedule: {bot_spec['routines'][0].get('schedule', 'Manual') if bot_spec.get('routines') else 'Manual'}",
                        "bot_spec": bot_spec,
                    },
                    escalation_note=f"Proposed by {bot['name']} for human confirmation.",
                    hop_count=hop_count,
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "queued_approval",
                        "approval_id": queued["id"],
                        "proposed_name": bot_spec["name"],
                    }
                )

            elif a_type == "propose_fleet_cleanup":
                operations = [
                    op for op in (action.get("operations") or []) if isinstance(op, dict) and op.get("bot_slug")
                ]
                if not operations:
                    continue
                reason = str(action.get("reason") or "Bot audit cleanup proposal").strip()
                lines = []
                for op in operations:
                    changes = []
                    if op.get("delete"):
                        changes.append("delete")
                    if op.get("enabled") is False:
                        changes.append("pause")
                    if op.get("hidden_in_sidebar"):
                        changes.append("hide from sidebar")
                    if op.get("section"):
                        changes.append(f"move to section '{op['section']}'")
                    lines.append(f"- {op['bot_slug']}: {', '.join(changes) or 'update'}")
                queued = await self._approvals.enqueue_human_approval(
                    correlation_id=correlation_id,
                    bot_slug=bot["slug"],
                    target_account_slug="argo_workspace",
                    action_type="fleet_cleanup",
                    payload={
                        "title": f"Bot Fleet Audit ({len(operations)} changes)",
                        "text": f"{reason}\n\n" + "\n".join(lines),
                        "operations": operations,
                    },
                    escalation_note=reason,
                    hop_count=hop_count,
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "queued_approval",
                        "approval_id": queued["id"],
                        "operations_count": len(operations),
                    }
                )

            elif a_type == "desktop_browse":
                url = str(action.get("url") or "").strip()
                if not url:
                    continue
                if bot["runtime"] != "desktop" or self._cdp_bridge is None:
                    msg = f"Bot '{bot['slug']}' runs in API-only mode and cannot invoke desktop_browse."
                    await self._bus.publish(
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                        target_slug="desktop",
                        event_type="connector.blocked",
                        payload={
                            "category": "alerts",
                            "title": f"Blocked Desktop Browse ({bot['name']})",
                            "badge": "Desktop Policy",
                            "badge_tone": "red",
                            "summary": msg,
                            "meta": "runtime='desktop' required",
                        },
                        hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                    )
                    results.append({"type": a_type, "status": "blocked_desktop_policy", "detail": msg})
                    continue

                try:
                    extracted = await self._cdp_bridge.navigate_and_extract(
                        bot["slug"],
                        url,
                        selector=str(action["selector"]) if action.get("selector") else None,
                        correlation_id=correlation_id,
                        max_chars=int(action.get("max_chars") or 12000),
                    )
                except DesktopStartupBlockedError as exc:
                    results.append({"type": a_type, "status": "queued_ram_gate", "detail": str(exc)})
                    continue
                except DesktopTakeoverRequiredError as exc:
                    results.append(
                        {
                            "type": a_type,
                            "status": "halted_takeover_required",
                            "gate_type": exc.gate_type,
                            "detail": str(exc),
                        }
                    )
                    continue
                except DesktopRuntimeError as exc:
                    err_item: dict[str, Any] = {
                        "type": a_type,
                        "status": "error",
                        "detail": redact_secrets(str(exc)),
                    }
                    if self._desktop_mcp is not None:
                        with suppress(Exception):
                            status_info = await self._desktop_mcp.inspect_desktop(
                                bot["slug"], correlation_id=correlation_id
                            )
                            err_item["desktop_status"] = {
                                "provision": status_info.get("provision"),
                                "cdp_proxy_ready": status_info.get("cdp_proxy_ready"),
                                "tools": status_info.get("tools"),
                            }
                            launch_res = await self._desktop_mcp.execute_action(
                                bot["slug"],
                                "launch",
                                {"app": "chromium", "url": url},
                                correlation_id=correlation_id,
                            )
                            err_item["fallback_launch"] = launch_res
                    results.append(err_item)
                    continue

                save_col = action.get("save_to_collection")
                if save_col:
                    clean_col = collection_slug(str(save_col))
                    if clean_col in allowed_write:
                        self._repo.upsert_document(
                            collection=clean_col,
                            external_key=extracted["url"],
                            search_text=f"{extracted['title']}\n{extracted['content']}"[:1000],
                            doc={
                                "title": extracted["title"],
                                "url": extracted["url"],
                                "content": extracted["content"],
                                "captured_via": extracted["container_name"],
                            },
                        )
                    else:
                        results.append(
                            {
                                "type": a_type,
                                "status": "blocked_collection_acl",
                                "url": extracted["url"],
                                "detail": f"Bot '{bot['slug']}' lacks write permission on '{clean_col}'.",
                            }
                        )
                        continue
                ok_item: dict[str, Any] = {
                    "type": a_type,
                    "status": "ok",
                    "url": extracted["url"],
                    "title": extracted["title"],
                    "container_name": extracted["container_name"],
                    "content": str(extracted.get("content") or "")[:4000],
                }
                results.append(ok_item)

            elif a_type in _ALL_DESKTOP_MCP_ACTIONS:
                mcp_res = await self._execute_desktop_mcp_action(
                    bot=bot,
                    a_type=a_type,
                    action=action,
                    correlation_id=correlation_id,
                    hop_count=hop_count,
                    turn_screenshots=turn_screenshots,
                )
                results.append(mcp_res)

            elif a_type == "upsert_page":
                page_title = str(action.get("title") or "").strip()
                page_slug_raw = str(action.get("slug") or page_title or "").strip()
                if target_page_slug:
                    page_slug_raw = target_page_slug
                    if not page_title:
                        with suppress(Exception):
                            page_title = str(self._repo.get_page(target_page_slug).get("title") or "")
                if not page_slug_raw or not page_title:
                    continue
                render_mode = str(action.get("render_mode") or "declarative_json").strip()
                requested_collections = [
                    collection_slug(str(c))
                    for c in (action.get("allowed_collections") or [])
                    if str(c).strip()
                ]
                allowed_bot_cols = allowed_write | {
                    collection_slug(str(c))
                    for c in (bot.get("collections", {}).get("read") or [])
                    if str(c).strip()
                }
                if not requested_collections:
                    existing_cols: list[str] = []
                    with suppress(Exception):
                        existing_cols = list(self._repo.get_page(slugify(page_slug_raw)).get("allowed_collections") or [])
                    bot_data_cols = [
                        c
                        for c in list(
                            dict.fromkeys(
                                [
                                    *data_write_cols,
                                    *[
                                        collection_slug(str(col))
                                        for col in (bot.get("collections", {}).get("read") or [])
                                        if str(col).strip()
                                    ],
                                ]
                            )
                        )
                        if c and c not in _INTERNAL_SYSTEM_COLLECTIONS
                    ]
                    requested_collections = existing_cols or bot_data_cols
                disallowed = [c for c in requested_collections if c not in allowed_bot_cols]
                if disallowed:
                    msg = (
                        f"Bot '{bot['slug']}' cannot bind page to unpermitted collections: "
                        f"{', '.join(disallowed)}."
                    )
                    await self._bus.publish(
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                        target_slug=slugify(page_slug_raw),
                        event_type="connector.blocked",
                        payload={
                            "category": "alerts",
                            "title": f"Blocked Page Bind ({bot['name']})",
                            "badge": "Page Collection ACL",
                            "badge_tone": "red",
                            "summary": msg,
                            "meta": f"Allowed: {sorted(allowed_bot_cols)}",
                        },
                        hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                    )
                    results.append({"type": a_type, "status": "blocked_collection_acl", "detail": msg})
                    continue

                raw_payload = action.get("content_payload")
                if isinstance(raw_payload, dict):
                    resolved_payload: str | None = json.dumps(raw_payload)
                elif raw_payload is not None:
                    resolved_payload = str(raw_payload)
                else:
                    resolved_payload = None

                try:
                    saved_page = self._repo.upsert_page_by_slug(
                        slug=page_slug_raw,
                        title=page_title,
                        render_mode=render_mode,
                        content_payload=resolved_payload,
                        allowed_collections=requested_collections,
                        owner_bot_slug=bot["slug"],
                        description=str(action.get("description") or ""),
                    )
                except ValueError as exc:
                    results.append(
                        {"type": a_type, "status": "blocked_invalid_payload", "detail": str(exc)}
                    )
                    continue

                await self._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=saved_page["slug"],
                    event_type="page.updated",
                    payload={
                        "category": "reviews",
                        "title": f"Updated Dynamic Page: {saved_page['title']}",
                        "badge": saved_page["render_mode"],
                        "badge_tone": "indigo",
                        "summary": f"Allowed collections: {', '.join(saved_page['allowed_collections']) or 'none'}",
                        "meta": f"Owner: {bot['slug']}",
                    },
                    hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "slug": saved_page["slug"],
                        "render_mode": saved_page["render_mode"],
                    }
                )

            else:
                results.append(
                    {
                        "type": a_type or "unknown",
                        "status": "skipped_unknown_action",
                        "detail": f"Unsupported action type '{a_type}'.",
                    }
                )

    async def _run_bot_llm_turn(
        self,
        *,
        bot: dict[str, Any],
        user_prompt: str,
        sys_prompt: str,
        trigger_type: str,
        corr_id: str,
        hop_count: int,
        images: list[bytes] | None,
        run_item: QueuedTurnItem | None,
        from_chat_thread: bool,
        vault_scrub_vals: list[str],
    ) -> Any:
        """Invoke LLMRouter.stream for live chat/queued runs or complete() for quiet background runs."""
        if run_item is None and not from_chat_thread:
            return await self._llm_router.complete(
                bot_slug=bot["slug"],
                prompt=user_prompt,
                requested_model=bot["model"],
                system_prompt=sys_prompt,
                trigger_type=trigger_type,
                correlation_id=corr_id,
                hop_count=hop_count,
                outbound_rbac=bot["outbound_rbac"],
                images=images,
            )

        extractor = _IncrementalSummaryExtractor()

        async def _on_raw_delta(raw_delta: str) -> None:
            prose = extractor.feed(raw_delta)
            if not prose or run_item is None or run_item.cancel_event.is_set():
                return
            safe_prose = redact_secrets(prose, vault_scrub_vals)
            if not safe_prose:
                return
            run_item.partial_text += safe_prose
            await self._emit_turn_stream(
                {
                    "type": "text_delta",
                    "run_id": run_item.run_id,
                    "thread_key": run_item.thread_key,
                    "target_type": run_item.target_type,
                    "target_slug": run_item.target_slug,
                    "bot_slug": bot["slug"],
                    "delta": safe_prose,
                }
            )

        llm_res = await self._llm_router.stream(
            bot_slug=bot["slug"],
            prompt=user_prompt,
            on_delta=_on_raw_delta,
            cancel_event=run_item.cancel_event if run_item is not None else None,
            extra_secrets=vault_scrub_vals,
            requested_model=bot["model"],
            system_prompt=sys_prompt,
            trigger_type=trigger_type,
            correlation_id=corr_id,
            hop_count=hop_count,
            outbound_rbac=bot["outbound_rbac"],
            images=images,
        )
        tail = extractor.finish()
        if tail and run_item is not None and not run_item.cancel_event.is_set():
            safe_tail = redact_secrets(tail, vault_scrub_vals)
            if safe_tail:
                run_item.partial_text += safe_tail
                await self._emit_turn_stream(
                    {
                        "type": "text_delta",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": bot["slug"],
                        "delta": safe_tail,
                    }
                )
        return llm_res

    @staticmethod
    def _extract_written_file_attachments(action_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Collect metadata for files written via write_workspace_file so replies link directly."""
        attachments: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for res in action_results:
            if res.get("type") != "write_workspace_file" or res.get("status") != "ok":
                continue
            fobj = res.get("file")
            if not isinstance(fobj, dict):
                continue
            fid = str(fobj.get("id") or "").strip()
            if not fid or fid in seen_ids:
                continue
            seen_ids.add(fid)
            attachments.append(
                {
                    "id": fid,
                    "filename": str(fobj.get("filename") or "file"),
                    "mime_type": str(fobj.get("mime_type") or "text/plain"),
                    "size_bytes": int(fobj.get("size_bytes") or 0),
                    "is_image": bool(fobj.get("is_image")),
                }
            )
        return attachments

    async def execute_bot(
        self,
        slug: str,
        *,
        trigger_type: str = "manual_trigger",
        correlation_id: str | None = None,
        hop_count: int = 1,
        trigger_payload: dict[str, Any] | None = None,
        routine_id: str | None = None,
        run_item: QueuedTurnItem | None = None,
    ) -> dict[str, Any]:
        """Run one isolated turn for a declarative bot with lock, dedup, LLM, and RBAC actions."""
        corr_id = correlation_id or make_id("corr")
        bot = self._repo.get_bot(slug)
        if not bot["enabled"]:
            return {
                "status": "skipped_disabled",
                "bot_slug": bot["slug"],
                "correlation_id": corr_id,
            }

        if hop_count > MAX_HOP_COUNT:
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot["slug"],
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=bot["model"],
                status="blocked",
                summary=f"Loop guard halted execution at hop {hop_count} (max {MAX_HOP_COUNT}).",
                started_at=utc_now(),
                finished_at=utc_now(),
            )
            await self._bus.publish(
                correlation_id=corr_id,
                source_slug=bot["slug"],
                target_slug="activity",
                event_type="bot.hop_limit_halted",
                payload={
                    "category": "alerts",
                    "title": f"Loop Guard Halted {bot['name']}",
                    "badge": f"Halted · Hop {hop_count}/{MAX_HOP_COUNT}",
                    "badge_tone": "amber",
                    "summary": f"Execution stopped cleanly because hop_count={hop_count} exceeded {MAX_HOP_COUNT}.",
                    "meta": f"Trigger: {trigger_type}",
                    "attempted_hop_count": hop_count,
                },
                hop_count=MAX_HOP_COUNT,
            )
            return {
                "status": "halted_hop_limit",
                "bot_slug": bot["slug"],
                "hop_count": hop_count,
                "correlation_id": corr_id,
            }

        payload = dict(trigger_payload or {})
        lock_key = str(payload.get("external_key") or routine_id or "default")
        acquired = await self._bus.acquire_lock("bot_run", f"{bot['slug']}:{lock_key}", bot["slug"], ttl_seconds=60)
        if not acquired:
            return {
                "status": "locked_conflict",
                "bot_slug": bot["slug"],
                "correlation_id": corr_id,
            }

        started_at = utc_now()
        trace_turns: list[dict[str, Any]] = []
        try:
            is_background_poll = trigger_type.startswith("cron") or trigger_type == "scheduled"
            active_routine = None
            if routine_id:
                active_routine = next(
                    (r for r in (bot.get("routines") or []) if isinstance(r, dict) and r.get("id") == routine_id),
                    None,
                )
            if isinstance(active_routine, dict):
                if active_routine.get("prompt") and not payload.get("routine_prompt"):
                    payload["routine_prompt"] = str(active_routine["prompt"])
                r_skill_slugs = [
                    slugify(str(s))
                    for s in (active_routine.get("skill_slugs") or [])
                    if str(s).strip()
                ]
                if r_skill_slugs:
                    existing_skills = list(payload.get("active_skills") or [])
                    seen_sk = {s.get("slug") for s in existing_skills if isinstance(s, dict)}
                    all_sk = {s["slug"]: s for s in self._repo.list_skills()}
                    for sk_slug in r_skill_slugs:
                        if sk_slug in all_sk and sk_slug not in seen_sk:
                            existing_skills.append(
                                {
                                    "slug": all_sk[sk_slug]["slug"],
                                    "name": all_sk[sk_slug]["name"],
                                    "description": all_sk[sk_slug]["description"],
                                    "instructions": all_sk[sk_slug]["instructions"],
                                }
                            )
                    if existing_skills:
                        payload["active_skills"] = existing_skills

            attachment_vision_images: list[bytes] = []
            raw_attachment_ids = [str(fid).strip() for fid in (payload.get("attachment_ids") or []) if str(fid).strip()]
            if raw_attachment_ids:
                op_email = str(payload.get("operator_email") or "").strip().lower() or None
                attached_meta_list: list[dict[str, Any]] = []
                for fid in raw_attachment_ids[:6]:
                    try:
                        fmeta, fpath = self._repo.get_workspace_file(fid, owner_email=op_email)
                        attached_meta_list.append(
                            {
                                "id": fmeta["id"],
                                "filename": fmeta["filename"],
                                "mime_type": fmeta["mime_type"],
                                "size_bytes": fmeta["size_bytes"],
                                "text_preview": str(fmeta.get("text_preview") or "")[:8000],
                            }
                        )
                        if fmeta.get("is_image") and fpath.stat().st_size <= 5 * 1024 * 1024:
                            attachment_vision_images.append(fpath.read_bytes())
                    except Exception:
                        continue
                if attached_meta_list:
                    payload["attached_files"] = attached_meta_list

            sources = self._collect_ingestion_sources(
                bot,
                routine_id=routine_id,
                trigger_payload=payload,
            )
            any_configured_sources = bool(
                sources.get("feeds")
                or sources.get("webpages")
                or sources.get("tg_channels")
                or sources.get("gmail_accounts")
            )
            has_sources = bool(
                sources.get("feeds")
                or sources.get("webpages")
                or sources.get("tg_channels")
                or (is_background_poll and sources.get("gmail_accounts"))
            )
            await self._emit_progress(
                bot["slug"],
                "running",
                "Checking sources..." if has_sources else "Starting...",
                corr_id,
            )
            raw_write_cols = [
                collection_slug(c) for c in (bot.get("collections", {}).get("write") or [])
            ]
            if any_configured_sources and not [
                c for c in raw_write_cols if c not in _INTERNAL_SYSTEM_COLLECTIONS
            ]:
                self._repo.ensure_bot_data_collection(bot["slug"])
                bot = self._repo.get_bot(bot["slug"])
                raw_write_cols = [
                    collection_slug(c) for c in (bot.get("collections", {}).get("write") or [])
                ]
            write_cols = [c for c in raw_write_cols if c != "bot_threads"] or raw_write_cols
            had_sources, unseen_entries, dedup_count = await self._poll_ingestion_sources(
                bot=bot,
                bot_slug=bot["slug"],
                correlation_id=corr_id,
                sources=sources,
                write_collections=write_cols,
                is_background_poll=is_background_poll,
            )

            stale_policy = (
                str(active_routine.get("stale_data_policy") or "skip_quietly")
                if isinstance(active_routine, dict)
                else "skip_quietly"
            )
            if had_sources and not unseen_entries and stale_policy != "always_run":
                summary = (
                    f"0 unseen items across polled sources ({dedup_count} already deduplicated by external_key)."
                )
                if stale_policy == "notify_missing" and (
                    not isinstance(active_routine, dict)
                    or str(active_routine.get("delivery_mode") or "chat_and_activity") != "silent"
                ):
                    routine_lbl = str(active_routine.get("label") or "Routine") if isinstance(active_routine, dict) else "Routine"
                    summary = f"{routine_lbl}: 0 new items found across polled sources ({dedup_count} already seen)."
                    if not payload.get("suppress_1to1_thread"):
                        self._repo.append_bot_message(bot["slug"], "bot", summary)
                elif trigger_type == "manual" and not payload.get("suppress_1to1_thread"):
                    self._repo.append_bot_message(bot["slug"], "bot", summary)
                run_rec = self._repo.record_bot_run(
                    correlation_id=corr_id,
                    bot_slug=bot["slug"],
                    trigger_type=trigger_type,
                    hop_count=hop_count,
                    llm_model_used=bot["model"],
                    input_tokens=0,
                    output_tokens=0,
                    estimated_cost_usd=0.0,
                    status="success",
                    summary=summary,
                    started_at=started_at,
                    finished_at=utc_now(),
                )
                self._record_debug_trace(
                    bot=bot,
                    correlation_id=corr_id,
                    trigger_type=trigger_type,
                    status="deduplicated_noop",
                    model_used=bot["model"],
                    tokens_used=0,
                    summary=summary,
                    turns=[{"turn": 0, "sources": sources, "deduplicated_count": dedup_count}],
                    started_at=started_at,
                )
                await self._bus.publish(
                    correlation_id=corr_id,
                    source_slug=bot["slug"],
                    target_slug=write_cols[0] if write_cols else "collections",
                    event_type="bot.run.deduplicated",
                    payload={
                        "category": "reviews",
                        "title": f"{bot['name']} · 0 New Items",
                        "badge": "0 Tokens · Deduplicated",
                        "badge_tone": "slate",
                        "summary": summary,
                        "meta": f"Hop {hop_count}/{MAX_HOP_COUNT}",
                    },
                    hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                )
                return {
                    "status": "deduplicated_noop",
                    "bot_slug": bot["slug"],
                    "correlation_id": corr_id,
                    "hop_count": hop_count,
                    "tokens_used": 0,
                    "new_items": 0,
                    "deduplicated_count": dedup_count,
                    "run": run_rec,
                }

            resolved_target_page_slug = self._resolve_target_page_slug(bot, payload)
            all_action_results: list[dict[str, Any]] = []
            tool_observations: list[dict[str, Any]] = []
            last_actions_list: list[dict[str, Any]] = []
            last_llm_result = None
            last_envelope: dict[str, Any] | None = None
            total_input_tokens = 0
            total_output_tokens = 0
            pending_vision_images: list[bytes] = list(attachment_vision_images)
            latest_desktop_png: bytes | None = None
            best_effort_shot_failed = False
            needs_final_synthesis = False
            max_turns = (
                MAX_DESKTOP_GUI_TURNS
                if (bot.get("runtime") == "desktop" and payload.get("active_skills"))
                else MAX_TOOL_TURNS
            )
            cancel_event = run_item.cancel_event if run_item is not None else None
            from_chat = bool(payload.get("from_chat_thread"))
            local_stream_item = False
            if run_item is None and from_chat and not payload.get("suppress_1to1_thread"):
                run_item = QueuedTurnItem(
                    run_id=make_id("run"),
                    thread_key=f"bot:{bot['slug']}",
                    target_type="bot",
                    target_slug=bot["slug"],
                    correlation_id=corr_id,
                    bot_slug=bot["slug"],
                    bot_name=bot["name"],
                )
                local_stream_item = True
                cancel_event = run_item.cancel_event
                await self._emit_turn_stream(
                    {
                        "type": "run_started",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": bot["slug"],
                        "bot_name": bot["name"],
                        "routed_reason": "",
                        "routing_source": "",
                    }
                )
            vault_scrub_vals = self._repo.collect_all_vault_secret_values()

            for turn_idx in range(1, MAX_DESKTOP_GUI_TURNS + 1):
                if cancel_event is not None and cancel_event.is_set():
                    break
                bot = self._repo.get_bot(bot["slug"])
                await self._emit_progress(
                    bot["slug"],
                    "running",
                    "Thinking..." if turn_idx == 1 else "Analyzing results...",
                    corr_id,
                )
                sys_prompt, user_prompt = self._build_context_isolated_prompt(
                    bot=bot,
                    correlation_id=corr_id,
                    hop_count=hop_count,
                    trigger_type=trigger_type,
                    trigger_payload=payload,
                    unseen_entries=unseen_entries if turn_idx == 1 else [],
                    tool_observations=tool_observations,
                    target_page_slug=resolved_target_page_slug,
                )

                llm_result = await self._run_bot_llm_turn(
                    bot=bot,
                    user_prompt=user_prompt,
                    sys_prompt=sys_prompt,
                    trigger_type=trigger_type,
                    corr_id=corr_id,
                    hop_count=hop_count,
                    images=pending_vision_images or None,
                    run_item=run_item,
                    from_chat_thread=from_chat,
                    vault_scrub_vals=vault_scrub_vals,
                )
                last_llm_result = llm_result
                total_input_tokens += llm_result.input_tokens
                total_output_tokens += llm_result.output_tokens

                if llm_result.cancelled or (cancel_event is not None and cancel_event.is_set()):
                    break

                envelope = _extract_json_envelope(llm_result.output_text)
                last_envelope = envelope
                actions_list = (
                    list(envelope.get("actions", []))
                    if envelope and isinstance(envelope.get("actions"), list)
                    else []
                )
                last_actions_list = actions_list
                captured_this_turn: list[bytes] = []
                turn_actions = await self._execute_actions(
                    bot=bot,
                    correlation_id=corr_id,
                    hop_count=hop_count,
                    actions=actions_list,
                    turn_screenshots=captured_this_turn,
                    target_page_slug=resolved_target_page_slug,
                    trigger_type=trigger_type,
                    trigger_payload=payload,
                    run_item=run_item,
                )
                if captured_this_turn:
                    latest_desktop_png = captured_this_turn[-1]
                    pending_vision_images = [captured_this_turn[-1]]
                    best_effort_shot_failed = False
                else:
                    pending_vision_images = []
                    if (
                        bot.get("runtime") == "desktop"
                        and any(
                            (r.get("type") == "desktop_browse" or r.get("type") in _DESKTOP_MCP_INTERACTIVE_ACTIONS)
                            and r.get("status") in {"ok", "error", "command_failed", "timeout"}
                            for r in turn_actions
                        )
                    ):
                        best_effort_shot_failed = True
                all_action_results.extend(turn_actions)
                if turn_actions:
                    tool_observations.extend(turn_actions)

                vault_scrub_vals = self._repo.collect_all_vault_secret_values()
                trace_turns.append(
                    {
                        "turn": turn_idx,
                        "prompt_preview": redact_secrets(user_prompt, vault_scrub_vals)[:1200],
                        "response_preview": redact_secrets(llm_result.output_text, vault_scrub_vals)[:1200],
                        "actions": actions_list,
                        "action_results": [
                            {k: v for k, v in item.items() if k not in {"markdown", "content", "env"}}
                            for item in turn_actions
                        ],
                    }
                )
                if cancel_event is not None and cancel_event.is_set():
                    break

                def _is_discovery_act(act: Any) -> bool:
                    if not isinstance(act, dict):
                        return False
                    norm = _normalize_action_type(act.get("type"))
                    if norm in _DISCOVERY_ONLY_ACTIONS or norm in _ALL_DESKTOP_MCP_ACTIONS:
                        return True
                    if norm == "delegate_to_bot" and bool(act.get("await_result")):
                        return True
                    return norm == "desktop_browse" and not act.get("save_to_collection")

                has_discovery_action = any(_is_discovery_act(act) for act in actions_list)
                has_non_discovery_action = any(
                    isinstance(act, dict) and not _is_discovery_act(act)
                    for act in actions_list
                )
                has_followup_observation = any(
                    (
                        res.get("type") in _DISCOVERY_ONLY_ACTIONS
                        or res.get("type") in _ALL_DESKTOP_MCP_ACTIONS
                        or res.get("type") == "desktop_browse"
                        or (res.get("type") == "delegate_to_bot" and bool(res.get("await_result")))
                    )
                    and res.get("status")
                    in {
                        "ok",
                        "error",
                        "command_failed",
                        "timeout",
                        "queued_ram_gate",
                        "halted_takeover_required",
                        "blocked_desktop_policy",
                        "blocked_vault_acl",
                        "not_found",
                    }
                    for res in turn_actions
                )
                if (
                    bot.get("runtime") == "desktop"
                    and any(
                        r.get("type")
                        in {
                            "desktop_launch",
                            "desktop_browse",
                            "desktop_click",
                            "desktop_type",
                            "desktop_key",
                            "desktop_scroll",
                            "desktop_focus_window",
                        }
                        for r in turn_actions
                    )
                    and not any(
                        r.get("status") in {"command_failed", "timeout", "error"}
                        for r in all_action_results
                    )
                ):
                    max_turns = MAX_DESKTOP_GUI_TURNS
                should_continue = (
                    has_discovery_action
                    and not has_non_discovery_action
                    and has_followup_observation
                )
                if should_continue and run_item is not None and run_item.partial_text:
                    run_item.partial_text = ""
                    await self._emit_turn_stream(
                        {
                            "type": "text_reset",
                            "run_id": run_item.run_id,
                            "thread_key": run_item.thread_key,
                            "target_type": run_item.target_type,
                            "target_slug": run_item.target_slug,
                            "bot_slug": bot["slug"],
                        }
                    )
                if not (should_continue and turn_idx < max_turns):
                    needs_final_synthesis = bool(should_continue and turn_idx == max_turns)
                    break

            if (
                needs_final_synthesis
                and tool_observations
                and not (cancel_event is not None and cancel_event.is_set())
            ):
                bot = self._repo.get_bot(bot["slug"])
                await self._emit_progress(
                    bot["slug"],
                    "running",
                    "Summarizing results...",
                    corr_id,
                )
                sys_prompt, user_prompt = self._build_context_isolated_prompt(
                    bot=bot,
                    correlation_id=corr_id,
                    hop_count=hop_count,
                    trigger_type=trigger_type,
                    trigger_payload=payload,
                    unseen_entries=[],
                    tool_observations=tool_observations,
                    target_page_slug=resolved_target_page_slug,
                    synthesis_only=True,
                )
                synth_result = await self._run_bot_llm_turn(
                    bot=bot,
                    user_prompt=user_prompt,
                    sys_prompt=sys_prompt,
                    trigger_type=trigger_type,
                    corr_id=corr_id,
                    hop_count=hop_count,
                    images=pending_vision_images or None,
                    run_item=run_item,
                    from_chat_thread=from_chat,
                    vault_scrub_vals=vault_scrub_vals,
                )
                last_llm_result = synth_result
                total_input_tokens += synth_result.input_tokens
                total_output_tokens += synth_result.output_tokens
                envelope = _extract_json_envelope(synth_result.output_text)
                last_envelope = envelope
                last_actions_list = []
                vault_scrub_vals = self._repo.collect_all_vault_secret_values()
                trace_turns.append(
                    {
                        "turn": MAX_TOOL_TURNS + 1,
                        "prompt_preview": redact_secrets(user_prompt, vault_scrub_vals)[:1200],
                        "response_preview": redact_secrets(synth_result.output_text, vault_scrub_vals)[:1200],
                        "actions": [],
                        "action_results": [],
                    }
                )

            if cancel_event is not None and cancel_event.is_set():
                vault_scrub_vals = self._repo.collect_all_vault_secret_values()
                partial_raw = (
                    (run_item.partial_text if run_item is not None else "")
                    or (
                        str(last_envelope.get("summary") or "").strip()
                        if last_envelope
                        else (last_llm_result.output_text.strip() if last_llm_result else "")
                    )
                )
                partial_clean = redact_secrets(partial_raw.strip(), vault_scrub_vals)
                stopped_text = f"{partial_clean}\n\n*(Stopped)*" if partial_clean else "*(Stopped)*"
                tokens_used = total_input_tokens + total_output_tokens
                compact_actions = [
                    {k: v for k, v in item.items() if k not in {"markdown", "content"}}
                    for item in all_action_results
                ]
                cancel_meta: dict[str, Any] = {
                    "correlation_id": corr_id,
                    "trigger_type": trigger_type,
                    "model_used": last_llm_result.model_used if last_llm_result else bot["model"],
                    "tokens_used": tokens_used,
                    "actions": compact_actions,
                    "stopped_by_user": True,
                }
                if run_item is not None:
                    cancel_meta["run_id"] = run_item.run_id
                    if run_item.chips:
                        cancel_meta["chips"] = list(run_item.chips)
                written_cancel_files = self._extract_written_file_attachments(compact_actions)
                if written_cancel_files:
                    cancel_meta["attachments"] = written_cancel_files
                if not bool(payload.get("suppress_1to1_thread")):
                    saved_msg = self._repo.append_bot_message(
                        bot["slug"],
                        "bot",
                        stopped_text,
                        metadata=cancel_meta,
                    )
                    if run_item is not None:
                        run_item.message_id = saved_msg["id"]
                self._record_debug_trace(
                    bot=bot,
                    correlation_id=corr_id,
                    trigger_type=trigger_type,
                    status="cancelled",
                    model_used=last_llm_result.model_used if last_llm_result else bot["model"],
                    tokens_used=tokens_used,
                    summary=stopped_text,
                    turns=trace_turns,
                    started_at=started_at,
                )
                return {
                    "status": "cancelled",
                    "bot_slug": bot["slug"],
                    "correlation_id": corr_id,
                    "hop_count": hop_count,
                    "model_used": last_llm_result.model_used if last_llm_result else bot["model"],
                    "tokens_used": tokens_used,
                    "summary": stopped_text,
                    "actions": all_action_results,
                    "metadata": cancel_meta,
                    "run": last_llm_result.run_record if last_llm_result else None,
                }

            assert last_llm_result is not None
            vault_scrub_vals = self._repo.collect_all_vault_secret_values()
            summary_text = redact_secrets(
                (
                    str(last_envelope.get("summary") or "").strip()
                    if last_envelope
                    else last_llm_result.output_text.strip()
                )
                or f"Completed {trigger_type} turn.",
                vault_scrub_vals,
            )

            last_exec_res = next(
                (r for r in reversed(all_action_results) if r.get("type") == "desktop_exec"),
                None,
            )
            if last_exec_res and last_exec_res.get("status") in {"command_failed", "timeout"}:
                failed_cmd = str(last_exec_res.get("failed_command") or "").strip()
                exit_code = last_exec_res.get("exit_code")
                err_tail = str(
                    last_exec_res.get("stderr") or last_exec_res.get("detail") or ""
                ).strip()[-600:]
                already_reported = (
                    (bool(failed_cmd) and failed_cmd in summary_text)
                    or (exit_code is not None and str(exit_code) in summary_text)
                )
                if not already_reported:
                    diag = f"\n\nCommand failed (exit_code={exit_code}): `{failed_cmd}`" if failed_cmd else f"\n\nCommand failed (exit_code={exit_code})."
                    if err_tail:
                        diag += f"\n```text\n{err_tail}\n```"
                    summary_text = f"{summary_text}{diag}".strip()

            user_input_str = str(payload.get("input_text") or payload.get("text") or "").strip()
            if (
                not is_background_poll
                and user_input_str
                and _OPEN_BOARD_RE.search(user_input_str)
                and not _BOARD_EDIT_VERBS_RE.search(user_input_str)
                and not any(r.get("type") == "open_page" and r.get("status") == "ok" for r in all_action_results)
            ):
                auto_open = await self._execute_actions(
                    bot=bot,
                    correlation_id=corr_id,
                    hop_count=hop_count,
                    actions=[{"type": "open_page", "slug": resolved_target_page_slug or "", "mode": "split"}],
                    target_page_slug=resolved_target_page_slug,
                    trigger_type=trigger_type,
                    trigger_payload=payload,
                )
                all_action_results.extend(auto_open)
                opened_ok = next((r for r in auto_open if r.get("type") == "open_page" and r.get("status") == "ok"), None)
                if opened_ok and last_llm_result.unconfigured_local:
                    summary_text = f"Opening **{opened_ok['title']}** beside our chat now."

            for item in all_action_results:
                item.pop("screenshot_url", None)
            target_desktop_res = next(
                (
                    r
                    for r in reversed(all_action_results)
                    if (
                        r.get("type") == "desktop_browse"
                        or r.get("type") in _ALL_DESKTOP_MCP_ACTIONS
                    )
                    and r.get("status") in {"ok", "error", "command_failed", "timeout"}
                ),
                None,
            )
            if target_desktop_res is not None and self._desktop_mcp is not None:
                if latest_desktop_png is None and not best_effort_shot_failed:
                    with suppress(Exception):
                        latest_desktop_png, _ = await self._desktop_mcp.capture_screenshot(
                            bot["slug"],
                            correlation_id=corr_id,
                            ready_timeout_seconds=2.5,
                        )
                if latest_desktop_png:
                    final_snap_url = self._save_snapshot_url(
                        bot["slug"],
                        latest_desktop_png,
                        caption=f"Final state: {target_desktop_res['type']}",
                        url=str(target_desktop_res.get("url") or ""),
                    )
                    if final_snap_url:
                        target_desktop_res["screenshot_url"] = final_snap_url

            has_outbound_action = any(
                isinstance(act, dict)
                and _normalize_action_type(act.get("type"))
                in {"connector_publish", "publish_telegram", "request_human_approval"}
                for act in last_actions_list
            )
            tg_account_slug = str(payload.get("account_slug") or "").strip()
            if (
                trigger_type == "on_event:telegram.message"
                and bot["outbound_rbac"] in {"draft", "execute"}
                and not has_outbound_action
                and tg_account_slug
                and summary_text
            ):
                if not self._is_account_permitted(bot, tg_account_slug):
                    all_action_results.append(
                        await self._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=corr_id,
                            hop_count=hop_count,
                            action_type="publish_telegram",
                            account_slug=tg_account_slug,
                        )
                    )
                else:
                    try:
                        gate_res = await self._approvals.execute_or_queue_outbound(
                            bot=bot,
                            correlation_id=corr_id,
                            hop_count=hop_count,
                            account_slug=tg_account_slug,
                            action_type="publish_telegram",
                            text=summary_text,
                            target=str(payload["chat_id"]) if payload.get("chat_id") else None,
                        )
                        all_action_results.append({"type": "publish_telegram", **gate_res})
                    except ConnectorPermissionError as exc:
                        all_action_results.append(
                            {"type": "publish_telegram", "status": "blocked_rbac", "detail": str(exc)}
                        )

            handoff_slug = str(bot.get("handoff_bot_slug") or "").strip()
            already_delegated = any(
                r.get("type") == "delegate_to_bot" and r.get("target_bot") == handoff_slug
                for r in all_action_results
            )
            saved_new_docs = any(
                r.get("type") == "upsert_document" and r.get("status") == "ok"
                for r in all_action_results
            )
            if handoff_slug and hop_count < MAX_HOP_COUNT and saved_new_docs and not already_delegated:
                try:
                    target_rec = self._repo.get_bot(handoff_slug)
                    if target_rec.get("enabled"):
                        next_hop = hop_count + 1
                        await self._emit_progress(
                            bot["slug"],
                            "running",
                            f"Handing off to {target_rec['name']}...",
                            corr_id,
                        )
                        await self._bus.publish(
                            correlation_id=corr_id,
                            source_slug=bot["slug"],
                            target_slug=handoff_slug,
                            event_type="operator.instruction",
                            payload={
                                "category": "reviews",
                                "title": f"{bot['name']} -> {target_rec['name']}",
                                "badge": f"Handoff · Hop {next_hop}/{MAX_HOP_COUNT}",
                                "badge_tone": "indigo",
                                "summary": f"Handoff from {bot['name']}: {summary_text[:200]}",
                                "input_text": f"Handoff from {bot['name']}:\n{summary_text}",
                                "delegated_by": bot["slug"],
                                "hop_count": next_hop,
                            },
                            hop_count=next_hop,
                        )
                        all_action_results.append(
                            {
                                "type": "delegate_to_bot",
                                "status": "ok",
                                "target_bot": handoff_slug,
                                "hop_count": next_hop,
                            }
                        )
                except Exception:
                    logger.debug("Auto-handoff target %s unavailable", handoff_slug, exc_info=True)

            primary_data_write = (
                write_cols[0]
                if write_cols and write_cols[0] != "bot_threads"
                else None
            )
            if primary_data_write and unseen_entries:
                for unseen in unseen_entries:
                    if unseen.get("source_type") != "gmail":
                        continue
                    ext_key = str(unseen.get("external_key") or "").strip()
                    if not ext_key:
                        continue
                    with suppress(Exception):
                        self._repo.upsert_document(
                            collection=primary_data_write,
                            external_key=ext_key,
                            search_text=(
                                f"{unseen.get('subject', '')} {unseen.get('from', '')} "
                                f"{unseen.get('snippet', '')}"
                            )[:1000],
                            doc={
                                "source_type": "gmail",
                                "account_slug": unseen.get("account_slug", ""),
                                "message_id": unseen.get("message_id", ""),
                                "thread_id": unseen.get("thread_id"),
                                "from": unseen.get("from", ""),
                                "to": unseen.get("to", ""),
                                "subject": unseen.get("subject", "(No subject)"),
                                "date": unseen.get("date", ""),
                                "snippet": unseen.get("snippet", ""),
                                "label_ids": unseen.get("label_ids") or [],
                            },
                            description=f"Processed Gmail message for {bot['name']}",
                        )
            if unseen_entries:
                with suppress(Exception):
                    self._repo.mark_ingestion_keys_seen(
                        bot["slug"],
                        [
                            str(u.get("external_key") or "")
                            for u in unseen_entries
                            if u.get("external_key")
                        ],
                    )

            tokens_used = total_input_tokens + total_output_tokens
            compact_actions = [
                {k: v for k, v in item.items() if k not in {"markdown", "content"}}
                for item in all_action_results
            ]
            routine_delivery = "chat_and_activity"
            if routine_id:
                for rtn in bot.get("routines") or []:
                    if isinstance(rtn, dict) and rtn.get("id") == routine_id:
                        routine_delivery = str(rtn.get("delivery_mode") or "chat_and_activity")
                        break
            skip_thread_log = (
                bool(payload.get("suppress_1to1_thread"))
                or routine_delivery == "silent"
                or (
                    is_background_poll
                    and len(compact_actions) == 0
                    and len(unseen_entries) == 0
                )
            )
            reply_meta: dict[str, Any] = {
                "correlation_id": corr_id,
                "trigger_type": trigger_type,
                "model_used": last_llm_result.model_used,
                "tokens_used": tokens_used,
                "actions": compact_actions,
            }
            if run_item is not None:
                reply_meta["run_id"] = run_item.run_id
                if run_item.chips:
                    reply_meta["chips"] = list(run_item.chips)
            written_files = self._extract_written_file_attachments(compact_actions)
            if written_files:
                reply_meta["attachments"] = written_files
            if trigger_type == "operator_event" and payload.get("delegated_by"):
                reply_meta["delegated_by"] = str(payload["delegated_by"])
            applied_cfg_list = [
                r.get("applied_changes")
                for r in compact_actions
                if r.get("type") == "update_self_config" and r.get("applied_changes")
            ]
            if applied_cfg_list:
                merged_cfg: dict[str, Any] = {}
                for chunk in applied_cfg_list:
                    if isinstance(chunk, dict):
                        merged_cfg.update(chunk)
                if merged_cfg:
                    reply_meta["applied_changes"] = merged_cfg
            proposed_plan = next(
                (
                    r.get("plan")
                    for r in reversed(compact_actions)
                    if r.get("type") == "propose_delegation_plan" and r.get("status") == "proposed" and r.get("plan")
                ),
                None,
            )
            if proposed_plan:
                reply_meta["delegation_plan"] = proposed_plan
            if (
                trigger_type == "manual"
                and not payload.get("suppress_1to1_thread")
                and any(
                    r.get("type") in _SUBSTANTIVE_HABIT_ACTION_TYPES and r.get("status") in {"ok", "queued_approval"}
                    for r in compact_actions
                )
                and not any(
                    r.get("type") in {"configure_routine", "save_skill", "update_self_config", "open_page"}
                    for r in compact_actions
                )
            ):
                base_title = (user_input_str[:42] if user_input_str else f"{bot['name']} Check").strip(" .?!")
                reply_meta["habit_proposal"] = {
                    "suggested_skill_name": f"{bot['name']} · {base_title}"[:70],
                    "suggested_routine_label": base_title[:60] or f"{bot['name']} Routine",
                    "suggested_schedule": "Every weekday at 09:00",
                    "suggested_instructions": user_input_str or summary_text[:500],
                }
            if not skip_thread_log:
                saved_msg = self._repo.append_bot_message(
                    bot["slug"],
                    "bot",
                    summary_text,
                    metadata=reply_meta,
                )
                if run_item is not None and run_item.target_type == "bot":
                    run_item.message_id = saved_msg["id"]

            if local_stream_item and run_item is not None:
                await self._emit_turn_stream(
                    {
                        "type": "run_finished",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": bot["slug"],
                        "message_id": run_item.message_id,
                        "status": "completed",
                    }
                )

            self._record_debug_trace(
                bot=bot,
                correlation_id=corr_id,
                trigger_type=trigger_type,
                status="completed",
                model_used=last_llm_result.model_used,
                tokens_used=tokens_used,
                summary=summary_text,
                turns=trace_turns,
                started_at=started_at,
            )
            await self._bus.publish(
                correlation_id=corr_id,
                source_slug=bot["slug"],
                target_slug=slugify(trigger_type),
                event_type="bot.run.completed",
                payload={
                    "category": "reviews",
                    "title": f"{bot['name']} Completed ({trigger_type})",
                    "badge": f"Hop {hop_count}/{MAX_HOP_COUNT} · {last_llm_result.model_used}",
                    "badge_tone": "emerald",
                    "summary": summary_text[:280],
                    "meta": f"{tokens_used} tokens · {len(all_action_results)} action(s)",
                    "actions_count": len(all_action_results),
                },
                hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
            )
            return {
                "status": "completed",
                "bot_slug": bot["slug"],
                "correlation_id": corr_id,
                "hop_count": hop_count,
                "model_used": last_llm_result.model_used,
                "tokens_used": tokens_used,
                "summary": summary_text,
                "actions": all_action_results,
                "metadata": reply_meta,
                "run": last_llm_result.run_record,
            }
        except Exception as exc:
            self._record_debug_trace(
                bot=bot,
                correlation_id=corr_id,
                trigger_type=trigger_type,
                status="error",
                model_used=bot["model"],
                tokens_used=0,
                summary=f"Run failed: {redact_secrets(str(exc))}",
                turns=trace_turns,
                started_at=started_at,
                error=redact_secrets(str(exc)),
            )
            raise
        finally:
            await self._emit_progress(bot["slug"], "idle", "", corr_id)
            await self._bus.release_lock("bot_run", f"{bot['slug']}:{lock_key}", bot["slug"])

    def _record_debug_trace(
        self,
        *,
        bot: dict[str, Any],
        correlation_id: str,
        trigger_type: str,
        status: str,
        model_used: str,
        tokens_used: int,
        summary: str,
        turns: list[dict[str, Any]],
        started_at: str,
        error: str | None = None,
    ) -> None:
        """Persist a secret-redacted run trace in debug_run_traces (bounded at 150 traces)."""
        try:
            trace_doc = {
                "bot_slug": bot["slug"],
                "bot_name": bot["name"],
                "correlation_id": correlation_id,
                "trigger_type": trigger_type,
                "status": status,
                "model_used": model_used,
                "tokens_used": tokens_used,
                "summary": redact_secrets(summary)[:1000],
                "error": redact_secrets(error)[:500] if error else None,
                "turns": json.loads(redact_secrets(json.dumps(turns, default=str))),
                "started_at": started_at,
                "finished_at": utc_now(),
            }
            self._repo.upsert_document(
                collection="debug_run_traces",
                external_key=f"trace:{correlation_id}:{bot['slug']}:{started_at}",
                search_text=f"{bot['slug']} {trigger_type} {status} {trace_doc['summary']}",
                doc=trace_doc,
                description="Redacted per-run LLM & tool execution traces for on-demand Debug console",
            )
            existing = self._repo.search_documents("debug_run_traces", limit=200)
            if len(existing) > 150:
                for old_doc in existing[150:]:
                    self._repo.delete_document("debug_run_traces", old_doc["id"])
        except Exception:
            logger.debug("Unable to persist debug_run_trace for %s", bot["slug"], exc_info=True)

    @staticmethod
    def _extract_room_member_mentions(
        text: str,
        members: list[dict[str, Any]],
    ) -> list[str]:
        """Resolve @slug or @Bot Name mentions to member slugs in order of appearance."""
        if not text:
            return []
        lower_text = text.lower()
        matches: list[tuple[int, str]] = []
        for member in members:
            slug = str(member.get("slug") or "")
            name = str(member.get("name") or "").strip()
            best_pos: int | None = None
            candidates = [slug]
            if name:
                candidates.append(name)
            for cand in sorted(set(candidates), key=len, reverse=True):
                if not cand:
                    continue
                pat = re.compile(rf"(?<!\w)@{re.escape(cand.lower())}(?!\w)")
                found = pat.search(lower_text)
                if found and (best_pos is None or found.start() < best_pos):
                    best_pos = found.start()
            if best_pos is not None:
                matches.append((best_pos, slug))
        matches.sort(key=lambda item: item[0])
        ordered: list[str] = []
        for _, slug in matches:
            if slug not in ordered:
                ordered.append(slug)
        return ordered

    async def execute_delegation_plan(
        self,
        plan_id: str,
        *,
        operator_email: str | None = None,
        edited_steps: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute an approved multi-bot delegation plan round-trip and synthesize one combined reply."""
        plan = self._repo.get_delegation_plan(plan_id)
        if str(plan.get("status") or "") == "completed":
            return {
                "status": "already_completed",
                "plan": plan,
                "synthesis": str(plan.get("synthesis") or ""),
                "results": list(plan.get("results") or []),
                "message": None,
            }

        coord_slug = slugify(str(plan.get("coordinator_slug") or ""))
        coord_bot = self._repo.get_bot(coord_slug)
        corr_id = str(plan.get("correlation_id") or make_id("planrun"))
        room_slug = str(plan.get("room_slug") or "").strip() or None
        bots_by_slug = {b["slug"]: b for b in self._repo.list_bots()}

        raw_steps = list(edited_steps if edited_steps is not None else (plan.get("steps") or []))
        steps: list[dict[str, Any]] = []
        for idx, st in enumerate(raw_steps[:8]):
            if not isinstance(st, dict):
                continue
            b_slug = slugify(str(st.get("bot_slug") or st.get("target_bot") or ""))
            task_txt = str(st.get("task") or st.get("instruction") or "").strip()
            if not b_slug or not task_txt or b_slug not in bots_by_slug:
                continue
            steps.append(
                {
                    "id": str(st.get("id") or f"step_{idx + 1}"),
                    "bot_slug": b_slug,
                    "bot_name": bots_by_slug[b_slug]["name"],
                    "task": task_txt,
                    "parallel_group": max(1, int(st.get("parallel_group") or 1)),
                }
            )
        if not steps:
            raise ValueError("Delegation plan contains no valid enabled specialist steps.")

        running_plan = self._repo.save_delegation_plan(
            {
                **plan,
                "steps": steps,
                "status": "running",
                "started_at": utc_now(),
            }
        )

        groups: dict[int, list[dict[str, Any]]] = {}
        for st in steps:
            groups.setdefault(int(st["parallel_group"]), []).append(st)

        step_outputs: list[dict[str, Any]] = []
        room_ctx: dict[str, Any] | None = None
        if room_slug:
            with suppress(Exception):
                r_obj = self._repo.get_room(room_slug)
                room_ctx = {
                    "room_slug": r_obj["slug"],
                    "room_title": r_obj["title"],
                    "coordinator_bot_slug": r_obj.get("coordinator_bot_slug"),
                    "members": [
                        {
                            "slug": bots_by_slug[m]["slug"],
                            "name": bots_by_slug[m]["name"],
                            "role": bots_by_slug[m].get("role", ""),
                        }
                        for m in r_obj["member_bot_slugs"]
                        if m in bots_by_slug
                    ],
                }

        async def _run_step(st: dict[str, Any]) -> dict[str, Any]:
            b_slug = st["bot_slug"]
            b_name = st["bot_name"]
            try:
                res = await self.execute_bot(
                    b_slug,
                    trigger_type="delegation_plan_step",
                    correlation_id=corr_id,
                    hop_count=2,
                    trigger_payload={
                        "input_text": st["task"],
                        "text": st["task"],
                        "delegated_by": coord_slug,
                        "operator_email": operator_email or "",
                        "suppress_1to1_thread": True,
                        "from_chat_thread": True,
                        **({"room_context": room_ctx} if room_ctx else {}),
                    },
                )
                return {
                    "step_id": st["id"],
                    "bot_slug": b_slug,
                    "bot_name": b_name,
                    "task": st["task"],
                    "parallel_group": st["parallel_group"],
                    "status": str(res.get("status") or "completed"),
                    "summary": str(res.get("summary") or "").strip(),
                    "tokens_used": int(res.get("tokens_used") or 0),
                    "actions": list(res.get("actions") or []),
                }
            except Exception as exc:
                return {
                    "step_id": st["id"],
                    "bot_slug": b_slug,
                    "bot_name": b_name,
                    "task": st["task"],
                    "parallel_group": st["parallel_group"],
                    "status": "error",
                    "summary": f"Step failed: {redact_secrets(str(exc))}",
                    "tokens_used": 0,
                    "actions": [],
                }

        for grp_idx in sorted(groups.keys()):
            grp_results = await asyncio.gather(*(_run_step(st) for st in groups[grp_idx]))
            step_outputs.extend(grp_results)
            if room_slug:
                for st_out in grp_results:
                    step_attachments = self._extract_written_file_attachments(st_out["actions"])
                    self._repo.append_room_message(
                        room_slug,
                        sender_type="bot",
                        sender_slug=st_out["bot_slug"],
                        sender_name=st_out["bot_name"],
                        text=st_out["summary"] or f"Completed: {st_out['task']}",
                        metadata={
                            "correlation_id": corr_id,
                            "plan_id": plan_id,
                            "step_id": st_out["step_id"],
                            "delegated_by": coord_slug,
                            "actions": st_out["actions"],
                            **({"attachments": step_attachments} if step_attachments else {}),
                        },
                    )

        sys_prompt, user_prompt = self._build_context_isolated_prompt(
            bot=coord_bot,
            correlation_id=corr_id,
            hop_count=1,
            trigger_type="delegation_plan_synthesis",
            trigger_payload={
                "input_text": f"Combine specialist findings for goal: {running_plan.get('goal', '')}",
                "text": str(running_plan.get("goal") or ""),
                "specialist_results": step_outputs,
                "from_chat_thread": True,
                **({"room_context": room_ctx} if room_ctx else {}),
            },
            unseen_entries=[],
            tool_observations=step_outputs,
            synthesis_only=True,
        )
        synth_tokens = 0
        synth_model = coord_bot["model"]
        synthesis_text = ""
        try:
            synth_llm = await self._llm_router.complete(
                bot_slug=coord_bot["slug"],
                prompt=user_prompt,
                requested_model=coord_bot["model"],
                system_prompt=sys_prompt,
                trigger_type="delegation_plan_synthesis",
                correlation_id=corr_id,
                hop_count=1,
                outbound_rbac=coord_bot["outbound_rbac"],
            )
            synth_tokens = synth_llm.input_tokens + synth_llm.output_tokens
            synth_model = synth_llm.model_used
            if not synth_llm.unconfigured_local:
                env = _extract_json_envelope(synth_llm.output_text)
                synthesis_text = (
                    str(env.get("summary") or "").strip() if env else synth_llm.output_text.strip()
                )
        except Exception:
            logger.debug("Delegation plan synthesis LLM call failed; falling back to structured rollup.", exc_info=True)

        vault_vals = self._repo.collect_all_vault_secret_values()
        if not synthesis_text:
            lines = [f"**Combined Summary — {running_plan.get('goal', 'Plan Complete')}**\n"]
            for st_out in step_outputs:
                lines.append(f"- **{st_out['bot_name']}** ({st_out['status']}): {st_out['summary']}")
            synthesis_text = "\n".join(lines)
        synthesis_text = redact_secrets(synthesis_text, vault_vals)

        completed_plan = self._repo.save_delegation_plan(
            {
                **running_plan,
                "status": "completed",
                "results": step_outputs,
                "synthesis": synthesis_text,
                "completed_at": utc_now(),
            }
        )
        msg_meta: dict[str, Any] = {
            "correlation_id": corr_id,
            "plan_id": plan_id,
            "delegation_plan": completed_plan,
            "model_used": synth_model,
            "tokens_used": synth_tokens,
        }
        if room_slug:
            final_msg = self._repo.append_room_message(
                room_slug,
                sender_type="bot",
                sender_slug=coord_bot["slug"],
                sender_name=coord_bot["name"],
                text=synthesis_text,
                metadata=msg_meta,
            )
        else:
            final_msg = self._repo.append_bot_message(
                coord_bot["slug"],
                "bot",
                synthesis_text,
                metadata=msg_meta,
            )

        await self._bus.publish(
            correlation_id=corr_id,
            source_slug=coord_bot["slug"],
            target_slug=room_slug or coord_bot["slug"],
            event_type="bot.plan.completed",
            payload={
                "category": "reviews",
                "title": f"{coord_bot['name']} Completed Multi-Bot Plan",
                "badge": f"{len(step_outputs)} Specialist(s)",
                "badge_tone": "emerald",
                "summary": synthesis_text[:280],
                "plan_id": plan_id,
            },
            hop_count=1,
        )
        return {
            "status": "completed",
            "plan": completed_plan,
            "synthesis": synthesis_text,
            "results": step_outputs,
            "message": final_msg,
        }

    def _match_unique_room_capability(
        self,
        clean_text: str,
        member_bots: list[dict[str, Any]],
    ) -> tuple[str, str] | None:
        """Tier 1 (0-token): route only when a single specialist exclusively owns the requested capability."""
        lower = clean_text.lower()
        if not lower:
            return None

        def _bot_has_tool(b: dict[str, Any], name: str) -> bool:
            return any(
                (isinstance(t, str) and t == name)
                or (isinstance(t, dict) and str(t.get("name") or "") == name)
                for t in (b.get("tools") or [])
            )

        integrations_by_slug = {acc["slug"]: acc for acc in self._repo.list_integrations()}

        def _bot_has_provider(b: dict[str, Any], provider: str) -> bool:
            if not b.get("linked_accounts_restricted"):
                return any(acc.get("provider") == provider for acc in integrations_by_slug.values())
            linked = {slugify(str(a)) for a in (b.get("linked_accounts") or []) if str(a).strip()}
            return any(
                acc_slug in linked and acc.get("provider") == provider
                for acc_slug, acc in integrations_by_slug.items()
            )

        desktop_bots = [b for b in member_bots if b.get("runtime") == "desktop"]
        if len(desktop_bots) == 1 and re.search(
            r"\b(screenshot|browser|ssl|certificate|tls|virtual desktop|selkies|chromium|terminal|ssh|login page)\b",
            lower,
        ):
            reason = (
                "Browser & SSL inspection"
                if re.search(r"\b(ssl|certificate|tls|browser|screenshot)\b", lower)
                else "Virtual Desktop inspection"
            )
            return desktop_bots[0]["slug"], reason

        if re.search(r"\b(gmail|inbox|unread email|emails?)\b", lower):
            gmail_bots = [
                b
                for b in member_bots
                if _bot_has_tool(b, "gmail_search") or _bot_has_provider(b, "google")
            ]
            if len(gmail_bots) == 1:
                return gmail_bots[0]["slug"], "Gmail capability match"

        if re.search(r"\b(telegram|t\.me)\b", lower):
            tg_bots = [
                b
                for b in member_bots
                if _bot_has_tool(b, "fetch_telegram_public_channel") or _bot_has_provider(b, "telegram")
            ]
            if len(tg_bots) == 1:
                return tg_bots[0]["slug"], "Telegram capability match"

        if re.search(r"\blinkedin\b", lower):
            li_bots = [b for b in member_bots if _bot_has_provider(b, "linkedin")]
            if len(li_bots) == 1:
                return li_bots[0]["slug"], "LinkedIn capability match"

        return None

    async def _pick_room_speaker_with_flash(
        self,
        *,
        room: dict[str, Any],
        clean_text: str,
        member_bots: list[dict[str, Any]],
        recent_msgs: list[dict[str, Any]],
    ) -> tuple[str, str] | None:
        """Tier 2 (<= 800 ms): micro-classifier selecting best Room specialist."""
        has_transport = getattr(self._llm_router, "_transport", None) is not None
        all_providers = self._repo.list_model_provider_credentials()
        configured = [
            p
            for p in all_providers
            if (p.get("provider_type") == "ollama" and (p.get("api_base") or p.get("api_key")))
            or p.get("api_key")
        ]
        if not has_transport and not configured:
            return None

        flash_model = next(
            (p["model_id"] for p in configured if p["model_id"] == "google:gemini-3.8-flash"),
            configured[0]["model_id"] if configured else "google:gemini-3.8-flash",
        )
        roster_lines = [
            f"- {b['slug']}: {str(b.get('role') or b['name'])[:80]}"
            for b in member_bots
        ]
        history_lines = [
            f"{m.get('sender_name', 'User')}: {str(m.get('text') or '')[:90]}"
            for m in recent_msgs[-3:]
            if str(m.get("text") or "").strip()
        ]
        prompt = (
            f"Room: {room['title']}\n"
            f"Members:\n" + "\n".join(roster_lines) + "\n"
            + (f"Recent:\n" + "\n".join(history_lines) + "\n" if history_lines else "")
            + f"User message: {clean_text[:280]}"
        )
        sys_prompt = (
            'Pick the single best Room member to respond first. '
            'Return ONLY strict JSON: {"speaker": "<member_slug>", "reason": "<2-5 word reason>"}.'
        )
        try:
            res = await asyncio.wait_for(
                self._llm_router.complete(
                    bot_slug=f"room-router:{room['slug']}",
                    prompt=prompt,
                    requested_model=flash_model,
                    system_prompt=sys_prompt,
                    trigger_type="room_auto_picker",
                    hop_count=1,
                    thinking_level="low",
                ),
                timeout=0.8,
            )
        except Exception:
            return None

        if res.unconfigured_local:
            return None

        raw = (res.output_text or "").strip()
        candidates = [raw]
        fence_match = _JSON_FENCE_RE.search(raw)
        if fence_match:
            candidates.insert(0, fence_match.group(1).strip())
        first_brace = raw.find("{")
        last_brace = raw.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            candidates.append(raw[first_brace : last_brace + 1])

        member_slugs = {b["slug"] for b in member_bots}
        for cand in candidates:
            try:
                parsed = json.loads(cand)
            except Exception:
                continue
            if isinstance(parsed, dict) and isinstance(parsed.get("speaker"), str):
                picked_slug = slugify(parsed["speaker"])
                if picked_slug in member_slugs:
                    reason = str(parsed.get("reason") or "").strip()[:80]
                    return picked_slug, reason or "Best specialist match"
        return None

    async def _select_room_initial_speakers(
        self,
        *,
        room: dict[str, Any],
        clean_text: str,
        member_bots: list[dict[str, Any]],
        member_map: dict[str, dict[str, Any]],
        quoted_message: dict[str, Any] | None,
        approved_clean: str,
    ) -> tuple[list[str], str, str]:
        """Select initial Room speaker(s) returning (speakers, routing_source, routed_reason)."""
        if approved_clean and approved_clean in member_map:
            return [approved_clean], "mention", ""

        explicit_mentions = self._extract_room_member_mentions(clean_text, member_bots)
        if explicit_mentions:
            return explicit_mentions, "mention", ""

        if (
            quoted_message
            and quoted_message.get("sender") == "bot"
            and quoted_message.get("sender_slug") in member_map
        ):
            return [str(quoted_message["sender_slug"])], "reply", ""

        routing_mode = str(room.get("routing_mode") or "auto").strip().lower()
        coord_slug = str(room.get("coordinator_bot_slug") or "")
        lead_fallback = coord_slug if coord_slug in member_map else member_bots[0]["slug"]

        if routing_mode == "stage":
            return [member_bots[0]["slug"]], "stage", ""
        if routing_mode == "lead":
            return [lead_fallback], "lead_fallback", ""

        # routing_mode == "auto"
        cap_match = self._match_unique_room_capability(clean_text, member_bots)
        if cap_match is not None:
            picked_slug, reason = cap_match
            return [picked_slug], "capability", reason

        recent_msgs = self._repo.list_room_messages(room["slug"], limit=4)
        flash_match = await self._pick_room_speaker_with_flash(
            room=room,
            clean_text=clean_text,
            member_bots=member_bots,
            recent_msgs=recent_msgs,
        )
        if flash_match is not None:
            picked_slug, reason = flash_match
            return [picked_slug], "auto_picker", reason

        return [lead_fallback], "lead_fallback", ""

    async def execute_room_turn(
        self,
        room_slug: str,
        *,
        user_text: str,
        operator_email: str | None = None,
        reply_to_id: str | None = None,
        attachment_ids: list[str] | None = None,
        skill_slugs: list[str] | None = None,
        target_page_slug: str | None = None,
        approved_handoff_bot_slug: str | None = None,
        run_item: QueuedTurnItem | None = None,
        precreated_user_message: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a multi-bot Room turn with auto-picker, Stage/@mention routing & streaming."""
        room = self._repo.get_room(room_slug)
        bots_by_slug = {b["slug"]: b for b in self._repo.list_bots()}
        member_order = list(room.get("stage_order") or room["member_bot_slugs"])
        member_bots = [bots_by_slug[s] for s in member_order if s in bots_by_slug]
        if not member_bots:
            raise ValueError(f"Room '{room['slug']}' has no active bots.")
        member_map = {b["slug"]: b for b in member_bots}

        attachments_meta: list[dict[str, Any]] = []
        for fid in (attachment_ids or []):
            try:
                fmeta, _ = self._repo.get_workspace_file(fid, owner_email=operator_email)
                attachments_meta.append(
                    {
                        "id": fmeta["id"],
                        "filename": fmeta["filename"],
                        "mime_type": fmeta["mime_type"],
                        "size_bytes": fmeta["size_bytes"],
                        "is_image": fmeta["is_image"],
                    }
                )
            except Exception:
                continue

        quoted_message = self._repo._resolve_reply_preview(
            collection="room_threads",
            reply_to_id=reply_to_id,
        )
        clean_text = user_text.strip()
        if precreated_user_message is None and not approved_handoff_bot_slug and (clean_text or attachments_meta):
            user_meta: dict[str, Any] = {}
            if attachments_meta:
                user_meta["attachments"] = attachments_meta
            if skill_slugs:
                user_meta["skill_slugs"] = list(skill_slugs)
            if target_page_slug:
                user_meta["target_page_slug"] = target_page_slug
            self._repo.append_room_message(
                room["slug"],
                sender_type="user",
                sender_slug="user",
                sender_name="You",
                text=clean_text,
                metadata=user_meta,
                reply_to_id=reply_to_id,
            )

        approved_clean = slugify(approved_handoff_bot_slug) if approved_handoff_bot_slug else ""
        speaker_queue, routing_source, routed_reason = await self._select_room_initial_speakers(
            room=room,
            clean_text=clean_text,
            member_bots=member_bots,
            member_map=member_map,
            quoted_message=quoted_message,
            approved_clean=approved_clean,
        )

        corr_id = run_item.correlation_id if run_item is not None else make_id("roomturn")
        local_room_stream_item = False
        if run_item is None and speaker_queue:
            lead_bot_obj = member_map.get(speaker_queue[0], member_bots[0])
            run_item = QueuedTurnItem(
                run_id=make_id("run"),
                thread_key=f"room:{room['slug']}",
                target_type="room",
                target_slug=room["slug"],
                correlation_id=corr_id,
                bot_slug=lead_bot_obj["slug"],
                bot_name=lead_bot_obj["name"],
            )
            local_room_stream_item = True

        if run_item is not None and speaker_queue:
            lead_bot_obj = member_map.get(speaker_queue[0], member_bots[0])
            run_item.bot_slug = lead_bot_obj["slug"]
            run_item.bot_name = lead_bot_obj["name"]
            run_item.routing_source = routing_source
            run_item.routed_reason = routed_reason
            await self._emit_turn_stream(
                {
                    "type": "run_started",
                    "run_id": run_item.run_id,
                    "thread_key": run_item.thread_key,
                    "target_type": run_item.target_type,
                    "target_slug": run_item.target_slug,
                    "bot_slug": lead_bot_obj["slug"],
                    "bot_name": lead_bot_obj["name"],
                    "routed_reason": routed_reason,
                    "routing_source": routing_source,
                }
            )

        cap = min(max(1, int(room.get("max_bot_turns_per_message") or 3)), MAX_HOP_COUNT)
        visited_speakers: set[str] = set()
        executed_turns: list[dict[str, Any]] = []
        aggregated_actions: list[dict[str, Any]] = []
        pending_inputs: dict[str, str] = {}
        effective_default_input = clean_text
        if approved_clean and not effective_default_input:
            recent = self._repo.list_room_messages(room["slug"], limit=3)
            last_msg_txt = recent[-1]["text"][:400] if recent else ""
            effective_default_input = (
                f"@{approved_clean} Continue the requested stage in the room based on the latest message: {last_msg_txt}"
            ).strip()

        cancel_event = run_item.cancel_event if run_item is not None else None

        while speaker_queue and len(executed_turns) < cap:
            if cancel_event is not None and cancel_event.is_set():
                break
            speaker_slug = speaker_queue.pop(0)
            if speaker_slug in visited_speakers or speaker_slug not in member_map:
                continue
            visited_speakers.add(speaker_slug)
            speaker_bot = member_map[speaker_slug]
            speaker_input = pending_inputs.get(speaker_slug) or effective_default_input

            if run_item is not None and len(executed_turns) > 0:
                run_item.bot_slug = speaker_bot["slug"]
                run_item.bot_name = speaker_bot["name"]
                run_item.partial_text = ""
                run_item.chips = []
                await self._emit_turn_stream(
                    {
                        "type": "run_started",
                        "run_id": run_item.run_id,
                        "thread_key": run_item.thread_key,
                        "target_type": run_item.target_type,
                        "target_slug": run_item.target_slug,
                        "bot_slug": speaker_bot["slug"],
                        "bot_name": speaker_bot["name"],
                        "routed_reason": "",
                        "routing_source": "handoff",
                    }
                )

            recent_msgs = self._repo.list_room_messages(room["slug"], limit=12)
            room_context = {
                "room_slug": room["slug"],
                "room_title": room["title"],
                "coordinator_bot_slug": room.get("coordinator_bot_slug"),
                "stage_order": member_order,
                "ask_before_bot_handoff": bool(room.get("ask_before_bot_handoff")),
                "members": [
                    {
                        "slug": m["slug"],
                        "name": m["name"],
                        "role": m.get("role", ""),
                    }
                    for m in member_bots
                ],
                "recent_room_messages": [
                    {
                        "id": rm["id"],
                        "sender_slug": rm["sender_slug"],
                        "sender_name": rm["sender_name"],
                        "text": str(rm.get("text") or "")[:500],
                    }
                    for rm in recent_msgs
                ],
            }

            turn_payload: dict[str, Any] = {
                "text": speaker_input,
                "input_text": speaker_input,
                "from_chat_thread": True,
                "suppress_1to1_thread": True,
                "operator_email": operator_email or "",
                "attachment_ids": list(attachment_ids or []),
                "quoted_message": quoted_message if len(executed_turns) == 0 else None,
                "skill_slugs": list(skill_slugs or []) if len(executed_turns) == 0 else [],
                "target_page_slug": target_page_slug or room.get("pinned_page_slug"),
                "room_context": room_context,
            }
            res = await self.execute_bot(
                speaker_slug,
                trigger_type="room_turn",
                correlation_id=corr_id,
                hop_count=len(executed_turns) + 1,
                trigger_payload=turn_payload,
                run_item=run_item,
            )
            is_first_bot_reply = len(executed_turns) == 0
            executed_turns.append(res)
            turn_actions = list(res.get("actions") or [])
            aggregated_actions.extend(turn_actions)

            summary_out = str(res.get("summary") or "").strip()
            reply_meta = dict(res.get("metadata") or {})
            reply_meta.setdefault("correlation_id", corr_id)
            reply_meta["room_slug"] = room["slug"]
            if is_first_bot_reply:
                reply_meta["routing_source"] = routing_source
                if routed_reason:
                    reply_meta["routed_reason"] = routed_reason

            was_cancelled = res.get("status") == "cancelled" or (
                cancel_event is not None and cancel_event.is_set()
            )
            if not was_cancelled:
                next_candidates: list[tuple[str, str]] = []
                for act in turn_actions:
                    if act.get("type") == "delegate_to_bot" and act.get("in_room_handoff"):
                        t_slug = str(act.get("target_bot") or "")
                        if t_slug in member_map and t_slug not in visited_speakers:
                            next_candidates.append((t_slug, str(act.get("instruction") or summary_out)))
                for m_slug in self._extract_room_member_mentions(summary_out, member_bots):
                    if m_slug in member_map and m_slug not in visited_speakers:
                        if not any(cand_s == m_slug for cand_s, _ in next_candidates):
                            next_candidates.append((m_slug, summary_out))

                if next_candidates and len(executed_turns) < cap and not reply_meta.get("delegation_plan"):
                    next_slug, next_instr = next_candidates[0]
                    if room.get("ask_before_bot_handoff"):
                        reply_meta["pending_room_handoff"] = {
                            "target_bot_slug": next_slug,
                            "target_bot_name": member_map[next_slug]["name"],
                            "instruction": next_instr[:500],
                        }
                    else:
                        pending_inputs[next_slug] = next_instr
                        if next_slug not in speaker_queue:
                            speaker_queue.append(next_slug)

            saved_room_msg = self._repo.append_room_message(
                room["slug"],
                sender_type="bot",
                sender_slug=speaker_bot["slug"],
                sender_name=speaker_bot["name"],
                text=summary_out or f"Completed turn for {speaker_bot['name']}.",
                metadata=reply_meta,
                reply_to_id=reply_to_id if is_first_bot_reply else None,
            )
            if run_item is not None:
                run_item.message_id = saved_room_msg["id"]
            if was_cancelled:
                break

        if operator_email:
            with suppress(Exception):
                self._repo.mark_thread_read(
                    user_email=operator_email,
                    target_type="room",
                    slug=room["slug"],
                )

        if local_room_stream_item and run_item is not None:
            await self._emit_turn_stream(
                {
                    "type": "run_finished",
                    "run_id": run_item.run_id,
                    "thread_key": run_item.thread_key,
                    "target_type": run_item.target_type,
                    "target_slug": run_item.target_slug,
                    "bot_slug": run_item.bot_slug,
                    "message_id": run_item.message_id,
                    "status": "cancelled" if (cancel_event is not None and cancel_event.is_set()) else "completed",
                }
            )

        messages, has_more, total_count = self._repo.list_room_messages_window(room["slug"], limit=80)
        return {
            "status": "cancelled" if (cancel_event is not None and cancel_event.is_set()) else "completed",
            "room_slug": room["slug"],
            "messages": messages,
            "has_more": has_more,
            "total_count": total_count,
            "results": executed_turns,
            "actions": aggregated_actions,
        }
