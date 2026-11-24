"""Telegram Bot API connector using aiogram v3.31.0 with fallback HTTP transport."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import html
import json
import logging
import re
import secrets
import urllib.error
import urllib.request
from typing import Any, Literal, Protocol

from argo_core.bus.valkey_bus import EventBus
from argo_core.connectors.telegram_channels import (
    TelegramConfigError,
    fetch_telegram_public_channel,
    normalize_public_channel_handle,
)
from argo_core.db.repositories import (
    AlreadyResolvedError,
    ArgoRepository,
    make_id,
    slugify,
    utc_now,
)
from argo_core.security.ssrf import AntiBotHaltError, PublicHttpFetcher, SafePublicHttpFetcher
from argo_core.security.vault import redact_secrets
from argo_core.watchdog.resource_guard import HostTelemetry

logger = logging.getLogger(__name__)

MAX_CALLBACK_DATA_BYTES = 64
STOP_IDLE_DESKTOPS_CALLBACK = "sys:stop_idle"
TELEGRAM_POSTS_COLLECTION = "telegram_channel_posts"
TELEGRAM_MAX_MESSAGE_LENGTH = 4096
TELEGRAM_FORMAT_INPUT_MAX_LENGTH = 3950
_BOT_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")

_FENCED_CODE_BLOCK_RE = re.compile(
    r"^[ \t]*```([A-Za-z0-9_.+-]*)[ \t]*\n(.*?)(?:\n)?^[ \t]*```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
_INLINE_TRIPLE_CODE_RE = re.compile(r"```([^`\n]+)```")
_INLINE_DOUBLE_CODE_RE = re.compile(r"``([^`\n]+?)``")
_INLINE_SINGLE_CODE_RE = re.compile(r"`([^`\n]+)`")
_HTML_PRE_BLOCK_RE = re.compile(r"<pre>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
_HTML_PRE_INNER_CODE_RE = re.compile(
    r"^\s*<code(?:\s+class=([\"'])(language-[A-Za-z0-9_.+-]+)\1)?\s*>(.*)</code>\s*$",
    re.IGNORECASE | re.DOTALL,
)
_HTML_CODE_TAG_RE = re.compile(
    r"<code(?:\s+class=([\"'])(language-[A-Za-z0-9_.+-]+)\1)?\s*>(.*?)</code>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_LINK_TAG_RE = re.compile(
    r"<a\s+href=([\"'])((?:https?|tg)://[^\"'\s<>]+|mailto:[^\"'\s<>]+)\1\s*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_SAFE_PAIR_TAG_RE = re.compile(
    r"<(/?)(b|strong|i|em|u|ins|s|strike|del|tg-spoiler|blockquote)(\s+expandable)?\s*>",
    re.IGNORECASE,
)
_MD_LINK_RE = re.compile(
    r"\[([^\]\n]+)\]\(((?:https?://|tg://|mailto:)[^\s<>()]+(?:\([^\s<>()]*\)[^\s<>()]*)*)\)"
)
_BARE_URL_RE = re.compile(r"(?<![A-Za-z0-9_])https?://[^\s<>\"'`]+")
_BLOCKQUOTE_LINE_RE = re.compile(r"^[ \t]*(?:&gt;|>)[ \t]?(.*)$")
_HR_LINE_RE = re.compile(r"^[ \t]*(?:[-*_][ \t]*){3,}$")
_ATX_HEADING_RE = re.compile(r"^[ \t]*#{1,6}[ \t]+(.+?)[ \t]*$")
_BULLET_LINE_RE = re.compile(r"^([ \t]*)[-*][ \t]+(.*)$")

_BOLD_ITALIC_STAR_RE = re.compile(r"\*\*\*([^\s*](?:.*?\S)?)\*\*\*")
_BOLD_ITALIC_UNDER_RE = re.compile(
    r"(?<![A-Za-z0-9_])___([^\s_](?:.*?\S)?)___(?![A-Za-z0-9_])"
)
_BOLD_STAR_RE = re.compile(r"\*\*([^\s*](?:.*?\S)?)\*\*")
_UNDERLINE_RE = re.compile(
    r"(?<![A-Za-z0-9_])__([^\s_](?:.*?\S)?)__(?![A-Za-z0-9_])"
)
_STRIKE_RE = re.compile(r"~~([^\s~](?:.*?\S)?)~~")
_SPOILER_RE = re.compile(r"\|\|([^\s|](?:.*?\S)?)\|\|")
_ITALIC_STAR_RE = re.compile(r"(?<!\*)\*([^\s*](?:[^*]*?\S)?)\*(?!\*)")
_ITALIC_UNDER_RE = re.compile(
    r"(?<![A-Za-z0-9_])_([^\s_](?:[^_]*?\S)?)_(?![A-Za-z0-9_])"
)
_PLACEHOLDER_TOKEN_RE = re.compile(r"\x00TGPH(\d+)\x00")


def _truncate_text_at_boundary(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    cut = text[: max_len - 3]
    newline_pos = cut.rfind("\n")
    space_pos = cut.rfind(" ")
    boundary = max(newline_pos, space_pos)
    if boundary > max_len // 2:
        cut = cut[:boundary]
    return cut.rstrip() + "..."


def _split_bare_url_trailing(raw_url: str) -> tuple[str, str]:
    url = raw_url
    trailing = ""
    while url:
        last = url[-1]
        if last in ".,;:!?'\"[]":
            trailing = last + trailing
            url = url[:-1]
            continue
        if last == ")" and url.count(")") > url.count("("):
            trailing = last + trailing
            url = url[:-1]
            continue
        break
    return url, trailing


def _apply_inline_markdown_html(line: str) -> str:
    line = _BOLD_ITALIC_STAR_RE.sub(r"<b><i>\1</i></b>", line)
    line = _BOLD_ITALIC_UNDER_RE.sub(r"<b><i>\1</i></b>", line)
    line = _BOLD_STAR_RE.sub(r"<b>\1</b>", line)
    line = _UNDERLINE_RE.sub(r"<u>\1</u>", line)
    line = _STRIKE_RE.sub(r"<s>\1</s>", line)
    line = _SPOILER_RE.sub(r"<tg-spoiler>\1</tg-spoiler>", line)
    line = _ITALIC_STAR_RE.sub(r"<i>\1</i>", line)
    line = _ITALIC_UNDER_RE.sub(r"<i>\1</i>", line)
    return line


def _protect_paired_safe_tags(
    text: str,
    add_placeholder: Any,
) -> str:
    """Protect balanced allowlisted HTML tag delimiters before escaping stray angle brackets."""
    stack: list[tuple[str, int, int, str]] = []
    replacements: list[tuple[int, int, str]] = []

    for match in _HTML_SAFE_PAIR_TAG_RE.finditer(text):
        is_close = bool(match.group(1))
        tag_name = match.group(2).lower()
        attrs = match.group(3) or ""
        if not is_close:
            if attrs and tag_name != "blockquote":
                continue
            canonical_open = (
                "<blockquote expandable>" if attrs and tag_name == "blockquote" else f"<{tag_name}>"
            )
            stack.append((tag_name, match.start(), match.end(), canonical_open))
        else:
            if attrs:
                continue
            match_idx = -1
            for idx in range(len(stack) - 1, -1, -1):
                if stack[idx][0] == tag_name:
                    match_idx = idx
                    break
            if match_idx == -1:
                continue
            _, open_start, open_end, canonical_open = stack[match_idx]
            del stack[match_idx:]
            replacements.append((open_start, open_end, canonical_open))
            replacements.append((match.start(), match.end(), f"</{tag_name}>"))

    if not replacements:
        return text

    replacements.sort(key=lambda item: item[0], reverse=True)
    updated = text
    for start, end, canonical in replacements:
        token = add_placeholder(canonical)
        updated = updated[:start] + token + updated[end:]
    return updated


def _render_telegram_html_segment(
    source: str,
    *,
    allow_block_constructs: bool = True,
    allow_links: bool = True,
    allow_bare_urls: bool = True,
) -> str:
    placeholders: list[str] = []

    def add_placeholder(snippet: str) -> str:
        idx = len(placeholders)
        placeholders.append(snippet)
        return f"\x00TGPH{idx}\x00"

    text = source

    if allow_block_constructs:
        def _replace_fenced_code(match: re.Match[str]) -> str:
            lang = match.group(1).strip()
            code_body = html.escape(match.group(2).rstrip("\n"), quote=False)
            if lang:
                snippet = f'<pre><code class="language-{html.escape(lang, quote=True)}">{code_body}</code></pre>'
            else:
                snippet = f"<pre>{code_body}</pre>"
            return add_placeholder(snippet)

        text = _FENCED_CODE_BLOCK_RE.sub(_replace_fenced_code, text)

    for code_re in (_INLINE_TRIPLE_CODE_RE, _INLINE_DOUBLE_CODE_RE, _INLINE_SINGLE_CODE_RE):
        text = code_re.sub(
            lambda m: add_placeholder(f"<code>{html.escape(m.group(1), quote=False)}</code>"),
            text,
        )

    def _replace_pre_html(match: re.Match[str]) -> str:
        inner = match.group(1)
        inner_code = _HTML_PRE_INNER_CODE_RE.match(inner)
        if inner_code:
            lang_class = inner_code.group(2)
            body = html.escape(html.unescape(inner_code.group(3)), quote=False)
            if lang_class:
                return add_placeholder(f'<pre><code class="{lang_class}">{body}</code></pre>')
            return add_placeholder(f"<pre><code>{body}</code></pre>")
        return add_placeholder(f"<pre>{html.escape(html.unescape(inner), quote=False)}</pre>")

    text = _HTML_PRE_BLOCK_RE.sub(_replace_pre_html, text)

    def _replace_code_html(match: re.Match[str]) -> str:
        lang_class = match.group(2)
        body = html.escape(html.unescape(match.group(3)), quote=False)
        if lang_class:
            return add_placeholder(f'<code class="{lang_class}">{body}</code>')
        return add_placeholder(f"<code>{body}</code>")

    text = _HTML_CODE_TAG_RE.sub(_replace_code_html, text)

    if allow_links:
        def _replace_html_link(match: re.Match[str]) -> str:
            safe_href = html.escape(html.unescape(match.group(2)), quote=True)
            label_html = _render_telegram_html_segment(
                match.group(3),
                allow_block_constructs=False,
                allow_links=False,
                allow_bare_urls=False,
            )
            return add_placeholder(f'<a href="{safe_href}">{label_html}</a>')

        text = _HTML_LINK_TAG_RE.sub(_replace_html_link, text)

    text = _protect_paired_safe_tags(text, add_placeholder)

    if allow_links:
        def _replace_md_link(match: re.Match[str]) -> str:
            safe_href = html.escape(match.group(2), quote=True)
            label_html = _render_telegram_html_segment(
                match.group(1),
                allow_block_constructs=False,
                allow_links=False,
                allow_bare_urls=False,
            )
            return add_placeholder(f'<a href="{safe_href}">{label_html}</a>')

        text = _MD_LINK_RE.sub(_replace_md_link, text)

    if allow_bare_urls:
        def _replace_bare_url(match: re.Match[str]) -> str:
            url, trailing = _split_bare_url_trailing(match.group(0))
            if not url:
                return match.group(0)
            return add_placeholder(html.escape(url, quote=False)) + html.escape(trailing, quote=False)

        text = _BARE_URL_RE.sub(_replace_bare_url, text)

    text = html.escape(text, quote=False)

    if not allow_block_constructs:
        rendered = _apply_inline_markdown_html(text)
    else:
        output_lines: list[str] = []
        lines = text.split("\n")
        idx = 0
        total_lines = len(lines)
        while idx < total_lines:
            line = lines[idx]
            quote_match = _BLOCKQUOTE_LINE_RE.match(line)
            if quote_match:
                quote_lines: list[str] = []
                while idx < total_lines:
                    q_match = _BLOCKQUOTE_LINE_RE.match(lines[idx])
                    if not q_match:
                        break
                    quote_lines.append(_apply_inline_markdown_html(q_match.group(1)))
                    idx += 1
                output_lines.append(f"<blockquote>{chr(10).join(quote_lines)}</blockquote>")
                continue

            if _HR_LINE_RE.match(line):
                output_lines.append("──────────")
                idx += 1
                continue

            heading_match = _ATX_HEADING_RE.match(line)
            if heading_match:
                heading_inner = re.sub(r"\s+#+$", "", heading_match.group(1)).strip()
                heading_formatted = _apply_inline_markdown_html(heading_inner)
                heading_formatted = re.sub(r"</?b>", "", heading_formatted)
                output_lines.append(f"<b>{heading_formatted}</b>")
                idx += 1
                continue

            bullet_match = _BULLET_LINE_RE.match(line)
            if bullet_match:
                indent = "  " if len(bullet_match.group(1).expandtabs(2)) >= 2 else ""
                body_formatted = _apply_inline_markdown_html(bullet_match.group(2))
                output_lines.append(f"{indent}• {body_formatted}")
                idx += 1
                continue

            output_lines.append(_apply_inline_markdown_html(line))
            idx += 1

        rendered = "\n".join(output_lines)

    while "\x00TGPH" in rendered:
        rendered = _PLACEHOLDER_TOKEN_RE.sub(
            lambda m: placeholders[int(m.group(1))],
            rendered,
        )
    return rendered


def format_telegram_html(text: str) -> str:
    """Convert Markdown/mixed text into sanitized Telegram Bot API HTML within the 4096-char limit."""
    normalized = str(text or "").replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    bounded = _truncate_text_at_boundary(normalized, TELEGRAM_FORMAT_INPUT_MAX_LENGTH)
    rendered = _render_telegram_html_segment(bounded)
    if len(rendered) <= TELEGRAM_MAX_MESSAGE_LENGTH:
        return rendered

    limit = len(bounded)
    while len(rendered) > TELEGRAM_MAX_MESSAGE_LENGTH and limit > 120:
        next_limit = min(limit - 1, max(120, int(limit * 3900 / max(len(rendered), 1))))
        if next_limit >= limit:
            next_limit = limit - 50
        limit = next_limit
        bounded = _truncate_text_at_boundary(normalized, limit)
        rendered = _render_telegram_html_segment(bounded)

    if len(rendered) <= TELEGRAM_MAX_MESSAGE_LENGTH:
        return rendered

    plain_limit = 800
    escaped_fallback = html.escape(_truncate_text_at_boundary(normalized, plain_limit), quote=False)
    while len(escaped_fallback) > TELEGRAM_MAX_MESSAGE_LENGTH and plain_limit > 64:
        plain_limit = max(64, plain_limit // 2)
        escaped_fallback = html.escape(
            _truncate_text_at_boundary(normalized, plain_limit), quote=False
        )
    return escaped_fallback


def _is_telegram_entity_parse_error(exc: Exception) -> bool:
    detail = str(exc).lower()
    return (
        "can't parse entities" in detail
        or "can't find end of the entity" in detail
        or "unsupported start tag" in detail
    )


class TelegramIntegrationError(RuntimeError):
    """Raised when Telegram Bot API operations fail."""


class TelegramTransport(Protocol):
    """Protocol implemented by aiogram v3.31.0 transport, urllib fallback, and test doubles."""

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        """Validate the bot token via Telegram Bot API getMe."""

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Deliver a message to a Telegram chat or channel."""

    async def answer_callback_query(
        self,
        bot_token: str,
        *,
        callback_query_id: str,
        text: str | None = None,
    ) -> bool:
        """Clear client loading state on an inline keyboard button tap."""

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update and optionally lock an interactive Telegram card in place."""

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str],
    ) -> bool:
        """Register webhook delivery endpoint with X-Telegram-Bot-Api-Secret-Token."""


def validate_callback_data(callback_data: str) -> str:
    """Enforce Telegram Bot API <= 64-byte UTF-8 constraint on callback_data."""
    cleaned = callback_data.strip()
    if not cleaned:
        raise TelegramConfigError("Telegram callback_data cannot be empty.")
    encoded_len = len(cleaned.encode("utf-8"))
    if encoded_len > MAX_CALLBACK_DATA_BYTES:
        raise TelegramConfigError(
            f"Telegram callback_data '{cleaned}' exceeds 64 bytes ({encoded_len} bytes)."
        )
    return cleaned


def build_inline_keyboard(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
    """Validate button callbacks (<= 64 bytes) and build InlineKeyboardMarkup JSON."""
    serialized_rows = [
        [
            {"text": label, "callback_data": validate_callback_data(cb_data)}
            for label, cb_data in row
        ]
        for row in rows
    ]
    try:
        from aiogram.types import (  # type: ignore[import-not-found]
            InlineKeyboardButton,
            InlineKeyboardMarkup,
        )

        markup = InlineKeyboardMarkup(
            inline_keyboard=[
                [InlineKeyboardButton(text=btn["text"], callback_data=btn["callback_data"]) for btn in row]
                for row in serialized_rows
            ]
        )
        return markup.model_dump(exclude_none=True)
    except ImportError:
        return {"inline_keyboard": serialized_rows}


def _normalize_handles(handles: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for raw in handles or []:
        handle = raw.strip()
        if not handle:
            continue
        if not handle.startswith("@") and not handle.lstrip("-").isdigit():
            handle = f"@{handle}"
        if handle not in normalized:
            normalized.append(handle)
    return normalized


class AiogramTelegramTransport:
    """Production Telegram transport using aiogram v3.31.0 (or stdlib HTTPS fallback)."""

    async def _call_bot_api(self, bot_token: str, method: str, payload: dict[str, Any]) -> Any:
        def _do_request() -> Any:
            url = f"https://api.telegram.org/bot{bot_token}/{method}"
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    parsed = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                raise TelegramIntegrationError(
                    redact_secrets(f"Telegram API {method} HTTP {exc.code}: {err_body}", [bot_token])
                ) from exc
            except Exception as exc:
                raise TelegramIntegrationError(
                    redact_secrets(f"Telegram API {method} failed: {exc}", [bot_token])
                ) from exc

            if not parsed.get("ok"):
                desc = parsed.get("description", "Unknown Telegram API error")
                raise TelegramIntegrationError(redact_secrets(desc, [bot_token]))
            return parsed["result"]

        return await asyncio.to_thread(_do_request)

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        try:
            from aiogram import Bot  # type: ignore[import-not-found]
        except ImportError:
            user = await self._call_bot_api(bot_token, "getMe", {})
            return {
                "bot_id": int(user["id"]),
                "username": str(user.get("username", "")),
                "first_name": str(user.get("first_name", "")),
                "can_join_groups": bool(user.get("can_join_groups", False)),
                "can_read_all_group_messages": bool(user.get("can_read_all_group_messages", False)),
            }

        try:
            async with Bot(token=bot_token) as bot:
                me = await bot.get_me()
                return {
                    "bot_id": int(me.id),
                    "username": str(me.username or ""),
                    "first_name": str(me.first_name or ""),
                    "can_join_groups": bool(me.can_join_groups),
                    "can_read_all_group_messages": bool(me.can_read_all_group_messages),
                }
        except Exception as exc:
            raise TelegramIntegrationError(
                redact_secrets(f"Telegram getMe failed: {exc}", [bot_token])
            ) from exc

    @staticmethod
    def _prepare_outgoing(text: str, parse_mode: str | None) -> tuple[str, str | None]:
        normalized_mode = (
            parse_mode.strip() if isinstance(parse_mode, str) and parse_mode.strip() else None
        )
        if normalized_mode == "HTML":
            return format_telegram_html(text), "HTML"
        return _truncate_text_at_boundary(str(text or ""), TELEGRAM_MAX_MESSAGE_LENGTH), normalized_mode

    async def _call_bot_api_with_parse_fallback(
        self,
        bot_token: str,
        method: str,
        payload: dict[str, Any],
        plain_text: str,
    ) -> Any:
        try:
            return await self._call_bot_api(bot_token, method, payload)
        except TelegramIntegrationError as exc:
            if payload.get("parse_mode") and _is_telegram_entity_parse_error(exc):
                logger.warning(
                    "Telegram %s rejected formatted entities; retrying as plain text",
                    method,
                )
                fallback_payload = dict(payload)
                fallback_payload.pop("parse_mode", None)
                fallback_payload["text"] = _truncate_text_at_boundary(
                    str(plain_text or ""), TELEGRAM_MAX_MESSAGE_LENGTH
                )
                return await self._call_bot_api(bot_token, method, fallback_payload)
            raise

    async def _invoke_aiogram_with_parse_fallback(
        self,
        bot_token: str,
        method_name: Literal["send_message", "edit_message_text"],
        error_label: str,
        *,
        plain_text: str,
        reply_markup: dict[str, Any] | None,
        call_kwargs: dict[str, Any],
        bot_cls: Any,
        markup_cls: Any,
    ) -> Any:
        try:
            markup_obj = (
                markup_cls.model_validate(reply_markup)
                if reply_markup is not None
                else None
            )
            kwargs = dict(call_kwargs)
            kwargs["reply_markup"] = markup_obj
            async with bot_cls(token=bot_token) as bot:
                method_fn = getattr(bot, method_name)
                try:
                    return await method_fn(**kwargs)
                except Exception as exc:
                    if kwargs.get("parse_mode") and _is_telegram_entity_parse_error(exc):
                        logger.warning(
                            "Telegram %s rejected formatted entities; retrying as plain text",
                            error_label,
                        )
                        fallback_kwargs = dict(kwargs)
                        fallback_kwargs.pop("parse_mode", None)
                        fallback_kwargs["text"] = _truncate_text_at_boundary(
                            str(plain_text or ""), TELEGRAM_MAX_MESSAGE_LENGTH
                        )
                        return await method_fn(**fallback_kwargs)
                    raise
        except Exception as exc:
            raise TelegramIntegrationError(
                redact_secrets(f"Telegram {error_label} failed: {exc}", [bot_token])
            ) from exc

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = "HTML",
    ) -> dict[str, Any]:
        outgoing_text, resolved_mode = self._prepare_outgoing(text, parse_mode)
        try:
            from aiogram import Bot  # type: ignore[import-not-found]
            from aiogram.types import InlineKeyboardMarkup  # type: ignore[import-not-found]
        except ImportError:
            payload: dict[str, Any] = {"chat_id": chat_id, "text": outgoing_text}
            if resolved_mode is not None:
                payload["parse_mode"] = resolved_mode
            if reply_markup is not None:
                payload["reply_markup"] = reply_markup
            msg = await self._call_bot_api_with_parse_fallback(
                bot_token,
                "sendMessage",
                payload,
                text,
            )
            return {
                "message_id": int(msg["message_id"]),
                "chat_id": str(msg.get("chat", {}).get("id", chat_id)),
            }

        call_kwargs: dict[str, Any] = {
            "chat_id": chat_id,
            "text": outgoing_text,
        }
        if resolved_mode is not None:
            call_kwargs["parse_mode"] = resolved_mode
        sent = await self._invoke_aiogram_with_parse_fallback(
            bot_token,
            "send_message",
            "sendMessage",
            plain_text=text,
            reply_markup=reply_markup,
            call_kwargs=call_kwargs,
            bot_cls=Bot,
            markup_cls=InlineKeyboardMarkup,
        )
        return {
            "message_id": int(sent.message_id),
            "chat_id": str(sent.chat.id),
        }

    async def answer_callback_query(
        self,
        bot_token: str,
        *,
        callback_query_id: str,
        text: str | None = None,
    ) -> bool:
        try:
            from aiogram import Bot  # type: ignore[import-not-found]
        except ImportError:
            payload: dict[str, Any] = {"callback_query_id": callback_query_id}
            if text:
                payload["text"] = text
            return bool(await self._call_bot_api(bot_token, "answerCallbackQuery", payload))

        try:
            async with Bot(token=bot_token) as bot:
                return bool(
                    await bot.answer_callback_query(
                        callback_query_id=callback_query_id,
                        text=text,
                    )
                )
        except Exception as exc:
            raise TelegramIntegrationError(
                redact_secrets(f"Telegram answerCallbackQuery failed: {exc}", [bot_token])
            ) from exc

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = "HTML",
    ) -> dict[str, Any]:
        outgoing_text, resolved_mode = self._prepare_outgoing(text, parse_mode)
        try:
            from aiogram import Bot  # type: ignore[import-not-found]
            from aiogram.types import InlineKeyboardMarkup  # type: ignore[import-not-found]
        except ImportError:
            payload: dict[str, Any] = {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": outgoing_text,
            }
            if resolved_mode is not None:
                payload["parse_mode"] = resolved_mode
            if reply_markup is not None:
                payload["reply_markup"] = reply_markup
            res = await self._call_bot_api_with_parse_fallback(
                bot_token,
                "editMessageText",
                payload,
                text,
            )
            if isinstance(res, dict):
                return {"message_id": int(res.get("message_id", message_id))}
            return {"message_id": message_id}

        call_kwargs: dict[str, Any] = {
            "text": outgoing_text,
            "chat_id": chat_id,
            "message_id": message_id,
        }
        if resolved_mode is not None:
            call_kwargs["parse_mode"] = resolved_mode
        res = await self._invoke_aiogram_with_parse_fallback(
            bot_token,
            "edit_message_text",
            "editMessageText",
            plain_text=text,
            reply_markup=reply_markup,
            call_kwargs=call_kwargs,
            bot_cls=Bot,
            markup_cls=InlineKeyboardMarkup,
        )
        msg_id = int(getattr(res, "message_id", message_id))
        return {"message_id": msg_id}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str],
    ) -> bool:
        try:
            from aiogram import Bot  # type: ignore[import-not-found]
        except ImportError:
            return bool(
                await self._call_bot_api(
                    bot_token,
                    "setWebhook",
                    {
                        "url": url,
                        "secret_token": secret_token,
                        "allowed_updates": allowed_updates,
                    },
                )
            )

        try:
            async with Bot(token=bot_token) as bot:
                return bool(
                    await bot.set_webhook(
                        url=url,
                        secret_token=secret_token,
                        allowed_updates=allowed_updates,
                    )
                )
        except Exception as exc:
            raise TelegramIntegrationError(
                redact_secrets(f"Telegram setWebhook failed: {exc}", [bot_token])
            ) from exc


class TelegramBotService:
    """Manages Telegram Bot onboarding, webhook verification, and resource guard alerts."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        transport: TelegramTransport | None = None,
        public_fetcher: PublicHttpFetcher | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._transport: TelegramTransport = transport or AiogramTelegramTransport()
        self._public_fetcher: PublicHttpFetcher = public_fetcher or SafePublicHttpFetcher()
        self._approval_coordinator: Any = None
        self._desktop_manager: Any = None
        self._llm_router: Any = None
        self._guard: Any = None
        self._bot_scheduler: Any = None

    def attach_approval_coordinator(self, coordinator: Any) -> None:
        """Bind ApprovalCoordinator for dual-UI inline button callbacks and reply revisions."""
        self._approval_coordinator = coordinator

    def attach_desktop_manager(self, desktop_manager: Any) -> None:
        """Bind DesktopManager for live container hibernation via Telegram controls."""
        self._desktop_manager = desktop_manager

    def attach_platform_services(
        self,
        *,
        llm_router: Any = None,
        guard: Any = None,
        bot_scheduler: Any = None,
    ) -> None:
        """Bind LLMRouter, HostResourceGuard, and BotScheduler for operator status queries."""
        self._llm_router = llm_router
        self._guard = guard
        self._bot_scheduler = bot_scheduler

    def _get_bot_token_for_slug(self, slug: str) -> tuple[dict[str, Any], str]:
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "telegram":
            raise TelegramConfigError(f"Integration '{slug}' is not a Telegram connector.")
        bot_token = str(account["secrets"].get("bot_token") or "").strip()
        if not bot_token:
            raise TelegramIntegrationError(
                f"Telegram account '{slug}' does not have an encrypted bot_token stored."
            )
        return account, bot_token

    async def publish_message(
        self,
        slug: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a message or permission card through an onboarded Telegram Bot account."""
        _, bot_token = self._get_bot_token_for_slug(slug)
        return await self._transport.send_message(
            bot_token,
            chat_id=chat_id,
            text=text,
            reply_markup=reply_markup,
        )

    async def edit_operator_message(
        self,
        slug: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Edit an existing Telegram card (e.g., locking inline buttons after resolution)."""
        _, bot_token = self._get_bot_token_for_slug(slug)
        return await self._transport.edit_message_text(
            bot_token,
            chat_id=chat_id,
            message_id=int(message_id),
            text=text,
            reply_markup=reply_markup,
        )

    @staticmethod
    def validate_token_format(bot_token: str) -> str:
        token = bot_token.strip()
        if not _BOT_TOKEN_RE.match(token):
            raise TelegramConfigError(
                "Invalid Telegram Bot token format; expected '<digits>:<secret>'."
            )
        return token

    async def verify_token(self, bot_token: str) -> dict[str, Any]:
        """Validate token syntax and confirm identity with Telegram Bot API getMe."""
        token = self.validate_token_format(bot_token)
        try:
            identity = await self._transport.get_me(token)
        except TelegramIntegrationError:
            raise
        except Exception as exc:
            raise TelegramIntegrationError(
                redact_secrets(f"Telegram token verification failed: {exc}", [token])
            ) from exc
        if not identity.get("bot_id"):
            raise TelegramIntegrationError("Telegram getMe returned an incomplete bot identity.")
        return identity

    async def onboard_bot(
        self,
        *,
        bot_token: str,
        slug: str | None = None,
        display_name: str | None = None,
        operator_chat_id: str | None = None,
        admin_channels: list[str] | None = None,
        public_channels: list[str] | None = None,
        register_webhook: bool = False,
        public_base_url: str = "",
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Verify token via getMe, store encrypted credentials, and optionally set webhook."""
        token = self.validate_token_format(bot_token)
        identity = await self.verify_token(token)
        username = str(identity.get("username") or "").lstrip("@")
        resolved_slug = slugify(slug or f"tg-{username or identity['bot_id']}")
        resolved_name = (
            display_name.strip()
            if display_name and display_name.strip()
            else (identity.get("first_name") or f"@{username}")
        )
        norm_admin = _normalize_handles(admin_channels)
        norm_public = [
            f"@{normalize_public_channel_handle(ch)}"
            for ch in (public_channels or [])
            if ch and ch.strip()
        ]
        clean_chat_id = operator_chat_id.strip() if operator_chat_id and operator_chat_id.strip() else None

        scopes = ["bot_api", "watchdog_alerts", "inline_approvals"]
        if norm_admin:
            scopes.append("channel_post")
        if norm_public:
            scopes.append("public_preview")

        webhook_secret = secrets.token_urlsafe(24)
        webhook_path = f"/hooks/telegram/{resolved_slug}"
        webhook_registered = False

        if register_webhook and public_base_url.startswith("https://"):
            full_webhook_url = f"{public_base_url.rstrip('/')}{webhook_path}"
            webhook_registered = await self._transport.set_webhook(
                token,
                url=full_webhook_url,
                secret_token=webhook_secret,
                allowed_updates=["message", "channel_post", "edited_channel_post", "callback_query"],
            )

        record = self._repo.upsert_integration(
            slug=resolved_slug,
            provider="telegram",
            display_name=resolved_name,
            account_identifier=f"@{username}" if username else str(identity["bot_id"]),
            scopes=scopes,
            secrets={
                "bot_token": token,
                "bot_id": identity["bot_id"],
                "username": username,
                "operator_chat_id": clean_chat_id,
                "admin_channels": norm_admin,
                "public_channels": norm_public,
                "webhook_secret": webhook_secret,
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
            event_type="integration.telegram.connected",
            payload={
                "category": "alerts",
                "title": f"Connected Telegram Bot {resolved_name}",
                "badge": "aiogram v3.31.0 · Healthy",
                "badge_tone": "emerald",
                "summary": (
                    f"Verified @{username} (id={identity['bot_id']}) via getMe. "
                    f"Operator alert chat: {clean_chat_id or 'not bound'}."
                ),
                "meta": f"Webhook route: {webhook_path}",
            },
            hop_count=1,
        )

        return {
            **record,
            "bot_id": identity["bot_id"],
            "username": username,
            "operator_chat_id": clean_chat_id,
            "admin_channels": norm_admin,
            "public_channels": norm_public,
            "webhook_path": webhook_path,
            "webhook_registered": webhook_registered,
        }

    async def onboard_public_monitor(
        self,
        *,
        channel_handle: str,
        slug: str | None = None,
        display_name: str | None = None,
        sync_immediately: bool = True,
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register a non-admin public channel monitor using https://t.me/s/ without MTProto."""
        clean_handle = normalize_public_channel_handle(channel_handle)
        resolved_slug = slugify(slug or f"tg-pub-{clean_handle}")
        resolved_name = (
            display_name.strip()
            if display_name and display_name.strip()
            else f"@{clean_handle} (Public Preview)"
        )
        record = self._repo.upsert_integration(
            slug=resolved_slug,
            provider="telegram",
            display_name=resolved_name,
            account_identifier=f"https://t.me/s/{clean_handle}",
            scopes=["public_preview"],
            secrets={
                "mode": "public_preview",
                "public_channels": [f"@{clean_handle}"],
            },
            owner_email=owner_email,
            visibility=visibility,
            allowed_groups=allowed_groups,
            status="ok",
        )

        sync_summary: dict[str, Any] | None = None
        if sync_immediately:
            sync_summary = await self.sync_public_channels(resolved_slug)
        return {
            **record,
            "channel_handle": f"@{clean_handle}",
            "sync_summary": sync_summary,
        }

    async def sync_public_channels(
        self,
        slug: str,
        *,
        limit_per_channel: int = 20,
    ) -> dict[str, Any]:
        """Poll configured t.me/s/ public channels, deduplicate in SQLite, and emit Activity events."""
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "telegram":
            raise TelegramConfigError(f"Integration '{slug}' is not a Telegram connector.")

        public_channels = [
            str(ch) for ch in (account["secrets"].get("public_channels") or []) if str(ch).strip()
        ]
        if not public_channels:
            raise TelegramConfigError(
                f"Telegram integration '{account['slug']}' has no public_channels configured."
            )

        total_fetched = 0
        total_new = 0
        total_updated = 0
        for handle in public_channels:
            try:
                posts = await fetch_telegram_public_channel(
                    handle,
                    fetcher=self._public_fetcher,
                    limit=limit_per_channel,
                )
            except AntiBotHaltError as exc:
                self._repo.update_integration_health(
                    account["slug"],
                    status="degraded",
                    last_error=str(exc),
                )
                await self._bus.publish(
                    correlation_id=make_id("corr"),
                    source_slug="integrations",
                    target_slug=account["slug"],
                    event_type="telegram.public_channel.halted",
                    payload={
                        "category": "alerts",
                        "title": f"Public Preview Halted ({handle})",
                        "badge": f"Halted · HTTP {exc.status_code}",
                        "badge_tone": "amber",
                        "summary": exc.reason,
                        "meta": f"Channel {handle} · zero anti-bot bypass",
                    },
                    hop_count=1,
                )
                raise

            for item in posts:
                ext_key = str(item["external_key"])
                existed = self._repo.document_exists(TELEGRAM_POSTS_COLLECTION, ext_key)
                self._repo.upsert_document(
                    collection=TELEGRAM_POSTS_COLLECTION,
                    external_key=ext_key,
                    search_text=f"{item['channel']} {item['text']}",
                    doc={
                        **item,
                        "source_mode": "public_preview",
                        "account_slug": account["slug"],
                        "ingested_at": utc_now(),
                    },
                    description="Ingested Telegram admin channel_post and t.me/s/ public posts",
                )
                total_fetched += 1
                if existed:
                    total_updated += 1
                else:
                    total_new += 1

        self._repo.update_integration_health(account["slug"], status="ok", last_error=None)
        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug="integrations",
            target_slug=account["slug"],
            event_type="telegram.public_channel_synced",
            payload={
                "category": "reviews",
                "title": f"Synced Public Telegram Preview ({', '.join(public_channels)})",
                "badge": f"{total_new} New · {total_fetched} Fetched",
                "badge_tone": "emerald",
                "summary": (
                    f"Fetched {total_fetched} post(s) via https://t.me/s/ "
                    f"({total_new} new, {total_updated} deduplicated/updated)."
                ),
                "meta": f"Collection: {TELEGRAM_POSTS_COLLECTION}",
            },
            hop_count=1,
        )
        return {
            "slug": account["slug"],
            "channels": public_channels,
            "fetched_count": total_fetched,
            "new_count": total_new,
            "updated_count": total_updated,
            "collection": TELEGRAM_POSTS_COLLECTION,
        }

    async def probe_account(
        self,
        slug: str,
        *,
        send_test_message: bool = False,
    ) -> dict[str, Any]:
        """Probe stored Telegram credentials and update connector health in SQLite."""
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "telegram":
            return self._repo.update_integration_health(
                account["slug"], status="ok", last_error=None
            )

        if account["secrets"].get("mode") == "public_preview":
            public_channels = list(account["secrets"].get("public_channels") or [])
            if not public_channels:
                self._repo.update_integration_health(
                    account["slug"],
                    status="degraded",
                    last_error="Public preview monitor has no public_channels configured.",
                )
                raise TelegramIntegrationError(
                    "Public preview monitor has no public_channels configured."
                )
            try:
                await fetch_telegram_public_channel(
                    str(public_channels[0]),
                    fetcher=self._public_fetcher,
                    limit=5,
                )
                return self._repo.update_integration_health(
                    account["slug"],
                    status="ok",
                    last_error=None,
                )
            except Exception as exc:
                self._repo.update_integration_health(
                    account["slug"],
                    status="degraded",
                    last_error=str(exc),
                )
                raise TelegramIntegrationError(str(exc)) from exc

        token = str(account["secrets"].get("bot_token") or "")
        if not token:
            updated = self._repo.update_integration_health(
                account["slug"],
                status="degraded",
                last_error="Stored bot_token is missing.",
            )
            raise TelegramIntegrationError("Stored bot_token is missing.")

        if send_test_message and not str(account["secrets"].get("operator_chat_id") or "").strip():
            raise TelegramConfigError(
                f"Telegram connector '{account['slug']}' has no Operator Alert Chat ID configured for test messages."
            )

        try:
            identity = await self.verify_token(token)
            if send_test_message:
                await self._transport.send_message(
                    token,
                    chat_id=account["secrets"]["operator_chat_id"],
                    text=(
                        f"Argo connector probe succeeded for @{identity.get('username', account['slug'])}. "
                        "Send /status or ask any question here to inspect bot jobs and platform health."
                    ),
                )
            return self._repo.update_integration_health(
                account["slug"],
                status="ok",
                last_error=None,
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc), [token])
            self._repo.update_integration_health(
                account["slug"],
                status="degraded",
                last_error=safe_err,
            )
            raise TelegramIntegrationError(safe_err) from exc

    async def send_resource_alert(
        self,
        *,
        telemetry: HostTelemetry,
        alert_kind: Literal["ram_warning", "ram_critical", "disk_warning"],
        stopped_desktops: list[str] | None = None,
        cleaned_files: int = 0,
    ) -> list[dict[str, Any]]:
        """Dispatch Host Resource Guard alerts with inline control buttons to connected operators."""
        stopped = stopped_desktops or []
        if alert_kind == "ram_critical":
            stopped_note = (
                f"Auto-hibernated desktops: {', '.join(stopped)}."
                if stopped
                else "No active desktop containers were running."
            )
            message_text = (
                f"[Argo Host Guard · CRITICAL RAM {telemetry.ram_percent}%]\n"
                f"Host memory exceeded the 90% critical threshold (CPU {telemetry.cpu_percent}%, "
                f"RAM {telemetry.ram_percent}%). {stopped_note} Session volumes remain preserved."
            )
            reply_markup = None
        elif alert_kind == "ram_warning":
            message_text = (
                f"[Argo Host Guard · RAM Startup Gate {telemetry.ram_percent}%]\n"
                f"Host memory exceeded the 80% gate (RAM {telemetry.ram_percent}%, "
                f"CPU {telemetry.cpu_percent}%). New desktop launches are queued until pressure drops."
            )
            reply_markup = build_inline_keyboard(
                [[("Stop Idle Desktops", STOP_IDLE_DESKTOPS_CALLBACK)]]
            )
        else:
            message_text = (
                f"[Argo Host Guard · Disk Warning {telemetry.disk_percent}%]\n"
                f"Root volume exceeded the 85% disk threshold ({telemetry.disk_percent}%). "
                f"Cleaned {cleaned_files} temporary artifact(s); SQLite database and desktop volumes untouched."
            )
            reply_markup = build_inline_keyboard(
                [[("Stop Idle Desktops", STOP_IDLE_DESKTOPS_CALLBACK)]]
            )

        deliveries: list[dict[str, Any]] = []
        for account in self._repo.list_telegram_integrations():
            if account["status"] == "expired":
                continue
            secrets_map = account["secrets"]
            token = str(secrets_map.get("bot_token") or "")
            chat_id = secrets_map.get("operator_chat_id")
            if not token or not chat_id:
                continue
            try:
                sent = await self._transport.send_message(
                    token,
                    chat_id=chat_id,
                    text=message_text,
                    reply_markup=reply_markup,
                )
                deliveries.append(
                    {
                        "account_slug": account["slug"],
                        "chat_id": str(chat_id),
                        "message_id": sent.get("message_id"),
                    }
                )
            except Exception as exc:
                safe_err = redact_secrets(str(exc), [token])
                logger.warning(
                    "Failed to send Telegram resource alert via %s: %s",
                    account["slug"],
                    safe_err,
                )
                self._repo.update_integration_health(
                    account["slug"],
                    status="degraded",
                    last_error=safe_err,
                )

        return deliveries

    async def send_operator_notice(
        self,
        *,
        title: str,
        body: str,
    ) -> list[dict[str, Any]]:
        """Dispatch a plain operational alert (e.g., Selkies takeover request) to connected operators."""
        message_text = f"[{title}]\n{body}"
        deliveries: list[dict[str, Any]] = []
        for account in self._repo.list_telegram_integrations():
            if account["status"] == "expired":
                continue
            secrets_map = account["secrets"]
            token = str(secrets_map.get("bot_token") or "")
            chat_id = secrets_map.get("operator_chat_id")
            if not token or not chat_id:
                continue
            try:
                sent = await self._transport.send_message(
                    token,
                    chat_id=chat_id,
                    text=message_text,
                )
                deliveries.append(
                    {
                        "account_slug": account["slug"],
                        "chat_id": str(chat_id),
                        "message_id": sent.get("message_id"),
                    }
                )
            except Exception as exc:
                safe_err = redact_secrets(str(exc), [token])
                logger.warning(
                    "Failed to send Telegram operator notice via %s: %s",
                    account["slug"],
                    safe_err,
                )
        return deliveries

    def _collect_status_snapshot(self) -> dict[str, Any]:
        host_telemetry = self._guard.sample().to_dict() if self._guard is not None else None
        scheduled_jobs = (
            self._bot_scheduler.list_scheduled_jobs()
            if self._bot_scheduler is not None
            else None
        )
        return self._repo.build_platform_status_snapshot(
            host_telemetry=host_telemetry,
            scheduled_jobs=scheduled_jobs,
        )

    @staticmethod
    def _format_status_report(snapshot: dict[str, Any], section: str = "status") -> str:
        counts = snapshot.get("counts") or {}
        host = snapshot.get("host")
        bots = list(snapshot.get("bots") or [])
        scheduled_jobs = list(snapshot.get("scheduled_jobs") or [])
        runs = list(snapshot.get("recent_runs") or [])
        pending = list(snapshot.get("pending_approvals") or [])
        integrations = list(snapshot.get("integrations") or [])
        models_info = snapshot.get("models") or {}

        if section == "help":
            return (
                "Argo Operator Telegram Controls\n\n"
                "Commands:\n"
                "- /status — Platform health, host RAM/CPU/Disk, bots & recent jobs\n"
                "- /bots — Registered declarative bots & active schedules\n"
                "- /runs — Latest bot job executions & token/cost totals\n"
                "- /approvals — Pending human approval queue items\n"
                "- /help — Show this command reference\n\n"
                "Natural-language questions:\n"
                "Ask anything directly (e.g. 'What failed recently?', 'Summarize active bots', "
                "or 'How much RAM is free?').\n\n"
                "Approval cards:\n"
                "Tap [Approve & Publish] / [Reject], or swipe-reply to revise any draft."
            )

        if section == "bots":
            lines = [f"Argo Bots ({len(bots)} registered · {len(scheduled_jobs)} scheduled jobs)"]
            if not bots:
                lines.append("No declarative bots registered yet. Create one via + New Bot in the Web UI.")
            else:
                for b in bots[:12]:
                    state = "enabled" if b["enabled"] else "disabled"
                    desk = f" ({b['desktop_state']})" if b["runtime"] == "desktop" else ""
                    lines.append(
                        f"- {b['name']} [{b['slug']}]: {state} · {b['runtime']}{desk} · "
                        f"RBAC={b['outbound_rbac']} · {b['model']}"
                    )
                    rt_parts = [
                        f"{r.get('label') or r.get('type')} ({r.get('schedule')})"
                        for r in (b.get("routines") or [])
                        if r.get("enabled", True)
                    ]
                    if rt_parts:
                        lines.append(f"  Routines: {', '.join(rt_parts[:4])}")
            if scheduled_jobs:
                lines.append("\nScheduled Jobs:")
                for job in scheduled_jobs[:8]:
                    lines.append(
                        f"- {job['bot_slug']} · {job['label']}: {job['schedule']} ({job['backend']})"
                    )
            return "\n".join(lines)[:3800]

        if section == "runs":
            lines = [
                f"Argo Recent Bot Jobs (today: {models_info.get('today_tokens', 0)} tok, "
                f"${float(models_info.get('today_cost_usd', 0.0)):.4f})"
            ]
            if not runs:
                lines.append("No bot runs recorded yet.")
            else:
                for r in runs[:8]:
                    tok = int(r.get("input_tokens") or 0) + int(r.get("output_tokens") or 0)
                    summary = str(r.get("summary") or "").replace("\n", " ")[:120]
                    lines.append(
                        f"- [{r['status']}] {r['bot_slug']} ({r['trigger_type']}) · "
                        f"{r.get('llm_model_used') or '-'} · {tok} tok · {r['started_at']}"
                    )
                    if summary:
                        lines.append(f"  {summary}")
            return "\n".join(lines)[:3800]

        if section == "approvals":
            count = int(counts.get("pending_approvals", len(pending)))
            lines = [f"Argo Pending Approvals ({count} waiting)"]
            if not pending:
                lines.append("0 pending approvals in queue.")
            else:
                for item in pending[:8]:
                    preview = str(item.get("text_preview") or "").replace("\n", " ")[:120]
                    lines.append(
                        f"- {item['id']} · {item['bot_slug']} -> {item['action_type']} ({item['target_account_slug']})"
                    )
                    if preview:
                        lines.append(f"  {preview}")
            return "\n".join(lines)[:3800]

        # Default "status" overview
        lines = [f"Argo Platform Status ({snapshot.get('generated_at')})"]
        if isinstance(host, dict):
            gate = "BLOCKED (>80%)" if host.get("ram_startup_gate_blocked") else "Open (<80%)"
            lines.append(
                f"Host: CPU {host.get('cpu_percent')}% · RAM {host.get('ram_percent')}% "
                f"(of {host.get('ram_total_gb')} GB, Desktop Gate: {gate}) · Disk {host.get('disk_percent')}%"
            )
        enabled_bots = sum(1 for b in bots if b.get("enabled"))
        lines.append(
            f"Workspace: {counts.get('bots', len(bots))} bots ({enabled_bots} enabled) · "
            f"{counts.get('desktops_running', 0)}/{counts.get('desktops_total', 0)} desktops ON · "
            f"{counts.get('pending_approvals', 0)} pending approvals"
        )
        if integrations:
            int_summary = ", ".join(f"{i['slug']}={i['status']}" for i in integrations[:6])
            lines.append(f"Connectors ({len(integrations)}): {int_summary}")
        else:
            lines.append("Connectors: none configured")

        providers = list(models_info.get("providers") or [])
        configured_models = [p["model_id"] for p in providers if p.get("configured")]
        lines.append(
            f"Models ({len(configured_models)}/{len(providers)} ready): "
            f"{', '.join(configured_models[:4]) or 'no API keys configured'} · "
            f"today {models_info.get('today_tokens', 0)} tok (${float(models_info.get('today_cost_usd', 0.0)):.4f})"
        )
        lines.append("\nLatest Bot Runs:")
        if not runs:
            lines.append("- No bot runs recorded yet.")
        else:
            for r in runs[:5]:
                tok = int(r.get("input_tokens") or 0) + int(r.get("output_tokens") or 0)
                lines.append(
                    f"- {r['bot_slug']} [{r['status']}] via {r['trigger_type']} · {tok} tok · {r['started_at']}"
                )
        return "\n".join(lines)[:3800]

    def _matching_telegram_message_bots(self) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for bot in self._repo.list_bots():
            if not bot.get("enabled"):
                continue
            for routine in bot.get("routines", []):
                if not isinstance(routine, dict) or not routine.get("enabled", True):
                    continue
                ev_name = str(
                    routine.get("event")
                    or routine.get("trigger")
                    or routine.get("topic")
                    or ""
                ).strip()
                if (str(routine.get("type") or "") == "on_event" or ev_name) and ev_name == "telegram.message":
                    matches.append(bot)
                    break
        return matches

    async def _answer_with_builtin_assistant(
        self,
        *,
        bot_token: str,
        account_slug: str,
        msg_chat_id: str | int,
        raw_text: str,
        reply_to_text: str,
        corr_id: str,
    ) -> dict[str, Any]:
        snapshot = self._collect_status_snapshot()
        providers = self._repo.list_model_provider_credentials()
        has_active_llm = self._llm_router is not None and (
            getattr(self._llm_router, "_transport", None) is not None
            or any(
                bool(p.get("api_key"))
                or (p["provider_type"] == "ollama" and bool(p.get("api_base")))
                for p in providers
            )
        )
        model_used = "deterministic-fallback"
        if has_active_llm:
            try:
                system_prompt = (
                    "You are the built-in Argo Operator Status Assistant answering an authorized operator "
                    "over Telegram. Ground every claim strictly in the provided platform_status JSON snapshot "
                    "(never invent jobs, metrics, or secrets). Reply concisely in Telegram-friendly Markdown "
                    "(**bold**, `code`, short bullet lists) using the same language as the operator's message."
                )
                prompt_payload: dict[str, Any] = {
                    "operator_message": raw_text,
                    "platform_status": snapshot,
                }
                if reply_to_text:
                    prompt_payload["reply_to_text"] = reply_to_text
                llm_res = await self._llm_router.complete(
                    bot_slug="telegram-operator-assistant",
                    prompt=json.dumps(prompt_payload, ensure_ascii=False),
                    system_prompt=system_prompt,
                    trigger_type="telegram_dm",
                    correlation_id=corr_id,
                    hop_count=1,
                    outbound_rbac="execute",
                )
                reply_text = str(llm_res.output_text or "").strip() or self._format_status_report(
                    snapshot, section="status"
                )
                model_used = str(llm_res.model_used)
            except Exception as exc:
                safe_err = redact_secrets(str(exc), [bot_token])
                logger.warning("Built-in Telegram Operator Assistant failed: %s", safe_err)
                reply_text = (
                    f"Assistant fallback ({safe_err[:120]}):\n\n"
                    f"{self._format_status_report(snapshot, section='status')}"
                )
        else:
            reply_text = (
                "No active LLM API key is configured in Models yet. Live platform status:\n\n"
                f"{self._format_status_report(snapshot, section='status')}"
            )

        sent = await self._transport.send_message(
            bot_token,
            chat_id=msg_chat_id,
            text=reply_text[:3900],
        )
        await self._bus.publish(
            correlation_id=corr_id,
            source_slug="telegram-operator-assistant",
            target_slug=account_slug,
            event_type="telegram.assistant_replied",
            payload={
                "category": "reviews",
                "title": f"Telegram Assistant Replied ({model_used})",
                "badge": model_used,
                "badge_tone": "emerald",
                "summary": reply_text[:280],
                "meta": f"Chat {msg_chat_id}",
            },
            hop_count=1,
        )
        return {
            "status": "replied_assistant",
            "correlation_id": corr_id,
            "model_used": model_used,
            "message_id": sent.get("message_id"),
        }

    async def handle_webhook(
        self,
        slug: str,
        *,
        secret_header: str | None,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle Telegram webhook updates with HMAC-constant-time secret verification and callbacks."""
        account = self._repo.get_integration_secrets(slug)
        secrets_map = account["secrets"]
        expected_secret = str(secrets_map.get("webhook_secret") or "")
        if (
            not expected_secret
            or not secret_header
            or not hmac.compare_digest(secret_header, expected_secret)
        ):
            raise PermissionError("Invalid Telegram webhook secret token.")

        update_id = payload.get("update_id")
        if update_id is not None:
            is_fresh = await self._bus.check_and_mark_seen(
                f"tg_upd:{account['slug']}:{update_id}"
            )
            if not is_fresh:
                return {"status": "duplicate_ignored", "update_id": update_id}

        callback_query = payload.get("callback_query")
        if isinstance(callback_query, dict):
            cb_id = str(callback_query.get("id") or "")
            cb_data = str(callback_query.get("data") or "")
            actor_info = callback_query.get("from") or {}
            bot_token = str(secrets_map.get("bot_token") or "")
            if bool(actor_info.get("is_bot")):
                return {"status": "ignored_bot_sender"}
            actor_name = (
                actor_info.get("username")
                or actor_info.get("id")
                or "telegram_operator"
            )
            message_obj = callback_query.get("message") or {}
            chat_id = (message_obj.get("chat") or {}).get("id")
            configured_op_chat = str(secrets_map.get("operator_chat_id") or "").strip()
            if not configured_op_chat or chat_id is None or str(chat_id) != configured_op_chat:
                if cb_id and bot_token:
                    with contextlib.suppress(Exception):
                        await self._transport.answer_callback_query(
                            bot_token,
                            callback_query_id=cb_id,
                            text="Unauthorized chat.",
                        )
                return {"status": "ignored_unauthorized_chat"}
            message_id = message_obj.get("message_id")
            original_text = str(message_obj.get("text") or "Argo Host Resource Guard Alert")

            if cb_data == STOP_IDLE_DESKTOPS_CALLBACK:
                if cb_id and bot_token:
                    await self._transport.answer_callback_query(
                        bot_token,
                        callback_query_id=cb_id,
                        text="Hibernating active desktop containers...",
                    )
                if self._desktop_manager is not None:
                    stopped = await self._desktop_manager.stop_all_desktops(
                        reason="telegram_stop_idle",
                        idle_only=True,
                    )
                else:
                    stopped = self._repo.stop_running_desktops()
                summary_line = (
                    f"Hibernated {len(stopped)} desktop container(s): {', '.join(stopped)}"
                    if stopped
                    else "No running desktop containers needed hibernation"
                )
                if bot_token and chat_id is not None and message_id is not None:
                    locked_text = (
                        f"{original_text}\n\n"
                        f"Status: {summary_line} · by @{actor_name} at {utc_now()}"
                    )
                    await self._transport.edit_message_text(
                        bot_token,
                        chat_id=chat_id,
                        message_id=int(message_id),
                        text=locked_text,
                        reply_markup=None,
                    )

                await self._bus.publish(
                    correlation_id=make_id("corr"),
                    source_slug=f"telegram:{actor_name}",
                    target_slug="host-guard",
                    event_type="desktop.stopped_via_telegram",
                    payload={
                        "category": "alerts",
                        "title": "Desktops Hibernated via Telegram Control",
                        "badge": f"Hibernated · {len(stopped)}",
                        "badge_tone": "emerald",
                        "summary": summary_line,
                        "meta": f"Triggered from {account['slug']} inline keyboard",
                    },
                    hop_count=1,
                )
                return {
                    "status": "handled",
                    "action": "stop_idle_desktops",
                    "stopped_desktops": stopped,
                }

            if cb_data.startswith(("apr:ok:", "apr:no:")):
                action: Literal["approve", "reject"] = (
                    "approve" if cb_data.startswith("apr:ok:") else "reject"
                )
                approval_id = cb_data.split(":", 2)[2]
                if self._approval_coordinator is None:
                    if cb_id and bot_token:
                        await self._transport.answer_callback_query(
                            bot_token,
                            callback_query_id=cb_id,
                            text="Processing approval...",
                        )
                    return {
                        "status": "ignored_no_coordinator",
                        "approval_id": approval_id,
                    }
                try:
                    existing_apr = self._repo.get_approval(approval_id)
                except Exception:
                    existing_apr = None
                if (
                    isinstance(existing_apr, dict)
                    and existing_apr.get("telegram_chat_id")
                    and str(existing_apr["telegram_chat_id"]) != str(chat_id)
                ):
                    if cb_id and bot_token:
                        with contextlib.suppress(Exception):
                            await self._transport.answer_callback_query(
                                bot_token,
                                callback_query_id=cb_id,
                                text="Unauthorized chat.",
                            )
                    return {"status": "ignored_unauthorized_chat", "approval_id": approval_id}
                if cb_id and bot_token:
                    await self._transport.answer_callback_query(
                        bot_token,
                        callback_query_id=cb_id,
                        text="Processing approval...",
                    )
                try:
                    resolved = await self._approval_coordinator.resolve_approval(
                        approval_id,
                        action=action,
                        actor=f"telegram:{actor_name}",
                    )
                    return {
                        "status": "handled",
                        "action": action,
                        "approval_id": approval_id,
                        "approval_status": resolved["status"],
                    }
                except AlreadyResolvedError:
                    return {
                        "status": "already_resolved",
                        "approval_id": approval_id,
                        "message": "Already resolved.",
                    }

        channel_post = payload.get("channel_post") or payload.get("edited_channel_post")
        if isinstance(channel_post, dict):
            is_edited = isinstance(payload.get("edited_channel_post"), dict)
            chat = channel_post.get("chat") or {}
            username = str(chat.get("username") or "").lstrip("@")
            chat_id_str = str(chat.get("id") or "")
            channel_key = f"@{username.lower()}" if username else chat_id_str
            channel_title = str(chat.get("title") or channel_key)

            admin_channels = [
                str(ch).strip().lower()
                for ch in (secrets_map.get("admin_channels") or [])
                if str(ch).strip()
            ]
            if admin_channels and (
                channel_key.lower() not in admin_channels
                and chat_id_str.lower() not in admin_channels
            ):
                return {
                    "status": "ignored_unlisted_channel",
                    "channel": channel_key,
                }

            message_id = channel_post.get("message_id")
            text = str(channel_post.get("text") or channel_post.get("caption") or "").strip()
            ext_key = f"tg:{channel_key}:{message_id if message_id is not None else update_id}"
            post_url = (
                f"https://t.me/{username}/{message_id}"
                if username and message_id is not None
                else None
            )
            doc_row = self._repo.upsert_document(
                collection=TELEGRAM_POSTS_COLLECTION,
                external_key=ext_key,
                search_text=f"{channel_key} {channel_title} {text}",
                doc={
                    "source_mode": "bot_api_admin",
                    "account_slug": account["slug"],
                    "channel": channel_key,
                    "channel_title": channel_title,
                    "message_id": message_id,
                    "text": text,
                    "url": post_url,
                    "edited": is_edited,
                    "ingested_at": utc_now(),
                },
                description="Ingested Telegram admin channel_post and t.me/s/ public posts",
            )
            event_type = "telegram.edited_channel_post" if is_edited else "telegram.channel_post"
            await self._bus.publish(
                correlation_id=make_id("corr"),
                source_slug=f"telegram:{channel_key}",
                target_slug=TELEGRAM_POSTS_COLLECTION,
                event_type=event_type,
                payload={
                    "category": "reviews",
                    "title": (
                        f"Edited Channel Post ({channel_key})"
                        if is_edited
                        else f"Admin Channel Post ({channel_key})"
                    ),
                    "badge": "edited_channel_post" if is_edited else "channel_post",
                    "badge_tone": "emerald",
                    "summary": text[:280] or "(Empty media post)",
                    "meta": f"Key: {ext_key}",
                },
                hop_count=1,
            )
            return {
                "status": "ingested",
                "external_key": ext_key,
                "document_id": doc_row["id"],
                "edited": is_edited,
            }

        message_obj = payload.get("message")
        if isinstance(message_obj, dict):
            from_info = message_obj.get("from") or {}
            if bool(from_info.get("is_bot")):
                return {"status": "ignored_bot_sender"}

            msg_chat_id = (message_obj.get("chat") or {}).get("id")
            configured_op_chat = str(secrets_map.get("operator_chat_id") or "").strip()
            if not configured_op_chat or msg_chat_id is None:
                return {"status": "ignored_no_operator_chat"}
            if str(msg_chat_id) != configured_op_chat:
                return {"status": "ignored_unauthorized_chat"}

            sender_name = (
                from_info.get("username")
                or from_info.get("id")
                or "telegram_operator"
            )
            raw_text = str(message_obj.get("text") or message_obj.get("caption") or "").strip()

            reply_to = message_obj.get("reply_to_message")
            if isinstance(reply_to, dict) and self._approval_coordinator is not None:
                reply_msg_id = reply_to.get("message_id")
                if msg_chat_id is not None and reply_msg_id is not None and raw_text:
                    revision = await self._approval_coordinator.handle_telegram_reply_revision(
                        chat_id=msg_chat_id,
                        reply_to_message_id=int(reply_msg_id),
                        instruction_text=raw_text,
                        actor=f"telegram:{sender_name}",
                        telegram_account_slug=account["slug"],
                    )
                    if revision is not None:
                        return {"status": "revised", **revision}

            if not raw_text:
                return {"status": "accepted"}

            bot_token = str(secrets_map.get("bot_token") or "").strip()
            if not bot_token:
                return {"status": "accepted"}

            command_map = {
                "/start": "help",
                "/help": "help",
                "/status": "status",
                "/bots": "bots",
                "/runs": "runs",
                "/jobs": "runs",
                "/approvals": "approvals",
            }
            cmd = raw_text.split()[0].lower().split("@", 1)[0]
            if cmd in command_map:
                snapshot = self._collect_status_snapshot()
                report = self._format_status_report(snapshot, section=command_map[cmd])
                sent = await self._transport.send_message(
                    bot_token,
                    chat_id=msg_chat_id,
                    text=report,
                )
                await self._bus.publish(
                    correlation_id=make_id("corr"),
                    source_slug=f"telegram:{sender_name}",
                    target_slug=account["slug"],
                    event_type="telegram.command_handled",
                    payload={
                        "category": "reviews",
                        "title": f"Telegram Command {cmd}",
                        "badge": f"Telegram · {account['slug']}",
                        "badge_tone": "emerald",
                        "summary": report[:240],
                        "meta": f"Chat {msg_chat_id}",
                    },
                    hop_count=1,
                )
                return {
                    "status": "replied_command",
                    "command": cmd,
                    "message_id": sent.get("message_id"),
                }

            corr_id = make_id("corr")
            reply_to_text = (
                str(reply_to.get("text") or "").strip() if isinstance(reply_to, dict) else ""
            )
            dm_ext_key = (
                f"tg_dm:{account['slug']}:{msg_chat_id}:"
                f"{message_obj.get('message_id') or update_id or corr_id}"
            )
            self._repo.upsert_document(
                collection=TELEGRAM_POSTS_COLLECTION,
                external_key=dm_ext_key,
                search_text=f"{account['slug']} {sender_name} {raw_text}",
                doc={
                    "source_mode": "bot_api_dm",
                    "account_slug": account["slug"],
                    "chat_id": str(msg_chat_id),
                    "message_id": message_obj.get("message_id"),
                    "sender": str(sender_name),
                    "title": f"Telegram DM from @{sender_name}",
                    "text": raw_text,
                    "reply_to_text": reply_to_text,
                    "ingested_at": utc_now(),
                },
                description="Ingested Telegram channel posts and bot DM messages",
            )
            matching_bots = self._matching_telegram_message_bots()
            await self._bus.publish(
                correlation_id=corr_id,
                source_slug=f"telegram:{sender_name}",
                target_slug=account["slug"],
                event_type="telegram.message",
                payload={
                    "category": "reviews",
                    "title": f"Telegram Operator Request (@{sender_name})",
                    "badge": f"Telegram · {account['slug']}",
                    "badge_tone": "sky",
                    "summary": raw_text[:280],
                    "meta": f"Chat {msg_chat_id}",
                    "account_slug": account["slug"],
                    "chat_id": str(msg_chat_id),
                    "message_id": message_obj.get("message_id"),
                    "sender": str(sender_name),
                    "text": raw_text,
                    "reply_to_text": reply_to_text,
                    "external_key": dm_ext_key,
                },
                hop_count=1,
            )
            if matching_bots:
                return {
                    "status": "dispatched_to_bot",
                    "correlation_id": corr_id,
                    "matched_bots": [b["slug"] for b in matching_bots],
                }

            return await self._answer_with_builtin_assistant(
                bot_token=bot_token,
                account_slug=account["slug"],
                msg_chat_id=msg_chat_id,
                raw_text=raw_text,
                reply_to_text=reply_to_text,
                corr_id=corr_id,
            )

        return {"status": "accepted"}
