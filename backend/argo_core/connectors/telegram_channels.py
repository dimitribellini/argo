"""Telegram public channel preview (https://t.me/s/<handle>) ingestion without MTProto."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

from argo_core.db.repositories import utc_now
from argo_core.security.ssrf import PublicHttpFetcher, SafePublicHttpFetcher

_CHANNEL_HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_HTML_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class TelegramConfigError(ValueError):
    """Raised when Telegram credentials, chat IDs, channel handles, or callbacks are invalid."""


def normalize_public_channel_handle(raw: str) -> str:
    """Normalize a Telegram public channel handle or t.me/s/ URL into a clean username."""
    cleaned = raw.strip()
    for prefix in (
        "https://t.me/s/",
        "http://t.me/s/",
        "https://t.me/",
        "http://t.me/",
        "t.me/s/",
        "t.me/",
    ):
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break

    cleaned = cleaned.split("?", 1)[0].split("#", 1)[0].strip("/")
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    cleaned = cleaned.lstrip("@").strip()

    if not _CHANNEL_HANDLE_RE.match(cleaned):
        raise TelegramConfigError(
            f"Invalid Telegram public channel handle '{raw}'; expected 4-32 alphanumeric/underscore characters."
        )
    return cleaned


def _clean_post_text(raw_text: str) -> str:
    lines = [" ".join(line.split()) for line in raw_text.splitlines()]
    non_empty = [line for line in lines if line]
    return "\n".join(non_empty).strip()


def _parse_msg_id(data_post: str) -> tuple[str | None, int | str | None]:
    parts = data_post.strip().split("/")
    if len(parts) < 2 or not parts[-1].strip():
        return None, None
    post_channel = parts[-2].strip() or None
    msg_part = parts[-1].strip()
    return post_channel, (int(msg_part) if msg_part.isdigit() else msg_part)


def _extract_lxml_text(node: Any) -> str:
    parts: list[str] = []

    def _walk(el: Any) -> None:
        tag = str(getattr(el, "tag", "") or "").lower()
        if tag == "br":
            parts.append("\n")
        if getattr(el, "text", None):
            parts.append(str(el.text))
        for child in el:
            _walk(child)
            if getattr(child, "tail", None):
                parts.append(str(child.tail))

    _walk(node)
    return _clean_post_text("".join(parts))


def _parse_with_lxml(html_text: str, channel_handle: str) -> list[dict[str, Any]]:
    if not html_text or not html_text.strip():
        return []
    from lxml import html as lxml_html  # type: ignore[import-not-found]
    from lxml.etree import ParserError  # type: ignore[import-not-found]

    try:
        doc = lxml_html.fromstring(html_text)
    except (ParserError, ValueError):
        return []
    widgets = doc.xpath("//*[contains(concat(' ', normalize-space(@class), ' '), ' tgme_widget_message ') and @data-post]")
    items: list[dict[str, Any]] = []
    for widget in widgets:
        data_post = str(widget.get("data-post") or "")
        post_channel, msg_id = _parse_msg_id(data_post)
        if msg_id is None:
            continue

        text_nodes = widget.xpath(
            ".//*[contains(concat(' ', normalize-space(@class), ' '), ' tgme_widget_message_text ') "
            "and not(ancestor::*[contains(concat(' ', normalize-space(@class), ' '), ' tgme_widget_message_reply ')])]"
        )
        if not text_nodes:
            continue
        post_text = _extract_lxml_text(text_nodes[-1])
        if not post_text:
            continue

        time_nodes = widget.xpath(
            ".//*[contains(concat(' ', normalize-space(@class), ' '), ' tgme_widget_message_date ')]//time[@datetime]"
        ) or widget.xpath(".//time[@datetime]")
        published_at = (
            str(time_nodes[0].get("datetime")).strip()
            if time_nodes and time_nodes[0].get("datetime")
            else utc_now()
        )

        views_nodes = widget.xpath(
            ".//*[contains(concat(' ', normalize-space(@class), ' '), ' tgme_widget_message_views ')]"
        )
        views = _clean_post_text(views_nodes[0].text_content()) if views_nodes else None

        handle_for_url = (post_channel or channel_handle).lstrip("@")
        items.append(
            {
                "channel": f"@{channel_handle.lower()}",
                "message_id": msg_id,
                "text": post_text,
                "published_at": published_at,
                "views": views or None,
                "url": f"https://t.me/{handle_for_url}/{msg_id}",
                "external_key": f"tg:@{channel_handle.lower()}:{msg_id}",
            }
        )
    return items


class _StdlibTelegramHTMLParser(HTMLParser):
    """Dependency-free HTMLParser fallback extracting t.me/s/ widget posts."""

    def __init__(self, channel_handle: str) -> None:
        super().__init__(convert_charrefs=True)
        self._channel_handle = channel_handle
        self._stack: list[str] = []
        self._widget_depth: int | None = None
        self._reply_depth: int | None = None
        self._text_depth: int | None = None
        self._views_depth: int | None = None
        self._date_depth: int | None = None
        self._current: dict[str, Any] | None = None
        self._text_chunks: list[str] = []
        self._views_chunks: list[str] = []
        self.items: list[dict[str, Any]] = []

    def _finalize_current(self) -> None:
        if not self._current:
            return
        post_text = _clean_post_text("".join(self._text_chunks))
        if post_text:
            msg_id = self._current["message_id"]
            post_channel = (self._current.get("post_channel") or self._channel_handle).lstrip("@")
            views_text = _clean_post_text("".join(self._views_chunks))
            self.items.append(
                {
                    "channel": f"@{self._channel_handle.lower()}",
                    "message_id": msg_id,
                    "text": post_text,
                    "published_at": self._current.get("published_at") or utc_now(),
                    "views": views_text or None,
                    "url": f"https://t.me/{post_channel}/{msg_id}",
                    "external_key": f"tg:@{self._channel_handle.lower()}:{msg_id}",
                }
            )
        self._current = None
        self._text_chunks = []
        self._views_chunks = []
        self._widget_depth = None
        self._reply_depth = None
        self._text_depth = None
        self._views_depth = None
        self._date_depth = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        classes = set(attr_map.get("class", "").split())

        if tag_lower == "br":
            if self._text_depth is not None and self._reply_depth is None:
                self._text_chunks.append("\n")
            return

        if tag_lower in _HTML_VOID_TAGS:
            return

        depth = len(self._stack) + 1
        self._stack.append(tag_lower)

        data_post = attr_map.get("data-post", "").strip()
        if "tgme_widget_message" in classes and data_post:
            post_channel, msg_id = _parse_msg_id(data_post)
            if msg_id is not None:
                self._finalize_current()
                self._widget_depth = depth
                self._current = {
                    "post_channel": post_channel,
                    "message_id": msg_id,
                    "published_at": None,
                }
                self._text_chunks = []
                self._views_chunks = []
            return

        if self._current is None:
            return

        if "tgme_widget_message_reply" in classes and self._reply_depth is None:
            self._reply_depth = depth
        if (
            "tgme_widget_message_text" in classes
            and self._reply_depth is None
            and self._text_depth is None
        ):
            self._text_chunks = []
            self._text_depth = depth
        if "tgme_widget_message_views" in classes and self._views_depth is None:
            self._views_depth = depth
        if "tgme_widget_message_date" in classes and self._date_depth is None:
            self._date_depth = depth
        if tag_lower == "time" and attr_map.get("datetime"):
            if self._date_depth is not None or self._current.get("published_at") is None:
                self._current["published_at"] = attr_map["datetime"].strip()

    def handle_data(self, data: str) -> None:
        if self._current is None:
            return
        if self._text_depth is not None and self._reply_depth is None:
            self._text_chunks.append(data)
        elif self._views_depth is not None:
            self._views_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in _HTML_VOID_TAGS or not self._stack:
            return

        # Unwind stack carefully to matching tag in case of unclosed HTML elements.
        popped_depth = len(self._stack)
        if tag_lower in self._stack:
            while self._stack:
                current_depth = len(self._stack)
                top = self._stack.pop()
                self._close_depth(current_depth)
                if top == tag_lower:
                    break
        else:
            self._stack.pop()
            self._close_depth(popped_depth)

    def _close_depth(self, depth: int) -> None:
        if self._reply_depth == depth:
            self._reply_depth = None
        if self._text_depth == depth:
            self._text_depth = None
        if self._views_depth == depth:
            self._views_depth = None
        if self._date_depth == depth:
            self._date_depth = None
        if self._widget_depth == depth:
            self._finalize_current()


def _parse_with_stdlib(html_text: str, channel_handle: str) -> list[dict[str, Any]]:
    parser = _StdlibTelegramHTMLParser(channel_handle)
    parser.feed(html_text)
    parser.close()
    parser._finalize_current()
    return parser.items


def parse_telegram_public_html(
    html_text: str,
    channel_handle: str,
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Extract structured posts from https://t.me/s/<channel_handle> HTML."""
    clean_handle = normalize_public_channel_handle(channel_handle)
    try:
        import lxml.html  # type: ignore[import-not-found] # noqa: F401

        parsed = _parse_with_lxml(html_text, clean_handle)
    except ImportError:
        parsed = _parse_with_stdlib(html_text, clean_handle)

    capped = max(1, min(limit, 100))
    if len(parsed) > capped:
        return parsed[-capped:]
    return parsed


async def fetch_telegram_public_channel(
    channel_handle: str,
    *,
    fetcher: PublicHttpFetcher | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Fetch public channel preview HTML via SSRF-guarded HTTP and parse posts."""
    clean_handle = normalize_public_channel_handle(channel_handle)
    preview_url = f"https://t.me/s/{clean_handle}"
    http_fetcher = fetcher or SafePublicHttpFetcher()
    response = await http_fetcher.fetch(preview_url)
    return parse_telegram_public_html(
        response.body,
        clean_handle,
        limit=limit,
    )
