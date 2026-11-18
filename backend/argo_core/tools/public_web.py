"""Zero-overhead SSRF-guarded public RSS/Atom and webpage Markdown fetch tools."""

from __future__ import annotations

import hashlib
import html as html_lib
import re
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any

from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, make_id, utc_now
from argo_core.security.ssrf import (
    AntiBotHaltError,
    PublicHttpFetcher,
    SafePublicHttpFetcher,
)

HTTP_FEED_CACHE_COLLECTION = "http_feed_cache"
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(raw: str) -> str:
    unescaped = html_lib.unescape(raw or "")
    cleaned = _TAG_RE.sub(" ", unescaped)
    return re.sub(r"\s+", " ", cleaned).strip()


def _stable_entry_key(url: str, guid: str, title: str, published: str) -> str:
    seed = guid.strip() or url.strip() or f"{title.strip()}|{published.strip()}"
    if seed.startswith(("http://", "https://")) and len(seed) <= 180:
        return f"rss:{seed}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]
    return f"rss:{digest}"


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()
    return tag.lower()


def _child_text(elem: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for child in elem:
        if _local_name(child.tag) in wanted:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _atom_link(elem: ET.Element) -> str:
    fallback_href = ""
    for child in elem:
        if _local_name(child.tag) == "link":
            href = (child.attrib.get("href") or "").strip()
            rel = (child.attrib.get("rel") or "alternate").strip().lower()
            if href and rel == "alternate":
                return href
            if href and not fallback_href:
                fallback_href = href
            if not href and child.text and child.text.strip():
                return child.text.strip()
    return fallback_href


def _parse_feed_stdlib(xml_text: str, *, limit: int) -> tuple[str, list[dict[str, Any]]]:
    root = ET.fromstring(xml_text.strip())
    root_name = _local_name(root.tag)
    entries: list[dict[str, Any]] = []
    feed_title = ""

    channel_elem = root.find("channel")
    if root_name == "rss" or channel_elem is not None:
        channel = channel_elem if channel_elem is not None else root
        feed_title = _strip_html(_child_text(channel, "title"))
        for item in list(channel):
            if _local_name(item.tag) != "item":
                continue
            title = _strip_html(_child_text(item, "title"))
            link = _child_text(item, "link").strip()
            guid = _child_text(item, "guid").strip()
            published = _child_text(item, "pubdate", "published", "date").strip()
            summary = _strip_html(_child_text(item, "description", "encoded", "summary"))
            entries.append(
                {
                    "external_key": _stable_entry_key(link, guid, title, published),
                    "id": guid or link or title,
                    "title": title,
                    "url": link,
                    "published": published,
                    "summary": summary[:1000],
                }
            )
            if len(entries) >= limit:
                break
        return feed_title, entries

    if root_name == "feed":
        feed_title = _strip_html(_child_text(root, "title"))
        for child in list(root):
            if _local_name(child.tag) != "entry":
                continue
            title = _strip_html(_child_text(child, "title"))
            link = _atom_link(child)
            entry_id = _child_text(child, "id").strip()
            published = _child_text(child, "updated", "published").strip()
            summary = _strip_html(_child_text(child, "summary", "content"))
            entries.append(
                {
                    "external_key": _stable_entry_key(link, entry_id, title, published),
                    "id": entry_id or link or title,
                    "title": title,
                    "url": link,
                    "published": published,
                    "summary": summary[:1000],
                }
            )
            if len(entries) >= limit:
                break
    return feed_title, entries


def _parse_feed(xml_text: str, *, limit: int) -> tuple[str, list[dict[str, Any]]]:
    try:
        import feedparser  # type: ignore[import-not-found]
    except ImportError:
        return _parse_feed_stdlib(xml_text, limit=limit)

    parsed = feedparser.parse(xml_text)
    feed_meta = getattr(parsed, "feed", {}) or {}
    feed_title = _strip_html(str(feed_meta.get("title") or ""))
    entries: list[dict[str, Any]] = []
    for raw_entry in list(getattr(parsed, "entries", []) or [])[:limit]:
        title = _strip_html(str(raw_entry.get("title") or ""))
        link = str(raw_entry.get("link") or "").strip()
        guid = str(raw_entry.get("id") or "").strip()
        published = str(
            raw_entry.get("published") or raw_entry.get("updated") or ""
        ).strip()
        raw_summary = raw_entry.get("summary") or raw_entry.get("description") or ""
        if not raw_summary and isinstance(raw_entry.get("content"), list) and raw_entry["content"]:
            first_content = raw_entry["content"][0]
            if isinstance(first_content, dict):
                raw_summary = first_content.get("value") or ""
        summary = _strip_html(str(raw_summary))
        entries.append(
            {
                "external_key": _stable_entry_key(link, guid, title, published),
                "id": guid or link or title,
                "title": title,
                "url": link,
                "published": published,
                "summary": summary[:1000],
            }
        )
    if not entries and "<" in xml_text:
        return _parse_feed_stdlib(xml_text, limit=limit)
    return feed_title, entries


class _MarkdownHTMLParser(HTMLParser):
    """Lightweight stdlib HTML-to-Markdown extractor skipping nav/script/style boilerplate."""

    _SKIP_TAGS = {"script", "style", "noscript", "svg", "nav", "footer", "aside"}
    _HEADING_TAGS = {"h1": "# ", "h2": "## ", "h3": "### ", "h4": "#### "}

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self._skip_depth = 0
        self._in_title = False
        self._in_link_href: str | None = None
        self._link_parts: list[str] = []
        self.title_parts: list[str] = []
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if lowered == "title":
            self._in_title = True
            return
        if self._skip_depth > 0:
            return
        if lowered in self._HEADING_TAGS:
            self.chunks.append(f"\n\n{self._HEADING_TAGS[lowered]}")
        elif lowered == "li":
            self.chunks.append("\n- ")
        elif lowered in {"p", "div", "section", "article", "blockquote", "br"}:
            self.chunks.append("\n\n")
        elif lowered == "a":
            attr_map = dict(attrs)
            href = (attr_map.get("href") or "").strip()
            if href:
                self._in_link_href = urllib.parse.urljoin(self._base_url, href)
                self._link_parts = []

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in self._SKIP_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if lowered == "title":
            self._in_title = False
            return
        if self._skip_depth > 0:
            return
        if lowered == "a" and self._in_link_href is not None:
            label = re.sub(r"\s+", " ", "".join(self._link_parts)).strip()
            if label:
                self.chunks.append(f"[{label}]({self._in_link_href})")
            self._in_link_href = None
            self._link_parts = []
        elif lowered in self._HEADING_TAGS or lowered in {"p", "li"}:
            self.chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
            return
        if self._skip_depth > 0:
            return
        if self._in_link_href is not None:
            self._link_parts.append(data)
        else:
            self.chunks.append(data)

    def result(self) -> tuple[str, str]:
        title = re.sub(r"\s+", " ", "".join(self.title_parts)).strip()
        raw = "".join(self.chunks)
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in raw.splitlines()]
        collapsed: list[str] = []
        prev_blank = True
        for line in lines:
            if not line:
                if not prev_blank:
                    collapsed.append("")
                prev_blank = True
            else:
                collapsed.append(line)
                prev_blank = False
        markdown = "\n".join(collapsed).strip()
        return title, markdown


def _extract_title_fast(raw_html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
    return _strip_html(match.group(1)) if match else ""


class _FeedLinkParser(HTMLParser):
    """Extract RSS/Atom <link rel="alternate" ...> feed URLs from HTML head."""

    _FEED_MIME_TYPES = {
        "application/rss+xml",
        "application/atom+xml",
        "application/feed+json",
        "application/xml",
        "text/xml",
    }

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base_url = base_url
        self.feeds: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "link":
            return
        attr_map = {str(k).lower(): str(v or "") for k, v in attrs}
        rel_tokens = set(attr_map.get("rel", "").lower().split())
        link_type = attr_map.get("type", "").split(";", 1)[0].strip().lower()
        href = attr_map.get("href", "").strip()
        if not href:
            return
        is_feed_type = link_type in self._FEED_MIME_TYPES
        is_alternate_feed = "alternate" in rel_tokens and (
            is_feed_type or "rss" in href.lower() or "feed" in href.lower() or "atom" in href.lower()
        )
        if is_alternate_feed or ("feed" in rel_tokens and href):
            resolved = urllib.parse.urljoin(self._base_url, href)
            if resolved.startswith(("http://", "https://")) and resolved not in self.feeds:
                self.feeds.append(resolved)


def discover_feed_urls(raw_html: str, base_url: str) -> list[str]:
    """Discover alternate RSS/Atom feed URLs advertised in an HTML page's <head>."""
    if not raw_html or "<link" not in raw_html.lower():
        return []
    parser = _FeedLinkParser(base_url)
    try:
        parser.feed(raw_html[:250_000])
        parser.close()
    except Exception:
        pass
    return parser.feeds[:8]


async def _publish_antibot_halt(
    bus: EventBus | None,
    *,
    correlation_id: str | None,
    source_slug: str,
    exc: AntiBotHaltError,
) -> None:
    if bus is None:
        return
    try:
        await bus.publish(
            correlation_id=correlation_id or make_id("corr"),
            source_slug=source_slug,
            target_slug="activity",
            event_type="web.fetch.halted",
            payload={
                "category": "alerts",
                "title": f"Fetch Halted on Anti-Bot Gate (HTTP {exc.status_code})",
                "badge": f"HTTP {exc.status_code} · Zero-Bypass Policy",
                "badge_tone": "amber",
                "summary": (
                    f"{exc.reason} Configure email newsletter ingestion or operator-authenticated "
                    "Selkies fallback instead of bypassing protection."
                ),
                "meta": exc.url,
            },
            hop_count=1,
        )
    except Exception:
        pass


async def fetch_rss_feed(
    url: str,
    *,
    repo: ArgoRepository | None = None,
    bus: EventBus | None = None,
    fetcher: PublicHttpFetcher | None = None,
    limit: int = 20,
    correlation_id: str | None = None,
    source_slug: str = "builtin:rss",
) -> dict[str, Any]:
    """Fetch and parse a public RSS/Atom feed using SSRF validation and ETag/Last-Modified cache."""
    cleaned_url = url.strip()
    cache_key = f"rss:{cleaned_url}"
    cached_doc: dict[str, Any] = {}
    req_headers: dict[str, str] = {
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5"
    }

    if repo is not None:
        existing = repo.get_document_by_external_key(HTTP_FEED_CACHE_COLLECTION, cache_key)
        if existing and isinstance(existing.get("doc"), dict):
            cached_doc = existing["doc"]
            if cached_doc.get("etag"):
                req_headers["If-None-Match"] = str(cached_doc["etag"])
            if cached_doc.get("last_modified"):
                req_headers["If-Modified-Since"] = str(cached_doc["last_modified"])

    http_fetcher = fetcher or SafePublicHttpFetcher()
    try:
        resp = await http_fetcher.fetch(cleaned_url, headers=req_headers)
    except AntiBotHaltError as exc:
        await _publish_antibot_halt(
            bus,
            correlation_id=correlation_id,
            source_slug=source_slug,
            exc=exc,
        )
        raise

    if resp.status_code == 304:
        return {
            "url": resp.url,
            "status_code": 304,
            "not_modified": True,
            "feed_title": str(cached_doc.get("feed_title") or ""),
            "entries": [],
        }

    feed_title, entries = _parse_feed(resp.body, limit=max(1, min(limit, 100)))
    lower_headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    new_etag = lower_headers.get("etag")
    new_last_modified = lower_headers.get("last-modified")

    if repo is not None and (new_etag or new_last_modified or feed_title):
        repo.upsert_document(
            collection=HTTP_FEED_CACHE_COLLECTION,
            external_key=cache_key,
            search_text=f"{cleaned_url} {feed_title}",
            doc={
                "url": cleaned_url,
                "feed_title": feed_title,
                "etag": new_etag,
                "last_modified": new_last_modified,
                "checked_at": utc_now(),
            },
            description="Conditional HTTP ETag and Last-Modified feed cache",
        )

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "not_modified": False,
        "feed_title": feed_title,
        "entries": entries,
    }


async def fetch_public_webpage(
    url: str,
    *,
    repo: ArgoRepository | None = None,
    bus: EventBus | None = None,
    fetcher: PublicHttpFetcher | None = None,
    max_chars: int = 12000,
    correlation_id: str | None = None,
    source_slug: str = "builtin:web",
) -> dict[str, Any]:
    """Fetch a public HTML page safely (SSRF-guarded), extract Markdown, and track ETag/content hash."""
    cleaned_url = url.strip()
    cache_key = f"web:{cleaned_url}"
    cached_doc: dict[str, Any] = {}
    req_headers: dict[str, str] = {
        "Accept": "text/html, application/xhtml+xml;q=0.9, */*;q=0.5"
    }

    if repo is not None:
        existing = repo.get_document_by_external_key(HTTP_FEED_CACHE_COLLECTION, cache_key)
        if existing and isinstance(existing.get("doc"), dict):
            cached_doc = existing["doc"]
            if cached_doc.get("etag"):
                req_headers["If-None-Match"] = str(cached_doc["etag"])
            if cached_doc.get("last_modified"):
                req_headers["If-Modified-Since"] = str(cached_doc["last_modified"])

    http_fetcher = fetcher or SafePublicHttpFetcher()
    try:
        resp = await http_fetcher.fetch(
            cleaned_url,
            headers=req_headers,
        )
    except AntiBotHaltError as exc:
        await _publish_antibot_halt(
            bus,
            correlation_id=correlation_id,
            source_slug=source_slug,
            exc=exc,
        )
        raise

    if resp.status_code == 304:
        return {
            "url": resp.url,
            "status_code": 304,
            "not_modified": True,
            "unchanged": True,
            "content_hash": str(cached_doc.get("content_hash") or ""),
            "title": str(cached_doc.get("title") or ""),
            "markdown": "",
            "char_count": 0,
            "discovered_feeds": list(cached_doc.get("discovered_feeds") or []),
        }

    title = _extract_title_fast(resp.body)
    markdown = ""
    try:
        import trafilatura  # type: ignore[import-not-found]

        extracted = trafilatura.extract(
            resp.body,
            url=resp.url,
            output_format="markdown",
            include_links=True,
        )
        if isinstance(extracted, str) and extracted.strip():
            markdown = extracted.strip()
    except ImportError:
        pass
    except Exception:
        markdown = ""

    if not markdown:
        parser = _MarkdownHTMLParser(resp.url)
        parser.feed(resp.body)
        parser.close()
        parsed_title, parsed_md = parser.result()
        title = parsed_title or title
        markdown = parsed_md

    discovered_feeds = discover_feed_urls(resp.body, resp.url)
    clipped = markdown[: max(200, max_chars)]
    content_hash = hashlib.sha256(clipped.encode("utf-8")).hexdigest()[:24]
    unchanged = bool(
        cached_doc.get("content_hash") and cached_doc.get("content_hash") == content_hash
    )
    lower_headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    if repo is not None:
        repo.upsert_document(
            collection=HTTP_FEED_CACHE_COLLECTION,
            external_key=cache_key,
            search_text=f"{cleaned_url} {title}"[:300],
            doc={
                "url": cleaned_url,
                "title": title,
                "etag": lower_headers.get("etag"),
                "last_modified": lower_headers.get("last-modified"),
                "content_hash": content_hash,
                "discovered_feeds": discovered_feeds,
                "checked_at": utc_now(),
            },
            description="Conditional HTTP ETag, Last-Modified, and content hash cache",
        )

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "not_modified": False,
        "unchanged": unchanged,
        "content_hash": content_hash,
        "title": title,
        "markdown": clipped,
        "char_count": len(clipped),
        "discovered_feeds": discovered_feeds,
    }
