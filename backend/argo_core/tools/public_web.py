"""Zero-overhead SSRF-guarded public RSS/Atom and webpage Markdown fetch tools."""

from __future__ import annotations

import asyncio
import hashlib
import html as html_lib
import inspect
import json
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from lxml import html as lxml_html

from argo_core.analytics.engine import (
    _deduplicate_headers,
    _json_safe,
    _normalize_cell_value,
    extract_document_summary_from_bytes,
    ingest_file_to_analytics,
    is_analytics_or_document_file,
    profile_datasets,
    read_dataset_rows,
    write_rows_to_parquet,
)
from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, collection_slug, make_id, slugify, utc_now
from argo_core.security.ssrf import (
    AntiBotHaltError,
    PublicFetchError,
    PublicHttpFetcher,
    PublicHttpResponse,
    SafePublicHttpFetcher,
)
from argo_core.security.vault import redact_secrets

HTTP_FEED_CACHE_COLLECTION = "http_feed_cache"
_PLAIN_TEXT_CONTENT_TYPES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/x-markdown",
        "text/x-shellscript",
        "application/x-sh",
        "application/x-shellscript",
        "text/x-python",
        "text/x-script.python",
        "text/yaml",
        "application/x-yaml",
        "application/toml",
        "text/x-ini",
        "text/x-diff",
    }
)
_PLAIN_TEXT_EXTS = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".py",
        ".rb",
        ".pl",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".c",
        ".h",
        ".cpp",
        ".java",
        ".sql",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".service",
        ".rules",
        ".md",
        ".markdown",
        ".rst",
        ".txt",
        ".log",
        ".patch",
        ".diff",
    }
)
_TAG_RE = re.compile(r"<[^>]+>")
_JSON_LD_RE = re.compile(
    r"<script\b[^>]*type\s*=\s*['\"]application/ld\+json['\"][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_PRICE_RE = re.compile(r"(?:[$€£¥]\s*\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:USD|EUR|GBP)\b)")


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
        self._in_table_row = False
        self._in_table_cell = False
        self._row_cells: list[str] = []
        self._cell_parts: list[str] = []
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
        if lowered == "table":
            self.chunks.append("\n\n")
        elif lowered == "tr":
            self._in_table_row = True
            self._row_cells = []
        elif lowered in {"th", "td"}:
            self._in_table_cell = True
            self._cell_parts = []
        elif lowered in self._HEADING_TAGS:
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
                rendered = f"[{label}]({self._in_link_href})"
                if self._in_table_cell:
                    self._cell_parts.append(label)
                else:
                    self.chunks.append(rendered)
            self._in_link_href = None
            self._link_parts = []
        elif lowered in {"th", "td"} and self._in_table_cell:
            cell_text = re.sub(r"\s+", " ", "".join(self._cell_parts)).strip().replace("|", "\\|")
            self._row_cells.append(cell_text)
            self._in_table_cell = False
            self._cell_parts = []
        elif lowered == "tr" and self._in_table_row:
            if any(c for c in self._row_cells):
                self.chunks.append("\n| " + " | ".join(self._row_cells) + " |")
            self._in_table_row = False
            self._row_cells = []
        elif lowered == "table":
            self.chunks.append("\n\n")
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
        elif self._in_table_cell:
            self._cell_parts.append(data)
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


def _extract_json_ld(raw_html: str) -> list[Any]:
    """Extract parsed <script type="application/ld+json"> payloads before HTML stripping."""
    if not raw_html or "ld+json" not in raw_html.lower():
        return []
    found: list[Any] = []
    for raw_block in _JSON_LD_RE.findall(raw_html):
        cleaned = raw_block.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r"^\s*<!--|-->\s*$", "", cleaned).strip()
        try:
            parsed = json.loads(cleaned)
        except Exception:
            continue
        if isinstance(parsed, list):
            found.extend(parsed)
        else:
            found.append(parsed)
    return found


async def _fetch_public_http(
    http_fetcher: PublicHttpFetcher,
    url: str,
    *,
    headers: dict[str, str],
    max_bytes: int = 10_485_760,
) -> PublicHttpResponse:
    kwargs: dict[str, Any] = {"headers": headers}
    try:
        sig = inspect.signature(http_fetcher.fetch)
        accepts_var = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        if accepts_var or "max_bytes" in sig.parameters:
            kwargs["max_bytes"] = max_bytes
    except (TypeError, ValueError):
        pass
    return await http_fetcher.fetch(url, **kwargs)


def _guess_filename_from_url_and_mime(url: str, mime_type: str) -> str:
    path_name = Path(urllib.parse.urlsplit(url).path).name
    if path_name and "." in path_name:
        return path_name
    ext_map = {
        "application/pdf": "document.pdf",
        "text/csv": "data.csv",
        "application/csv": "data.csv",
        "text/tab-separated-values": "data.tsv",
        "application/json": "data.json",
        "application/x-ndjson": "data.ndjson",
        "application/ndjson": "data.ndjson",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "workbook.xlsx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document.docx",
        "application/parquet": "data.parquet",
        "application/vnd.apache.parquet": "data.parquet",
    }
    return ext_map.get(mime_type, "webpage.html")


async def fetch_public_webpage(
    url: str,
    *,
    repo: ArgoRepository | None = None,
    bus: EventBus | None = None,
    fetcher: PublicHttpFetcher | None = None,
    max_chars: int = 12000,
    offset: int = 0,
    correlation_id: str | None = None,
    source_slug: str = "builtin:web",
) -> dict[str, Any]:
    """Fetch a public webpage/document safely (SSRF-guarded), extract Markdown + JSON-LD, and paginate up to 48k chars."""
    cleaned_url = url.strip()
    cache_key = f"web:{cleaned_url}"
    cached_doc: dict[str, Any] = {}
    req_headers: dict[str, str] = {
        "Accept": "text/html, application/xhtml+xml;q=0.9, application/pdf, text/csv, application/json, */*;q=0.5"
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
        resp = await _fetch_public_http(
            http_fetcher,
            cleaned_url,
            headers=req_headers,
            max_bytes=10_485_760,
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
            "offset": max(0, int(offset)),
            "total_chars": 0,
            "has_more": False,
            "next_offset": None,
            "structured_json_ld": [],
            "discovered_feeds": list(cached_doc.get("discovered_feeds") or []),
        }

    lower_headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    ctype = lower_headers.get("content-type", "").split(";", 1)[0].strip().lower()
    fname = _guess_filename_from_url_and_mime(resp.url, ctype)
    url_path = urllib.parse.urlparse(resp.url).path
    url_suffix = Path(url_path).suffix.lower()
    is_json_text = (
        ctype
        in {
            "application/json",
            "text/json",
            "application/x-ndjson",
            "application/ndjson",
            "application/jsonl",
        }
        or ctype.endswith("+json")
        or (
            ctype not in {"text/html", "application/xhtml+xml"}
            and not ctype.endswith("+xml")
            and url_suffix in {".json", ".ndjson", ".jsonl"}
        )
    )
    is_direct_doc = (
        (not is_json_text)
        and ctype != "text/html"
        and ctype != "application/xhtml+xml"
        and is_analytics_or_document_file(fname, ctype)
    )
    is_plain_text = (not is_direct_doc) and (
        is_json_text
        or ctype in _PLAIN_TEXT_CONTENT_TYPES
        or (
            ctype not in {"text/html", "application/xhtml+xml"}
            and not ctype.endswith("+xml")
            and url_suffix in _PLAIN_TEXT_EXTS
        )
    )

    structured_json_ld: list[Any] = []
    discovered_feeds: list[str] = []
    title = ""
    full_markdown = ""
    secret_vals = repo.collect_all_vault_secret_values() if repo is not None else []

    if is_direct_doc:
        raw_bytes = getattr(resp, "raw_bytes", b"") or resp.body.encode("utf-8", errors="replace")
        try:
            parsed_doc = extract_document_summary_from_bytes(
                raw_bytes,
                filename=fname,
                mime_type=ctype,
                vault_secrets=secret_vals,
                max_chars=120_000,
            )
            title = fname
            full_markdown = str(parsed_doc.get("excerpt") or "")
        except Exception as exc:
            if (
                ctype in {"text/csv", "text/tab-separated-values", "application/csv"}
                or Path(fname).suffix.lower() in {".csv", ".tsv"}
            ):
                title = Path(url_path).name or fname or resp.url
                full_markdown = redact_secrets(resp.body, secret_vals) if secret_vals else resp.body
            else:
                raise PublicFetchError(
                    url=resp.url,
                    status_code=resp.status_code,
                    message=f"Unable to parse document '{fname}' ({ctype or 'unknown'}): {exc}",
                ) from exc
    elif is_plain_text:
        title = Path(url_path).name or fname or resp.url
        full_markdown = redact_secrets(resp.body, secret_vals) if secret_vals else resp.body
    else:
        structured_json_ld = _extract_json_ld(resp.body)
        title = _extract_title_fast(resp.body)
        try:
            import trafilatura  # type: ignore[import-not-found]

            extracted = trafilatura.extract(
                resp.body,
                url=resp.url,
                output_format="markdown",
                include_links=True,
                include_tables=True,
            )
            if isinstance(extracted, str) and extracted.strip():
                full_markdown = extracted.strip()
        except ImportError:
            pass
        except Exception:
            full_markdown = ""

        if not full_markdown:
            parser = _MarkdownHTMLParser(resp.url)
            parser.feed(resp.body)
            parser.close()
            parsed_title, parsed_md = parser.result()
            title = parsed_title or title
            full_markdown = parsed_md

        discovered_feeds = discover_feed_urls(resp.body, resp.url)

    capped_chars = max(200, min(int(max_chars), 48_000))
    clean_offset = max(0, int(offset))
    total_chars = len(full_markdown)
    clipped = full_markdown[clean_offset : clean_offset + capped_chars]
    has_more = (clean_offset + len(clipped)) < total_chars
    next_offset = (clean_offset + len(clipped)) if has_more else None

    content_hash = hashlib.sha256(full_markdown[:48_000].encode("utf-8")).hexdigest()[:24]
    unchanged = bool(
        cached_doc.get("content_hash") and cached_doc.get("content_hash") == content_hash
    )
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
        "offset": clean_offset,
        "total_chars": total_chars,
        "has_more": has_more,
        "next_offset": next_offset,
        "structured_json_ld": structured_json_ld,
        "discovered_feeds": discovered_feeds,
    }


def _css_part_to_xpath(part: str) -> str:
    """Convert a simple CSS selector segment (tag#id.cls1.cls2[attr=val]) to XPath."""
    rem = part.strip()
    tag = "*"
    tag_m = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*)", rem)
    if tag_m:
        tag = tag_m.group(1).lower()
        rem = rem[tag_m.end() :]
    predicates: list[str] = []
    for id_m in re.finditer(r"#([A-Za-z0-9_-]+)", rem):
        predicates.append(f"@id={repr(id_m.group(1))}")
    for cls_m in re.finditer(r"\.([A-Za-z0-9_-]+)", rem):
        cls = cls_m.group(1)
        predicates.append(f"contains(concat(' ', normalize-space(@class), ' '), {repr(' ' + cls + ' ')})")
    for attr_m in re.finditer(r"\[([A-Za-z0-9_:-]+)(?:=['\"]?([^'\"\]]+)['\"]?)?\]", rem):
        attr_name = attr_m.group(1)
        attr_val = attr_m.group(2)
        if attr_val is not None:
            predicates.append(f"@{attr_name}={repr(attr_val)}")
        else:
            predicates.append(f"@{attr_name}")
    if predicates:
        return f"{tag}[{' and '.join(predicates)}]"
    return tag


def _css_or_xpath_query(doc: Any, selector: str) -> list[Any]:
    sel = selector.strip()
    if not sel:
        return []
    if sel.startswith(("/", "(")):
        return list(doc.xpath(sel))
    results: list[Any] = []
    for branch in sel.split(","):
        branch_clean = branch.strip()
        if not branch_clean:
            continue
        parts = [p for p in re.split(r"\s+", branch_clean) if p]
        xpath_expr = "//" + "//".join(_css_part_to_xpath(p) for p in parts)
        try:
            for el in doc.xpath(xpath_expr):
                if el not in results:
                    results.append(el)
        except Exception:
            continue
    return results


def _extract_html_tables(doc: Any) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    for tbl in doc.xpath("//table"):
        if tbl.xpath(".//table"):
            # Skip outer layout wrapper tables containing nested data tables
            continue
        tr_nodes = tbl.xpath(".//tr")
        if len(tr_nodes) < 2:
            continue
        header_cells: list[str] = []
        data_matrix: list[list[str]] = []
        thead_rows = tbl.xpath("./thead/tr")
        if thead_rows:
            header_cells = [
                re.sub(r"\s+", " ", "".join(cell.itertext())).strip()
                for cell in thead_rows[0].xpath("./th|./td")
            ]
        for tr in tr_nodes:
            if thead_rows and tr is thead_rows[0]:
                continue
            cells = [
                re.sub(r"\s+", " ", "".join(cell.itertext())).strip()
                for cell in tr.xpath("./th|./td")
            ]
            if not any(cells):
                continue
            if not header_cells:
                header_cells = cells
            else:
                data_matrix.append(cells)
        if len(data_matrix) < 2 or not header_cells:
            continue
        col_count = max(len(header_cells), max(len(r) for r in data_matrix))
        if col_count < 1:
            continue
        cols = _deduplicate_headers(header_cells, col_count)
        rows = [
            {cols[idx]: (row[idx] if idx < len(row) else "") for idx in range(col_count)}
            for row in data_matrix
        ]
        tables.append({"columns": cols, "rows": rows})
    return tables


def _flatten_json_ld_items(items: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def _visit(node: Any) -> None:
        if isinstance(node, list):
            for el in node:
                _visit(el)
            return
        if not isinstance(node, dict):
            return
        if "@graph" in node and isinstance(node["@graph"], list):
            for el in node["@graph"]:
                _visit(el)
            return
        if "itemListElement" in node and isinstance(node["itemListElement"], list):
            for el in node["itemListElement"]:
                if isinstance(el, dict) and isinstance(el.get("item"), dict):
                    _visit(el["item"])
                else:
                    _visit(el)
            return
        row: dict[str, Any] = {}
        for k, v in node.items():
            clean_k = str(k).lstrip("@")
            if k == "@context":
                continue
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    if not isinstance(sub_v, (dict, list)):
                        row[f"{clean_k}_{str(sub_k).lstrip('@')}"] = _normalize_cell_value(sub_v)
            elif isinstance(v, list):
                if v and all(not isinstance(x, (dict, list)) for x in v):
                    row[clean_k] = ", ".join(str(x) for x in v)
                elif v and isinstance(v[0], dict):
                    for sub_k, sub_v in v[0].items():
                        if not isinstance(sub_v, (dict, list)):
                            row[f"{clean_k}_{str(sub_k).lstrip('@')}"] = _normalize_cell_value(sub_v)
            else:
                row[clean_k] = _normalize_cell_value(v)
        if row:
            rows.append(row)

    for item in items:
        _visit(item)
    return rows


async def extract_web_data(
    url: str,
    *,
    selector: str | None = None,
    target_collection: str | None = None,
    save_as_file: bool = False,
    repo: ArgoRepository | None = None,
    bus: EventBus | None = None,
    fetcher: PublicHttpFetcher | None = None,
    bot_slug: str | None = None,
    owner_email: str | None = None,
    correlation_id: str | None = None,
    source_slug: str = "builtin:web_extract",
) -> dict[str, Any]:
    """Deterministically extract structured tables, JSON-LD, files, or CSS selectors to 0o444 Parquet at 0 LLM tokens."""
    cleaned_url = url.strip()
    http_fetcher = fetcher or SafePublicHttpFetcher()
    try:
        resp = await _fetch_public_http(
            http_fetcher,
            cleaned_url,
            headers={
                "Accept": "text/html, application/xhtml+xml, text/csv, application/json, application/pdf, */*;q=0.8"
            },
            max_bytes=10_485_760,
        )
    except AntiBotHaltError as exc:
        await _publish_antibot_halt(
            bus,
            correlation_id=correlation_id,
            source_slug=source_slug,
            exc=exc,
        )
        raise

    lower_headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    ctype = lower_headers.get("content-type", "").split(";", 1)[0].strip().lower()
    fname = _guess_filename_from_url_and_mime(resp.url, ctype)
    is_direct_doc = (
        ctype != "text/html"
        and ctype != "application/xhtml+xml"
        and is_analytics_or_document_file(fname, ctype)
    )
    secret_vals = repo.collect_all_vault_secret_values() if repo is not None else []

    def _process_extracted_sync() -> dict[str, Any]:
        extracted_rows: list[dict[str, Any]] = []
        extracted_cols: list[str] = []
        tables_found = 0
        extraction_kind = "none"

        if is_direct_doc:
            raw_bytes = getattr(resp, "raw_bytes", b"") or resp.body.encode("utf-8", errors="replace")
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_p = Path(tmpdir)
                src_f = tmp_p / fname
                src_f.write_bytes(raw_bytes)
                der_dir = tmp_p / "derived"
                ingested = ingest_file_to_analytics(
                    src_f,
                    der_dir,
                    file_id="file_web",
                    filename=fname,
                    mime_type=ctype,
                    vault_secrets=secret_vals,
                )
                def_name = ingested.get("default_parquet_name")
                if def_name and (der_dir / def_name).is_file():
                    extracted_cols, extracted_rows, _ = read_dataset_rows(
                        der_dir / def_name,
                        limit=100_000,
                        secret_values=secret_vals,
                    )
            tables_found = max(1, len(ingested.get("derived_datasets") or [])) if extracted_rows else 0
            extraction_kind = "direct_file"
        else:
            html_body = resp.body or ""
            try:
                doc = lxml_html.fromstring(html_body)
                if resp.url.startswith(("http://", "https://")):
                    try:
                        doc.make_links_absolute(resp.url)
                    except Exception:
                        pass
            except Exception:
                doc = None

            if selector and selector.strip() and doc is not None:
                matched_nodes = _css_or_xpath_query(doc, selector.strip())
                for node in matched_nodes[:5000]:
                    text_val = re.sub(r"\s+", " ", "".join(node.itertext())).strip()
                    if not text_val:
                        continue
                    href = node.attrib.get("href") or ""
                    if not href:
                        a_nodes = node.xpath(".//a[@href]")
                        if a_nodes:
                            href = str(a_nodes[0].attrib.get("href") or "")
                    title_nodes = node.xpath(".//h1|.//h2|.//h3|.//h4|.//a[1]")
                    title_val = (
                        re.sub(r"\s+", " ", "".join(title_nodes[0].itertext())).strip()
                        if title_nodes
                        else text_val[:120]
                    )
                    price_m = _PRICE_RE.search(text_val)
                    extracted_rows.append(
                        {
                            "title": title_val[:240],
                            "text": text_val[:1000],
                            "href": href,
                            "price": price_m.group(0) if price_m else "",
                        }
                    )
                if extracted_rows:
                    extracted_cols = ["title", "text", "href", "price"]
                    tables_found = 1
                    extraction_kind = "selector"

            if not extracted_rows and doc is not None:
                html_tables = _extract_html_tables(doc)
                if html_tables:
                    tables_found = len(html_tables)
                    best = max(html_tables, key=lambda t: len(t["rows"]))
                    extracted_cols = best["columns"]
                    extracted_rows = best["rows"]
                    extraction_kind = "html_table"

            if not extracted_rows:
                json_ld_items = _extract_json_ld(html_body)
                ld_rows = _flatten_json_ld_items(json_ld_items)
                if ld_rows:
                    extracted_rows = ld_rows
                    tables_found = 1
                    extraction_kind = "json_ld"

        if not extracted_rows:
            return {
                "status": "empty",
                "url": resp.url,
                "dataset_id": None,
                "row_count": 0,
                "tables_found": 0,
                "columns": [],
                "profile": None,
                "sample_rows": [],
                "detail": "No structured HTML tables, JSON-LD items, or matching selector data found.",
            }

        # Scrub secrets across all extracted cells before materializing Parquet
        scrubbed_rows = [
            {str(k): _json_safe(v, secret_vals) for k, v in row.items()}
            for row in extracted_rows
        ]

        parsed_url = urllib.parse.urlsplit(resp.url)
        url_slug = slugify(f"{parsed_url.netloc}_{parsed_url.path}".strip("_"))[:36] or "web"

        if repo is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_parquet = Path(tmpdir) / "main.parquet"
                row_count, cols = write_rows_to_parquet(
                    scrubbed_rows, tmp_parquet, columns=extracted_cols or None
                )
                prof = profile_datasets(
                    [{"id": f"web_{url_slug}", "parquet_path": str(tmp_parquet)}],
                    secret_values=secret_vals,
                )[0]
            return {
                "status": "ok",
                "url": resp.url,
                "extraction_kind": extraction_kind,
                "dataset_id": f"web_{url_slug}",
                "row_count": row_count,
                "tables_found": tables_found,
                "columns": cols,
                "profile": prof,
                "sample_rows": prof.get("sample_rows") or [],
            }

        if save_as_file and owner_email:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_parquet = Path(tmpdir) / f"{url_slug}.parquet"
                row_count, cols = write_rows_to_parquet(
                    scrubbed_rows, tmp_parquet, columns=extracted_cols or None
                )
                saved_file = repo.save_workspace_file(
                    owner_email=owner_email,
                    filename=f"{url_slug}.parquet",
                    mime_type="application/parquet",
                    content_bytes=tmp_parquet.read_bytes(),
                    uploaded_by=bot_slug or "bot",
                )
            dataset_id = f"file:{saved_file['id']}"
            specs = repo.resolve_authorized_datasets([dataset_id], owner_email=owner_email)
            prof = profile_datasets(specs, secret_values=secret_vals)[0]
            return {
                "status": "ok",
                "url": resp.url,
                "extraction_kind": extraction_kind,
                "dataset_id": dataset_id,
                "file_id": saved_file["id"],
                "row_count": row_count,
                "tables_found": tables_found,
                "columns": cols,
                "profile": prof,
                "sample_rows": prof.get("sample_rows") or [],
            }

        default_col = (
            target_collection
            or (f"bot_{slugify(bot_slug)}_web_{url_slug}" if bot_slug else f"web_{url_slug}")
        )
        clean_col = collection_slug(default_col)
        analytics_dir = repo.analytics_dir_for_collection(clean_col)
        parquet_path = analytics_dir / "main.parquet"
        row_count, cols = write_rows_to_parquet(
            scrubbed_rows, parquet_path, columns=extracted_cols or None
        )
        repo.register_analytics_collection(
            clean_col,
            parquet_path=parquet_path,
            row_count=row_count,
            columns=cols,
            source_url=resp.url,
            description=f"Web extracted dataset from {resp.url}",
        )
        prof = profile_datasets(
            [{"id": clean_col, "parquet_path": str(parquet_path)}],
            secret_values=secret_vals,
        )[0]
        return {
            "status": "ok",
            "url": resp.url,
            "extraction_kind": extraction_kind,
            "dataset_id": clean_col,
            "row_count": row_count,
            "tables_found": tables_found,
            "columns": cols,
            "profile": prof,
            "sample_rows": prof.get("sample_rows") or [],
        }

    return await asyncio.to_thread(_process_extracted_sync)
