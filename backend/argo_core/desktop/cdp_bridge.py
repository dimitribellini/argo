"""chrome-devtools-mcp v1.13+ & internal CDP :9222 browser bridge."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from argo_core.db.repositories import make_id
from argo_core.desktop.manager import (
    CDP_PORT,
    SELKIES_HTTP_PORT,
    DesktopManager,
    DesktopRuntimeError,
    validate_desktop_slug,
)
from argo_core.security.ssrf import PublicFetchError, validate_public_url

if TYPE_CHECKING:
    from argo_core.bus.valkey_bus import EventBus
    from argo_core.connectors.telegram_bot import TelegramBotService

_CAPTCHA_MARKERS = (
    "g-recaptcha",
    "h-captcha",
    "cf-turnstile",
    "verify you are human",
    "attention required! | cloudflare",
    "just a moment...",
    "altcha",
)

_MFA_MARKERS = (
    "two-factor authentication",
    "enter verification code",
    "2fa_required",
    "authenticator code",
)


@dataclass(frozen=True, slots=True)
class CDPPageSnapshot:
    """DOM snapshot returned by Chromium CDP :9222 inside an isolated desktop container."""

    url: str
    status_code: int
    title: str
    text: str
    html: str = ""
    scroll_y: int = 0
    scroll_height: int = 0
    viewport_height: int = 0
    interactive_elements: list[dict[str, Any]] = field(default_factory=list)
    target_id: str = ""
    matched_element: dict[str, Any] | None = None
    tabs: list[dict[str, Any]] = field(default_factory=list)


CDPTransport = Callable[[str, str, str, str | None], Awaitable[CDPPageSnapshot]]
CDPActionTransport = Callable[[str, str, str, dict[str, Any]], Awaitable[CDPPageSnapshot]]

SUPPORTED_BROWSER_ACTIONS: frozenset[str] = frozenset(
    {
        "snapshot",
        "read",
        "click",
        "fill",
        "type",
        "select",
        "scroll",
        "key",
        "wait",
        "back",
        "forward",
        "tabs",
        "switch_tab",
    }
)

_INTERACTIVE_SELECTOR = (
    'button, a[href], input:not([type="hidden"]), textarea, select, '
    '[role="button"], [role="link"], [role="tab"], [role="option"], '
    '[role="combobox"], [role="textbox"], [role="checkbox"], [role="radio"], '
    '[contenteditable="true"]'
)

_CDP_KEY_MAP: dict[str, tuple[str, str, int, str]] = {
    "enter": ("Enter", "Enter", 13, "\r"),
    "return": ("Enter", "Enter", 13, "\r"),
    "tab": ("Tab", "Tab", 9, ""),
    "escape": ("Escape", "Escape", 27, ""),
    "esc": ("Escape", "Escape", 27, ""),
    "backspace": ("Backspace", "Backspace", 8, ""),
    "delete": ("Delete", "Delete", 46, ""),
    "del": ("Delete", "Delete", 46, ""),
    "arrowdown": ("ArrowDown", "ArrowDown", 40, ""),
    "down": ("ArrowDown", "ArrowDown", 40, ""),
    "arrowup": ("ArrowUp", "ArrowUp", 38, ""),
    "up": ("ArrowUp", "ArrowUp", 38, ""),
    "arrowleft": ("ArrowLeft", "ArrowLeft", 37, ""),
    "left": ("ArrowLeft", "ArrowLeft", 37, ""),
    "arrowright": ("ArrowRight", "ArrowRight", 39, ""),
    "right": ("ArrowRight", "ArrowRight", 39, ""),
    "pagedown": ("PageDown", "PageDown", 34, ""),
    "pageup": ("PageUp", "PageUp", 33, ""),
    "home": ("Home", "Home", 36, ""),
    "end": ("End", "End", 35, ""),
    "space": (" ", "Space", 32, " "),
}


class DesktopTakeoverRequiredError(RuntimeError):
    """Raised cleanly when a portal presents a CAPTCHA, WAF, or 2FA gate requiring manual Selkies takeover."""

    def __init__(
        self,
        message: str,
        *,
        bot_slug: str,
        url: str,
        gate_type: str,
        reason: str,
    ) -> None:
        super().__init__(message)
        self.bot_slug = bot_slug
        self.url = url
        self.gate_type = gate_type
        self.reason = reason


def _detect_gate(snapshot: CDPPageSnapshot) -> tuple[str, str] | None:
    if snapshot.status_code in {403, 429}:
        return (
            "http_403_429",
            f"HTTP {snapshot.status_code} anti-bot/rate-limit gate",
        )
    haystack = f"{snapshot.title}\n{snapshot.html}\n{snapshot.text}".lower()
    if any(marker in haystack for marker in _CAPTCHA_MARKERS):
        return (
            "captcha_gate",
            "CAPTCHA / anti-bot verification gate detected",
        )
    if any(marker in haystack for marker in _MFA_MARKERS):
        return (
            "mfa_login_gate",
            "Interactive 2FA/session authentication required",
        )
    return None


async def _ensure_cdp_ready(
    session: Any,
    cdp_endpoint: str,
    *,
    ep_host: str,
    ep_port: int,
    host_headers: dict[str, str],
    agent_token: str = "",
    progress_cb: Callable[[str], Awaitable[None]] | None = None,
) -> None:
    import aiohttp  # type: ignore[import-not-found]

    agent_status_url = f"http://{ep_host}:9223/status"
    agent_headers = {"X-Argo-Desktop-Token": agent_token} if agent_token else None
    last_err: str | None = None
    ready = False
    start_ts = time.monotonic()
    max_wait = 35.0
    last_progress_at = -10.0
    launched_on_demand = False

    while True:
        try:
            async with session.get(
                f"{cdp_endpoint}/json/version",
                headers=host_headers,
                timeout=aiohttp.ClientTimeout(total=3),
            ) as ver_resp:
                if ver_resp.status < 400:
                    ready = True
                    break
                last_err = f"HTTP {ver_resp.status}"
        except Exception as exc:
            last_err = str(exc)

        prov_detail = ""
        prov_state = ""
        with contextlib.suppress(Exception):
            async with session.get(
                agent_status_url,
                headers=agent_headers,
                timeout=aiohttp.ClientTimeout(total=2),
            ) as st_resp:
                if st_resp.status == 200:
                    st_data = await st_resp.json(content_type=None)
                    prov = st_data.get("provision") or {}
                    prov_state = str(prov.get("state") or "")
                    prov_detail = str(prov.get("detail") or "")
                    if prov_state in {"installing_packages", "starting_browser", "waiting_x11"}:
                        max_wait = 95.0

        if not launched_on_demand and prov_state != "installing_packages":
            with contextlib.suppress(Exception):
                async with session.post(
                    f"http://{ep_host}:9223/action",
                    json={"action": "launch", "app": "chromium"},
                    headers=agent_headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as launch_resp:
                    if launch_resp.status < 500:
                        launched_on_demand = True

        elapsed = time.monotonic() - start_ts
        if elapsed >= max_wait:
            break

        if progress_cb is not None and (elapsed - last_progress_at) >= 3.0:
            last_progress_at = elapsed
            elapsed_i = int(elapsed)
            if prov_detail:
                await progress_cb(f"{prov_detail} ({elapsed_i}s)")
            else:
                await progress_cb(
                    f"Waiting for Chromium browser inside Virtual Desktop ({elapsed_i}s)..."
                )

        await asyncio.sleep(1.0)

    if not ready:
        raise DesktopRuntimeError(
            f"Chromium CDP :{ep_port} did not become ready at {cdp_endpoint}: {last_err or 'timeout'}"
        )


async def _list_cdp_page_targets(
    session: Any,
    cdp_endpoint: str,
    *,
    host_headers: dict[str, str],
) -> list[dict[str, Any]]:
    import aiohttp  # type: ignore[import-not-found]

    pages: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        async with session.get(
            f"{cdp_endpoint}/json/list",
            headers=host_headers,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as list_resp:
            if list_resp.status < 400:
                targets = await list_resp.json()
                for cand in targets or []:
                    if (
                        isinstance(cand, dict)
                        and cand.get("type") == "page"
                        and cand.get("webSocketDebuggerUrl")
                    ):
                        pages.append(cand)
    return pages


def _select_cdp_target(
    targets: list[dict[str, Any]],
    *,
    preferred_target_id: str | None = None,
    prefer_http: bool = False,
) -> dict[str, Any]:
    if not targets:
        return {}
    if preferred_target_id:
        for cand in targets:
            if str(cand.get("id") or "") == preferred_target_id:
                return cand
    filtered = [
        cand
        for cand in targets
        if not str(cand.get("url") or "").startswith(("devtools://", "chrome-extension://"))
    ]
    pool = filtered or targets
    if prefer_http:
        for cand in pool:
            if str(cand.get("url") or "").startswith(("http://", "https://")):
                return cand
    for cand in pool:
        if not str(cand.get("url") or "").startswith("chrome://"):
            return cand
    return pool[0]


def _resolve_ws_url(
    target: dict[str, Any],
    *,
    cdp_endpoint: str,
    ep_host: str,
    ep_port: int,
) -> tuple[str, str]:
    target_id = str(target.get("id") or "")
    raw_ws = str(target.get("webSocketDebuggerUrl") or "")
    if not raw_ws:
        raise DesktopRuntimeError(f"CDP WebSocket debugger URL missing for endpoint {cdp_endpoint}")
    ws_parsed = urllib.parse.urlparse(raw_ws)
    ws_path = ws_parsed.path or (f"/devtools/page/{target_id}" if target_id else "")
    ws_query = f"?{ws_parsed.query}" if ws_parsed.query else ""
    return target_id, f"ws://{ep_host}:{ep_port}{ws_path}{ws_query}"


async def _cdp_send_and_wait(
    ws: Any,
    cmd_id: int,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 10.0,
) -> tuple[dict[str, Any], int | None]:
    import aiohttp  # type: ignore[import-not-found]

    payload: dict[str, Any] = {"id": cmd_id, "method": method}
    if params is not None:
        payload["params"] = params
    await ws.send_json(payload)

    doc_status: int | None = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            msg = await ws.receive(timeout=remaining)
        except asyncio.TimeoutError:
            break
        if msg.type != aiohttp.WSMsgType.TEXT:
            if msg.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                break
            continue
        frame = msg.json()
        if frame.get("id") == cmd_id:
            return frame, doc_status
        ev_method = frame.get("method")
        ev_params = frame.get("params") or {}
        if ev_method == "Network.responseReceived" and ev_params.get("type") == "Document":
            resp_obj = ev_params.get("response") or {}
            if resp_obj.get("status"):
                doc_status = int(resp_obj["status"])
    return {}, doc_status


async def _cdp_eval_json(
    ws: Any,
    cmd_id: int,
    expression: str,
    *,
    timeout: float = 10.0,
) -> tuple[dict[str, Any], int | None]:
    frame, doc_status = await _cdp_send_and_wait(
        ws,
        cmd_id,
        "Runtime.evaluate",
        {"expression": expression, "returnByValue": True},
        timeout=timeout,
    )
    raw_val = frame.get("result", {}).get("result", {}).get("value")
    if isinstance(raw_val, str) and raw_val.strip():
        with contextlib.suppress(Exception):
            parsed = json.loads(raw_val)
            if isinstance(parsed, dict):
                return parsed, doc_status
    elif isinstance(raw_val, dict):
        return raw_val, doc_status
    return {}, doc_status


async def _wait_for_navigation_or_settle(
    ws: Any,
    *,
    settle_seconds: float = 0.8,
    load_timeout: float = 10.0,
) -> int | None:
    import aiohttp  # type: ignore[import-not-found]

    doc_status: int | None = None
    nav_started = False
    deadline = time.monotonic() + max(0.1, settle_seconds)
    while time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            msg = await ws.receive(timeout=remaining)
        except asyncio.TimeoutError:
            break
        if msg.type != aiohttp.WSMsgType.TEXT:
            if msg.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                break
            continue
        frame = msg.json()
        method = frame.get("method")
        params = frame.get("params") or {}
        if method == "Network.responseReceived" and params.get("type") == "Document":
            resp_obj = params.get("response") or {}
            if resp_obj.get("status"):
                doc_status = int(resp_obj["status"])
        elif method in {"Page.frameStartedLoading", "Page.frameNavigated"} and not nav_started:
            nav_started = True
            deadline = max(deadline, time.monotonic() + load_timeout)
        elif method in {"Page.loadEventFired", "Page.frameStoppedLoading"} and nav_started:
            await asyncio.sleep(0.4)
            break
    return doc_status


def _build_extract_js(selector: str | None = None, max_elements: int = 45) -> str:
    return (
        "(function(){"
        f"const sel = {json.dumps(selector)};"
        f"const maxEl = {int(max_elements)};"
        f"const qSel = {json.dumps(_INTERACTIVE_SELECTOR)};"
        "document.querySelectorAll('[data-argo-el]').forEach(n => n.removeAttribute('data-argo-el'));"
        "document.querySelectorAll('[data-argo-target]').forEach(n => n.removeAttribute('data-argo-target'));"
        "let node = document.body;"
        "if (sel) { try { node = document.querySelector(sel) || document.body; } catch (e) { node = document.body; } }"
        "const vw = window.innerWidth || (document.documentElement ? document.documentElement.clientWidth : 1280) || 1280;"
        "const vh = window.innerHeight || (document.documentElement ? document.documentElement.clientHeight : 800) || 800;"
        "const scrollY = Math.round(window.scrollY || (document.documentElement ? document.documentElement.scrollTop : 0) || 0);"
        "const scrollH = Math.round(Math.max(document.documentElement ? document.documentElement.scrollHeight : 0, document.body ? document.body.scrollHeight : 0));"
        "const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();"
        "const isVisible = (el) => {"
        "  if (!el || el.disabled) return false;"
        "  if (el.getAttribute('aria-disabled') === 'true') return false;"
        "  if (el.getAttribute('aria-hidden') === 'true') return false;"
        "  const st = window.getComputedStyle(el);"
        "  if (!st || st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity || '1') === 0) return false;"
        "  const r = el.getBoundingClientRect();"
        "  return !!r && r.width >= 2 && r.height >= 2;"
        "};"
        "const raw = Array.from(document.querySelectorAll(qSel));"
        "const elements = [];"
        "for (const el of raw) {"
        "  if (elements.length >= maxEl) break;"
        "  if (!isVisible(el)) continue;"
        "  const r = el.getBoundingClientRect();"
        "  const idx = elements.length + 1;"
        "  el.setAttribute('data-argo-el', String(idx));"
        "  const tag = (el.tagName || '').toLowerCase();"
        "  const role = norm(el.getAttribute('role'));"
        "  const inputType = norm(el.getAttribute('type'));"
        "  let txt = '';"
        "  if (tag === 'input' && ['submit', 'button', 'reset'].includes(inputType.toLowerCase())) {"
        "    txt = norm(el.value);"
        "  } else {"
        "    txt = norm(el.innerText || el.textContent);"
        "  }"
        "  const ariaLabel = norm(el.getAttribute('aria-label') || el.getAttribute('title'));"
        "  const placeholder = norm(el.getAttribute('placeholder'));"
        "  const nameAttr = norm(el.getAttribute('name'));"
        "  let val = '';"
        "  if ((tag === 'input' || tag === 'textarea' || tag === 'select') && inputType.toLowerCase() !== 'password' && !['submit', 'button', 'reset'].includes(inputType.toLowerCase())) {"
        "    val = norm(String(el.value || ''));"
        "  }"
        "  const cx = Math.round(r.left + r.width / 2);"
        "  const cy = Math.round(r.top + r.height / 2);"
        "  const inVp = r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw;"
        "  const elId = norm(el.getAttribute('id'));"
        "  let bestSel = '[data-argo-el=\"' + idx + '\"]';"
        "  if (elId && /^[a-zA-Z_-][a-zA-Z0-9_-]*$/.test(elId)) {"
        "    try { if (document.querySelectorAll('#' + CSS.escape(elId)).length === 1) bestSel = '#' + elId; } catch (e) {}"
        "  }"
        "  const item = {index: idx, tag: tag, selector: bestSel, in_viewport: inVp, x: cx, y: cy};"
        "  if (role) item.role = role;"
        "  if (inputType && tag === 'input') item.type = inputType;"
        "  if (txt) item.text = txt.slice(0, 80);"
        "  if (ariaLabel && ariaLabel !== txt) item.aria_label = ariaLabel.slice(0, 80);"
        "  if (placeholder) item.placeholder = placeholder.slice(0, 60);"
        "  if (nameAttr) item.name = nameAttr.slice(0, 40);"
        "  if (val) item.value = val.slice(0, 60);"
        "  elements.push(item);"
        "}"
        "return JSON.stringify({"
        "  url: location.href,"
        "  title: document.title || '',"
        "  text: node ? (node.innerText || '') : '',"
        "  html: document.documentElement ? document.documentElement.outerHTML.slice(0, 60000) : '',"
        "  scroll_y: scrollY,"
        "  scroll_height: scrollH,"
        "  viewport_height: Math.round(vh),"
        "  interactive_elements: elements"
        "});"
        "})()"
    )


def _build_locate_element_js(params: dict[str, Any], *, allow_active_fallback: bool = False) -> str:
    raw_index = params.get("index")
    index_val: int | None = None
    if raw_index is not None and str(raw_index).strip() != "":
        with contextlib.suppress(ValueError, TypeError):
            index_val = int(raw_index)
    raw_selector = str(params.get("selector") or "").strip()
    raw_query = str(
        params.get("text")
        or params.get("label")
        or params.get("placeholder")
        or params.get("name")
        or ""
    ).strip()
    nth = 0
    with contextlib.suppress(ValueError, TypeError):
        nth = max(0, int(params.get("nth") or 0))

    return (
        "(function(){"
        f"const idxVal = {json.dumps(index_val)};"
        f"const sel = {json.dumps(raw_selector)};"
        f"const query = {json.dumps(raw_query)}.toLowerCase().replace(/\\s+/g, ' ').trim();"
        f"const nth = {nth};"
        f"const allowActive = {json.dumps(allow_active_fallback)};"
        f"const qSel = {json.dumps(_INTERACTIVE_SELECTOR)};"
        "document.querySelectorAll('[data-argo-target]').forEach(n => n.removeAttribute('data-argo-target'));"
        "const norm = (s) => (s || '').toLowerCase().replace(/\\s+/g, ' ').trim();"
        "const isVis = (el) => {"
        "  if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;"
        "  const st = window.getComputedStyle(el);"
        "  if (!st || st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity || '1') === 0) return false;"
        "  const r = el.getBoundingClientRect();"
        "  return !!r && r.width >= 2 && r.height >= 2;"
        "};"
        "let target = null;"
        "if (idxVal !== null) {"
        "  target = document.querySelector('[data-argo-el=\"' + idxVal + '\"]');"
        "} else if (sel) {"
        "  try { target = document.querySelector(sel); } catch (e) { return JSON.stringify({found: false, error: 'Invalid CSS selector: ' + e.message}); }"
        "} else if (query) {"
        "  const cands = Array.from(document.querySelectorAll(qSel)).filter(isVis);"
        "  const scored = [];"
        "  for (const el of cands) {"
        "    const tag = (el.tagName || '').toLowerCase();"
        "    const iType = norm(el.getAttribute('type'));"
        "    const txt = norm(el.innerText || el.textContent);"
        "    const aria = norm(el.getAttribute('aria-label') || el.getAttribute('title'));"
        "    const ph = norm(el.getAttribute('placeholder'));"
        "    const nm = norm(el.getAttribute('name'));"
        "    const lbl = norm(Array.from(el.labels || []).map(l => l.innerText || l.textContent).join(' '));"
        "    const val = (tag === 'input' && ['submit','button','reset'].includes(iType)) ? norm(el.value) : '';"
        "    const fields = [txt, aria, ph, lbl, val, nm].filter(Boolean);"
        "    let score = 0;"
        "    for (const f of fields) {"
        "      if (f === query) score = Math.max(score, 3);"
        "      else if (f.includes(query)) score = Math.max(score, 1);"
        "    }"
        "    if (score > 0) {"
        "      const inModal = !!el.closest('dialog, [role=\"dialog\"], [aria-modal=\"true\"]');"
        "      scored.push({el: el, score: score + (inModal ? 10 : 0)});"
        "    }"
        "  }"
        "  scored.sort((a, b) => b.score - a.score);"
        "  if (nth < scored.length) target = scored[nth].el;"
        "} else if (allowActive && document.activeElement && document.activeElement !== document.body) {"
        "  target = document.activeElement;"
        "}"
        "if (!target) {"
        "  return JSON.stringify({found: false, error: 'No matching interactive element found'});"
        "}"
        "target.setAttribute('data-argo-target', '1');"
        "target.scrollIntoView({block: 'center', inline: 'center', behavior: 'instant'});"
        "const r = target.getBoundingClientRect();"
        "const vw = window.innerWidth || (document.documentElement ? document.documentElement.clientWidth : 1280) || 1280;"
        "const vh = window.innerHeight || (document.documentElement ? document.documentElement.clientHeight : 800) || 800;"
        "const cx = Math.round(r.left + r.width / 2);"
        "const cy = Math.round(r.top + r.height / 2);"
        "const inVp = r.width > 0 && r.height > 0 && cx >= 0 && cy >= 0 && cx < vw && cy < vh;"
        "const tag = (target.tagName || '').toLowerCase();"
        "return JSON.stringify({"
        "  found: true,"
        "  tag: tag,"
        "  text: (target.innerText || target.value || '').replace(/\\s+/g, ' ').trim().slice(0, 80),"
        "  aria_label: (target.getAttribute('aria-label') || '').trim().slice(0, 80),"
        "  x: cx,"
        "  y: cy,"
        "  in_viewport: inVp,"
        "  is_select: tag === 'select'"
        "});"
        "})()"
    )


async def _default_cdp_transport(
    bot_slug: str,
    cdp_endpoint: str,
    url: str,
    selector: str | None,
    *,
    preferred_target_id: str | None = None,
    agent_token: str = "",
    progress_cb: Callable[[str], Awaitable[None]] | None = None,
) -> CDPPageSnapshot:
    """Drive Chromium inside argo-desktop-<bot_slug> via internal CDP :9222 without anti-bot bypass."""
    del bot_slug
    import aiohttp  # type: ignore[import-not-found]

    parsed_ep = urllib.parse.urlparse(cdp_endpoint)
    ep_host = parsed_ep.hostname or "127.0.0.1"
    ep_port = parsed_ep.port or CDP_PORT
    host_headers = {"Host": f"127.0.0.1:{ep_port}"}
    if agent_token:
        host_headers["X-Argo-Desktop-Token"] = agent_token
    ws_headers = {"X-Argo-Desktop-Token": agent_token} if agent_token else None

    async with aiohttp.ClientSession() as session:
        await _ensure_cdp_ready(
            session,
            cdp_endpoint,
            ep_host=ep_host,
            ep_port=ep_port,
            host_headers=host_headers,
            agent_token=agent_token,
            progress_cb=progress_cb,
        )

        if progress_cb is not None:
            await progress_cb(f"Opening {url} in Virtual Desktop Chromium...")

        targets = await _list_cdp_page_targets(
            session, cdp_endpoint, host_headers=host_headers
        )
        target = _select_cdp_target(
            targets,
            preferred_target_id=preferred_target_id,
            prefer_http=True,
        )

        if not target:
            open_target_url = f"{cdp_endpoint}/json/new?about:blank"
            async with session.put(
                open_target_url,
                headers=host_headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status < 400:
                    target = await resp.json()
                else:
                    fallback_targets = await _list_cdp_page_targets(
                        session, cdp_endpoint, host_headers=host_headers
                    )
                    target = fallback_targets[0] if fallback_targets else {}

        target_id, ws_url = _resolve_ws_url(
            target, cdp_endpoint=cdp_endpoint, ep_host=ep_host, ep_port=ep_port
        )
        expr = _build_extract_js(selector)

        doc_status = 200
        evaluated: dict[str, Any] = {}
        async with session.ws_connect(
            ws_url, headers=ws_headers, timeout=20, max_msg_size=0
        ) as ws:
            await _cdp_send_and_wait(ws, 1, "Page.enable", timeout=5.0)
            await _cdp_send_and_wait(ws, 2, "Network.enable", timeout=5.0)
            with contextlib.suppress(Exception):
                await _cdp_send_and_wait(ws, 3, "Page.bringToFront", timeout=3.0)
            await ws.send_json({"id": 4, "method": "Page.navigate", "params": {"url": url}})

            main_frame_id: str | None = None
            nav_deadline = time.monotonic() + 15.0
            while time.monotonic() < nav_deadline:
                remaining = max(0.1, nav_deadline - time.monotonic())
                try:
                    msg = await ws.receive(timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if msg.type != aiohttp.WSMsgType.TEXT:
                    if msg.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                        break
                    continue
                frame = msg.json()
                if frame.get("id") == 4:
                    res = frame.get("result") or {}
                    if isinstance(res, dict):
                        if res.get("frameId"):
                            main_frame_id = str(res["frameId"])
                        if res.get("errorText"):
                            break
                    continue
                method = frame.get("method")
                params = frame.get("params") or {}
                if method == "Network.responseReceived" and params.get("type") == "Document":
                    resp_obj = params.get("response") or {}
                    if resp_obj.get("status"):
                        doc_status = int(resp_obj["status"])
                elif method == "Page.loadEventFired":
                    break
                elif (
                    method == "Page.frameStoppedLoading"
                    and main_frame_id
                    and params.get("frameId") == main_frame_id
                ):
                    break

            await asyncio.sleep(0.5)
            evaluated, eval_status = await _cdp_eval_json(ws, 99, expr, timeout=10.0)
            if eval_status is not None:
                doc_status = eval_status

        return CDPPageSnapshot(
            url=str(evaluated.get("url") or url),
            status_code=doc_status,
            title=str(evaluated.get("title") or ""),
            text=str(evaluated.get("text") or ""),
            html=str(evaluated.get("html") or ""),
            scroll_y=int(evaluated.get("scroll_y") or 0),
            scroll_height=int(evaluated.get("scroll_height") or 0),
            viewport_height=int(evaluated.get("viewport_height") or 0),
            interactive_elements=list(evaluated.get("interactive_elements") or []),
            target_id=target_id,
        )


async def _default_cdp_action_transport(
    bot_slug: str,
    cdp_endpoint: str,
    action: str,
    params: dict[str, Any],
    *,
    preferred_target_id: str | None = None,
    agent_token: str = "",
    progress_cb: Callable[[str], Awaitable[None]] | None = None,
) -> CDPPageSnapshot:
    """Execute a generic browser DOM/input action inside argo-desktop-<bot_slug> via CDP :9222."""
    del bot_slug
    import aiohttp  # type: ignore[import-not-found]

    act = str(action or "snapshot").strip().lower()
    if act not in SUPPORTED_BROWSER_ACTIONS:
        raise DesktopRuntimeError(f"Unsupported browser action: {action}")

    parsed_ep = urllib.parse.urlparse(cdp_endpoint)
    ep_host = parsed_ep.hostname or "127.0.0.1"
    ep_port = parsed_ep.port or CDP_PORT
    host_headers = {"Host": f"127.0.0.1:{ep_port}"}
    if agent_token:
        host_headers["X-Argo-Desktop-Token"] = agent_token
    ws_headers = {"X-Argo-Desktop-Token": agent_token} if agent_token else None

    async with aiohttp.ClientSession() as session:
        await _ensure_cdp_ready(
            session,
            cdp_endpoint,
            ep_host=ep_host,
            ep_port=ep_port,
            host_headers=host_headers,
            agent_token=agent_token,
            progress_cb=progress_cb,
        )

        targets = await _list_cdp_page_targets(
            session, cdp_endpoint, host_headers=host_headers
        )
        if not targets:
            raise DesktopRuntimeError(
                "No open Chromium page tab found; call desktop_browse with a URL first."
            )

        tabs_list = [
            {
                "index": idx + 1,
                "target_id": str(t.get("id") or ""),
                "title": str(t.get("title") or ""),
                "url": str(t.get("url") or ""),
            }
            for idx, t in enumerate(targets)
        ]

        if act == "switch_tab":
            want_id = str(params.get("target_id") or "").strip()
            target: dict[str, Any] = {}
            if want_id:
                target = _select_cdp_target(targets, preferred_target_id=want_id)
            elif params.get("index") is not None:
                with contextlib.suppress(ValueError, TypeError):
                    idx_1 = int(params["index"]) - 1
                    if 0 <= idx_1 < len(targets):
                        target = targets[idx_1]
            if not target:
                raise DesktopRuntimeError("Requested browser tab target_id/index was not found.")
        else:
            target = _select_cdp_target(
                targets,
                preferred_target_id=preferred_target_id,
                prefer_http=True,
            )

        target_id, ws_url = _resolve_ws_url(
            target, cdp_endpoint=cdp_endpoint, ep_host=ep_host, ep_port=ep_port
        )
        cmd_seq = 0

        def next_id() -> int:
            nonlocal cmd_seq
            cmd_seq += 1
            return cmd_seq

        doc_status = 200
        matched_element: dict[str, Any] | None = None

        async with session.ws_connect(
            ws_url, headers=ws_headers, timeout=20, max_msg_size=0
        ) as ws:
            await _cdp_send_and_wait(ws, next_id(), "Page.enable", timeout=5.0)
            await _cdp_send_and_wait(ws, next_id(), "Network.enable", timeout=5.0)
            with contextlib.suppress(Exception):
                await _cdp_send_and_wait(ws, next_id(), "Page.bringToFront", timeout=3.0)

            wait_ms_raw = str(params.get("wait_ms") or "").strip().lower().removesuffix("ms").strip()
            wait_ms_num = 900
            if wait_ms_raw:
                with contextlib.suppress(ValueError, TypeError):
                    wait_ms_num = int(float(wait_ms_raw))
            wait_ms = max(200, min(8000, wait_ms_num))

            if act in {"snapshot", "read", "tabs", "switch_tab"}:
                if act == "switch_tab":
                    await asyncio.sleep(0.25)

            elif act == "wait":
                wait_raw = str(params.get("seconds") or "").strip().lower().removesuffix("s").strip()
                wait_sec_num = 2.0
                if wait_raw:
                    with contextlib.suppress(ValueError, TypeError):
                        wait_sec_num = float(wait_raw)
                wait_s = min(10.0, max(0.5, wait_sec_num))
                if progress_cb is not None:
                    await progress_cb(f"Waiting {wait_s:.1f}s for page updates...")
                await asyncio.sleep(wait_s)

            elif act in {"back", "forward"}:
                js = "history.back()" if act == "back" else "history.forward()"
                await _cdp_send_and_wait(
                    ws,
                    next_id(),
                    "Runtime.evaluate",
                    {"expression": js, "returnByValue": True},
                    timeout=5.0,
                )
                nav_st = await _wait_for_navigation_or_settle(ws, settle_seconds=1.2)
                if nav_st is not None:
                    doc_status = nav_st

            elif act == "scroll":
                direction = str(params.get("direction") or "down").strip().lower()
                raw_amt = str(params.get("amount") or "").strip().lower().removesuffix("px").strip()
                amount_val = 0
                if raw_amt:
                    with contextlib.suppress(ValueError, TypeError):
                        parsed_amt = int(float(raw_amt))
                        if parsed_amt > 0:
                            amount_val = parsed_amt
                sign = -1 if direction == "up" else 1
                scroll_js = (
                    "(function(){"
                    f"const sign = {sign};"
                    f"const customAmt = {amount_val};"
                    "const delta = sign * (customAmt > 0 ? customAmt : Math.max(300, Math.round((window.innerHeight || 800) * 0.75)));"
                    "const beforeY = window.scrollY || document.documentElement.scrollTop || 0;"
                    "window.scrollBy(0, delta);"
                    "const afterY = window.scrollY || document.documentElement.scrollTop || 0;"
                    "if (afterY === beforeY) {"
                    "  const all = Array.from(document.querySelectorAll('*'));"
                    "  let best = null; let bestH = 0;"
                    "  for (const el of all) {"
                    "    if (el.scrollHeight > el.clientHeight + 20) {"
                    "      const st = window.getComputedStyle(el);"
                    "      if (st && (st.overflowY === 'auto' || st.overflowY === 'scroll')) {"
                    "        if (el.clientHeight > bestH) { best = el; bestH = el.clientHeight; }"
                    "      }"
                    "    }"
                    "  }"
                    "  if (best) best.scrollBy(0, delta);"
                    "}"
                    "return JSON.stringify({before: Math.round(beforeY), after: Math.round(window.scrollY || document.documentElement.scrollTop || 0)});"
                    "})()"
                )
                await _cdp_eval_json(ws, next_id(), scroll_js, timeout=5.0)
                await asyncio.sleep(0.35)

            elif act == "click":
                loc_res, _ = await _cdp_eval_json(
                    ws, next_id(), _build_locate_element_js(params), timeout=8.0
                )
                if not loc_res.get("found"):
                    hint = (
                        params.get("selector")
                        or params.get("text")
                        or params.get("aria_label")
                        or params.get("index")
                        or "element"
                    )
                    raise DesktopRuntimeError(
                        f"Could not find clickable element matching '{hint}' on {target.get('url') or 'page'}."
                    )
                await asyncio.sleep(0.1)
                rect_res, _ = await _cdp_eval_json(
                    ws,
                    next_id(),
                    "(function(){"
                    "const el = document.querySelector('[data-argo-target=\"1\"]');"
                    "if (!el) return JSON.stringify({});"
                    "const r = el.getBoundingClientRect();"
                    "const vw = window.innerWidth || 1280; const vh = window.innerHeight || 800;"
                    "const cx = Math.round(r.left + r.width / 2); const cy = Math.round(r.top + r.height / 2);"
                    "return JSON.stringify({x: cx, y: cy, in_viewport: r.width > 0 && r.height > 0 && cx >= 0 && cy >= 0 && cx < vw && cy < vh});"
                    "})()",
                    timeout=5.0,
                )
                cx = int(rect_res.get("x") or loc_res.get("x") or 0)
                cy = int(rect_res.get("y") or loc_res.get("y") or 0)
                in_vp = bool(rect_res.get("in_viewport", loc_res.get("in_viewport")))
                matched_element = {
                    k: loc_res[k]
                    for k in ("tag", "text", "aria_label")
                    if loc_res.get(k) not in (None, "")
                }
                matched_element["x"] = cx
                matched_element["y"] = cy
                if in_vp and cx > 0 and cy > 0:
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchMouseEvent",
                        {"type": "mouseMoved", "x": cx, "y": cy},
                        timeout=4.0,
                    )
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchMouseEvent",
                        {
                            "type": "mousePressed",
                            "x": cx,
                            "y": cy,
                            "button": "left",
                            "clickCount": 1,
                        },
                        timeout=4.0,
                    )
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchMouseEvent",
                        {
                            "type": "mouseReleased",
                            "x": cx,
                            "y": cy,
                            "button": "left",
                            "clickCount": 1,
                        },
                        timeout=4.0,
                    )
                else:
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Runtime.evaluate",
                        {
                            "expression": "document.querySelector('[data-argo-target=\"1\"]')?.click()",
                            "returnByValue": True,
                        },
                        timeout=5.0,
                    )
                nav_st = await _wait_for_navigation_or_settle(
                    ws, settle_seconds=wait_ms / 1000.0
                )
                if nav_st is not None:
                    doc_status = nav_st

            elif act in {"fill", "type"}:
                has_explicit_val = "value" in params and params["value"] is not None
                typed_text = str(params["value"] if has_explicit_val else (params.get("text") or ""))
                if not typed_text and not params.get("clear", True):
                    raise DesktopRuntimeError("text or value is required for fill/type action.")
                locate_params: dict[str, Any] = {
                    k: params[k]
                    for k in ("index", "selector", "label", "placeholder", "name", "nth")
                    if params.get(k) is not None
                }
                if not locate_params:
                    if params.get("field") is not None:
                        locate_params["label"] = params["field"]
                    elif params.get("target") is not None:
                        locate_params["label"] = params["target"]
                    elif has_explicit_val and params.get("text"):
                        locate_params["text"] = params["text"]

                loc_res, _ = await _cdp_eval_json(
                    ws,
                    next_id(),
                    _build_locate_element_js(locate_params, allow_active_fallback=True),
                    timeout=8.0,
                )
                if not loc_res.get("found"):
                    raise DesktopRuntimeError("Could not find target input element to fill/type into.")
                await asyncio.sleep(0.08)
                cx = int(loc_res.get("x") or 0)
                cy = int(loc_res.get("y") or 0)
                matched_element = {
                    k: loc_res[k]
                    for k in ("tag", "text", "aria_label")
                    if loc_res.get(k) not in (None, "")
                }
                if bool(loc_res.get("in_viewport")) and cx > 0 and cy > 0:
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchMouseEvent",
                        {
                            "type": "mousePressed",
                            "x": cx,
                            "y": cy,
                            "button": "left",
                            "clickCount": 1,
                        },
                        timeout=4.0,
                    )
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchMouseEvent",
                        {
                            "type": "mouseReleased",
                            "x": cx,
                            "y": cy,
                            "button": "left",
                            "clickCount": 1,
                        },
                        timeout=4.0,
                    )

                should_clear = bool(params.get("clear", True))
                focus_js = (
                    "(function(){"
                    "const el = document.querySelector('[data-argo-target=\"1\"]') || document.activeElement;"
                    "if (!el) return false;"
                    "el.focus();"
                    f"if ({json.dumps(should_clear)}) {{"
                    "  const tag = (el.tagName || '').toLowerCase();"
                    "  if (tag === 'input' || tag === 'textarea') {"
                    "    const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;"
                    "    const desc = Object.getOwnPropertyDescriptor(proto, 'value');"
                    "    if (desc && desc.set) desc.set.call(el, ''); else el.value = '';"
                    "    el.dispatchEvent(new Event('input', {bubbles: true}));"
                    "    if (typeof el.select === 'function') el.select();"
                    "  } else if (el.isContentEditable) {"
                    "    try { document.execCommand('selectAll', false, null); } catch (e) {}"
                    "  }"
                    "}"
                    "return true;"
                    "})()"
                )
                await _cdp_send_and_wait(
                    ws,
                    next_id(),
                    "Runtime.evaluate",
                    {"expression": focus_js, "returnByValue": True},
                    timeout=5.0,
                )
                if typed_text:
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.insertText",
                        {"text": typed_text},
                        timeout=6.0,
                    )
                if params.get("submit"):
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchKeyEvent",
                        {
                            "type": "rawKeyDown",
                            "key": "Enter",
                            "code": "Enter",
                            "windowsVirtualKeyCode": 13,
                        },
                        timeout=4.0,
                    )
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchKeyEvent",
                        {"type": "char", "text": "\r"},
                        timeout=4.0,
                    )
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchKeyEvent",
                        {
                            "type": "keyUp",
                            "key": "Enter",
                            "code": "Enter",
                            "windowsVirtualKeyCode": 13,
                        },
                        timeout=4.0,
                    )
                nav_st = await _wait_for_navigation_or_settle(
                    ws, settle_seconds=0.7
                )
                if nav_st is not None:
                    doc_status = nav_st

            elif act == "select":
                opt_val = str(params.get("value") or params.get("option") or params.get("text") or "").strip()
                if not opt_val:
                    raise DesktopRuntimeError("value or option is required for select action.")
                locate_params = {
                    k: params[k]
                    for k in ("index", "selector", "label", "placeholder", "name", "nth")
                    if params.get(k) is not None
                }
                loc_res, _ = await _cdp_eval_json(
                    ws,
                    next_id(),
                    _build_locate_element_js(locate_params),
                    timeout=8.0,
                )
                if not loc_res.get("found"):
                    raise DesktopRuntimeError("Could not find target <select> element.")
                sel_js = (
                    "(function(){"
                    "const el = document.querySelector('[data-argo-target=\"1\"]');"
                    f"const want = {json.dumps(opt_val)}.toLowerCase().trim();"
                    "if (!el || (el.tagName || '').toLowerCase() !== 'select') return JSON.stringify({ok: false, error: 'Target element is not a <select>'});"
                    "const opts = Array.from(el.options || []);"
                    "const match = opts.find(o => String(o.value).toLowerCase().trim() === want || String(o.text || '').toLowerCase().trim() === want)"
                    "  || opts.find(o => String(o.text || '').toLowerCase().includes(want) || String(o.value).toLowerCase().includes(want));"
                    "if (!match) return JSON.stringify({ok: false, error: 'Option not found: ' + want});"
                    "el.value = match.value;"
                    "el.dispatchEvent(new Event('input', {bubbles: true}));"
                    "el.dispatchEvent(new Event('change', {bubbles: true}));"
                    "return JSON.stringify({ok: true, value: match.value, text: (match.text || '').trim()});"
                    "})()"
                )
                sel_out, _ = await _cdp_eval_json(ws, next_id(), sel_js, timeout=5.0)
                if not sel_out.get("ok"):
                    raise DesktopRuntimeError(str(sel_out.get("error") or "Failed selecting option."))
                matched_element = {
                    "tag": "select",
                    "text": str(sel_out.get("text") or ""),
                    "value": str(sel_out.get("value") or ""),
                }
                await asyncio.sleep(0.45)

            elif act == "key":
                raw_key = str(params.get("key") or params.get("keys") or "").strip()
                if not raw_key:
                    raise DesktopRuntimeError("key is required for key action.")
                mapped = _CDP_KEY_MAP.get(raw_key.lower())
                if mapped:
                    k_name, k_code, k_vk, k_txt = mapped
                else:
                    k_name = raw_key
                    k_code = f"Key{raw_key.upper()}" if len(raw_key) == 1 and raw_key.isalpha() else raw_key
                    k_vk = ord(raw_key.upper()) if len(raw_key) == 1 else 0
                    k_txt = raw_key if len(raw_key) == 1 else ""
                await _cdp_send_and_wait(
                    ws,
                    next_id(),
                    "Input.dispatchKeyEvent",
                    {
                        "type": "rawKeyDown",
                        "key": k_name,
                        "code": k_code,
                        "windowsVirtualKeyCode": k_vk,
                    },
                    timeout=4.0,
                )
                if k_txt:
                    await _cdp_send_and_wait(
                        ws,
                        next_id(),
                        "Input.dispatchKeyEvent",
                        {"type": "char", "text": k_txt},
                        timeout=4.0,
                    )
                await _cdp_send_and_wait(
                    ws,
                    next_id(),
                    "Input.dispatchKeyEvent",
                    {
                        "type": "keyUp",
                        "key": k_name,
                        "code": k_code,
                        "windowsVirtualKeyCode": k_vk,
                    },
                    timeout=4.0,
                )
                nav_st = await _wait_for_navigation_or_settle(ws, settle_seconds=0.6)
                if nav_st is not None:
                    doc_status = nav_st

            extract_sel = str(params.get("selector") or "").strip() if act in {"snapshot", "read"} else None
            evaluated, eval_status = await _cdp_eval_json(
                ws,
                next_id(),
                _build_extract_js(extract_sel or None),
                timeout=10.0,
            )
            if eval_status is not None:
                doc_status = eval_status

        return CDPPageSnapshot(
            url=str(evaluated.get("url") or target.get("url") or ""),
            status_code=doc_status,
            title=str(evaluated.get("title") or target.get("title") or ""),
            text=str(evaluated.get("text") or ""),
            html=str(evaluated.get("html") or ""),
            scroll_y=int(evaluated.get("scroll_y") or 0),
            scroll_height=int(evaluated.get("scroll_height") or 0),
            viewport_height=int(evaluated.get("viewport_height") or 0),
            interactive_elements=list(evaluated.get("interactive_elements") or []),
            target_id=target_id,
            matched_element=matched_element,
            tabs=tabs_list if act in {"tabs", "switch_tab"} else [],
        )


class ChromeDevToolsBridge:
    """Bridges Universal Bot Runner to per-bot Chromium CDP :9222 & chrome-devtools-mcp."""

    def __init__(
        self,
        *,
        desktop_manager: DesktopManager,
        bus: EventBus,
        telegram_service: TelegramBotService | None = None,
        transport: CDPTransport | None = None,
        action_transport: CDPActionTransport | None = None,
    ) -> None:
        self._desktop_manager = desktop_manager
        self._bus = bus
        self._telegram = telegram_service
        self._transport: CDPTransport = transport or _default_cdp_transport
        self._action_transport: CDPActionTransport = action_transport or _default_cdp_action_transport
        self._active_target_ids: dict[str, str] = {}

    def _agent_token_for(self, bot_slug: str) -> str:
        fn = getattr(self._desktop_manager, "agent_token_for", None)
        if callable(fn):
            return str(fn(bot_slug) or "")
        return ""

    @staticmethod
    def _validate_post_nav_url(snapshot_url: str, *, is_default_transport: bool) -> None:
        final_url = str(snapshot_url or "").strip()
        if not final_url or final_url.lower().startswith(
            ("about:", "chrome:", "chrome-extension:", "data:")
        ):
            return
        try:
            validate_public_url(final_url)
        except PublicFetchError:
            if is_default_transport:
                raise

    @staticmethod
    def build_mcp_server_config(bot_slug: str) -> dict[str, Any]:
        """Return chrome-devtools-mcp v1.13+ stdio configuration targeting argo-desktop-<slug>:9222."""
        clean_slug = validate_desktop_slug(bot_slug)
        cdp_endpoint = f"http://argo-desktop-{clean_slug}:{CDP_PORT}"
        return {
            "server_name": f"chrome_devtools_{clean_slug}",
            "command": "npx",
            "args": [
                "-y",
                "chrome-devtools-mcp@latest",
                f"--browserUrl={cdp_endpoint}",
            ],
            "cdp_endpoint": cdp_endpoint,
        }

    @classmethod
    def create_pydantic_ai_mcp_toolset(cls, bot_slug: str) -> Any:
        """Instantiate pydantic_ai.mcp.MCPToolset with FastMCP StdioTransport bound to argo-desktop-<slug>:9222."""
        from fastmcp.client.transports import StdioTransport  # type: ignore[import-not-found]
        from pydantic_ai.mcp import MCPToolset  # type: ignore[import-not-found]

        cfg = cls.build_mcp_server_config(bot_slug)
        transport = StdioTransport(command=cfg["command"], args=list(cfg["args"]))
        return MCPToolset(transport, id=cfg["server_name"])

    @classmethod
    def create_pydantic_ai_mcp_server(cls, bot_slug: str) -> Any:
        """Alias for create_pydantic_ai_mcp_toolset using PydanticAI v2.68+ MCPToolset."""
        return cls.create_pydantic_ai_mcp_toolset(bot_slug)

    async def _check_gate_or_raise(
        self,
        *,
        clean_slug: str,
        fallback_url: str,
        snapshot: CDPPageSnapshot,
        correlation_id: str | None,
    ) -> None:
        gate = _detect_gate(snapshot)
        if gate is None:
            return
        gate_type, reason = gate
        corr = correlation_id or make_id("corr")
        target_url = snapshot.url or fallback_url
        self._desktop_manager.mark_awaiting_takeover(
            clean_slug,
            url=target_url,
            reason=reason,
        )
        await self._bus.publish(
            correlation_id=corr,
            source_slug=clean_slug,
            target_slug="operator",
            event_type="desktop.takeover_required",
            payload={
                "category": "alerts",
                "title": f"Manual Selkies Takeover Required · {clean_slug}",
                "badge": f"Takeover Required · Selkies :{SELKIES_HTTP_PORT}",
                "badge_tone": "amber",
                "summary": (
                    f"Halted cleanly at {target_url} ({reason}) with zero bypass attempts. "
                    f"Open Desktops -> Live Screen for argo-desktop-{clean_slug}."
                ),
                "meta": f"Gate: {gate_type} · CDP :{CDP_PORT}",
                "url": target_url,
                "gate_type": gate_type,
            },
            hop_count=1,
        )
        if self._telegram is not None:
            await self._telegram.send_operator_notice(
                title=f"Manual Selkies Takeover Required ({clean_slug})",
                body=(
                    f"argo-desktop-{clean_slug} halted transparently at {target_url}: "
                    f"{reason}. Open Argo Desktops -> Take Over (Selkies :{SELKIES_HTTP_PORT}) "
                    "to authenticate manually."
                ),
            )
        raise DesktopTakeoverRequiredError(
            f"Portal halted cleanly ({reason}); operator Selkies takeover required.",
            bot_slug=clean_slug,
            url=target_url,
            gate_type=gate_type,
            reason=reason,
        )

    async def navigate_and_extract(
        self,
        bot_slug: str,
        url: str,
        *,
        selector: str | None = None,
        correlation_id: str | None = None,
        max_chars: int = 12000,
    ) -> dict[str, Any]:
        """Validate SSRF rules, wake per-bot desktop if <80% RAM, and read page via CDP :9222."""
        clean_slug = validate_desktop_slug(bot_slug)
        validate_public_url(url)

        await self._desktop_manager.start_desktop(
            clean_slug,
            reason="cdp_bridge",
            correlation_id=correlation_id,
        )
        cdp_endpoint = f"http://argo-desktop-{clean_slug}:{CDP_PORT}"

        async def _emit_step(msg: str) -> None:
            with contextlib.suppress(Exception):
                await self._bus.emit_progress(
                    clean_slug,
                    "working",
                    step=msg,
                    correlation_id=correlation_id or "",
                )

        if self._transport is _default_cdp_transport:
            snapshot = await _default_cdp_transport(
                clean_slug,
                cdp_endpoint,
                url,
                selector,
                preferred_target_id=self._active_target_ids.get(clean_slug),
                agent_token=self._agent_token_for(clean_slug),
                progress_cb=_emit_step,
            )
        else:
            snapshot = await self._transport(clean_slug, cdp_endpoint, url, selector)
        self._desktop_manager.touch_activity(clean_slug)
        if snapshot.target_id:
            self._active_target_ids[clean_slug] = snapshot.target_id

        self._validate_post_nav_url(
            snapshot.url,
            is_default_transport=(self._transport is _default_cdp_transport),
        )

        await self._check_gate_or_raise(
            clean_slug=clean_slug,
            fallback_url=url,
            snapshot=snapshot,
            correlation_id=correlation_id,
        )

        return {
            "bot_slug": clean_slug,
            "container_name": f"argo-desktop-{clean_slug}",
            "url": snapshot.url or url,
            "title": snapshot.title,
            "content": snapshot.text[:max_chars],
            "scroll_y": snapshot.scroll_y,
            "scroll_height": snapshot.scroll_height,
            "viewport_height": snapshot.viewport_height,
            "interactive_elements": list(snapshot.interactive_elements[:45]),
            "cdp_endpoint": cdp_endpoint,
        }

    async def browser_action(
        self,
        bot_slug: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
        max_chars: int = 12000,
    ) -> dict[str, Any]:
        """Run a generic browser DOM/input action via CDP :9222 on the bot's active Chromium tab."""
        clean_slug = validate_desktop_slug(bot_slug)
        act = str(action or "snapshot").strip().lower()
        if act not in SUPPORTED_BROWSER_ACTIONS:
            raise ValueError(
                f"Unsupported desktop_browser_action '{action}'. Supported: {sorted(SUPPORTED_BROWSER_ACTIONS)}"
            )

        await self._desktop_manager.start_desktop(
            clean_slug,
            reason="cdp_bridge",
            correlation_id=correlation_id,
        )
        cdp_endpoint = f"http://argo-desktop-{clean_slug}:{CDP_PORT}"
        act_params = dict(params or {})

        async def _emit_step(msg: str) -> None:
            with contextlib.suppress(Exception):
                await self._bus.emit_progress(
                    clean_slug,
                    "working",
                    step=msg,
                    correlation_id=correlation_id or "",
                )

        if self._action_transport is _default_cdp_action_transport:
            snapshot = await _default_cdp_action_transport(
                clean_slug,
                cdp_endpoint,
                act,
                act_params,
                preferred_target_id=self._active_target_ids.get(clean_slug),
                agent_token=self._agent_token_for(clean_slug),
                progress_cb=_emit_step,
            )
        else:
            snapshot = await self._action_transport(clean_slug, cdp_endpoint, act, act_params)

        self._desktop_manager.touch_activity(clean_slug)
        if snapshot.target_id:
            self._active_target_ids[clean_slug] = snapshot.target_id

        self._validate_post_nav_url(
            snapshot.url,
            is_default_transport=(self._action_transport is _default_cdp_action_transport),
        )

        await self._check_gate_or_raise(
            clean_slug=clean_slug,
            fallback_url=str(act_params.get("url") or snapshot.url or ""),
            snapshot=snapshot,
            correlation_id=correlation_id,
        )

        out: dict[str, Any] = {
            "bot_slug": clean_slug,
            "container_name": f"argo-desktop-{clean_slug}",
            "action": act,
            "url": snapshot.url,
            "title": snapshot.title,
            "content": snapshot.text[:max_chars],
            "scroll_y": snapshot.scroll_y,
            "scroll_height": snapshot.scroll_height,
            "viewport_height": snapshot.viewport_height,
            "interactive_elements": list(snapshot.interactive_elements[:45]),
            "cdp_endpoint": cdp_endpoint,
        }
        if snapshot.matched_element:
            out["matched_element"] = dict(snapshot.matched_element)
        if snapshot.tabs:
            out["tabs"] = list(snapshot.tabs)
        return out
