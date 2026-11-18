"""chrome-devtools-mcp v1.13+ & internal CDP :9222 browser bridge."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from argo_core.db.repositories import make_id
from argo_core.desktop.manager import (
    CDP_PORT,
    SELKIES_HTTP_PORT,
    DesktopManager,
    DesktopRuntimeError,
    validate_desktop_slug,
)
from argo_core.security.ssrf import validate_public_url

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


CDPTransport = Callable[[str, str, str, str | None], Awaitable[CDPPageSnapshot]]


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


async def _default_cdp_transport(
    bot_slug: str,
    cdp_endpoint: str,
    url: str,
    selector: str | None,
    *,
    progress_cb: Callable[[str], Awaitable[None]] | None = None,
) -> CDPPageSnapshot:
    """Drive Chromium inside argo-desktop-<bot_slug> via internal CDP :9222 without anti-bot bypass."""
    del bot_slug
    import aiohttp  # type: ignore[import-not-found]

    parsed_ep = urllib.parse.urlparse(cdp_endpoint)
    ep_host = parsed_ep.hostname or "127.0.0.1"
    ep_port = parsed_ep.port or CDP_PORT
    host_headers = {"Host": f"127.0.0.1:{ep_port}"}
    agent_status_url = f"http://{ep_host}:9223/status"

    async with aiohttp.ClientSession() as session:
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

        if progress_cb is not None:
            await progress_cb(f"Opening {url} in Virtual Desktop Chromium...")

        target: dict[str, Any] = {}
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
                            target = cand
                            break

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
                    async with session.get(
                        f"{cdp_endpoint}/json/list",
                        headers=host_headers,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as list_resp:
                        targets = await list_resp.json()
                        target = targets[0] if targets else {}

        target_id = str(target.get("id") or "")
        raw_ws = str(target.get("webSocketDebuggerUrl") or "")
        if not raw_ws:
            raise DesktopRuntimeError(f"CDP WebSocket debugger URL missing for endpoint {cdp_endpoint}")

        ws_parsed = urllib.parse.urlparse(raw_ws)
        ws_path = ws_parsed.path or (f"/devtools/page/{target_id}" if target_id else "")
        ws_query = f"?{ws_parsed.query}" if ws_parsed.query else ""
        ws_url = f"ws://{ep_host}:{ep_port}{ws_path}{ws_query}"

        expr = (
            "(function(){"
            f"const sel = {json.dumps(selector)};"
            "const node = sel ? document.querySelector(sel) : document.body;"
            "return JSON.stringify({"
            "url: location.href, "
            "title: document.title || '', "
            "text: node ? (node.innerText || '') : '', "
            "html: document.documentElement ? document.documentElement.outerHTML : ''"
            "});"
            "})()"
        )

        doc_status = 200
        evaluated: dict[str, Any] = {}
        async with session.ws_connect(ws_url, timeout=20, max_msg_size=0) as ws:
            await ws.send_json({"id": 1, "method": "Page.enable"})
            await ws.send_json({"id": 2, "method": "Network.enable"})
            await ws.send_json({"id": 3, "method": "Page.navigate", "params": {"url": url}})

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
                if frame.get("id") == 3:
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

            await asyncio.sleep(0.4)
            await ws.send_json(
                {
                    "id": 99,
                    "method": "Runtime.evaluate",
                    "params": {"expression": expr, "returnByValue": True},
                }
            )
            eval_deadline = time.monotonic() + 10.0
            while time.monotonic() < eval_deadline:
                remaining = max(0.1, eval_deadline - time.monotonic())
                try:
                    msg = await ws.receive(timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if msg.type != aiohttp.WSMsgType.TEXT:
                    if msg.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                        break
                    continue
                frame = msg.json()
                if frame.get("id") == 99:
                    raw_val = (
                        frame.get("result", {}).get("result", {}).get("value")
                        or "{}"
                    )
                    evaluated = json.loads(raw_val) if isinstance(raw_val, str) else {}
                    break

        snapshot = CDPPageSnapshot(
            url=str(evaluated.get("url") or url),
            status_code=doc_status,
            title=str(evaluated.get("title") or ""),
            text=str(evaluated.get("text") or ""),
            html=str(evaluated.get("html") or ""),
        )
        # Keep the navigated tab open so the operator and Desktop Screenshot see the live page.
        return snapshot


class ChromeDevToolsBridge:
    """Bridges Universal Bot Runner to per-bot Chromium CDP :9222 & chrome-devtools-mcp."""

    def __init__(
        self,
        *,
        desktop_manager: DesktopManager,
        bus: EventBus,
        telegram_service: TelegramBotService | None = None,
        transport: CDPTransport | None = None,
    ) -> None:
        self._desktop_manager = desktop_manager
        self._bus = bus
        self._telegram = telegram_service
        self._transport: CDPTransport = transport or _default_cdp_transport

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
                progress_cb=_emit_step,
            )
        else:
            snapshot = await self._transport(clean_slug, cdp_endpoint, url, selector)
        self._desktop_manager.touch_activity(clean_slug)

        gate = _detect_gate(snapshot)
        if gate is not None:
            gate_type, reason = gate
            corr = correlation_id or make_id("corr")
            self._desktop_manager.mark_awaiting_takeover(
                clean_slug,
                url=snapshot.url or url,
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
                        f"Halted cleanly at {snapshot.url or url} ({reason}) with zero bypass attempts. "
                        f"Open Desktops -> Live Screen for argo-desktop-{clean_slug}."
                    ),
                    "meta": f"Gate: {gate_type} · CDP :{CDP_PORT}",
                    "url": snapshot.url or url,
                    "gate_type": gate_type,
                },
                hop_count=1,
            )
            if self._telegram is not None:
                await self._telegram.send_operator_notice(
                    title=f"Manual Selkies Takeover Required ({clean_slug})",
                    body=(
                        f"argo-desktop-{clean_slug} halted transparently at {snapshot.url or url}: "
                        f"{reason}. Open Argo Desktops -> Take Over (Selkies :{SELKIES_HTTP_PORT}) "
                        "to authenticate manually."
                    ),
                )
            raise DesktopTakeoverRequiredError(
                f"Portal halted cleanly ({reason}); operator Selkies takeover required.",
                bot_slug=clean_slug,
                url=snapshot.url or url,
                gate_type=gate_type,
                reason=reason,
            )

        return {
            "bot_slug": clean_slug,
            "container_name": f"argo-desktop-{clean_slug}",
            "url": snapshot.url or url,
            "title": snapshot.title,
            "content": snapshot.text[:max_chars],
            "cdp_endpoint": cdp_endpoint,
        }
