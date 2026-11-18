"""Anti-SSRF URL/DNS validator and zero-bypass public HTTP fetcher."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")
_DISALLOWED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "argo-core",
    "valkey",
    "oauth2-proxy",
    "host.docker.internal",
    "metadata.google.internal",
}
_DISALLOWED_SUFFIXES = (".localhost", ".local", ".internal")
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_CAPTCHA_MARKERS = ("cf-turnstile", "g-recaptcha", "h-captcha")


class SSRFBlockedError(PermissionError):
    """Raised when a URL targets a disallowed scheme, internal hostname, or non-public IP."""


class AntiBotHaltError(RuntimeError):
    """Raised when an upstream host presents an HTTP 403/429 or anti-bot challenge."""

    def __init__(self, *, url: str, status_code: int, reason: str) -> None:
        self.url = url
        self.status_code = status_code
        self.reason = reason
        super().__init__(reason)


class PublicFetchError(RuntimeError):
    """Raised on network failures or unexpected 4xx/5xx responses during public fetch."""

    def __init__(self, *, url: str, status_code: int | None, message: str) -> None:
        self.url = url
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PublicHttpResponse:
    """Normalized response returned by a SSRF-validated public HTTP fetch."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str


class PublicHttpFetcher(Protocol):
    """Protocol implemented by SafePublicHttpFetcher and unit-test doubles."""

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        """Fetch a public HTTP(S) resource after SSRF validation without bypassing WAF/CAPTCHA."""


def _check_ip_obj(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    if addr.is_loopback:
        return True, f"Loopback address '{addr}' is disallowed."
    if addr.is_link_local:
        return True, f"Link-local/metadata address '{addr}' is disallowed."
    if addr.is_private:
        return True, f"Private/bridge/ULA address '{addr}' is disallowed."
    if addr.is_multicast:
        return True, f"Multicast address '{addr}' is disallowed."
    if addr.is_unspecified:
        return True, f"Unspecified address '{addr}' is disallowed."
    if addr.is_reserved:
        return True, f"Reserved address '{addr}' is disallowed."
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in _CGNAT_NET:
            return True, f"CGNAT address '{addr}' is disallowed."
        if addr in _BENCHMARK_NET:
            return True, f"Benchmark address '{addr}' is disallowed."
    return False, ""


def is_disallowed_ip(raw_ip: str) -> tuple[bool, str]:
    """Return (blocked, reason) if raw_ip targets loopback, private, bridge, or metadata ranges."""
    candidate = raw_ip.strip()
    if not candidate:
        return True, "Empty IP address is disallowed."
    if "%" in candidate:
        return True, f"Scoped link-local IP address '{candidate}' is disallowed."
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return True, f"Malformed IP address '{candidate}' is disallowed."

    blocked, reason = _check_ip_obj(addr)
    if blocked:
        return True, reason

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        mapped_blocked, mapped_reason = _check_ip_obj(addr.ipv4_mapped)
        if mapped_blocked:
            return True, f"IPv4-mapped address '{addr}' rejected: {mapped_reason}"

    return False, ""


def _default_dns_resolve(hostname: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for _, _, _, _, sockaddr in infos:
        ip_str = str(sockaddr[0])
        if ip_str not in seen:
            seen.append(ip_str)
    return seen


def validate_public_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("https", "http"),
    resolver: Callable[[str], list[str]] | None = None,
) -> tuple[str, list[str]]:
    """Validate URL scheme, credentials, hostname, and resolved IPs against SSRF targets."""
    cleaned = url.strip()
    if not cleaned:
        raise SSRFBlockedError("Target URL cannot be empty.")

    parsed = urllib.parse.urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        raise SSRFBlockedError(f"URL scheme '{scheme or 'none'}' is disallowed.")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFBlockedError("Embedded URL credentials are disallowed.")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise SSRFBlockedError("URL must include a target hostname.")
    if hostname in _DISALLOWED_HOSTNAMES or hostname.endswith(_DISALLOWED_SUFFIXES):
        raise SSRFBlockedError(f"Internal hostname '{hostname}' is disallowed.")

    try:
        ip_literal = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        ip_literal = None

    if ip_literal is not None or "%" in hostname:
        blocked, reason = is_disallowed_ip(hostname)
        if blocked:
            raise SSRFBlockedError(reason)
        return cleaned, [str(ip_literal)]

    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        resolved_ips = (
            resolver(hostname)
            if resolver is not None
            else _default_dns_resolve(hostname, port)
        )
    except OSError as exc:
        raise PublicFetchError(
            url=cleaned,
            status_code=None,
            message=f"DNS resolution failed for '{hostname}': {exc}",
        ) from exc

    if not resolved_ips:
        raise SSRFBlockedError(f"Hostname '{hostname}' did not resolve to any public IP.")

    for ip_str in resolved_ips:
        blocked, reason = is_disallowed_ip(ip_str)
        if blocked:
            raise SSRFBlockedError(
                f"Hostname '{hostname}' resolved to disallowed IP '{ip_str}': {reason}"
            )

    return cleaned, resolved_ips


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return 3xx responses directly so each redirect hop is re-validated against SSRF."""

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp

    def http_error_302(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp

    def http_error_303(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp

    def http_error_307(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp

    def http_error_308(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        return fp


class SafePublicHttpFetcher:
    """Async public HTTP fetcher validating every DNS resolution and redirect against SSRF."""

    def __init__(self, *, resolver: Callable[[str], list[str]] | None = None) -> None:
        self._resolver = resolver

    async def _single_get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout_seconds: float,
        max_bytes: int,
    ) -> PublicHttpResponse:
        try:
            import aiohttp  # type: ignore[import-not-found]
        except ImportError:
            aiohttp = None

        if aiohttp is not None:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=False,
                ) as resp:
                    raw = await resp.content.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        raw = raw[:max_bytes]
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    return PublicHttpResponse(
                        url=str(resp.url),
                        status_code=int(resp.status),
                        headers=resp_headers,
                        body=raw.decode("utf-8", errors="replace"),
                    )

        def _sync_get() -> PublicHttpResponse:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with opener.open(req, timeout=timeout_seconds) as resp:
                    raw = resp.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        raw = raw[:max_bytes]
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    return PublicHttpResponse(
                        url=str(getattr(resp, "url", url) or url),
                        status_code=int(resp.getcode() or 200),
                        headers=resp_headers,
                        body=raw.decode("utf-8", errors="replace"),
                    )
            except urllib.error.HTTPError as exc:
                raw = exc.read(max_bytes) if hasattr(exc, "read") else b""
                resp_headers = (
                    {k.lower(): v for k, v in exc.headers.items()}
                    if exc.headers is not None
                    else {}
                )
                return PublicHttpResponse(
                    url=url,
                    status_code=int(exc.code),
                    headers=resp_headers,
                    body=raw.decode("utf-8", errors="replace"),
                )
            except Exception as exc:
                raise PublicFetchError(
                    url=url,
                    status_code=None,
                    message=f"HTTP request failed for '{url}': {exc}",
                ) from exc

        return await asyncio.to_thread(_sync_get)

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        """Fetch url across validated public redirects; halt immediately on 403/429 or CAPTCHAs."""
        req_headers = {
            "User-Agent": "ArgoCore/0.1 (SSRF-Guarded Fetcher)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **(headers or {}),
        }
        current_url = url
        for _ in range(max_redirects + 1):
            validated_url, _ = validate_public_url(
                current_url,
                resolver=self._resolver,
            )
            response = await self._single_get(
                validated_url,
                headers=req_headers,
                timeout_seconds=timeout_seconds,
                max_bytes=max_bytes,
            )

            if response.status_code in _REDIRECT_CODES:
                location = response.headers.get("location", "").strip()
                if not location:
                    raise PublicFetchError(
                        url=validated_url,
                        status_code=response.status_code,
                        message=f"Redirect HTTP {response.status_code} missing Location header.",
                    )
                current_url = urllib.parse.urljoin(validated_url, location)
                continue

            lowered_body = response.body.lower()
            cf_mitigated = response.headers.get("cf-mitigated", "").strip()
            has_captcha = response.status_code == 503 and any(
                marker in lowered_body for marker in _CAPTCHA_MARKERS
            )
            if response.status_code in (403, 429) or cf_mitigated or has_captcha:
                raise AntiBotHaltError(
                    url=validated_url,
                    status_code=response.status_code,
                    reason=(
                        f"Halted cleanly on upstream anti-bot/rate gate "
                        f"(HTTP {response.status_code}) at {validated_url}; "
                        "zero CAPTCHA/WAF bypass attempted."
                    ),
                )

            if response.status_code >= 400:
                raise PublicFetchError(
                    url=validated_url,
                    status_code=response.status_code,
                    message=f"Upstream HTTP {response.status_code} fetching {validated_url}",
                )

            return response

        raise PublicFetchError(
            url=url,
            status_code=None,
            message=f"Exceeded maximum redirect limit ({max_redirects}) for {url}",
        )
