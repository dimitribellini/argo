"""SSO principal extraction from oauth2-proxy forwarded headers."""

from __future__ import annotations

import hmac
import ipaddress
import socket
import threading
import time
from typing import Any

from starlette.requests import HTTPConnection

_PROXY_DNS_LOCK = threading.Lock()
_PROXY_DNS_CACHE: dict[str, tuple[float, frozenset[str]]] = {}
_PROXY_DNS_TTL_SECONDS = 30.0


def normalize_peer_ip(raw_host: str) -> str:
    """Normalize IPv4/IPv6 peer strings (including IPv4-mapped IPv6 addresses)."""
    clean = raw_host.strip().split("%", 1)[0]
    if clean in {"", "testclient"}:
        return clean
    try:
        addr = ipaddress.ip_address(clean)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return clean


def _resolve_proxy_host_ips(hostname: str) -> frozenset[str]:
    clean = hostname.strip()
    if not clean:
        return frozenset()
    now = time.monotonic()
    with _PROXY_DNS_LOCK:
        cached = _PROXY_DNS_CACHE.get(clean)
        if cached is not None and (now - cached[0]) < _PROXY_DNS_TTL_SECONDS:
            return cached[1]
    resolved: set[str] = set()
    try:
        infos = socket.getaddrinfo(clean, None, type=socket.SOCK_STREAM)
        for info in infos:
            ip_str = str(info[4][0])
            norm = normalize_peer_ip(ip_str)
            if norm:
                resolved.add(norm)
    except OSError:
        pass
    frozen = frozenset(resolved)
    with _PROXY_DNS_LOCK:
        _PROXY_DNS_CACHE[clean] = (now, frozen)
    return frozen


def is_trusted_proxy_request(conn: HTTPConnection, settings: Any) -> bool:
    """Return True if the request originates from an authenticated or allowed proxy peer."""
    proxy_secret = str(getattr(settings, "proxy_secret", "") or "").strip()
    if proxy_secret:
        presented = str(conn.headers.get("X-Argo-Proxy-Secret") or "").strip()
        if not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), proxy_secret.encode("utf-8"))

    raw_peer = str(conn.client.host if conn.client else "").strip()
    peer_ip = normalize_peer_ip(raw_peer)
    if not peer_ip:
        return False

    trusted_ips: set[str] = {"127.0.0.1", "::1", "testclient"}
    for item in getattr(settings, "trusted_proxy_ips", ()) or ():
        norm = normalize_peer_ip(str(item))
        if norm:
            trusted_ips.add(norm)
    proxy_host = str(getattr(settings, "trusted_proxy_host", "") or "").strip()
    if proxy_host:
        trusted_ips.update(_resolve_proxy_host_ips(proxy_host))
    return peer_ip in trusted_ips


def extract_sso_principal(request: HTTPConnection) -> dict[str, Any]:
    """Read authenticated principal from middleware scope state or oauth2-proxy headers."""
    scope_state = request.scope.get("state")
    if isinstance(scope_state, dict):
        cached = scope_state.get("argo_principal")
        if isinstance(cached, dict) and cached.get("email"):
            return dict(cached)
    email = (
        request.headers.get("X-Auth-Request-Email")
        or request.headers.get("X-Forwarded-Email")
        or ""
    ).strip()
    user = (
        request.headers.get("X-Auth-Request-User")
        or request.headers.get("X-Forwarded-User")
        or ""
    ).strip()
    authenticated = bool(email or user)
    identity = email or user
    return {
        "authenticated": authenticated,
        "email": email or "operator@local",
        "actor": f"user:{identity}" if identity else "operator:web_ui",
    }
