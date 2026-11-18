"""SSO principal extraction from oauth2-proxy forwarded headers."""

from __future__ import annotations

from typing import Any

from fastapi import Request


def extract_sso_principal(request: Request) -> dict[str, Any]:
    """Read authenticated operator identity injected by oauth2-proxy."""
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
