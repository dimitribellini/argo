"""LinkedIn Official Versioned Posts API (/rest/posts) connector."""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Literal, Protocol

from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, make_id, slugify
from argo_core.security.vault import redact_secrets

DEFAULT_LINKEDIN_VERSION = "202611"
LINKEDIN_POSTS_URL = "https://api.linkedin.com/rest/posts"
LINKEDIN_USERINFO_URL = "https://api.linkedin.com/v2/userinfo"
_VERSION_RE = re.compile(r"^\d{6}$")
_AUTHOR_URN_RE = re.compile(r"^urn:li:(person|organization):[A-Za-z0-9_-]+$")


class LinkedInConfigError(ValueError):
    """Raised when LinkedIn API version, author URN, or post payload violates constraints."""


class LinkedInIntegrationError(RuntimeError):
    """Raised when LinkedIn REST API calls fail."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class LinkedInTransport(Protocol):
    """Protocol implemented by DefaultLinkedInTransport and unit-test doubles."""

    async def verify_token(
        self,
        access_token: str,
        *,
        linkedin_version: str,
    ) -> dict[str, Any]:
        """Verify an OAuth access token via LinkedIn OIDC userinfo endpoint."""

    async def create_post(
        self,
        access_token: str,
        *,
        linkedin_version: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a post using LinkedIn's versioned POST /rest/posts endpoint."""


def validate_linkedin_version(version: str) -> str:
    """Enforce YYYYMM LinkedIn-Version header format and forbid deprecated /v2/ugcPosts."""
    cleaned = version.strip()
    lowered = cleaned.lower()
    if "ugcposts" in lowered or "/v2/" in lowered:
        raise LinkedInConfigError(
            "Deprecated LinkedIn /v2/ugcPosts API is forbidden; use versioned "
            "/rest/posts with YYYYMM Linkedin-Version."
        )
    if not _VERSION_RE.match(cleaned):
        raise LinkedInConfigError(
            f"Invalid LinkedIn-Version '{cleaned}'; expected YYYYMM (e.g. '202611')."
        )
    return cleaned


def validate_author_urn(urn: str) -> str:
    """Validate LinkedIn person or organization URN syntax."""
    cleaned = urn.strip()
    if not _AUTHOR_URN_RE.match(cleaned):
        raise LinkedInConfigError(
            f"Invalid LinkedIn author URN '{cleaned}'; expected "
            "'urn:li:person:<id>' or 'urn:li:organization:<id>'."
        )
    return cleaned


class DefaultLinkedInTransport:
    """Production LinkedIn Posts API transport (/rest/posts) via aiohttp or stdlib urllib."""

    @staticmethod
    def _headers(access_token: str, linkedin_version: str, *, with_json: bool = False) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-Restli-Protocol-Version": "2.0.0",
            "Linkedin-Version": linkedin_version,
        }
        if with_json:
            headers["Content-Type"] = "application/json"
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        *,
        access_token: str,
        linkedin_version: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, Any]]:
        headers = self._headers(
            access_token,
            linkedin_version,
            with_json=payload is not None,
        )
        try:
            import aiohttp  # type: ignore[import-not-found]
        except ImportError:
            aiohttp = None

        if aiohttp is not None:
            timeout = aiohttp.ClientTimeout(total=15)
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(
                        method,
                        url,
                        headers=headers,
                        json=payload,
                    ) as resp:
                        raw_text = await resp.text()
                        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                        if resp.status >= 400:
                            raise LinkedInIntegrationError(
                                redact_secrets(
                                    f"LinkedIn API HTTP {resp.status}: {raw_text}",
                                    [access_token],
                                ),
                                status_code=int(resp.status),
                            )
                        parsed = json.loads(raw_text) if raw_text.strip() else {}
                        return int(resp.status), resp_headers, parsed if isinstance(parsed, dict) else {}
            except LinkedInIntegrationError:
                raise
            except Exception as exc:
                raise LinkedInIntegrationError(
                    redact_secrets(f"LinkedIn API request failed: {exc}", [access_token])
                ) from exc

        def _sync_req() -> tuple[int, dict[str, str], dict[str, Any]]:
            body = json.dumps(payload).encode("utf-8") if payload is not None else None
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw_text = resp.read().decode("utf-8", errors="replace")
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    parsed = json.loads(raw_text) if raw_text.strip() else {}
                    return (
                        int(resp.getcode() or 200),
                        resp_headers,
                        parsed if isinstance(parsed, dict) else {},
                    )
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                raise LinkedInIntegrationError(
                    redact_secrets(
                        f"LinkedIn API HTTP {exc.code}: {err_body}",
                        [access_token],
                    ),
                    status_code=int(exc.code),
                ) from exc
            except Exception as exc:
                raise LinkedInIntegrationError(
                    redact_secrets(f"LinkedIn API request failed: {exc}", [access_token])
                ) from exc

        return await asyncio.to_thread(_sync_req)

    async def verify_token(
        self,
        access_token: str,
        *,
        linkedin_version: str,
    ) -> dict[str, Any]:
        _, _, data = await self._request(
            "GET",
            LINKEDIN_USERINFO_URL,
            access_token=access_token,
            linkedin_version=linkedin_version,
        )
        return {
            "sub": data.get("sub"),
            "name": data.get("name"),
            "email": data.get("email"),
        }

    async def create_post(
        self,
        access_token: str,
        *,
        linkedin_version: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        status_code, headers, data = await self._request(
            "POST",
            LINKEDIN_POSTS_URL,
            access_token=access_token,
            linkedin_version=linkedin_version,
            payload=payload,
        )
        post_urn = str(headers.get("x-restli-id") or data.get("id") or "")
        return {
            "post_urn": post_urn,
            "status_code": status_code,
        }


class LinkedInService:
    """Manages LinkedIn versioned /rest/posts onboarding, health checks, and publishing."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        transport: LinkedInTransport | None = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._transport: LinkedInTransport = transport or DefaultLinkedInTransport()

    async def onboard_account(
        self,
        *,
        access_token: str,
        author_urn: str | None = None,
        linkedin_version: str = DEFAULT_LINKEDIN_VERSION,
        slug: str | None = None,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        """Validate version + token, store Fernet-encrypted credentials, and log activation."""
        clean_token = access_token.strip()
        if len(clean_token) < 12:
            raise LinkedInConfigError("LinkedIn access_token appears invalid or too short.")

        version = validate_linkedin_version(linkedin_version)
        profile = await self._transport.verify_token(
            clean_token,
            linkedin_version=version,
        )
        if author_urn and author_urn.strip():
            resolved_urn = validate_author_urn(author_urn)
        else:
            sub = str(profile.get("sub") or "").strip()
            if not sub:
                raise LinkedInConfigError(
                    "LinkedIn author_urn is required when userinfo omits 'sub'."
                )
            resolved_urn = validate_author_urn(f"urn:li:person:{sub}")

        urn_suffix = resolved_urn.rsplit(":", 1)[-1]
        resolved_slug = slugify(slug or f"linkedin-{urn_suffix}")
        resolved_name = (
            display_name.strip()
            if display_name and display_name.strip()
            else (str(profile.get("name") or "").strip() or resolved_urn)
        )
        scopes = ["rest_posts", f"version:{version}"]

        record = self._repo.upsert_integration(
            slug=resolved_slug,
            provider="linkedin",
            display_name=resolved_name,
            account_identifier=resolved_urn,
            scopes=scopes,
            secrets={
                "access_token": clean_token,
                "author_urn": resolved_urn,
                "linkedin_version": version,
                "endpoint": LINKEDIN_POSTS_URL,
            },
            status="ok",
        )

        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug="integrations",
            target_slug=resolved_slug,
            event_type="integration.linkedin.connected",
            payload={
                "category": "alerts",
                "title": f"Connected LinkedIn Connector {resolved_name}",
                "badge": f"/rest/posts · v{version}",
                "badge_tone": "emerald",
                "summary": f"Author {resolved_urn} verified using LinkedIn Posts API (v{version}).",
                "meta": LINKEDIN_POSTS_URL,
            },
            hop_count=1,
        )
        return {
            **record,
            "author_urn": resolved_urn,
            "linkedin_version": version,
            "endpoint": LINKEDIN_POSTS_URL,
        }

    async def publish_post(
        self,
        slug: str,
        *,
        commentary: str,
        visibility: Literal["PUBLIC", "CONNECTIONS"] = "PUBLIC",
        article_url: str | None = None,
        article_title: str | None = None,
    ) -> dict[str, Any]:
        """Publish a post via LinkedIn versioned POST /rest/posts endpoint."""
        clean_text = commentary.strip()
        if not clean_text:
            raise LinkedInConfigError("LinkedIn post commentary cannot be empty.")

        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "linkedin":
            raise LinkedInConfigError(f"Integration '{slug}' is not a LinkedIn connector.")

        sec = account["secrets"]
        access_token = str(sec.get("access_token") or "").strip()
        author_urn = validate_author_urn(str(sec.get("author_urn") or account.get("account_identifier") or ""))
        linkedin_version = validate_linkedin_version(
            str(sec.get("linkedin_version") or DEFAULT_LINKEDIN_VERSION)
        )
        if not access_token:
            raise LinkedInIntegrationError("Stored LinkedIn access_token is missing.", status_code=401)

        payload: dict[str, Any] = {
            "author": author_urn,
            "commentary": clean_text,
            "visibility": visibility,
            "distribution": {
                "feedDistribution": "MAIN_FEED",
                "targetEntities": [],
                "thirdPartyDistributionChannels": [],
            },
            "lifecycleState": "PUBLISHED",
            "isReshareDisabledByAuthor": False,
        }

        if article_url and article_url.strip():
            parsed_url = urllib.parse.urlsplit(article_url.strip())
            if parsed_url.scheme not in ("https", "http") or not parsed_url.netloc:
                raise LinkedInConfigError("article_url must be a valid HTTP(S) URL.")
            article_block: dict[str, str] = {"source": article_url.strip()}
            if article_title and article_title.strip():
                article_block["title"] = article_title.strip()
            payload["content"] = {"article": article_block}

        result = await self._transport.create_post(
            access_token,
            linkedin_version=linkedin_version,
            payload=payload,
        )
        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug="integrations",
            target_slug=account["slug"],
            event_type="linkedin.post.published",
            payload={
                "category": "reviews",
                "title": f"Published LinkedIn Post ({author_urn})",
                "badge": f"/rest/posts · v{linkedin_version}",
                "badge_tone": "emerald",
                "summary": clean_text[:240],
                "meta": f"Post URN: {result.get('post_urn') or 'created'}",
            },
            hop_count=1,
        )
        return {
            "slug": account["slug"],
            "author_urn": author_urn,
            "linkedin_version": linkedin_version,
            "endpoint": LINKEDIN_POSTS_URL,
            **result,
        }

    async def probe_account(self, slug: str) -> dict[str, Any]:
        """Verify stored LinkedIn token and transition health to ok | expired | degraded."""
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "linkedin":
            return self._repo.update_integration_health(
                account["slug"], status="ok", last_error=None
            )

        sec = account["secrets"]
        access_token = str(sec.get("access_token") or "").strip()
        version = str(sec.get("linkedin_version") or DEFAULT_LINKEDIN_VERSION)
        if not access_token:
            self._repo.update_integration_health(
                account["slug"],
                status="expired",
                last_error="Stored LinkedIn access_token is missing.",
            )
            raise LinkedInIntegrationError("Stored LinkedIn access_token is missing.", status_code=401)

        try:
            await self._transport.verify_token(access_token, linkedin_version=version)
            return self._repo.update_integration_health(
                account["slug"],
                status="ok",
                last_error=None,
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc), [access_token])
            status_code = getattr(exc, "status_code", None)
            is_expired = status_code == 401 or "401" in safe_err or "expired" in safe_err.lower()
            next_status = "expired" if is_expired else "degraded"
            self._repo.update_integration_health(
                account["slug"],
                status=next_status,
                last_error=safe_err,
            )
            raise LinkedInIntegrationError(safe_err, status_code=status_code) from exc
