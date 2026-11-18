"""Multi-account Google OAuth 2.0 Web Server connector using google-auth-oauthlib 1.5+."""

from __future__ import annotations

import asyncio
import base64
from email.message import EmailMessage
import hashlib
import inspect
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, make_id, slugify
from argo_core.security.vault import SecretVault, redact_secrets

GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
PENDING_STATE_COLLECTION = "oauth_pending_states"
PENDING_STATE_TTL_SECONDS = 900

GOOGLE_IDENTITY_SCOPES: tuple[str, ...] = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
)

GOOGLE_SCOPE_CATALOG: dict[str, dict[str, Any]] = {
    "gmail_read": {
        "label": "Gmail (Read-Only)",
        "description": "Ingest inbound threads, search messages, and read newsletter digests.",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    },
    "gmail_compose": {
        "label": "Gmail (Draft & Modify)",
        "description": "Create drafts queued via Approvals and apply labels.",
        "scopes": [
            "https://www.googleapis.com/auth/gmail.compose",
            "https://www.googleapis.com/auth/gmail.modify",
        ],
    },
    "calendar": {
        "label": "Google Calendar",
        "description": "Read schedules and manage approved calendar events.",
        "scopes": [
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/calendar.events",
        ],
    },
    "drive_docs": {
        "label": "Drive, Docs & Sheets (Read-Only)",
        "description": "Read Google Drive files, Docs notes, and spreadsheets via REST API.",
        "scopes": [
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/documents.readonly",
            "https://www.googleapis.com/auth/spreadsheets.readonly",
        ],
    },
    "meet": {
        "label": "Google Meet Artifacts (Read-Only)",
        "description": "Fetch meeting transcripts and recordings stored via Workspace API.",
        "scopes": ["https://www.googleapis.com/auth/meetings.space.readonly"],
    },
    "youtube_read": {
        "label": "YouTube Data API (Read-Only)",
        "description": "Read subscriptions, playlists, and channel metadata.",
        "scopes": ["https://www.googleapis.com/auth/youtube.readonly"],
    },
}


class GoogleOAuthConfigError(ValueError):
    """Raised when Google OAuth configuration, consent mode, or state parameters are invalid."""


class GoogleOAuthIntegrationError(RuntimeError):
    """Raised when Google OAuth token exchange or refresh verification fails."""


class GoogleOAuthTransport(Protocol):
    """Protocol implemented by google-auth-oauthlib / google-api-python-client or test doubles."""

    def build_authorization_url(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        state: str,
        code_verifier: str,
        login_hint: str | None = None,
    ) -> str:
        """Build an offline Google OAuth 2.0 consent URL with prompt=select_account consent."""

    async def exchange_code(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code: str,
        code_verifier: str,
        scopes: list[str],
    ) -> dict[str, Any]:
        """Exchange an authorization code for tokens and Google userinfo profile."""

    async def refresh_and_verify(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        token_uri: str = GOOGLE_TOKEN_URI,
    ) -> dict[str, Any]:
        """Refresh the offline token and verify the authorized Google identity."""


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _mask_client_id(client_id: str) -> str:
    cleaned = client_id.strip()
    if len(cleaned) <= 16:
        return "***"
    return f"{cleaned[:8]}...{cleaned[-22:]}" if len(cleaned) > 32 else f"{cleaned[:6]}...{cleaned[-6:]}"


def _resolve_scopes(
    scope_groups: list[str] | None,
    extra_scopes: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    selected_groups = list(scope_groups or ["gmail_read", "calendar"])
    unknown = [g for g in selected_groups if g not in GOOGLE_SCOPE_CATALOG]
    if unknown:
        raise GoogleOAuthConfigError(
            f"Unsupported Google scope group(s): {', '.join(sorted(unknown))}."
        )

    scopes: list[str] = list(GOOGLE_IDENTITY_SCOPES)
    for group in selected_groups:
        for scope in GOOGLE_SCOPE_CATALOG[group]["scopes"]:
            if scope not in scopes:
                scopes.append(scope)
    for raw_scope in extra_scopes or []:
        cleaned = raw_scope.strip()
        if cleaned and cleaned not in scopes:
            scopes.append(cleaned)
    return selected_groups, scopes


class DefaultGoogleOAuthTransport:
    """Production Google OAuth 2.0 transport via google-auth-oauthlib 1.5 & googleapiclient 2.202."""

    @staticmethod
    def _client_config(client_id: str, client_secret: str, redirect_uri: str) -> dict[str, Any]:
        return {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": GOOGLE_AUTH_URI,
                "token_uri": GOOGLE_TOKEN_URI,
                "redirect_uris": [redirect_uri],
            }
        }

    def build_authorization_url(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        state: str,
        code_verifier: str,
        login_hint: str | None = None,
    ) -> str:
        try:
            from google_auth_oauthlib.flow import Flow  # type: ignore[import-not-found]
        except ImportError:
            Flow = None

        if Flow is not None:
            flow = Flow.from_client_config(
                self._client_config(client_id, client_secret, redirect_uri),
                scopes=scopes,
            )
            flow.redirect_uri = redirect_uri
            flow.code_verifier = code_verifier
            kwargs: dict[str, Any] = {
                "access_type": "offline",
                "include_granted_scopes": "true",
                "prompt": "select_account consent",
                "state": state,
            }
            if login_hint:
                kwargs["login_hint"] = login_hint
            auth_url, _ = flow.authorization_url(**kwargs)
            return str(auth_url)

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "select_account consent",
            "code_challenge": _pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return f"{GOOGLE_AUTH_URI}?{urllib.parse.urlencode(params)}"

    @staticmethod
    def _http_form_post(url: str, data: dict[str, str], redact_list: list[str]) -> dict[str, Any]:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return dict(json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"Google OAuth HTTP {exc.code}: {err_body}",
                    redact_list,
                )
            ) from exc
        except Exception as exc:
            raise GoogleOAuthIntegrationError(
                redact_secrets(f"Google OAuth request failed: {exc}", redact_list)
            ) from exc

    @staticmethod
    def _http_get_userinfo(access_token: str, redact_list: list[str]) -> dict[str, Any]:
        req = urllib.request.Request(
            GOOGLE_USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return dict(json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"Google userinfo HTTP {exc.code}: {err_body}",
                    [*redact_list, access_token],
                )
            ) from exc
        except Exception as exc:
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"Google userinfo request failed: {exc}",
                    [*redact_list, access_token],
                )
            ) from exc

    @staticmethod
    def _http_gmail_json(
        method: str,
        url: str,
        access_token: str,
        body: dict[str, Any] | None = None,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        secrets_to_scrub = [*(redact_list or []), access_token]
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {access_token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=encoded_body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                return dict(json.loads(raw)) if raw else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"Gmail API HTTP {exc.code}: {err_body}",
                    secrets_to_scrub,
                )
            ) from exc
        except Exception as exc:
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"Gmail API request failed: {exc}",
                    secrets_to_scrub,
                )
            ) from exc

    @staticmethod
    def _build_raw_mime_message(
        *,
        to_email: str,
        subject: str,
        body_text: str,
        from_email: str | None = None,
        cc_email: str | None = None,
        in_reply_to: str | None = None,
    ) -> str:
        msg = EmailMessage()
        msg["To"] = to_email.strip()
        msg["Subject"] = subject.strip() or "(No subject)"
        if from_email and from_email.strip():
            msg["From"] = from_email.strip()
        if cc_email and cc_email.strip():
            msg["Cc"] = cc_email.strip()
        if in_reply_to and in_reply_to.strip():
            msg["In-Reply-To"] = in_reply_to.strip()
            msg["References"] = in_reply_to.strip()
        msg.set_content(body_text or "")
        return base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")

    async def search_gmail_messages(
        self,
        *,
        access_token: str,
        query: str = "",
        max_results: int = 10,
        redact_list: list[str] | None = None,
        exclude_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        capped = max(1, min(int(max_results), 25))
        excluded = {str(x).strip() for x in (exclude_ids or ()) if str(x).strip()}

        def _run_search() -> list[dict[str, Any]]:
            params: list[tuple[str, str]] = [("maxResults", str(capped))]
            if query.strip():
                params.append(("q", query.strip()))
            list_url = f"{GMAIL_API_BASE}/messages?{urllib.parse.urlencode(params)}"
            listing = self._http_gmail_json(
                "GET", list_url, access_token, redact_list=redact_list
            )
            refs = list(listing.get("messages") or [])
            results: list[dict[str, Any]] = []
            for item in refs[:capped]:
                msg_id = str(item.get("id") or "").strip()
                if not msg_id or msg_id in excluded:
                    continue
                detail_query = urllib.parse.urlencode(
                    [
                        ("format", "metadata"),
                        ("metadataHeaders", "From"),
                        ("metadataHeaders", "To"),
                        ("metadataHeaders", "Subject"),
                        ("metadataHeaders", "Date"),
                        ("metadataHeaders", "Message-ID"),
                    ]
                )
                detail = self._http_gmail_json(
                    "GET",
                    f"{GMAIL_API_BASE}/messages/{urllib.parse.quote(msg_id)}?{detail_query}",
                    access_token,
                    redact_list=redact_list,
                )
                payload = detail.get("payload") or {}
                headers_map = {
                    str(h.get("name") or "").lower(): str(h.get("value") or "")
                    for h in (payload.get("headers") or [])
                    if isinstance(h, dict)
                }
                results.append(
                    {
                        "id": msg_id,
                        "thread_id": detail.get("threadId") or item.get("threadId"),
                        "from": headers_map.get("from", ""),
                        "to": headers_map.get("to", ""),
                        "subject": headers_map.get("subject", "(No subject)"),
                        "date": headers_map.get("date", ""),
                        "message_id_header": headers_map.get("message-id", ""),
                        "snippet": str(detail.get("snippet") or ""),
                        "label_ids": list(detail.get("labelIds") or []),
                    }
                )
            return results

        return await asyncio.to_thread(_run_search)

    async def create_gmail_draft(
        self,
        *,
        access_token: str,
        to_email: str,
        subject: str,
        body_text: str,
        from_email: str | None = None,
        cc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        raw_mime = self._build_raw_mime_message(
            to_email=to_email,
            subject=subject,
            body_text=body_text,
            from_email=from_email,
            cc_email=cc_email,
            in_reply_to=in_reply_to,
        )
        message_obj: dict[str, Any] = {"raw": raw_mime}
        if thread_id and thread_id.strip():
            message_obj["threadId"] = thread_id.strip()

        def _run_draft() -> dict[str, Any]:
            res = self._http_gmail_json(
                "POST",
                f"{GMAIL_API_BASE}/drafts",
                access_token,
                body={"message": message_obj},
                redact_list=redact_list,
            )
            msg = res.get("message") or {}
            return {
                "draft_id": res.get("id"),
                "message_id": msg.get("id"),
                "thread_id": msg.get("threadId") or thread_id,
                "to": to_email,
                "subject": subject,
            }

        return await asyncio.to_thread(_run_draft)

    async def send_gmail_message(
        self,
        *,
        access_token: str,
        to_email: str,
        subject: str,
        body_text: str,
        from_email: str | None = None,
        cc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        raw_mime = self._build_raw_mime_message(
            to_email=to_email,
            subject=subject,
            body_text=body_text,
            from_email=from_email,
            cc_email=cc_email,
            in_reply_to=in_reply_to,
        )
        message_obj: dict[str, Any] = {"raw": raw_mime}
        if thread_id and thread_id.strip():
            message_obj["threadId"] = thread_id.strip()

        def _run_send() -> dict[str, Any]:
            res = self._http_gmail_json(
                "POST",
                f"{GMAIL_API_BASE}/messages/send",
                access_token,
                body=message_obj,
                redact_list=redact_list,
            )
            return {
                "message_id": res.get("id"),
                "thread_id": res.get("threadId") or thread_id,
                "label_ids": list(res.get("labelIds") or []),
                "to": to_email,
                "subject": subject,
            }

        return await asyncio.to_thread(_run_send)

    async def exchange_code(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code: str,
        code_verifier: str,
        scopes: list[str],
    ) -> dict[str, Any]:
        try:
            from google_auth_oauthlib.flow import Flow  # type: ignore[import-not-found]
            from googleapiclient.discovery import build  # type: ignore[import-not-found]
        except ImportError:
            Flow = None
            build = None

        if Flow is not None and build is not None:
            def _run_exchange() -> dict[str, Any]:
                try:
                    flow = Flow.from_client_config(
                        self._client_config(client_id, client_secret, redirect_uri),
                        scopes=scopes,
                    )
                    flow.redirect_uri = redirect_uri
                    flow.code_verifier = code_verifier
                    flow.fetch_token(code=code)
                    creds = flow.credentials
                    service = build("oauth2", "v2", credentials=creds, cache_discovery=False)
                    profile = service.userinfo().get().execute()
                    return {
                        "access_token": getattr(creds, "token", None),
                        "refresh_token": getattr(creds, "refresh_token", None),
                        "token_uri": getattr(creds, "token_uri", GOOGLE_TOKEN_URI),
                        "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None,
                        "email": profile.get("email"),
                        "name": profile.get("name"),
                    }
                except Exception as exc:
                    raise GoogleOAuthIntegrationError(
                        redact_secrets(
                            f"Google OAuth code exchange failed: {exc}",
                            [client_secret, code],
                        )
                    ) from exc

            return await asyncio.to_thread(_run_exchange)

        def _fallback_exchange() -> dict[str, Any]:
            tokens = self._http_form_post(
                GOOGLE_TOKEN_URI,
                {
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                    "code_verifier": code_verifier,
                },
                [client_secret, code],
            )
            access_token = str(tokens.get("access_token") or "")
            if not access_token:
                raise GoogleOAuthIntegrationError("Google token response omitted access_token.")
            profile = self._http_get_userinfo(access_token, [client_secret])
            return {
                "access_token": access_token,
                "refresh_token": tokens.get("refresh_token"),
                "token_uri": GOOGLE_TOKEN_URI,
                "expiry": None,
                "email": profile.get("email"),
                "name": profile.get("name"),
            }

        return await asyncio.to_thread(_fallback_exchange)

    async def refresh_and_verify(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        token_uri: str = GOOGLE_TOKEN_URI,
    ) -> dict[str, Any]:
        try:
            from google.auth.transport.requests import Request as GoogleAuthRequest  # type: ignore[import-not-found]
            from google.oauth2.credentials import Credentials  # type: ignore[import-not-found]
            from googleapiclient.discovery import build  # type: ignore[import-not-found]
        except ImportError:
            Credentials = None
            GoogleAuthRequest = None
            build = None

        if Credentials is not None and GoogleAuthRequest is not None and build is not None:
            def _run_refresh() -> dict[str, Any]:
                try:
                    creds = Credentials(
                        token=None,
                        refresh_token=refresh_token,
                        token_uri=token_uri,
                        client_id=client_id,
                        client_secret=client_secret,
                    )
                    creds.refresh(GoogleAuthRequest())
                    service = build("oauth2", "v2", credentials=creds, cache_discovery=False)
                    profile = service.userinfo().get().execute()
                    return {
                        "access_token": getattr(creds, "token", None),
                        "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None,
                        "email": profile.get("email"),
                    }
                except Exception as exc:
                    raise GoogleOAuthIntegrationError(
                        redact_secrets(
                            f"Google OAuth refresh failed: {exc}",
                            [client_secret, refresh_token],
                        )
                    ) from exc

            return await asyncio.to_thread(_run_refresh)

        def _fallback_refresh() -> dict[str, Any]:
            tokens = self._http_form_post(
                token_uri,
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
                [client_secret, refresh_token],
            )
            access_token = str(tokens.get("access_token") or "")
            if not access_token:
                raise GoogleOAuthIntegrationError("Google refresh response omitted access_token.")
            profile = self._http_get_userinfo(access_token, [client_secret, refresh_token])
            return {
                "access_token": access_token,
                "expiry": None,
                "email": profile.get("email"),
            }

        return await asyncio.to_thread(_fallback_refresh)


class GoogleOAuthService:
    """Manages multi-account Google OAuth 2.0 onboarding, token probes, and Gmail actions."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        bus: EventBus,
        vault: SecretVault,
        transport: GoogleOAuthTransport | None = None,
        default_client_id: str = "",
        default_client_secret: str = "",
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._vault = vault
        self._transport: GoogleOAuthTransport = transport or DefaultGoogleOAuthTransport()
        self._default_client_id = default_client_id.strip()
        self._default_client_secret = default_client_secret.strip()

    @staticmethod
    def redirect_uri(public_base_url: str) -> str:
        """Build the authorized OAuth redirect URI under the public origin."""
        return f"{public_base_url.rstrip('/')}/api/integrations/google/callback"

    def _find_server_client(self) -> tuple[str, str] | None:
        if self._default_client_id and self._default_client_secret:
            return self._default_client_id, self._default_client_secret
        return None

    @staticmethod
    def _is_consumer_gmail_address(value: str | None) -> bool:
        cleaned = (value or "").strip().lower()
        return cleaned.endswith("@gmail.com") or cleaned.endswith("@googlemail.com")

    def _saved_client_accounts(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for account in self._repo.list_integrations_by_provider("google"):
            sec = account["secrets"]
            cid = str(sec.get("client_id") or "").strip()
            csec = str(sec.get("client_secret") or "").strip()
            if cid and csec:
                results.append(account)
        return results

    def _find_saved_client(
        self,
        *,
        preferred_slug: str | None = None,
        login_hint: str | None = None,
        display_name: str | None = None,
    ) -> tuple[str, str] | None:
        accounts = self._saved_client_accounts()

        if preferred_slug and preferred_slug.strip():
            norm_slug = slugify(preferred_slug)
            hint_lower = (login_hint or "").strip().lower()
            for account in accounts:
                if account["slug"] == norm_slug:
                    acct_ident = str(account.get("account_identifier") or "").strip().lower()
                    if not hint_lower or not acct_ident or acct_ident == hint_lower:
                        sec = account["secrets"]
                        return str(sec["client_id"]).strip(), str(sec["client_secret"]).strip()

        trimmed_hint = (login_hint or "").strip()
        has_non_gmail_hint = "@" in trimmed_hint and not self._is_consumer_gmail_address(trimmed_hint)
        is_consumer_gmail = self._is_consumer_gmail_address(trimmed_hint) or (
            not has_non_gmail_hint
            and (
                (bool(preferred_slug and preferred_slug.strip()) and slugify(preferred_slug) == "personal-gmail")
                or "personal" in (display_name or "").strip().lower()
            )
        )
        if is_consumer_gmail:
            for account in reversed(accounts):
                if self._is_consumer_gmail_address(account.get("account_identifier")):
                    sec = account["secrets"]
                    return str(sec["client_id"]).strip(), str(sec["client_secret"]).strip()
            server_client = self._find_server_client()
            if server_client is not None:
                return server_client
        else:
            for account in reversed(accounts):
                if not self._is_consumer_gmail_address(account.get("account_identifier")):
                    sec = account["secrets"]
                    return str(sec["client_id"]).strip(), str(sec["client_secret"]).strip()
            server_client = self._find_server_client()
            if server_client is not None:
                return server_client

        for account in reversed(accounts):
            sec = account["secrets"]
            return str(sec["client_id"]).strip(), str(sec["client_secret"]).strip()
        return self._find_server_client()

    def get_wizard_config(self, public_base_url: str) -> dict[str, Any]:
        """Return Google OAuth onboarding metadata and any saved/server client ID hint."""
        saved = self._find_saved_client()
        server_client = self._find_server_client()
        saved_accounts = self._saved_client_accounts()
        personal_account = next(
            (
                acc
                for acc in reversed(saved_accounts)
                if self._is_consumer_gmail_address(acc.get("account_identifier"))
            ),
            None,
        )
        workspace_account = next(
            (
                acc
                for acc in reversed(saved_accounts)
                if not self._is_consumer_gmail_address(acc.get("account_identifier"))
            ),
            None,
        )
        has_personal_gmail_client = personal_account is not None
        personal_client_id_hint = (
            _mask_client_id(str(personal_account["secrets"]["client_id"]).strip())
            if personal_account is not None
            else None
        )
        workspace_client_id_hint = (
            _mask_client_id(str(server_client[0]).strip())
            if server_client is not None
            else (
                _mask_client_id(str(workspace_account["secrets"]["client_id"]).strip())
                if workspace_account is not None
                else None
            )
        )
        return {
            "redirect_uri": self.redirect_uri(public_base_url),
            "has_saved_client": saved is not None,
            "saved_client_id_hint": _mask_client_id(saved[0]) if saved else None,
            "has_server_client": server_client is not None,
            "server_client_id_hint": _mask_client_id(server_client[0]) if server_client else None,
            "has_personal_gmail_client": has_personal_gmail_client,
            "personal_client_id_hint": personal_client_id_hint,
            "workspace_client_id_hint": workspace_client_id_hint,
            "saved_accounts": [
                {
                    "slug": acc["slug"],
                    "display_name": acc["display_name"],
                    "account_identifier": acc.get("account_identifier"),
                    "client_id_hint": _mask_client_id(str(acc["secrets"]["client_id"]).strip()),
                }
                for acc in saved_accounts
            ],
            "required_oauth_params": {
                "access_type": "offline",
                "include_granted_scopes": "true",
                "prompt": "select_account consent",
                "pkce": "S256",
            },
            "steps": [
                {
                    "step": 1,
                    "title": "Google Cloud Consent Mode ('In Production')",
                    "summary": (
                        "Publish the OAuth consent screen to 'In Production' mode so offline "
                        "refresh tokens do not expire after 7 days."
                    ),
                },
                {
                    "step": 2,
                    "title": "OAuth Client Credentials & Redirect URI",
                    "summary": (
                        "Paste the Web Application Client ID and Client Secret, and add the "
                        "exact Redirect URI shown below."
                    ),
                },
                {
                    "step": 3,
                    "title": "Account Label & API Scopes",
                    "summary": (
                        "Choose read/draft scopes for Gmail, Calendar, Drive, Docs, Sheets, or Meet."
                    ),
                },
                {
                    "step": 4,
                    "title": "Select Google Account & Authorize",
                    "summary": (
                        "Google forces prompt=select_account consent so personal and Workspace "
                        "accounts authorize independently into the encrypted SQLite vault."
                    ),
                },
            ],
            "scope_catalog": [
                {
                    "key": key,
                    "label": entry["label"],
                    "description": entry["description"],
                    "scopes": entry["scopes"],
                }
                for key, entry in GOOGLE_SCOPE_CATALOG.items()
            ],
        }

    def start_authorization(
        self,
        *,
        public_base_url: str,
        in_production_confirmed: bool,
        client_id: str | None = None,
        client_secret: str | None = None,
        reuse_saved_client: bool = False,
        slug: str | None = None,
        display_name: str | None = None,
        login_hint: str | None = None,
        scope_groups: list[str] | None = None,
        extra_scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Step 1-3 validation -> generate PKCE + encrypted state -> return Google consent URL."""
        if not in_production_confirmed:
            raise GoogleOAuthConfigError(
                "Google Cloud OAuth consent screen must be set to 'In Production' mode "
                "to avoid 7-day testing token expiry."
            )

        resolved_cid = (client_id or "").strip()
        resolved_csec = (client_secret or "").strip()
        if (not resolved_cid or not resolved_csec) and (
            reuse_saved_client or self._find_server_client() is not None
        ):
            saved = self._find_saved_client(
                preferred_slug=slug,
                login_hint=login_hint,
                display_name=display_name,
            )
            if saved is not None:
                resolved_cid, resolved_csec = saved

        if not resolved_cid or not resolved_csec:
            raise GoogleOAuthConfigError(
                "Google OAuth client_id and client_secret are required unless reusing saved credentials."
            )

        selected_groups, full_scopes = _resolve_scopes(scope_groups, extra_scopes)
        resolved_redirect = self.redirect_uri(public_base_url)
        state = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48)

        pending_payload = {
            "client_id": resolved_cid,
            "client_secret": resolved_csec,
            "redirect_uri": resolved_redirect,
            "code_verifier": code_verifier,
            "scopes": full_scopes,
            "scope_groups": selected_groups,
            "slug": slug.strip() if slug and slug.strip() else None,
            "display_name": display_name.strip() if display_name and display_name.strip() else None,
            "login_hint": login_hint.strip() if login_hint and login_hint.strip() else None,
            "in_production_confirmed": True,
        }
        encrypted_state = self._vault.encrypt_json(pending_payload).decode("ascii")
        self._repo.upsert_document(
            collection=PENDING_STATE_COLLECTION,
            external_key=state,
            search_text=f"google oauth pending {slug or ''} {login_hint or ''}",
            doc={
                "encrypted_state": encrypted_state,
                "consumed": False,
                "created_epoch": int(time.time()),
            },
            description="Ephemeral encrypted OAuth 2.0 CSRF/PKCE state records",
        )

        auth_url = self._transport.build_authorization_url(
            client_id=resolved_cid,
            client_secret=resolved_csec,
            redirect_uri=resolved_redirect,
            scopes=full_scopes,
            state=state,
            code_verifier=code_verifier,
            login_hint=pending_payload["login_hint"],
        )
        return {
            "authorization_url": auth_url,
            "state": state,
            "redirect_uri": resolved_redirect,
            "scope_groups": selected_groups,
            "scopes": full_scopes,
            "expires_in_seconds": PENDING_STATE_TTL_SECONDS,
        }

    async def complete_callback(
        self,
        *,
        code: str | None,
        state: str | None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Step 4: verify CSRF state once, exchange authorization code, and store encrypted tokens."""
        if error and error.strip():
            raise GoogleOAuthIntegrationError(
                f"Google authorization declined or failed: {error.strip()}"
            )

        clean_state = (state or "").strip()
        clean_code = (code or "").strip()
        if not clean_state or not clean_code:
            raise GoogleOAuthConfigError("Missing required OAuth 'code' or 'state' parameter.")

        state_doc = self._repo.get_document_by_external_key(PENDING_STATE_COLLECTION, clean_state)
        if state_doc is None:
            raise GoogleOAuthConfigError("Invalid or unrecognized Google OAuth state.")

        doc_body = state_doc["doc"]
        if doc_body.get("consumed"):
            raise GoogleOAuthConfigError("Google OAuth state has already been consumed.")

        created_epoch = int(doc_body.get("created_epoch") or 0)
        if int(time.time()) - created_epoch > PENDING_STATE_TTL_SECONDS:
            raise GoogleOAuthConfigError("Google OAuth authorization state expired.")

        # Mark state consumed immediately before token exchange to block replay attempts.
        self._repo.upsert_document(
            collection=PENDING_STATE_COLLECTION,
            external_key=clean_state,
            search_text=state_doc["search_text"],
            doc={
                **doc_body,
                "consumed": True,
                "consumed_epoch": int(time.time()),
            },
            description="Ephemeral encrypted OAuth 2.0 CSRF/PKCE state records",
        )

        pending = self._vault.decrypt_json(str(doc_body["encrypted_state"]).encode("ascii"))
        client_id = str(pending["client_id"])
        client_secret = str(pending["client_secret"])
        redirect_uri = str(pending["redirect_uri"])
        code_verifier = str(pending["code_verifier"])
        scopes = [str(s) for s in pending.get("scopes", [])]
        scope_groups = [str(g) for g in pending.get("scope_groups", [])]

        token_data = await self._transport.exchange_code(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code=clean_code,
            code_verifier=code_verifier,
            scopes=scopes,
        )

        email = str(token_data.get("email") or pending.get("login_hint") or "").strip()
        if not email:
            raise GoogleOAuthIntegrationError(
                "Google OAuth userinfo response did not include an email address."
            )

        requested_slug = pending.get("slug")
        requested_display = str(pending.get("display_name") or "").strip()
        if requested_slug:
            base_slug = slugify(str(requested_slug))
            target_slug = base_slug
        elif requested_display:
            base_slug = slugify(requested_display)
            target_slug = base_slug
        else:
            base_slug = slugify(f"google-{email}")
            target_slug = base_slug

        existing_same = self._repo.find_integration_secrets(target_slug)
        if existing_same and existing_same.get("account_identifier") not in ("", None, email):
            email_local = slugify(email.split("@", 1)[0])
            candidate_slug = slugify(f"{base_slug}-{email_local}")
            existing_candidate = self._repo.find_integration_secrets(candidate_slug)
            if existing_candidate and existing_candidate.get("account_identifier") not in ("", None, email):
                target_slug = slugify(f"{base_slug}-{email}")
            else:
                target_slug = candidate_slug

        refresh_token = str(token_data.get("refresh_token") or "").strip()
        if not refresh_token:
            for existing in self._repo.list_integrations_by_provider("google"):
                if existing["slug"] == target_slug or existing.get("account_identifier") == email:
                    refresh_token = str(existing["secrets"].get("refresh_token") or "").strip()
                    break

        if not refresh_token:
            raise GoogleOAuthConfigError(
                "Google did not return an offline refresh_token; ensure "
                "prompt='select_account consent' and access_type='offline'."
            )

        display_name = (
            str(pending.get("display_name") or "").strip()
            or str(token_data.get("name") or "").strip()
            or email
        )
        stored_scopes = scope_groups or scopes
        record = self._repo.upsert_integration(
            slug=target_slug,
            provider="google",
            display_name=display_name,
            account_identifier=email,
            scopes=stored_scopes,
            secrets={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "access_token": token_data.get("access_token"),
                "token_uri": token_data.get("token_uri") or GOOGLE_TOKEN_URI,
                "token_expiry": token_data.get("expiry"),
                "granted_scopes": scopes,
                "redirect_uri": redirect_uri,
                "in_production_confirmed": True,
            },
            status="ok",
        )

        await self._bus.publish(
            correlation_id=make_id("corr"),
            source_slug="integrations",
            target_slug=record["slug"],
            event_type="integration.google.connected",
            payload={
                "category": "alerts",
                "title": f"Connected Google Account {email}",
                "badge": "OAuth 2.0 · Offline Valid",
                "badge_tone": "emerald",
                "summary": (
                    f"Authorized {email} ({record['slug']}) with scopes: "
                    f"{', '.join(stored_scopes)}."
                ),
                "meta": "google-auth-oauthlib · In Production mode",
            },
            hop_count=1,
        )
        return record

    async def probe_account(self, slug: str) -> dict[str, Any]:
        """Refresh and verify stored Google OAuth credentials; update SQLite health state."""
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "google":
            return self._repo.update_integration_health(
                account["slug"], status="ok", last_error=None
            )

        sec = account["secrets"]
        client_id = str(sec.get("client_id") or "").strip()
        client_secret = str(sec.get("client_secret") or "").strip()
        refresh_token = str(sec.get("refresh_token") or "").strip()
        token_uri = str(sec.get("token_uri") or GOOGLE_TOKEN_URI)

        if not client_id or not client_secret or not refresh_token:
            self._repo.update_integration_health(
                account["slug"],
                status="expired",
                last_error="Stored Google OAuth refresh credentials are incomplete.",
            )
            raise GoogleOAuthIntegrationError(
                "Stored Google OAuth refresh credentials are incomplete."
            )

        try:
            refreshed = await self._transport.refresh_and_verify(
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
                token_uri=token_uri,
            )
            self._repo.upsert_integration(
                slug=account["slug"],
                provider="google",
                display_name=account["display_name"],
                account_identifier=str(refreshed.get("email") or account["account_identifier"] or ""),
                scopes=account["scopes"],
                secrets={
                    "access_token": refreshed.get("access_token"),
                    "token_expiry": refreshed.get("expiry"),
                },
                status="ok",
            )
            return self._repo.update_integration_health(
                account["slug"],
                status="ok",
                last_error=None,
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc), [client_secret, refresh_token])
            lowered = safe_err.lower()
            next_status = "expired" if ("invalid_grant" in lowered or "401" in lowered) else "degraded"
            self._repo.update_integration_health(
                account["slug"],
                status=next_status,
                last_error=safe_err,
            )
            raise GoogleOAuthIntegrationError(safe_err) from exc

    async def _ensure_access_token(
        self,
        slug: str,
        *,
        force_refresh: bool = False,
    ) -> tuple[dict[str, Any], str, list[str]]:
        account = self._repo.get_integration_secrets(slug)
        if account["provider"] != "google":
            raise GoogleOAuthConfigError(f"Integration '{slug}' is not a Google account.")
        sec = account.get("secrets") or {}
        client_id = str(sec.get("client_id") or "").strip()
        client_secret = str(sec.get("client_secret") or "").strip()
        refresh_token = str(sec.get("refresh_token") or "").strip()
        access_token = str(sec.get("access_token") or "").strip()
        token_uri = str(sec.get("token_uri") or GOOGLE_TOKEN_URI)
        redact_list = [s for s in (client_secret, refresh_token, access_token) if s]

        if access_token and not force_refresh:
            return account, access_token, redact_list

        if not client_id or not client_secret or not refresh_token:
            raise GoogleOAuthIntegrationError(
                f"Google account '{account['slug']}' lacks refresh credentials; please reconnect it."
            )

        refreshed = await self._transport.refresh_and_verify(
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
            token_uri=token_uri,
        )
        new_token = str(refreshed.get("access_token") or "").strip()
        if not new_token:
            raise GoogleOAuthIntegrationError(
                f"Google token refresh for '{account['slug']}' returned no access_token."
            )
        self._repo.upsert_integration(
            slug=account["slug"],
            provider="google",
            display_name=account["display_name"],
            account_identifier=str(refreshed.get("email") or account.get("account_identifier") or ""),
            scopes=account["scopes"],
            secrets={
                "access_token": new_token,
                "token_expiry": refreshed.get("expiry"),
            },
            status="ok",
        )
        redact_list.append(new_token)
        return account, new_token, redact_list

    async def _with_fresh_token(self, slug: str, fn: Any) -> Any:
        account, access_token, redact_list = await self._ensure_access_token(slug, force_refresh=False)
        try:
            return await fn(account, access_token, redact_list)
        except GoogleOAuthIntegrationError as exc:
            if "401" not in str(exc):
                raise
            account, access_token, redact_list = await self._ensure_access_token(
                slug, force_refresh=True
            )
            return await fn(account, access_token, redact_list)

    async def search_messages(
        self,
        slug: str,
        *,
        query: str = "",
        max_results: int = 10,
        exclude_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Search Gmail messages on an authorized Google integration."""
        search_fn = getattr(self._transport, "search_gmail_messages", None)
        if search_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Gmail search.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            call_kwargs: dict[str, Any] = {
                "access_token": token,
                "query": query,
                "max_results": max_results,
                "redact_list": redact_list,
            }
            if exclude_ids is not None:
                try:
                    sig = inspect.signature(search_fn)
                    accepts_var_kw = any(
                        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                    )
                    if accepts_var_kw or "exclude_ids" in sig.parameters:
                        call_kwargs["exclude_ids"] = exclude_ids
                except (TypeError, ValueError):
                    pass
            messages = await search_fn(**call_kwargs)
            if exclude_ids:
                excluded = {str(x).strip() for x in exclude_ids if str(x).strip()}
                messages = [
                    m for m in messages if str((m or {}).get("id") or "").strip() not in excluded
                ]
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                "query": query,
                "messages": messages,
            }

        return await self._with_fresh_token(slug, _call)

    async def create_draft(
        self,
        slug: str,
        *,
        to_email: str,
        subject: str,
        body_text: str,
        cc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Create a Gmail Draft so operators can also review/edit directly inside Gmail."""
        draft_fn = getattr(self._transport, "create_gmail_draft", None)
        if draft_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Gmail drafts.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            res = await draft_fn(
                access_token=token,
                to_email=to_email,
                subject=subject,
                body_text=body_text,
                from_email=account.get("account_identifier"),
                cc_email=cc_email,
                thread_id=thread_id,
                in_reply_to=in_reply_to,
                redact_list=redact_list,
            )
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                **res,
            }

        return await self._with_fresh_token(slug, _call)

    async def send_email(
        self,
        slug: str,
        *,
        to_email: str,
        subject: str,
        body_text: str,
        cc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Send an email via Gmail REST API v1 on an authorized Google integration."""
        send_fn = getattr(self._transport, "send_gmail_message", None)
        if send_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Gmail sending.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            res = await send_fn(
                access_token=token,
                to_email=to_email,
                subject=subject,
                body_text=body_text,
                from_email=account.get("account_identifier"),
                cc_email=cc_email,
                thread_id=thread_id,
                in_reply_to=in_reply_to,
                redact_list=redact_list,
            )
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                **res,
            }

        return await self._with_fresh_token(slug, _call)
