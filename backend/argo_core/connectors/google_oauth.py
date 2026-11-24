"""Multi-account Google OAuth 2.0 Web Server connector using google-auth-oauthlib 1.5+."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
import hashlib
import html
import inspect
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Protocol

from argo_core.analytics.engine import extract_document_summary_from_bytes
from argo_core.bus.valkey_bus import EventBus
from argo_core.db.repositories import ArgoRepository, make_id, slugify
from argo_core.security.tenancy import normalize_email
from argo_core.security.vault import SecretVault, redact_secrets

GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"
CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3"
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
    def _http_google_bytes(
        method: str,
        url: str,
        access_token: str,
        *,
        service_label: str = "Google API",
        body: dict[str, Any] | None = None,
        redact_list: list[str] | None = None,
        max_bytes: int = 16_777_216,
        allow_truncate: bool = False,
    ) -> bytes:
        secrets_to_scrub = [*(redact_list or []), access_token]
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {access_token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=encoded_body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if allow_truncate:
                    return resp.read(max_bytes)
                raw = resp.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raise GoogleOAuthIntegrationError(
                        f"{service_label} response exceeded {max_bytes} byte limit."
                    )
                return raw
        except GoogleOAuthIntegrationError:
            raise
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"{service_label} HTTP {exc.code}: {err_body}",
                    secrets_to_scrub,
                )
            ) from exc
        except Exception as exc:
            raise GoogleOAuthIntegrationError(
                redact_secrets(
                    f"{service_label} request failed: {exc}",
                    secrets_to_scrub,
                )
            ) from exc

    @classmethod
    def _http_google_json(
        cls,
        method: str,
        url: str,
        access_token: str,
        *,
        service_label: str = "Google API",
        body: dict[str, Any] | None = None,
        redact_list: list[str] | None = None,
        max_bytes: int = 16_777_216,
    ) -> dict[str, Any]:
        raw_bytes = cls._http_google_bytes(
            method,
            url,
            access_token,
            service_label=service_label,
            body=body,
            redact_list=redact_list,
            max_bytes=max_bytes,
            allow_truncate=False,
        )
        raw = raw_bytes.decode("utf-8", errors="replace")
        return dict(json.loads(raw)) if raw.strip() else {}

    @classmethod
    def _http_gmail_json(
        cls,
        method: str,
        url: str,
        access_token: str,
        body: dict[str, Any] | None = None,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        return cls._http_google_json(
            method,
            url,
            access_token,
            service_label="Gmail API",
            body=body,
            redact_list=redact_list,
        )

    @staticmethod
    def _decode_base64url_text(raw: str) -> str:
        cleaned = (raw or "").strip()
        if not cleaned:
            return ""
        pad = "=" * (-len(cleaned) % 4)
        try:
            return base64.urlsafe_b64decode(cleaned + pad).decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _strip_html_text(raw_html: str) -> str:
        if not raw_html:
            return ""
        no_scripts = re.sub(
            r"<(script|style)\b[^>]*>.*?</\1>",
            " ",
            raw_html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        no_tags = re.sub(r"<[^>]+>", " ", no_scripts)
        unescaped = html.unescape(no_tags)
        return re.sub(r"\s+", " ", unescaped).strip()

    @classmethod
    def _extract_mime_parts(
        cls,
        payload: dict[str, Any],
    ) -> tuple[str, list[dict[str, Any]]]:
        plain_texts: list[str] = []
        html_texts: list[str] = []
        attachments: list[dict[str, Any]] = []

        def _walk(part: dict[str, Any]) -> None:
            if not isinstance(part, dict):
                return
            mime_type = str(part.get("mimeType") or "").strip().lower()
            filename = str(part.get("filename") or "").strip()
            body = part.get("body") if isinstance(part.get("body"), dict) else {}
            attachment_id = str(body.get("attachmentId") or "").strip()
            part_id = str(part.get("partId") or "").strip()

            if (filename or attachment_id) and not mime_type.startswith("multipart/"):
                attachments.append(
                    {
                        "filename": filename or f"attachment-{part_id or len(attachments) + 1}",
                        "mime_type": mime_type or "application/octet-stream",
                        "size_bytes": int(body.get("size") or 0),
                        "part_id": part_id,
                    }
                )
            elif body.get("data") and not mime_type.startswith("multipart/"):
                decoded = cls._decode_base64url_text(str(body.get("data") or ""))
                if decoded:
                    if mime_type == "text/html":
                        html_texts.append(decoded)
                    elif mime_type == "text/plain" or not mime_type:
                        plain_texts.append(decoded)

            for child in part.get("parts") or []:
                if isinstance(child, dict):
                    _walk(child)

        _walk(payload)
        raw_body = "\n".join(t.strip() for t in plain_texts if t.strip()).strip()
        if not raw_body and html_texts:
            raw_body = cls._strip_html_text("\n".join(html_texts))
        return raw_body, attachments

    @staticmethod
    def _build_raw_mime_message(
        *,
        to_email: str,
        subject: str,
        body_text: str,
        from_email: str | None = None,
        cc_email: str | None = None,
        bcc_email: str | None = None,
        in_reply_to: str | None = None,
    ) -> str:
        msg = EmailMessage()
        msg["To"] = to_email.strip()
        msg["Subject"] = subject.strip() or "(No subject)"
        if from_email and from_email.strip():
            msg["From"] = from_email.strip()
        if cc_email and cc_email.strip():
            msg["Cc"] = cc_email.strip()
        if bcc_email and bcc_email.strip():
            msg["Bcc"] = bcc_email.strip()
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
        secrets_to_scrub = [*(redact_list or []), access_token]

        def _run_search() -> list[dict[str, Any]]:
            results: list[dict[str, Any]] = []
            page_token = ""
            for _page in range(5):
                params: list[tuple[str, str]] = [("maxResults", str(min(50, max(capped * 2, capped))))]
                if query.strip():
                    params.append(("q", query.strip()))
                if page_token:
                    params.append(("pageToken", page_token))
                list_url = f"{GMAIL_API_BASE}/messages?{urllib.parse.urlencode(params)}"
                listing = self._http_gmail_json(
                    "GET", list_url, access_token, redact_list=redact_list
                )
                refs = list(listing.get("messages") or [])
                if not refs:
                    break
                for item in refs:
                    if len(results) >= capped:
                        break
                    msg_id = str(item.get("id") or "").strip()
                    if not msg_id or msg_id in excluded:
                        continue
                    excluded.add(msg_id)
                    detail_query = urllib.parse.urlencode([("format", "full")])
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
                    raw_internal_date = detail.get("internalDate")
                    try:
                        internal_date_ms = (
                            int(raw_internal_date)
                            if raw_internal_date is not None and str(raw_internal_date).strip()
                            else None
                        )
                    except (TypeError, ValueError):
                        internal_date_ms = None
                    label_ids = [str(lbl) for lbl in (detail.get("labelIds") or [])]
                    body_raw, attachments = self._extract_mime_parts(payload)
                    body_excerpt = redact_secrets(body_raw, secrets_to_scrub)[:4000]
                    results.append(
                        {
                            "id": msg_id,
                            "thread_id": detail.get("threadId") or item.get("threadId"),
                            "from": redact_secrets(headers_map.get("from", ""), secrets_to_scrub),
                            "to": redact_secrets(headers_map.get("to", ""), secrets_to_scrub),
                            "cc": redact_secrets(headers_map.get("cc", ""), secrets_to_scrub),
                            "bcc": redact_secrets(headers_map.get("bcc", ""), secrets_to_scrub),
                            "reply_to": redact_secrets(headers_map.get("reply-to", ""), secrets_to_scrub),
                            "subject": redact_secrets(headers_map.get("subject", "(No subject)"), secrets_to_scrub),
                            "date": headers_map.get("date", ""),
                            "message_id_header": headers_map.get("message-id", ""),
                            "in_reply_to": headers_map.get("in-reply-to", ""),
                            "internal_date_ms": internal_date_ms,
                            "size_estimate": int(detail.get("sizeEstimate") or 0),
                            "label_ids": label_ids,
                            "is_unread": "UNREAD" in label_ids,
                            "history_id": str(detail.get("historyId") or ""),
                            "has_attachments": bool(attachments),
                            "attachments": attachments,
                            "body_excerpt": body_excerpt,
                            "snippet": redact_secrets(str(detail.get("snippet") or ""), secrets_to_scrub),
                        }
                    )
                page_token = str(listing.get("nextPageToken") or "").strip()
                if len(results) >= capped or not page_token:
                    break
            return results

        return await asyncio.to_thread(_run_search)

    async def search_drive_files(
        self,
        *,
        access_token: str,
        query: str = "",
        page_size: int = 25,
        page_token: str | None = None,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        capped = max(1, min(int(page_size), 50))
        secrets_to_scrub = [*(redact_list or []), access_token]

        def _run_drive_search() -> dict[str, Any]:
            fields = (
                "nextPageToken,files(id,name,mimeType,size,createdTime,modifiedTime,"
                "viewedByMeTime,shared,starred,trashed,owners(displayName,emailAddress),"
                "lastModifyingUser(displayName,emailAddress),parents,webViewLink,iconLink,description)"
            )
            params: list[tuple[str, str]] = [
                ("supportsAllDrives", "true"),
                ("includeItemsFromAllDrives", "true"),
                ("pageSize", str(capped)),
                ("fields", fields),
            ]
            if query.strip():
                params.append(("q", query.strip()))
            if page_token and page_token.strip():
                params.append(("pageToken", page_token.strip()))
            url = f"{DRIVE_API_BASE}/files?{urllib.parse.urlencode(params)}"
            listing = self._http_google_json(
                "GET",
                url,
                access_token,
                service_label="Google Drive API",
                redact_list=redact_list,
            )
            files_out: list[dict[str, Any]] = []
            for item in listing.get("files") or []:
                if not isinstance(item, dict):
                    continue
                cleaned = dict(item)
                if "description" in cleaned and cleaned["description"] is not None:
                    cleaned["description"] = redact_secrets(
                        str(cleaned["description"]), secrets_to_scrub
                    )[:1000]
                files_out.append(cleaned)
            return {
                "files": files_out,
                "next_page_token": listing.get("nextPageToken"),
            }

        return await asyncio.to_thread(_run_drive_search)

    async def read_drive_file_excerpt(
        self,
        *,
        access_token: str,
        file_id: str,
        mime_type: str | None = None,
        max_chars: int = 16000,
        redact_list: list[str] | None = None,
    ) -> dict[str, Any]:
        clean_id = file_id.strip()
        if not clean_id:
            raise GoogleOAuthConfigError("Missing required Drive file_id.")
        capped_chars = max(200, min(int(max_chars), 16000))
        secrets_to_scrub = [*(redact_list or []), access_token]

        def _run_drive_read() -> dict[str, Any]:
            meta_url = (
                f"{DRIVE_API_BASE}/files/{urllib.parse.quote(clean_id)}"
                "?supportsAllDrives=true"
                "&fields=id,name,mimeType,size,createdTime,modifiedTime,"
                "owners(displayName,emailAddress),webViewLink,description"
            )
            meta = self._http_google_json(
                "GET",
                meta_url,
                access_token,
                service_label="Google Drive API",
                redact_list=redact_list,
            )
            resolved_mime = str(meta.get("mimeType") or mime_type or "").strip()
            file_name = str(meta.get("name") or "")
            export_map = {
                "application/vnd.google-apps.document": "text/plain",
                "application/vnd.google-apps.spreadsheet": "text/csv",
                "application/vnd.google-apps.presentation": "text/plain",
            }
            excerpt = ""
            page_count: int | None = None
            scanned_pages: list[int] = []
            tables_preview: list[dict[str, Any]] = []
            row_count: int | None = None

            binary_doc_mimes = {
                "application/pdf",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.ms-excel.sheet.macroenabled.12",
                "application/vnd.ms-excel.sheet.binary.macroenabled.12",
                "application/vnd.ms-excel",
                "application/vnd.oasis.opendocument.spreadsheet",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/parquet",
                "application/vnd.apache.parquet",
            }
            binary_doc_exts = (".pdf", ".xlsx", ".xlsm", ".xlsb", ".xls", ".ods", ".docx", ".parquet")

            if resolved_mime in export_map:
                export_mime = export_map[resolved_mime]
                export_url = (
                    f"{DRIVE_API_BASE}/files/{urllib.parse.quote(clean_id)}/export"
                    f"?{urllib.parse.urlencode([('mimeType', export_mime)])}"
                )
                raw_bytes = self._http_google_bytes(
                    "GET",
                    export_url,
                    access_token,
                    service_label="Google Drive Export",
                    redact_list=redact_list,
                    max_bytes=262_144,
                    allow_truncate=True,
                )
                excerpt = raw_bytes.decode("utf-8", errors="replace")
            elif resolved_mime in binary_doc_mimes or file_name.lower().endswith(binary_doc_exts):
                media_url = (
                    f"{DRIVE_API_BASE}/files/{urllib.parse.quote(clean_id)}"
                    "?alt=media&supportsAllDrives=true"
                )
                raw_bytes = self._http_google_bytes(
                    "GET",
                    media_url,
                    access_token,
                    service_label="Google Drive Document Download",
                    redact_list=redact_list,
                    max_bytes=100 * 1024 * 1024,
                    allow_truncate=False,
                )
                fallback_name = file_name or (
                    f"{clean_id}.pdf"
                    if resolved_mime == "application/pdf"
                    else f"{clean_id}.xlsx"
                )
                parsed_doc = extract_document_summary_from_bytes(
                    raw_bytes,
                    filename=fallback_name,
                    mime_type=resolved_mime,
                    vault_secrets=secrets_to_scrub,
                    max_chars=capped_chars,
                )
                excerpt = str(parsed_doc.get("excerpt") or "")
                page_count = parsed_doc.get("page_count")
                scanned_pages = list(parsed_doc.get("scanned_pages") or [])
                tables_preview = list(parsed_doc.get("tables_preview") or [])
                row_count = parsed_doc.get("row_count")
            elif (
                resolved_mime.startswith("text/")
                or resolved_mime
                in {
                    "application/json",
                    "application/xml",
                    "application/csv",
                    "application/x-yaml",
                    "application/javascript",
                }
                or file_name.lower().endswith(
                    (".txt", ".md", ".csv", ".tsv", ".json", ".yaml", ".yml", ".log", ".xml", ".sql", ".py", ".ts")
                )
            ):
                media_url = (
                    f"{DRIVE_API_BASE}/files/{urllib.parse.quote(clean_id)}"
                    "?alt=media&supportsAllDrives=true"
                )
                raw_bytes = self._http_google_bytes(
                    "GET",
                    media_url,
                    access_token,
                    service_label="Google Drive Download",
                    redact_list=redact_list,
                    max_bytes=262_144,
                    allow_truncate=True,
                )
                excerpt = raw_bytes.decode("utf-8", errors="replace")

            res_payload: dict[str, Any] = {
                "id": meta.get("id") or clean_id,
                "name": file_name,
                "mimeType": resolved_mime,
                "size": meta.get("size"),
                "createdTime": meta.get("createdTime"),
                "modifiedTime": meta.get("modifiedTime"),
                "owners": list(meta.get("owners") or []),
                "webViewLink": meta.get("webViewLink"),
                "description": redact_secrets(
                    str(meta.get("description") or ""), secrets_to_scrub
                )[:1000],
                "excerpt": redact_secrets(excerpt, secrets_to_scrub)[:capped_chars],
            }
            if page_count is not None:
                res_payload["page_count"] = page_count
            if scanned_pages:
                res_payload["scanned_pages"] = scanned_pages
            if tables_preview:
                res_payload["tables_preview"] = tables_preview
            if row_count is not None:
                res_payload["row_count"] = row_count
            return res_payload

        return await asyncio.to_thread(_run_drive_read)

    async def list_calendar_events(
        self,
        *,
        access_token: str,
        calendar_id: str = "primary",
        time_min: str | None = None,
        time_max: str | None = None,
        query: str = "",
        max_results: int = 25,
        redact_list: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        capped = max(1, min(int(max_results), 50))
        secrets_to_scrub = [*(redact_list or []), access_token]
        cal_id = (calendar_id or "primary").strip() or "primary"

        def _run_cal() -> list[dict[str, Any]]:
            params: list[tuple[str, str]] = [
                ("singleEvents", "true"),
                ("orderBy", "startTime"),
                ("maxResults", str(capped)),
            ]
            if time_min and time_min.strip():
                params.append(("timeMin", time_min.strip()))
            if time_max and time_max.strip():
                params.append(("timeMax", time_max.strip()))
            if query.strip():
                params.append(("q", query.strip()))
            url = (
                f"{CALENDAR_API_BASE}/calendars/{urllib.parse.quote(cal_id, safe='')}/events"
                f"?{urllib.parse.urlencode(params)}"
            )
            listing = self._http_google_json(
                "GET",
                url,
                access_token,
                service_label="Google Calendar API",
                redact_list=redact_list,
            )
            events_out: list[dict[str, Any]] = []
            for ev in listing.get("items") or []:
                if not isinstance(ev, dict):
                    continue
                attendees = [
                    {
                        "email": a.get("email"),
                        "displayName": a.get("displayName"),
                        "responseStatus": a.get("responseStatus"),
                        "self": bool(a.get("self")),
                    }
                    for a in (ev.get("attendees") or [])
                    if isinstance(a, dict)
                ]
                events_out.append(
                    {
                        "id": ev.get("id"),
                        "status": ev.get("status"),
                        "summary": redact_secrets(str(ev.get("summary") or "(No title)"), secrets_to_scrub),
                        "description": redact_secrets(str(ev.get("description") or ""), secrets_to_scrub)[:2000],
                        "location": redact_secrets(str(ev.get("location") or ""), secrets_to_scrub),
                        "htmlLink": ev.get("htmlLink"),
                        "hangoutLink": ev.get("hangoutLink"),
                        "start": ev.get("start") or {},
                        "end": ev.get("end") or {},
                        "creator": ev.get("creator") or {},
                        "organizer": ev.get("organizer") or {},
                        "attendees": attendees,
                        "recurringEventId": ev.get("recurringEventId"),
                        "updated": ev.get("updated"),
                    }
                )
            return events_out

        return await asyncio.to_thread(_run_cal)

    async def create_gmail_draft(
        self,
        *,
        access_token: str,
        to_email: str,
        subject: str,
        body_text: str,
        from_email: str | None = None,
        cc_email: str | None = None,
        bcc_email: str | None = None,
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
            bcc_email=bcc_email,
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
        bcc_email: str | None = None,
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
            bcc_email=bcc_email,
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

    async def delete_gmail_draft(
        self,
        *,
        access_token: str,
        draft_id: str,
        redact_list: list[str] | None = None,
    ) -> bool:
        clean_id = str(draft_id or "").strip()
        if not clean_id:
            return False

        def _run_del() -> bool:
            self._http_google_bytes(
                "DELETE",
                f"{GMAIL_API_BASE}/drafts/{urllib.parse.quote(clean_id, safe='')}",
                access_token,
                service_label="Gmail API",
                redact_list=redact_list,
                max_bytes=1_048_576,
                allow_truncate=True,
            )
            return True

        return await asyncio.to_thread(_run_del)

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
                        "refresh_token": getattr(creds, "refresh_token", None) or None,
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
                "refresh_token": tokens.get("refresh_token"),
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
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
        is_admin: bool = False,
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
            "owner_email": owner_email,
            "visibility": visibility,
            "allowed_groups": list(allowed_groups) if allowed_groups is not None else None,
            "is_admin": bool(is_admin),
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
        target_slug_clean = slugify(target_slug)
        existing_int = next(
            (i for i in self._repo.list_integrations() if i["slug"] == target_slug_clean),
            None,
        )
        pending_owner = normalize_email(pending.get("owner_email"))
        if (
            existing_int is not None
            and normalize_email(existing_int.get("owner_email"))
            and normalize_email(existing_int.get("owner_email")) != pending_owner
            and not bool(pending.get("is_admin"))
        ):
            raise GoogleOAuthConfigError(
                f"Integration '{target_slug_clean}' is owned by another user."
            )
        resolved_owner = (
            str(existing_int.get("owner_email") or "")
            if existing_int is not None and existing_int.get("owner_email")
            else str(pending.get("owner_email") or "")
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
            owner_email=resolved_owner,
            visibility=pending.get("visibility"),
            allowed_groups=pending.get("allowed_groups"),
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
            updated_secrets: dict[str, Any] = {
                "access_token": refreshed.get("access_token"),
                "token_expiry": refreshed.get("expiry"),
            }
            if refreshed.get("refresh_token") and str(refreshed["refresh_token"]).strip():
                updated_secrets["refresh_token"] = str(refreshed["refresh_token"]).strip()
            self._repo.upsert_integration(
                slug=account["slug"],
                provider="google",
                display_name=account["display_name"],
                account_identifier=str(refreshed.get("email") or account["account_identifier"] or ""),
                scopes=account["scopes"],
                secrets=updated_secrets,
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

    @staticmethod
    def _is_token_expired(raw_expiry: Any, *, skew_seconds: int = 60) -> bool:
        expiry_str = str(raw_expiry or "").strip()
        if not expiry_str:
            return False
        norm = expiry_str[:-1] + "+00:00" if expiry_str.endswith("Z") else expiry_str
        try:
            dt = datetime.fromisoformat(norm)
        except ValueError:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)
        return dt <= datetime.now(UTC) + timedelta(seconds=skew_seconds)

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

        if access_token and not force_refresh and not self._is_token_expired(sec.get("token_expiry")):
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
        updated_secrets: dict[str, Any] = {
            "access_token": new_token,
            "token_expiry": refreshed.get("expiry"),
        }
        new_refresh = str(refreshed.get("refresh_token") or "").strip()
        if new_refresh:
            updated_secrets["refresh_token"] = new_refresh
            redact_list.append(new_refresh)
        self._repo.upsert_integration(
            slug=account["slug"],
            provider="google",
            display_name=account["display_name"],
            account_identifier=str(refreshed.get("email") or account.get("account_identifier") or ""),
            scopes=account["scopes"],
            secrets=updated_secrets,
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

    @staticmethod
    def _require_google_scope(
        account: dict[str, Any],
        accepted: set[str],
        *,
        capability: str,
    ) -> None:
        raw_scopes: list[str] = []
        for s in account.get("scopes") or []:
            if str(s).strip():
                raw_scopes.append(str(s).strip())
        sec = account.get("secrets") or {}
        for s in sec.get("granted_scopes") or []:
            if str(s).strip():
                raw_scopes.append(str(s).strip())

        expanded: set[str] = set()
        for item in raw_scopes:
            low = item.lower()
            expanded.add(low)
            expanded.add(low.rsplit("/", 1)[-1])
            cat_entry = GOOGLE_SCOPE_CATALOG.get(low)
            if cat_entry:
                for full_scope in cat_entry.get("scopes") or []:
                    full_low = str(full_scope).lower()
                    expanded.add(full_low)
                    expanded.add(full_low.rsplit("/", 1)[-1])

        if not (expanded & {a.lower() for a in accepted}):
            raise GoogleOAuthConfigError(
                f"Google account '{account['slug']}' lacks required {capability} scope."
            )

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
            self._require_google_scope(
                account,
                {
                    "gmail_read",
                    "gmail_compose",
                    "gmail_send",
                    "default",
                    "gmail.readonly",
                    "gmail.modify",
                    "gmail.compose",
                    "https://mail.google.com/",
                },
                capability="Gmail read",
            )
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

    async def search_drive_files(
        self,
        slug: str,
        *,
        query: str = "",
        page_size: int = 25,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Search Google Drive files and metadata on an authorized Google integration."""
        search_fn = getattr(self._transport, "search_drive_files", None)
        if search_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Drive search.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            self._require_google_scope(
                account,
                {
                    "drive_docs",
                    "drive.readonly",
                    "drive",
                    "drive.metadata.readonly",
                    "documents.readonly",
                    "spreadsheets.readonly",
                },
                capability="Google Drive read",
            )
            res = await search_fn(
                access_token=token,
                query=query,
                page_size=page_size,
                page_token=page_token,
                redact_list=redact_list,
            )
            files = list((res or {}).get("files") or [])
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                "query": query,
                "files": files,
                "next_page_token": (res or {}).get("next_page_token"),
            }

        return await self._with_fresh_token(slug, _call)

    async def read_drive_file_excerpt(
        self,
        slug: str,
        *,
        file_id: str,
        max_chars: int = 16000,
    ) -> dict[str, Any]:
        """Read/export text content from a Google Doc, Sheet, Slides, or text Drive file."""
        read_fn = getattr(self._transport, "read_drive_file_excerpt", None)
        if read_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Drive file reading.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            self._require_google_scope(
                account,
                {
                    "drive_docs",
                    "drive.readonly",
                    "drive",
                    "documents.readonly",
                    "spreadsheets.readonly",
                },
                capability="Google Drive read",
            )
            res = await read_fn(
                access_token=token,
                file_id=file_id,
                max_chars=max_chars,
                redact_list=redact_list,
            )
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                **(res or {}),
            }

        return await self._with_fresh_token(slug, _call)

    async def list_calendar_events(
        self,
        slug: str,
        *,
        calendar_id: str = "primary",
        time_min: str | None = None,
        time_max: str | None = None,
        query: str = "",
        max_results: int = 25,
    ) -> dict[str, Any]:
        """List raw Google Calendar events on an authorized Google integration."""
        cal_fn = getattr(self._transport, "list_calendar_events", None)
        if cal_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Google Calendar.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            self._require_google_scope(
                account,
                {
                    "calendar",
                    "calendar.readonly",
                    "calendar.events",
                },
                capability="Google Calendar read",
            )
            events = await cal_fn(
                access_token=token,
                calendar_id=calendar_id,
                time_min=time_min,
                time_max=time_max,
                query=query,
                max_results=max_results,
                redact_list=redact_list,
            )
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                "calendar_id": calendar_id,
                "query": query,
                "events": list(events or []),
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
        bcc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Create a Gmail Draft so operators can also review/edit directly inside Gmail."""
        draft_fn = getattr(self._transport, "create_gmail_draft", None)
        if draft_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Gmail drafts.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            extra_kwargs = (
                {"bcc_email": str(bcc_email).strip()}
                if bcc_email and str(bcc_email).strip()
                else {}
            )
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
                **extra_kwargs,
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
        bcc_email: str | None = None,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Send an email via Gmail REST API v1 on an authorized Google integration."""
        send_fn = getattr(self._transport, "send_gmail_message", None)
        if send_fn is None:
            raise GoogleOAuthIntegrationError("Configured Google transport does not support Gmail sending.")

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> dict[str, Any]:
            extra_kwargs = (
                {"bcc_email": str(bcc_email).strip()}
                if bcc_email and str(bcc_email).strip()
                else {}
            )
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
                **extra_kwargs,
            )
            return {
                "provider": "google",
                "account_slug": account["slug"],
                "account_identifier": account.get("account_identifier"),
                **res,
            }

        return await self._with_fresh_token(slug, _call)

    async def delete_draft(self, slug: str, *, draft_id: str) -> bool:
        """Delete a Gmail Draft by ID (best-effort cleanup after sending or rejection)."""
        del_fn = getattr(self._transport, "delete_gmail_draft", None)
        clean_id = str(draft_id or "").strip()
        if del_fn is None or not clean_id:
            return False

        async def _call(account: dict[str, Any], token: str, redact_list: list[str]) -> bool:
            return bool(
                await del_fn(
                    access_token=token,
                    draft_id=clean_id,
                    redact_list=redact_list,
                )
            )

        return bool(await self._with_fresh_token(slug, _call))

    def materialize_binary_attachment_to_workspace(
        self,
        *,
        owner_email: str | None,
        filename: str,
        mime_type: str,
        raw_bytes: bytes,
        uploaded_by: str = "google_connector",
    ) -> dict[str, Any]:
        """Persist a Gmail/Drive binary attachment into per-user workspace storage + Parquet sidecars."""
        return self._repo.save_workspace_file(
            owner_email=owner_email,
            filename=filename,
            mime_type=mime_type,
            content_bytes=raw_bytes,
            uploaded_by=uploaded_by,
        )
