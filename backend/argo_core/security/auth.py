"""Native hybrid authentication helpers: scrypt passwords, sessions, CSRF, rate limits, and invite-only Google OAuth."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from starlette.requests import HTTPConnection
from starlette.responses import Response

from argo_core.security.tenancy import normalize_email

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "argo_session"
OAUTH_NONCE_COOKIE_NAME = "argo_oauth_nonce"
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
OAUTH_STATE_TTL_SECONDS = 600
LOGIN_RATE_LIMIT_MAX = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 900

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo"


class GoogleAuthLoginError(RuntimeError):
    """Raised when native Google Sign-In OAuth validation or exchange fails."""


def validate_password_strength(password: str) -> None:
    """Enforce baseline password length and character hygiene rules."""
    if not isinstance(password, str) or "\x00" in password:
        raise ValueError("Password contains unsupported characters.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if len(password) > MAX_PASSWORD_LEN:
        raise ValueError(f"Password must not exceed {MAX_PASSWORD_LEN} characters.")


def hash_password(password: str) -> str:
    """Hash a password with per-user salt using stdlib hashlib.scrypt."""
    validate_password_strength(password)
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    dk_b64 = base64.urlsafe_b64encode(dk).decode("ascii")
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt_b64}${dk_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored scrypt digest in constant time."""
    if not isinstance(password, str) or not password or not stored_hash or "\x00" in password:
        return False
    parts = str(stored_hash).split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n_val = int(parts[1])
        r_val = int(parts[2])
        p_val = int(parts[3])
        salt = base64.urlsafe_b64decode(parts[4].encode("ascii"))
        expected_dk = base64.urlsafe_b64decode(parts[5].encode("ascii"))
    except Exception:
        return False
    if n_val <= 1 or r_val <= 0 or p_val <= 0 or not salt or not expected_dk:
        return False
    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n_val,
            r=r_val,
            p=p_val,
            dklen=len(expected_dk),
        )
    except Exception:
        return False
    return hmac.compare_digest(derived, expected_dk)


def hash_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of an opaque session or OAuth state token."""
    return hashlib.sha256(str(raw_token or "").encode("utf-8")).hexdigest()


def generate_session_token() -> tuple[str, str]:
    """Generate a random bearer cookie token and its SHA-256 lookup hash."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def is_https_public_url(public_base_url: str) -> bool:
    """Return True when ARGO_PUBLIC_BASE_URL uses https://."""
    parsed = urllib.parse.urlparse(str(public_base_url or "").strip())
    return parsed.scheme.lower() == "https"


def set_session_cookie(response: Response, raw_token: str, settings: Any) -> None:
    """Attach the HttpOnly session cookie to an HTTP response."""
    ttl_hours = max(1, int(getattr(settings, "session_ttl_hours", 168) or 168))
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=ttl_hours * 3600,
        path="/",
        httponly=True,
        secure=is_https_public_url(getattr(settings, "public_base_url", "")),
        samesite="lax",
    )


def clear_session_cookie(response: Response, settings: Any) -> None:
    """Clear the HttpOnly session cookie."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=is_https_public_url(getattr(settings, "public_base_url", "")),
        samesite="lax",
    )


def _norm_netloc(parsed: urllib.parse.ParseResult) -> str:
    netloc = str(parsed.netloc or "").strip().lower()
    if not netloc:
        return ""
    scheme = str(parsed.scheme or "").strip().lower()
    if scheme == "https" and netloc.endswith(":443"):
        return netloc[:-4]
    if scheme == "http" and netloc.endswith(":80"):
        return netloc[:-3]
    return netloc


def _strip_default_port(host: str) -> str:
    clean = str(host or "").strip().lower()
    if clean.endswith(":443"):
        return clean[:-4]
    if clean.endswith(":80"):
        return clean[:-3]
    return clean


def is_valid_csrf_origin(conn: HTTPConnection, settings: Any) -> bool:
    """Validate Origin / Referer / Sec-Fetch-Site for cookie-authenticated writes."""
    sec_fetch = str(conn.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_fetch == "cross-site":
        return False

    allowed_hosts: set[str] = set()
    pub_raw = str(getattr(settings, "public_base_url", "") or "").strip()
    if pub_raw:
        pub_norm = _norm_netloc(urllib.parse.urlparse(pub_raw))
        if pub_norm:
            allowed_hosts.add(pub_norm)
    xf_host = str(conn.headers.get("x-forwarded-host") or "").split(",")[0].strip().lower()
    if xf_host:
        allowed_hosts.add(_strip_default_port(xf_host))
    host_hdr = str(conn.headers.get("host") or "").strip().lower()
    if host_hdr:
        allowed_hosts.add(_strip_default_port(host_hdr))

    origin = conn.headers.get("origin")
    if origin is not None:
        clean_origin = origin.strip()
        if not clean_origin or clean_origin.lower() == "null":
            return False
        parsed_origin = urllib.parse.urlparse(clean_origin)
        if parsed_origin.scheme.lower() not in {"http", "https"}:
            return False
        return _norm_netloc(parsed_origin) in allowed_hosts

    referer = conn.headers.get("referer")
    if referer is not None:
        clean_ref = referer.strip()
        if not clean_ref:
            return False
        parsed_ref = urllib.parse.urlparse(clean_ref)
        if parsed_ref.scheme.lower() not in {"http", "https"}:
            return False
        return _norm_netloc(parsed_ref) in allowed_hosts

    return True


class LoginRateLimiter:
    """Sliding-window login brute-force rate limiter backed by Valkey or memory."""

    def __init__(
        self,
        *,
        bus: Any = None,
        max_attempts: int = LOGIN_RATE_LIMIT_MAX,
        window_seconds: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self._bus = bus
        self._max_attempts = max(1, int(max_attempts))
        self._window_seconds = max(10, int(window_seconds))
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = {}

    def _redis_key(self, bucket: str) -> str:
        digest = hashlib.sha256(bucket.encode("utf-8")).hexdigest()[:32]
        return f"argo:auth:rl:{digest}"

    def _mem_prune(self, bucket: str, now: float) -> list[float]:
        cutoff = now - self._window_seconds
        entries = [ts for ts in self._attempts.get(bucket, []) if ts > cutoff]
        if entries:
            self._attempts[bucket] = entries
        else:
            self._attempts.pop(bucket, None)
        return entries

    async def check_allowed(self, bucket: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds) for a rate-limit bucket."""
        client = getattr(self._bus, "_client", None)
        if client is not None:
            rkey = self._redis_key(bucket)
            try:
                raw_cnt = await client.get(rkey)
                cnt = int(raw_cnt or 0)
                if cnt >= self._max_attempts:
                    ttl = await client.ttl(rkey)
                    return False, max(1, int(ttl or self._window_seconds))
                return True, 0
            except Exception:
                pass
        now = time.monotonic()
        with self._lock:
            entries = self._mem_prune(bucket, now)
            if len(entries) >= self._max_attempts:
                retry_after = max(1, int(entries[0] + self._window_seconds - now))
                return False, retry_after
        return True, 0

    async def record_failure(self, bucket: str) -> None:
        """Record a failed login attempt for the bucket."""
        client = getattr(self._bus, "_client", None)
        if client is not None:
            rkey = self._redis_key(bucket)
            try:
                val = int(await client.incr(rkey))
                if val <= 1:
                    await client.expire(rkey, self._window_seconds)
                return
            except Exception:
                pass
        now = time.monotonic()
        with self._lock:
            entries = self._mem_prune(bucket, now)
            entries.append(now)
            self._attempts[bucket] = entries

    async def reset(self, bucket: str) -> None:
        """Clear failed login counters after successful authentication."""
        client = getattr(self._bus, "_client", None)
        if client is not None:
            rkey = self._redis_key(bucket)
            try:
                await client.delete(rkey)
            except Exception:
                pass
        with self._lock:
            self._attempts.pop(bucket, None)


def seed_bootstrap_admins(repo: Any, settings: Any) -> None:
    """Ensure configured ARGO_ADMIN_EMAILS exist as active admin users in SQLite."""
    raw_admins = getattr(settings, "admin_emails", ()) or ()
    admin_emails = [
        normalize_email(str(a)) for a in raw_admins if normalize_email(str(a))
    ]
    if not admin_emails:
        return
    init_pw = str(getattr(settings, "initial_admin_password", "") or "")
    for idx, email in enumerate(admin_emails):
        existing = repo.get_user(email, include_secret=True)
        if existing is None:
            pw_hash = ""
            if idx == 0 and init_pw:
                try:
                    pw_hash = hash_password(init_pw)
                except ValueError as exc:
                    logger.warning("Ignoring ARGO_INITIAL_ADMIN_PASSWORD: %s", exc)
            repo.upsert_user(
                email=email,
                display_name=email.split("@", 1)[0].replace(".", " ").title() or "Admin",
                role="admin",
                active=True,
                auth_methods=["password", "google"],
                password_hash=pw_hash if pw_hash else None,
                must_change_password=False,
                created_by="system",
            )
        else:
            needs_role = existing.get("role") != "admin" or not existing.get("active", True)
            needs_pw = idx == 0 and bool(init_pw) and not existing.get("password_hash")
            if needs_role or needs_pw:
                pw_hash_val: str | None = None
                if needs_pw:
                    try:
                        pw_hash_val = hash_password(init_pw)
                    except ValueError as exc:
                        logger.warning("Ignoring ARGO_INITIAL_ADMIN_PASSWORD: %s", exc)
                repo.upsert_user(
                    email=email,
                    role="admin",
                    active=True,
                    auth_methods=list(existing.get("auth_methods") or ["password", "google"]),
                    password_hash=pw_hash_val if pw_hash_val else None,
                    must_change_password=False if needs_pw else None,
                )


def needs_initial_setup(repo: Any, settings: Any) -> bool:
    """Return True when local/hybrid mode has no usable admin credentials yet."""
    mode = settings.resolved_auth_mode() if callable(getattr(settings, "resolved_auth_mode", None)) else "sso"
    if mode == "sso":
        return False
    users = repo.list_users()
    active_admins = [u for u in users if u.get("active", True) and u.get("role") == "admin"]
    if any(bool(u.get("has_password")) for u in active_admins):
        return False
    if mode == "hybrid" and callable(getattr(settings, "google_auth_configured", None)) and settings.google_auth_configured():
        if any("google" in (u.get("auth_methods") or []) for u in active_admins):
            return False
    return True


class GoogleAuthTransport(Protocol):
    """Transport protocol for native Sign in with Google OAuth code/userinfo exchange."""

    def build_login_url(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
    ) -> str:
        ...

    def exchange_code_for_profile(
        self,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        ...


class DefaultGoogleAuthTransport:
    """Standard-library HTTPS Google OAuth2 identity transport (zero external deps)."""

    def build_login_url(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
    ) -> str:
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTH_URI}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_profile(
        self,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        form = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            }
        ).encode("utf-8")
        tok_req = urllib.request.Request(
            GOOGLE_TOKEN_URI,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(tok_req, timeout=15) as resp:
                tok_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise GoogleAuthLoginError(f"Google token exchange failed (HTTP {exc.code}).") from exc
        except Exception as exc:
            raise GoogleAuthLoginError(f"Google token exchange failed: {exc}") from exc

        access_token = str(tok_data.get("access_token") or "").strip()
        if not access_token:
            raise GoogleAuthLoginError("Google token response did not include an access token.")

        info_req = urllib.request.Request(
            GOOGLE_USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(info_req, timeout=15) as resp:
                profile = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise GoogleAuthLoginError(f"Google userinfo lookup failed (HTTP {exc.code}).") from exc
        except Exception as exc:
            raise GoogleAuthLoginError(f"Google userinfo lookup failed: {exc}") from exc

        verified_raw = (
            profile.get("verified_email")
            if "verified_email" in profile
            else profile.get("email_verified", False)
        )
        return {
            "email": str(profile.get("email") or "").strip(),
            "email_verified": bool(verified_raw),
            "name": str(profile.get("name") or "").strip(),
        }


class GoogleLoginService:
    """Handles PKCE + state + nonce login flows for native Sign in with Google."""

    def __init__(self, transport: GoogleAuthTransport | None = None) -> None:
        self._transport: GoogleAuthTransport = transport or DefaultGoogleAuthTransport()

    @staticmethod
    def callback_uri(settings: Any) -> str:
        base = str(getattr(settings, "public_base_url", "") or "").rstrip("/")
        return f"{base}/api/auth/google/callback"

    def start_login(self, repo: Any, settings: Any) -> tuple[str, str]:
        if not getattr(settings, "google_auth_configured", lambda: False)():
            raise GoogleAuthLoginError("Google Sign-In is not configured on this server.")
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        expires_at = (
            (datetime.now(UTC) + timedelta(seconds=OAUTH_STATE_TTL_SECONDS))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        repo.store_auth_oauth_state(
            hash_token(state),
            {
                "code_verifier": verifier,
                "nonce_hash": hash_token(nonce),
                "expires_at": expires_at,
            },
        )
        auth_url = self._transport.build_login_url(
            client_id=str(settings.google_auth_client_id),
            redirect_uri=self.callback_uri(settings),
            state=state,
            code_challenge=challenge,
        )
        return auth_url, nonce

    async def complete_login(
        self,
        repo: Any,
        settings: Any,
        *,
        code: str,
        state: str,
        raw_nonce: str,
    ) -> tuple[str, str]:
        if not code or not state or not raw_nonce:
            raise GoogleAuthLoginError("Missing OAuth state, code, or session verification nonce.")
        stored = repo.consume_auth_oauth_state(hash_token(state))
        if stored is None:
            raise GoogleAuthLoginError("Google Sign-In state expired or was already used.")
        expected_nonce_hash = str(stored.get("nonce_hash") or "")
        if not expected_nonce_hash or not hmac.compare_digest(hash_token(raw_nonce), expected_nonce_hash):
            raise GoogleAuthLoginError("Google Sign-In session verification failed.")
        verifier = str(stored.get("code_verifier") or "")
        if not verifier:
            raise GoogleAuthLoginError("Google Sign-In PKCE verifier missing.")

        fn = self._transport.exchange_code_for_profile
        kwargs = {
            "client_id": str(settings.google_auth_client_id),
            "client_secret": str(settings.google_auth_client_secret),
            "code": code,
            "redirect_uri": self.callback_uri(settings),
            "code_verifier": verifier,
        }
        if inspect.iscoroutinefunction(fn):
            profile = await fn(**kwargs)
        else:
            call_or_coro = await asyncio.to_thread(fn, **kwargs)
            profile = await call_or_coro if inspect.isawaitable(call_or_coro) else call_or_coro
        if not isinstance(profile, dict):
            raise GoogleAuthLoginError("Invalid profile payload returned by Google.")
        if not bool(profile.get("email_verified")):
            raise GoogleAuthLoginError("Google account email address is not verified.")
        email = normalize_email(str(profile.get("email") or ""))
        if not email or "@" not in email:
            raise GoogleAuthLoginError("Google account did not provide a valid email address.")
        return email, str(profile.get("name") or "").strip()
