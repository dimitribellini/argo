"""Sprint 3 integration, OAuth, anti-SSRF, webhook HMAC, and Telegram channel test suite."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.connectors.google_oauth import DefaultGoogleOAuthTransport  # noqa: E402
from argo_core.connectors.telegram_channels import (  # noqa: E402
    fetch_telegram_public_channel,
    normalize_public_channel_handle,
    parse_telegram_public_html,
)
from argo_core.connectors.webhooks import compute_hmac_sha256  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.security.ssrf import (  # noqa: E402
    AntiBotHaltError,
    PublicHttpResponse,
    SSRFBlockedError,
    SafePublicHttpFetcher,
    validate_public_url,
)
from argo_core.security.vault import redact_secrets  # noqa: E402


SAMPLE_TG_PUBLIC_HTML = """
<!doctype html>
<html>
<body>
  <div class="tgme_widget_message_wrap">
    <div class="tgme_widget_message" data-post="cloud_releases/101">
      <div class="tgme_widget_message_reply">
        <div class="tgme_widget_message_text">Quoted parent message must be ignored</div>
      </div>
      <div class="tgme_widget_message_text">
        Argo v3.15 shipped.<br/>Supports Fedora 45 &amp; Valkey 9.1.
      </div>
      <div class="tgme_widget_message_info">
        <span class="tgme_widget_message_views">4.2K</span>
        <a class="tgme_widget_message_date" href="https://t.me/cloud_releases/101">
          <time datetime="2026-11-10T09:15:00+00:00">09:15</time>
        </a>
      </div>
    </div>
  </div>
  <div class="tgme_widget_message_wrap">
    <div class="tgme_widget_message" data-post="cloud_releases/102">
      <div class="tgme_widget_message_text">Second release note item</div>
      <div class="tgme_widget_message_info">
        <span class="tgme_widget_message_views">1.8K</span>
        <a class="tgme_widget_message_date" href="https://t.me/cloud_releases/102">
          <time datetime="2026-11-10T10:00:00+00:00">10:00</time>
        </a>
      </div>
    </div>
  </div>
</body>
</html>
"""


class FakeTelegramTransport:
    """In-memory Telegram Bot API double for webhook/channel tests."""

    def __init__(self) -> None:
        self.webhooks: list[dict[str, object]] = []
        self.messages: list[dict[str, object]] = []

    async def get_me(self, bot_token: str) -> dict[str, object]:
        if "invalid" in bot_token:
            raise RuntimeError("Unauthorized")
        return {"bot_id": 990011, "username": "argo_ops_bot", "first_name": "Argo Ops"}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str] | None = None,
    ) -> bool:
        self.webhooks.append(
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": list(allowed_updates or []),
            }
        )
        return True

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: int | str,
        text: str,
        reply_markup: object | None = None,
    ) -> dict[str, object]:
        self.messages.append({"chat_id": chat_id, "text": text})
        return {"message_id": 500 + len(self.messages)}

    async def answer_callback_query(
        self, bot_token: str, *, callback_query_id: str, text: str | None = None
    ) -> bool:
        return True

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: object | None = None,
    ) -> dict[str, object]:
        return {"message_id": message_id, "text": text}


class FakeGoogleOAuthTransport:
    """Deterministic multi-account Google OAuth 2.0 transport double."""

    def __init__(self) -> None:
        self.authorize_calls: list[dict[str, object]] = []
        self.exchange_calls: list[dict[str, object]] = []
        self.refresh_calls: list[dict[str, object]] = []
        self.fail_refresh_tokens: set[str] = set()

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
        self.authorize_calls.append(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scopes": list(scopes),
                "state": state,
                "code_verifier": code_verifier,
                "login_hint": login_hint,
            }
        )
        return DefaultGoogleOAuthTransport().build_authorization_url(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            code_verifier=code_verifier,
            login_hint=login_hint,
        )

    async def exchange_code(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        code: str,
        code_verifier: str,
        scopes: list[str],
    ) -> dict[str, object]:
        self.exchange_calls.append({"code": code, "client_id": client_id})
        if code == "code-personal":
            return {
                "access_token": "ya29.personal_access_secret_token",
                "refresh_token": "1//0g_personal_refresh_secret",
                "token_uri": "https://oauth2.googleapis.com/token",
                "expiry": "2026-11-14T22:00:00Z",
                "email": "personal@gmail.com",
                "name": "Personal Gmail",
            }
        return {
            "access_token": "ya29.work_access_secret_token",
            "refresh_token": "1//0g_work_refresh_secret",
            "token_uri": "https://oauth2.googleapis.com/token",
            "expiry": "2026-11-14T22:00:00Z",
            "email": "operator@acme.io",
            "name": "Acme Workspace",
        }

    async def refresh_and_verify(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        token_uri: str = "https://oauth2.googleapis.com/token",
    ) -> dict[str, object]:
        self.refresh_calls.append({"client_id": client_id, "refresh_token": refresh_token})
        if refresh_token in self.fail_refresh_tokens:
            raise RuntimeError(
                f"invalid_grant: Token has been expired or revoked ({refresh_token})"
            )
        email = "personal@gmail.com" if "personal" in refresh_token else "operator@acme.io"
        return {
            "access_token": f"ya29.refreshed_{email}",
            "expiry": "2026-11-14T23:00:00Z",
            "email": email,
        }


class FakeLinkedInTransport:
    """In-memory LinkedIn /rest/posts transport double."""

    def __init__(self) -> None:
        self.verify_calls: list[dict[str, object]] = []
        self.post_calls: list[dict[str, object]] = []
        self.expired_tokens: set[str] = set()

    async def verify_token(
        self,
        access_token: str,
        *,
        linkedin_version: str,
    ) -> dict[str, object]:
        self.verify_calls.append(
            {"access_token": access_token, "linkedin_version": linkedin_version}
        )
        if access_token in self.expired_tokens:
            from argo_core.connectors.linkedin import LinkedInIntegrationError

            raise LinkedInIntegrationError(
                f"LinkedIn API HTTP 401: Unauthorized token {access_token}",
                status_code=401,
            )
        return {"sub": "user998877", "name": "Argo Publisher", "email": "pub@acme.io"}

    async def create_post(
        self,
        access_token: str,
        *,
        linkedin_version: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        self.post_calls.append(
            {
                "access_token": access_token,
                "linkedin_version": linkedin_version,
                "payload": payload,
            }
        )
        return {"post_urn": "urn:li:share:987654321", "status_code": 201}


class FakePublicHttpFetcher:
    """Stub SSRF-checked public HTTP fetcher returning canned HTML or errors."""

    def __init__(self) -> None:
        self.routes: dict[str, PublicHttpResponse | Exception] = {}
        self.calls: list[str] = []

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        self.calls.append(url)
        outcome = self.routes.get(url)
        if outcome is None:
            raise AssertionError(f"Unexpected URL requested in FakePublicHttpFetcher: {url}")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _make_test_app(
    tmp_dir: Path,
    *,
    google_transport: FakeGoogleOAuthTransport | None = None,
    linkedin_transport: FakeLinkedInTransport | None = None,
    telegram_transport: FakeTelegramTransport | None = None,
    public_http_fetcher: FakePublicHttpFetcher | None = None,
):
    static_dir = tmp_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html><body>Argo Test UI</body></html>", encoding="utf-8")
    settings = ArgoSettings(
        master_key=Fernet.generate_key().decode("ascii"),
        db_path=str(tmp_dir / "argo_test.db"),
        valkey_url="memory://localhost",
        desktop_volumes_root=str(tmp_dir / "desktops"),
        public_base_url="https://argo.example.com",
        static_dir=str(static_dir),
    )
    app = create_app(
        settings,
        telegram_transport=telegram_transport or FakeTelegramTransport(),
        google_transport=google_transport or FakeGoogleOAuthTransport(),
        linkedin_transport=linkedin_transport or FakeLinkedInTransport(),
        public_http_fetcher=public_http_fetcher or FakePublicHttpFetcher(),
    )
    return app, settings


class TestAntiSSRFAndZeroBypass(unittest.IsolatedAsyncioTestCase):
    """Verify SSRF IP/hostname blocking, redirect re-validation, and 403/429 halts."""

    def test_validate_public_url_blocks_private_loopback_metadata_and_schemes(self) -> None:
        blocked_urls = [
            "http://127.0.0.1:8080/health",
            "http://localhost:6379/",
            "http://0.0.0.0/",
            "http://10.0.0.5/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://172.17.0.2:3000/",
            "http://valkey:6379/",
            "http://argo-core:8000/",
            "http://oauth2-proxy/",
            "http://host.docker.internal/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fd00::1]/",
            "http://100.64.0.1/",
            "file:///etc/passwd",
            "ftp://example.com/file",
            "https://user:pass@example.com/",
        ]
        for url in blocked_urls:
            with self.assertRaises(SSRFBlockedError, msg=f"Expected SSRF block for {url}"):
                validate_public_url(url)

    def test_validate_public_url_blocks_dns_rebinding_and_allows_public_ip(self) -> None:
        with self.assertRaises(SSRFBlockedError):
            validate_public_url(
                "https://rebind.example.com/feed",
                resolver=lambda _host: ["10.1.2.3"],
            )

        cleaned, ips = validate_public_url(
            "https://t.me/s/cloud_releases",
            resolver=lambda _host: ["149.154.167.99"],
        )
        self.assertEqual(cleaned, "https://t.me/s/cloud_releases")
        self.assertEqual(ips, ["149.154.167.99"])

    async def test_safe_fetcher_blocks_redirect_to_metadata_and_halts_on_403_429_captcha(self) -> None:
        class _RedirectingFetcher(SafePublicHttpFetcher):
            def __init__(self, responses: list[PublicHttpResponse]) -> None:
                super().__init__(resolver=lambda _h: ["149.154.167.99"])
                self._responses = list(responses)
                self.requested: list[str] = []

            async def _single_get(
                self,
                url: str,
                *,
                headers: dict[str, str],
                timeout_seconds: float,
                max_bytes: int,
            ) -> PublicHttpResponse:
                self.requested.append(url)
                return self._responses.pop(0)

        redirect_fetcher = _RedirectingFetcher(
            [
                PublicHttpResponse(
                    url="https://t.me/s/public",
                    status_code=302,
                    headers={"location": "http://169.254.169.254/latest/meta-data"},
                    body="",
                )
            ]
        )
        with self.assertRaises(SSRFBlockedError):
            await redirect_fetcher.fetch("https://t.me/s/public")
        self.assertEqual(redirect_fetcher.requested, ["https://t.me/s/public"])

        for status_code, body, extra_headers in [
            (403, "Forbidden", {}),
            (429, "Too Many Requests", {}),
            (503, '<div class="cf-turnstile">Verify human</div>', {"cf-mitigated": "challenge"}),
        ]:
            halt_fetcher = _RedirectingFetcher(
                [
                    PublicHttpResponse(
                        url="https://t.me/s/public",
                        status_code=status_code,
                        headers=extra_headers,
                        body=body,
                    )
                ]
            )
            with self.assertRaises(AntiBotHaltError) as ctx:
                await halt_fetcher.fetch("https://t.me/s/public")
            self.assertEqual(ctx.exception.status_code, status_code)


class TestGoogleOAuthWizard(unittest.TestCase):
    """Verify 4-step Multi-Account Google OAuth flow, CSRF state replay block, and redaction."""

    def test_multi_account_oauth_wizard_callbacks_and_probe(self) -> None:
        google_transport = FakeGoogleOAuthTransport()
        with tempfile.TemporaryDirectory() as tmp:
            app, settings = _make_test_app(Path(tmp), google_transport=google_transport)
            with TestClient(app) as client:
                cfg_res = client.get("/api/integrations/google/wizard-config")
                self.assertEqual(cfg_res.status_code, 200)
                cfg = cfg_res.json()
                self.assertEqual(
                    cfg["redirect_uri"], "https://argo.example.com/api/integrations/google/callback"
                )
                self.assertFalse(cfg["has_saved_client"])
                self.assertEqual(cfg["required_oauth_params"]["prompt"], "select_account consent")
                self.assertEqual(len(cfg["steps"]), 4)

                # Must fail unless OAuth consent screen 'In Production' is confirmed.
                bad_auth = client.post(
                    "/api/integrations/google/authorize",
                    json={
                        "in_production_confirmed": False,
                        "client_id": "1234567890-abc.apps.googleusercontent.com",
                        "client_secret": "GOCSPX-secret-client-value",
                    },
                )
                self.assertEqual(bad_auth.status_code, 400)

                # Step 1-3: Work account authorize URL.
                auth1 = client.post(
                    "/api/integrations/google/authorize",
                    json={
                        "in_production_confirmed": True,
                        "client_id": "1234567890-abc.apps.googleusercontent.com",
                        "client_secret": "GOCSPX-secret-client-value",
                        "slug": "google_work",
                        "display_name": "Acme Work",
                        "login_hint": "operator@acme.io",
                        "scope_groups": ["gmail_read", "calendar"],
                    },
                )
                self.assertEqual(auth1.status_code, 200)
                auth1_body = auth1.json()
                parsed_url = urlparse(auth1_body["authorization_url"])
                qs = parse_qs(parsed_url.query)
                self.assertEqual(qs["prompt"], ["select_account consent"])
                self.assertEqual(qs["access_type"], ["offline"])
                self.assertEqual(qs["code_challenge_method"], ["S256"])
                self.assertEqual(qs["login_hint"], ["operator@acme.io"])

                # Browser GET callback completes exchange and 302-redirects to Integrations UI.
                cb1 = client.get(
                    "/api/integrations/google/callback",
                    params={"code": "code-work", "state": auth1_body["state"]},
                    follow_redirects=False,
                )
                self.assertEqual(cb1.status_code, 302)
                self.assertIn(
                    "/?view=integrations&oauth=google_connected&slug=google-work",
                    cb1.headers["location"],
                )

                # Replay of the same CSRF state must be blocked.
                replay = client.post(
                    "/api/integrations/google/callback",
                    json={"code": "code-work", "state": auth1_body["state"]},
                )
                self.assertEqual(replay.status_code, 400)

                # Wizard config now reveals saved client hint without leaking secret.
                cfg2 = client.get("/api/integrations/google/wizard-config").json()
                self.assertTrue(cfg2["has_saved_client"])
                self.assertIn("12345678", cfg2["saved_client_id_hint"])

                # Second Google account reusing saved client via JSON POST callback.
                auth2 = client.post(
                    "/api/integrations/google/authorize",
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": True,
                        "slug": "google_personal",
                        "display_name": "Personal Gmail",
                        "scope_groups": ["gmail_read"],
                    },
                )
                self.assertEqual(auth2.status_code, 200)
                cb2 = client.post(
                    "/api/integrations/google/callback",
                    json={"code": "code-personal", "state": auth2.json()["state"]},
                )
                self.assertEqual(cb2.status_code, 201)
                self.assertEqual(cb2.json()["account_identifier"], "personal@gmail.com")

                # Public API must never expose encrypted tokens or secrets.
                listed = client.get("/api/integrations").json()
                google_accounts = [item for item in listed if item["provider"] == "google"]
                self.assertEqual(len(google_accounts), 2)
                serialized = json.dumps(listed)
                self.assertNotIn("GOCSPX-secret-client-value", serialized)
                self.assertNotIn("1//0g_work_refresh_secret", serialized)
                self.assertNotIn("ya29.work_access_secret_token", serialized)

                # Probe failure (invalid_grant) marks account expired and redacts secrets.
                google_transport.fail_refresh_tokens.add("1//0g_work_refresh_secret")
                probe_fail = client.post("/api/integrations/google-work/test", json={})
                self.assertEqual(probe_fail.status_code, 502)
                refreshed_list = {
                    item["slug"]: item for item in client.get("/api/integrations").json()
                }
                self.assertEqual(refreshed_list["google-work"]["status"], "expired")
                self.assertNotIn(
                    "1//0g_work_refresh_secret",
                    refreshed_list["google-work"]["last_error"],
                )
                self.assertEqual(refreshed_list["google-personal"]["status"], "ok")

                # Also verify vault can decrypt stored SQLite record directly.
                secrets_row = app.state.repo.get_integration_secrets("google-work")
                self.assertEqual(
                    secrets_row["secrets"]["refresh_token"],
                    "1//0g_work_refresh_secret",
                )
                self.assertGreaterEqual(len(settings.master_key), 32)

    def test_redaction_patterns_cover_google_and_bearer_tokens(self) -> None:
        raw = (
            "Failed call client_secret=GOCSPX-AbcDef12345 "
            "access=ya29.a0AfH6SMC_sample refresh=1//0gXYZ123token "
            "Authorization: Bearer aqv_bearer_token_999"
        )
        redacted = redact_secrets(raw)
        self.assertNotIn("GOCSPX-AbcDef12345", redacted)
        self.assertNotIn("ya29.a0AfH6SMC_sample", redacted)
        self.assertNotIn("1//0gXYZ123token", redacted)
        self.assertNotIn("aqv_bearer_token_999", redacted)

    def test_default_google_transport_uses_oauthlib_and_googleapiclient_when_installed(self) -> None:
        recorded: dict[str, object] = {}

        class _FakeCreds:
            token = "ya29.stub_access"
            refresh_token = "1//0g_stub_refresh"
            token_uri = "https://oauth2.googleapis.com/token"
            expiry = None

        class _FakeFlow:
            def __init__(self, config: dict[str, object], scopes: list[str]) -> None:
                self.redirect_uri = ""
                self.code_verifier = ""
                self.credentials = _FakeCreds()
                recorded["scopes"] = scopes

            @classmethod
            def from_client_config(
                cls, client_config: dict[str, object], scopes: list[str]
            ) -> "_FakeFlow":
                recorded["client_config"] = client_config
                return cls(client_config, scopes)

            def authorization_url(self, **kwargs: object) -> tuple[str, str]:
                recorded["auth_kwargs"] = kwargs
                return ("https://accounts.google.com/o/oauth2/v2/auth?mock=1", str(kwargs["state"]))

            def fetch_token(self, *, code: str) -> None:
                recorded["fetched_code"] = code

        class _FakeUserinfo:
            def get(self):
                class _Exec:
                    @staticmethod
                    def execute() -> dict[str, str]:
                        return {"email": "stub@acme.io", "name": "Stub User"}

                return _Exec()

        class _FakeService:
            @staticmethod
            def userinfo() -> _FakeUserinfo:
                return _FakeUserinfo()

        def _fake_build(api: str, version: str, *, credentials: object, cache_discovery: bool):
            recorded["built"] = (api, version, cache_discovery)
            return _FakeService()

        mod_flow = types.ModuleType("google_auth_oauthlib.flow")
        mod_flow.Flow = _FakeFlow  # type: ignore[attr-defined]
        mod_oauthlib = types.ModuleType("google_auth_oauthlib")
        mod_oauthlib.flow = mod_flow  # type: ignore[attr-defined]
        mod_disc = types.ModuleType("googleapiclient.discovery")
        mod_disc.build = _fake_build  # type: ignore[attr-defined]
        mod_gapi = types.ModuleType("googleapiclient")
        mod_gapi.discovery = mod_disc  # type: ignore[attr-defined]

        with patch.dict(
            sys.modules,
            {
                "google_auth_oauthlib": mod_oauthlib,
                "google_auth_oauthlib.flow": mod_flow,
                "googleapiclient": mod_gapi,
                "googleapiclient.discovery": mod_disc,
            },
        ):
            transport = DefaultGoogleOAuthTransport()
            url = transport.build_authorization_url(
                client_id="cid",
                client_secret="csec",
                redirect_uri="https://argo.example.com/api/integrations/google/callback",
                scopes=["openid"],
                state="st1",
                code_verifier="cv1",
                login_hint="stub@acme.io",
            )
            self.assertIn("mock=1", url)
            self.assertEqual(recorded["auth_kwargs"]["prompt"], "select_account consent")

            import asyncio

            res = asyncio.run(
                transport.exchange_code(
                    client_id="cid",
                    client_secret="csec",
                    redirect_uri="https://argo.example.com/api/integrations/google/callback",
                    code="authcode",
                    code_verifier="cv1",
                    scopes=["openid"],
                )
            )
            self.assertEqual(res["email"], "stub@acme.io")
            self.assertEqual(recorded["fetched_code"], "authcode")
            self.assertEqual(recorded["built"], ("oauth2", "v2", False))


class TestLinkedInConnector(unittest.TestCase):
    """Verify LinkedIn /rest/posts versioned API connector & legacy ugcPosts block."""

    def test_linkedin_onboard_publish_and_tombstone_guard(self) -> None:
        li_transport = FakeLinkedInTransport()
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = _make_test_app(Path(tmp), linkedin_transport=li_transport)
            with TestClient(app) as client:
                # Legacy /v2/ugcPosts must be rejected.
                legacy = client.post(
                    "/api/integrations/linkedin/onboard",
                    json={
                        "access_token": "AQV_linkedin_secret_token_1234",
                        "linkedin_version": "v2/ugcPosts",
                    },
                )
                self.assertEqual(legacy.status_code, 400)
                self.assertIn("ugcPosts", legacy.json()["detail"])

                bad_urn = client.post(
                    "/api/integrations/linkedin/onboard",
                    json={
                        "access_token": "AQV_linkedin_secret_token_1234",
                        "author_urn": "bad-urn",
                    },
                )
                self.assertEqual(bad_urn.status_code, 400)

                onboard = client.post(
                    "/api/integrations/linkedin/onboard",
                    json={
                        "access_token": "AQV_linkedin_secret_token_1234",
                        "linkedin_version": "202611",
                        "slug": "linkedin_main",
                        "display_name": "Acme Official",
                    },
                )
                self.assertEqual(onboard.status_code, 201)
                self.assertEqual(onboard.json()["account_identifier"], "urn:li:person:user998877")

                pub = client.post(
                    "/api/integrations/linkedin/linkedin-main/posts",
                    json={
                        "commentary": "Shipping Fedora 45 + Valkey 9.1 baseline.",
                        "visibility": "PUBLIC",
                        "article_url": "https://example.com/release",
                        "article_title": "Release Notes",
                    },
                )
                self.assertEqual(pub.status_code, 201)
                self.assertEqual(pub.json()["post_urn"], "urn:li:share:987654321")
                self.assertEqual(li_transport.post_calls[0]["linkedin_version"], "202611")
                payload = li_transport.post_calls[0]["payload"]
                self.assertEqual(payload["lifecycleState"], "PUBLISHED")
                self.assertEqual(payload["content"]["article"]["source"], "https://example.com/release")

                # Probe handles HTTP 401 -> status=expired without leaking token.
                li_transport.expired_tokens.add("AQV_linkedin_secret_token_1234")
                probe = client.post("/api/integrations/linkedin-main/test", json={})
                self.assertEqual(probe.status_code, 502)
                accounts = {item["slug"]: item for item in client.get("/api/integrations").json()}
                self.assertEqual(accounts["linkedin-main"]["status"], "expired")
                self.assertNotIn(
                    "AQV_linkedin_secret_token_1234",
                    accounts["linkedin-main"]["last_error"],
                )


class TestSignedWebhooks(unittest.TestCase):
    """Verify HMAC-SHA256 webhook onboarding, signature checks, FTS storage, and replay guard."""

    def test_webhook_hmac_verification_collection_storage_and_replay_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = _make_test_app(Path(tmp))
            with TestClient(app) as client:
                onboard = client.post(
                    "/api/integrations/webhook/onboard",
                    json={
                        "display_name": "Release CI Hook",
                        "slug": "ci_release",
                        "event_type": "ci.release_ready",
                        "target_collection": "release_hooks",
                    },
                )
                self.assertEqual(onboard.status_code, 201)
                body = onboard.json()
                secret = body["signing_secret_once"]
                self.assertIsNotNone(secret)
                self.assertEqual(body["webhook_path"], "/hooks/webhook/ci-release")

                # Secret must never be exposed in GET /api/integrations.
                listed_json = json.dumps(client.get("/api/integrations").json())
                self.assertNotIn(secret, listed_json)

                raw_payload = json.dumps({"id": "deliv-100", "tag": "v3.15.0"}).encode("utf-8")

                # Missing or tampered signature returns 401.
                missing_sig = client.post("/hooks/webhook/ci-release", content=raw_payload)
                self.assertEqual(missing_sig.status_code, 401)
                bad_sig = client.post(
                    "/hooks/webhook/ci-release",
                    content=raw_payload,
                    headers={"X-Argo-Signature-256": "sha256=" + ("0" * 64)},
                )
                self.assertEqual(bad_sig.status_code, 401)

                # Valid HMAC succeeds, stores searchable collection doc, and emits Activity event.
                valid_sig = compute_hmac_sha256(secret, raw_payload)
                accepted = client.post(
                    "/hooks/webhook/ci-release",
                    content=raw_payload,
                    headers={
                        "X-Argo-Signature-256": valid_sig,
                        "X-Argo-Delivery": "deliv-100",
                    },
                )
                self.assertEqual(accepted.status_code, 200)
                self.assertEqual(accepted.json()["status"], "accepted")

                # Replaying same delivery_id is ignored idempotently.
                dup = client.post(
                    "/hooks/webhook/ci-release",
                    content=raw_payload,
                    headers={
                        "X-Argo-Signature-256": valid_sig,
                        "X-Argo-Delivery": "deliv-100",
                    },
                )
                self.assertEqual(dup.status_code, 200)
                self.assertEqual(dup.json()["status"], "duplicate_ignored")

                docs = client.get(
                    "/api/collections/release_hooks/documents",
                    params={"q": "v3.15.0"},
                ).json()
                self.assertEqual(len(docs), 1)
                self.assertEqual(docs[0]["doc"]["payload"]["tag"], "v3.15.0")


class TestTelegramChannelsAndManager(unittest.TestCase):
    """Verify Telegram admin channel webhooks, public preview sync, lxml path, and probe-all."""

    def test_telegram_public_html_parsers_stdlib_and_lxml_branch(self) -> None:
        self.assertEqual(
            normalize_public_channel_handle("https://t.me/s/Cloud_Releases?q=1"),
            "Cloud_Releases",
        )
        with self.assertRaises(Exception):
            normalize_public_channel_handle("invalid!")

        stdlib_items = parse_telegram_public_html(SAMPLE_TG_PUBLIC_HTML, "@cloud_releases")
        self.assertEqual(len(stdlib_items), 2)
        self.assertEqual(stdlib_items[0]["external_key"], "tg:@cloud_releases:101")
        self.assertNotIn("Quoted parent message", stdlib_items[0]["text"])
        self.assertIn("Fedora 45 & Valkey 9.1", stdlib_items[0]["text"])
        self.assertEqual(stdlib_items[0]["views"], "4.2K")

        # Verify _parse_with_lxml path when lxml.html is importable in container.
        class _FakeNode:
            def __init__(self, tag: str, text: str = "", attrs: dict[str, str] | None = None, children=None):
                self.tag = tag
                self.text = text
                self.tail = ""
                self._attrs = attrs or {}
                self._children = children or []

            def __iter__(self):
                return iter(self._children)

            def get(self, key: str, default: str | None = None) -> str | None:
                return self._attrs.get(key, default)

            def text_content(self) -> str:
                return self.text

            def xpath(self, expr: str):
                if "tgme_widget_message_text" in expr:
                    return [_FakeNode("div", "Parsed via lxml container path")]
                if "time[@datetime]" in expr:
                    return [_FakeNode("time", attrs={"datetime": "2026-11-11T12:00:00Z"})]
                if "tgme_widget_message_views" in expr:
                    return [_FakeNode("span", "9.9K")]
                return []

        class _FakeDoc:
            @staticmethod
            def xpath(_expr: str):
                return [_FakeNode("div", attrs={"data-post": "cloud_releases/555"})]

        mod_lxml_html = types.ModuleType("lxml.html")
        mod_lxml_html.fromstring = lambda _html: _FakeDoc()  # type: ignore[attr-defined]
        mod_lxml = types.ModuleType("lxml")
        mod_lxml.html = mod_lxml_html  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"lxml": mod_lxml, "lxml.html": mod_lxml_html}):
            lxml_items = parse_telegram_public_html("<html></html>", "cloud_releases")
            self.assertEqual(len(lxml_items), 1)
            self.assertEqual(lxml_items[0]["external_key"], "tg:@cloud_releases:555")
            self.assertEqual(lxml_items[0]["text"], "Parsed via lxml container path")

    def test_telegram_admin_channel_public_monitor_sync_and_probe_all(self) -> None:
        tg_transport = FakeTelegramTransport()
        public_fetcher = FakePublicHttpFetcher()
        public_fetcher.routes["https://t.me/s/cloud_releases"] = PublicHttpResponse(
            url="https://t.me/s/cloud_releases",
            status_code=200,
            headers={},
            body=SAMPLE_TG_PUBLIC_HTML,
        )
        google_transport = FakeGoogleOAuthTransport()
        li_transport = FakeLinkedInTransport()

        with tempfile.TemporaryDirectory() as tmp:
            app, _ = _make_test_app(
                Path(tmp),
                telegram_transport=tg_transport,
                google_transport=google_transport,
                linkedin_transport=li_transport,
                public_http_fetcher=public_fetcher,
            )
            with TestClient(app) as client:
                # 1. Onboard Telegram bot with @news_admin allowlist.
                tg_onboard = client.post(
                    "/api/integrations/telegram/onboard",
                    json={
                        "bot_token": "123456:AA_VALID_BOT_TOKEN_1234567890",
                        "slug": "tg-ops",
                        "operator_chat_id": "778899",
                        "admin_channels": ["@news_admin"],
                    },
                )
                self.assertEqual(tg_onboard.status_code, 201)
                tg_secret = app.state.repo.get_integration_secrets("tg-ops")["secrets"][
                    "webhook_secret"
                ]

                # Unlisted channel is ignored safely.
                ignored = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": tg_secret},
                    json={
                        "update_id": 1001,
                        "channel_post": {
                            "message_id": 10,
                            "chat": {"id": -1001, "username": "other_channel", "title": "Other"},
                            "text": "Ignore me",
                        },
                    },
                )
                self.assertEqual(ignored.status_code, 200)
                self.assertEqual(ignored.json()["status"], "ignored_unlisted_channel")

                # Listed @news_admin channel_post and edited_channel_post ingest & update cleanly.
                posted = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": tg_secret},
                    json={
                        "update_id": 1002,
                        "channel_post": {
                            "message_id": 44,
                            "chat": {"id": -1002, "username": "news_admin", "title": "News Admin"},
                            "text": "Initial admin announcement",
                        },
                    },
                )
                self.assertEqual(posted.status_code, 200)
                self.assertEqual(posted.json()["external_key"], "tg:@news_admin:44")

                edited = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": tg_secret},
                    json={
                        "update_id": 1003,
                        "edited_channel_post": {
                            "message_id": 44,
                            "chat": {"id": -1002, "username": "news_admin", "title": "News Admin"},
                            "text": "Corrected admin announcement",
                        },
                    },
                )
                self.assertEqual(edited.status_code, 200)
                self.assertTrue(edited.json()["edited"])

                # 2. Onboard t.me/s/ public monitor & verify idempotent deduplication.
                mon = client.post(
                    "/api/integrations/telegram/public-monitor",
                    json={"channel_handle": "@cloud_releases", "sync_immediately": True},
                )
                self.assertEqual(mon.status_code, 201)
                mon_body = mon.json()
                self.assertEqual(mon_body["sync_summary"]["new_count"], 2)

                resync = client.post(
                    f"/api/integrations/{mon_body['slug']}/sync",
                    json={"limit_per_channel": 20},
                )
                self.assertEqual(resync.status_code, 200)
                self.assertEqual(resync.json()["fetched_count"], 2)
                self.assertEqual(resync.json()["new_count"], 0)

                # AntiBotHaltError (HTTP 429) degrades connector and logs Activity alert.
                public_fetcher.routes["https://t.me/s/cloud_releases"] = AntiBotHaltError(
                    url="https://t.me/s/cloud_releases",
                    status_code=429,
                    reason="HTTP 429 rate limited",
                )
                halted = client.post(f"/api/integrations/{mon_body['slug']}/sync", json={})
                self.assertEqual(halted.status_code, 502)

                # Reset public channel mock and onboard Google + LinkedIn + Webhook for probe-all sweep.
                public_fetcher.routes["https://t.me/s/cloud_releases"] = PublicHttpResponse(
                    url="https://t.me/s/cloud_releases",
                    status_code=200,
                    headers={},
                    body=SAMPLE_TG_PUBLIC_HTML,
                )
                client.post(
                    "/api/integrations/linkedin/onboard",
                    json={
                        "access_token": "AQV_probe_all_token_1234",
                        "linkedin_version": "202611",
                        "slug": "li_sweep",
                    },
                )
                client.post(
                    "/api/integrations/webhook/onboard",
                    json={"display_name": "Sweep Hook", "slug": "wh_sweep"},
                )
                auth = client.post(
                    "/api/integrations/google/authorize",
                    json={
                        "in_production_confirmed": True,
                        "client_id": "cid-sweep",
                        "client_secret": "GOCSPX-sweep",
                        "slug": "g_sweep",
                    },
                ).json()
                client.post(
                    "/api/integrations/google/callback",
                    json={"code": "code-work", "state": auth["state"]},
                )

                # Force LinkedIn 401 expiration and verify probe-all catches mixed statuses.
                li_transport.expired_tokens.add("AQV_probe_all_token_1234")
                sweep = client.post("/api/integrations/probe-all")
                self.assertEqual(sweep.status_code, 200)
                sweep_body = sweep.json()
                self.assertEqual(sweep_body["total"], 5)
                self.assertEqual(sweep_body["expired"], 1)
                self.assertEqual(sweep_body["ok"], 4)

                events = client.get("/api/activity", params={"limit": 50}).json()
                event_types = {ev["event_type"] for ev in events}
                self.assertIn("telegram.public_channel.halted", event_types)
                self.assertIn("integrations.health_degraded", event_types)


if __name__ == "__main__":
    unittest.main()
