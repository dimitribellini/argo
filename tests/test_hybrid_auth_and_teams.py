"""End-to-end tests for Hybrid Native Auth, Invite-Only Google Sign-In, Team Groups, and 3-Level ACLs."""

from __future__ import annotations

import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.desktop.manager import InMemoryDockerDriver  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.sandbox.manager import InMemorySandboxDriver  # noqa: E402
from argo_core.security.auth import OAUTH_NONCE_COOKIE_NAME, SESSION_COOKIE_NAME  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeGoogleAuthTransport:
    """In-memory mock GoogleAuthTransport for PKCE & invite-only Sign-In E2E tests."""

    def __init__(self, code_profiles: dict[str, dict[str, Any]]) -> None:
        self._code_profiles = dict(code_profiles)
        self.started_states: dict[str, str] = {}
        self.exchanges: list[dict[str, str]] = []

    def build_login_url(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
    ) -> str:
        self.started_states[state] = code_challenge
        qs = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
            }
        )
        return f"https://accounts.google.com/o/oauth2/v2/auth?{qs}"

    def exchange_code_for_profile(
        self,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        del client_id, client_secret, redirect_uri
        self.exchanges.append({"code": code, "code_verifier": code_verifier})
        if code not in self._code_profiles:
            raise RuntimeError(f"Unknown mock authorization code: {code}")
        return dict(self._code_profiles[code])


def _build_app(
    tmp: str,
    *,
    auth_mode: str = "hybrid",
    multi_user: bool = True,
    require_sso: bool = True,
    admin_emails: tuple[str, ...] = (),
    initial_admin_password: str = "",
    google_auth_client_id: str = "",
    google_auth_client_secret: str = "",
    google_auth_transport: Any = None,
    docker_driver: Any = None,
    sandbox_driver: Any = None,
    max_active_desktops_per_user: int = 2,
    max_active_sandboxes_per_user: int = 4,
) -> Any:
    static_dir = Path(tmp) / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
    guard = HostResourceGuard(
        metrics_provider=lambda: {
            "ram_percent": 30.0,
            "ram_total_gb": 16.0,
            "cpu_percent": 10.0,
            "disk_percent": 20.0,
        },
        alert_cooldown_seconds=0.0,
    )
    settings = ArgoSettings(
        master_key=Fernet.generate_key().decode("ascii"),
        db_path=str(Path(tmp) / "argo.db"),
        valkey_url="valkey://127.0.0.1:6399/0",
        desktop_volumes_root=str(Path(tmp) / "desktops"),
        sandbox_volumes_root=str(Path(tmp) / "sandboxes"),
        workspace_files_root=str(Path(tmp) / "workspace_files"),
        ssh_audit_root=str(Path(tmp) / "ssh_audit"),
        public_base_url="https://argo.example.com",
        static_dir=str(static_dir),
        require_sso=require_sso,
        multi_user=multi_user,
        admin_emails=admin_emails,
        auth_mode=auth_mode,
        google_auth_client_id=google_auth_client_id,
        google_auth_client_secret=google_auth_client_secret,
        initial_admin_password=initial_admin_password,
        max_active_desktops_per_user=max_active_desktops_per_user,
        max_active_sandboxes_per_user=max_active_sandboxes_per_user,
    )
    return create_app(
        settings=settings,
        guard=guard,
        docker_driver=docker_driver or InMemoryDockerDriver(),
        sandbox_driver=sandbox_driver or InMemorySandboxDriver(),
        google_auth_transport=google_auth_transport,
    )


def _https_client(app: Any) -> TestClient:
    return TestClient(app, base_url="https://argo.example.com")


def _use_session(client: TestClient, token: str | None) -> None:
    client.cookies.clear()
    if token:
        client.cookies.set(SESSION_COOKIE_NAME, token, domain="argo.example.com", path="/")


def _login_session(client: TestClient, email: str, password: str) -> str:
    client.cookies.clear()
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        raise AssertionError(f"Expected login 200 for {email}, got {resp.status_code}: {resp.text}")
    tok = client.cookies.get(SESSION_COOKIE_NAME)
    assert tok
    return str(tok)


class TestHybridAuthAndTeams(unittest.TestCase):
    """End-to-end verification of Option 2: Hybrid Auth, Team Groups, 3-level ACLs, and Admin RBAC."""

    def test_1_bootstrap_password_login_csrf_rate_limit_and_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(tmp, auth_mode="hybrid", multi_user=True)
            with _https_client(app) as client:
                cfg = client.get("/api/auth/config")
                self.assertEqual(cfg.status_code, 200)
                self.assertTrue(cfg.json()["needs_setup"])
                self.assertEqual(cfg.json()["auth_mode"], "hybrid")

                # Spoofed oauth2-proxy headers must be ignored in local/hybrid mode
                self.assertEqual(
                    client.get(
                        "/api/me",
                        headers={"X-Auth-Request-Email": "admin@co.com"},
                    ).status_code,
                    401,
                )

                # First-boot admin creation succeeds and issues HttpOnly session cookie
                boot = client.post(
                    "/api/auth/bootstrap",
                    json={
                        "email": "admin@co.com",
                        "display_name": "Root Admin",
                        "password": "AdminStrongPassword!99",
                    },
                )
                self.assertEqual(boot.status_code, 201)
                admin_tok = str(client.cookies.get(SESSION_COOKIE_NAME) or "")
                self.assertTrue(admin_tok)

                _use_session(client, None)
                self.assertFalse(client.get("/api/auth/config").json()["needs_setup"])

                # Bootstrap locks immediately after first admin exists
                second_boot = client.post(
                    "/api/auth/bootstrap",
                    json={
                        "email": "hacker@co.com",
                        "password": "AnotherStrongPassword!99",
                    },
                )
                self.assertEqual(second_boot.status_code, 403)

                # CSRF Origin validation blocks cross-site state mutations
                _use_session(client, admin_tok)
                csrf_bad = client.post(
                    "/api/bots",
                    headers={"Origin": "https://evil.example"},
                    json={
                        "name": "Evil Bot",
                        "role": "Test",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                )
                self.assertEqual(csrf_bad.status_code, 403)

                csrf_ok = client.post(
                    "/api/bots",
                    headers={"Origin": "https://argo.example.com"},
                    json={
                        "name": "Admin Bot",
                        "role": "Assist",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                )
                self.assertEqual(csrf_ok.status_code, 201)

                # Admin invites Bob with temporary password requiring immediate rotation
                invite = client.post(
                    "/api/admin/users",
                    json={
                        "email": "bob@co.com",
                        "display_name": "Bob",
                        "role": "member",
                        "auth_methods": ["password"],
                        "password": "TempPassword123!",
                        "must_change_password": True,
                    },
                )
                self.assertEqual(invite.status_code, 201)

                old_bob_tok = _login_session(client, "bob@co.com", "TempPassword123!")

                # While must_change_password=True, /api/me shows flag and /api/bots is gated (403)
                bob_me = client.get("/api/me")
                self.assertEqual(bob_me.status_code, 200)
                self.assertTrue(bob_me.json()["must_change_password"])
                self.assertEqual(client.get("/api/bots").status_code, 403)

                # Change password unlocks workspace & revokes pre-rotation session token
                changed = client.post(
                    "/api/auth/change-password",
                    json={
                        "current_password": "TempPassword123!",
                        "new_password": "BobPermanentPassword!456",
                    },
                )
                self.assertEqual(changed.status_code, 200)
                new_bob_tok = str(client.cookies.get(SESSION_COOKIE_NAME) or "")
                self.assertTrue(new_bob_tok)
                self.assertEqual(client.get("/api/bots").status_code, 200)

                _use_session(client, old_bob_tok)
                self.assertEqual(client.get("/api/bots").status_code, 401)

                # Admin disables Bob -> Bob's active cookie immediately rejected (401 revoked) & login denied (403)
                _use_session(client, admin_tok)
                disabled = client.patch(
                    "/api/admin/users/bob@co.com",
                    json={"active": False},
                )
                self.assertEqual(disabled.status_code, 200)
                _use_session(client, new_bob_tok)
                self.assertEqual(client.get("/api/bots").status_code, 401)
                _use_session(client, None)
                disabled_login = client.post(
                    "/api/auth/login",
                    json={"email": "bob@co.com", "password": "BobPermanentPassword!456"},
                )
                self.assertEqual(disabled_login.status_code, 403)

                # Logout revokes session server-side
                _use_session(client, admin_tok)
                self.assertEqual(client.post("/api/auth/logout").status_code, 200)
                self.assertEqual(client.get("/api/me").status_code, 401)

                # Brute-force rate limiter triggers HTTP 429 with Retry-After after repeated failures
                _use_session(client, None)
                saw_401 = False
                locked = None
                for _ in range(12):
                    attempt = client.post(
                        "/api/auth/login",
                        json={"email": "admin@co.com", "password": "WrongPassword999"},
                    )
                    if attempt.status_code == 401:
                        saw_401 = True
                    elif attempt.status_code == 429:
                        locked = attempt
                        break
                    else:  # pragma: no cover
                        self.fail(f"Unexpected login status during rate limit test: {attempt.status_code}")
                self.assertTrue(saw_401)
                self.assertIsNotNone(locked)
                assert locked is not None
                self.assertEqual(locked.status_code, 429)
                self.assertIn("Retry-After", locked.headers)

    def test_2_invite_only_native_google_signin_hybrid_mode(self) -> None:
        transport = _FakeGoogleAuthTransport(
            {
                "code-stranger": {
                    "email": "stranger@co.com",
                    "email_verified": True,
                    "name": "Stranger",
                },
                "code-pwonly": {
                    "email": "pwonly@co.com",
                    "email_verified": True,
                    "name": "PW Only",
                },
                "code-alice": {
                    "email": "alice@co.com",
                    "email_verified": True,
                    "name": "Alice Invited",
                },
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(
                tmp,
                auth_mode="hybrid",
                multi_user=True,
                admin_emails=("admin@co.com",),
                initial_admin_password="AdminInitPassword!123",
                google_auth_client_id="google-client-123",
                google_auth_client_secret="google-secret-xyz",
                google_auth_transport=transport,
            )
            with _https_client(app) as client:
                cfg = client.get("/api/auth/config").json()
                self.assertTrue(cfg["google_auth_enabled"])
                self.assertFalse(cfg["needs_setup"])

                _login_session(client, "admin@co.com", "AdminInitPassword!123")
                client.post(
                    "/api/admin/users",
                    json={
                        "email": "pwonly@co.com",
                        "display_name": "PW Only",
                        "role": "member",
                        "auth_methods": ["password"],
                        "password": "PasswordOnly!123",
                    },
                )
                client.post(
                    "/api/admin/users",
                    json={
                        "email": "alice@co.com",
                        "display_name": "Alice Invited",
                        "role": "member",
                        "auth_methods": ["google"],
                    },
                )

                def _run_google_flow(code: str) -> tuple[Any, str]:
                    client.cookies.clear()
                    start = client.get("/api/auth/google/start", follow_redirects=False)
                    self.assertEqual(start.status_code, 302)
                    self.assertIn(OAUTH_NONCE_COOKIE_NAME, client.cookies)
                    parsed = urllib.parse.urlparse(start.headers["location"])
                    state = urllib.parse.parse_qs(parsed.query)["state"][0]
                    cb = client.get(
                        f"/api/auth/google/callback?code={code}&state={state}",
                        follow_redirects=False,
                    )
                    return cb, state

                # 1. Uninvited Google account is strictly rejected
                cb_stranger, _ = _run_google_flow("code-stranger")
                self.assertEqual(cb_stranger.status_code, 302)
                self.assertIn("auth_error=not_invited", cb_stranger.headers["location"])
                self.assertNotIn(SESSION_COOKIE_NAME, client.cookies)
                self.assertEqual(client.get("/api/me").status_code, 401)

                # 2. Password-only invited account is blocked from Google Sign-In
                cb_pwonly, _ = _run_google_flow("code-pwonly")
                self.assertEqual(cb_pwonly.status_code, 302)
                self.assertIn("auth_error=google_not_enabled", cb_pwonly.headers["location"])
                self.assertEqual(client.get("/api/me").status_code, 401)

                # 3. Invited Google account succeeds and establishes cookie session
                cb_alice, used_state = _run_google_flow("code-alice")
                self.assertEqual(cb_alice.status_code, 302)
                self.assertEqual(cb_alice.headers["location"], "/")
                me = client.get("/api/me")
                self.assertEqual(me.status_code, 200)
                self.assertEqual(me.json()["email"], "alice@co.com")
                self.assertEqual(me.json()["auth_method"], "google")

                # 1-click Google Workspace connector wizard inherits ARGO_GOOGLE_AUTH_CLIENT_ID/SECRET by default
                wiz_cfg = client.get("/api/integrations/google/wizard-config")
                self.assertEqual(wiz_cfg.status_code, 200)
                self.assertTrue(wiz_cfg.json()["has_server_client"])
                self.assertEqual(
                    ArgoSettings(
                        master_key="k",
                        db_path=":memory:",
                        valkey_url="valkey://v:6379/0",
                        desktop_volumes_root="/tmp/d",
                        public_base_url="https://argo.example.com",
                        static_dir="",
                        google_auth_client_id="auth-id",
                        google_auth_client_secret="auth-sec",
                        google_client_id="int-id",
                        google_client_secret="int-sec",
                    ).resolved_google_integration_client(),
                    ("int-id", "int-sec"),
                )

                # Replaying consumed OAuth state fails closed
                replay = client.get(
                    f"/api/auth/google/callback?code=code-alice&state={used_state}",
                    follow_redirects=False,
                )
                self.assertEqual(replay.status_code, 302)
                self.assertIn("auth_error=google_failed", replay.headers["location"])

    def test_3_team_groups_three_level_acl_scope_subset_and_group_delete_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(
                tmp,
                auth_mode="local",
                multi_user=True,
                admin_emails=("admin@co.com",),
                initial_admin_password="AdminPassword!123",
            )
            with _https_client(app) as client:
                admin_tok = _login_session(client, "admin@co.com", "AdminPassword!123")
                for email in ("alice@co.com", "bob@co.com", "carol@co.com"):
                    self.assertEqual(
                        client.post(
                            "/api/admin/users",
                            json={
                                "email": email,
                                "display_name": email.split("@", 1)[0].title(),
                                "role": "member",
                                "auth_methods": ["password"],
                                "password": "MemberPassword!123",
                                "must_change_password": False,
                            },
                        ).status_code,
                        201,
                    )

                grp = client.post(
                    "/api/admin/teams",
                    json={
                        "name": "Engineering",
                        "description": "Core platform engineers",
                        "member_emails": ["alice@co.com", "bob@co.com"],
                    },
                )
                self.assertEqual(grp.status_code, 201)
                self.assertEqual(grp.json()["slug"], "engineering")

                alice_tok = _login_session(client, "alice@co.com", "MemberPassword!123")
                bob_tok = _login_session(client, "bob@co.com", "MemberPassword!123")
                carol_tok = _login_session(client, "carol@co.com", "MemberPassword!123")

                # Non-member Carol sees no engineering team and cannot create engineering-scoped bot
                _use_session(client, carol_tok)
                self.assertEqual(client.get("/api/teams").json(), [])
                self.assertEqual(
                    client.post(
                        "/api/bots",
                        json={
                            "name": "Carol Spoof Bot",
                            "role": "Spoof",
                            "runtime": "api",
                            "outbound_rbac": "internal",
                            "visibility": "team",
                            "allowed_groups": ["engineering"],
                        },
                    ).status_code,
                    403,
                )

                # Alice creates team-scoped webhook integration, Vault secret, 2 Bots, Room & Page
                _use_session(client, alice_tok)
                int_res = client.post(
                    "/api/integrations",
                    json={
                        "slug": "eng-hook",
                        "provider": "webhook",
                        "display_name": "Eng Webhook",
                        "scopes": ["default"],
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(int_res.status_code, 201)

                vault_res = client.post(
                    "/api/vault",
                    json={
                        "name": "Eng Token",
                        "secret_type": "api_token",
                        "secrets": {"token": "secret-eng-token"},
                        "allowed_bots": ["*"],
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(vault_res.status_code, 201)

                bot1_res = client.post(
                    "/api/bots",
                    json={
                        "name": "Eng Triage",
                        "role": "Triage",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["eng-hook"],
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(bot1_res.status_code, 201)
                bot1_slug = bot1_res.json()["slug"]

                bot2_res = client.post(
                    "/api/bots",
                    json={
                        "name": "Eng Writer",
                        "role": "Write",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(bot2_res.status_code, 201)
                bot2_slug = bot2_res.json()["slug"]

                room_res = client.post(
                    "/api/rooms",
                    json={
                        "title": "Eng War Room",
                        "member_bot_slugs": [bot1_slug, bot2_slug],
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(room_res.status_code, 201)
                room_slug = room_res.json()["slug"]

                page_res = client.post(
                    "/api/pages",
                    json={
                        "title": "Eng Metrics",
                        "description": "Engineering KPIs",
                        "render_mode": "declarative_json",
                        "visibility": "team",
                        "allowed_groups": ["engineering"],
                    },
                )
                self.assertEqual(page_res.status_code, 201)
                page_slug = page_res.json()["slug"]

                # Bob (engineering teammate) can read & list all 5 resources, but cannot mutate/delete them
                _use_session(client, bob_tok)
                self.assertIn(bot1_slug, [b["slug"] for b in client.get("/api/bots").json()])
                self.assertIn("eng-hook", [i["slug"] for i in client.get("/api/integrations").json()])
                self.assertIn("eng-token", [v["slug"] for v in client.get("/api/vault").json()])
                self.assertIn(room_slug, [r["slug"] for r in client.get("/api/rooms").json()])
                self.assertIn(page_slug, [p["slug"] for p in client.get("/api/pages").json()])

                self.assertEqual(client.get(f"/api/bots/{bot1_slug}").status_code, 200)
                self.assertEqual(
                    client.patch(f"/api/bots/{bot1_slug}", json={"role": "Hijack"}).status_code,
                    403,
                )
                self.assertEqual(client.delete(f"/api/bots/{bot1_slug}").status_code, 403)
                self.assertEqual(client.delete(f"/api/rooms/{room_slug}").status_code, 403)
                self.assertEqual(client.delete(f"/api/pages/{page_slug}").status_code, 403)

                # Scope subset check: shared bot cannot link team-scoped integration
                shared_leak = client.post(
                    "/api/bots",
                    json={
                        "name": "Leaking Shared Bot",
                        "role": "Leak",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["eng-hook"],
                        "visibility": "shared",
                    },
                )
                self.assertEqual(shared_leak.status_code, 403)

                # Carol (non-member) is denied read/action & filtered out from every list
                _use_session(client, carol_tok)
                self.assertNotIn(bot1_slug, [b["slug"] for b in client.get("/api/bots").json()])
                self.assertNotIn("eng-hook", [i["slug"] for i in client.get("/api/integrations").json()])
                self.assertNotIn("eng-token", [v["slug"] for v in client.get("/api/vault").json()])
                self.assertEqual(client.get(f"/api/bots/{bot1_slug}").status_code, 403)
                self.assertEqual(client.get(f"/api/rooms/{room_slug}/messages").status_code, 403)
                self.assertEqual(client.get(f"/api/pages/{page_slug}/data").status_code, 403)
                self.assertEqual(client.post("/api/integrations/eng-hook/test").status_code, 403)
                self.assertEqual(client.delete("/api/integrations/eng-hook").status_code, 403)
                self.assertEqual(
                    client.patch("/api/vault/eng-token", json={"name": "Hack"}).status_code,
                    403,
                )
                self.assertEqual(client.delete("/api/vault/eng-token").status_code, 403)

                # Runner runtime _can_bot_access_resource matches same-team and blocks shared->team
                runner = app.state.bot_runner
                eng_bot = app.state.repo.get_bot(bot1_slug)
                eng_vault = app.state.repo.get_vault_secret_decrypted("eng-token")
                shared_bot_rec = {
                    "slug": "shared-bot",
                    "owner_email": "bob@co.com",
                    "visibility": "shared",
                    "allowed_groups": [],
                }
                self.assertTrue(runner._can_bot_access_resource(eng_bot, eng_vault))
                self.assertFalse(runner._can_bot_access_resource(shared_bot_rec, eng_vault))

                # Deleting Team Group downgrades orphaned 'team' resources to 'private' (fail-closed)
                _use_session(client, admin_tok)
                self.assertEqual(client.delete("/api/admin/teams/engineering").status_code, 200)
                downgraded = app.state.repo.get_bot(bot1_slug)
                self.assertEqual(downgraded["visibility"], "private")
                self.assertEqual(downgraded["allowed_groups"], [])
                _use_session(client, bob_tok)
                self.assertEqual(client.get(f"/api/bots/{bot1_slug}").status_code, 403)
                _use_session(client, alice_tok)
                self.assertEqual(client.get(f"/api/bots/{bot1_slug}").status_code, 200)

    def test_4_admin_only_models_and_per_user_container_quota_override(self) -> None:
        # Check Admin-only Models holds even when multi_user=False in hybrid mode
        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(
                tmp,
                auth_mode="hybrid",
                multi_user=False,
                admin_emails=("admin@co.com",),
                initial_admin_password="AdminPassword!123",
                max_active_desktops_per_user=2,
            )
            with _https_client(app) as client:
                admin_tok = _login_session(client, "admin@co.com", "AdminPassword!123")
                client.post(
                    "/api/admin/users",
                    json={
                        "email": "bob@co.com",
                        "display_name": "Bob",
                        "role": "member",
                        "auth_methods": ["password"],
                        "password": "BobPassword!123",
                        "must_change_password": False,
                    },
                )
                bob_tok = _login_session(client, "bob@co.com", "BobPassword!123")
                _use_session(client, bob_tok)
                self.assertEqual(
                    client.post(
                        "/api/models",
                        json={
                            "slug": "g-flash",
                            "provider_type": "google",
                            "model_id": "google:gemini-3.8-flash",
                            "is_default": True,
                        },
                    ).status_code,
                    403,
                )
                self.assertEqual(client.get("/api/admin/users").status_code, 403)

                _use_session(client, admin_tok)
                self.assertEqual(
                    client.post(
                        "/api/models",
                        json={
                            "slug": "g-flash",
                            "provider_type": "google",
                            "model_id": "google:gemini-3.8-flash",
                            "is_default": True,
                        },
                    ).status_code,
                    201,
                )

        # Check per-user desktop quota override & clear_quota_overrides in multi_user=True
        with tempfile.TemporaryDirectory() as tmp:
            app = _build_app(
                tmp,
                auth_mode="local",
                multi_user=True,
                admin_emails=("admin@co.com",),
                initial_admin_password="AdminPassword!123",
                max_active_desktops_per_user=2,
            )
            with _https_client(app) as client:
                admin_tok = _login_session(client, "admin@co.com", "AdminPassword!123")
                client.post(
                    "/api/admin/users",
                    json={
                        "email": "bob@co.com",
                        "display_name": "Bob",
                        "role": "member",
                        "auth_methods": ["password"],
                        "password": "BobPassword!123",
                        "must_change_password": False,
                        "max_active_desktops": 1,
                    },
                )
                bob_tok = _login_session(client, "bob@co.com", "BobPassword!123")
                _use_session(client, bob_tok)
                self.assertEqual(client.get("/api/me").json()["max_active_desktops_per_user"], 1)

                d1 = client.post(
                    "/api/bots",
                    json={
                        "name": "Desk One",
                        "role": "Browse",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                    },
                ).json()["slug"]
                d2 = client.post(
                    "/api/bots",
                    json={
                        "name": "Desk Two",
                        "role": "Browse",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                    },
                ).json()["slug"]

                self.assertEqual(client.post(f"/api/desktops/{d1}/toggle").status_code, 200)
                self.assertEqual(client.post(f"/api/desktops/{d2}/toggle").status_code, 409)

                # Admin clears override -> falls back to server default of 2
                _use_session(client, admin_tok)
                cleared = client.patch(
                    "/api/admin/users/bob@co.com",
                    json={"clear_quota_overrides": True},
                )
                self.assertEqual(cleared.status_code, 200)
                self.assertIsNone(cleared.json()["max_active_desktops"])
                _use_session(client, bob_tok)
                self.assertEqual(client.get("/api/me").json()["max_active_desktops_per_user"], 2)
                self.assertEqual(client.post(f"/api/desktops/{d2}/toggle").status_code, 200)

    def test_5_safe_upgrade_fallback_and_compose_hybrid_defaults(self) -> None:
        # Unset auth_mode with existing trusted proxy or local non-SSO keeps "sso"
        self.assertEqual(
            ArgoSettings(
                master_key="k",
                db_path=":memory:",
                valkey_url="valkey://v:6379/0",
                desktop_volumes_root="/tmp/d",
                public_base_url="https://argo.example.com",
                static_dir="",
                require_sso=True,
                trusted_proxy_host="oauth2-proxy",
                auth_mode="",
            ).resolved_auth_mode(),
            "sso",
        )
        self.assertEqual(
            ArgoSettings(
                master_key="k",
                db_path=":memory:",
                valkey_url="valkey://v:6379/0",
                desktop_volumes_root="/tmp/d",
                public_base_url="https://argo.example.com",
                static_dir="",
                require_sso=False,
                auth_mode="",
            ).resolved_auth_mode(),
            "sso",
        )
        self.assertEqual(
            ArgoSettings(
                master_key="k",
                db_path=":memory:",
                valkey_url="valkey://v:6379/0",
                desktop_volumes_root="/tmp/d",
                public_base_url="https://argo.example.com",
                static_dir="",
                require_sso=True,
                auth_mode="",
            ).resolved_auth_mode(),
            "hybrid",
        )

        compose_text = (ROOT / "compose.yml").read_text(encoding="utf-8")
        self.assertIn('ARGO_AUTH_MODE: "hybrid"', compose_text)
        self.assertIn('\n      ARGO_MULTI_USER: "true"\n', compose_text)
        self.assertIn('\n      ARGO_GOOGLE_AUTH_CLIENT_ID: ""\n', compose_text)
        self.assertIn('\n      ARGO_GOOGLE_AUTH_CLIENT_SECRET: ""\n', compose_text)
        self.assertIn('"127.0.0.1:8000:8000"', compose_text)
        self.assertIn('profiles: ["oauth2-proxy"]', compose_text)


if __name__ == "__main__":
    unittest.main()
