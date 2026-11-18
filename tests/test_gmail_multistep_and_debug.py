"""End-to-end tests for named multi-account Gmail, Draft-First approvals, RSS auto-discovery, multi-turn runner, chat thread memory, and Debug Console."""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
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
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.security.ssrf import PublicHttpResponse, validate_public_url  # noqa: E402


ZABBIX_BLOG_HTML = """<!doctype html>
<html>
<head>
  <title>Zabbix Blog</title>
  <link rel="alternate" type="application/rss+xml" title="Zabbix Blog RSS" href="/rss.xml" />
</head>
<body>
  <main><h1>Official Zabbix Blog</h1><p>Latest technical posts and updates.</p></main>
</body>
</html>
"""

ZABBIX_RSS_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>Zabbix Blog</title>
    <item>
      <title>Zabbix 7.4 LTS Released With Streaming Telemetry</title>
      <link>https://blog.zabbix.com/zabbix-7-4-lts-released</link>
      <guid>zabbix-740-release</guid>
      <pubDate>Sun, 15 Nov 2026 09:00:00 GMT</pubDate>
      <description>New streaming telemetry pipeline for distributed monitoring.</description>
    </item>
    <item>
      <title>Retail Customer Case Study: Global Store Monitoring</title>
      <link>https://blog.zabbix.com/retail-customer-case-study</link>
      <guid>zabbix-case-study-1</guid>
      <pubDate>Sun, 15 Nov 2026 08:00:00 GMT</pubDate>
      <description>Marketing customer case study testimonial.</description>
    </item>
  </channel>
</rss>
"""

VENDOR_NOTES_HTML = """<!doctype html>
<html>
<head><title>Release Notes</title></head>
<body>
  <main>
    <h1>Fedora 45 Base Image Update</h1>
    <p>Includes Python 3.15 performance improvements and Valkey 9.1 fixes.</p>
  </main>
</body>
</html>
"""


class FakeHttpFetcher:
    """In-memory SSRF-checked public HTTP fetcher for blog/RSS auto-discovery tests."""

    def __init__(self) -> None:
        self.routes: dict[str, PublicHttpResponse] = {}
        self.requested_urls: list[str] = []

    def set_page(
        self,
        url: str,
        *,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        status_code: int = 200,
    ) -> None:
        self.routes[url] = PublicHttpResponse(
            url=url,
            status_code=status_code,
            headers={"content-type": content_type},
            body=body,
        )

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        del headers, timeout_seconds, max_redirects, max_bytes
        validate_public_url(url, resolver=lambda _host: ["93.184.216.34"])
        self.requested_urls.append(url)
        if url not in self.routes:
            return PublicHttpResponse(url=url, status_code=404, headers={}, body="Not Found")
        return self.routes[url]


class FakeTelegramTransport:
    """In-memory Telegram Bot API double capturing inline approval cards."""

    def __init__(self) -> None:
        self.messages: list[dict[str, object]] = []

    async def get_me(self, bot_token: str) -> dict[str, object]:
        del bot_token
        return {"bot_id": 771122, "username": "argo_ops_bot", "first_name": "Argo Ops"}

    async def set_webhook(
        self,
        bot_token: str,
        *,
        url: str,
        secret_token: str,
        allowed_updates: list[str] | None = None,
    ) -> bool:
        del bot_token, url, secret_token, allowed_updates
        return True

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: int | str,
        text: str,
        reply_markup: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del bot_token
        msg_id = 800 + len(self.messages) + 1
        self.messages.append(
            {
                "chat_id": str(chat_id),
                "message_id": msg_id,
                "text": text,
                "reply_markup": reply_markup,
            }
        )
        return {"message_id": msg_id}

    async def answer_callback_query(
        self, bot_token: str, *, callback_query_id: str, text: str | None = None
    ) -> bool:
        del bot_token, callback_query_id, text
        return True

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict[str, object] | None = None,
    ) -> dict[str, object]:
        del bot_token, reply_markup
        return {"message_id": message_id, "chat_id": str(chat_id), "text": text}


class FakeGmailOAuthTransport:
    """Multi-account Google OAuth + Gmail REST v1 test double."""

    def __init__(self) -> None:
        self.authorize_calls: list[dict[str, object]] = []
        self.search_calls: list[dict[str, object]] = []
        self.draft_calls: list[dict[str, object]] = []
        self.send_calls: list[dict[str, object]] = []
        self.inbox_by_token: dict[str, list[dict[str, object]]] = {
            "ya29.personal_access": [
                {
                    "id": "msg_personal_1",
                    "thread_id": "thr_personal_1",
                    "from": "friend@gmail.com",
                    "to": "personal@gmail.com",
                    "subject": "Weekend dinner plans",
                    "snippet": "Hey! Are we still on for Saturday?",
                }
            ],
            "ya29.business_access": [
                {
                    "id": "msg_biz_1",
                    "thread_id": "thr_biz_1",
                    "from": "client@acme.io",
                    "to": "ops@company.com",
                    "subject": "Proposal Question",
                    "message_id_header": "<msg_biz_1@acme.io>",
                    "snippet": "Could you confirm onboarding timeline and pricing?",
                }
            ],
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
        self.authorize_calls.append(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scopes": list(scopes),
                "state": state,
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
        del client_id, client_secret, redirect_uri, code_verifier, scopes
        if code == "code-personal":
            return {
                "access_token": "ya29.personal_access",
                "refresh_token": "1//personal_refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "expiry": "2026-11-16T00:00:00Z",
                "email": "personal@gmail.com",
                "name": "Personal Gmail",
            }
        if code == "code-dimiz":
            return {
                "access_token": "ya29.personal_access",
                "refresh_token": "1//personal_refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "expiry": "2026-11-16T00:00:00Z",
                "email": "dimiz.dubai@gmail.com",
                "name": "Personal Gmail",
            }
        if code == "code-quadrata":
            return {
                "access_token": "ya29.business_access",
                "refresh_token": "1//business_refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "expiry": "2026-11-16T00:00:00Z",
                "email": "dimitri.bellini@quadrata-group.com",
                "name": "Business Gmail",
            }
        if code == "code-colleague":
            return {
                "access_token": "ya29.personal_access",
                "refresh_token": "1//personal_refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "expiry": "2026-11-16T00:00:00Z",
                "email": "colleague@gmail.com",
                "name": "Personal Gmail",
            }
        return {
            "access_token": "ya29.business_access",
            "refresh_token": "1//business_refresh",
            "token_uri": "https://oauth2.googleapis.com/token",
            "expiry": "2026-11-16T00:00:00Z",
            "email": "ops@company.com",
            "name": "Business Gmail",
        }

    async def refresh_and_verify(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        token_uri: str = "https://oauth2.googleapis.com/token",
    ) -> dict[str, object]:
        del client_id, client_secret, token_uri
        if "personal" in refresh_token:
            return {
                "access_token": "ya29.personal_access",
                "expiry": "2026-11-16T00:00:00Z",
                "email": "personal@gmail.com",
            }
        return {
            "access_token": "ya29.business_access",
            "expiry": "2026-11-16T00:00:00Z",
            "email": "ops@company.com",
        }

    async def search_gmail_messages(
        self,
        *,
        access_token: str,
        query: str = "",
        max_results: int = 10,
        redact_list: list[str] | None = None,
    ) -> list[dict[str, object]]:
        del redact_list
        self.search_calls.append(
            {"access_token": access_token, "query": query, "max_results": max_results}
        )
        return list(self.inbox_by_token.get(access_token, []))[:max_results]

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
    ) -> dict[str, object]:
        del redact_list
        draft_id = f"r_{len(self.draft_calls) + 1}"
        rec = {
            "draft_id": draft_id,
            "message_id": f"m_{len(self.draft_calls) + 1}",
            "access_token": access_token,
            "from_email": from_email,
            "to_email": to_email,
            "cc_email": cc_email,
            "subject": subject,
            "body_text": body_text,
            "thread_id": thread_id,
            "in_reply_to": in_reply_to,
        }
        self.draft_calls.append(rec)
        return {"draft_id": draft_id, "message_id": rec["message_id"], "thread_id": thread_id}

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
    ) -> dict[str, object]:
        del redact_list
        msg_id = f"sent_{len(self.send_calls) + 1}"
        rec = {
            "message_id": msg_id,
            "thread_id": thread_id or f"thr_sent_{len(self.send_calls) + 1}",
            "access_token": access_token,
            "from_email": from_email,
            "to_email": to_email,
            "cc_email": cc_email,
            "subject": subject,
            "body_text": body_text,
            "in_reply_to": in_reply_to,
        }
        self.send_calls.append(rec)
        return {"message_id": msg_id, "thread_id": rec["thread_id"], "label_ids": ["SENT"]}


class TestGmailMultistepAndDebug(unittest.TestCase):
    """Verify Sprint 6 usability, Gmail engine, isolation, auto-discovery & Debug Console."""

    @staticmethod
    def _sso_headers() -> dict[str, str]:
        return {
            "X-Auth-Request-Email": "operator@example.com",
            "X-Auth-Request-User": "operator",
        }

    def _build_env(
        self,
        tmp: str,
        *,
        llm_transport=None,
        google_transport=None,
        tg_transport=None,
        http_fetcher=None,
        google_client_id: str = "",
        google_client_secret: str = "",
    ):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")

        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
        )
        return create_app(
            settings=settings,
            llm_transport=llm_transport,
            google_transport=google_transport,
            telegram_transport=tg_transport,
            public_http_fetcher=http_fetcher,
        )

    @staticmethod
    def _connect_gmail_pair(
        client: TestClient,
        headers: dict[str, str],
    ) -> tuple[dict[str, object], dict[str, object]]:
        p_auth = client.post(
            "/api/integrations/google/authorize",
            headers=headers,
            json={
                "in_production_confirmed": True,
                "reuse_saved_client": True,
                "display_name": "Personal Gmail",
                "login_hint": "personal@gmail.com",
                "scope_groups": ["gmail_read", "gmail_compose"],
            },
        )
        assert p_auth.status_code == 200, p_auth.text
        p_done = client.post(
            "/api/integrations/google/callback",
            headers=headers,
            json={"code": "code-personal", "state": p_auth.json()["state"]},
        )
        assert p_done.status_code == 201, p_done.text

        b_auth = client.post(
            "/api/integrations/google/authorize",
            headers=headers,
            json={
                "in_production_confirmed": True,
                "reuse_saved_client": True,
                "display_name": "Business Gmail",
                "login_hint": "ops@company.com",
                "scope_groups": ["gmail_read", "gmail_compose"],
            },
        )
        assert b_auth.status_code == 200, b_auth.text
        b_done = client.post(
            "/api/integrations/google/callback",
            headers=headers,
            json={"code": "code-business", "state": b_auth.json()["state"]},
        )
        assert b_done.status_code == 201, b_done.text
        return p_done.json(), b_done.json()

    def test_named_multi_account_gmail_one_click_onboarding(self) -> None:
        google_transport = FakeGmailOAuthTransport()
        headers = self._sso_headers()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                google_transport=google_transport,
                google_client_id="server-oauth-client.apps.googleusercontent.com",
                google_client_secret="GOCSPX-server-oauth-secret",
            )
            with TestClient(app) as client:
                cfg = client.get("/api/integrations/google/wizard-config", headers=headers)
                self.assertEqual(cfg.status_code, 200)
                cfg_data = cfg.json()
                self.assertTrue(cfg_data["has_server_client"])
                self.assertIsNotNone(cfg_data["server_client_id_hint"])

                personal, business = self._connect_gmail_pair(client, headers)
                self.assertEqual(personal["slug"], "personal-gmail")
                self.assertEqual(personal["account_identifier"], "personal@gmail.com")
                self.assertEqual(business["slug"], "business-gmail")
                self.assertEqual(business["account_identifier"], "ops@company.com")

                listed = client.get("/api/integrations", headers=headers).json()
                slugs = {item["slug"] for item in listed}
                self.assertIn("personal-gmail", slugs)
                self.assertIn("business-gmail", slugs)

    def test_gmail_draft_first_workflow_and_account_isolation(self) -> None:
        google_transport = FakeGmailOAuthTransport()
        tg_transport = FakeTelegramTransport()
        headers = self._sso_headers()
        scenario = {"mode": "allowed_workflow", "turn": 0, "prompts": []}

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            scenario["prompts"].append(req.user_prompt)
            scenario["turn"] += 1
            if scenario["mode"] == "allowed_workflow":
                if scenario["turn"] == 1:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Searching unread Business Gmail messages.",
                                "actions": [
                                    {
                                        "type": "gmail_search",
                                        "account": "business-gmail",
                                        "query": "is:unread",
                                        "max_results": 5,
                                    }
                                ],
                            }
                        ),
                        "input_tokens": 30,
                        "output_tokens": 20,
                    }
                return {
                    "text": json.dumps(
                        {
                            "summary": "Created a formal reply draft for client@acme.io.",
                            "actions": [
                                {
                                    "type": "send_email",
                                    "account": "business-gmail",
                                    "to": "client@acme.io",
                                    "subject": "Re: Proposal Question",
                                    "thread_id": "thr_biz_1",
                                    "in_reply_to": "<msg_biz_1@acme.io>",
                                    "text": "Dear Client, our onboarding begins within 5 business days.",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 40,
                    "output_tokens": 30,
                }

            return {
                "text": json.dumps(
                    {
                        "summary": "Attempting unauthorized access to personal inbox.",
                        "actions": [
                            {
                                "type": "gmail_search",
                                "account": "personal-gmail",
                                "query": "is:unread",
                            },
                            {
                                "type": "send_email",
                                "account": "personal-gmail",
                                "to": "friend@gmail.com",
                                "subject": "Test",
                                "text": "Should be blocked",
                            },
                        ],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 20,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                google_transport=google_transport,
                tg_transport=tg_transport,
                google_client_id="server-oauth-client.apps.googleusercontent.com",
                google_client_secret="GOCSPX-server-oauth-secret",
            )
            with TestClient(app) as client:
                app.state.repo.upsert_integration(
                    slug="tg-ops",
                    provider="telegram",
                    display_name="Ops Telegram",
                    account_identifier="argo_ops_bot",
                    scopes=["bot_api"],
                    secrets={"bot_token": "991122:AAtesttoken", "operator_chat_id": "1001"},
                    status="ok",
                )
                app.state.repo.upsert_model(
                    slug="default-flash",
                    provider_type="google",
                    model_id="google:gemini-3.8-flash",
                    api_key="AIzaSyFakeKey",
                    is_default=True,
                )
                self._connect_gmail_pair(client, headers)

                biz_res = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Business Inbox Bot",
                        "role": "Handle business client emails in formal tone.",
                        "outbound_rbac": "draft",
                        "linked_accounts": ["business-gmail"],
                    },
                )
                self.assertEqual(biz_res.status_code, 201, biz_res.text)
                personal_res = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Personal Inbox Bot",
                        "role": "Handle personal messages warmly.",
                        "outbound_rbac": "draft",
                        "linked_accounts": ["personal-gmail"],
                    },
                )
                self.assertEqual(personal_res.status_code, 201, personal_res.text)

                run_res = client.post(
                    "/api/bots/business-inbox-bot/trigger",
                    headers=headers,
                    json={"wait_for_chain": True},
                )
                self.assertEqual(run_res.status_code, 200, run_res.text)
                self.assertEqual(scenario["turn"], 2)
                self.assertIn("Proposal Question", scenario["prompts"][1])
                self.assertEqual(len(google_transport.search_calls), 1)
                self.assertEqual(
                    google_transport.search_calls[0]["access_token"],
                    "ya29.business_access",
                )

                # Draft-first saved a real Gmail Draft and queued pending approval before any send.
                self.assertEqual(len(google_transport.draft_calls), 1)
                self.assertEqual(google_transport.draft_calls[0]["to_email"], "client@acme.io")
                self.assertEqual(len(google_transport.send_calls), 0)

                pending = client.get("/api/approvals?tab=pending", headers=headers).json()
                self.assertEqual(len(pending), 1)
                approval = pending[0]
                self.assertEqual(approval["target_account_slug"], "business-gmail")
                self.assertEqual(approval["payload"]["to"], "client@acme.io")
                self.assertEqual(approval["payload"]["subject"], "Re: Proposal Question")
                self.assertEqual(approval["payload"]["gmail_draft_id"], "r_1")

                # Approvals stay channel-agnostic: Business Gmail drafts do not auto-forward to an unlinked Telegram bot
                # unless a composable on_event="approval.queued" notifier bot is configured.
                self.assertEqual(tg_transport.messages, [])

                # Approving sends the email through Business Gmail.
                resolve = client.post(
                    f"/api/approvals/{approval['id']}/resolve",
                    headers=headers,
                    json={"action": "approve"},
                )
                self.assertEqual(resolve.status_code, 200, resolve.text)
                self.assertEqual(resolve.json()["status"], "executed")
                self.assertEqual(len(google_transport.send_calls), 1)
                self.assertEqual(
                    google_transport.send_calls[0]["access_token"],
                    "ya29.business_access",
                )
                self.assertEqual(google_transport.send_calls[0]["to_email"], "client@acme.io")

                # Isolation check: business-inbox-bot cannot touch personal-gmail even if LLM asks.
                scenario["mode"] = "cross_account_attack"
                blocked_run = client.post(
                    "/api/bots/business-inbox-bot/trigger",
                    headers=headers,
                    json={"wait_for_chain": True},
                )
                self.assertEqual(blocked_run.status_code, 200, blocked_run.text)
                actions = blocked_run.json()["actions"]
                self.assertEqual(len(actions), 2)
                self.assertTrue(all(a["status"] == "blocked_unlinked_account" for a in actions))
                self.assertEqual(
                    [c["access_token"] for c in google_transport.search_calls],
                    ["ya29.business_access"],
                )
                self.assertEqual(len(google_transport.send_calls), 1)

                blocked_events = [
                    ev
                    for ev in app.state.repo.list_events(limit=30)
                    if ev["event_type"] == "connector.blocked"
                ]
                self.assertGreaterEqual(len(blocked_events), 2)

    def test_blog_rss_autodiscovery_and_multistep_webpage_synthesis(self) -> None:
        fetcher = FakeHttpFetcher()
        fetcher.set_page("https://blog.zabbix.com", body=ZABBIX_BLOG_HTML)
        fetcher.set_page(
            "https://blog.zabbix.com/rss.xml",
            body=ZABBIX_RSS_XML,
            content_type="application/rss+xml; charset=utf-8",
        )
        fetcher.set_page("https://vendor.example.org/notes", body=VENDOR_NOTES_HTML)
        tg_transport = FakeTelegramTransport()
        headers = self._sso_headers()
        prompts_seen: list[str] = []
        turn_state = {"multi_step": 0}

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            prompts_seen.append(f"{req.system_prompt}\n{req.user_prompt}")
            if "Refine this Argo declarative bot JSON spec" in req.user_prompt:
                return {"text": "not json", "input_tokens": 5, "output_tokens": 5}
            if "zabbix_news" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Saved Zabbix 7.4 LTS article (discarded case study) and queued Telegram summary.",
                            "actions": [
                                {
                                    "type": "upsert_document",
                                    "collection": "zabbix_news",
                                    "external_key": "zabbix-740-release",
                                    "search_text": "Zabbix 7.4 LTS Released With Streaming Telemetry",
                                    "doc": {
                                        "title": "Zabbix 7.4 LTS Released With Streaming Telemetry",
                                        "url": "https://blog.zabbix.com/zabbix-7-4-lts-released",
                                    },
                                },
                                {
                                    "type": "publish_telegram",
                                    "account": "tg-ops",
                                    "text": "New Zabbix Blog Post: Zabbix 7.4 LTS Released With Streaming Telemetry",
                                },
                            ],
                        }
                    ),
                    "input_tokens": 50,
                    "output_tokens": 45,
                }

            turn_state["multi_step"] += 1
            if turn_state["multi_step"] == 1:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Fetching release notes webpage.",
                            "actions": [
                                {
                                    "type": "fetch_public_webpage",
                                    "url": "https://vendor.example.org/notes",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 15,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Synthesized Fedora 45 notes into collection vendor_notes.",
                        "actions": [
                            {
                                "type": "upsert_document",
                                "collection": "vendor_notes",
                                "external_key": "fedora-45-notes",
                                "search_text": "Fedora 45 Base Image Update",
                                "doc": {
                                    "title": "Fedora 45 Base Image Update",
                                    "summary": "Includes Python 3.15 performance improvements.",
                                },
                            }
                        ],
                    }
                ),
                "input_tokens": 35,
                "output_tokens": 25,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                tg_transport=tg_transport,
                http_fetcher=fetcher,
            )
            with TestClient(app) as client:
                app.state.repo.upsert_integration(
                    slug="tg-ops",
                    provider="telegram",
                    display_name="Ops Telegram",
                    account_identifier="argo_ops_bot",
                    scopes=["bot_api"],
                    secrets={"bot_token": "991122:AAtesttoken", "operator_chat_id": "1001"},
                    status="ok",
                )
                app.state.repo.upsert_model(
                    slug="default-flash",
                    provider_type="google",
                    model_id="google:gemini-3.8-flash",
                    api_key="AIzaSyFakeKey",
                    is_default=True,
                )

                prompt_text = (
                    "Fetch https://blog.zabbix.com, save unseen articles "
                    "(discard 'case study') into collection zabbix_news, "
                    "and queue a short Telegram summary for human approval."
                )
                draft_res = client.post(
                    "/api/bots/builder/draft",
                    headers=headers,
                    json={"prompt": prompt_text, "linked_accounts": ["tg-ops"]},
                )
                self.assertEqual(draft_res.status_code, 200, draft_res.text)
                draft = draft_res.json()["draft"]
                created = client.post("/api/bots", headers=headers, json=draft)
                self.assertEqual(created.status_code, 201, created.text)
                bot_slug = created.json()["slug"]

                run_res = client.post(
                    f"/api/bots/{bot_slug}/trigger",
                    headers=headers,
                    json={"wait_for_chain": True},
                )
                self.assertEqual(run_res.status_code, 200, run_res.text)
                self.assertIn("https://blog.zabbix.com/rss.xml", fetcher.requested_urls)
                self.assertTrue(
                    any(
                        "rss_autodiscovered" in p
                        and "Zabbix 7.4 LTS Released With Streaming Telemetry" in p
                        for p in prompts_seen
                    )
                )
                saved_docs = app.state.repo.search_documents("zabbix_news", limit=10)
                self.assertEqual(len(saved_docs), 1)
                self.assertEqual(saved_docs[0]["external_key"], "zabbix-740-release")
                pending = client.get("/api/approvals?tab=pending", headers=headers).json()
                self.assertEqual(len(pending), 1)
                self.assertIn("Zabbix 7.4 LTS Released", pending[0]["payload"]["text"])

                # Legacy pre-existing scheduled bot (routine without webpage_urls) still extracts URL from role_prompt.
                legacy_bot = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Legacy Blog Watcher",
                        "role": "Watch Zabbix blog",
                        "role_prompt": "Fetch https://blog.zabbix.com and store articles into zabbix_news.",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["zabbix_news"], "write": ["zabbix_news"]},
                        "routines": [
                            {
                                "id": "rtn_legacy_1",
                                "type": "cron",
                                "label": "Scheduled polling",
                                "schedule": "Every 15m",
                                "enabled": True,
                            }
                        ],
                    },
                )
                self.assertEqual(legacy_bot.status_code, 201, legacy_bot.text)
                fetcher.requested_urls.clear()
                legacy_run = client.post(
                    "/api/bots/legacy-blog-watcher/trigger",
                    headers=headers,
                    json={"routine_id": "rtn_legacy_1", "wait_for_chain": True},
                )
                self.assertEqual(legacy_run.status_code, 200, legacy_run.text)
                self.assertIn("https://blog.zabbix.com/rss.xml", fetcher.requested_urls)

                # Multi-turn discovery loop: turn 1 calls fetch_public_webpage, turn 2 sees Markdown and saves doc.
                multi_bot = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Multi Step Notes Bot",
                        "role": "Fetch webpage and synthesize notes",
                        "role_prompt": "Inspect vendor release notes when requested.",
                        "outbound_rbac": "internal",
                        "collections": {"read": ["vendor_notes"], "write": ["vendor_notes"]},
                        "tools": ["fetch_public_webpage"],
                    },
                )
                self.assertEqual(multi_bot.status_code, 201, multi_bot.text)
                multi_run = client.post(
                    "/api/bots/multi-step-notes-bot/trigger",
                    headers=headers,
                    json={"input_text": "Read release notes now", "wait_for_chain": True},
                )
                self.assertEqual(multi_run.status_code, 200, multi_run.text)
                self.assertEqual(turn_state["multi_step"], 2)
                self.assertIn("Fedora 45 Base Image Update", prompts_seen[-1])
                notes_docs = app.state.repo.search_documents("vendor_notes", limit=10)
                self.assertEqual(len(notes_docs), 1)
                self.assertEqual(notes_docs[0]["external_key"], "fedora-45-notes")

    def test_conversational_bot_thread_memory_and_schedule_update(self) -> None:
        headers = self._sso_headers()

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            del req
            return {
                "text": json.dumps(
                    {
                        "summary": "Understood — I saved your bullet-point rule and updated my schedule to every 30 minutes.",
                        "actions": [
                            {
                                "type": "remember_rule",
                                "rule_text": "Always reply in concise executive bullet points.",
                            },
                            {
                                "type": "configure_routine",
                                "schedule": "Every 30m",
                            },
                        ],
                    }
                ),
                "input_tokens": 25,
                "output_tokens": 25,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                app.state.repo.upsert_model(
                    slug="default-flash",
                    provider_type="google",
                    model_id="google:gemini-3.8-flash",
                    api_key="AIzaSyFakeKey",
                    is_default=True,
                )
                created = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Executive Briefing Bot",
                        "role": "Summarize operational updates",
                        "outbound_rbac": "internal",
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                bot_slug = created.json()["slug"]

                msg_res = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=headers,
                    json={"text": "Always reply in concise executive bullet points and check every 30m"},
                )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                thread = msg_res.json()["messages"]
                self.assertEqual(thread[-1]["sender"], "bot")
                self.assertIn("every 30 minutes", thread[-1]["text"])

                rules = client.get("/api/style-rules", headers=headers).json()
                self.assertTrue(
                    any(
                        r["scope_slug"] == bot_slug
                        and "concise executive bullet points" in r["rule_text"]
                        for r in rules
                    )
                )
                updated_bot = client.get(f"/api/bots/{bot_slug}", headers=headers).json()
                self.assertEqual(updated_bot["routines"][0]["schedule"], "Every 30m")

    def test_debug_overview_and_secret_redaction(self) -> None:
        headers = self._sso_headers()
        raw_secrets = [
            "sk-testsecretkey1234567890abcd",
            "GOCSPX-supersecretvalue123456",
            "ya29.a0AfH6SMBxSecretTokenValue12345",
            "123456789:AAHsecretTelegramTokenValue12345",
        ]

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            del req
            return {
                "text": json.dumps(
                    {
                        "summary": f"Checked status with token {raw_secrets[2]} cleanly.",
                        "actions": [],
                    }
                ),
                "input_tokens": 15,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                app.state.repo.upsert_model(
                    slug="default-flash",
                    provider_type="google",
                    model_id="google:gemini-3.8-flash",
                    api_key="AIzaSyFakeKey",
                    is_default=True,
                )
                client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Trace Test Bot",
                        "role": "Produce debug trace",
                        "outbound_rbac": "internal",
                    },
                )
                run_res = client.post(
                    "/api/bots/trace-test-bot/trigger",
                    headers=headers,
                    json={"wait_for_chain": True},
                )
                self.assertEqual(run_res.status_code, 200, run_res.text)

                logging.getLogger("argo_core.test_debug").warning(
                    "Connector warning openai=%s google_secret=%s oauth=%s tg=%s",
                    raw_secrets[0],
                    raw_secrets[1],
                    raw_secrets[2],
                    raw_secrets[3],
                )

                overview = client.get("/api/debug/overview", headers=headers)
                self.assertEqual(overview.status_code, 200, overview.text)
                payload = overview.json()
                self.assertGreaterEqual(len(payload["traces"]), 1)
                self.assertTrue(
                    any(
                        entry["logger"] == "argo_core.test_debug"
                        for entry in payload["logs"]
                    )
                )
                serialized = json.dumps(payload)
                for secret in raw_secrets:
                    self.assertNotIn(secret, serialized)
                self.assertIn("<REDACTED_API_KEY>", serialized)
                self.assertIn("<REDACTED_CLIENT_SECRET>", serialized)
                self.assertIn("<REDACTED_OAUTH_ACCESS_TOKEN>", serialized)
                self.assertIn("<REDACTED_TELEGRAM_TOKEN>", serialized)

                cleared = client.post("/api/debug/clear", headers=headers)
                self.assertEqual(cleared.status_code, 200, cleared.text)
                after = client.get("/api/debug/overview", headers=headers).json()
                self.assertEqual(after["traces"], [])
                self.assertEqual(after["logs"], [])

    def test_oauth2_proxy_env_isolated_and_separate_personal_business_oauth_clients(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ARGO_GOOGLE_CLIENT_ID": "",
                "ARGO_GOOGLE_CLIENT_SECRET": "",
                "OAUTH2_PROXY_CLIENT_ID": "internal-sso-client.apps.googleusercontent.com",
                "OAUTH2_PROXY_CLIENT_SECRET": "GOCSPX-internal-sso-secret",
            },
            clear=False,
        ):
            env_settings = ArgoSettings.from_env()
            self.assertEqual(env_settings.google_client_id, "")
            self.assertEqual(env_settings.google_client_secret, "")

        google_transport = FakeGmailOAuthTransport()
        headers = self._sso_headers()
        client_a = "workspace-client-a.apps.googleusercontent.com"
        secret_a = "GOCSPX-workspace-secret-a"
        client_b = "personal-client-b.apps.googleusercontent.com"
        secret_b = "GOCSPX-personal-secret-b"

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, google_transport=google_transport)
            with TestClient(app) as client:
                # 1. Connect Business Gmail using Workspace Internal OAuth Client A
                biz_auth = client.post(
                    "/api/integrations/google/authorize",
                    headers=headers,
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": False,
                        "client_id": client_a,
                        "client_secret": secret_a,
                        "display_name": "Business Gmail",
                        "login_hint": "dimitri.bellini@quadrata-group.com",
                        "scope_groups": ["gmail_read", "gmail_compose"],
                    },
                )
                self.assertEqual(biz_auth.status_code, 200, biz_auth.text)
                biz_done = client.post(
                    "/api/integrations/google/callback",
                    headers=headers,
                    json={"code": "code-quadrata", "state": biz_auth.json()["state"]},
                )
                self.assertEqual(biz_done.status_code, 201, biz_done.text)
                self.assertEqual(biz_done.json()["slug"], "business-gmail")

                mid_cfg = client.get("/api/integrations/google/wizard-config", headers=headers).json()
                self.assertTrue(mid_cfg["has_saved_client"])
                self.assertFalse(mid_cfg["has_personal_gmail_client"])
                self.assertFalse(mid_cfg["has_server_client"])

                # 2. Connect Personal Gmail using External OAuth Client B
                per_auth = client.post(
                    "/api/integrations/google/authorize",
                    headers=headers,
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": False,
                        "client_id": client_b,
                        "client_secret": secret_b,
                        "display_name": "Personal Gmail",
                        "login_hint": "dimiz.dubai@gmail.com",
                        "scope_groups": ["gmail_read", "gmail_compose"],
                    },
                )
                self.assertEqual(per_auth.status_code, 200, per_auth.text)
                per_done = client.post(
                    "/api/integrations/google/callback",
                    headers=headers,
                    json={"code": "code-dimiz", "state": per_auth.json()["state"]},
                )
                self.assertEqual(per_done.status_code, 201, per_done.text)
                self.assertEqual(per_done.json()["slug"], "personal-gmail")

                full_cfg = client.get("/api/integrations/google/wizard-config", headers=headers).json()
                self.assertTrue(full_cfg["has_personal_gmail_client"])
                self.assertIsNotNone(full_cfg["personal_client_id_hint"])
                self.assertIsNotNone(full_cfg["workspace_client_id_hint"])
                self.assertEqual(len(full_cfg.get("saved_accounts") or []), 2)

                # 2b. Second colleague connects Personal Gmail with zero secrets -> reuses Client B & gets distinct slug
                col_auth = client.post(
                    "/api/integrations/google/authorize",
                    headers=headers,
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": True,
                        "display_name": "Personal Gmail",
                        "login_hint": "colleague@gmail.com",
                        "scope_groups": ["gmail_read", "gmail_compose"],
                    },
                )
                self.assertEqual(col_auth.status_code, 200, col_auth.text)
                col_qs = parse_qs(urlparse(col_auth.json()["authorization_url"]).query)
                self.assertEqual(col_qs["client_id"], [client_b])
                col_done = client.post(
                    "/api/integrations/google/callback",
                    headers=headers,
                    json={"code": "code-colleague", "state": col_auth.json()["state"]},
                )
                self.assertEqual(col_done.status_code, 201, col_done.text)
                self.assertEqual(col_done.json()["slug"], "personal-gmail-colleague")
                self.assertEqual(col_done.json()["account_identifier"], "colleague@gmail.com")

                # First user's personal-gmail integration stays intact alongside colleague's
                listed = client.get("/api/integrations", headers=headers).json()
                by_slug = {item["slug"]: item for item in listed}
                self.assertEqual(by_slug["personal-gmail"]["account_identifier"], "dimiz.dubai@gmail.com")
                self.assertEqual(by_slug["personal-gmail-colleague"]["account_identifier"], "colleague@gmail.com")

                # 3. Re-authorizing each integration with reuse_saved_client=True preserves its own client_id
                reauth_biz = client.post(
                    "/api/integrations/google/authorize",
                    headers=headers,
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": True,
                        "slug": "business-gmail",
                        "login_hint": "dimitri.bellini@quadrata-group.com",
                    },
                )
                self.assertEqual(reauth_biz.status_code, 200, reauth_biz.text)
                biz_qs = parse_qs(urlparse(reauth_biz.json()["authorization_url"]).query)
                self.assertEqual(biz_qs["client_id"], [client_a])

                reauth_per = client.post(
                    "/api/integrations/google/authorize",
                    headers=headers,
                    json={
                        "in_production_confirmed": True,
                        "reuse_saved_client": True,
                        "slug": "personal-gmail",
                        "login_hint": "dimiz.dubai@gmail.com",
                    },
                )
                self.assertEqual(reauth_per.status_code, 200, reauth_per.text)
                per_qs = parse_qs(urlparse(reauth_per.json()["authorization_url"]).query)
                self.assertEqual(per_qs["client_id"], [client_b])

    def test_blog_watcher_queues_approval_and_delivers_telegram_card_with_llm_aliases(self) -> None:
        headers = self._sso_headers()
        tg_transport = FakeTelegramTransport()
        http_fetcher = FakeHttpFetcher()
        http_fetcher.set_page("https://blog.zabbix.com", body=ZABBIX_BLOG_HTML)
        zabbix_8_rss = """<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>Zabbix Blog</title>
    <item>
      <title>What's New in Zabbix 8.0 LTS</title>
      <link>https://blog.zabbix.com/whats-new-in-zabbix-8-0-lts</link>
      <guid>zabbix-80-lts</guid>
      <pubDate>Sun, 15 Nov 2026 19:00:00 GMT</pubDate>
      <description>High availability and distributed telemetry enhancements in Zabbix 8.0 LTS.</description>
    </item>
  </channel>
</rss>
"""
        http_fetcher.set_page(
            "https://blog.zabbix.com/rss.xml",
            body=zabbix_8_rss,
            content_type="application/rss+xml; charset=utf-8",
        )

        call_state = {"count": 0}

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            del req
            call_state["count"] += 1
            if call_state["count"] == 1:
                return {
                    "text": json.dumps(
                        {
                            "summary": (
                                "Processed unseen Zabbix blog post 'What's New in Zabbix 8.0 LTS' "
                                "(not a case study), saved it to the zabbix_news collection, and queued "
                                "a Telegram summary for human approval."
                            ),
                            "actions": [
                                {
                                    "type": "save_document",
                                    "collection": "zabbix_news",
                                    "external_key": "zabbix-80-lts",
                                    "search_text": "What's New in Zabbix 8.0 LTS",
                                    "data": {
                                        "title": "What's New in Zabbix 8.0 LTS",
                                        "url": "https://blog.zabbix.com/whats-new-in-zabbix-8-0-lts",
                                        "summary": "Distributed high availability and streaming updates.",
                                    },
                                },
                                {
                                    "type": "request_human_approval",
                                    "summary": "New Zabbix article: What's New in Zabbix 8.0 LTS",
                                    "target": "@argo_ops_bot",
                                    "source_url": "https://blog.zabbix.com/whats-new-in-zabbix-8-0-lts",
                                },
                            ],
                        }
                    ),
                    "input_tokens": 55,
                    "output_tokens": 45,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Queued follow-up Telegram message via alias.",
                        "actions": [
                            {
                                "type": "send_telegram",
                                "account": "Argo Operations Bot",
                                "message": "Quick digest: Zabbix 8.0 LTS highlights.",
                            },
                            {"type": "nonexistent_tool", "foo": "bar"},
                        ],
                    }
                ),
                "input_tokens": 25,
                "output_tokens": 25,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                tg_transport=tg_transport,
                http_fetcher=http_fetcher,
            )
            with TestClient(app) as client:
                app.state.repo.upsert_model(
                    slug="default-flash",
                    provider_type="google",
                    model_id="google:gemini-3.8-flash",
                    api_key="AIzaSyFakeKey",
                    is_default=True,
                )
                tg_res = client.post(
                    "/api/integrations/telegram/onboard",
                    headers=headers,
                    json={
                        "bot_token": "123456789:AAHtestTelegramTokenValue12345",
                        "display_name": "Argo Operations Bot",
                        "operator_chat_id": "99887766",
                    },
                )
                self.assertEqual(tg_res.status_code, 201, tg_res.text)
                tg_slug = tg_res.json()["slug"]

                bot_res = client.post(
                    "/api/bots",
                    headers=headers,
                    json={
                        "name": "Fetch Https Blog Zabbix",
                        "role": "Watch Zabbix blog",
                        "role_prompt": (
                            "Fetch https://blog.zabbix.com, save unseen articles "
                            '(discard "case study") into collection zabbix_news, and queue a short '
                            "Telegram summary for human approval."
                        ),
                        "outbound_rbac": "draft",
                        "collections": {"read": ["zabbix_news"], "write": ["zabbix_news"]},
                        "linked_accounts": [tg_slug],
                    },
                )
                self.assertEqual(bot_res.status_code, 201, bot_res.text)
                bot_slug = bot_res.json()["slug"]

                trigger_res = client.post(
                    f"/api/bots/{bot_slug}/trigger",
                    headers=headers,
                    json={"wait_for_chain": True},
                )
                self.assertEqual(trigger_res.status_code, 200, trigger_res.text)

                # 1. Collection document saved with full doc fields
                docs = app.state.repo.search_documents("zabbix_news", limit=10)
                self.assertEqual(len(docs), 1)
                self.assertEqual(docs[0]["external_key"], "zabbix-80-lts")
                self.assertEqual(docs[0]["doc"]["title"], "What's New in Zabbix 8.0 LTS")

                # 2. Approvals queue has 1 pending card targeted at tg_slug
                approvals = client.get("/api/approvals", headers=headers).json()
                self.assertEqual(len(approvals), 1)
                approval = approvals[0]
                self.assertEqual(approval["status"], "pending")
                self.assertEqual(approval["target_account_slug"], tg_slug)
                self.assertEqual(
                    approval["payload"]["text"],
                    "New Zabbix article: What's New in Zabbix 8.0 LTS",
                )

                # 3. Telegram received inline Approve/Reject card on operator_chat_id
                self.assertEqual(len(tg_transport.messages), 1)
                tg_card = tg_transport.messages[0]
                self.assertEqual(tg_card["chat_id"], "99887766")
                self.assertIn("What's New in Zabbix 8.0 LTS", str(tg_card["text"]))
                self.assertIsNotNone(tg_card["reply_markup"])

                # 4. Approving card delivers final summary to chat_id 99887766 (ignoring @argo_ops_bot)
                resolve_res = client.post(
                    f"/api/approvals/{approval['id']}/resolve",
                    headers=headers,
                    json={"action": "approve"},
                )
                self.assertEqual(resolve_res.status_code, 200, resolve_res.text)
                self.assertEqual(resolve_res.json()["status"], "executed")
                self.assertEqual(len(tg_transport.messages), 2)
                self.assertEqual(tg_transport.messages[1]["chat_id"], "99887766")
                self.assertEqual(
                    tg_transport.messages[1]["text"],
                    "New Zabbix article: What's New in Zabbix 8.0 LTS",
                )

                # 5. Also verify send_telegram + display name + message + unknown action trace logging
                msg_res = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=headers,
                    json={"text": "Send follow-up digest"},
                )
                self.assertEqual(msg_res.status_code, 200, msg_res.text)
                approvals_after = client.get("/api/approvals", headers=headers).json()
                self.assertEqual(len(approvals_after), 1)
                newest_approval = approvals_after[0]
                self.assertNotEqual(newest_approval["id"], approval["id"])
                self.assertEqual(newest_approval["target_account_slug"], tg_slug)
                self.assertEqual(
                    newest_approval["payload"]["text"],
                    "Quick digest: Zabbix 8.0 LTS highlights.",
                )

                overview = client.get("/api/debug/overview", headers=headers).json()
                latest_trace = overview["traces"][0]
                action_outcomes = {
                    item["type"]: item.get("status") or item.get("outcome")
                    for item in latest_trace["turns"][0]["action_results"]
                }
                self.assertEqual(action_outcomes.get("publish_telegram"), "queued_approval")
                self.assertEqual(action_outcomes.get("nonexistent_tool"), "skipped_unknown_action")


if __name__ == "__main__":
    unittest.main()
