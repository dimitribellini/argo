"""Sprint 4 tests: SSRF-guarded RSS/Web tools, UniversalBotRunner chains, RBAC caps & Dual-UI Approvals."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.bus.valkey_bus import MAX_HOP_COUNT, EventBus  # noqa: E402
from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.connectors.linkedin import LinkedInService  # noqa: E402
from argo_core.connectors.telegram_bot import TelegramBotService  # noqa: E402
from argo_core.db.repositories import ArgoRepository  # noqa: E402
from argo_core.db.sqlite import init_db  # noqa: E402
from argo_core.llm.router import LLMRequest, LLMRouter  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.bot_runner import UniversalBotRunner  # noqa: E402
from argo_core.runner.scheduler import BotScheduler, parse_routine_schedule  # noqa: E402
from argo_core.approvals.coordinator import ApprovalCoordinator  # noqa: E402
from argo_core.security.ssrf import (  # noqa: E402
    AntiBotHaltError,
    PublicHttpResponse,
    SSRFBlockedError,
    SafePublicHttpFetcher,
)
from argo_core.security.vault import SecretVault  # noqa: E402
from argo_core.tools.public_web import fetch_public_webpage, fetch_rss_feed  # noqa: E402


SAMPLE_RSS_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>Vendor Security Advisories</title>
    <item>
      <title>Zabbix 7.4 LTS Security Release</title>
      <link>https://vendor.example.org/advisories/zabbix-7-4-sec</link>
      <guid>adv-zabbix-7401</guid>
      <pubDate>Sun, 15 Nov 2026 08:00:00 GMT</pubDate>
      <description>&lt;p&gt;Fixes TLS session handling in proxy worker.&lt;/p&gt;</description>
    </item>
  </channel>
</rss>
"""

SAMPLE_ATOM_XML = """<?xml version="1.0" encoding="UTF-8" ?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Linux Kernel Releases</title>
  <entry>
    <id>urn:kernel:6.18.1</id>
    <title>Linux 6.18.1 Released</title>
    <link rel="alternate" href="https://vendor.example.org/kernel-6-18-1"/>
    <updated>2026-11-15T07:30:00Z</updated>
    <summary>Stability updates for Fedora 45 networking stack.</summary>
  </entry>
</feed>
"""

SAMPLE_WEBPAGE_HTML = """<!doctype html>
<html>
<head><title>Zabbix 7.4 Advisory Note</title></head>
<body>
  <nav><a href="/home">Ignore Nav</a></nav>
  <script>console.log("ignore");</script>
  <article>
    <h1>Zabbix 7.4 LTS Patch</h1>
    <p>Operators should upgrade proxies. Read the <a href="/docs/upgrade">upgrade guide</a>.</p>
  </article>
  <footer>Ignore Footer</footer>
</body>
</html>
"""


class FakeHttpFetcher:
    """In-memory PublicHttpFetcher with ETag/304 tracking and SSRF delegation."""

    def __init__(self) -> None:
        self.routes: dict[str, list[dict[str, object]]] = {}
        self.seen_headers: list[tuple[str, dict[str, str]]] = []
        self._ssrf = SafePublicHttpFetcher(resolver=lambda _host: ["93.184.216.34"])

    def set_response(
        self,
        url: str,
        *,
        body: str = "",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        anti_bot: bool = False,
    ) -> None:
        self.routes[url] = [
            {
                "body": body,
                "status_code": status_code,
                "headers": headers or {},
                "anti_bot": anti_bot,
            }
        ]

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        if url.startswith(("http://127.", "http://169.254.", "http://10.", "http://192.168.")):
            return await self._ssrf.fetch(url, headers=headers)
        req_headers = dict(headers or {})
        self.seen_headers.append((url, req_headers))
        item = (self.routes.get(url) or [{"body": "", "status_code": 404, "headers": {}, "anti_bot": False}])[0]
        if item["anti_bot"]:
            raise AntiBotHaltError(
                url=url,
                status_code=int(item["status_code"]),
                reason=f"HTTP {item['status_code']} anti-bot Turnstile challenge on {url}",
            )
        expected_etag = str((item["headers"] or {}).get("ETag") or "")
        if expected_etag and req_headers.get("If-None-Match") == expected_etag:
            return PublicHttpResponse(url=url, status_code=304, headers=dict(item["headers"]), body="")
        return PublicHttpResponse(
            url=url,
            status_code=int(item["status_code"]),
            headers=dict(item["headers"]),
            body=str(item["body"]),
        )


class FakeTelegramTransport:
    """In-memory Telegram Bot API double capturing cards, edits, and channel publishes."""

    def __init__(self) -> None:
        self.sent_messages: list[dict[str, object]] = []
        self.edited_messages: list[dict[str, object]] = []
        self.answered_callbacks: list[dict[str, object]] = []
        self._msg_seq = 500

    async def get_me(self, bot_token: str) -> dict[str, object]:
        return {"bot_id": 990044, "username": "argo_gate_bot", "first_name": "Argo Gate"}

    async def set_webhook(self, bot_token: str, *, url: str, secret_token: str, allowed_updates: list[str] | None = None) -> bool:
        return True

    async def send_message(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self._msg_seq += 1
        rec = {
            "chat_id": str(chat_id),
            "message_id": self._msg_seq,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.sent_messages.append(rec)
        return {"message_id": self._msg_seq, "chat_id": str(chat_id)}

    async def answer_callback_query(
        self,
        bot_token: str,
        *,
        callback_query_id: str,
        text: str | None = None,
    ) -> bool:
        self.answered_callbacks.append({"callback_query_id": callback_query_id, "text": text})
        return True

    async def edit_message_text(
        self,
        bot_token: str,
        *,
        chat_id: str | int,
        message_id: int,
        text: str,
        reply_markup: dict[str, object] | None = None,
    ) -> dict[str, object]:
        self.edited_messages.append(
            {
                "chat_id": str(chat_id),
                "message_id": int(message_id),
                "text": text,
                "reply_markup": reply_markup,
            }
        )
        return {"message_id": int(message_id)}


class TestSprint4RunnerAndApprovals(unittest.TestCase):
    """Verify Sprint 4 public tools, composable pipelines, RBAC caps, and dual-UI approvals."""

    def _build_env(
        self,
        tmp: str,
        *,
        llm_transport=None,
        tg_transport: FakeTelegramTransport | None = None,
        http_fetcher: FakeHttpFetcher | None = None,
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
        )
        app = create_app(
            settings=settings,
            llm_transport=llm_transport,
            telegram_transport=tg_transport,
            public_http_fetcher=http_fetcher,
        )
        return app

    @staticmethod
    def _sso_headers() -> dict[str, str]:
        return {
            "X-Auth-Request-Email": "operator@example.com",
            "X-Auth-Request-User": "operator",
        }

    def test_fetch_rss_feed_etag_304_ssrf_and_antibot_halt(self) -> None:
        fetcher = FakeHttpFetcher()
        fetcher.set_response(
            "https://vendor.example.org/rss.xml",
            body=SAMPLE_RSS_XML,
            headers={"ETag": '"v1-rss"', "Last-Modified": "Sun, 15 Nov 2026 08:00:00 GMT"},
        )
        fetcher.set_response("https://vendor.example.org/atom.xml", body=SAMPLE_ATOM_XML)
        fetcher.set_response("https://vendor.example.org/waf", status_code=403, anti_bot=True)

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, http_fetcher=fetcher)
            with TestClient(app) as client:
                first = client.post(
                    "/api/tools/fetch-rss",
                    json={"url": "https://vendor.example.org/rss.xml", "limit": 10},
                )
                self.assertEqual(first.status_code, 200, first.text)
                first_data = first.json()
                self.assertFalse(first_data["not_modified"])
                self.assertEqual(first_data["feed_title"], "Vendor Security Advisories")
                self.assertEqual(len(first_data["entries"]), 1)
                self.assertEqual(first_data["entries"][0]["id"], "adv-zabbix-7401")
                self.assertTrue(first_data["entries"][0]["external_key"].startswith("rss:"))
                self.assertEqual(len(first_data["entries"][0]["external_key"]), 28)

                # Second fetch sends If-None-Match & receives 304 zero-parse response
                second = client.post(
                    "/api/tools/fetch-rss",
                    json={"url": "https://vendor.example.org/rss.xml"},
                )
                self.assertEqual(second.status_code, 200)
                second_data = second.json()
                self.assertTrue(second_data["not_modified"])
                self.assertEqual(second_data["entries"], [])
                self.assertEqual(fetcher.seen_headers[-1][1].get("If-None-Match"), '"v1-rss"')

                # Atom 1.0 feed normalization
                atom = client.post(
                    "/api/tools/fetch-rss",
                    json={"url": "https://vendor.example.org/atom.xml"},
                )
                self.assertEqual(atom.status_code, 200)
                self.assertEqual(atom.json()["entries"][0]["title"], "Linux 6.18.1 Released")

                # SSRF blocks metadata / loopback targets cleanly with HTTP 403
                ssrf = client.post(
                    "/api/tools/fetch-rss",
                    json={"url": "http://169.254.169.254/latest/meta-data/"},
                )
                self.assertEqual(ssrf.status_code, 403)

                # Anti-bot 403 halts transparently & emits Activity alert
                waf = client.post(
                    "/api/tools/fetch-rss",
                    json={"url": "https://vendor.example.org/waf"},
                )
                self.assertEqual(waf.status_code, 502)
                events = client.get("/api/activity?category=alerts").json()
                self.assertTrue(any(ev["event_type"] == "web.fetch.halted" for ev in events))

        # Exercise feedparser sys.modules branch
        fake_feedparser = types.ModuleType("feedparser")
        fake_feedparser.parse = lambda _txt: types.SimpleNamespace(  # type: ignore[attr-defined]
            feed={"title": "Stub Feed"},
            entries=[
                {
                    "id": "stub-1",
                    "title": "Stub Entry",
                    "link": "https://vendor.example.org/stub-1",
                    "published": "2026-11-15",
                    "summary": "<p>Stub text</p>",
                }
            ],
        )
        with patch.dict(sys.modules, {"feedparser": fake_feedparser}):
            res = asyncio.run(
                fetch_rss_feed("https://vendor.example.org/atom.xml", fetcher=fetcher)
            )
            self.assertEqual(res["feed_title"], "Stub Feed")
            self.assertEqual(res["entries"][0]["summary"], "Stub text")

    def test_fetch_public_webpage_markdown_ssrf_and_trafilatura_stub(self) -> None:
        fetcher = FakeHttpFetcher()
        fetcher.set_response(
            "https://vendor.example.org/docs/advisory",
            body=SAMPLE_WEBPAGE_HTML,
        )

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, http_fetcher=fetcher)
            with TestClient(app) as client:
                ok = client.post(
                    "/api/tools/fetch-webpage",
                    json={"url": "https://vendor.example.org/docs/advisory"},
                )
                self.assertEqual(ok.status_code, 200, ok.text)
                body = ok.json()
                self.assertEqual(body["title"], "Zabbix 7.4 Advisory Note")
                self.assertIn("# Zabbix 7.4 LTS Patch", body["markdown"])
                self.assertIn("https://vendor.example.org/docs/upgrade", body["markdown"])
                self.assertNotIn("Ignore Nav", body["markdown"])
                self.assertNotIn("Ignore Footer", body["markdown"])

                blocked = client.post(
                    "/api/tools/fetch-webpage",
                    json={"url": "http://127.0.0.1:6379/info"},
                )
                self.assertEqual(blocked.status_code, 403)

        fake_traf = types.ModuleType("trafilatura")
        fake_traf.extract = lambda _html, **_kw: "# Trafilatura Extracted\nClean article body."  # type: ignore[attr-defined]
        with patch.dict(sys.modules, {"trafilatura": fake_traf}):
            res = asyncio.run(
                fetch_public_webpage(
                    "https://vendor.example.org/docs/advisory",
                    fetcher=fetcher,
                )
            )
            self.assertIn("# Trafilatura Extracted", res["markdown"])

    def test_composable_three_bot_pipeline_dedup_and_connector_rbac(self) -> None:
        fetcher = FakeHttpFetcher()
        feed_url = "https://vendor.example.org/security.xml"
        fetcher.set_response(
            feed_url,
            body=SAMPLE_RSS_XML,
            headers={"ETag": '"sec-1"'},
        )
        tg_transport = FakeTelegramTransport()
        llm_calls: list[dict[str, object]] = []

        async def fake_llm(req: LLMRequest) -> dict[str, object]:
            prompt_data = json.loads(req.user_prompt)
            llm_calls.append({"model": req.model_id, "prompt": prompt_data})
            sys_txt = req.system_prompt

            if "Bot slug: news-collector" in sys_txt:
                entries = prompt_data.get("unseen_ingested_entries", [])
                actions = []
                for entry in entries:
                    ext_key = entry["external_key"]
                    actions.append(
                        {
                            "type": "upsert_document",
                            "collection": "raw_news",
                            "external_key": ext_key,
                            "search_text": f"{entry['title']} {entry['summary']}",
                            "doc": entry,
                        }
                    )
                    actions.append(
                        {
                            "type": "emit_event",
                            "event_type": "news.collected",
                            "target_slug": "editorial-reviewer",
                            "payload": {"collection": "raw_news", "external_key": ext_key},
                        }
                    )
                return {
                    "text": json.dumps({"summary": f"Collected {len(entries)} unseen item(s).", "actions": actions}),
                    "input_tokens": 50,
                    "output_tokens": 40,
                }

            if "Bot slug: editorial-reviewer" in sys_txt:
                docs = prompt_data.get("permitted_collection_documents", [])
                ext_key = docs[0]["external_key"]
                title = docs[0]["doc"]["title"]
                draft = f"Community Release Alert: {title}. Upgrade recommended."
                review_key = f"rev:{ext_key}"
                return {
                    "text": json.dumps(
                        {
                            "summary": f"Reviewed {ext_key} for community release.",
                            "actions": [
                                {
                                    "type": "upsert_document",
                                    "collection": "reviewed_news",
                                    "external_key": review_key,
                                    "search_text": draft,
                                    "doc": {
                                        "title": title,
                                        "draft_text": draft,
                                        "source_url": docs[0]["doc"].get("url"),
                                        "borderline": "borderline" in title.lower(),
                                        "leak_test": "leak" in title.lower(),
                                        "wrong_target": "wrongtarget" in title.lower(),
                                    },
                                },
                                {
                                    "type": "emit_event",
                                    "event_type": "news.reviewed",
                                    "target_slug": "release-gatekeeper",
                                    "payload": {"collection": "reviewed_news", "external_key": review_key},
                                },
                            ],
                        }
                    ),
                    "input_tokens": 80,
                    "output_tokens": 60,
                }

            if "Bot slug: release-gatekeeper" in sys_txt:
                docs = prompt_data.get("permitted_collection_documents", [])
                doc_data = docs[0]["doc"]
                if doc_data.get("borderline"):
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Escalated borderline release draft for operator sign-off.",
                                "actions": [
                                    {
                                        "type": "request_human_approval",
                                        "account": "tg-ops",
                                        "action_type": "publish_telegram",
                                        "target": "@zabbix_community",
                                        "text": doc_data["draft_text"],
                                        "source_url": doc_data.get("source_url"),
                                        "escalation_note": "Borderline vendor claim; human confirmation requested.",
                                    }
                                ],
                            }
                        ),
                        "input_tokens": 70,
                        "output_tokens": 50,
                    }
                text_out = doc_data["draft_text"]
                if doc_data.get("leak_test"):
                    text_out = f"{text_out} sk-leaktestsecret998877665544"
                target_chan = "@other_channel" if doc_data.get("wrong_target") else "@zabbix_community"
                return {
                    "text": json.dumps(
                        {
                            "summary": "Dispatched community announcement through gatekeeper RBAC.",
                            "actions": [
                                {
                                    "type": "connector_publish",
                                    "account": "tg-ops",
                                    "action_type": "publish_telegram",
                                    "target": target_chan,
                                    "text": text_out,
                                    "source_url": doc_data.get("source_url"),
                                }
                            ],
                        }
                    ),
                    "input_tokens": 65,
                    "output_tokens": 45,
                }

            if "Bot slug: draft-only-bot" in sys_txt or "Bot slug: internal-only-bot" in sys_txt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Attempting outbound Telegram send.",
                            "actions": [
                                {
                                    "type": "connector_publish",
                                    "account": "tg-ops",
                                    "action_type": "publish_telegram",
                                    "target": "@zabbix_community",
                                    "text": "Unauthorized direct send attempt.",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 20,
                }

            return {"text": json.dumps({"summary": "ok", "actions": []}), "input_tokens": 10, "output_tokens": 5}

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm, tg_transport=tg_transport, http_fetcher=fetcher)
            with TestClient(app) as client:
                # Configure live Google API key so FakeLLM runs
                client.post(
                    "/api/models",
                    json={
                        "slug": "google-flash",
                        "provider_type": "google",
                        "model_id": "google:gemini-3.8-flash",
                        "api_key": "fake-google-key-for-runner",
                        "is_default": True,
                    },
                )
                # Onboard Telegram bot & channel
                tg_onboard = client.post(
                    "/api/integrations/telegram/onboard",
                    json={
                        "slug": "tg-ops",
                        "display_name": "Argo Ops Telegram",
                        "bot_token": "123456789:ABCDEFGhijKLMNOPqrstUVWXYZ_1234",
                        "operator_chat_id": "998877",
                        "admin_channels": ["@zabbix_community"],
                    },
                )
                self.assertEqual(tg_onboard.status_code, 201, tg_onboard.text)

                # Bot 1: News Collector
                b1 = client.post(
                    "/api/bots",
                    json={
                        "slug": "news-collector",
                        "name": "News Collector",
                        "role": "Poll vendor RSS and write raw_news",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "routines": [
                            {
                                "id": "rss_poll",
                                "label": "Poll Vendor RSS",
                                "schedule": "Every 15m",
                                "feed_urls": [feed_url],
                                "enabled": True,
                            }
                        ],
                        "collections": {"read": ["raw_news"], "write": ["raw_news"]},
                    },
                )
                self.assertEqual(b1.status_code, 201, b1.text)

                # Bot 2: Editorial Reviewer
                b2 = client.post(
                    "/api/bots",
                    json={
                        "slug": "editorial-reviewer",
                        "name": "Editorial Reviewer",
                        "role": "Score relevance and write reviewed_news",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "routines": [
                            {
                                "id": "on_collected",
                                "type": "on_event",
                                "event": "news.collected",
                                "label": "Review Collected News",
                                "enabled": True,
                            }
                        ],
                        "collections": {"read": ["raw_news"], "write": ["reviewed_news"]},
                    },
                )
                self.assertEqual(b2.status_code, 201, b2.text)

                # Bot 3: Release Gatekeeper (execute cap=1 to test cap exhaustion on 2nd execute)
                b3 = client.post(
                    "/api/bots",
                    json={
                        "slug": "release-gatekeeper",
                        "name": "Release Gatekeeper",
                        "role": "Enforce daily cap & PII gate before publishing",
                        "outbound_rbac": "execute",
                        "daily_cap": 1,
                        "routines": [
                            {
                                "id": "on_reviewed",
                                "type": "on_event",
                                "event": "news.reviewed",
                                "label": "Gatekeep Reviewed News",
                                "enabled": True,
                            }
                        ],
                        "tools": [
                            {
                                "type": "connector",
                                "account": "tg-ops",
                                "capability": "execute",
                                "target": "@zabbix_community",
                                "max_calls_per_day": 1,
                            },
                            {"type": "builtin", "name": "request_human_approval"},
                        ],
                        "collections": {"read": ["reviewed_news"], "write": []},
                    },
                )
                self.assertEqual(b3.status_code, 201, b3.text)

                # Run 1: Collect -> Review -> Gatekeeper Execute directly (1/1 cap)
                trig1 = client.post("/api/bots/news-collector/trigger", json={"wait_for_chain": True})
                self.assertEqual(trig1.status_code, 200, trig1.text)
                corr_id = trig1.json()["correlation_id"]
                self.assertEqual(len(llm_calls), 3)

                # Channel post published directly to @zabbix_community
                channel_msgs = [m for m in tg_transport.sent_messages if m["chat_id"] == "@zabbix_community"]
                self.assertEqual(len(channel_msgs), 1)
                self.assertIn("Zabbix 7.4 LTS Security Release", str(channel_msgs[0]["text"]))

                # Verify single correlation_id preserved across all 3 bot_runs hops
                runs = [r for r in client.get("/api/runs?limit=20").json() if r["correlation_id"] == corr_id]
                self.assertEqual({r["bot_slug"]: r["hop_count"] for r in runs}, {
                    "news-collector": 1,
                    "editorial-reviewer": 2,
                    "release-gatekeeper": 3,
                })

                # Run 2 (same RSS item): deduplicated at 0 LLM tokens!
                calls_before = len(llm_calls)
                trig2 = client.post("/api/bots/news-collector/trigger", json={"wait_for_chain": True})
                self.assertEqual(trig2.status_code, 200)
                self.assertEqual(trig2.json()["status"], "deduplicated_noop")
                self.assertEqual(trig2.json()["tokens_used"], 0)
                self.assertEqual(len(llm_calls), calls_before)

                # Run 3: New RSS item exceeds daily cap (1/1) -> downgraded to approvals_outbox + Telegram card
                fetcher.set_response(
                    feed_url,
                    body=SAMPLE_RSS_XML.replace("adv-zabbix-7401", "adv-zabbix-7402").replace(
                        "Zabbix 7.4 LTS Security Release", "Zabbix 7.4.1 Overflow Release"
                    ),
                    headers={"ETag": '"sec-2"'},
                )
                trig3 = client.post("/api/bots/news-collector/trigger", json={"wait_for_chain": True})
                self.assertEqual(trig3.status_code, 200)
                pending = client.get("/api/approvals?tab=pending").json()
                self.assertEqual(len(pending), 1)
                self.assertIn("Daily cap reached", pending[0]["escalation_note"])
                self.assertIsNotNone(pending[0]["telegram_message_id"])

                # Verify callback_data <= 64 bytes on Telegram permission card
                op_cards = [m for m in tg_transport.sent_messages if m["chat_id"] == "998877"]
                self.assertEqual(len(op_cards), 1)
                buttons = op_cards[0]["reply_markup"]["inline_keyboard"][0]  # type: ignore[index]
                self.assertLessEqual(len(buttons[0]["callback_data"].encode("utf-8")), 64)

                # Increase both bot & tool cap to 5, then verify borderline escalation, PII leak, and wrong target downgrades
                client.patch(
                    "/api/bots/release-gatekeeper",
                    json={
                        "daily_cap": 5,
                        "tools": [
                            {
                                "type": "connector",
                                "account": "tg-ops",
                                "capability": "execute",
                                "target": "@zabbix_community",
                                "max_calls_per_day": 5,
                            },
                            {"type": "builtin", "name": "request_human_approval"},
                        ],
                    },
                )

                for guid, title in [
                    ("adv-borderline-1", "Borderline Vendor Benchmark"),
                    ("adv-leak-1", "Leak Advisory"),
                    ("adv-target-1", "WrongTarget Advisory"),
                ]:
                    fetcher.set_response(
                        feed_url,
                        body=SAMPLE_RSS_XML.replace("adv-zabbix-7401", guid).replace(
                            "Zabbix 7.4 LTS Security Release", title
                        ),
                        headers={"ETag": f'"{guid}"'},
                    )
                    resp = client.post("/api/bots/news-collector/trigger", json={"wait_for_chain": True})
                    self.assertEqual(resp.status_code, 200)

                pending_notes = [p["escalation_note"] or "" for p in client.get("/api/approvals?tab=pending").json()]
                self.assertTrue(any("Borderline vendor claim" in note for note in pending_notes))
                self.assertTrue(any("Safety leak filter triggered" in note for note in pending_notes))
                self.assertTrue(any("outside allowed targets" in note for note in pending_notes))
                self.assertEqual(len([m for m in tg_transport.sent_messages if m["chat_id"] == "@zabbix_community"]), 1)

                # Test draft bot cannot publish directly & internal bot is blocked
                client.post(
                    "/api/bots",
                    json={"slug": "draft-only-bot", "name": "Draft Bot", "role": "Draft test", "outbound_rbac": "draft"},
                )
                d_res = client.post("/api/bots/draft-only-bot/trigger", json={"wait_for_chain": True})
                self.assertEqual(d_res.status_code, 200)
                self.assertEqual(d_res.json()["actions"][0]["outcome"], "queued_approval")

                client.post(
                    "/api/bots",
                    json={"slug": "internal-only-bot", "name": "Internal Bot", "role": "Internal test", "outbound_rbac": "internal", "daily_cap": 0},
                )
                i_res = client.post("/api/bots/internal-only-bot/trigger", json={"wait_for_chain": True})
                self.assertEqual(i_res.status_code, 200)
                self.assertEqual(i_res.json()["actions"][0]["status"], "blocked_rbac")

    def test_hop_count_loop_guard_halts_infinite_event_chain(self) -> None:
        async def ping_pong_llm(req: LLMRequest) -> dict[str, object]:
            if "Bot slug: ping-bot" in req.system_prompt:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Ping emitted",
                            "actions": [{"type": "emit_event", "event_type": "ping.event"}],
                        }
                    ),
                    "input_tokens": 5,
                    "output_tokens": 5,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Pong emitted",
                        "actions": [{"type": "emit_event", "event_type": "pong.event"}],
                    }
                ),
                "input_tokens": 5,
                "output_tokens": 5,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=ping_pong_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/models",
                    json={
                        "slug": "google-flash",
                        "provider_type": "google",
                        "model_id": "google:gemini-3.8-flash",
                        "api_key": "fake-key-loop",
                        "is_default": True,
                    },
                )
                client.post(
                    "/api/bots",
                    json={
                        "slug": "ping-bot",
                        "name": "Ping Bot",
                        "role": "Emit ping",
                        "outbound_rbac": "internal",
                        "routines": [{"id": "on_pong", "type": "on_event", "event": "pong.event", "enabled": True}],
                    },
                )
                client.post(
                    "/api/bots",
                    json={
                        "slug": "pong-bot",
                        "name": "Pong Bot",
                        "role": "Emit pong",
                        "outbound_rbac": "internal",
                        "routines": [{"id": "on_ping", "type": "on_event", "event": "ping.event", "enabled": True}],
                    },
                )

                res = client.post("/api/bots/ping-bot/trigger", json={"wait_for_chain": True})
                self.assertEqual(res.status_code, 200)
                corr = res.json()["correlation_id"]

                runs = [r for r in client.get("/api/runs?limit=30").json() if r["correlation_id"] == corr]
                self.assertTrue(all(r["hop_count"] <= MAX_HOP_COUNT for r in runs))
                events = [e for e in client.get("/api/activity?category=all&limit=50").json() if e["correlation_id"] == corr]
                self.assertTrue(any(e["event_type"] == "bot.hop_limit_halted" for e in events))

    def test_dual_ui_atomic_approval_lock_and_telegram_reply_revision(self) -> None:
        tg_transport = FakeTelegramTransport()

        async def revision_llm(req: LLMRequest) -> dict[str, object]:
            return {
                "text": "Concise Zabbix advisory: Upgrade proxy nodes today.",
                "input_tokens": 30,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=revision_llm, tg_transport=tg_transport)
            with TestClient(app) as client:
                client.post(
                    "/api/models",
                    json={
                        "slug": "google-flash",
                        "provider_type": "google",
                        "model_id": "google:gemini-3.8-flash",
                        "api_key": "fake-key-rev",
                        "is_default": True,
                    },
                )
                client.post(
                    "/api/integrations/telegram/onboard",
                    json={
                        "slug": "tg-ops",
                        "display_name": "Argo Ops Bot",
                        "bot_token": "123456789:ABCDEFGhijKLMNOPqrstUVWXYZ_1234",
                        "operator_chat_id": "998877",
                        "admin_channels": ["@zabbix_community"],
                    },
                )
                # Read generated webhook_secret from repo directly for test signing
                webhook_secret = app.state.repo.get_integration_secrets("tg-ops")["secrets"]["webhook_secret"]

                # Case A: Approval via Telegram button wins -> executed -> Web UI gets 409 Conflict
                apr1 = client.post(
                    "/api/approvals",
                    json={
                        "bot_slug": "release-gatekeeper",
                        "target_account_slug": "tg-ops",
                        "action_type": "publish_telegram",
                        "payload": {
                            "target": "@zabbix_community",
                            "text": "Zabbix 7.4 LTS shipped with CVSS 8.1 fix.",
                        },
                        "escalation_note": "Awaiting operator review",
                    },
                    headers=self._sso_headers(),
                ).json()
                self.assertIsNotNone(apr1["telegram_message_id"])
                card1_msg_id = apr1["telegram_message_id"]

                tg_cb = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                    json={
                        "update_id": 1001,
                        "callback_query": {
                            "id": "cb_ok_1",
                            "data": f"apr:ok:{apr1['id']}",
                            "from": {"id": 998877, "username": "alice"},
                            "message": {"message_id": card1_msg_id, "chat": {"id": 998877}, "text": "card"},
                        },
                    },
                )
                self.assertEqual(tg_cb.status_code, 200, tg_cb.text)
                self.assertEqual(tg_cb.json()["approval_status"], "executed")
                self.assertEqual(tg_transport.answered_callbacks[-1]["callback_query_id"], "cb_ok_1")
                self.assertIsNone(tg_transport.edited_messages[-1]["reply_markup"])
                self.assertIn("Executed by telegram:alice", str(tg_transport.edited_messages[-1]["text"]))

                # Concurrent/late Web UI click fails with 409 Conflict & zero duplicate send
                pub_count_before = len([m for m in tg_transport.sent_messages if m["chat_id"] == "@zabbix_community"])
                late_web = client.post(
                    f"/api/approvals/{apr1['id']}/resolve",
                    json={"action": "approve"},
                    headers=self._sso_headers(),
                )
                self.assertEqual(late_web.status_code, 409)
                self.assertEqual(
                    len([m for m in tg_transport.sent_messages if m["chat_id"] == "@zabbix_community"]),
                    pub_count_before,
                )

                # Case B: Web UI edit_approve with blank style_rule auto-synthesizes rule & locks Telegram card
                apr2 = client.post(
                    "/api/approvals",
                    json={
                        "bot_slug": "release-gatekeeper",
                        "target_account_slug": "tg-ops",
                        "action_type": "publish_telegram",
                        "payload": {
                            "target": "@zabbix_community",
                            "text": "Verbose advisory (CVSS 9.8) https://raw.example/long-url with extra details.",
                        },
                    },
                    headers=self._sso_headers(),
                ).json()
                web_edit = client.post(
                    f"/api/approvals/{apr2['id']}/resolve",
                    json={
                        "action": "edit_approve",
                        "edited_text": "Zabbix proxy patch available today.",
                    },
                    headers=self._sso_headers(),
                )
                self.assertEqual(web_edit.status_code, 200, web_edit.text)
                self.assertEqual(web_edit.json()["status"], "executed")
                rules = client.get("/api/style-rules").json()
                self.assertGreaterEqual(len(rules), 1)
                self.assertEqual(tg_transport.edited_messages[-1]["message_id"], apr2["telegram_message_id"])
                self.assertIsNone(tg_transport.edited_messages[-1]["reply_markup"])

                # Duplicate Telegram click after Web UI resolution returns already_resolved
                late_tg = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                    json={
                        "update_id": 1002,
                        "callback_query": {
                            "id": "cb_ok_2",
                            "data": f"apr:ok:{apr2['id']}",
                            "from": {"id": 998877, "username": "alice"},
                            "message": {"message_id": apr2["telegram_message_id"], "chat": {"id": 998877}, "text": "card"},
                        },
                    },
                )
                self.assertEqual(late_tg.status_code, 200)
                self.assertEqual(late_tg.json()["status"], "already_resolved")

                # Case C: Telegram reply_to_message revision supersedes old draft & posts new card
                apr3 = client.post(
                    "/api/approvals",
                    json={
                        "bot_slug": "release-gatekeeper",
                        "target_account_slug": "tg-ops",
                        "action_type": "publish_telegram",
                        "payload": {
                            "target": "@zabbix_community",
                            "text": "Long verbose draft with CVSS 9.1 details.",
                        },
                    },
                    headers=self._sso_headers(),
                ).json()
                rev_resp = client.post(
                    "/hooks/telegram/tg-ops",
                    headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
                    json={
                        "update_id": 1003,
                        "message": {
                            "message_id": 9001,
                            "chat": {"id": 998877},
                            "from": {"id": 998877, "username": "alice"},
                            "text": "Make it punchier and omit CVSS score",
                            "reply_to_message": {"message_id": apr3["telegram_message_id"]},
                        },
                    },
                )
                self.assertEqual(rev_resp.status_code, 200, rev_resp.text)
                rev_data = rev_resp.json()
                self.assertEqual(rev_data["status"], "revised")
                self.assertEqual(rev_data["superseded_id"], apr3["id"])
                new_id = rev_data["new_approval"]["id"]
                self.assertNotEqual(new_id, apr3["id"])
                self.assertEqual(rev_data["new_approval"]["payload"]["text"], "Concise Zabbix advisory: Upgrade proxy nodes today.")

                history = client.get("/api/approvals?tab=history").json()
                superseded_rows = [h for h in history if h["id"] == apr3["id"]]
                self.assertEqual(superseded_rows[0]["status"], "superseded")

    def test_bot_scheduler_interval_cron_and_apscheduler_stub(self) -> None:
        self.assertEqual(parse_routine_schedule("Every 15m"), {"kind": "interval", "seconds": 900, "raw": "Every 15m"})
        self.assertEqual(
            parse_routine_schedule("*/10 * * * *"),
            {"kind": "cron", "minute": "*/10", "hour": "*", "day": "*", "month": "*", "day_of_week": "*", "raw": "*/10 * * * *"},
        )
        self.assertIsNone(parse_routine_schedule("Event-driven"))
        self.assertIsNone(parse_routine_schedule("on:news.collected"))

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    json={
                        "slug": "cron-poller",
                        "name": "Cron Poller",
                        "role": "Scheduled polling bot",
                        "routines": [{"id": "c1", "label": "Every 5m", "schedule": "*/5 * * * *", "enabled": True}],
                    },
                )
                client.post(
                    "/api/bots",
                    json={
                        "slug": "event-only",
                        "name": "Event Only",
                        "role": "Subscribed bot",
                        "routines": [{"id": "e1", "type": "on_event", "event": "news.collected", "enabled": True}],
                    },
                )
                jobs = client.get("/api/scheduler/jobs").json()
                self.assertEqual(len(jobs), 1)
                self.assertEqual(jobs[0]["bot_slug"], "cron-poller")
                self.assertEqual(jobs[0]["kind"], "cron")

            # Verify APScheduler sys.modules branch
            added_jobs: dict[str, object] = {}

            class FakeAsyncIOScheduler:
                def __init__(self, timezone="UTC") -> None:
                    self.started = False

                def start(self) -> None:
                    self.started = True

                def shutdown(self, wait=False) -> None:
                    self.started = False

                def add_job(self, func, *, trigger, id, **kwargs) -> None:
                    added_jobs[id] = trigger

                def remove_job(self, job_id) -> None:
                    added_jobs.pop(job_id, None)

            fake_ap = types.ModuleType("apscheduler")
            fake_sched = types.ModuleType("apscheduler.schedulers")
            fake_async = types.ModuleType("apscheduler.schedulers.asyncio")
            fake_trig = types.ModuleType("apscheduler.triggers")
            fake_cron = types.ModuleType("apscheduler.triggers.cron")
            fake_int = types.ModuleType("apscheduler.triggers.interval")
            fake_async.AsyncIOScheduler = FakeAsyncIOScheduler  # type: ignore[attr-defined]
            fake_cron.CronTrigger = lambda **kw: ("cron", kw)  # type: ignore[attr-defined]
            fake_int.IntervalTrigger = lambda **kw: ("interval", kw)  # type: ignore[attr-defined]

            with patch.dict(
                sys.modules,
                {
                    "apscheduler": fake_ap,
                    "apscheduler.schedulers": fake_sched,
                    "apscheduler.schedulers.asyncio": fake_async,
                    "apscheduler.triggers": fake_trig,
                    "apscheduler.triggers.cron": fake_cron,
                    "apscheduler.triggers.interval": fake_int,
                },
            ):
                conn = init_db(Path(tmp) / "sched.db")
                vault = SecretVault(Fernet.generate_key().decode("ascii"))
                repo = ArgoRepository(conn=conn, vault=vault)
                repo.ensure_defaults()
                bus = EventBus("redis://127.0.0.1:6399/0", repo)
                router = LLMRouter(repo=repo)
                tg = TelegramBotService(repo=repo, bus=bus)
                li = LinkedInService(repo=repo, bus=bus)
                coord = ApprovalCoordinator(repo=repo, bus=bus, llm_router=router, telegram_service=tg, linkedin_service=li)
                runner = UniversalBotRunner(repo=repo, bus=bus, llm_router=router, approval_coordinator=coord)
                repo.create_bot(name="Stubbed Cron", role="Poll")
                scheduler = BotScheduler(repo=repo, runner=runner)

                async def _exercise() -> None:
                    await scheduler.start()
                    self.assertEqual(scheduler.backend, "apscheduler")
                    self.assertEqual(len(added_jobs), 1)
                    await scheduler.stop()

                asyncio.run(_exercise())
                conn.close()


if __name__ == "__main__":
    unittest.main()
