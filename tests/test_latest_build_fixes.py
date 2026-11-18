"""End-to-end tests for the 8 Argo build fixes (Pages in-place update, Desktop single screenshot & exec errors, Chat pagination, Auto-refresh data binding, Zero-token dedup & prompt compaction)."""

from __future__ import annotations

import asyncio
import functools
import json
import sys
import tempfile
import threading
import unittest
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
from argo_core.desktop.mcp_bridge import (  # noqa: E402
    DESKTOP_AGENT_VERSION,
    _DESKTOP_AGENT_SCRIPT,
    _DefaultDesktopAgentTransport,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.security.ssrf import PublicHttpResponse, validate_public_url  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _MutableWebFetcher:
    """In-memory public HTTP fetcher supporting mutable page HTML and ETag/304 checks."""

    def __init__(self) -> None:
        self.pages: dict[str, tuple[str, str]] = {}
        self.calls: list[str] = []

    def set_html(self, url: str, html_body: str, *, etag: str = '"v1"') -> None:
        self.pages[url] = (html_body, etag)

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        del timeout_seconds, max_redirects, max_bytes
        validate_public_url(url, resolver=lambda _host: ["93.184.216.34"])
        self.calls.append(url)
        body, etag = self.pages[url]
        req_etag = (headers or {}).get("If-None-Match")
        if req_etag and req_etag == etag:
            return PublicHttpResponse(
                url=url,
                status_code=304,
                headers={"ETag": etag},
                body="",
            )
        return PublicHttpResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8", "ETag": etag},
            body=body,
        )


class TestLatestBuildFixes(unittest.TestCase):
    """Verify all 8 fixes across Pages, Virtual Desktop, Chat Pagination, and Token Optimization."""

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
        docker_driver=None,
        http_fetcher=None,
    ):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text(
            "<!doctype html><html><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 40.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 15.0,
                "disk_percent": 30.0,
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            desktop_idle_timeout_seconds=300.0,
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            google_transport=google_transport,
            docker_driver=docker_driver,
            public_http_fetcher=http_fetcher,
        )

    def test_page_inplace_redesign_vs_explicit_new_page_and_autobind(self) -> None:
        prompts_seen: list[str] = []
        mode = {"step": "tweak_explicit"}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            prompts_seen.append(req.user_prompt)
            if "Generate a complete self-contained HTML5" in req.user_prompt or "Redesign/update a complete self-contained HTML5" in req.user_prompt:
                return {
                    "text": "<!DOCTYPE html><html><body><h1>Generated Update</h1><script>window.parent.postMessage({type:'ARGO_READY'},'*');</script></body></html>",
                    "input_tokens": 20,
                    "output_tokens": 25,
                }
            if mode["step"] == "new_page":
                return {
                    "text": json.dumps(
                        {
                            "summary": "Created a separate Weekly Metrics page.",
                            "actions": [
                                {
                                    "type": "upsert_page",
                                    "slug": "weekly-metrics",
                                    "title": "Weekly Metrics",
                                    "render_mode": "sandboxed_html",
                                    "content_payload": "<html><body>Metrics</body></html>",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 20,
                }
            # Even when the LLM invents a brand-new slug/title while tweaking, runner updates in-place!
            return {
                "text": json.dumps(
                    {
                        "summary": "Redesigned Executive Inbox Digest in-place.",
                        "actions": [
                            {
                                "type": "upsert_page",
                                "slug": "executive-inbox-triage-briefing",
                                "title": "Executive Inbox Triage & Briefing",
                                "render_mode": "sandboxed_html",
                                "content_payload": f"<html><body>Updated ({mode['step']})</body></html>",
                            }
                        ],
                    }
                ),
                "input_tokens": 25,
                "output_tokens": 30,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Dimiz eMail",
                        "role": "Screen emails",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["bot_dimiz-email_items"], "write": ["bot_dimiz-email_items"]},
                    },
                ).json()

                long_html = "<!DOCTYPE html><html><body>" + ("x" * 4500) + "</body></html>"
                created_pg = client.post(
                    "/api/pages",
                    headers=self._sso_headers(),
                    json={
                        "title": "Executive Inbox Digest",
                        "description": "Inbox digest",
                        "render_mode": "sandboxed_html",
                        "content_payload": long_html,
                        "allowed_collections": ["bot_dimiz-email_items"],
                        "owner_bot_slug": bot["slug"],
                    },
                )
                self.assertEqual(created_pg.status_code, 201, created_pg.text)
                orig_slug = created_pg.json()["slug"]
                self.assertEqual(orig_slug, "executive-inbox-digest")

                # 1. Explicit target_page_slug tweaks existing page in-place even if LLM emits a different slug
                r1 = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={
                        "text": "Change header layout and use English labels",
                        "target_page_slug": orig_slug,
                    },
                )
                self.assertEqual(r1.status_code, 200, r1.text)
                pages = client.get("/api/pages", headers=self._sso_headers()).json()
                self.assertEqual(len(pages), 1)
                self.assertEqual(pages[0]["slug"], orig_slug)
                self.assertEqual(pages[0]["title"], "Executive Inbox Triage & Briefing")
                self.assertIn("Updated (tweak_explicit)", pages[0]["content_payload"])
                # Target page preview passes > 3000 chars so full HTML is visible to the bot
                env1 = json.loads(prompts_seen[-1])
                self.assertGreater(len(env1["target_page"]["content_preview"]), 3500)
                # Auto-bound data collection stays intact even though LLM omitted allowed_collections
                self.assertEqual(pages[0]["allowed_collections"], ["bot_dimiz-email_items"])

                # 2. Conversational tweak WITHOUT target_page_slug still updates the owned page in-place
                mode["step"] = "tweak_chat"
                r2 = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Please tweak the dashboard card spacing and filter"},
                )
                self.assertEqual(r2.status_code, 200, r2.text)
                pages_after_tweak = client.get("/api/pages", headers=self._sso_headers()).json()
                self.assertEqual(len(pages_after_tweak), 1)
                self.assertEqual(pages_after_tweak[0]["slug"], orig_slug)
                self.assertIn("Updated (tweak_chat)", pages_after_tweak[0]["content_payload"])

                # 3. Live data added to bot collection immediately appears via /api/pages/{slug}/data
                app.state.repo.upsert_document(
                    collection="bot_dimiz-email_items",
                    external_key="gmail:biz:m99",
                    search_text="Contract signed",
                    doc={"title": "Contract Signed", "from": "vip@example.com"},
                )
                pg_data = client.get(
                    f"/api/pages/{orig_slug}/data",
                    headers=self._sso_headers(),
                ).json()
                self.assertEqual(pg_data["total_records"], 1)
                self.assertEqual(pg_data["records"][0]["doc"]["title"], "Contract Signed")

                # 4. Explicit "create a new page" request creates a 2nd Page
                mode["step"] = "new_page"
                r3 = client.post(
                    f"/api/bots/{bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Create a new page for Weekly Metrics"},
                )
                self.assertEqual(r3.status_code, 200, r3.text)
                pages_after_new = client.get("/api/pages", headers=self._sso_headers()).json()
                self.assertEqual(len(pages_after_new), 2)

                # 5. POST /api/pages/generate with existing_page_slug updates in-place & keeps collections
                gen = client.post(
                    "/api/pages/generate",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Refine colors",
                        "existing_page_slug": orig_slug,
                        "owner_bot_slug": bot["slug"],
                    },
                )
                self.assertEqual(gen.status_code, 201, gen.text)
                self.assertEqual(gen.json()["slug"], orig_slug)
                self.assertEqual(gen.json()["allowed_collections"], ["bot_dimiz-email_items"])
                self.assertIn("Existing Page HTML to redesign", prompts_seen[-1])

    def test_desktop_single_final_screenshot_and_exec_error_feedback(self) -> None:
        # Part A: Embedded Desktop Agent HTTP :9223 real subprocess execution + fail-fast stderr
        ns: dict[str, object] = {}
        exec(compile(_DESKTOP_AGENT_SCRIPT, "<desktop-agent>", "exec"), ns)
        server_cls = ns["_Server"]
        handler_cls = ns["_Handler"]
        server = server_cls(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            transport = _DefaultDesktopAgentTransport()
            endpoint = f"http://127.0.0.1:{port}"

            async def _run_agent_checks() -> None:
                health = await transport.health("exec-bot", endpoint)
                self.assertEqual(health["agent_version"], DESKTOP_AGENT_VERSION)

                exec_res = await transport.execute_action(
                    "exec-bot",
                    endpoint,
                    "exec",
                    {
                        "commands": [
                            "echo step1_ok",
                            "echo step2_err >&2; exit 22",
                            "echo step3_skipped",
                        ],
                        "show_terminal": False,
                    },
                )
                self.assertEqual(exec_res["status"], "command_failed")
                self.assertEqual(exec_res["exit_code"], 22)
                self.assertEqual(exec_res["failed_command"], "echo step2_err >&2; exit 22")
                self.assertEqual(len(exec_res["steps"]), 2)
                self.assertIn("step1_ok", exec_res["stdout"])
                self.assertIn("step2_err", exec_res["stderr"])

                mcp_err = await transport.call_mcp(
                    "exec-bot",
                    endpoint,
                    "tools/call",
                    {
                        "name": "desktop_exec",
                        "arguments": {"command": "echo oops >&2; exit 7", "show_terminal": False},
                    },
                )
                self.assertTrue(mcp_err["result"]["isError"])

            asyncio.run(_run_agent_checks())
        finally:
            server.shutdown()
            server.server_close()

        # Part B: Runner multi-turn single screenshot + MAX_TOOL_TURNS failure feedback
        llm_turn = {"n": 0, "scenario": "single_shot"}
        seen_images_per_turn: list[int] = []

        async def fake_desktop_llm(req: LLMRequest) -> dict[str, Any]:
            llm_turn["n"] += 1
            seen_images_per_turn.append(len(req.images))
            if llm_turn["scenario"] == "single_shot":
                if llm_turn["n"] == 1:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Launching terminal and typing command.",
                                "actions": [
                                    {"type": "desktop_launch", "app": "xfce4-terminal"},
                                    {"type": "desktop_type", "text": "ls -la"},
                                    {"type": "desktop_key", "keys": "Return"},
                                ],
                            }
                        ),
                        "input_tokens": 15,
                        "output_tokens": 20,
                    }
                if llm_turn["n"] == 2:
                    return {
                        "text": json.dumps(
                            {
                                "summary": "Running verification command.",
                                "actions": [
                                    {"type": "desktop_exec", "commands": ["echo hello", "ls -la"]}
                                ],
                            }
                        ),
                        "input_tokens": 18,
                        "output_tokens": 15,
                    }
                return {
                    "text": json.dumps({"summary": "All commands completed cleanly.", "actions": []}),
                    "input_tokens": 12,
                    "output_tokens": 10,
                }

            # Scenario: multi-command failure at MAX_TOOL_TURNS
            if llm_turn["n"] <= 5:
                return {
                    "text": json.dumps(
                        {
                            "summary": f"Step {llm_turn['n']} running.",
                            "actions": [
                                {
                                    "type": "desktop_exec",
                                    "commands": [
                                        "echo prep_ok",
                                        "rpm -Uvh https://repo.example.com/missing.rpm; exit 22",
                                        "dnf install -y zabbix-agent2",
                                    ],
                                }
                            ],
                        }
                    ),
                    "input_tokens": 10,
                    "output_tokens": 10,
                }
            # Final synthesis call returns generic summary without stderr to verify safety net too
            return {
                "text": json.dumps({"summary": "Checked installation outcome.", "actions": []}),
                "input_tokens": 10,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_desktop_llm,
                docker_driver=InMemoryDockerDriver(),
            )
            with TestClient(app) as client:
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Desktop Test Bot",
                        "role": "Execute terminal commands on desktop",
                        "runtime": "desktop",
                        "outbound_rbac": "internal",
                    },
                ).json()
                slug = bot["slug"]

                res = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Open terminal and run ls -la"},
                )
                self.assertEqual(res.status_code, 200, res.text)
                # Turn 2 and Turn 3 each saw 1 vision image, but ONLY 1 snapshot was persisted at the end!
                self.assertEqual(seen_images_per_turn, [0, 1, 1])
                msgs = client.get(f"/api/bots/{slug}/messages", headers=self._sso_headers()).json()
                actions = msgs[-1]["metadata"]["actions"]
                shot_urls = [a.get("screenshot_url") for a in actions if a.get("screenshot_url")]
                self.assertEqual(len(shot_urls), 1, f"Expected exactly 1 final screenshot, got {actions}")
                self.assertEqual(actions[-1]["type"], "desktop_exec")
                self.assertEqual(actions[-1]["screenshot_url"], shot_urls[0])
                snaps = app.state.repo.search_documents("desktop_snapshots", limit=50)
                self.assertEqual(len(snaps), 1)

                # Scenario 2: MAX_TOOL_TURNS failure feedback surfaces command + exit_code + stderr
                llm_turn["n"] = 0
                llm_turn["scenario"] = "fail_at_cap"
                fail_res = client.post(
                    f"/api/bots/{slug}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Install package via rpm and dnf"},
                )
                self.assertEqual(fail_res.status_code, 200, fail_res.text)
                summary_out = fail_res.json()["result"]["summary"]
                self.assertIn("22", summary_out)
                self.assertIn("rpm -Uvh", summary_out)

    def test_chat_thread_pagination_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Heavy Thread Bot",
                        "role": "Hold long chat history",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                ).json()
                slug = bot["slug"]
                # Delete welcome message so we have exact 95 seeded messages
                welcome = client.get(f"/api/bots/{slug}/messages", headers=self._sso_headers()).json()[0]
                app.state.repo.delete_document("bot_threads", welcome["id"])

                for idx in range(1, 96):
                    app.state.repo.append_bot_message(
                        slug,
                        "user" if idx % 2 == 1 else "bot",
                        f"Message #{idx:02d}",
                    )

                page1 = client.get(
                    f"/api/bots/{slug}/messages?limit=40",
                    headers=self._sso_headers(),
                )
                self.assertEqual(page1.status_code, 200)
                self.assertEqual(page1.headers.get("X-Has-More"), "true")
                self.assertEqual(page1.headers.get("X-Total-Count"), "95")
                p1_data = page1.json()
                self.assertEqual(len(p1_data), 40)
                self.assertEqual(p1_data[0]["text"], "Message #56")
                self.assertEqual(p1_data[-1]["text"], "Message #95")

                page2 = client.get(
                    f"/api/bots/{slug}/messages?limit=40&before_id={p1_data[0]['id']}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(page2.status_code, 200)
                self.assertEqual(page2.headers.get("X-Has-More"), "true")
                p2_data = page2.json()
                self.assertEqual(len(p2_data), 40)
                self.assertEqual(p2_data[0]["text"], "Message #16")
                self.assertEqual(p2_data[-1]["text"], "Message #55")

                page3 = client.get(
                    f"/api/bots/{slug}/messages?limit=40&before_id={p2_data[0]['id']}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(page3.status_code, 200)
                self.assertEqual(page3.headers.get("X-Has-More"), "false")
                p3_data = page3.json()
                self.assertEqual(len(p3_data), 15)
                self.assertEqual(p3_data[0]["text"], "Message #01")
                self.assertEqual(p3_data[-1]["text"], "Message #15")

                all_texts = [m["text"] for m in [*p3_data, *p2_data, *p1_data]]
                self.assertEqual(all_texts, [f"Message #{i:02d}" for i in range(1, 96)])

    def test_token_optimization_healing_discard_dedup_webpage_hash_and_prompt_compaction(self) -> None:
        llm_requests: list[LLMRequest] = []
        fake_inbox = [
            {
                "id": "gm_1",
                "thread_id": "thr_gm_1",
                "from": "Newsletter <promo@shop.example.com>",
                "to": "me@gmail.com",
                "subject": "50% Off Promo",
                "snippet": "Limited time sale.",
                "label_ids": ["INBOX", "UNREAD"],
            }
        ]

        class _FakeGmailTransport:
            async def refresh_and_verify(self, **kwargs) -> dict[str, Any]:
                del kwargs
                return {"access_token": "ya29.tok", "expiry": "2099-01-01T00:00:00Z", "email": "me@gmail.com"}

            async def search_gmail_messages(
                self, *, access_token: str, query: str = "", max_results: int = 10, redact_list=None, exclude_ids=None
            ) -> list[dict[str, Any]]:
                del access_token, query, redact_list
                excluded = set(exclude_ids or ())
                return [m for m in fake_inbox[:max_results] if m["id"] not in excluded]

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            llm_requests.append(req)
            # Bot intentionally discards item without calling upsert_document!
            return {
                "text": json.dumps({"summary": "Checked items; all promotional noise discarded.", "actions": []}),
                "input_tokens": 60,
                "output_tokens": 15,
            }

        fetcher = _MutableWebFetcher()
        page_url = "https://status.vendor.example.org/changelog"
        fetcher.set_html(page_url, "<html><head><title>Changelog</title></head><body><main><p>Release 1.0</p></main></body></html>", etag='"v1"')

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                google_transport=_FakeGmailTransport(),
                http_fetcher=fetcher,
            )
            with TestClient(app) as client:
                # 1. Builder assigns dedicated data collection to Gmail bot even without "rss"/"collect"
                draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={"prompt": "Check my Gmail inbox every 15 minutes and discard promos"},
                )
                self.assertEqual(draft.status_code, 200, draft.text)
                draft_write = draft.json()["draft"]["collections"]["write"]
                self.assertTrue(any(c != "bot_threads" for c in draft_write), draft_write)
                llm_requests.clear()

                # 2. Legacy bot created with ONLY bot_threads auto-heals and deduplicates at 0 tokens
                app.state.repo.upsert_integration(
                    slug="personal-gmail",
                    provider="google",
                    display_name="Personal Gmail",
                    account_identifier="me@gmail.com",
                    scopes=["gmail_read"],
                    secrets={
                        "client_id": "cid",
                        "client_secret": "csec",
                        "refresh_token": "1//ref",
                        "access_token": "ya29.tok",
                        "expiry": "2099-01-01T00:00:00Z",
                    },
                    status="ok",
                )
                legacy_email_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Legacy Email Bot",
                        "role": "Screen Gmail inbox",
                        "role_prompt": "Check unread Gmail inbox and discard noise.",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["bot_threads"], "write": ["bot_threads"]},
                    },
                ).json()
                slug_email = legacy_email_bot["slug"]

                async def _cron_email():
                    return await app.state.bot_runner.execute_bot(slug_email, trigger_type="cron:rtn_1")

                res_e1 = client.portal.call(_cron_email)  # type: ignore[union-attr]
                self.assertEqual(res_e1["status"], "completed")
                self.assertEqual(len(llm_requests), 1)
                # Verify prompt compaction on background cron poll + API-only bot
                cron_env = json.loads(llm_requests[0].user_prompt)
                self.assertNotIn("recent_thread_messages", cron_env)
                self.assertNotIn("desktop_browse", llm_requests[0].system_prompt)
                healed_bot = client.get(f"/api/bots/{slug_email}", headers=self._sso_headers()).json()
                self.assertIn(f"bot_{slug_email}_items", healed_bot["collections"]["write"])

                res_e2 = client.portal.call(_cron_email)  # type: ignore[union-attr]
                self.assertEqual(res_e2["status"], "deduplicated_noop")
                self.assertEqual(res_e2["tokens_used"], 0)
                self.assertEqual(len(llm_requests), 1)

                # 3. Webpage watcher that discards items still dedups at 0 tokens via ingestion_seen_keys
                web_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Changelog Watcher",
                        "role": "Watch changelog webpage",
                        "role_prompt": f"Check {page_url} and summarize releases.",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "collections": {"read": ["changelog_items"], "write": ["changelog_items"]},
                    },
                ).json()
                slug_web = web_bot["slug"]

                async def _cron_web():
                    return await app.state.bot_runner.execute_bot(slug_web, trigger_type="cron:rtn_w")

                rw1 = client.portal.call(_cron_web)  # type: ignore[union-attr]
                self.assertEqual(rw1["status"], "completed")
                self.assertEqual(len(llm_requests), 2)

                # Run 2 with unchanged webpage (304 / identical hash) -> 0 tokens!
                rw2 = client.portal.call(_cron_web)  # type: ignore[union-attr]
                self.assertEqual(rw2["status"], "deduplicated_noop")
                self.assertEqual(rw2["tokens_used"], 0)
                self.assertEqual(len(llm_requests), 2)

                # Run 3 when webpage body changes -> triggers LLM once!
                fetcher.set_html(
                    page_url,
                    "<html><head><title>Changelog</title></head><body><main><p>Release 2.0 Available</p></main></body></html>",
                    etag='"v2"',
                )
                rw3 = client.portal.call(_cron_web)  # type: ignore[union-attr]
                self.assertEqual(rw3["status"], "completed")
                self.assertEqual(len(llm_requests), 3)

                # Run 4 again unchanged -> back to 0 tokens!
                rw4 = client.portal.call(_cron_web)  # type: ignore[union-attr]
                self.assertEqual(rw4["status"], "deduplicated_noop")
                self.assertEqual(rw4["tokens_used"], 0)
                self.assertEqual(len(llm_requests), 3)

                # 4. Models stats reflect deduplicated 0-token checks; ingestion_seen_keys stays internal
                models_resp = client.get("/api/models", headers=self._sso_headers()).json()
                self.assertGreaterEqual(models_resp["deduplicated_runs_today"], 3)
                cols = {c["slug"]: c for c in client.get("/api/collections", headers=self._sso_headers()).json()}
                self.assertTrue(cols["ingestion_seen_keys"]["is_internal"])


if __name__ == "__main__":
    unittest.main()
