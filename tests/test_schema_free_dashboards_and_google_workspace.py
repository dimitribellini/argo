"""End-to-end tests for zero-hole bot-to-bot data linking, SQLite JSON1 sandbox, data_dashboard Living Pages, zero-egress CSP, and full Google Workspace ingestion."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.connectors.google_oauth import (  # noqa: E402
    DefaultGoogleOAuthTransport,
    GoogleOAuthConfigError,
    GoogleOAuthService,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeHttpResponse:
    """Minimal context-manager HTTP response double for DefaultGoogleOAuthTransport."""

    def __init__(self, body: bytes | str) -> None:
        self._bytes = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, n: int = -1) -> bytes:
        return self._bytes if n is None or n < 0 else self._bytes[:n]

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        del exc_type, exc, tb
        return False


class _MutableWorkspaceGoogleTransport:
    """In-memory Google transport supporting Gmail, Drive, and Calendar with mutable timestamps."""

    def __init__(self) -> None:
        self.drive_files: list[dict[str, Any]] = []
        self.drive_excerpts: dict[str, str] = {}
        self.calendar_events: list[dict[str, Any]] = []
        self.gmail_messages: list[dict[str, Any]] = []
        self.drive_calls = 0
        self.cal_calls = 0

    async def refresh_and_verify(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "access_token": "ya29.workspace_access",
            "expiry": "2099-01-01T00:00:00Z",
            "email": "ops@company.example",
        }

    async def search_gmail_messages(self, **kwargs: Any) -> list[dict[str, Any]]:
        excluded = set(kwargs.get("exclude_ids") or ())
        return [m for m in self.gmail_messages if m.get("id") not in excluded]

    async def search_drive_files(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        self.drive_calls += 1
        return {"files": list(self.drive_files), "next_page_token": None}

    async def read_drive_file_excerpt(self, **kwargs: Any) -> dict[str, Any]:
        fid = str(kwargs.get("file_id") or "")
        meta = next((f for f in self.drive_files if f.get("id") == fid), {"id": fid, "name": fid})
        return {**meta, "excerpt": self.drive_excerpts.get(fid, "")}

    async def list_calendar_events(self, **kwargs: Any) -> list[dict[str, Any]]:
        del kwargs
        self.cal_calls += 1
        return list(self.calendar_events)


class TestSchemaFreeDashboardsAndGoogleWorkspace(unittest.TestCase):
    """Verify scoped 1:1/Room linking, hermetic SQLite JSON1 sandbox, CSP, data_dashboard, and Google APIs."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None, google_transport=None):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text(
            "<!doctype html><html><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 32.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 11.0,
                "disk_percent": 22.0,
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
        )

    def test_security_untrusted_triggers_and_1to1_linking_and_approval_flow(self) -> None:
        prompts_seen: list[dict[str, Any]] = []
        turn_actions_queue: list[list[dict[str, Any]]] = []

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            prompts_seen.append(json.loads(req.user_prompt))
            actions = turn_actions_queue.pop(0) if turn_actions_queue else []
            return {
                "text": json.dumps({"summary": "Executed requested step.", "actions": actions}),
                "input_tokens": 25,
                "output_tokens": 20,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                runner = app.state.bot_runner
                repo = app.state.repo
                # 1. Create Fetcher Bot + sample records
                fetcher = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Email Fetcher",
                        "slug": "email-fetcher",
                        "role": "Collect incoming Gmail metadata",
                        "outbound_rbac": "internal",
                    },
                ).json()
                fetcher_col = next(c for c in fetcher["collections"]["write"] if c != "bot_threads")
                self.assertEqual(fetcher_col, "bot_email-fetcher_items")
                repo.upsert_document(
                    collection=fetcher_col,
                    external_key="gmail:biz:m1",
                    search_text="Invoice Q4",
                    doc={
                        "source_type": "gmail",
                        "from": "billing@vendor.io",
                        "subject": "Invoice Q4",
                        "size_estimate": 4200,
                        "attachments": [{"filename": "q4.pdf", "mime_type": "application/pdf", "size_bytes": 4096}],
                    },
                )

                # 2. Untrusted cron/webhook bot cannot read or bind another bot's collection
                cron_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Untrusted Scraper",
                        "slug": "untrusted-scraper",
                        "role": "Web scraper",
                        "outbound_rbac": "execute",
                    },
                ).json()
                for trig in ("cron:rtn_1", "on_event:webhook.received", "webhook"):
                    turn_actions_queue.append(
                        [
                            {
                                "type": "data_query",
                                "collections": [fetcher_col],
                                "sql": "SELECT COUNT(*) AS c FROM docs",
                            },
                            {
                                "type": "data_query",
                                "sql": f"SELECT COUNT(*) AS c FROM docs WHERE collection = '{fetcher_col}'",
                            },
                            {
                                "type": "upsert_page",
                                "slug": f"leaked-{trig.replace(':', '-')}",
                                "title": "Leaked",
                                "allowed_collections": [fetcher_col],
                            },
                        ]
                    )
                    res = asyncio.run(
                        runner.execute_bot(
                            cron_bot["slug"],
                            trigger_type=trig,
                            trigger_payload={"text": f"Check @{fetcher['name']}"},
                        )
                    )
                    statuses = [a["status"] for a in res["actions"]]
                    self.assertEqual(
                        statuses,
                        ["blocked_collection_acl", "blocked_collection_acl", "blocked_collection_acl"],
                        res,
                    )

                # 3. Standalone internal RBAC bot receives zero secret skill injection & auto-persists @Email Fetcher link in 1:1 chat
                arch = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Dashboard Architect",
                        "role": "Build live SQLite JSON1 dashboards",
                        "outbound_rbac": "internal",
                        "model": "google:gemini-4-argon",
                        "collections": {"read": ["bot_threads"], "write": ["bot_threads"]},
                    },
                ).json()
                self.assertTrue(arch["linked_accounts_restricted"])
                self.assertEqual(arch["linked_accounts"], [])
                self.assertEqual(repo.list_skills(scope_slug=arch["slug"]), [])

                # Turn 1: mention @Email Fetcher
                turn_actions_queue.append([{"type": "data_describe", "collections": [fetcher_col]}])
                turn_actions_queue.append(
                    [
                        {
                            "type": "upsert_page",
                            "slug": "inbox-overview",
                            "title": "Inbox Overview",
                            "template": "data_dashboard",
                            "allowed_collections": [fetcher_col],
                            "dashboard_spec": {
                                "subtitle": "Live email metrics",
                                "kpis": [{"label": "Emails", "sql": "SELECT COUNT(*) AS total FROM docs"}],
                            },
                        }
                    ]
                )
                t1 = client.post(
                    f"/api/bots/{arch['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Build a dashboard from @Email Fetcher"},
                )
                self.assertEqual(t1.status_code, 200, t1.text)
                arch_after_t1 = repo.get_bot(arch["slug"])
                self.assertIn(fetcher_col, arch_after_t1["collections"]["read"])
                self.assertTrue(
                    any(
                        ds["collection"] == fetcher_col
                        for ds in prompts_seen[-2].get("authorized_data_stores", [])
                    )
                )
                self.assertIn("source_data_profiles", prompts_seen[-2])
                self.assertIn("source_data_profiles", prompts_seen[-1])

                # Turn 2: tweak WITHOUT re-mentioning @Email Fetcher
                turn_actions_queue.append(
                    [
                        {
                            "type": "data_query",
                            "sql": "SELECT json_extract(doc_json, '$.from') AS sender, COUNT(*) AS cnt FROM docs GROUP BY 1",
                        },
                        {
                            "type": "upsert_page",
                            "slug": "inbox-overview",
                            "title": "Inbox Overview",
                            "template": "data_dashboard",
                            "allowed_collections": [fetcher_col],
                            "dashboard_spec": {
                                "subtitle": "Attachment size chart added",
                                "charts": [
                                    {
                                        "type": "bar",
                                        "title": "Attachment Sizes",
                                        "sql": "SELECT json_extract(doc_json, '$.subject') AS label, json_extract(doc_json, '$.size_estimate') AS val FROM docs",
                                    }
                                ],
                            },
                        },
                    ]
                )
                t2 = client.post(
                    f"/api/bots/{arch['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Add a chart of attachment sizes", "target_page_slug": "inbox-overview"},
                )
                self.assertEqual(t2.status_code, 200, t2.text)
                t2_actions = t2.json()["result"]["actions"]
                self.assertEqual([a["status"] for a in t2_actions], ["ok", "ok"], t2_actions)

                # 4. Non-internal (draft) bot mentioning @Email Fetcher or calling update_self_config requires Approval Card
                draft_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Draft Helper",
                        "slug": "draft-helper",
                        "role": "Draft emails",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["bot_threads"], "write": ["bot_threads"]},
                    },
                ).json()
                turn_actions_queue.append(
                    [
                        {"type": "data_query", "collections": [fetcher_col], "sql": "SELECT COUNT(*) FROM docs"},
                        {"type": "update_self_config", "read_collections": [fetcher_col]},
                    ]
                )
                d1 = client.post(
                    f"/api/bots/{draft_bot['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Read @Email Fetcher and draft replies"},
                )
                self.assertEqual(d1.status_code, 200, d1.text)
                self.assertNotIn(fetcher_col, repo.get_bot(draft_bot["slug"])["collections"]["read"])
                d1_actions = d1.json()["result"]["actions"]
                self.assertEqual(d1_actions[0]["status"], "queued_approval")
                self.assertEqual(d1_actions[1]["status"], "blocked_collection_acl")
                self.assertEqual(d1_actions[2]["status"], "queued_approval")

                pending = client.get("/api/approvals?tab=pending", headers=self._sso_headers()).json()
                update_cards = [
                    a for a in pending if a["bot_slug"] == draft_bot["slug"] and a["action_type"] == "update_bot_config"
                ]
                self.assertGreaterEqual(len(update_cards), 1)
                resolved = client.post(
                    f"/api/approvals/{update_cards[0]['id']}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve", "channel": "web_ui"},
                )
                self.assertEqual(resolved.status_code, 200, resolved.text)
                self.assertIn(fetcher_col, repo.get_bot(draft_bot["slug"])["collections"]["read"])

                # 5. Optional Group Room scoping: internal member reads teammate data; draft member cannot
                draft_room_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Room Draft Bot",
                        "slug": "room-draft-bot",
                        "role": "Draft member in room",
                        "outbound_rbac": "draft",
                        "collections": {"read": ["bot_threads"], "write": ["bot_threads"]},
                    },
                ).json()
                room = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Workspace Analytics Room",
                        "member_bot_slugs": [arch["slug"], fetcher["slug"], draft_room_bot["slug"]],
                        "coordinator_bot_slug": arch["slug"],
                    },
                ).json()
                turn_actions_queue.append(
                    [{"type": "data_query", "collections": [fetcher_col], "sql": "SELECT COUNT(*) AS cnt FROM docs"}]
                )
                room_res = client.post(
                    f"/api/rooms/{room['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": f"@{arch['slug']} count records"},
                )
                self.assertEqual(room_res.status_code, 200, room_res.text)
                self.assertEqual(room_res.json()["actions"][0]["status"], "ok")

                turn_actions_queue.append(
                    [{"type": "data_query", "collections": [fetcher_col], "sql": "SELECT COUNT(*) AS cnt FROM docs"}]
                )
                room_draft_res = client.post(
                    f"/api/rooms/{room['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": f"@{draft_room_bot['slug']} read fetcher data"},
                )
                self.assertEqual(room_draft_res.status_code, 200, room_draft_res.text)
                self.assertEqual(room_draft_res.json()["actions"][0]["status"], "blocked_collection_acl")

    def test_memory_sqlite_sandbox_authorizer_and_secret_scrubbing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                repo = app.state.repo
                repo.upsert_vault_secret(
                    name="Prod DB",
                    slug="prod-db",
                    secret_type="custom",
                    secrets={"api_token": "supersecret_vault_value_999"},
                )
                repo.upsert_document(
                    collection="bot_inbox_items",
                    external_key="m1",
                    search_text="token leak check",
                    doc={
                        "subject": "Auth check",
                        "notes": "Bearer ya29.secret_oauth_token_123456 and supersecret_vault_value_999",
                        "attendees": [{"email": "alice@example.com"}],
                    },
                )
                page = client.post(
                    "/api/pages",
                    headers=self._sso_headers(),
                    json={
                        "title": "Sandbox Probe",
                        "render_mode": "sandboxed_html",
                        "allowed_collections": ["bot_inbox_items"],
                    },
                ).json()

                # Forbidden SQL statements & tables rejected with 403 / 400
                forbidden_queries = [
                    ("PRAGMA table_info(docs)", 403),
                    ("ATTACH DATABASE ':memory:' AS stolen", 403),
                    ("INSERT INTO docs (id, collection, doc_json) VALUES ('x', 'y', '{}')", 403),
                    ("DROP TABLE docs", 403),
                    ("WITH x AS (SELECT 1) DELETE FROM docs", 403),
                    ("SELECT * FROM vault_secrets", 403),
                    ("SELECT * FROM integrations", 403),
                    ("SELECT * FROM oauth_accounts", 403),
                    ("SELECT * FROM sqlite_master", 403),
                    ("SELECT * FROM bot_threads", 403),
                    ("SELECT COUNT(*) FROM docs; DROP TABLE docs", 400),
                ]
                for sql, expected_code in forbidden_queries:
                    resp = client.post(
                        f"/api/pages/{page['slug']}/sql",
                        headers=self._sso_headers(),
                        json={"sql": sql},
                    )
                    self.assertEqual(resp.status_code, expected_code, (sql, resp.status_code, resp.text))

                # Scrubbing in both describe_collections and execute_sandboxed_json_query
                described = repo.describe_collections(["bot_inbox_items"])
                dumped_desc = json.dumps(described)
                self.assertNotIn("supersecret_vault_value_999", dumped_desc)
                self.assertNotIn("ya29.secret_oauth_token_123456", dumped_desc)

                ok_sql = client.post(
                    f"/api/pages/{page['slug']}/sql",
                    headers=self._sso_headers(),
                    json={"sql": "SELECT json_extract(doc_json, '$.notes') AS notes FROM docs"},
                )
                self.assertEqual(ok_sql.status_code, 200, ok_sql.text)
                notes_val = ok_sql.json()["rows"][0]["notes"]
                self.assertNotIn("supersecret_vault_value_999", notes_val)
                self.assertNotIn("ya29.secret_oauth_token_123456", notes_val)
                self.assertIn("<REDACTED>", notes_val)

    def test_csp_hardening_and_frontend_contracts(self) -> None:
        pages_view = (ROOT / "frontend" / "src" / "components" / "views" / "PagesView.tsx").read_text(
            encoding="utf-8"
        )
        inspector = (ROOT / "frontend" / "src" / "components" / "Inspector.tsx").read_text(
            encoding="utf-8"
        )
        modals = (ROOT / "frontend" / "src" / "components" / "Modals.tsx").read_text(
            encoding="utf-8"
        )
        api_ts = (ROOT / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")

        self.assertIn("ARGO_QUERY_SQL", pages_view)
        self.assertIn("ARGO_SQL_RESULT", pages_view)
        self.assertIn("ARGO_SQL_ERROR", pages_view)
        self.assertIn("prepareSandboxedPageSrcDoc", pages_view)
        self.assertIn("queryPageSql", api_ts)
        self.assertIn("Source Bots", inspector)
        self.assertNotIn("Dashboard Architect", modals)

        # Execute the real TypeScript prepareSandboxedPageSrcDoc implementation via Node + TypeScript transpiler
        match = re.search(
            r"const WEBUI_IFRAME_SCROLLBAR_STYLE[\s\S]*?export function prepareSandboxedPageSrcDoc\(rawHtml: string\): string \{[\s\S]*?\n\}",
            pages_view,
        )
        self.assertIsNotNone(match, "prepareSandboxedPageSrcDoc not found in PagesView.tsx")
        ts_snippet = match.group(0)
        node_script = f"""
const ts = require({json.dumps(str(ROOT / "frontend" / "node_modules" / "typescript"))});
const src = {json.dumps(ts_snippet)};
const out = ts.transpileModule(src, {{ compilerOptions: {{ module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }} }}).outputText;
const mod = {{ exports: {{}} }};
new Function("exports", "module", out)(mod.exports, mod);
const hostile = '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src *"><base href="https://evil.example/"><title>X</title></head><body>Hi</body></html>';
const res = mod.exports.prepareSandboxedPageSrcDoc(hostile);
console.log(JSON.stringify({{
  hasEvilCsp: res.includes("default-src *"),
  hasEvilBase: res.includes("evil.example"),
  hasConnectNone: res.includes("connect-src 'none'"),
  hasDefaultNone: res.includes("default-src 'none'"),
  hasFormNone: res.includes("form-action 'none'"),
  hasBaseUriNone: res.includes("base-uri 'none'"),
  hasScrollStyle: res.includes('id="argo-webui-scroll"'),
  cspBeforeTitle: res.indexOf("connect-src 'none'") < res.indexOf("<title>"),
}}));
"""
        proc = subprocess.run(
            ["node", "-e", node_script],
            check=True,
            capture_output=True,
            text=True,
        )
        parsed = json.loads(proc.stdout.strip())
        self.assertFalse(parsed["hasEvilCsp"])
        self.assertFalse(parsed["hasEvilBase"])
        self.assertTrue(parsed["hasConnectNone"])
        self.assertTrue(parsed["hasDefaultNone"])
        self.assertTrue(parsed["hasFormNone"])
        self.assertTrue(parsed["hasBaseUriNone"])
        self.assertTrue(parsed["hasScrollStyle"])
        self.assertTrue(parsed["cspBeforeTitle"])

        # Verify Source Bots & generic analytics builder contracts
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                draft_arch = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": (
                            "Create an analytics bot to inspect my linked Source Bots "
                            "and build interactive ECharts pages"
                        )
                    },
                )
                self.assertEqual(draft_arch.status_code, 200, draft_arch.text)
                draft_obj = draft_arch.json()["draft"]
                self.assertEqual(draft_obj["outbound_rbac"], "internal")
                self.assertTrue(draft_obj["linked_accounts_restricted"])
                self.assertEqual(draft_obj["linked_accounts"], [])
                draft_tool_names = [t.get("name") for t in draft_obj["tools"] if isinstance(t, dict)]
                self.assertIn("upsert_page", draft_tool_names)
                self.assertIn("data_query", draft_tool_names)

                b1 = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"name": "Source Alpha", "outbound_rbac": "internal"},
                ).json()
                b2 = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Analytics Explorer",
                        "outbound_rbac": "internal",
                        "tools": [{"type": "account", "slug": "acc-1", "capability": "read"}],
                    },
                ).json()
                self.assertEqual(b2["linked_accounts"], ["acc-1"])
                patched = client.patch(
                    f"/api/bots/{b2['slug']}",
                    headers=self._sso_headers(),
                    json={
                        "collections": {
                            "read": ["bot_threads", b1["collections"]["write"][0]],
                            "write": ["bot_threads"],
                        }
                    },
                )
                self.assertEqual(patched.status_code, 200, patched.text)
                self.assertIn(b1["collections"]["write"][0], patched.json()["collections"]["read"])

    def test_prebuilt_data_dashboard_engine_and_zero_token_live_queries(self) -> None:
        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            obs = json.loads(req.user_prompt).get("tool_observations") or []
            if not obs:
                return {
                    "text": json.dumps(
                        {
                            "summary": "",
                            "actions": [{"type": "data_describe", "collections": ["bot_mail_items", "bot_drive_items", "bot_cal_items"]}],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 12,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Published live Workspace Executive Dashboard.",
                        "actions": [
                            {
                                "type": "upsert_page",
                                "slug": "workspace-executive",
                                "title": "Workspace Executive",
                                "template": "data_dashboard",
                                "allowed_collections": ["bot_mail_items", "bot_drive_items", "bot_cal_items"],
                                "dashboard_spec": {
                                    "subtitle": "Gmail, Drive, and Calendar unified via SQLite JSON1",
                                    "kpis": [
                                        {"label": "Total Docs", "sql": "SELECT COUNT(*) AS cnt FROM docs"},
                                        {
                                            "label": "Attachments",
                                            "sql": "SELECT COUNT(*) AS cnt FROM docs, json_each(doc_json, '$.attachments') WHERE json_extract(doc_json, '$.source_type') = 'gmail'",
                                        },
                                    ],
                                    "charts": [
                                        {
                                            "type": "donut",
                                            "title": "By Source",
                                            "sql": "SELECT json_extract(doc_json, '$.source_type') AS src, COUNT(*) AS cnt FROM docs GROUP BY 1",
                                        },
                                        {
                                            "type": "bar",
                                            "title": "Drive Types",
                                            "sql": "SELECT json_extract(doc_json, '$.mimeType') AS mime, COUNT(*) AS cnt FROM docs WHERE collection = 'bot_drive_items' GROUP BY 1",
                                        },
                                    ],
                                    "filters": [{"label": "Unread", "value": "true"}],
                                    "table_sql": "SELECT collection, json_extract(doc_json, '$.subject') AS subject, json_extract(doc_json, '$.name') AS name, json_extract(doc_json, '$.summary') AS summary FROM docs LIMIT 50",
                                },
                            }
                        ],
                    }
                ),
                "input_tokens": 35,
                "output_tokens": 45,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                repo = app.state.repo
                # Seed mixed Gmail, Drive, Calendar + 230 rows across two collections to verify limit=200 & true total_records
                repo.upsert_document(
                    collection="bot_mail_items",
                    external_key="gmail:1",
                    search_text="mail 1",
                    doc={
                        "source_type": "gmail",
                        "from": "ceo@acme.io",
                        "subject": "Board Pack",
                        "is_unread": True,
                        "attachments": [{"filename": "deck.pdf", "mime_type": "application/pdf", "size_bytes": 1200}],
                    },
                )
                repo.upsert_document(
                    collection="bot_drive_items",
                    external_key="gdrive:1",
                    search_text="drive 1",
                    doc={
                        "source_type": "gdrive",
                        "name": "Q4 Plan",
                        "mimeType": "application/vnd.google-apps.document",
                        "owners": [{"emailAddress": "ops@acme.io"}],
                    },
                )
                for idx in range(228):
                    repo.upsert_document(
                        collection="bot_cal_items",
                        external_key=f"gcal:{idx}",
                        search_text=f"Sync {idx}",
                        doc={
                            "source_type": "gcal",
                            "summary": f"Sync {idx}",
                            "attendees": [{"email": f"user{idx % 5}@acme.io", "responseStatus": "accepted"}],
                        },
                    )

                desc = repo.describe_collections(["bot_mail_items", "bot_drive_items", "bot_cal_items"])
                self.assertEqual(desc["total_documents"], 230)
                paths_by_col = {
                    c["collection"]: {f["path"]: f for f in c["fields"]}
                    for c in desc["collections"]
                }
                self.assertIn("$.from", paths_by_col["bot_mail_items"])
                self.assertIn("$.attachments[].mime_type", paths_by_col["bot_mail_items"])
                self.assertIn("$.mimeType", paths_by_col["bot_drive_items"])
                self.assertIn("$.attendees[].email", paths_by_col["bot_cal_items"])

                arch = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Dashboard Architect",
                        "outbound_rbac": "internal",
                        "collections": {
                            "read": ["bot_threads", "bot_mail_items", "bot_drive_items", "bot_cal_items"],
                            "write": ["bot_threads"],
                        },
                    },
                ).json()
                chat_res = client.post(
                    f"/api/bots/{arch['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Build unified workspace dashboard"},
                )
                self.assertEqual(chat_res.status_code, 200, chat_res.text)

                page = client.get("/api/pages/workspace-executive", headers=self._sso_headers()).json()
                self.assertEqual(page["render_mode"], "sandboxed_html")
                html_body = page["content_payload"]
                self.assertIn("ARGO_QUERY_SQL", html_body)
                self.assertIn("ARGO_TRIGGER_BOT", html_body)
                self.assertIn("ARGO_OPEN_BOT", html_body)
                self.assertIn("ARGO_DOWNLOAD_FILE", html_body)
                self.assertIn("<svg", html_body)
                self.assertNotIn("cdn.", html_body.lower())

                # GET /api/pages/{slug}/data defaults to limit=200 and returns true total_records=230
                page_data = client.get(
                    "/api/pages/workspace-executive/data",
                    headers=self._sso_headers(),
                ).json()
                self.assertEqual(len(page_data["records"]), 200)
                self.assertEqual(page_data["total_records"], 230)
                self.assertEqual(
                    page_data["collection_counts"],
                    {"bot_mail_items": 1, "bot_drive_items": 1, "bot_cal_items": 228},
                )

                # POST /api/pages/{slug}/sql executes JSON1 at 0 LLM tokens
                runs_before = len(repo.list_bot_runs(limit=100))
                sql_res = client.post(
                    "/api/pages/workspace-executive/sql",
                    headers=self._sso_headers(),
                    json={
                        "sql": (
                            "SELECT json_extract(je.value, '$.email') AS attendee, COUNT(*) AS cnt "
                            "FROM docs, json_each(doc_json, '$.attendees') AS je "
                            "WHERE collection = 'bot_cal_items' GROUP BY 1 ORDER BY cnt DESC"
                        )
                    },
                )
                self.assertEqual(sql_res.status_code, 200, sql_res.text)
                rows = sql_res.json()["rows"]
                self.assertEqual(sum(r["cnt"] for r in rows), 228)
                self.assertEqual(len(repo.list_bot_runs(limit=100)), runs_before)

    def test_google_workspace_connectors_full_payloads_and_zero_token_dedup(self) -> None:
        # 1. Verify DefaultGoogleOAuthTransport parses full Gmail MIME, Drive search/export, and Calendar
        transport = DefaultGoogleOAuthTransport()
        raw_plain = base64.urlsafe_b64encode(b"Hello team, attached is the Q4 report.").decode("ascii").rstrip("=")
        requested_urls: list[str] = []

        def fake_urlopen(req: Any, timeout: int = 20) -> _FakeHttpResponse:
            del timeout
            url = req.full_url if hasattr(req, "full_url") else str(req)
            requested_urls.append(url)
            if "/messages?" in url:
                return _FakeHttpResponse(json.dumps({"messages": [{"id": "gm_1", "threadId": "thr_1"}]}))
            if "/messages/gm_1?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "id": "gm_1",
                            "threadId": "thr_1",
                            "historyId": "9001",
                            "internalDate": "1763456000000",
                            "sizeEstimate": 8192,
                            "labelIds": ["INBOX", "UNREAD"],
                            "snippet": "Hello team...",
                            "payload": {
                                "headers": [
                                    {"name": "From", "value": "cfo@acme.io"},
                                    {"name": "To", "value": "ops@acme.io"},
                                    {"name": "Cc", "value": "finance@acme.io"},
                                    {"name": "Bcc", "value": "audit@acme.io"},
                                    {"name": "Reply-To", "value": "reply@acme.io"},
                                    {"name": "Subject", "value": "Q4 Report"},
                                    {"name": "Message-ID", "value": "<gm1@acme.io>"},
                                    {"name": "In-Reply-To", "value": "<gm0@acme.io>"},
                                ],
                                "mimeType": "multipart/mixed",
                                "parts": [
                                    {
                                        "partId": "0",
                                        "mimeType": "text/plain",
                                        "body": {"data": raw_plain},
                                    },
                                    {
                                        "partId": "1",
                                        "filename": "q4.pdf",
                                        "mimeType": "application/pdf",
                                        "body": {"attachmentId": "att_1", "size": 54321},
                                    },
                                ],
                            },
                        }
                    )
                )
            if "/drive/v3/files?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "nextPageToken": "tok_2",
                            "files": [
                                {
                                    "id": "drv_doc_1",
                                    "name": "Q4 Roadmap",
                                    "mimeType": "application/vnd.google-apps.document",
                                    "modifiedTime": "2026-11-18T08:00:00Z",
                                    "owners": [{"displayName": "Alice", "emailAddress": "alice@acme.io"}],
                                    "webViewLink": "https://docs.google.com/document/d/drv_doc_1",
                                }
                            ],
                        }
                    )
                )
            if "/drive/v3/files/drv_doc_1?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "id": "drv_doc_1",
                            "name": "Q4 Roadmap",
                            "mimeType": "application/vnd.google-apps.document",
                            "modifiedTime": "2026-11-18T08:00:00Z",
                        }
                    )
                )
            if "/drive/v3/files/drv_doc_1/export" in url:
                return _FakeHttpResponse("Q4 Roadmap Exported Text")
            if "/drive/v3/files/drv_sheet_1?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "id": "drv_sheet_1",
                            "name": "Budget",
                            "mimeType": "application/vnd.google-apps.spreadsheet",
                        }
                    )
                )
            if "/drive/v3/files/drv_sheet_1/export" in url:
                return _FakeHttpResponse("month,amount\nNov,4200\n")
            if "/drive/v3/files/drv_txt_1?" in url and "alt=media" in url:
                return _FakeHttpResponse("Plain text Drive notes with token ya29.secret_tok_999")
            if "/drive/v3/files/drv_txt_1?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "id": "drv_txt_1",
                            "name": "notes.txt",
                            "mimeType": "text/plain",
                        }
                    )
                )
            if "/calendar/v3/calendars/primary/events?" in url:
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "items": [
                                {
                                    "id": "cal_ev_1",
                                    "status": "confirmed",
                                    "summary": "Product Sync",
                                    "hangoutLink": "https://meet.google.com/abc-defg-hij",
                                    "start": {"dateTime": "2026-11-19T10:00:00Z"},
                                    "end": {"dateTime": "2026-11-19T10:30:00Z"},
                                    "organizer": {"email": "pm@acme.io"},
                                    "attendees": [
                                        {"email": "dev@acme.io", "responseStatus": "accepted", "self": True}
                                    ],
                                    "updated": "2026-11-18T08:15:00Z",
                                }
                            ]
                        }
                    )
                )
            raise AssertionError(f"Unexpected URL: {url}")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            msgs = asyncio.run(transport.search_gmail_messages(access_token="ya29.test_tok"))
            self.assertEqual(len(msgs), 1)
            self.assertTrue(any("format=full" in u for u in requested_urls))
            m0 = msgs[0]
            self.assertEqual(m0["cc"], "finance@acme.io")
            self.assertEqual(m0["bcc"], "audit@acme.io")
            self.assertEqual(m0["reply_to"], "reply@acme.io")
            self.assertEqual(m0["in_reply_to"], "<gm0@acme.io>")
            self.assertEqual(m0["internal_date_ms"], 1763456000000)
            self.assertEqual(m0["size_estimate"], 8192)
            self.assertTrue(m0["is_unread"])
            self.assertEqual(m0["history_id"], "9001")
            self.assertTrue(m0["has_attachments"])
            self.assertEqual(m0["attachments"][0]["filename"], "q4.pdf")
            self.assertIn("Q4 report", m0["body_excerpt"])

            drive_res = asyncio.run(transport.search_drive_files(access_token="ya29.test_tok"))
            self.assertEqual(drive_res["next_page_token"], "tok_2")
            self.assertEqual(drive_res["files"][0]["id"], "drv_doc_1")
            self.assertTrue(any("supportsAllDrives=true" in u for u in requested_urls))

            doc_exp = asyncio.run(
                transport.read_drive_file_excerpt(access_token="ya29.test_tok", file_id="drv_doc_1")
            )
            self.assertEqual(doc_exp["excerpt"], "Q4 Roadmap Exported Text")

            sheet_exp = asyncio.run(
                transport.read_drive_file_excerpt(access_token="ya29.test_tok", file_id="drv_sheet_1")
            )
            self.assertIn("month,amount", sheet_exp["excerpt"])

            txt_exp = asyncio.run(
                transport.read_drive_file_excerpt(access_token="ya29.test_tok", file_id="drv_txt_1")
            )
            self.assertIn("Plain text Drive notes", txt_exp["excerpt"])
            self.assertNotIn("ya29.secret_tok_999", txt_exp["excerpt"])

            cal_events = asyncio.run(transport.list_calendar_events(access_token="ya29.test_tok"))
            self.assertEqual(cal_events[0]["hangoutLink"], "https://meet.google.com/abc-defg-hij")
            self.assertEqual(cal_events[0]["attendees"][0]["email"], "dev@acme.io")

        # 2. Verify scope enforcement + 0-token scheduled Drive/Calendar dedup
        ws_transport = _MutableWorkspaceGoogleTransport()
        ws_transport.drive_files = [
            {
                "id": "drv_1",
                "name": "Ops Sheet",
                "mimeType": "application/vnd.google-apps.spreadsheet",
                "modifiedTime": "2026-11-18T08:00:00Z",
            }
        ]
        ws_transport.calendar_events = [
            {
                "id": "ev_1",
                "summary": "Ops Standup",
                "start": {"dateTime": "2026-11-19T09:00:00Z"},
                "updated": "2026-11-18T08:00:00Z",
            }
        ]
        llm_calls = 0

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            nonlocal llm_calls
            llm_calls += 1
            return {
                "text": json.dumps({"summary": "Processed Google Workspace items.", "actions": []}),
                "input_tokens": 15,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm, google_transport=ws_transport)
            with TestClient(app) as client:
                repo = app.state.repo
                runner = app.state.bot_runner
                google_svc: GoogleOAuthService = app.state.google_oauth_service

                repo.upsert_integration(
                    slug="gmail-only",
                    provider="google",
                    display_name="Gmail Only",
                    account_identifier="mail@acme.io",
                    scopes=["gmail_read"],
                    secrets={
                        "client_id": "cid",
                        "client_secret": "csec",
                        "refresh_token": "1//ref",
                        "access_token": "ya29.mail",
                    },
                    status="ok",
                )
                with self.assertRaises(GoogleOAuthConfigError):
                    asyncio.run(google_svc.search_drive_files("gmail-only"))
                with self.assertRaises(GoogleOAuthConfigError):
                    asyncio.run(google_svc.list_calendar_events("gmail-only"))

                repo.upsert_integration(
                    slug="full-ws",
                    provider="google",
                    display_name="Full Workspace",
                    account_identifier="ops@company.example",
                    scopes=["gmail_read", "drive_docs", "calendar"],
                    secrets={
                        "client_id": "cid",
                        "client_secret": "csec",
                        "refresh_token": "1//ref",
                        "access_token": "ya29.ws",
                    },
                    status="ok",
                )

                drive_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Drive Watcher",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["full-ws"],
                        "tools": [{"type": "builtin", "name": "gdrive_search"}],
                    },
                ).json()
                cal_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Calendar Watcher",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["full-ws"],
                        "tools": [{"type": "builtin", "name": "gcal_events"}],
                    },
                ).json()

                # Run 1 ingests unseen Drive + Calendar items
                r1_drv = asyncio.run(runner.execute_bot(drive_bot["slug"], trigger_type="cron:rtn_1"))
                r1_cal = asyncio.run(runner.execute_bot(cal_bot["slug"], trigger_type="cron:rtn_2"))
                self.assertEqual(r1_drv["status"], "completed")
                self.assertEqual(r1_cal["status"], "completed")
                self.assertEqual(llm_calls, 2)
                drive_col = next(c for c in drive_bot["collections"]["write"] if c != "bot_threads")
                cal_col = next(c for c in cal_bot["collections"]["write"] if c != "bot_threads")
                self.assertIsNotNone(
                    repo.get_document_by_external_key(drive_col, "gdrive:full-ws:drv_1")
                )
                self.assertIsNotNone(
                    repo.get_document_by_external_key(cal_col, "gcal:full-ws:ev_1")
                )

                # Run 2 with unchanged modifiedTime/updated hits 0-token deduplicated_noop
                r2_drv = asyncio.run(runner.execute_bot(drive_bot["slug"], trigger_type="cron:rtn_1"))
                r2_cal = asyncio.run(runner.execute_bot(cal_bot["slug"], trigger_type="cron:rtn_2"))
                self.assertEqual(r2_drv["status"], "deduplicated_noop")
                self.assertEqual(r2_drv["tokens_used"], 0)
                self.assertEqual(r2_cal["status"], "deduplicated_noop")
                self.assertEqual(r2_cal["tokens_used"], 0)
                self.assertEqual(llm_calls, 2)

                # Run 3 after modifiedTime / updated advance re-ingests cleanly
                ws_transport.drive_files[0]["modifiedTime"] = "2026-11-18T09:30:00Z"
                ws_transport.calendar_events[0]["updated"] = "2026-11-18T09:30:00Z"
                r3_drv = asyncio.run(runner.execute_bot(drive_bot["slug"], trigger_type="cron:rtn_1"))
                r3_cal = asyncio.run(runner.execute_bot(cal_bot["slug"], trigger_type="cron:rtn_2"))
                self.assertEqual(r3_drv["status"], "completed")
                self.assertEqual(r3_cal["status"], "completed")
                self.assertEqual(llm_calls, 4)


if __name__ == "__main__":
    unittest.main()
