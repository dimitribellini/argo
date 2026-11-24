"""End-to-end tests for Wave 3: Opt-in Tool Scoping, Dynamic MCP Connectors, Pluggable Adapters, and Fedora 45 Script Sandbox."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
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
from argo_core.connectors.gateway import (  # noqa: E402
    ConnectorAdapter,
    ConnectorToolContext,
    LinkedInConnectorAdapter,
    TelegramConnectorAdapter,
)
from argo_core.connectors.mcp_client import (  # noqa: E402
    MCPConnectorService,
    classify_mcp_tool_readonly,
    make_mcp_tool_name,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.tool_registry import (  # noqa: E402
    build_bot_tool_specs,
    validate_gemini_safe_schema,
)
from argo_core.sandbox.manager import (  # noqa: E402
    SANDBOX_IMAGE,
    SANDBOX_NETWORK,
    SANDBOX_TMPFS_OPTS,
    SANDBOX_USER,
    DockerSandboxDriver,
    InMemorySandboxDriver,
    SandboxConfigError,
    SandboxRuntimeError,
    SandboxRuntimeSpec,
)
from argo_core.tool_schema import ToolSpec  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _MutableMetrics:
    def __init__(self, ram_percent: float = 30.0) -> None:
        self.ram_percent = ram_percent

    def __call__(self) -> dict[str, float]:
        return {
            "ram_percent": self.ram_percent,
            "ram_total_gb": 16.0,
            "cpu_percent": 15.0,
            "disk_percent": 22.0,
        }


class TestWave3PluggableMCPAndSandbox(unittest.TestCase):
    """Verify Option 1 (opt-in tools + dynamic MCP + pluggable adapters) and Option 2 (sandbox runtime)."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    @staticmethod
    def _build_env(
        tmp: str,
        *,
        llm_transport=None,
        mcp_transport=None,
        sandbox_driver=None,
        metrics_provider=None,
        idle_timeout_seconds: float = 300.0,
    ):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
        guard = HostResourceGuard(
            metrics_provider=metrics_provider
            or (
                lambda: {
                    "ram_percent": 30.0,
                    "ram_total_gb": 16.0,
                    "cpu_percent": 12.0,
                    "disk_percent": 20.0,
                }
            ),
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            sandbox_volumes_root=str(Path(tmp) / "sandboxes"),
            sandbox_idle_timeout_seconds=idle_timeout_seconds,
            workspace_files_root=str(Path(tmp) / "workspace_files"),
            ssh_audit_root=str(Path(tmp) / "ssh_audit"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            mcp_transport=mcp_transport,
            sandbox_driver=sandbox_driver,
        )

    def test_1_opt_in_scoping_and_gemini_safe_schemas(self) -> None:
        base_bot = {
            "slug": "minimal-api",
            "runtime": "api",
            "outbound_rbac": "internal",
            "tools": [],
            "collections": {"read": [], "write": []},
            "routines": [],
        }
        minimal_names = {
            s.name
            for s in build_bot_tool_specs(
                bot=base_bot,
                read_cols=[],
                data_write_cols=[],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        for omitted in (
            "fetch_public_webpage",
            "extract_web_data",
            "fetch_rss_feed",
            "fetch_telegram_public_channel",
            "propose_specialist_bot",
            "propose_fleet_cleanup",
            "sandbox_exec",
            "desktop_browse",
            "ssh_exec",
            "gmail_search",
            "publish_telegram",
            "publish_linkedin",
        ):
            self.assertNotIn(omitted, minimal_names)

        # Opted-in web & supervisor hints expose only declared capabilities
        web_names = {
            s.name
            for s in build_bot_tool_specs(
                bot={**base_bot, "tools": ["fetch_public_webpage", "platform_status"]},
                read_cols=[],
                data_write_cols=[],
                permitted_integrations=[],
                has_ssh_vault=False,
                can_control_ssh=False,
                teammate_bots=[],
                trigger_type="manual",
                trigger_payload={},
                is_background_poll=False,
                needs_platform_status=False,
            )
        }
        self.assertIn("fetch_public_webpage", web_names)
        self.assertNotIn("fetch_rss_feed", web_names)
        self.assertIn("propose_specialist_bot", web_names)
        self.assertIn("propose_fleet_cleanup", web_names)

        # Validate sandbox_exec + complex nested MCP schema with $defs/$ref/anyOf/additionalProperties
        async def _complex_schema_transport(url: str, payload: dict[str, Any], headers: dict[str, str]):
            del url, headers
            if payload.get("method") == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "search_issues",
                                "description": "Search GitHub issues safely.",
                                "annotations": {"readOnlyHint": True},
                                "inputSchema": {
                                    "$schema": "http://json-schema.org/draft-07/schema#",
                                    "title": "SearchIssues",
                                    "type": "object",
                                    "additionalProperties": False,
                                    "$defs": {
                                        "Filter": {
                                            "type": "object",
                                            "additionalProperties": False,
                                            "properties": {
                                                "state": {
                                                    "anyOf": [
                                                        {"type": "string", "default": "open"},
                                                        {"type": "null"},
                                                    ]
                                                }
                                            },
                                        }
                                    },
                                    "properties": {
                                        "repo": {"type": "string", "title": "Repository"},
                                        "filter": {"$ref": "#/$defs/Filter"},
                                    },
                                    "required": ["repo"],
                                },
                            }
                        ]
                    },
                }
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {}}

        mcp_svc = MCPConnectorService(transport=_complex_schema_transport)
        mcp_specs = asyncio.run(
            mcp_svc.list_tool_specs(
                {
                    "slug": "mcp_gh",
                    "provider": "mcp",
                    "account_identifier": "https://93.184.216.34/mcp",
                    "secrets": {},
                }
            )
        )
        self.assertEqual(len(mcp_specs), 1)
        self.assertEqual(mcp_specs[0].name, make_mcp_tool_name("mcp_gh", "search_issues"))
        self.assertEqual(validate_gemini_safe_schema(mcp_specs[0].parameters_json_schema), [])

        sandbox_specs = build_bot_tool_specs(
            bot={**base_bot, "runtime": "sandbox"},
            read_cols=[],
            data_write_cols=[],
            permitted_integrations=[],
            has_ssh_vault=False,
            can_control_ssh=False,
            teammate_bots=[],
            trigger_type="manual",
            trigger_payload={},
            is_background_poll=False,
            needs_platform_status=False,
            extra_tool_specs=mcp_specs,
        )
        sb_names = {s.name for s in sandbox_specs}
        self.assertIn("sandbox_exec", sb_names)
        self.assertIn("mcp__mcp_gh__search_issues", sb_names)
        for spec in sandbox_specs:
            self.assertEqual(
                validate_gemini_safe_schema(spec.parameters_json_schema, tool_name=spec.name),
                [],
            )

        self.assertTrue(classify_mcp_tool_readonly({"name": "list_prs"}))
        self.assertFalse(
            classify_mcp_tool_readonly(
                {"name": "list_prs", "annotations": {"readOnlyHint": False}}
            )
        )
        self.assertFalse(classify_mcp_tool_readonly({"name": "create_issue"}))

    def test_2_dynamic_mcp_connector_lifecycle_and_rbac(self) -> None:
        rpc_calls: list[dict[str, Any]] = []
        mode_box = {"step": "readonly"}

        async def mcp_transport(url: str, payload: dict[str, Any], headers: dict[str, str]):
            rpc_calls.append({"url": url, "method": payload.get("method"), "params": payload.get("params"), "headers": headers})
            method = payload.get("method")
            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "get_ticket",
                                "description": "Fetch ticket details by ID",
                                "annotations": {"readOnlyHint": True},
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"ticket_id": {"type": "string"}},
                                    "required": ["ticket_id"],
                                },
                            },
                            {
                                "name": "create_issue",
                                "description": "Create a new issue on the remote tracker",
                                "annotations": {"readOnlyHint": False},
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"title": {"type": "string"}},
                                    "required": ["title"],
                                },
                            },
                        ]
                    },
                }
            if method == "tools/call":
                params = payload.get("params") or {}
                if params.get("name") == "get_ticket":
                    return {
                        "jsonrpc": "2.0",
                        "id": payload["id"],
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Ticket ARGO-42 open; leaked token super-secret-mcp-token-999",
                                }
                            ]
                        },
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {"content": [{"type": "text", "text": f"Created issue: {params.get('arguments')}"}], "isError": False},
                }
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {}}

        seen_reqs: list[LLMRequest] = []

        async def mcp_llm(req: LLMRequest) -> dict[str, Any]:
            seen_reqs.append(req)
            if mode_box["step"] == "readonly":
                if len(req.deferred_tool_results) == 0:
                    tool_names = {t.name for t in req.tools}
                    assert "mcp__mcp_ops__get_ticket" in tool_names
                    assert "mcp__mcp_ops__create_issue" in tool_names
                    return {
                        "chunks": [],
                        "tool_calls": [
                            {
                                "tool_call_id": "tc_mcp_read",
                                "tool_name": "mcp__mcp_ops__get_ticket",
                                "args": {"ticket_id": "ARGO-42"},
                            }
                        ],
                        "message_history": [{"turn": 1}],
                        "input_tokens": 12,
                        "output_tokens": 8,
                    }
                obs = req.deferred_tool_results[0].result
                assert obs["status"] == "ok"
                assert "super-secret-mcp-token-999" not in json.dumps(obs)
                return {
                    "chunks": ["Ticket ARGO-42 is open."],
                    "tool_calls": [],
                    "message_history": [{"turn": 2}],
                    "input_tokens": 14,
                    "output_tokens": 10,
                }

            return {
                "chunks": [],
                "tool_calls": [
                    {
                        "tool_call_id": "tc_mcp_write",
                        "tool_name": "mcp__mcp_ops__create_issue",
                        "args": {"title": "Fix Grafana check"},
                    }
                ],
                "message_history": [{"turn": 1}],
                "input_tokens": 12,
                "output_tokens": 8,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=mcp_llm, mcp_transport=mcp_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True

                # 1. SSRF guard blocks loopback MCP URL with 403 on test/probe
                ssrf_create = client.post(
                    "/api/integrations",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-ssrf",
                        "provider": "mcp",
                        "display_name": "Internal Loopback MCP",
                        "account_identifier": "http://127.0.0.1:9000/mcp",
                        "secrets": {},
                    },
                )
                self.assertIn(ssrf_create.status_code, (200, 201), ssrf_create.text)
                ssrf_probe = client.post("/api/integrations/mcp-ssrf/test", headers=self._sso_headers(), json={})
                self.assertEqual(ssrf_probe.status_code, 403, ssrf_probe.text)
                client.delete("/api/integrations/mcp-ssrf", headers=self._sso_headers())

                # 2. Register valid HTTPS public IP MCP server + Bearer token and verify probe discovers tools
                reg = client.post(
                    "/api/integrations",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-ops",
                        "provider": "mcp",
                        "display_name": "Ops Tracker MCP",
                        "account_identifier": "https://93.184.216.34/mcp",
                        "secrets": {"token": "super-secret-mcp-token-999"},
                    },
                )
                self.assertIn(reg.status_code, (200, 201), reg.text)
                probe = client.post("/api/integrations/mcp-ops/test", headers=self._sso_headers(), json={})
                self.assertEqual(probe.status_code, 200, probe.text)
                self.assertEqual(probe.json()["status"], "ok")

                # 3. Create internal bot linked to mcp-ops -> readonly works + secrets redacted
                b_res = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-worker",
                        "name": "MCP Worker",
                        "role": "Inspect tickets",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["mcp-ops"],
                    },
                )
                self.assertIn(b_res.status_code, (200, 201), b_res.text)

                res_ro = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "mcp-worker",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Check ticket ARGO-42", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res_ro["status"], "completed")
                self.assertIn("ARGO-42", res_ro["summary"])
                self.assertTrue(
                    any(
                        c["method"] == "tools/call"
                        and c["headers"].get("Authorization") == "Bearer super-secret-mcp-token-999"
                        for c in rpc_calls
                    )
                )

                # 4. Mutating MCP tool blocked under internal RBAC
                mode_box["step"] = "write"
                res_int = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "mcp-worker",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Create an issue", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res_int["actions"][0]["status"], "blocked_rbac")

                # 5. Switch to draft -> queues approval -> resolving approval dispatches tools/call
                client.patch(
                    "/api/bots/mcp-worker",
                    headers=self._sso_headers(),
                    json={"outbound_rbac": "draft"},
                )
                rpc_count_before_draft = sum(1 for c in rpc_calls if c["method"] == "tools/call" and c["params"].get("name") == "create_issue")
                res_draft = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "mcp-worker",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Create an issue", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res_draft["actions"][0]["status"], "queued_approval")
                self.assertEqual(
                    sum(1 for c in rpc_calls if c["method"] == "tools/call" and c["params"].get("name") == "create_issue"),
                    rpc_count_before_draft,
                )

                approval_id = res_draft["actions"][0]["approval_id"]
                resolved = client.post(
                    f"/api/approvals/{approval_id}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve"},
                )
                self.assertEqual(resolved.status_code, 200, resolved.text)
                self.assertEqual(resolved.json()["status"], "executed")
                self.assertEqual(
                    sum(1 for c in rpc_calls if c["method"] == "tools/call" and c["params"].get("name") == "create_issue"),
                    rpc_count_before_draft + 1,
                )

    def test_3_custom_third_party_connector_adapter_e2e(self) -> None:
        executed_calls: list[dict[str, Any]] = []

        class _CustomTicketingAdapter(ConnectorAdapter):
            provider = "custom_jira"
            display_label = "Custom Jira capability match"
            tool_names = ("custom_jira_get_issue",)

            async def probe(self, account: dict[str, Any], *, send_test_message: bool = False) -> dict[str, Any]:
                del send_test_message
                return {**account, "status": "ok"}

            async def get_tool_specs(
                self,
                account: dict[str, Any],
                *,
                bot: dict[str, Any] | None = None,
            ) -> list[ToolSpec]:
                del account, bot
                return [
                    ToolSpec(
                        name="custom_jira_get_issue",
                        description="Fetch an issue from Custom Jira adapter.",
                        parameters_json_schema={
                            "type": "object",
                            "properties": {"issue_key": {"type": "string"}},
                            "required": ["issue_key"],
                        },
                    )
                ]

            def owns_tool(self, tool_name: str, account: dict[str, Any]) -> bool:
                del account
                return tool_name == "custom_jira_get_issue"

            async def execute_tool(
                self,
                *,
                tool_name: str,
                action: dict[str, Any],
                ctx: ConnectorToolContext,
            ) -> dict[str, Any] | None:
                if tool_name != "custom_jira_get_issue":
                    return None
                executed_calls.append(
                    {
                        "issue_key": action.get("issue_key"),
                        "account_slug": ctx.account["slug"],
                        "api_secret": (ctx.account.get("secrets") or {}).get("token"),
                    }
                )
                return {
                    "type": tool_name,
                    "status": "ok",
                    "issue_key": action.get("issue_key"),
                    "title": "Pluggable adapter verified",
                }

        async def custom_llm(req: LLMRequest) -> dict[str, Any]:
            if len(req.deferred_tool_results) == 0:
                self.assertIn("custom_jira_get_issue", {t.name for t in req.tools})
                return {
                    "chunks": [],
                    "tool_calls": [
                        {
                            "tool_call_id": "tc_jira_1",
                            "tool_name": "custom_jira_get_issue",
                            "args": {"issue_key": "OPS-101"},
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 10,
                    "output_tokens": 6,
                }
            return {
                "chunks": ["OPS-101 says Pluggable adapter verified."],
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 10,
                "output_tokens": 8,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=custom_llm)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                app.state.connector_gateway.register(_CustomTicketingAdapter())

                app.state.repo.upsert_integration(
                    slug="jira_eu",
                    provider="custom_jira",
                    display_name="EU Jira",
                    account_identifier="https://jira.example.com",
                    scopes=["read"],
                    secrets={"token": "jira-secret-abc"},
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "jira-reader",
                        "name": "Jira Reader",
                        "role": "Check Jira issues",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["jira_eu"],
                    },
                )

                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "jira-reader",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Look up OPS-101", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res["status"], "completed")
                self.assertEqual(len(executed_calls), 1)
                self.assertEqual(executed_calls[0]["issue_key"], "OPS-101")
                self.assertEqual(executed_calls[0]["api_secret"], "jira-secret-abc")

    def test_4_headless_sandbox_lifecycle_vault_ram_and_room_routing(self) -> None:
        clock_now = [1000.0]
        metrics = _MutableMetrics(ram_percent=35.0)
        observed_envs: list[dict[str, str]] = []

        def _exec_cb(
            container_name: str,
            cmd: list[str],
            env: dict[str, str] | None,
            workdir: str,
            timeout_seconds: float,
        ) -> dict[str, Any]:
            del container_name, workdir, timeout_seconds
            clean_env = dict(env or {})
            observed_envs.append(clean_env)
            tok = clean_env.get("ARGO_VAULT_GRAFANA_API_TOKEN", "")
            return {
                "exit_code": 0,
                "stdout": f"cmd={' '.join(cmd)} | token={tok or 'none'}",
                "stderr": "",
                "timed_out": False,
            }

        sb_driver = InMemorySandboxDriver(exec_callback=_exec_cb)

        async def sandbox_llm(req: LLMRequest) -> dict[str, Any]:
            if req.tools and len(req.deferred_tool_results) == 0:
                tool_names = {t.name for t in req.tools}
                self.assertIn("sandbox_exec", tool_names)
                return {
                    "chunks": [],
                    "tool_calls": [
                        {
                            "tool_call_id": "sb_1",
                            "tool_name": "sandbox_exec",
                            "args": {
                                "script": "import json\nprint('Grafana v12.1.0')",
                                "interpreter": "python3",
                                "save_as": "check_grafana.py",
                                "vault_slugs": ["grafana-api"],
                            },
                        }
                    ],
                    "message_history": [{"turn": 1}],
                    "input_tokens": 12,
                    "output_tokens": 10,
                }
            return {
                "chunks": ["Executed check_grafana.py cleanly inside the sandbox."],
                "tool_calls": [],
                "message_history": [{"turn": 2}],
                "input_tokens": 10,
                "output_tokens": 8,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=sandbox_llm,
                sandbox_driver=sb_driver,
                metrics_provider=metrics,
                idle_timeout_seconds=120.0,
            )
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True
                app.state.sandbox_manager._clock = lambda: clock_now[0]

                # 1. Bot Builder infers runtime='sandbox' and attaches sandbox_exec (not fetch_public_webpage)
                draft_res = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Write a Python script with curl to monitor Grafana release API versions",
                        "preferred_runtime": "auto",
                    },
                )
                self.assertEqual(draft_res.status_code, 200, draft_res.text)
                draft = draft_res.json()["draft"]
                self.assertEqual(draft["runtime"], "sandbox")
                self.assertEqual(draft["sandbox_policy"], "on_demand")
                tool_names = [t.get("name") for t in draft["tools"] if isinstance(t, dict)]
                self.assertIn("sandbox_exec", tool_names)
                self.assertNotIn("fetch_public_webpage", tool_names)

                # 2. Register sandbox bot + non-sandbox companion bot in a Room
                sb_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "script-runner",
                        "name": "Script Runner",
                        "role": "Run Python and bash scripts",
                        "runtime": "sandbox",
                        "outbound_rbac": "internal",
                    },
                )
                self.assertIn(sb_bot.status_code, (200, 201), sb_bot.text)
                self.assertEqual(sb_bot.json()["ram_limit_mb"], 512)
                self.assertEqual(sb_bot.json()["sandbox_state"], "hibernated")

                api_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mail-helper",
                        "name": "Mail Helper",
                        "role": "Summarize emails",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                    },
                )
                self.assertIn(api_bot.status_code, (200, 201), api_bot.text)

                # Room Tier-1 deterministic routing picks sandbox bot for CLI/Python request
                speaker = app.state.bot_runner._match_unique_room_capability(
                    clean_text="Run a python script to verify checksums",
                    member_bots=[api_bot.json(), sb_bot.json()],
                )
                self.assertEqual(speaker, ("script-runner", "Script Sandbox execution"))

                # 3. Vault ACL fail-closed before grant -> blocked_vault_acl
                v_create = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Grafana API",
                        "slug": "grafana-api",
                        "secret_type": "api_token",
                        "url": "https://grafana.example.com",
                        "secrets": {"token": "glsa_super_secret_token_777"},
                        "allowed_bots": [],
                    },
                )
                self.assertIn(v_create.status_code, (200, 201), v_create.text)

                res_acl_block = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "script-runner",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Run check_grafana.py", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res_acl_block["actions"][0]["status"], "blocked_vault_acl")
                self.assertEqual(len(observed_envs), 0)

                # 4. Grant Vault ACL -> executes bash/python, saves script in /workspace, injects & redacts secret
                client.patch(
                    "/api/vault/grafana-api",
                    headers=self._sso_headers(),
                    json={"allowed_bots": ["script-runner"]},
                )
                res_ok = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "script-runner",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Run check_grafana.py", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res_ok["status"], "completed")
                act_res = res_ok["actions"][0]
                self.assertEqual(act_res["status"], "ok")
                self.assertEqual(act_res["saved_script"], "/workspace/check_grafana.py")
                self.assertNotIn("glsa_super_secret_token_777", act_res["stdout"])
                self.assertEqual(
                    observed_envs[-1].get("ARGO_VAULT_GRAFANA_API_TOKEN"),
                    "glsa_super_secret_token_777",
                )
                saved_host_file = Path(tmp) / "sandboxes" / "script-runner" / "check_grafana.py"
                self.assertTrue(saved_host_file.is_file())
                self.assertIn("Grafana v12.1.0", saved_host_file.read_text(encoding="utf-8"))

                # Path traversal in save_as is rejected cleanly
                with self.assertRaises(Exception):
                    asyncio.run(
                        app.state.sandbox_manager.exec_script(
                            "script-runner",
                            script="echo bad",
                            save_as="../escape.py",
                        )
                    )

                # 5. API status endpoints (/api/sandboxes and /api/desktops include sandboxes)
                sb_list = client.get("/api/sandboxes", headers=self._sso_headers())
                self.assertEqual(sb_list.status_code, 200)
                self.assertEqual(sb_list.json()["sandboxes"][0]["sandbox_state"], "running")

                desk_list = client.get("/api/desktops", headers=self._sso_headers())
                self.assertEqual(desk_list.status_code, 200)
                self.assertEqual(len(desk_list.json().get("sandboxes", [])), 1)

                # 6. Idle hibernation sweep stops sandbox after idle_timeout_seconds
                clock_now[0] += 130.0
                sweep_res = client.post("/api/sandboxes/sweep-idle", headers=self._sso_headers())
                self.assertEqual(sweep_res.status_code, 200, sweep_res.text)
                self.assertEqual(sweep_res.json()["hibernated_sandboxes"], ["script-runner"])
                self.assertEqual(app.state.repo.get_bot("script-runner")["sandbox_state"], "hibernated")

                # 7. Host RAM >= 80% gate blocks sandbox startup with 409
                metrics.ram_percent = 83.0
                blocked_start = client.post(
                    "/api/sandboxes/script-runner/start", headers=self._sso_headers()
                )
                self.assertEqual(blocked_start.status_code, 409, blocked_start.text)

                # 8. Host RAM < 80% starts sandbox; >= 90% watchdog evaluate auto-stops running sandboxes
                metrics.ram_percent = 40.0
                ok_toggle = client.post(
                    "/api/sandboxes/script-runner/toggle", headers=self._sso_headers()
                )
                self.assertEqual(ok_toggle.status_code, 200)
                self.assertEqual(ok_toggle.json()["sandbox_state"], "running")

                metrics.ram_percent = 92.5
                wd_res = client.post("/api/watchdog/evaluate", headers=self._sso_headers())
                self.assertEqual(wd_res.status_code, 200, wd_res.text)
                self.assertIn("script-runner", wd_res.json().get("stopped_sandboxes", []))
                self.assertEqual(app.state.repo.get_bot("script-runner")["sandbox_state"], "hibernated")

                # 9. Deleting the bot removes container and /workspace volume cleanly
                del_res = client.delete("/api/bots/script-runner", headers=self._sso_headers())
                self.assertEqual(del_res.status_code, 200)
                self.assertNotIn("argo-sandbox-script-runner", sb_driver.containers)
                self.assertFalse((Path(tmp) / "sandboxes" / "script-runner").exists())

    def test_5_mcp_cold_hydration_cache_eviction_and_outbound_owns_tool(self) -> None:
        rpc_calls: list[dict[str, Any]] = []

        async def mcp_transport(url: str, payload: dict[str, Any], headers: dict[str, str]):
            rpc_calls.append(
                {
                    "url": url,
                    "method": payload.get("method"),
                    "headers": dict(headers),
                }
            )
            if payload.get("method") == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "ping_status",
                                "description": "Check remote status",
                                "annotations": {"readOnlyHint": True},
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ]
                    },
                }
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"content": [{"type": "text", "text": "pong"}]}}

        async def mcp_llm(req: LLMRequest) -> dict[str, Any]:
            tool_names = {t.name for t in req.tools}
            self.assertIn("mcp__mcp_ops__ping_status", tool_names)
            return {
                "chunks": ["MCP tools hydrated with secret token."],
                "tool_calls": [],
                "message_history": [{"turn": 1}],
                "input_tokens": 5,
                "output_tokens": 4,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=mcp_llm, mcp_transport=mcp_transport)
            with TestClient(app) as client:
                app.state.llm_router._native_transport_tools = True

                # Outbound adapters must NOT own tools as discovery/execute_tool actions
                tg_adapter = TelegramConnectorAdapter(None)
                li_adapter = LinkedInConnectorAdapter(None)
                self.assertFalse(tg_adapter.owns_tool("publish_telegram", {"slug": "tg-1"}))
                self.assertFalse(tg_adapter.owns_tool("fetch_telegram_public_channel", {"slug": "tg-1"}))
                self.assertFalse(li_adapter.owns_tool("publish_linkedin", {"slug": "li-1"}))
                self.assertIsNone(
                    app.state.connector_gateway.resolve_tool_account(
                        "publish_telegram", [{"slug": "tg-1", "provider": "telegram"}]
                    )
                )
                self.assertIsNone(
                    app.state.connector_gateway.resolve_tool_account(
                        "publish_linkedin", [{"slug": "li-1", "provider": "linkedin"}]
                    )
                )

                client.post(
                    "/api/integrations",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-ops",
                        "provider": "mcp",
                        "display_name": "Ops MCP",
                        "account_identifier": "",
                        "secrets": {
                            "url": "https://93.184.216.34/mcp",
                            "token": "cold-start-bearer-xyz",
                        },
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-cold",
                        "name": "MCP Cold",
                        "role": "Inspect MCP status",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["mcp-ops"],
                    },
                )

                # Cold-start: cache is empty before execute_bot -> _build_native_tool_specs must hydrate secrets!
                app.state.mcp_service.invalidate("mcp-ops")
                res = asyncio.run(
                    app.state.bot_runner.execute_bot(
                        "mcp-cold",
                        trigger_type="manual",
                        trigger_payload={"input_text": "Check status", "from_chat_thread": True},
                    )
                )
                self.assertEqual(res["status"], "completed")
                cold_list_calls = [c for c in rpc_calls if c["method"] == "tools/list"]
                self.assertGreaterEqual(len(cold_list_calls), 1)
                self.assertEqual(
                    cold_list_calls[-1]["headers"].get("Authorization"),
                    "Bearer cold-start-bearer-xyz",
                )

                # Upsert / Delete invalidate MCP cache immediately
                self.assertIsNotNone(app.state.mcp_service._cache.get("mcp-ops"))
                client.post(
                    "/api/integrations",
                    headers=self._sso_headers(),
                    json={
                        "slug": "mcp-ops",
                        "provider": "mcp",
                        "display_name": "Ops MCP v2",
                        "account_identifier": "https://93.184.216.34/mcp",
                        "secrets": {"token": "rotated-bearer-123"},
                    },
                )
                self.assertNotIn("mcp-ops", app.state.mcp_service._cache)
                client.post("/api/integrations/mcp-ops/test", headers=self._sso_headers(), json={})
                self.assertIn("mcp-ops", app.state.mcp_service._cache)
                client.delete("/api/integrations/mcp-ops", headers=self._sso_headers())
                self.assertNotIn("mcp-ops", app.state.mcp_service._cache)

    def test_6_dynamic_google_dispatch_scoping_prompt_and_sandbox_lifecycle_fixes(self) -> None:
        from unittest.mock import AsyncMock

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, sandbox_driver=InMemorySandboxDriver())
            with TestClient(app) as client:
                # 1. Dockerfile.sandbox exists and defaults match Fedora 45 + python3/curl/jq + public GHCR default
                df_sandbox = ROOT / "Dockerfile.sandbox"
                self.assertTrue(df_sandbox.is_file())
                df_text = df_sandbox.read_text(encoding="utf-8")
                self.assertIn("registry.fedoraproject.org/fedora:45", df_text)
                for pkg in ("python3", "curl", "jq"):
                    self.assertIn(pkg, df_text)
                self.assertEqual(SANDBOX_IMAGE, "ghcr.io/dimitribellini/argo-sandbox:latest")
                self.assertEqual(app.state.settings.sandbox_image, "ghcr.io/dimitribellini/argo-sandbox:latest")

                # DockerSandboxDriver fails clearly without pulling bare local tag, while pulling registry-qualified images
                class _ImageNotFound(Exception):
                    pass

                pulled: list[str] = []

                class _FakeImages:
                    def get(self, name: str):
                        raise _ImageNotFound(name)

                    def pull(self, name: str):
                        pulled.append(name)
                        if "fail" in name:
                            raise RuntimeError("unauthorized")
                        return object()

                class _FakeContainers:
                    def __init__(self) -> None:
                        self.runs: list[tuple[str, dict[str, Any]]] = []

                    def get(self, name: str):
                        raise _ImageNotFound(name)

                    def run(self, image: str, **kwargs: Any):
                        self.runs.append((image, kwargs))
                        return type("_C", (), {"id": "cid-pulled", "status": "running"})()

                class _FakeNetworks:
                    def list(self):
                        return [type("_N", (), {"name": SANDBOX_NETWORK})()]

                fake_containers = _FakeContainers()

                class _FakeDockerClient:
                    images = _FakeImages()
                    containers = fake_containers
                    networks = _FakeNetworks()

                fake_driver = DockerSandboxDriver()
                fake_driver._get_client = lambda: (_FakeDockerClient(), _ImageNotFound)  # type: ignore[method-assign]
                with self.assertRaises(SandboxRuntimeError) as ctx_err:
                    fake_driver._sync_ensure_started(
                        SandboxRuntimeSpec(
                            bot_slug="sb-check",
                            container_name="argo-sandbox-sb-check",
                            image="argo-sandbox:latest",
                            network=SANDBOX_NETWORK,
                            host_volume_path=str(Path(tmp) / "sandboxes" / "sb-check"),
                        )
                    )
                self.assertEqual(pulled, [])
                self.assertIn("Dockerfile.sandbox", str(ctx_err.exception))

                fake_driver._sync_ensure_started(
                    SandboxRuntimeSpec(
                        bot_slug="sb-check",
                        container_name="argo-sandbox-sb-check",
                        image=SANDBOX_IMAGE,
                        network=SANDBOX_NETWORK,
                        host_volume_path=str(Path(tmp) / "sandboxes" / "sb-check"),
                    )
                )
                self.assertEqual(pulled, [SANDBOX_IMAGE])
                self.assertEqual(fake_containers.runs[0][0], SANDBOX_IMAGE)

                with self.assertRaises(SandboxRuntimeError) as pull_err:
                    fake_driver._sync_ensure_started(
                        SandboxRuntimeSpec(
                            bot_slug="sb-fail",
                            container_name="argo-sandbox-sb-fail",
                            image="ghcr.io/dimitribellini/argo-sandbox-fail:latest",
                            network=SANDBOX_NETWORK,
                            host_volume_path=str(Path(tmp) / "sandboxes" / "sb-fail"),
                        )
                    )
                self.assertIn("docker pull", str(pull_err.exception))

                # 2. JSON-fallback prompt is dynamically scoped (no static web/Gmail/Telegram dump)
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "minimal-json-bot",
                        "name": "Minimal JSON",
                        "role": "Simple helper",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "tools": [],
                        "linked_accounts": [],
                    },
                )
                minimal_bot = app.state.repo.get_bot("minimal-json-bot")
                sys_prompt, _ = app.state.bot_runner._build_context_isolated_prompt(
                    bot=minimal_bot,
                    correlation_id="corr_min",
                    hop_count=0,
                    trigger_type="manual",
                    trigger_payload={"input_text": "hello", "from_chat_thread": True},
                    unseen_entries=[],
                    native_tools=False,
                )
                for static_tool in (
                    "fetch_public_webpage",
                    "extract_web_data",
                    "fetch_rss_feed",
                    "fetch_telegram_public_channel",
                    "gmail_search",
                    "gdrive_search",
                    "gcal_events",
                    "send_email",
                    "publish_telegram",
                    "publish_linkedin",
                ):
                    self.assertNotIn(static_tool, sys_prompt)

                # 3. Google tools dispatch generically through GoogleConnectorAdapter
                res_no_acct = asyncio.run(
                    app.state.bot_runner._execute_actions(
                        bot=minimal_bot,
                        correlation_id="corr_g0",
                        hop_count=0,
                        actions=[{"type": "gmail_search", "query": "is:unread"}],
                        trigger_type="manual",
                        trigger_payload={"from_chat_thread": True},
                    )
                )
                self.assertEqual(res_no_acct[0]["status"], "skipped_invalid_action")

                app.state.repo.upsert_integration(
                    slug="g-work",
                    provider="google",
                    display_name="Work Gmail",
                    account_identifier="work@example.com",
                    scopes=["gmail.readonly"],
                    secrets={"refresh_token": "tok"},
                )
                # Restricted bot without g-work linked -> blocked_unlinked_account
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "restricted-bot",
                        "name": "Restricted Bot",
                        "role": "Isolated helper",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["unrelated-acct"],
                    },
                )
                restricted_bot = app.state.repo.get_bot("restricted-bot")
                res_unlinked = asyncio.run(
                    app.state.bot_runner._execute_actions(
                        bot=restricted_bot,
                        correlation_id="corr_g1",
                        hop_count=0,
                        actions=[{"type": "gmail_search", "query": "is:unread"}],
                        trigger_type="manual",
                        trigger_payload={"from_chat_thread": True},
                    )
                )
                self.assertEqual(res_unlinked[0]["status"], "blocked_unlinked_account")

                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "gmail-linked",
                        "name": "Gmail Linked",
                        "role": "Search email",
                        "outbound_rbac": "internal",
                        "linked_accounts": ["g-work"],
                    },
                )
                google_bot = app.state.repo.get_bot("gmail-linked")
                app.state.google_oauth_service.search_messages = AsyncMock(  # type: ignore[method-assign]
                    return_value={"query": "is:unread", "messages": [{"id": "m1", "subject": "Hello"}]}
                )
                res_ok = asyncio.run(
                    app.state.bot_runner._execute_actions(
                        bot=google_bot,
                        correlation_id="corr_g2",
                        hop_count=0,
                        actions=[{"type": "gmail_search", "account": "work@example.com", "query": "is:unread"}],
                        trigger_type="manual",
                        trigger_payload={"from_chat_thread": True},
                    )
                )
                self.assertEqual(res_ok[0]["status"], "ok")
                self.assertEqual(res_ok[0]["account"], "g-work")
                self.assertEqual(len(res_ok[0]["messages"]), 1)

                # 4. Runtime switch sandbox -> api stops running sandbox container cleanly
                sb_driver = app.state.sandbox_manager._driver
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "switch-sb",
                        "name": "Switch Sandbox",
                        "role": "Run CLI",
                        "runtime": "sandbox",
                        "outbound_rbac": "internal",
                    },
                )
                st_res = client.post("/api/sandboxes/switch-sb/start", headers=self._sso_headers())
                self.assertEqual(st_res.status_code, 200)
                self.assertEqual(sb_driver.containers["argo-sandbox-switch-sb"]["status"], "running")

                sw_res = client.patch(
                    "/api/bots/switch-sb",
                    headers=self._sso_headers(),
                    json={"runtime": "api"},
                )
                self.assertEqual(sw_res.status_code, 200)
                self.assertEqual(sw_res.json()["runtime"], "api")
                self.assertEqual(sb_driver.containers["argo-sandbox-switch-sb"]["status"], "exited")

                # 5. Approved fleet_cleanup deletion destroys sandbox container and /workspace directory
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "cleanup-sb",
                        "name": "Cleanup Sandbox",
                        "role": "Run CLI",
                        "runtime": "sandbox",
                        "outbound_rbac": "internal",
                    },
                )
                client.post("/api/sandboxes/cleanup-sb/start", headers=self._sso_headers())
                self.assertIn("argo-sandbox-cleanup-sb", sb_driver.containers)
                approval = asyncio.run(
                    app.state.approval_coordinator.enqueue_human_approval(
                        correlation_id="corr_clean",
                        bot_slug="minimal-json-bot",
                        target_account_slug="argo_workspace",
                        action_type="fleet_cleanup",
                        payload={"operations": [{"bot_slug": "cleanup-sb", "delete": True}]},
                        hop_count=0,
                    )
                )
                resolved = client.post(
                    f"/api/approvals/{approval['id']}/resolve",
                    headers=self._sso_headers(),
                    json={"action": "approve"},
                )
                self.assertEqual(resolved.status_code, 200, resolved.text)
                self.assertEqual(resolved.json()["status"], "executed")
                self.assertNotIn("argo-sandbox-cleanup-sb", sb_driver.containers)
                self.assertFalse((Path(tmp) / "sandboxes" / "cleanup-sb").exists())

    def test_7_phase1_container_and_network_hardening(self) -> None:
        import os
        import stat
        import types
        from unittest.mock import patch

        from argo_core.desktop.manager import (
            _DESKTOP_EXTRA_ISOLATION_HOSTS,
            DESKTOP_IMAGE,
            DESKTOP_PIDS_LIMIT,
            DesktopRuntimeSpec,
            DockerSdkDriver,
        )
        from argo_core.sandbox.manager import SandboxManager

        # 1. Dockerfile.sandbox configures UID/GID 1000 user, owns /workspace, and includes OCI labels
        df_text = (ROOT / "Dockerfile.sandbox").read_text(encoding="utf-8")
        self.assertIn("USER 1000:1000", df_text)
        self.assertIn("chown 1000:1000 /workspace", df_text)
        self.assertIn(":1000:1000:", df_text)
        self.assertIn("org.opencontainers.image.source", df_text)

        # 2. compose.yml creates argo-sandbox-net with ICC disabled, uses registry-qualified ARGO_SANDBOX_IMAGE,
        #    omits local build: services, and leaves control plane detached
        compose_text = (ROOT / "compose.yml").read_text(encoding="utf-8")
        self.assertIn("ARGO_SANDBOX_NETWORK: \"argo-sandbox-net\"", compose_text)
        self.assertNotIn("build:", compose_text)
        self.assertNotIn("sandbox-build", compose_text)
        self.assertIsNotNone(
            re.search(r'ARGO_SANDBOX_IMAGE:\s*"[^"/]+/[^"]+/argo-sandbox:latest"', compose_text)
        )
        self.assertIn("argo-sandbox-net:", compose_text)
        self.assertIn('com.docker.network.bridge.enable_icc: "false"', compose_text)
        argo_core_nets = compose_text.split("argo-core:", 1)[1].split("oauth2-proxy:", 1)[0].split("networks:", 1)[1]
        self.assertNotIn("argo-sandbox-net", argo_core_nets)
        oauth_block = compose_text.split("oauth2-proxy:", 1)[1].split("networks:", 1)[0]
        self.assertNotIn("argo-sandbox-net", oauth_block)

        workflow_path = ROOT / ".gitea" / "workflows" / "build.yml"
        if workflow_path.is_file():
            wf_text = workflow_path.read_text(encoding="utf-8")
            self.assertIn("SANDBOX_DOCKER_TAGS", wf_text)
            self.assertIn("file: Dockerfile.sandbox", wf_text)
            self.assertIn("-sandbox:latest", wf_text)

        # 3. SandboxManager defaults to argo-sandbox-net even if ARGO_DOCKER_NETWORK=argo-desktop-net is set,
        #    and rejects argo-core-net cleanly.
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, sandbox_driver=InMemorySandboxDriver())
            with TestClient(app) as client:
                with patch.dict(os.environ, {"ARGO_DOCKER_NETWORK": "argo-desktop-net"}, clear=False):
                    mgr = SandboxManager(
                        repo=app.state.repo,
                        bus=app.state.bus,
                        guard=app.state.guard,
                        volumes_root=Path(tmp) / "sb_root",
                        driver=InMemorySandboxDriver(),
                    )
                    self.assertEqual(mgr._network, "argo-sandbox-net")
                    spec = mgr.build_spec("hardened-bot")
                    self.assertEqual(spec.network, "argo-sandbox-net")
                    self.assertEqual(spec.user, SANDBOX_USER)
                    self.assertTrue(spec.read_only)

                with self.assertRaises(SandboxConfigError):
                    SandboxManager(
                        repo=app.state.repo,
                        bus=app.state.bus,
                        guard=app.state.guard,
                        volumes_root=Path(tmp) / "sb_root",
                        network="argo-core-net",
                        driver=InMemorySandboxDriver(),
                    )

                # save_as uses 0o755 for bash scripts so non-root UID 1000 can execute them
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "sb-perm",
                        "name": "SB Perm",
                        "role": "Script runner",
                        "runtime": "sandbox",
                        "outbound_rbac": "internal",
                    },
                )
                asyncio.run(
                    app.state.sandbox_manager.exec_script(
                        "sb-perm",
                        script="#!/bin/bash\necho hi\n",
                        interpreter="bash",
                        save_as="nested/run.sh",
                    )
                )
                saved_path = Path(tmp) / "sandboxes" / "sb-perm" / "nested" / "run.sh"
                self.assertEqual(stat.S_IMODE(saved_path.stat().st_mode), 0o755)

        # 4. DockerSandboxDriver creates ICC-disabled network, launches user=1000:1000 + read_only + tmpfs,
        #    executes as UID 1000:1000, and replaces legacy root/writable containers on next start.
        with tempfile.TemporaryDirectory() as tmp:
            class _NotFound(Exception):
                pass

            net_create_calls: list[dict[str, Any]] = []
            run_calls: list[dict[str, Any]] = []
            exec_calls: list[dict[str, Any]] = []

            class _FakeContainer:
                def __init__(self, cid: str, *, attrs: dict[str, Any]) -> None:
                    self.id = cid
                    self.status = "running"
                    self.attrs = attrs
                    self.stopped = False
                    self.removed = False

                def reload(self) -> None:
                    pass

                def start(self) -> None:
                    self.status = "running"

                def stop(self, *, timeout: int = 10) -> None:
                    del timeout
                    self.stopped = True
                    self.status = "exited"

                def remove(self, *, force: bool = False) -> None:
                    del force
                    self.removed = True
                    containers_map.pop(self.id, None)

                def exec_run(self, cmd: Any, **kwargs: Any) -> Any:
                    exec_calls.append({"cmd": cmd, **kwargs})
                    return types.SimpleNamespace(exit_code=0, output=(b"ok\n", b""))

            legacy_ctr = _FakeContainer(
                "argo-sandbox-upg",
                attrs={
                    "Config": {"User": ""},
                    "HostConfig": {"ReadonlyRootfs": False, "ExtraHosts": None},
                    "NetworkSettings": {"Networks": {"argo-desktop-net": {}}},
                },
            )
            containers_map: dict[str, _FakeContainer] = {"argo-sandbox-upg": legacy_ctr}
            existing_nets: list[Any] = []

            class _FakeContainers:
                def get(self, name: str) -> _FakeContainer:
                    if name not in containers_map:
                        raise _NotFound(name)
                    return containers_map[name]

                def run(self, image: str, **kwargs: Any) -> _FakeContainer:
                    run_calls.append({"image": image, **kwargs})
                    c = _FakeContainer(
                        str(kwargs["name"]),
                        attrs={
                            "Config": {"User": str(kwargs.get("user") or "")},
                            "HostConfig": {
                                "ReadonlyRootfs": bool(kwargs.get("read_only", False)),
                                "ExtraHosts": [f"{k}:{v}" for k, v in (kwargs.get("extra_hosts") or {}).items()],
                            },
                            "NetworkSettings": {"Networks": {str(kwargs["network"]): {}}},
                        },
                    )
                    containers_map[str(kwargs["name"])] = c
                    return c

            class _FakeNetworks:
                def list(self) -> list[Any]:
                    return list(existing_nets)

                def create(self, name: str, **kwargs: Any) -> Any:
                    net_create_calls.append({"name": name, **kwargs})
                    obj = types.SimpleNamespace(name=name)
                    existing_nets.append(obj)
                    return obj

                def get(self, name: str) -> Any:
                    return types.SimpleNamespace(connect=lambda _c: None, name=name)

            fake_client = types.SimpleNamespace(
                containers=_FakeContainers(),
                images=types.SimpleNamespace(get=lambda _n: object()),
                networks=_FakeNetworks(),
            )
            driver = DockerSandboxDriver()
            driver._get_client = lambda: (fake_client, _NotFound)  # type: ignore[method-assign]

            spec_upg = SandboxRuntimeSpec(
                bot_slug="upg",
                container_name="argo-sandbox-upg",
                image=SANDBOX_IMAGE,
                network="argo-sandbox-net",
                host_volume_path=str(Path(tmp) / "sb_upg"),
            )
            res_start = driver._sync_ensure_started(spec_upg)
            self.assertEqual(res_start["status"], "running")
            self.assertTrue(legacy_ctr.removed)
            self.assertEqual(len(net_create_calls), 1)
            self.assertEqual(net_create_calls[0]["name"], "argo-sandbox-net")
            self.assertEqual(
                net_create_calls[0]["options"],
                {"com.docker.network.bridge.enable_icc": "false"},
            )
            self.assertEqual(len(run_calls), 1)
            rc = run_calls[0]
            self.assertEqual(rc["user"], SANDBOX_USER)
            self.assertTrue(rc["read_only"])
            self.assertEqual(rc["tmpfs"], {"/tmp": SANDBOX_TMPFS_OPTS})
            self.assertEqual(rc["cap_drop"], ["ALL"])
            self.assertEqual(rc["security_opt"], ["no-new-privileges:true"])
            self.assertEqual(rc["network"], "argo-sandbox-net")
            self.assertIn("argo-core", rc["extra_hosts"])

            driver._sync_exec_in_container("argo-sandbox-upg", ["id"], None, "/workspace")
            self.assertEqual(exec_calls[0]["user"], SANDBOX_USER)

        # 5. Desktop DockerSdkDriver passes extra_hosts & pids_limit=512 and recreates legacy ExtraHosts=None containers
        with tempfile.TemporaryDirectory() as tmp:
            class _DeskNotFound(Exception):
                pass

            desk_run_calls: list[dict[str, Any]] = []

            class _FakeDeskContainer:
                def __init__(self, cid: str, *, attrs: dict[str, Any]) -> None:
                    self.id = cid
                    self.status = "running"
                    self.attrs = attrs
                    self.removed = False

                def reload(self) -> None:
                    pass

                def stop(self, *, timeout: int = 10) -> None:
                    del timeout
                    self.status = "exited"

                def remove(self, *, force: bool = False) -> None:
                    del force
                    self.removed = True
                    desk_map.pop(self.id, None)

                def exec_run(self, *args: Any, **kwargs: Any) -> tuple[int, bytes]:
                    del args, kwargs
                    return 0, b""

                def put_archive(self, *args: Any, **kwargs: Any) -> bool:
                    del args, kwargs
                    return True

            legacy_desk = _FakeDeskContainer(
                "argo-desktop-d1",
                attrs={
                    "Config": {"Env": ["SUBFOLDER=/api/desktops/d1/selkies/"]},
                    "HostConfig": {"SecurityOpt": ["seccomp=unconfined"], "ExtraHosts": None},
                    "NetworkSettings": {"Networks": {"argo-desktop-net": {}}},
                },
            )
            desk_map: dict[str, _FakeDeskContainer] = {"argo-desktop-d1": legacy_desk}

            class _FakeDeskContainers:
                def get(self, name: str) -> _FakeDeskContainer:
                    if name not in desk_map:
                        raise _DeskNotFound(name)
                    return desk_map[name]

                def run(self, image: str, **kwargs: Any) -> _FakeDeskContainer:
                    desk_run_calls.append({"image": image, **kwargs})
                    c = _FakeDeskContainer(
                        str(kwargs["name"]),
                        attrs={
                            "Config": {"Env": [f"{k}={v}" for k, v in (kwargs.get("environment") or {}).items()]},
                            "HostConfig": {
                                "SecurityOpt": list(kwargs.get("security_opt") or []),
                                "ExtraHosts": [f"{k}:{v}" for k, v in (kwargs.get("extra_hosts") or {}).items()],
                            },
                            "NetworkSettings": {"Networks": {str(kwargs["network"]): {}}},
                        },
                    )
                    desk_map[str(kwargs["name"])] = c
                    return c

            desk_client = types.SimpleNamespace(
                containers=_FakeDeskContainers(),
                images=types.SimpleNamespace(get=lambda _n: object()),
                networks=types.SimpleNamespace(
                    list=lambda: [types.SimpleNamespace(name="argo-desktop-net")],
                    get=lambda n: types.SimpleNamespace(connect=lambda _c: None, name=n),
                ),
            )
            desk_driver = DockerSdkDriver()
            desk_driver._get_client = lambda: (desk_client, _DeskNotFound)  # type: ignore[method-assign]
            desk_driver._sync_ensure_agent_injected = lambda *a, **kw: None  # type: ignore[method-assign]

            desk_driver._sync_ensure_started(
                DesktopRuntimeSpec(
                    bot_slug="d1",
                    container_name="argo-desktop-d1",
                    image=DESKTOP_IMAGE,
                    network="argo-desktop-net",
                    host_volume_path=str(Path(tmp) / "desk_d1"),
                    mem_limit="2g",
                    nano_cpus=1_500_000_000,
                    shm_size="1g",
                    environment={"SUBFOLDER": "/api/desktops/d1/selkies/"},
                )
            )
            self.assertTrue(legacy_desk.removed)
            self.assertEqual(len(desk_run_calls), 1)
            self.assertEqual(desk_run_calls[0]["pids_limit"], DESKTOP_PIDS_LIMIT)
            self.assertEqual(desk_run_calls[0]["extra_hosts"], _DESKTOP_EXTRA_ISOLATION_HOSTS)

    def test_8_asymmetric_host_bind_mount_translation(self) -> None:
        import socket
        import types
        from unittest.mock import patch

        from argo_core.desktop.manager import (
            DESKTOP_IMAGE,
            DesktopRuntimeSpec,
            DockerSdkDriver,
        )
        from argo_core.docker_mounts import resolve_host_bind_path
        from argo_core.sandbox.manager import (
            SANDBOX_IMAGE,
            SANDBOX_NETWORK,
            SANDBOX_USER,
            DockerSandboxDriver,
            SandboxRuntimeSpec,
        )

        # 1. resolve_host_bind_path translates subdirectories, exact matches, longest-prefix priority,
        #    containers.list() hostname fallback, and no-op when unmapped.
        class _NotFound(Exception):
            pass

        self_mounts = [
            {"Type": "volume", "Source": "vol-data", "Destination": "/data"},
            {"Type": "bind", "Source": "/opt/argo/sandboxes", "Destination": "/srv/argo/sandboxes"},
            {"Type": "bind", "Source": "/opt/argo/desktops", "Destination": "/srv/argo/desktops"},
            {"Type": "bind", "Source": "/opt/data", "Destination": "/data"},
            {"Type": "bind", "Source": "/mnt/fast_sub", "Destination": "/data/sub"},
        ]

        client_by_list = types.SimpleNamespace(
            containers=types.SimpleNamespace(
                get=lambda _n: (_ for _ in ()).throw(_NotFound(_n)),
                list=lambda: [
                    types.SimpleNamespace(
                        attrs={
                            "Config": {"Hostname": "argo-core-host-1"},
                            "Mounts": self_mounts,
                        }
                    )
                ],
            )
        )
        self.assertEqual(
            resolve_host_bind_path(
                client_by_list, "/srv/argo/sandboxes/sandbox-check", hostname="argo-core-host-1"
            ),
            "/opt/argo/sandboxes/sandbox-check",
        )
        self.assertEqual(
            resolve_host_bind_path(
                client_by_list, "/srv/argo/desktops/desk-1", hostname="argo-core-host-1"
            ),
            "/opt/argo/desktops/desk-1",
        )
        self.assertEqual(
            resolve_host_bind_path(
                client_by_list, "/srv/argo/sandboxes", hostname="argo-core-host-1"
            ),
            "/opt/argo/sandboxes",
        )
        self.assertEqual(
            resolve_host_bind_path(
                client_by_list, "/data/sub/file.txt", hostname="argo-core-host-1"
            ),
            "/mnt/fast_sub/file.txt",
        )
        self.assertEqual(
            resolve_host_bind_path(
                client_by_list, "/unmapped/path", hostname="argo-core-host-1"
            ),
            "/unmapped/path",
        )

        client_empty = types.SimpleNamespace(
            containers=types.SimpleNamespace(
                get=lambda _n: (_ for _ in ()).throw(_NotFound(_n))
            )
        )
        self.assertEqual(
            resolve_host_bind_path(client_empty, "/srv/argo/sandboxes/sandbox-check"),
            "/srv/argo/sandboxes/sandbox-check",
        )

        # 2. DockerSandboxDriver translates asymmetric mounts and recreates mismatched sandbox mounts
        with tempfile.TemporaryDirectory() as tmp:
            sb_dir = Path(tmp) / "sandbox-check"
            sb_dir.mkdir(parents=True, exist_ok=True)
            hostname = socket.gethostname()
            run_calls: list[dict[str, Any]] = []
            removed: list[str] = []

            class _FakeCtr:
                def __init__(self, name: str, attrs: dict[str, Any]) -> None:
                    self.name = name
                    self.id = f"id-{name}"
                    self.status = "running"
                    self.attrs = attrs

                def stop(self, timeout: int = 5) -> None:
                    del timeout

                def remove(self, force: bool = True) -> None:
                    del force
                    removed.append(self.name)

            self_ctr = _FakeCtr(
                hostname,
                attrs={
                    "Config": {"Hostname": hostname},
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": "/opt/argo/sandboxes",
                            "Destination": str(tmp),
                        }
                    ],
                },
            )
            stale_mount_ctr = _FakeCtr(
                "argo-sandbox-sandbox-check",
                attrs={
                    "Config": {"User": SANDBOX_USER},
                    "HostConfig": {
                        "ReadonlyRootfs": True,
                        "ExtraHosts": [
                            "argo-core:127.0.0.1",
                            "valkey:127.0.0.1",
                            "oauth2-proxy:127.0.0.1",
                            "host.docker.internal:127.0.0.1",
                            "metadata.google.internal:127.0.0.1",
                        ],
                    },
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": str(sb_dir),
                            "Destination": "/workspace",
                        }
                    ],
                    "NetworkSettings": {"Networks": {SANDBOX_NETWORK: {}}},
                },
            )
            ctr_map = {hostname: self_ctr, "argo-sandbox-sandbox-check": stale_mount_ctr}

            class _FakeContainers:
                def get(self, name: str) -> _FakeCtr:
                    if name not in ctr_map:
                        raise _NotFound(name)
                    return ctr_map[name]

                def run(self, image: str, **kwargs: Any) -> _FakeCtr:
                    run_calls.append({"image": image, **kwargs})
                    c = _FakeCtr(str(kwargs["name"]), attrs={})
                    ctr_map[str(kwargs["name"])] = c
                    return c

            fake_client = types.SimpleNamespace(
                containers=_FakeContainers(),
                images=types.SimpleNamespace(get=lambda _n: object()),
                networks=types.SimpleNamespace(list=lambda: [types.SimpleNamespace(name=SANDBOX_NETWORK)]),
            )
            driver = DockerSandboxDriver()
            driver._get_client = lambda: (fake_client, _NotFound)  # type: ignore[method-assign]

            driver._sync_ensure_started(
                SandboxRuntimeSpec(
                    bot_slug="sandbox-check",
                    container_name="argo-sandbox-sandbox-check",
                    image=SANDBOX_IMAGE,
                    network=SANDBOX_NETWORK,
                    host_volume_path=str(sb_dir),
                )
            )
            self.assertEqual(removed, ["argo-sandbox-sandbox-check"])
            self.assertEqual(len(run_calls), 1)
            self.assertEqual(
                run_calls[0]["volumes"],
                {"/opt/argo/sandboxes/sandbox-check": {"bind": "/workspace", "mode": "rw"}},
            )

        # 3. Desktop DockerSdkDriver translates asymmetric /opt/argo/desktops -> /srv/argo/desktops
        with tempfile.TemporaryDirectory() as tmp:
            desk_dir = Path(tmp) / "desk-1"
            desk_dir.mkdir(parents=True, exist_ok=True)
            hostname = socket.gethostname()
            desk_runs: list[dict[str, Any]] = []

            class _FakeDeskCtr:
                def __init__(self, name: str, attrs: dict[str, Any]) -> None:
                    self.name = name
                    self.id = f"id-{name}"
                    self.status = "running"
                    self.attrs = attrs

                def put_archive(self, *args: Any, **kwargs: Any) -> bool:
                    del args, kwargs
                    return True

                def exec_run(self, *args: Any, **kwargs: Any):
                    del args, kwargs
                    return 0, b""

            self_desk_ctr = _FakeDeskCtr(
                hostname,
                attrs={
                    "Config": {"Hostname": hostname},
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": "/opt/argo/desktops",
                            "Destination": str(tmp),
                        }
                    ],
                },
            )

            class _FakeDeskContainers:
                def get(self, name: str) -> _FakeDeskCtr:
                    if name == hostname:
                        return self_desk_ctr
                    raise _NotFound(name)

                def run(self, image: str, **kwargs: Any) -> _FakeDeskCtr:
                    desk_runs.append({"image": image, **kwargs})
                    return _FakeDeskCtr(str(kwargs["name"]), attrs={})

            desk_client = types.SimpleNamespace(
                containers=_FakeDeskContainers(),
                images=types.SimpleNamespace(get=lambda _n: object()),
                networks=types.SimpleNamespace(list=lambda: [types.SimpleNamespace(name="argo-desktop-net")]),
            )
            desk_driver = DockerSdkDriver()
            desk_driver._get_client = lambda: (desk_client, _NotFound)  # type: ignore[method-assign]
            desk_driver._sync_ensure_agent_injected = lambda *a, **kw: None  # type: ignore[method-assign]

            desk_driver._sync_ensure_started(
                DesktopRuntimeSpec(
                    bot_slug="desk-1",
                    container_name="argo-desktop-desk-1",
                    image=DESKTOP_IMAGE,
                    network="argo-desktop-net",
                    host_volume_path=str(desk_dir),
                    mem_limit="2g",
                    nano_cpus=1_500_000_000,
                    shm_size="1g",
                    environment={"SUBFOLDER": "/api/desktops/desk-1/selkies/"},
                )
            )
            self.assertEqual(len(desk_runs), 1)
            self.assertEqual(
                desk_runs[0]["volumes"],
                {"/opt/argo/desktops/desk-1": {"bind": "/config", "mode": "rw"}},
            )

    def test_9_builder_manual_schedule_and_room_preview_strip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, sandbox_driver=InMemorySandboxDriver())
            with TestClient(app) as client:
                # 1. Script Sandbox prompt without explicit interval defaults to Manual
                sb_draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={
                        "prompt": "Run shell or Python scripts inside your Script Sandbox to inspect APIs."
                    },
                )
                self.assertEqual(sb_draft.status_code, 200, sb_draft.text)
                sb_obj = sb_draft.json()["draft"]
                self.assertEqual(sb_obj["runtime"], "sandbox")
                self.assertEqual(sb_obj["routines"][0]["type"], "manual_trigger")
                self.assertEqual(sb_obj["routines"][0]["schedule"], "Manual")

                # 2. Non-monitoring API prompt defaults to Manual
                api_draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={"prompt": "You are a helpful coding assistant"},
                )
                self.assertEqual(api_draft.status_code, 200, api_draft.text)
                api_obj = api_draft.json()["draft"]
                self.assertEqual(api_obj["runtime"], "api")
                self.assertEqual(api_obj["routines"][0]["type"], "manual_trigger")
                self.assertEqual(api_obj["routines"][0]["schedule"], "Manual")

                # 3. Monitoring API prompt still gets Every 15m
                mon_draft = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={"prompt": "Watch my Gmail inbox and RSS feeds for release notes"},
                )
                self.assertEqual(mon_draft.status_code, 200, mon_draft.text)
                mon_obj = mon_draft.json()["draft"]
                self.assertEqual(mon_obj["routines"][0]["type"], "cron")
                self.assertEqual(mon_obj["routines"][0]["schedule"], "Every 15m")

                # 4. Sandbox prompt with explicit interval respects Every 30m
                sb_timed = client.post(
                    "/api/bots/builder/draft",
                    headers=self._sso_headers(),
                    json={"prompt": "Run a Python health script every 30 minutes"},
                )
                self.assertEqual(sb_timed.status_code, 200, sb_timed.text)
                timed_obj = sb_timed.json()["draft"]
                self.assertEqual(timed_obj["runtime"], "sandbox")
                self.assertEqual(timed_obj["routines"][0]["schedule"], "Every 30m")

                # 5. Room sidebar preview strips Markdown headings and links cleanly
                for slug, name in (("b-one", "Dimiz eMail"), ("testbot-chrome", "TestBot Chrome")):
                    r = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={"slug": slug, "name": name, "role": "Helper"},
                    )
                    self.assertEqual(r.status_code, 201, r.text)
                room = app.state.repo.create_room(
                    title="TestRoom",
                    member_bot_slugs=["b-one", "testbot-chrome"],
                )
                app.state.repo.append_room_message(
                    room["slug"],
                    sender_type="bot",
                    sender_slug="testbot-chrome",
                    sender_name="TestBot Chrome",
                    text="### Visual Capture of [example.com](https://example.com)\nDetails here",
                )
                status = app.state.repo.build_live_workspace_status(user_email="operator@example.com")
                room_entry = next(rm for rm in status["rooms"] if rm["slug"] == room["slug"])
                self.assertEqual(
                    room_entry["last_message_preview"],
                    "TestBot Chrome: Visual Capture of example.com",
                )


if __name__ == "__main__":
    unittest.main()
