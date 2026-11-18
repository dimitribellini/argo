"""End-to-end tests for Zero-AI Secrets Vault (@slug), Desktop session recording -> Skill, and composable approval.queued notifications."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
import threading
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
from argo_core.desktop.manager import _LAUNCH_BROWSER_SCRIPT, InMemoryDockerDriver  # noqa: E402
from argo_core.desktop.mcp_bridge import (  # noqa: E402
    DESKTOP_AGENT_VERSION,
    _DESKTOP_AGENT_SCRIPT,
    _DefaultDesktopAgentTransport,
)
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeTelegramTransport:
    """In-memory Telegram transport recording delivered messages & inline cards."""

    def __init__(self) -> None:
        self.sent_messages: list[dict[str, Any]] = []
        self._seq = 100

    async def get_me(self, bot_token: str) -> dict[str, Any]:
        del bot_token
        return {"bot_id": 771122, "username": "argo_test_notify_bot", "first_name": "Argo Notify"}

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
        chat_id: str | int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del bot_token
        self._seq += 1
        rec = {
            "chat_id": str(chat_id),
            "message_id": self._seq,
            "text": text,
            "reply_markup": reply_markup,
        }
        self.sent_messages.append(rec)
        return {"message_id": self._seq, "chat_id": str(chat_id)}


class TestDesktopVaultRecordingAndApprovals(unittest.TestCase):
    """Verify Secrets Vault, Desktop recording -> Skill, and composable approval.queued notifications."""

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
        telegram_transport=None,
        docker_driver=None,
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
                "ram_percent": 35.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 12.0,
                "disk_percent": 25.0,
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
            telegram_transport=telegram_transport,
            docker_driver=docker_driver,
        )

    def test_secrets_vault_zero_ai_exposure_acl_injection_and_scrubbing(self) -> None:
        secret_password = "SuperSecretSshPassword99!"
        secret_key_marker = "SECRETPRIVATEKEYMATERIAL42"
        secret_pem = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{secret_key_marker}\n-----END OPENSSH PRIVATE KEY-----"
        prompts_seen: list[tuple[str, str]] = []
        turn_counter: dict[str, int] = {}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            prompts_seen.append((req.system_prompt, req.user_prompt))
            match = re.search(r"Bot slug:\s*([a-z0-9-]+)", req.system_prompt)
            bot_slug = match.group(1) if match else "unknown"
            turn_counter[bot_slug] = turn_counter.get(bot_slug, 0) + 1
            turn_n = turn_counter[bot_slug]
            if turn_n == 1:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Running SSH command via vault placeholders.",
                            "actions": [
                                {
                                    "type": "desktop_exec",
                                    "command": (
                                        'sshpass -p "$ARGO_VAULT_MYSSH_PASSWORD" '
                                        "ssh -o StrictHostKeyChecking=no "
                                        '"$ARGO_VAULT_MYSSH_USERNAME@$ARGO_VAULT_MYSSH_HOST" whoami '
                                        "# echo {{vault:myssh.password}}"
                                    ),
                                }
                            ],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 18,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": f"Completed command check without leaking {secret_password}.",
                        "actions": [],
                    }
                ),
                "input_tokens": 14,
                "output_tokens": 10,
            }

        with tempfile.TemporaryDirectory() as tmp:
            driver = InMemoryDockerDriver()
            app = self._build_env(tmp, llm_transport=fake_llm, docker_driver=driver)
            with TestClient(app) as client:
                # 1. Create encrypted Vault SSH secret permitted only for ops-desktop
                created_secret = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Prod Zabbix SSH",
                        "slug": "myssh",
                        "secret_type": "ssh",
                        "host": "192.168.8.225",
                        "port": "22",
                        "secrets": {
                            "username": "root",
                            "password": secret_password,
                            "private_key": secret_pem,
                        },
                        "allowed_bots": ["ops-desktop"],
                    },
                )
                self.assertEqual(created_secret.status_code, 201, created_secret.text)
                sec_body = created_secret.json()
                self.assertEqual(sec_body["slug"], "myssh")
                self.assertIn("$ARGO_VAULT_MYSSH_PASSWORD", sec_body["env_placeholders"])
                self.assertIn("$ARGO_VAULT_MYSSH_USERNAME", sec_body["env_placeholders"])
                self.assertIn("$ARGO_VAULT_MYSSH_HOST", sec_body["env_placeholders"])
                self.assertIn("$ARGO_VAULT_MYSSH_PORT", sec_body["env_placeholders"])

                listed = client.get("/api/vault", headers=self._sso_headers())
                self.assertEqual(listed.status_code, 200)
                listed_json = json.dumps(listed.json())
                self.assertNotIn(secret_password, listed_json)
                self.assertNotIn(secret_key_marker, listed_json)

                # 2. Create two desktop bots: ops-desktop (permitted) and other-desktop (blocked)
                ops_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Ops Desktop",
                        "slug": "ops-desktop",
                        "role": "Run desktop SSH diagnostics",
                        "runtime": "desktop",
                        "outbound_rbac": "draft",
                    },
                )
                other_bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Other Desktop",
                        "slug": "other-desktop",
                        "role": "Unprivileged desktop bot",
                        "runtime": "desktop",
                        "outbound_rbac": "draft",
                    },
                )
                self.assertEqual(ops_bot.status_code, 201, ops_bot.text)
                self.assertEqual(other_bot.status_code, 201, other_bot.text)

                self.assertEqual(
                    client.post("/api/desktops/ops-desktop/toggle", headers=self._sso_headers()).status_code,
                    200,
                )
                self.assertEqual(
                    client.post("/api/desktops/other-desktop/toggle", headers=self._sso_headers()).status_code,
                    200,
                )

                # 3. Unpermitted bot mentions @myssh -> blocked_vault_acl + zero secret leak to LLM
                turn_counter["other-desktop"] = 0
                blocked_resp = client.post(
                    "/api/bots/other-desktop/messages",
                    headers=self._sso_headers(),
                    json={"text": "Use @myssh to run whoami"},
                )
                self.assertEqual(blocked_resp.status_code, 200, blocked_resp.text)
                blocked_result = blocked_resp.json()["result"]
                self.assertTrue(
                    any(a.get("status") == "blocked_vault_acl" for a in blocked_result["actions"]),
                    blocked_result["actions"],
                )
                for sys_p, usr_p in prompts_seen:
                    self.assertNotIn(secret_password, sys_p)
                    self.assertNotIn(secret_password, usr_p)
                    self.assertNotIn(secret_key_marker, usr_p)

                prompts_seen.clear()

                # 4. Permitted bot mentions @myssh -> placeholders in prompt, decrypted env injected, output scrubbed
                turn_counter["ops-desktop"] = 0
                ok_resp = client.post(
                    "/api/bots/ops-desktop/messages",
                    headers=self._sso_headers(),
                    json={"text": "Connect with @myssh and check whoami"},
                )
                self.assertEqual(ok_resp.status_code, 200, ok_resp.text)
                ok_payload = ok_resp.json()
                ok_result = ok_payload["result"]

                # Prompt sent to LLM exposes metadata & env placeholders only — NEVER plaintext password
                first_env = json.loads(prompts_seen[0][1])
                vault_entries = first_env.get("available_vault_secrets") or []
                self.assertEqual(len(vault_entries), 1)
                self.assertEqual(vault_entries[0]["slug"], "myssh")
                self.assertIn("$ARGO_VAULT_MYSSH_PASSWORD", vault_entries[0]["env_placeholders"])
                for sys_p, usr_p in prompts_seen:
                    self.assertNotIn(secret_password, sys_p)
                    self.assertNotIn(secret_password, usr_p)
                    self.assertNotIn(secret_key_marker, usr_p)

                # Simulated Desktop MCP received decrypted env variables cleanly
                sim_state = app.state.desktop_mcp_bridge._sim_state("ops-desktop")
                self.assertIsNotNone(sim_state.last_exec_env)
                assert sim_state.last_exec_env is not None
                self.assertEqual(sim_state.last_exec_env["ARGO_VAULT_MYSSH_PASSWORD"], secret_password)
                self.assertEqual(sim_state.last_exec_env["ARGO_VAULT_MYSSH_USERNAME"], "root")
                self.assertEqual(sim_state.last_exec_env["ARGO_VAULT_MYSSH_HOST"], "192.168.8.225")

                # Secret values echoed back in stdout / summary / debug traces are scrubbed to <REDACTED>
                dumped_result = json.dumps(ok_result)
                self.assertNotIn(secret_password, dumped_result)
                self.assertNotIn(secret_key_marker, dumped_result)
                self.assertIn("<REDACTED>", dumped_result)

                debug_ov = client.get(
                    "/api/debug/overview?bot_slug=ops-desktop",
                    headers=self._sso_headers(),
                ).json()
                dumped_debug = json.dumps(debug_ov)
                self.assertNotIn(secret_password, dumped_debug)
                self.assertNotIn(secret_key_marker, dumped_debug)

                msgs = client.get(
                    "/api/bots/ops-desktop/messages",
                    headers=self._sso_headers(),
                ).json()
                dumped_msgs = json.dumps(msgs)
                self.assertNotIn(secret_password, dumped_msgs)
                self.assertNotIn(secret_key_marker, dumped_msgs)

    def test_desktop_session_recording_to_skill_and_agent_keyfile_lifecycle(self) -> None:
        # Part A: Embedded Desktop MCP v4 server real subprocess env injection & temp SSH key cleanup + recording
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

            async def _run_real_agent() -> None:
                health = await transport.health("rec-agent", endpoint)
                self.assertEqual(health["agent_version"], DESKTOP_AGENT_VERSION)
                self.assertEqual(DESKTOP_AGENT_VERSION, "6")

                r_start = await transport.execute_action("rec-agent", endpoint, "record_start", {})
                self.assertTrue(r_start["recording"])

                exec_res = await transport.execute_action(
                    "rec-agent",
                    endpoint,
                    "exec",
                    {
                        "command": 'echo "KEY:$ARGO_VAULT_MYSSH_KEY_PATH" && ls -l "$ARGO_VAULT_MYSSH_KEY_PATH"',
                        "env": {
                            "ARGO_VAULT_MYSSH_PASSWORD": "SecretAgentPass!",
                            "ARGO_VAULT_MYSSH_PRIVATE_KEY": "-----BEGIN TEST-----\nabc\n-----END TEST-----\n",
                        },
                        "show_terminal": False,
                    },
                )
                self.assertEqual(exec_res["status"], "ok")
                self.assertIn("KEY:/", exec_res["stdout"])
                # Temp key path created strictly inside execution and cleaned up immediately afterward
                key_line = [ln for ln in exec_res["stdout"].splitlines() if ln.startswith("KEY:")][0]
                created_key_path = Path(key_line.split("KEY:", 1)[1].strip())
                self.assertFalse(created_key_path.exists())

                r_stop = await transport.execute_action("rec-agent", endpoint, "record_stop", {})
                self.assertFalse(r_stop["recording"])

            asyncio.run(_run_real_agent())
        finally:
            server.shutdown()
            server.server_close()

        # Part B: FastAPI /api/desktops/{slug}/recording/* -> scrubbed replayable Skill in GET /api/skills
        secret_pw = "RecordedSessionSecret77!"
        with tempfile.TemporaryDirectory() as tmp:
            driver = InMemoryDockerDriver()
            app = self._build_env(tmp, docker_driver=driver)
            with TestClient(app) as client:
                VaultCreate = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "SSH Box",
                        "slug": "box1",
                        "secret_type": "ssh",
                        "host": "10.0.0.5",
                        "secrets": {"username": "ops", "password": secret_pw},
                        "allowed_bots": ["*"],
                    },
                )
                self.assertEqual(VaultCreate.status_code, 201)

                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Recorder Bot",
                        "slug": "recorder-bot",
                        "role": "Record desktop procedures into skills",
                        "runtime": "desktop",
                    },
                ).json()
                self.assertEqual(
                    client.post(f"/api/desktops/{bot['slug']}/toggle", headers=self._sso_headers()).status_code,
                    200,
                )

                rec_start = client.post(
                    f"/api/desktops/{bot['slug']}/recording/start",
                    headers=self._sso_headers(),
                )
                self.assertEqual(rec_start.status_code, 200, rec_start.text)
                self.assertTrue(rec_start.json()["recording"])

                with patch("argo_core.desktop.mcp_bridge.validate_public_url", side_effect=lambda u: (u, ["93.184.216.34"])):
                    act_exec = client.post(
                        f"/api/desktops/{bot['slug']}/action",
                        headers=self._sso_headers(),
                        json={"action": "exec", "command": f"echo {secret_pw} && dnf install -y zabbix-agent2"},
                    )
                    self.assertEqual(act_exec.status_code, 200, act_exec.text)
                    act_launch = client.post(
                        f"/api/desktops/{bot['slug']}/action",
                        headers=self._sso_headers(),
                        json={"action": "launch", "app": "chromium", "url": "https://www.zabbix.com/download"},
                    )
                    self.assertEqual(act_launch.status_code, 200, act_launch.text)

                rec_status = client.get(
                    f"/api/desktops/{bot['slug']}/recording/status",
                    headers=self._sso_headers(),
                )
                self.assertEqual(rec_status.status_code, 200)
                self.assertTrue(rec_status.json()["recording"])
                self.assertGreaterEqual(rec_status.json()["command_count"], 1)

                rec_stop = client.post(
                    f"/api/desktops/{bot['slug']}/recording/stop",
                    headers=self._sso_headers(),
                    json={"skill_name": "Install Zabbix Agent", "save_skill": True},
                )
                self.assertEqual(rec_stop.status_code, 200, rec_stop.text)
                stop_data = rec_stop.json()
                self.assertIsNotNone(stop_data["skill"])
                self.assertEqual(stop_data["skill"]["slug"], "install-zabbix-agent")
                self.assertIn("dnf install -y zabbix-agent2", stop_data["skill"]["instructions"])
                self.assertNotIn(secret_pw, stop_data["skill"]["instructions"])
                self.assertIn("<REDACTED>", stop_data["skill"]["instructions"])

                skills = client.get("/api/skills", headers=self._sso_headers()).json()
                self.assertTrue(any(s["slug"] == "install-zabbix-agent" for s in skills))
                skills_count_before_discard = len(skills)

                # Stop a recording WITHOUT saving a skill (`save_skill: False`)
                rec_start_2 = client.post(
                    f"/api/desktops/{bot['slug']}/recording/start",
                    headers=self._sso_headers(),
                )
                self.assertEqual(rec_start_2.status_code, 200)
                client.post(
                    f"/api/desktops/{bot['slug']}/action",
                    headers=self._sso_headers(),
                    json={"action": "exec", "command": "echo discarded_cmd"},
                )
                rec_discard = client.post(
                    f"/api/desktops/{bot['slug']}/recording/stop",
                    headers=self._sso_headers(),
                    json={"save_skill": False},
                )
                self.assertEqual(rec_discard.status_code, 200, rec_discard.text)
                discard_data = rec_discard.json()
                self.assertTrue(discard_data["discarded"])
                self.assertIsNone(discard_data["skill"])
                self.assertFalse(discard_data["recording"]["recording"])
                rec_status_after = client.get(
                    f"/api/desktops/{bot['slug']}/recording/status",
                    headers=self._sso_headers(),
                ).json()
                self.assertFalse(rec_status_after["recording"])
                skills_after_discard = client.get("/api/skills", headers=self._sso_headers()).json()
                self.assertEqual(len(skills_after_discard), skills_count_before_discard)

                # Two-step Stop (`save_skill: False`) -> Deferred `/recording/save` with GUI clicks & typed inputs
                rec_start_3 = client.post(
                    f"/api/desktops/{bot['slug']}/recording/start",
                    headers=self._sso_headers(),
                )
                self.assertEqual(rec_start_3.status_code, 200)
                client.post(
                    f"/api/desktops/{bot['slug']}/action",
                    headers=self._sso_headers(),
                    json={"action": "click", "x": 320, "y": 410},
                )
                client.post(
                    f"/api/desktops/{bot['slug']}/action",
                    headers=self._sso_headers(),
                    json={"action": "type", "text": f"DXB {secret_pw}"},
                )
                client.post(
                    f"/api/desktops/{bot['slug']}/action",
                    headers=self._sso_headers(),
                    json={"action": "key", "key": "Return"},
                )

                stop_only = client.post(
                    f"/api/desktops/{bot['slug']}/recording/stop",
                    headers=self._sso_headers(),
                    json={"save_skill": False},
                )
                self.assertEqual(stop_only.status_code, 200, stop_only.text)
                stop_only_body = stop_only.json()
                self.assertFalse(stop_only_body["recording"]["recording"])
                self.assertIsNone(stop_only_body["skill"])
                self.assertGreaterEqual(len(stop_only_body["recording"]["clicks"]), 1)
                self.assertGreaterEqual(len(stop_only_body["recording"]["typed_inputs"]), 1)

                # Recorder must already be stopped before user clicks "Save Skill"
                status_stopped = client.get(
                    f"/api/desktops/{bot['slug']}/recording/status",
                    headers=self._sso_headers(),
                ).json()
                self.assertFalse(status_stopped["recording"])

                saved_deferred = client.post(
                    f"/api/desktops/{bot['slug']}/recording/save",
                    headers=self._sso_headers(),
                    json={
                        "skill_name": "Flight Search",
                        "recording": stop_only_body["recording"],
                    },
                )
                self.assertEqual(saved_deferred.status_code, 200, saved_deferred.text)
                saved_skill = saved_deferred.json()["skill"]
                self.assertIsNotNone(saved_skill)
                self.assertEqual(saved_skill["slug"], "flight-search")
                self.assertIn("Keyboard Input Sequence", saved_skill["instructions"])
                self.assertIn("Click (320, 410)", saved_skill["instructions"])
                self.assertNotIn(secret_pw, saved_skill["instructions"])
                self.assertIn("<REDACTED>", saved_skill["instructions"])

    def test_channel_agnostic_approvals_and_composable_approval_queued_bots(self) -> None:
        tg_transport = _FakeTelegramTransport()
        webhook_calls: list[dict[str, Any]] = []

        async def fake_webhook_post(url: str, body: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
            webhook_calls.append({"url": url, "body": body, "headers": headers})
            return {"status_code": 200, "ok": True}

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            match = re.search(r"Bot slug:\s*([a-z0-9-]+)", req.system_prompt)
            bot_slug = match.group(1) if match else "unknown"
            if bot_slug == "gmail-triage":
                return {
                    "text": json.dumps(
                        {
                            "summary": "Prepared client reply draft for human review.",
                            "actions": [
                                {
                                    "type": "send_email",
                                    "account": "biz-gmail",
                                    "to": "client@example.com",
                                    "subject": "Quarterly Maintenance Schedule",
                                    "text": "Hello, please find our updated maintenance window.",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 18,
                    "output_tokens": 22,
                }
            if bot_slug == "tg-approval-notifier":
                env = json.loads(req.user_prompt)
                aid = (env.get("trigger_payload") or {}).get("approval_id")
                return {
                    "text": json.dumps(
                        {
                            "summary": "Delivered Telegram approval alert.",
                            "actions": [
                                {
                                    "type": "notify_approval",
                                    "account": "tg-ops",
                                    "approval_id": aid,
                                }
                            ],
                        }
                    ),
                    "input_tokens": 12,
                    "output_tokens": 14,
                }
            if bot_slug == "slack-approval-notifier":
                env = json.loads(req.user_prompt)
                aid = (env.get("trigger_payload") or {}).get("approval_id")
                return {
                    "text": json.dumps(
                        {
                            "summary": "Delivered Slack webhook approval alert.",
                            "actions": [
                                {
                                    "type": "notify_approval",
                                    "account": "slack-ops",
                                    "approval_id": aid,
                                    "text": f"Slack alert: review approval {aid}",
                                }
                            ],
                        }
                    ),
                    "input_tokens": 12,
                    "output_tokens": 14,
                }
            return {"text": json.dumps({"summary": "Done.", "actions": []}), "input_tokens": 5, "output_tokens": 5}

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=fake_llm,
                telegram_transport=tg_transport,
            )

            with patch("argo_core.approvals.coordinator.validate_public_url", side_effect=lambda u: (u, ["93.184.216.34"])):
                with TestClient(app) as client:
                    app.state.approval_coordinator._webhook_transport = fake_webhook_post
                    # 1. Connect Telegram, Webhook (Slack), and Business Gmail
                    tg_res = client.post(
                        "/api/integrations/telegram/onboard",
                        headers=self._sso_headers(),
                        json={
                            "bot_token": "999999:TG_TEST_SECRET_TOKEN_0123456789ABCDEF",
                            "slug": "tg-ops",
                            "display_name": "Telegram Ops",
                            "operator_chat_id": "999111",
                            "register_webhook": False,
                        },
                    )
                    self.assertEqual(tg_res.status_code, 201, tg_res.text)

                    slack_res = client.post(
                        "/api/integrations",
                        headers=self._sso_headers(),
                        json={
                            "slug": "slack-ops",
                            "provider": "webhook",
                            "display_name": "Slack Ops Webhook",
                            "secrets": {"target_url": "https://hooks.slack.com/services/T000/B000/XXXX"},
                        },
                    )
                    self.assertEqual(slack_res.status_code, 201, slack_res.text)

                    app.state.repo.upsert_integration(
                        slug="biz-gmail",
                        provider="google",
                        display_name="Business Gmail",
                        account_identifier="ops@company.example",
                        scopes=["gmail_read", "gmail_send"],
                        secrets={
                            "client_id": "cid",
                            "client_secret": "csec",
                            "refresh_token": "1//ref",
                            "access_token": "ya29.tok",
                            "expiry": "2099-01-01T00:00:00Z",
                        },
                        status="ok",
                    )

                    # 2. Gmail triage bot queues draft -> stays ONLY in Approvals (zero automatic Telegram spam!)
                    gmail_bot = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={
                            "name": "Gmail Triage",
                            "slug": "gmail-triage",
                            "role": "Draft client replies for review",
                            "runtime": "api",
                            "outbound_rbac": "draft",
                            "linked_accounts": ["biz-gmail"],
                        },
                    )
                    self.assertEqual(gmail_bot.status_code, 201, gmail_bot.text)

                    r1 = client.post(
                        "/api/bots/gmail-triage/trigger",
                        headers=self._sso_headers(),
                        json={"wait_for_chain": True},
                    )
                    self.assertEqual(r1.status_code, 200, r1.text)
                    approvals_after_1 = client.get(
                        "/api/approvals?tab=pending",
                        headers=self._sso_headers(),
                    ).json()
                    self.assertEqual(len(approvals_after_1), 1)
                    self.assertEqual(approvals_after_1[0]["target_account_slug"], "biz-gmail")
                    self.assertEqual(tg_transport.sent_messages, [])

                    # 3. Create composable on_event:approval.queued subscriber bots (Telegram & Slack Webhook)
                    tg_sub = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={
                            "name": "Telegram Approval Notifier",
                            "slug": "tg-approval-notifier",
                            "role": "Forward approvals to Telegram",
                            "runtime": "api",
                            "outbound_rbac": "execute",
                            "daily_cap": 20,
                            "linked_accounts": ["tg-ops"],
                            "routines": [
                                {
                                    "id": "rtn_tg_apr",
                                    "type": "on_event",
                                    "event": "approval.queued",
                                    "enabled": True,
                                }
                            ],
                        },
                    )
                    slack_sub = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={
                            "name": "Slack Approval Notifier",
                            "slug": "slack-approval-notifier",
                            "role": "Forward approvals to Slack webhook",
                            "runtime": "api",
                            "outbound_rbac": "execute",
                            "daily_cap": 20,
                            "linked_accounts": ["slack-ops"],
                            "routines": [
                                {
                                    "id": "rtn_slack_apr",
                                    "type": "on_event",
                                    "event": "approval.queued",
                                    "enabled": True,
                                }
                            ],
                        },
                    )
                    self.assertEqual(tg_sub.status_code, 201, tg_sub.text)
                    self.assertEqual(slack_sub.status_code, 201, slack_sub.text)

                    # 4. Trigger Gmail bot again -> both composable approval subscribers notify Telegram & Slack!
                    r2 = client.post(
                        "/api/bots/gmail-triage/trigger",
                        headers=self._sso_headers(),
                        json={"wait_for_chain": True},
                    )
                    self.assertEqual(r2.status_code, 200, r2.text)

                    approvals_after_2 = client.get(
                        "/api/approvals?tab=pending",
                        headers=self._sso_headers(),
                    ).json()
                    self.assertEqual(len(approvals_after_2), 2)
                    self.assertEqual(len(tg_transport.sent_messages), 1)
                    self.assertEqual(tg_transport.sent_messages[0]["chat_id"], "999111")
                    self.assertIn("Approve", json.dumps(tg_transport.sent_messages[0]["reply_markup"]))
                    self.assertEqual(len(webhook_calls), 1)
                    self.assertEqual(
                        webhook_calls[0]["url"],
                        "https://hooks.slack.com/services/T000/B000/XXXX",
                    )
                    self.assertIn("Slack alert: review approval", webhook_calls[0]["body"]["text"])

    def test_chromium_on_demand_boot_and_multi_turn_gui_replay(self) -> None:
        # Boot script prepares flags (--test-type) cleanly without auto-launching Chromium
        self.assertNotIn("launch_chromium\n", _LAUNCH_BROWSER_SCRIPT)
        self.assertIn("--no-sandbox", _LAUNCH_BROWSER_SCRIPT)
        self.assertIn("--test-type", _LAUNCH_BROWSER_SCRIPT)
        self.assertIn("--hide-crash-restore-bubble", _LAUNCH_BROWSER_SCRIPT)

        gui_turns = 0

        async def gui_replay_llm(req: LLMRequest) -> dict[str, Any]:
            nonlocal gui_turns
            del req
            gui_turns += 1
            if gui_turns == 1:
                act = {"type": "desktop_launch", "app": "chromium", "url": "https://example.com/flights"}
            elif gui_turns in (2, 4):
                act = {"type": "desktop_click", "x": 240 + gui_turns * 10, "y": 510}
            elif gui_turns in (3, 5):
                act = {"type": "desktop_type", "text": "Dubai" if gui_turns == 3 else "Milan"}
            elif gui_turns == 6:
                act = {"type": "desktop_key", "key": "Return"}
            else:
                return {
                    "text": json.dumps(
                        {
                            "summary": "Completed 7-step GUI workflow replay.",
                            "actions": [],
                        }
                    ),
                    "input_tokens": 18,
                    "output_tokens": 12,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": f"Executing step {gui_turns}",
                        "actions": [act],
                    }
                ),
                "input_tokens": 18,
                "output_tokens": 14,
            }

        with tempfile.TemporaryDirectory() as tmp:
            driver = InMemoryDockerDriver()
            app = self._build_env(tmp, llm_transport=gui_replay_llm, docker_driver=driver)
            with patch(
                "argo_core.desktop.mcp_bridge.validate_public_url",
                side_effect=lambda u: (u, ["93.184.216.34"]),
            ):
                with TestClient(app) as client:
                    bot = client.post(
                        "/api/bots",
                        headers=self._sso_headers(),
                        json={
                            "name": "Flight Replay Bot",
                            "slug": "flight-replay",
                            "role": "Replay recorded browser searches",
                            "runtime": "desktop",
                        },
                    ).json()
                    client.post(f"/api/desktops/{bot['slug']}/toggle", headers=self._sso_headers())
                    res = client.post(
                        f"/api/bots/{bot['slug']}/messages",
                        headers=self._sso_headers(),
                        json={"text": "Run the multi-step search workflow"},
                    )
                    self.assertEqual(res.status_code, 200, res.text)
                    payload = res.json()
                    self.assertEqual(gui_turns, 7)
                    self.assertEqual(payload["result"]["summary"], "Completed 7-step GUI workflow replay.")
                    self.assertEqual(len(payload["result"]["actions"]), 6)
                    shots = [
                        a["screenshot_url"]
                        for a in payload["result"]["actions"]
                        if a.get("screenshot_url")
                    ]
                    self.assertEqual(len(shots), 1)
                    self.assertTrue(payload["result"]["actions"][-1].get("screenshot_url"))

    def test_delete_desktop_bot_cleans_container_volume_threads_snapshots_approvals_handoffs_and_rooms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            driver = InMemoryDockerDriver()
            app = self._build_env(tmp, docker_driver=driver)
            with TestClient(app) as client:
                created = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Test Bot with desktop",
                        "slug": "test-bot-with-desktop",
                        "role": "Desktop operator bot",
                        "runtime": "desktop",
                    },
                )
                self.assertEqual(created.status_code, 201, created.text)
                slug = created.json()["slug"]

                sibling = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "name": "Sibling Helper",
                        "slug": "sibling-helper",
                        "role": "Receives handoffs",
                        "runtime": "api",
                        "handoff_bot_slug": slug,
                    },
                )
                self.assertEqual(sibling.status_code, 201, sibling.text)

                toggle = client.post(f"/api/desktops/{slug}/toggle", headers=self._sso_headers())
                self.assertEqual(toggle.status_code, 200, toggle.text)
                container_name = f"argo-desktop-{slug}"
                self.assertIn(container_name, driver.containers)

                vol_dir = app.state.desktop_manager._volumes_root / slug
                vol_dir.mkdir(parents=True, exist_ok=True)
                marker = vol_dir / "chromium-profile.txt"
                marker.write_text("persisted-profile", encoding="utf-8")
                self.assertTrue(marker.exists())

                repo = app.state.repo
                repo.append_bot_message(
                    slug,
                    "bot",
                    "#### Step 1\n#my-id click\n**@vault** replayed",
                )
                snap_id = repo.save_desktop_snapshot(
                    slug,
                    png_base64="iVBORw0KGgo=",
                    caption="After click",
                    url="https://example.com",
                )
                skill = repo.upsert_skill(
                    name="Desktop Replay Skill",
                    description="Recorded click flow",
                    instructions="1. Click button\n2. Submit",
                    scope_slug=slug,
                )
                style_rule = repo.add_style_rule(
                    rule_text="Keep concise.",
                    scope_slug=slug,
                )
                approval = repo.create_approval(
                    correlation_id="corr_del_test",
                    bot_slug=slug,
                    target_account_slug="tg-ops",
                    action_type="send_message",
                    payload={"text": "Draft awaiting approval"},
                )
                room = repo.create_room(
                    title="Ops Coordination",
                    member_bot_slugs=[slug, "sibling-helper"],
                    coordinator_bot_slug=slug,
                    stage_order=[slug, "sibling-helper"],
                )

                snap_before = client.get(
                    f"/api/desktops/{slug}/snapshots/{snap_id}",
                    headers=self._sso_headers(),
                )
                self.assertEqual(snap_before.status_code, 200)

                deleted = client.delete(f"/api/bots/{slug}", headers=self._sso_headers())
                self.assertEqual(deleted.status_code, 200, deleted.text)
                self.assertEqual(deleted.json(), {"status": "deleted", "slug": slug})

                # Desktop container + persistent volume removed
                self.assertNotIn(container_name, driver.containers)
                self.assertFalse(vol_dir.exists())

                # Bot and duplicate delete return 404
                self.assertEqual(
                    client.get(f"/api/bots/{slug}", headers=self._sso_headers()).status_code,
                    404,
                )
                self.assertEqual(
                    client.delete(f"/api/bots/{slug}", headers=self._sso_headers()).status_code,
                    404,
                )

                # Snapshot HTTP endpoint & DB scoped collections cleaned
                self.assertEqual(
                    client.get(
                        f"/api/desktops/{slug}/snapshots/{snap_id}",
                        headers=self._sso_headers(),
                    ).status_code,
                    404,
                )
                with repo._lock:
                    thread_count = repo._conn.execute(
                        "SELECT COUNT(*) AS c FROM collection_documents WHERE collection = 'bot_threads' AND json_extract(doc_json, '$.bot_slug') = ?",
                        (slug,),
                    ).fetchone()["c"]
                    snap_count = repo._conn.execute(
                        "SELECT COUNT(*) AS c FROM collection_documents WHERE collection = 'desktop_snapshots' AND json_extract(doc_json, '$.bot_slug') = ?",
                        (slug,),
                    ).fetchone()["c"]
                    skill_count = repo._conn.execute(
                        "SELECT COUNT(*) AS c FROM collection_documents WHERE collection = 'bot_skills' AND json_extract(doc_json, '$.scope_slug') = ?",
                        (slug,),
                    ).fetchone()["c"]
                self.assertEqual(thread_count, 0)
                self.assertEqual(snap_count, 0)
                self.assertEqual(skill_count, 0)
                self.assertNotIn(skill["slug"], [s["slug"] for s in repo.list_skills(scope_slug=slug)])
                self.assertNotIn(style_rule["id"], [r["id"] for r in repo.list_style_rules()])

                # Pending approval superseded rather than orphaned
                updated_approval = repo.get_approval(approval["id"])
                self.assertEqual(updated_approval["status"], "superseded")

                # Sibling handoff_bot_slug cleared and Room membership reassigned
                updated_sibling = repo.get_bot("sibling-helper")
                self.assertEqual(updated_sibling["handoff_bot_slug"], "")
                rooms = [r for r in repo.list_rooms() if r["slug"] == room["slug"]]
                self.assertEqual(len(rooms), 1)
                self.assertEqual(rooms[0]["member_bot_slugs"], ["sibling-helper"])
                self.assertEqual(rooms[0]["coordinator_bot_slug"], "sibling-helper")

                # bot.deleted event emitted
                events = repo.list_events(category="all", limit=50)
                self.assertTrue(
                    any(e.get("event_type") == "bot.deleted" and e.get("target_slug") == slug for e in events)
                )


if __name__ == "__main__":
    unittest.main()
