"""Regression tests for 2-step Clear Chat, Markdown Transcript Export, and Chat Retention."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class TestChatHistoryCleanupAndRetention(unittest.TestCase):
    """Verify Option A (Clear Chat + Markdown Export) and Option B (Workspace Retention)."""

    @staticmethod
    def _sso_headers() -> dict[str, str]:
        return {
            "X-Auth-Request-Email": "operator@example.com",
            "X-Auth-Request-User": "operator",
        }

    def _build_app(self, tmp: str):
        db_path = Path(tmp) / "argo.db"
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
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            workspace_files_root=str(Path(tmp) / "workspace_files"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(settings=settings, guard=guard)

    def test_clear_bot_messages_keep_last_all_and_preserve_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_app(tmp)
            with TestClient(app) as client:
                repo = app.state.repo
                bot = repo.create_bot(
                    name="Ops Helper",
                    role="Infrastructure monitor",
                    runtime="api",
                    outbound_rbac="draft",
                    routines=[
                        {
                            "id": "rtn_keep",
                            "label": "Nightly Check",
                            "schedule": "Every day at 21:00",
                            "enabled": True,
                        }
                    ],
                )
                bot_slug = bot["slug"]
                initial_welcome_count = len(repo.list_bot_messages(bot_slug))
                data_col = repo.ensure_bot_data_collection(bot_slug)
                repo.upsert_document(
                    collection=data_col,
                    external_key="item-1",
                    search_text="keep data item",
                    doc={"title": "Keep Data Item"},
                )
                repo.upsert_skill(
                    name="Disk Triage",
                    instructions="Check df -h first",
                    scope_slug=bot_slug,
                )
                repo.add_style_rule(rule_text="Keep summaries bulleted.", scope_slug=bot_slug)
                repo.create_approval(
                    correlation_id="corr_1",
                    bot_slug=bot_slug,
                    target_account_slug="tg-ops",
                    action_type="send_message",
                    payload={"text": "hello"},
                )
                page = repo.create_page(
                    title="Ops Overview",
                    owner_bot_slug=bot_slug,
                    render_mode="declarative_json",
                )
                repo.save_workspace_file(
                    owner_email="operator@example.com",
                    filename="notes.txt",
                    mime_type="text/plain",
                    content_bytes=b"important runbook",
                )
                repo.upsert_ssh_audit_turn(
                    {
                        "session_id": "sess_keep_1",
                        "turn_seq": 1,
                        "bot_slug": bot_slug,
                        "host": "10.0.0.10",
                        "command": "uname -a",
                        "screen_excerpt": "Linux node1",
                    }
                )
                repo.mark_thread_read(
                    user_email="operator@example.com",
                    target_type="bot",
                    slug=bot_slug,
                )

                for i in range(1, 6):
                    repo.append_bot_message(
                        bot_slug,
                        "user" if i % 2 else "bot",
                        f"Message #{i}",
                    )

                # Partial keep_last=2 removes older messages, keeps last 2 in chronological order.
                resp_keep = client.delete(
                    f"/api/bots/{bot_slug}/messages?keep_last=2",
                    headers=self._sso_headers(),
                )
                self.assertEqual(resp_keep.status_code, 200)
                body_keep = resp_keep.json()
                self.assertEqual(body_keep["deleted_count"], initial_welcome_count + 3)
                self.assertEqual(body_keep["remaining_count"], 2)
                self.assertEqual([m["text"] for m in body_keep["messages"]], ["Message #4", "Message #5"])

                # Clear all removes remaining 2 and clears thread_read_cursors, preserving everything else.
                resp_all = client.delete(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso_headers(),
                )
                self.assertEqual(resp_all.status_code, 200)
                body_all = resp_all.json()
                self.assertEqual(body_all["deleted_count"], 2)
                self.assertEqual(body_all["remaining_count"], 0)
                self.assertEqual(body_all["messages"], [])

                # Verify read cursor was cleaned up for empty thread.
                cursors = repo._list_read_cursors_for_user("operator@example.com")
                self.assertNotIn(("bot", bot_slug), cursors)

                # Verify all non-transcript state is intact.
                reloaded_bot = repo.get_bot(bot_slug)
                self.assertEqual(len(reloaded_bot["routines"]), 1)
                self.assertEqual(len(repo.list_skills(bot_slug)), 1)
                self.assertEqual(len(repo.list_style_rules()), 1)
                self.assertEqual(len(repo.list_approvals(tab="pending")), 1)
                self.assertEqual(repo.get_page(page["slug"])["slug"], page["slug"])
                self.assertEqual(len(repo.list_workspace_files(owner_email="operator@example.com")), 1)
                self.assertTrue(repo.document_exists(data_col, "item-1"))
                self.assertEqual(repo.get_ssh_audit_settings()["total_recordings"], 1)

                # Unknown bot -> 404.
                resp_missing = client.delete(
                    "/api/bots/no-such-bot/messages",
                    headers=self._sso_headers(),
                )
                self.assertEqual(resp_missing.status_code, 404)

    def test_clear_bot_messages_older_than_days_and_active_run_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_app(tmp)
            with TestClient(app) as client:
                repo = app.state.repo
                bot_runner = app.state.bot_runner
                bot = repo.create_bot(name="Busy Bot", role="Worker")
                bot_slug = bot["slug"]
                initial_welcome_count = len(repo.list_bot_messages(bot_slug))

                m_old = repo.append_bot_message(bot_slug, "user", "Old question")
                m_new = repo.append_bot_message(bot_slug, "bot", "Fresh answer")
                old_ts = (
                    (datetime.now(UTC) - timedelta(days=15))
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                with repo._lock:
                    repo._conn.execute(
                        "UPDATE collection_documents SET created_at = ? WHERE id = ?",
                        (old_ts, m_old["id"]),
                    )
                    repo._conn.commit()

                # Active run guard returns 409 Conflict.
                bot_runner._active_runs[bot_slug] = {
                    "step": "Running tool",
                    "started_at": "2026-11-20T00:00:00Z",
                    "correlation_id": "c1",
                }
                try:
                    conflict = client.delete(
                        f"/api/bots/{bot_slug}/messages",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(conflict.status_code, 409)
                finally:
                    bot_runner._active_runs.pop(bot_slug, None)

                # Delete messages older than 7 days -> removes old, keeps fresh (+ welcome message).
                res = client.delete(
                    f"/api/bots/{bot_slug}/messages?older_than_days=7",
                    headers=self._sso_headers(),
                )
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertEqual(data["deleted_count"], 1)
                self.assertEqual(data["remaining_count"], initial_welcome_count + 1)
                self.assertEqual(data["messages"][-1]["id"], m_new["id"])

    def test_room_clear_active_guard_and_markdown_export_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_app(tmp)
            with TestClient(app) as client:
                repo = app.state.repo
                bot_runner = app.state.bot_runner
                bot = repo.create_bot(name="Analyst", role="Analyzes logs")
                bot2 = repo.create_bot(name="Reviewer", role="Reviews findings")
                room = repo.create_room(
                    title="Ops War Room",
                    member_bot_slugs=[bot["slug"], bot2["slug"]],
                    coordinator_bot_slug=bot["slug"],
                )
                room_slug = room["slug"]
                initial_room_msgs = len(repo.list_room_messages(room_slug, limit=None))

                # Store a vault secret that must be redacted on transcript export.
                secret_val = "SuperSecretToken_987654321"
                vault_res = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Deploy Token",
                        "secret_type": "api_token",
                        "secrets": {"token": secret_val},
                        "allowed_bots": [bot["slug"]],
                    },
                )
                self.assertIn(vault_res.status_code, (200, 201))

                # Write > 45 messages to both bot and room to confirm full export goes beyond 40-msg window.
                for idx in range(1, 46):
                    repo.append_bot_message(
                        bot["slug"],
                        "user" if idx % 2 else "bot",
                        f"Bot turn {idx} {secret_val if idx == 3 else ''}".strip(),
                    )
                    repo.append_room_message(
                        room_slug,
                        sender_type="user" if idx % 2 else "bot",
                        sender_slug="operator" if idx % 2 else bot["slug"],
                        sender_name="Operator" if idx % 2 else bot["name"],
                        text=f"Room turn {idx} {secret_val if idx == 2 else ''}".strip(),
                    )

                bot_export = client.get(
                    f"/api/bots/{bot['slug']}/messages/export",
                    headers=self._sso_headers(),
                )
                self.assertEqual(bot_export.status_code, 200)
                self.assertIn("text/markdown", bot_export.headers.get("content-type", ""))
                self.assertIn(f'filename="{bot["slug"]}-chat.md"', bot_export.headers.get("content-disposition", ""))
                self.assertIn("Bot turn 1", bot_export.text)
                self.assertIn("Bot turn 45", bot_export.text)
                self.assertNotIn(secret_val, bot_export.text)

                room_export = client.get(
                    f"/api/rooms/{room_slug}/messages/export",
                    headers=self._sso_headers(),
                )
                self.assertEqual(room_export.status_code, 200)
                self.assertIn(f'filename="{room_slug}-room-chat.md"', room_export.headers.get("content-disposition", ""))
                self.assertIn("Room turn 1", room_export.text)
                self.assertIn("Room turn 45", room_export.text)
                self.assertNotIn(secret_val, room_export.text)

                # Room active run conflict via queue.
                queue = bot_runner._thread_queues.setdefault(f"room:{room_slug}", asyncio.Queue())
                queue.put_nowait(object())
                try:
                    conflict = client.delete(
                        f"/api/rooms/{room_slug}/messages",
                        headers=self._sso_headers(),
                    )
                    self.assertEqual(conflict.status_code, 409)
                finally:
                    queue.get_nowait()

                # Room keep_last=2 then clear all.
                res_keep = client.delete(
                    f"/api/rooms/{room_slug}/messages?keep_last=2",
                    headers=self._sso_headers(),
                )
                self.assertEqual(res_keep.status_code, 200)
                self.assertEqual(res_keep.json()["deleted_count"], initial_room_msgs + 43)
                self.assertEqual(res_keep.json()["remaining_count"], 2)

                res_clear = client.delete(
                    f"/api/rooms/{room_slug}/messages",
                    headers=self._sso_headers(),
                )
                self.assertEqual(res_clear.status_code, 200)
                self.assertEqual(res_clear.json()["deleted_count"], 2)
                self.assertEqual(res_clear.json()["remaining_count"], 0)
                # Room and member bots still exist.
                self.assertEqual(repo.get_room(room_slug)["slug"], room_slug)
                self.assertEqual(repo.get_bot(bot["slug"])["slug"], bot["slug"])

    def test_workspace_chat_retention_settings_hidden_and_prune_now(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_app(tmp)
            with TestClient(app) as client:
                repo = app.state.repo
                bot = repo.create_bot(name="Writer", role="Drafts updates")
                bot2 = repo.create_bot(name="Editor", role="Edits drafts")
                room = repo.create_room(
                    title="Editorial Room",
                    member_bot_slugs=[bot["slug"], bot2["slug"]],
                    coordinator_bot_slug=bot["slug"],
                )
                repo.add_style_rule(rule_text="Use crisp active voice.", scope_slug="*")
                repo.upsert_skill(name="Outline", instructions="Start with 3 bullets", scope_slug="*")

                baseline_bot_total = repo.get_chat_retention_settings()["bot_messages_count"]
                baseline_room_total = repo.get_chat_retention_settings()["room_messages_count"]

                old_bot_msg = repo.append_bot_message(bot["slug"], "user", "Ancient bot prompt")
                new_bot_msg = repo.append_bot_message(bot["slug"], "bot", "Recent bot reply")
                old_room_msg = repo.append_room_message(
                    room["slug"],
                    sender_type="user",
                    sender_slug="operator",
                    sender_name="Operator",
                    text="Ancient room prompt",
                )
                new_room_msg = repo.append_room_message(
                    room["slug"],
                    sender_type="bot",
                    sender_slug=bot["slug"],
                    sender_name=bot["name"],
                    text="Recent room reply",
                )

                old_ts = (
                    (datetime.now(UTC) - timedelta(days=45))
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                with repo._lock:
                    repo._conn.execute(
                        "UPDATE collection_documents SET created_at = ? WHERE id IN (?, ?)",
                        (old_ts, old_bot_msg["id"], old_room_msg["id"]),
                    )
                    repo._conn.commit()

                # Default retention is 0 (Keep forever).
                get_res = client.get("/api/settings/chat-retention", headers=self._sso_headers())
                self.assertEqual(get_res.status_code, 200)
                self.assertEqual(get_res.json()["retention_days"], 0)
                self.assertEqual(get_res.json()["bot_messages_count"], baseline_bot_total + 2)
                self.assertEqual(get_res.json()["room_messages_count"], baseline_room_total + 2)

                # With retention_days=0, prune_expired_chat_messages is a strict no-op.
                noop = repo.prune_expired_chat_messages()
                self.assertEqual(noop["pruned_total"], 0)

                # Configure 30-day retention with immediate prune_now=True.
                patch_res = client.patch(
                    "/api/settings/chat-retention",
                    headers=self._sso_headers(),
                    json={"retention_days": 30, "prune_now": True},
                )
                self.assertEqual(patch_res.status_code, 200)
                pdata = patch_res.json()
                self.assertEqual(pdata["retention_days"], 30)
                self.assertEqual(pdata["pruned_bot_messages"], 1)
                self.assertEqual(pdata["pruned_room_messages"], 1)
                self.assertEqual(pdata["pruned_total"], 2)
                self.assertEqual(pdata["bot_messages_count"], baseline_bot_total + 1)
                self.assertEqual(pdata["room_messages_count"], baseline_room_total + 1)

                # Verify recent messages survived and old ones were deleted.
                bot_msg_ids = [m["id"] for m in repo.list_bot_messages(bot["slug"])]
                self.assertNotIn(old_bot_msg["id"], bot_msg_ids)
                self.assertIn(new_bot_msg["id"], bot_msg_ids)
                room_msg_ids = [m["id"] for m in repo.list_room_messages(room["slug"], limit=None)]
                self.assertNotIn(old_room_msg["id"], room_msg_ids)
                self.assertIn(new_room_msg["id"], room_msg_ids)

                # Verify chat_settings is flagged internal and excluded from visible Data Lists.
                cols_res = client.get("/api/collections", headers=self._sso_headers())
                self.assertEqual(cols_res.status_code, 200)
                visible_col_slugs = {
                    c["slug"] for c in cols_res.json() if not c.get("is_internal")
                }
                self.assertNotIn("chat_settings", visible_col_slugs)

                # Non-transcript artifacts remain completely untouched.
                self.assertEqual(len(repo.list_style_rules()), 1)
                self.assertEqual(len(repo.list_skills("*")), 1)
