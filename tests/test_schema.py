"""Verification tests for Argo's domain-agnostic SQLite WAL + FTS5 schema substrate."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from argo_core.db import init_db


class TestArgoSchema(unittest.TestCase):
    """Verify core schema creation, WAL mode, FTS5 sync triggers, and CHECK constraints."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "argo_test.db"
        self.conn = init_db(self.db_path)

    def tearDown(self) -> None:
        self.conn.close()
        self._tmpdir.cleanup()

    def test_wal_and_core_tables_created(self) -> None:
        journal_mode = self.conn.execute("PRAGMA journal_mode").fetchone()[0]
        foreign_keys = self.conn.execute("PRAGMA foreign_keys").fetchone()[0]
        self.assertEqual(str(journal_mode).lower(), "wal")
        self.assertEqual(foreign_keys, 1)

        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
        table_names = {row["name"] for row in rows}

        expected_tables = {
            "oauth_accounts",
            "model_providers",
            "bots",
            "bot_runs",
            "events_log",
            "collections",
            "collection_documents",
            "collection_documents_fts",
            "approvals_outbox",
            "style_memory",
            "pages",
        }
        self.assertTrue(expected_tables.issubset(table_names))

        forbidden_vertical_tables = {
            "clients",
            "contracts",
            "assessments",
            "meetings",
            "tickets",
        }
        self.assertTrue(forbidden_vertical_tables.isdisjoint(table_names))

    def test_fts5_triggers_and_deduplication(self) -> None:
        now = "2026-11-14T00:00:00Z"
        self.conn.execute(
            """
            INSERT INTO collection_documents(
                id, collection, external_key, search_text, doc_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "doc_1",
                "news_items",
                "https://example.com/zabbix-7-4",
                "Zabbix 7.4 async poller upgrades",
                '{"title": "Zabbix 7.4 async poller upgrades"}',
                now,
                now,
            ),
        )
        self.conn.commit()

        hits = self.conn.execute(
            """
            SELECT id, collection, search_text
            FROM collection_documents_fts
            WHERE collection_documents_fts MATCH 'zabbix'
            """
        ).fetchall()
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["id"], "doc_1")
        self.assertEqual(hits[0]["collection"], "news_items")

        self.conn.execute(
            "UPDATE collection_documents SET search_text = ?, updated_at = ? WHERE id = ?",
            ("Fedora 45 Selkies desktop isolation", "2026-11-14T00:05:00Z", "doc_1"),
        )
        self.conn.commit()

        old_hits = self.conn.execute(
            "SELECT id FROM collection_documents_fts WHERE collection_documents_fts MATCH 'zabbix'"
        ).fetchall()
        new_hits = self.conn.execute(
            "SELECT id FROM collection_documents_fts WHERE collection_documents_fts MATCH 'selkies'"
        ).fetchall()
        self.assertEqual(old_hits, [])
        self.assertEqual([row["id"] for row in new_hits], ["doc_1"])

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """
                INSERT INTO collection_documents(
                    id, collection, external_key, search_text, doc_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "doc_dup",
                    "news_items",
                    "https://example.com/zabbix-7-4",
                    "Duplicate external key",
                    "{}",
                    now,
                    now,
                ),
            )

        self.conn.execute("DELETE FROM collection_documents WHERE id = ?", ("doc_1",))
        self.conn.commit()
        after_delete = self.conn.execute(
            "SELECT id FROM collection_documents_fts WHERE collection_documents_fts MATCH 'selkies'"
        ).fetchall()
        self.assertEqual(after_delete, [])

    def test_approvals_and_pages_check_constraints(self) -> None:
        now = "2026-11-14T00:00:00Z"
        for idx, status in enumerate(
            ("pending", "approved", "executed", "rejected", "superseded")
        ):
            self.conn.execute(
                """
                INSERT INTO approvals_outbox(
                    id, correlation_id, bot_slug, target_account_slug,
                    action_type, status, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"apr_{idx}",
                    "corr_1",
                    "release-gatekeeper",
                    "tg_community",
                    "publish_telegram",
                    status,
                    '{"text": "Release brief"}',
                    now,
                ),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """
                INSERT INTO approvals_outbox(
                    id, correlation_id, bot_slug, target_account_slug,
                    action_type, status, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "apr_bad",
                    "corr_1",
                    "release-gatekeeper",
                    "tg_community",
                    "publish_telegram",
                    "invalid_status",
                    "{}",
                    now,
                ),
            )

        for idx, render_mode in enumerate(("declarative_json", "sandboxed_html")):
            self.conn.execute(
                """
                INSERT INTO pages(
                    id, slug, title, render_mode, content_payload,
                    allowed_collections_json, owner_bot_slug, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"page_{idx}",
                    f"view-{idx}",
                    f"View {idx}",
                    render_mode,
                    "{}",
                    '["news_items"]',
                    "operations-coordinator",
                    now,
                ),
            )

        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """
                INSERT INTO pages(
                    id, slug, title, render_mode, content_payload,
                    allowed_collections_json, owner_bot_slug, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "page_bad",
                    "view-bad",
                    "Invalid View",
                    "dynamic_jsx",
                    "{}",
                    "[]",
                    "operations-coordinator",
                    now,
                ),
            )

    def test_wheel_packages_schema_sql_data_file(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        expected_sql = (repo_root / "backend" / "argo_core" / "db" / "schema.sql").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-deps",
                    "--no-build-isolation",
                    "-w",
                    tmpdir,
                    str(repo_root),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            wheels = list(Path(tmpdir).glob("argo_core-*.whl"))
            self.assertEqual(len(wheels), 1)
            with zipfile.ZipFile(wheels[0]) as zf:
                self.assertIn("argo_core/db/schema.sql", zf.namelist())
                packaged_sql = zf.read("argo_core/db/schema.sql").decode("utf-8")
                self.assertEqual(packaged_sql, expected_sql)


if __name__ == "__main__":
    unittest.main()
