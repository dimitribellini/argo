"""SQLite WAL + FTS5 connection and schema initialization helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect_db(db_path: str | Path) -> sqlite3.Connection:
    """Open a thread-safe SQLite connection configured with WAL mode and foreign key enforcement."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Ensure parent directories exist, initialize the core schema, and return a connection."""
    target = Path(db_path)
    if str(db_path) != ":memory:":
        target.parent.mkdir(parents=True, exist_ok=True)
    conn = connect_db(db_path)
    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema_sql)
    # Safe additive migrations for existing databases
    existing_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(model_providers)").fetchall()
    }
    if "input_price_per_million" not in existing_cols:
        conn.execute("ALTER TABLE model_providers ADD COLUMN input_price_per_million REAL")
    if "output_price_per_million" not in existing_cols:
        conn.execute("ALTER TABLE model_providers ADD COLUMN output_price_per_million REAL")
    oauth_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(oauth_accounts)").fetchall()
    }
    if "owner_email" not in oauth_cols:
        conn.execute("ALTER TABLE oauth_accounts ADD COLUMN owner_email TEXT NOT NULL DEFAULT ''")
    if "visibility" not in oauth_cols:
        conn.execute("ALTER TABLE oauth_accounts ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'")
    if "allowed_groups_json" not in oauth_cols:
        conn.execute("ALTER TABLE oauth_accounts ADD COLUMN allowed_groups_json TEXT NOT NULL DEFAULT '[]'")

    bot_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(bots)").fetchall()
    }
    if "owner_email" not in bot_cols:
        conn.execute("ALTER TABLE bots ADD COLUMN owner_email TEXT NOT NULL DEFAULT ''")
    if "visibility" not in bot_cols:
        conn.execute("ALTER TABLE bots ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'")
    if "allowed_groups_json" not in bot_cols:
        conn.execute("ALTER TABLE bots ADD COLUMN allowed_groups_json TEXT NOT NULL DEFAULT '[]'")

    run_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(bot_runs)").fetchall()
    }
    if "triggered_by_email" not in run_cols:
        conn.execute("ALTER TABLE bot_runs ADD COLUMN triggered_by_email TEXT NOT NULL DEFAULT ''")

    page_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(pages)").fetchall()
    }
    if "created_by_email" not in page_cols:
        conn.execute("ALTER TABLE pages ADD COLUMN created_by_email TEXT NOT NULL DEFAULT ''")
    if "visibility" not in page_cols:
        conn.execute("ALTER TABLE pages ADD COLUMN visibility TEXT NOT NULL DEFAULT 'shared'")
    if "allowed_groups_json" not in page_cols:
        conn.execute("ALTER TABLE pages ADD COLUMN allowed_groups_json TEXT NOT NULL DEFAULT '[]'")
    conn.commit()
    return conn
