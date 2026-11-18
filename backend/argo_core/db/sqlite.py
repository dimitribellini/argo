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
    conn.commit()
    return conn
