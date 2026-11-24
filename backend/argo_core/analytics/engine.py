"""Embedded DuckDB 2.0 analytics, PDF/Excel/DOCX ingestion, SUMMARIZE profiler, and query sandbox."""

from __future__ import annotations

import csv
import datetime as dt
import decimal
import importlib
import importlib.util
import io
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import pdfplumber
import pypdfium2
import python_calamine
from docx import Document as DocxDocument

from argo_core.security.vault import redact_secrets

MAX_WORKSPACE_FILE_BYTES = 10 * 1024 * 1024
MAX_ANALYTICS_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_IN_MEMORY_PARQUET_LOAD_BYTES = 64 * 1024 * 1024

_SQLITE_MAGIC = b"SQLite format 3\x00"
_PARQUET_MAGIC = b"PAR1"
_REQUIRED_X86_DUCKDB_FLAGS = frozenset(
    {"avx", "avx2", "bmi1", "bmi2", "fma", "popcnt", "sse4_1", "sse4_2"}
)
_DUCKDB_RUNTIME_CACHE: dict[bool, bool] = {}


def _is_duckdb_disabled_by_env() -> bool:
    return os.environ.get("ARGO_DISABLE_DUCKDB", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _has_duckdb_cpu_flags() -> bool:
    """Return False immediately on Linux x86_64 CPUs lacking AVX2/BMI2 flags required by DuckDB."""
    arch = platform.machine().lower()
    if arch not in {"x86_64", "amd64"}:
        return True
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return True
    try:
        with cpuinfo.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.lower().startswith("flags"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        flags = set(parts[1].strip().split())
                        if not _REQUIRED_X86_DUCKDB_FLAGS.issubset(flags):
                            return False
                        if "abm" not in flags and "lzcnt" not in flags:
                            return False
                        return True
    except OSError:
        return True
    return True


def is_duckdb_runtime_supported() -> bool:
    """Safely check whether DuckDB native code can load and run without SIGILL on this CPU."""
    disabled = _is_duckdb_disabled_by_env()
    if disabled:
        _DUCKDB_RUNTIME_CACHE[True] = False
        return False
    if False in _DUCKDB_RUNTIME_CACHE:
        return _DUCKDB_RUNTIME_CACHE[False]
    if importlib.util.find_spec("duckdb") is None:
        _DUCKDB_RUNTIME_CACHE[False] = False
        return False
    if not _has_duckdb_cpu_flags():
        _DUCKDB_RUNTIME_CACHE[False] = False
        return False
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import duckdb; c = duckdb.connect(':memory:'); assert c.execute('SELECT 42').fetchone()[0] == 42; c.close()",
            ],
            capture_output=True,
            timeout=5,
        )
        ok = proc.returncode == 0
    except Exception:
        ok = False
    _DUCKDB_RUNTIME_CACHE[False] = ok
    return ok


def _get_duckdb() -> Any | None:
    """Import and return the duckdb module only when safe on the current CPU."""
    if not is_duckdb_runtime_supported():
        return None
    return importlib.import_module("duckdb")


def _file_magic(path: Path) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(16)
    except OSError:
        return b""


def _is_sqlite_store_file(path: Path) -> bool:
    return _file_magic(path).startswith(_SQLITE_MAGIC)


def _is_parquet_file(path: Path) -> bool:
    return _file_magic(path)[:4] == _PARQUET_MAGIC

ANALYTICS_DOCUMENT_EXTENSIONS = frozenset(
    {
        ".csv",
        ".tsv",
        ".parquet",
        ".json",
        ".ndjson",
        ".jsonl",
        ".xlsx",
        ".xlsm",
        ".xlsb",
        ".xls",
        ".ods",
        ".pdf",
        ".docx",
    }
)

ANALYTICS_DOCUMENT_MIMES = frozenset(
    {
        "text/csv",
        "text/tab-separated-values",
        "application/csv",
        "application/parquet",
        "application/vnd.apache.parquet",
        "application/x-parquet",
        "application/json",
        "application/x-ndjson",
        "application/ndjson",
        "application/jsonl",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.sheet.binary.macroenabled.12",
        "application/vnd.ms-excel",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)

_FILE_DATASET_RE = re.compile(r"^file:file_[a-z0-9]+(?::[a-z0-9_]+)?$")

_FORBIDDEN_SANDBOX_IDENTIFIERS = frozenset(
    {
        "pragma",
        "attach",
        "detach",
        "load_extension",
        "vault_secrets",
        "oauth_accounts",
        "integrations",
        "model_providers",
        "bot_threads",
        "room_threads",
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
    }
)

_FORBIDDEN_DML_DDL_KEYWORDS = frozenset(
    {
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "truncate",
        "copy",
        "install",
        "load",
        "export_database",
        "import_database",
        "vacuum",
        "merge",
        "call",
        "set",
        "reset",
    }
)

_FORBIDDEN_DUCKDB_FUNCTIONS = frozenset(
    {
        "read_csv",
        "read_csv_auto",
        "read_json",
        "read_json_auto",
        "read_ndjson",
        "read_ndjson_auto",
        "read_parquet",
        "read_text",
        "read_blob",
        "parquet_scan",
        "parquet_metadata",
        "parquet_schema",
        "parquet_kv_metadata",
        "csv_scan",
        "json_scan",
        "glob",
        "export_database",
        "import_database",
        "httpfs",
        "sqlite_scan",
        "sqlite_attach",
        "postgres_scan",
        "mysql_scan",
        "iceberg_scan",
        "delta_scan",
        "sniff_csv",
        "current_setting",
        "getenv",
    }
)


def _collection_slug_norm(text: str) -> str:
    slug = re.sub(r"[^a-z0-9_]+", "-", text.strip().lower()).strip("-_")
    return slug or "collection"


def dataset_identifier(raw: str) -> str:
    """Preserve file:<id>[:<sub>] dataset bindings while normalizing regular collection slugs."""
    candidate = str(raw or "").strip().lower()
    if _FILE_DATASET_RE.fullmatch(candidate):
        return candidate
    return _collection_slug_norm(str(raw or ""))


def is_analytics_or_document_file(filename: str, mime_type: str = "") -> bool:
    """Return True when filename or mime_type corresponds to a structured/document format."""
    ext = Path(str(filename or "")).suffix.lower()
    clean_mime = str(mime_type or "").split(";", 1)[0].strip().lower()
    return ext in ANALYTICS_DOCUMENT_EXTENSIONS or clean_mime in ANALYTICS_DOCUMENT_MIMES


def max_workspace_file_bytes_for_name(filename: str, mime_type: str = "") -> int:
    """Return 100 MB cap for analytical/document files and 10 MB cap for generic workspace files."""
    if is_analytics_or_document_file(filename, mime_type):
        return MAX_ANALYTICS_UPLOAD_BYTES
    return MAX_WORKSPACE_FILE_BYTES


def _sanitize_sql_ident(name: str, fallback: str = "col") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", str(name or "").strip()).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"c_{cleaned}"
    return cleaned[:80]


def _quote_ident(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _json_safe(value: Any, secret_values: list[str] | None = None) -> Any:
    """Convert DuckDB / Python values into JSON-serializable, secret-scrubbed primitives."""
    secrets = secret_values or []
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return value
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw_b = bytes(value)
        try:
            text = raw_b.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw_b)
        return redact_secrets(text, secrets) if secrets else text
    if isinstance(value, str):
        return redact_secrets(value, secrets) if secrets else value
    if isinstance(value, dict):
        return {
            (redact_secrets(str(k), secrets) if secrets else str(k)): _json_safe(v, secrets)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item, secrets) for item in value]
    rendered = str(value)
    return redact_secrets(rendered, secrets) if secrets else rendered


def validate_readonly_sandbox_sql(
    sql: str,
    *,
    block_duckdb_external_funcs: bool = False,
) -> str:
    """Validate that SQL is a single read-only SELECT/WITH query free of unsafe keywords/functions."""
    raw = str(sql or "").strip()
    if not raw:
        raise ValueError("SQL query cannot be empty.")

    tokens: list[tuple[str, bool, bool, bool]] = []  # (token_lower, is_single_quoted_literal, is_quoted_ident, is_call)
    semicolon_positions: list[int] = []
    n = len(raw)
    i = 0

    def _next_non_ws_is_lparen(pos: int) -> bool:
        j = pos
        while j < n:
            c = raw[j]
            if c.isspace():
                j += 1
                continue
            if c == "-" and j + 1 < n and raw[j + 1] == "-":
                nl_pos = raw.find("\n", j + 2)
                j = n if nl_pos == -1 else nl_pos + 1
                continue
            if c == "/" and j + 1 < n and raw[j + 1] == "*":
                end_pos = raw.find("*/", j + 2)
                if end_pos == -1:
                    return False
                j = end_pos + 2
                continue
            return c == "("
        return False

    while i < n:
        ch = raw[i]
        # Line comment --
        if ch == "-" and i + 1 < n and raw[i + 1] == "-":
            nl = raw.find("\n", i + 2)
            i = n if nl == -1 else nl + 1
            continue
        # Block comment /* ... */
        if ch == "/" and i + 1 < n and raw[i + 1] == "*":
            end = raw.find("*/", i + 2)
            if end == -1:
                raise ValueError("Unterminated SQL block comment.")
            i = end + 2
            continue
        # Reject DuckDB dollar-quoted strings ($$...$$ or $tag$...$tag$)
        if ch == "$":
            m_dollar = re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$", raw[i:])
            if m_dollar:
                raise PermissionError("Dollar-quoted SQL strings are disallowed in the SQL sandbox.")
        # Single-quoted string literal
        if ch == "'":
            i += 1
            while i < n:
                if raw[i] == "'":
                    if i + 1 < n and raw[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            else:
                raise ValueError("Unterminated SQL string literal.")
            tokens.append(("'str'", True, False, False))
            continue
        # Quoted identifiers ("...", `...`, [...])
        if ch in {'"', "`", "["}:
            close_ch = "]" if ch == "[" else ch
            start = i + 1
            i += 1
            while i < n:
                if raw[i] == close_ch:
                    if close_ch != "]" and i + 1 < n and raw[i + 1] == close_ch:
                        i += 2
                        continue
                    ident = raw[start:i].strip().lower()
                    i += 1
                    if ident:
                        tokens.append((ident, False, True, _next_non_ws_is_lparen(i)))
                    break
                i += 1
            else:
                raise ValueError("Unterminated SQL identifier.")
            continue
        if ch == ";":
            semicolon_positions.append(i)
            i += 1
            continue
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < n and (raw[i].isalnum() or raw[i] == "_"):
                i += 1
            tokens.append((raw[start:i].lower(), False, False, _next_non_ws_is_lparen(i)))
            continue
        i += 1

    if len(semicolon_positions) > 1:
        raise ValueError("Multiple semicolon-separated SQL statements are not allowed.")
    if len(semicolon_positions) == 1:
        semi_idx = semicolon_positions[0]
        trailing = raw[semi_idx + 1 :]
        t_pos = 0
        t_len = len(trailing)
        while t_pos < t_len:
            ch = trailing[t_pos]
            if ch.isspace():
                t_pos += 1
                continue
            if ch == "-" and t_pos + 1 < t_len and trailing[t_pos + 1] == "-":
                nl = trailing.find("\n", t_pos + 2)
                t_pos = t_len if nl == -1 else nl + 1
                continue
            if ch == "/" and t_pos + 1 < t_len and trailing[t_pos + 1] == "*":
                end = trailing.find("*/", t_pos + 2)
                if end == -1:
                    raise ValueError("Unterminated SQL block comment.")
                t_pos = end + 2
                continue
            raise ValueError("Multiple semicolon-separated SQL statements are not allowed.")
        cleaned = raw[:semi_idx].strip()
    else:
        cleaned = raw

    if not cleaned or not tokens:
        raise ValueError("SQL query cannot be empty.")

    first_tok, first_is_str, _, _ = tokens[0]
    if first_is_str or first_tok not in {"select", "with"}:
        raise PermissionError(
            "Only read-only SELECT or WITH queries are permitted in the SQL sandbox."
        )

    for idx, (tok, is_str, is_quoted, is_call) in enumerate(tokens):
        if is_str:
            continue
        if tok in _FORBIDDEN_SANDBOX_IDENTIFIERS:
            raise PermissionError(
                f"SQL sandbox blocked forbidden keyword or table reference '{tok}'."
            )
        if not is_quoted and tok in _FORBIDDEN_DML_DDL_KEYWORDS:
            raise PermissionError(
                f"SQL sandbox blocked write or administrative keyword '{tok}'."
            )
        if not is_quoted and tok == "replace" and idx + 1 < len(tokens) and tokens[idx + 1][0] == "into":
            raise PermissionError("SQL sandbox blocked write keyword 'replace into'.")
        if block_duckdb_external_funcs:
            if not is_quoted and tok in {"from", "join"} and idx + 1 < len(tokens) and tokens[idx + 1][1]:
                raise PermissionError(
                    "DuckDB sandbox blocked direct string-literal replacement scan."
                )
            if (
                tok.startswith("duckdb_")
                or tok.startswith("pragma_")
                or tok.startswith("read_")
                or tok.endswith("_scan")
                or (
                    tok in _FORBIDDEN_DUCKDB_FUNCTIONS
                    and (not is_quoted or is_call or tok != "glob")
                )
            ):
                raise PermissionError(
                    f"DuckDB sandbox blocked restricted system or external-access function '{tok}'."
                )

    return cleaned


def _deduplicate_headers(raw_headers: list[Any], col_count: int) -> list[str]:
    seen: dict[str, int] = {}
    out: list[str] = []
    for idx in range(col_count):
        raw = raw_headers[idx] if idx < len(raw_headers) else None
        base = _sanitize_sql_ident(str(raw or "").strip(), fallback=f"col_{idx + 1}")
        cnt = seen.get(base, 0) + 1
        seen[base] = cnt
        out.append(base if cnt == 1 else f"{base}_{cnt}")
    return out


def _normalize_cell_value(val: Any) -> Any:
    if val is None or isinstance(val, (bool, int, float, str)):
        if isinstance(val, float) and (val != val or val in (float("inf"), float("-inf"))):
            return None
        return val
    if isinstance(val, decimal.Decimal):
        return float(val)
    if isinstance(val, (dt.datetime, dt.date, dt.time)):
        return val.isoformat()
    if isinstance(val, (dict, list)):
        return json.dumps(val, ensure_ascii=False)
    return str(val)


def _rows_from_matrix(matrix: list[list[Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    """Promote first non-empty matrix row to deduplicated headers and return row dicts."""
    cleaned_rows = [
        [_normalize_cell_value(c) for c in row]
        for row in matrix
        if isinstance(row, (list, tuple)) and any(c is not None and str(c).strip() != "" for c in row)
    ]
    if len(cleaned_rows) < 2:
        return [], []
    col_count = max(len(r) for r in cleaned_rows)
    if col_count < 1:
        return [], []
    headers = _deduplicate_headers(cleaned_rows[0], col_count)
    out_rows: list[dict[str, Any]] = []
    for row in cleaned_rows[1:]:
        row_dict = {
            headers[idx]: (row[idx] if idx < len(row) else None)
            for idx in range(col_count)
        }
        if any(v is not None and str(v).strip() != "" for v in row_dict.values()):
            out_rows.append(row_dict)
    return headers, out_rows


def _lock_readonly_parquet(path: Path) -> None:
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def _coerce_sqlite_cell(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, (int, float, str)):
        if isinstance(val, float) and (val != val or val in (float("inf"), float("-inf"))):
            return None
        return val
    return _normalize_cell_value(val)


def _infer_sqlite_column_types(
    clean_cols: list[str],
    rows: list[dict[str, Any]],
    col_map: list[tuple[str, str]],
) -> dict[str, str]:
    inferred: dict[str, str] = {}
    for orig_k, clean_k in col_map:
        seen_int = False
        seen_float = False
        seen_str = False
        for row in rows:
            val = row.get(orig_k) if isinstance(row, dict) else (row if clean_k == clean_cols[0] else None)
            if val is None:
                continue
            if isinstance(val, bool):
                seen_int = True
            elif isinstance(val, int):
                seen_int = True
            elif isinstance(val, float):
                if val == val and val not in (float("inf"), float("-inf")):
                    seen_float = True
            elif isinstance(val, decimal.Decimal):
                seen_float = True
            else:
                seen_str = True
                break
        if seen_str or (not seen_int and not seen_float):
            inferred[clean_k] = "TEXT"
        elif seen_float:
            inferred[clean_k] = "REAL"
        else:
            inferred[clean_k] = "INTEGER"
    return inferred


def _write_rows_to_sqlite_store(
    rows: list[dict[str, Any]],
    out_path: Path,
    clean_cols: list[str],
    col_map: list[tuple[str, str]],
) -> int:
    col_types = _infer_sqlite_column_types(clean_cols, rows, col_map)
    col_defs = ", ".join(f"{_quote_ident(c)} {col_types.get(c, 'TEXT')}" for c in clean_cols)
    placeholders = ", ".join("?" for _ in clean_cols)
    quoted_cols = ", ".join(_quote_ident(c) for c in clean_cols)
    conn = sqlite3.connect(str(out_path))
    try:
        conn.execute(f"CREATE TABLE data ({col_defs})")
        if rows:
            tuples = [
                tuple(
                    _coerce_sqlite_cell(
                        row.get(orig_k) if isinstance(row, dict) else (row if c_idx == 0 else None)
                    )
                    for c_idx, (orig_k, _) in enumerate(col_map)
                )
                for row in rows
            ]
            conn.executemany(
                f"INSERT INTO data ({quoted_cols}) VALUES ({placeholders})",
                tuples,
            )
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def write_rows_to_parquet(
    rows: list[dict[str, Any]],
    out_parquet: Path,
    *,
    columns: list[str] | None = None,
) -> tuple[int, list[str]]:
    """Materialize Python row dicts into an immutable 0o444 ZSTD Parquet (or SQLite fallback) file."""
    out_parquet.parent.mkdir(parents=True, exist_ok=True)
    if out_parquet.exists():
        try:
            os.chmod(out_parquet, 0o644)
        except OSError:
            pass
        out_parquet.unlink(missing_ok=True)

    ordered_cols = list(columns or [])
    if not ordered_cols:
        seen_cols: list[str] = []
        seen_set: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            for k in row.keys():
                ks = str(k)
                if ks not in seen_set:
                    seen_set.add(ks)
                    seen_cols.append(ks)
        ordered_cols = seen_cols or ["value"]

    clean_cols = _deduplicate_headers(ordered_cols, len(ordered_cols))
    col_map = list(zip(ordered_cols, clean_cols))

    duck = _get_duckdb()
    if duck is None:
        row_count = _write_rows_to_sqlite_store(rows, out_parquet, clean_cols, col_map)
        _lock_readonly_parquet(out_parquet)
        return row_count, clean_cols

    if not rows:
        conn = duck.connect(database=":memory:")
        try:
            col_defs = ", ".join(f"{_quote_ident(c)} VARCHAR" for c in clean_cols)
            conn.execute(f"CREATE TEMP TABLE empty_tbl ({col_defs})")
            conn.execute(
                f"COPY empty_tbl TO {repr(str(out_parquet))} (FORMAT PARQUET, COMPRESSION ZSTD)"
            )
        finally:
            conn.close()
        _lock_readonly_parquet(out_parquet)
        return 0, clean_cols

    with tempfile.TemporaryDirectory() as tmpdir:
        ndjson_path = Path(tmpdir) / "rows.ndjson"
        with ndjson_path.open("w", encoding="utf-8") as fh:
            for row in rows:
                if not isinstance(row, dict):
                    obj = {clean_cols[0]: _normalize_cell_value(row)}
                else:
                    obj = {
                        clean_k: _normalize_cell_value(row.get(orig_k))
                        for orig_k, clean_k in col_map
                    }
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

        conn = duck.connect(database=":memory:")
        try:
            select_cols = ", ".join(_quote_ident(c) for c in clean_cols)
            try:
                conn.execute(
                    f"CREATE TEMP TABLE src AS SELECT {select_cols} FROM read_json_auto(?, sample_size=-1)",
                    [str(ndjson_path)],
                )
            except Exception:
                # Fallback with explicit VARCHAR typing for heterogeneous columns.
                col_spec = ", ".join(f"{repr(c)}: 'VARCHAR'" for c in clean_cols)
                conn.execute(
                    f"CREATE TEMP TABLE src AS SELECT {select_cols} FROM read_json_auto(?, columns={{{col_spec}}})",
                    [str(ndjson_path)],
                )
            conn.execute(
                f"COPY src TO {repr(str(out_parquet))} (FORMAT PARQUET, COMPRESSION ZSTD)"
            )
            row_count = int(conn.execute("SELECT COUNT(*) FROM src").fetchone()[0] or 0)
        finally:
            conn.close()
    _lock_readonly_parquet(out_parquet)
    return row_count, clean_cols


def _duckdb_fetch_tz_safe(
    conn: Any,
    sql: str,
    params: list[Any] | None = None,
    *,
    max_rows: int | None = None,
) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Execute a DuckDB query and fall back to positional VARCHAR casts when pytz is absent."""
    param_list = list(params) if params is not None else []
    rel = conn.execute(sql, param_list)
    desc = list(rel.description or ())
    cols = [str(d[0]) for d in desc]
    try:
        rows = rel.fetchmany(max_rows) if max_rows is not None else rel.fetchall()
        return cols, rows
    except Exception as exc:
        if "pytz" not in str(exc).lower() or not desc:
            raise
        clean_sql = sql.strip().rstrip(";").strip()
        tz_indices = {
            idx
            for idx, col_desc in enumerate(desc, start=1)
            if "TIME ZONE" in str(col_desc[1] or "").upper()
            or "TIMESTAMPTZ" in str(col_desc[1] or "").upper()
        }
        proj_parts = [
            f"CAST(#{idx} AS VARCHAR) AS {_quote_ident(col_name)}"
            if (idx in tz_indices or not tz_indices)
            else f"#{idx} AS {_quote_ident(col_name)}"
            for idx, col_name in enumerate(cols, start=1)
        ]
        wrapped_sql = f"SELECT {', '.join(proj_parts)} FROM ({clean_sql}) AS __argo_tz_safe"
        safe_rel = conn.execute(wrapped_sql, param_list)
        safe_cols = [str(d[0]) for d in (safe_rel.description or ())]
        safe_rows = safe_rel.fetchmany(max_rows) if max_rows is not None else safe_rel.fetchall()
        return safe_cols or cols, safe_rows


def read_dataset_rows(
    parquet_path: Path,
    *,
    limit: int = 2000,
    secret_values: list[str] | None = None,
) -> tuple[list[str], list[dict[str, Any]], int]:
    """Read bounded, secret-scrubbed rows from a Parquet or portable SQLite dataset file."""
    secrets = secret_values or []
    capped = max(1, int(limit))
    resolved_p = str(parquet_path.resolve())
    if _is_sqlite_store_file(parquet_path):
        sconn = sqlite3.connect(f"file:{resolved_p}?mode=ro", uri=True)
        try:
            cur = sconn.execute("SELECT * FROM data LIMIT ?", (capped,))
            cols = [d[0] for d in (cur.description or ())]
            fetched = cur.fetchall()
            total_rows = int(sconn.execute("SELECT COUNT(*) FROM data").fetchone()[0] or 0)
        finally:
            sconn.close()
        rows_out = [
            {c: _json_safe(v, secrets) for c, v in zip(cols, r)}
            for r in fetched
        ]
        return cols, rows_out, total_rows

    duck = _get_duckdb()
    if duck is None:
        raise ValueError(
            "Binary Parquet file requires a host CPU supporting DuckDB x86-64-v3 (AVX2/BMI2)."
        )
    conn = duck.connect(database=":memory:")
    try:
        _configure_sandbox_connection(conn, allowed_paths=[resolved_p])
        cols, fetched = _duckdb_fetch_tz_safe(
            conn, f"SELECT * FROM read_parquet({repr(resolved_p)}) LIMIT {capped}"
        )
        total_rows = int(
            conn.execute(f"SELECT COUNT(*) FROM read_parquet({repr(resolved_p)})").fetchone()[0] or 0
        )
    finally:
        conn.close()
    rows_out = [
        {c: _json_safe(v, secrets) for c, v in zip(cols, r)}
        for r in fetched
    ]
    return cols, rows_out, total_rows


def _format_preview_from_parquet(
    parquet_path: Path,
    *,
    vault_secrets: list[str],
    limit: int = 20,
    header_prefix: str = "",
) -> tuple[int, list[str], str]:
    cols, sample, total_rows = read_dataset_rows(
        parquet_path,
        limit=limit,
        secret_values=vault_secrets,
    )
    lines: list[str] = []
    if header_prefix:
        lines.append(header_prefix)
    if cols:
        lines.append(" | ".join(str(c) for c in cols))
        lines.append(" | ".join("---" for _ in cols))
    for row in sample:
        rendered = " | ".join(
            str(row.get(c) if row.get(c) is not None else "") for c in cols
        )
        lines.append(rendered[:500])
    preview = redact_secrets("\n".join(lines), vault_secrets)[:24_000]
    return total_rows, cols, preview


_INT_CELL_RE = re.compile(r"^-?(?:0|[1-9]\d*)$")
_FLOAT_CELL_RE = re.compile(r"^-?(?:0|[1-9]\d*)(?:\.\d+)$")


def _parse_csv_scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "":
        return None
    if _INT_CELL_RE.fullmatch(s):
        try:
            return int(s)
        except ValueError:
            return s
    if _FLOAT_CELL_RE.fullmatch(s):
        try:
            return float(s)
        except ValueError:
            return s
    return raw


def _ingest_tabular_via_python(
    file_path: Path,
    out_parquet: Path,
    *,
    ext: str,
    mime_type: str,
) -> None:
    if ext == ".parquet" or "parquet" in mime_type:
        if _is_sqlite_store_file(file_path):
            cols, all_rows, _ = read_dataset_rows(file_path, limit=500_000)
            write_rows_to_parquet(all_rows, out_parquet, columns=cols)
            return
        raise ValueError(
            "Binary .parquet upload requires a host CPU supporting DuckDB x86-64-v3 (AVX2/BMI2)."
        )

    if ext in {".csv", ".tsv"} or mime_type in {"text/csv", "text/tab-separated-values", "application/csv"}:
        delim = "\t" if (ext == ".tsv" or mime_type == "text/tab-separated-values") else ","
        with file_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter=delim)
            raw_rows = [row for row in reader if any(cell.strip() != "" for cell in row)]
        if not raw_rows:
            write_rows_to_parquet([], out_parquet, columns=["empty"])
            return
        col_count = max(len(r) for r in raw_rows)
        headers = _deduplicate_headers(raw_rows[0], col_count)
        parsed_rows = [
            {
                headers[idx]: (_parse_csv_scalar(row[idx]) if idx < len(row) else None)
                for idx in range(col_count)
            }
            for row in raw_rows[1:]
        ]
        write_rows_to_parquet(parsed_rows, out_parquet, columns=headers)
        return

    raw_text = file_path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not raw_text:
        write_rows_to_parquet([], out_parquet, columns=["empty"])
        return
    is_ndjson = ext in {".ndjson", ".jsonl"} or "ndjson" in mime_type

    def _parse_ndjson_lines(text: str) -> list[Any]:
        non_empty_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        parsed: list[Any] = []
        last_err: json.JSONDecodeError | None = None
        for idx, clean_line in enumerate(non_empty_lines):
            try:
                parsed.append(json.loads(clean_line))
            except json.JSONDecodeError as exc:
                last_err = exc
                # Tolerate a trailing truncated line if earlier lines already parsed cleanly.
                if parsed and idx == len(non_empty_lines) - 1:
                    break
                raise
        if not parsed and last_err is not None:
            raise last_err
        return parsed

    if is_ndjson:
        try:
            objs = _parse_ndjson_lines(raw_text)
        except json.JSONDecodeError as exc:
            try:
                loaded = json.loads(raw_text)
                objs = loaded if isinstance(loaded, list) else [loaded]
            except json.JSONDecodeError:
                raise ValueError(f"Malformed JSON content in '{file_path.name}': {exc}") from exc
    else:
        try:
            loaded = json.loads(raw_text)
            objs = loaded if isinstance(loaded, list) else [loaded]
        except json.JSONDecodeError as exc:
            try:
                objs = _parse_ndjson_lines(raw_text)
            except json.JSONDecodeError:
                raise ValueError(f"Malformed JSON content in '{file_path.name}': {exc}") from exc
    normalized: list[dict[str, Any]] = [
        (item if isinstance(item, dict) else {"value": item})
        for item in objs
    ]
    write_rows_to_parquet(normalized, out_parquet)


def _ingest_tabular_file(
    file_path: Path,
    derived_dir: Path,
    *,
    file_id: str,
    ext: str,
    mime_type: str,
    vault_secrets: list[str],
) -> dict[str, Any]:
    out_parquet = derived_dir / "main.parquet"
    duck = _get_duckdb()
    if duck is None:
        _ingest_tabular_via_python(file_path, out_parquet, ext=ext, mime_type=mime_type)
    else:
        fallback_to_python = False
        conn = duck.connect(database=":memory:")
        try:
            conn.execute("SET memory_limit='256MB'")
            conn.execute("SET threads=2")
            if ext in {".csv", ".tsv"} or mime_type in {"text/csv", "text/tab-separated-values", "application/csv"}:
                try:
                    conn.execute(
                        "CREATE TEMP TABLE tbl AS SELECT * FROM read_csv_auto(?, sample_size=-1)",
                        [str(file_path)],
                    )
                except Exception:
                    conn.execute(
                        "CREATE TEMP TABLE tbl AS SELECT * FROM read_csv_auto(?, sample_size=-1, ignore_errors=true)",
                        [str(file_path)],
                    )
            elif ext in {".json", ".ndjson", ".jsonl"} or "json" in mime_type:
                try:
                    conn.execute(
                        "CREATE TEMP TABLE tbl AS SELECT * FROM read_json_auto(?, sample_size=-1)",
                        [str(file_path)],
                    )
                except Exception:
                    try:
                        conn.execute(
                            "CREATE TEMP TABLE tbl AS SELECT * FROM read_json_auto(?, sample_size=-1, ignore_errors=true, maximum_object_size=67108864)",
                            [str(file_path)],
                        )
                    except Exception:
                        fallback_to_python = True
            elif ext == ".parquet" or "parquet" in mime_type:
                conn.execute(
                    "CREATE TEMP TABLE tbl AS SELECT * FROM read_parquet(?)",
                    [str(file_path)],
                )
            else:
                raise ValueError(f"Unsupported tabular extension '{ext}'.")

            if not fallback_to_python:
                conn.execute(f"COPY tbl TO {repr(str(out_parquet))} (FORMAT PARQUET, COMPRESSION ZSTD)")
        finally:
            conn.close()
        if fallback_to_python:
            _ingest_tabular_via_python(file_path, out_parquet, ext=ext, mime_type=mime_type)
        else:
            _lock_readonly_parquet(out_parquet)

    row_count, cols, preview = _format_preview_from_parquet(
        out_parquet,
        vault_secrets=vault_secrets,
        limit=20,
    )
    ds_entry = {
        "id": f"file:{file_id}",
        "alias": "main",
        "filename": out_parquet.name,
        "kind": "table",
        "row_count": row_count,
        "columns": cols,
    }
    return {
        "derived_datasets": [ds_entry],
        "default_parquet_name": out_parquet.name,
        "pages_parquet_name": None,
        "page_count": None,
        "scanned_pages": [],
        "extracted_tables": [],
        "text_preview": preview,
    }


def _write_sheet_matrix_streaming(
    matrix: list[list[Any]],
    out_parquet: Path,
) -> tuple[int, list[str]]:
    """Stream spreadsheet matrix rows into bounded 10k-row batches to avoid OOM on large .xlsx workbooks."""
    first_data_idx = -1
    raw_header_row: list[Any] = []
    max_width = 0
    for idx, row in enumerate(matrix):
        if isinstance(row, (list, tuple)) and any(c is not None and str(c).strip() != "" for c in row):
            if first_data_idx == -1:
                first_data_idx = idx
                raw_header_row = [_normalize_cell_value(c) for c in row]
            if len(row) > max_width:
                max_width = len(row)
    if first_data_idx == -1 or max_width < 1:
        return 0, []

    clean_cols = _deduplicate_headers(raw_header_row, max_width)
    duck = _get_duckdb()
    if duck is None:
        _, rows = _rows_from_matrix(matrix)
        if not rows:
            return 0, []
        return write_rows_to_parquet(rows, out_parquet, columns=clean_cols)

    out_parquet.parent.mkdir(parents=True, exist_ok=True)
    if out_parquet.exists():
        try:
            os.chmod(out_parquet, 0o644)
        except OSError:
            pass
        out_parquet.unlink(missing_ok=True)

    batch_size = 10_000
    row_written = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        ndjson_path = Path(tmpdir) / "sheet.ndjson"
        with ndjson_path.open("w", encoding="utf-8") as fh:
            for start in range(first_data_idx + 1, len(matrix), batch_size):
                chunk = matrix[start : start + batch_size]
                for row in chunk:
                    if not isinstance(row, (list, tuple)):
                        continue
                    has_val = False
                    obj: dict[str, Any] = {}
                    for c_idx, clean_k in enumerate(clean_cols):
                        val = _normalize_cell_value(row[c_idx]) if c_idx < len(row) else None
                        if val is not None and str(val).strip() != "":
                            has_val = True
                        obj[clean_k] = val
                    if has_val:
                        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
                        row_written += 1

        if row_written == 0:
            return 0, []

        conn = duck.connect(database=":memory:")
        try:
            conn.execute("SET memory_limit='256MB'")
            conn.execute("SET threads=2")
            select_cols = ", ".join(_quote_ident(c) for c in clean_cols)
            try:
                conn.execute(
                    f"CREATE TEMP TABLE src AS SELECT {select_cols} FROM read_json_auto(?, sample_size=-1)",
                    [str(ndjson_path)],
                )
            except Exception:
                col_spec = ", ".join(f"{repr(c)}: 'VARCHAR'" for c in clean_cols)
                conn.execute(
                    f"CREATE TEMP TABLE src AS SELECT {select_cols} FROM read_json_auto(?, columns={{{col_spec}}})",
                    [str(ndjson_path)],
                )
            conn.execute(
                f"COPY src TO {repr(str(out_parquet))} (FORMAT PARQUET, COMPRESSION ZSTD)"
            )
            final_count = int(conn.execute("SELECT COUNT(*) FROM src").fetchone()[0] or 0)
        finally:
            conn.close()

    _lock_readonly_parquet(out_parquet)
    return final_count, clean_cols


def _ingest_spreadsheet_file(
    file_path: Path,
    derived_dir: Path,
    *,
    file_id: str,
    vault_secrets: list[str],
) -> dict[str, Any]:
    wb = python_calamine.CalamineWorkbook.from_path(str(file_path))
    derived_datasets: list[dict[str, Any]] = []
    preview_sections: list[str] = []
    default_parquet_name: str | None = None

    for idx, sheet_name in enumerate(wb.sheet_names):
        sheet = wb.get_sheet_by_name(sheet_name)
        matrix = sheet.to_python()
        sheet_slug = re.sub(r"[^a-z0-9]+", "_", str(sheet_name).strip().lower()).strip("_") or f"sheet_{idx + 1}"
        if not sheet_slug.startswith("sheet_"):
            sub_id = f"sheet_{sheet_slug}"
        else:
            sub_id = sheet_slug
        # Ensure unique sub_id across sheets
        existing_ids = {d["alias"] for d in derived_datasets}
        if sub_id in existing_ids:
            sub_id = f"{sub_id}_{idx + 1}"
        out_parquet = derived_dir / f"{sub_id}.parquet"
        row_count, clean_cols = _write_sheet_matrix_streaming(matrix, out_parquet)
        del matrix
        if row_count == 0 or not clean_cols:
            continue
        if default_parquet_name is None:
            default_parquet_name = out_parquet.name
        ds_id = f"file:{file_id}:{sub_id}"
        derived_datasets.append(
            {
                "id": ds_id,
                "alias": sub_id,
                "sheet_name": str(sheet_name),
                "filename": out_parquet.name,
                "kind": "excel_sheet",
                "row_count": row_count,
                "columns": clean_cols,
            }
        )
        _, _, sheet_preview = _format_preview_from_parquet(
            out_parquet,
            vault_secrets=vault_secrets,
            limit=8,
            header_prefix=f"## Sheet: {sheet_name} ({row_count} rows, id={ds_id})",
        )
        preview_sections.append(sheet_preview)

    if not derived_datasets:
        # Write empty placeholder so file:<id> still resolves without crashing
        out_parquet = derived_dir / "main.parquet"
        write_rows_to_parquet([], out_parquet, columns=["empty"])
        default_parquet_name = out_parquet.name
        derived_datasets.append(
            {
                "id": f"file:{file_id}",
                "alias": "main",
                "filename": out_parquet.name,
                "kind": "excel_sheet",
                "row_count": 0,
                "columns": ["empty"],
            }
        )

    return {
        "derived_datasets": derived_datasets,
        "default_parquet_name": default_parquet_name,
        "pages_parquet_name": None,
        "page_count": None,
        "scanned_pages": [],
        "extracted_tables": [],
        "text_preview": redact_secrets("\n\n".join(preview_sections), vault_secrets)[:24_000],
    }


def _ingest_pdf_file(
    file_path: Path,
    derived_dir: Path,
    *,
    file_id: str,
    vault_secrets: list[str],
) -> dict[str, Any]:
    page_rows: list[dict[str, Any]] = []
    scanned_pages: list[int] = []
    preview_chunks: list[str] = []
    derived_datasets: list[dict[str, Any]] = []
    extracted_tables: list[dict[str, Any]] = []
    table_counter = 0

    with pdfplumber.open(str(file_path)) as pdf:
        page_count = len(pdf.pages)
        for p_idx, page in enumerate(pdf.pages, start=1):
            raw_text = page.extract_text() or ""
            scrubbed_text = redact_secrets(raw_text, vault_secrets) if vault_secrets else raw_text
            clean_len = len(scrubbed_text.strip())
            has_images = bool(getattr(page, "images", None))
            is_scanned = clean_len < 25 or (has_images and clean_len < 50)
            if is_scanned:
                scanned_pages.append(p_idx)
            page_rows.append(
                {
                    "page_num": p_idx,
                    "char_count": clean_len,
                    "is_scanned": is_scanned,
                    "text": scrubbed_text,
                }
            )
            if scrubbed_text.strip():
                preview_chunks.append(f"[Page {p_idx}]\n{scrubbed_text.strip()}")

            try:
                raw_tables = page.extract_tables() or []
            except Exception:
                raw_tables = []
            for raw_tbl in raw_tables:
                if not isinstance(raw_tbl, list) or len(raw_tbl) < 2:
                    continue
                col_len = max((len(r) for r in raw_tbl if isinstance(r, list)), default=0)
                if col_len < 2:
                    continue
                headers, rows = _rows_from_matrix(raw_tbl)
                if not rows:
                    continue
                table_counter += 1
                sub_id = f"table_{table_counter}"
                tbl_parquet = derived_dir / f"{sub_id}.parquet"
                row_count, clean_cols = write_rows_to_parquet(rows, tbl_parquet, columns=headers)
                ds_id = f"file:{file_id}:{sub_id}"
                ds_info = {
                    "id": ds_id,
                    "alias": sub_id,
                    "page_num": p_idx,
                    "filename": tbl_parquet.name,
                    "kind": "pdf_table",
                    "row_count": row_count,
                    "columns": clean_cols,
                }
                derived_datasets.append(ds_info)
                extracted_tables.append(
                    {
                        "dataset_id": ds_id,
                        "page_num": p_idx,
                        "row_count": row_count,
                        "columns": clean_cols,
                        "sample_rows": rows[:3],
                    }
                )

    pages_parquet = derived_dir / "pages.parquet"
    write_rows_to_parquet(
        page_rows,
        pages_parquet,
        columns=["page_num", "char_count", "is_scanned", "text"],
    )
    pages_ds = {
        "id": f"file:{file_id}:pages",
        "alias": "pages",
        "filename": pages_parquet.name,
        "kind": "pdf_pages",
        "row_count": len(page_rows),
        "columns": ["page_num", "char_count", "is_scanned", "text"],
    }
    derived_datasets.insert(0, pages_ds)

    text_preview = "\n\n".join(preview_chunks)[:24_000]
    if not text_preview and page_count > 0:
        text_preview = f"[Scanned PDF: {page_count} page(s) — vision OCR ready]"

    default_parquet_name = (
        f"table_1.parquet" if table_counter > 0 else pages_parquet.name
    )
    return {
        "derived_datasets": derived_datasets,
        "default_parquet_name": default_parquet_name,
        "pages_parquet_name": pages_parquet.name,
        "page_count": page_count,
        "scanned_pages": scanned_pages,
        "extracted_tables": extracted_tables,
        "text_preview": redact_secrets(text_preview, vault_secrets),
    }


def _ingest_docx_file(
    file_path: Path,
    derived_dir: Path,
    *,
    file_id: str,
    vault_secrets: list[str],
) -> dict[str, Any]:
    doc = DocxDocument(str(file_path))
    paragraphs = [
        redact_secrets(p.text.strip(), vault_secrets) if vault_secrets else p.text.strip()
        for p in doc.paragraphs
        if p.text and p.text.strip()
    ]
    pseudo_pages: list[dict[str, Any]] = []
    buf: list[str] = []
    buf_len = 0
    for para in paragraphs:
        if buf and buf_len + len(para) > 3500:
            joined = "\n\n".join(buf)
            pseudo_pages.append(
                {
                    "page_num": len(pseudo_pages) + 1,
                    "char_count": len(joined),
                    "is_scanned": False,
                    "text": joined,
                }
            )
            buf = []
            buf_len = 0
        buf.append(para)
        buf_len += len(para)
    if buf or not pseudo_pages:
        joined = "\n\n".join(buf)
        pseudo_pages.append(
            {
                "page_num": len(pseudo_pages) + 1,
                "char_count": len(joined),
                "is_scanned": False,
                "text": joined,
            }
        )

    pages_parquet = derived_dir / "pages.parquet"
    write_rows_to_parquet(
        pseudo_pages,
        pages_parquet,
        columns=["page_num", "char_count", "is_scanned", "text"],
    )

    derived_datasets: list[dict[str, Any]] = [
        {
            "id": f"file:{file_id}:pages",
            "alias": "pages",
            "filename": pages_parquet.name,
            "kind": "docx_pages",
            "row_count": len(pseudo_pages),
            "columns": ["page_num", "char_count", "is_scanned", "text"],
        }
    ]
    extracted_tables: list[dict[str, Any]] = []
    table_counter = 0
    for tbl in doc.tables:
        matrix = [[cell.text.strip() for cell in row.cells] for row in tbl.rows]
        if len(matrix) < 2 or max((len(r) for r in matrix), default=0) < 2:
            continue
        headers, rows = _rows_from_matrix(matrix)
        if not rows:
            continue
        table_counter += 1
        sub_id = f"table_{table_counter}"
        tbl_parquet = derived_dir / f"{sub_id}.parquet"
        row_count, clean_cols = write_rows_to_parquet(rows, tbl_parquet, columns=headers)
        ds_id = f"file:{file_id}:{sub_id}"
        derived_datasets.append(
            {
                "id": ds_id,
                "alias": sub_id,
                "filename": tbl_parquet.name,
                "kind": "docx_table",
                "row_count": row_count,
                "columns": clean_cols,
            }
        )
        extracted_tables.append(
            {
                "dataset_id": ds_id,
                "row_count": row_count,
                "columns": clean_cols,
                "sample_rows": rows[:3],
            }
        )

    preview = "\n\n".join(
        f"[Section {p['page_num']}]\n{p['text']}" for p in pseudo_pages if p["text"].strip()
    )[:24_000]
    default_parquet_name = "table_1.parquet" if table_counter > 0 else pages_parquet.name
    return {
        "derived_datasets": derived_datasets,
        "default_parquet_name": default_parquet_name,
        "pages_parquet_name": pages_parquet.name,
        "page_count": len(pseudo_pages),
        "scanned_pages": [],
        "extracted_tables": extracted_tables,
        "text_preview": redact_secrets(preview, vault_secrets),
    }


def ingest_file_to_analytics(
    file_path: Path,
    derived_dir: Path,
    *,
    file_id: str,
    filename: str = "",
    mime_type: str = "",
    vault_secrets: list[str] | None = None,
) -> dict[str, Any]:
    """Parse structured/document file into immutable 0o444 ZSTD Parquet sidecars + preview."""
    secrets = vault_secrets or []
    ext = Path(filename or file_path.name).suffix.lower()
    clean_mime = str(mime_type or "").split(";", 1)[0].strip().lower()
    derived_dir.mkdir(parents=True, exist_ok=True)

    if ext in {".csv", ".tsv", ".json", ".ndjson", ".jsonl", ".parquet"} or clean_mime in {
        "text/csv",
        "text/tab-separated-values",
        "application/csv",
        "application/json",
        "application/x-ndjson",
        "application/ndjson",
        "application/jsonl",
        "application/parquet",
        "application/vnd.apache.parquet",
        "application/x-parquet",
    }:
        return _ingest_tabular_file(
            file_path,
            derived_dir,
            file_id=file_id,
            ext=ext,
            mime_type=clean_mime,
            vault_secrets=secrets,
        )

    if ext in {".xlsx", ".xlsm", ".xlsb", ".xls", ".ods"} or clean_mime in {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.sheet.binary.macroenabled.12",
        "application/vnd.ms-excel",
        "application/vnd.oasis.opendocument.spreadsheet",
    }:
        return _ingest_spreadsheet_file(
            file_path,
            derived_dir,
            file_id=file_id,
            vault_secrets=secrets,
        )

    if ext == ".pdf" or clean_mime == "application/pdf":
        return _ingest_pdf_file(
            file_path,
            derived_dir,
            file_id=file_id,
            vault_secrets=secrets,
        )

    if ext == ".docx" or clean_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        return _ingest_docx_file(
            file_path,
            derived_dir,
            file_id=file_id,
            vault_secrets=secrets,
        )

    raise ValueError(f"Unsupported analytical file format: {ext or clean_mime}")


def render_pdf_pages_png(
    file_path: Path,
    page_numbers: list[int] | None = None,
    *,
    max_pages: int = 6,
    dpi: int = 150,
    max_total_bytes: int = 4 * 1024 * 1024,
) -> list[bytes]:
    """Render requested 1-indexed PDF pages into PNG bytes via pypdfium2 + Pillow."""
    doc = pypdfium2.PdfDocument(str(file_path))
    frames: list[bytes] = []
    total_bytes = 0
    try:
        num_pages = len(doc)
        if page_numbers:
            targets = [p for p in page_numbers if 1 <= int(p) <= num_pages][:max_pages]
        else:
            targets = list(range(1, min(num_pages, max_pages) + 1))

        for p_num in targets:
            page = doc[p_num - 1]
            bitmap = page.render(scale=dpi / 72.0)
            pil_img = bitmap.to_pil()
            buf = io.BytesIO()
            pil_img.save(buf, format="PNG", optimize=True)
            png_bytes = buf.getvalue()
            if total_bytes + len(png_bytes) > max_total_bytes and len(png_bytes) > 100_000:
                # Re-encode downscaled so scanned multipage batches stay under the 4 MB vision cap.
                resized = pil_img.copy()
                resized.thumbnail((1280, 1280))
                buf2 = io.BytesIO()
                resized.save(buf2, format="PNG", optimize=True)
                png_bytes = buf2.getvalue()
            if total_bytes + len(png_bytes) > max_total_bytes:
                break
            frames.append(png_bytes)
            total_bytes += len(png_bytes)
    finally:
        doc.close()
    return frames


def extract_document_summary_from_bytes(
    raw_bytes: bytes,
    *,
    filename: str,
    mime_type: str = "",
    vault_secrets: list[str] | None = None,
    max_chars: int = 16000,
) -> dict[str, Any]:
    """Parse in-memory document/spreadsheet/CSV/PDF bytes via a temp directory and return clean excerpt + metadata."""
    secrets = vault_secrets or []
    safe_name = Path(filename or "document.bin").name or "document.bin"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        src_file = tmp_path / safe_name
        src_file.write_bytes(raw_bytes)
        derived_dir = tmp_path / "derived"
        res = ingest_file_to_analytics(
            src_file,
            derived_dir,
            file_id="file_temp",
            filename=safe_name,
            mime_type=mime_type,
            vault_secrets=secrets,
        )
        default_name = res.get("default_parquet_name")
        row_count = 0
        if default_name and (derived_dir / default_name).is_file():
            for ds in res.get("derived_datasets") or []:
                if ds.get("filename") == default_name:
                    row_count = int(ds.get("row_count") or 0)
                    break
        return {
            "excerpt": str(res.get("text_preview") or "")[:max_chars],
            "page_count": res.get("page_count"),
            "scanned_pages": list(res.get("scanned_pages") or []),
            "tables_preview": list(res.get("extracted_tables") or []),
            "derived_datasets": list(res.get("derived_datasets") or []),
            "row_count": row_count,
        }


def _configure_sandbox_connection(
    conn: Any,
    *,
    allowed_paths: list[str],
) -> None:
    conn.execute("SET autoload_known_extensions = false;")
    conn.execute("SET autoinstall_known_extensions = false;")
    conn.execute("SET allow_community_extensions = false;")
    conn.execute("SET allow_unsigned_extensions = false;")
    conn.execute("SET memory_limit = '256MB';")
    conn.execute("SET threads = 2;")
    if allowed_paths:
        conn.execute("SET allowed_paths = ?", [allowed_paths])


def _prepare_sqlite_doc_rows(
    rows: list[dict[str, Any]],
    secret_values: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    flattened_objs: list[dict[str, Any]] = []
    raw_doc_rows: list[dict[str, Any]] = []
    reserved = {"id", "collection", "external_key", "search_text", "doc_json", "created_at", "updated_at"}
    for r in rows:
        scrubbed_doc = _json_safe(r.get("doc") or {}, secret_values)
        if not isinstance(scrubbed_doc, dict):
            scrubbed_doc = {"value": scrubbed_doc}
        doc_json_str = json.dumps(scrubbed_doc, ensure_ascii=False)
        flat: dict[str, Any] = {
            "id": str(r.get("id") or ""),
            "collection": str(r.get("collection") or ""),
            "external_key": _json_safe(r.get("external_key"), secret_values),
            "search_text": _json_safe(r.get("search_text") or "", secret_values),
            "doc_json": doc_json_str,
            "created_at": str(r.get("created_at") or ""),
            "updated_at": str(r.get("updated_at") or ""),
        }
        raw_doc_rows.append(dict(flat))
        for k, v in scrubbed_doc.items():
            ck = _sanitize_sql_ident(str(k), fallback="field")
            if ck in reserved or ck in flat:
                continue
            if isinstance(v, (dict, list)):
                flat[ck] = json.dumps(v, ensure_ascii=False)
            else:
                flat[ck] = _normalize_cell_value(v)
        flattened_objs.append(flat)
    return flattened_objs, raw_doc_rows


def _load_sqlite_docs_into_duckdb(
    conn: Any,
    rows: list[dict[str, Any]],
    *,
    table_name: str,
    secret_values: list[str],
    load_docs_table: bool = False,
) -> None:
    """Load scrubbed SQLite collection_documents rows into an in-memory DuckDB table + optional docs table."""
    if not rows:
        conn.execute(
            f"""
            CREATE TEMP TABLE {_quote_ident(table_name)} (
                id VARCHAR,
                collection VARCHAR,
                external_key VARCHAR,
                search_text VARCHAR,
                doc_json VARCHAR,
                created_at VARCHAR,
                updated_at VARCHAR
            )
            """
        )
        return

    flattened_objs, raw_doc_rows = _prepare_sqlite_doc_rows(rows, secret_values)

    with tempfile.TemporaryDirectory() as tmpdir:
        ndjson_flat = Path(tmpdir) / "flat.ndjson"
        with ndjson_flat.open("w", encoding="utf-8") as fh:
            for obj in flattened_objs:
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
        conn.execute("SET allowed_paths = ?", [[str(ndjson_flat.resolve())]])
        try:
            conn.execute(
                f"CREATE TEMP TABLE {_quote_ident(table_name)} AS SELECT * FROM read_json_auto(?, sample_size=-1)",
                [str(ndjson_flat.resolve())],
            )
        except Exception:
            all_keys = list(dict.fromkeys(k for obj in flattened_objs for k in obj.keys()))
            col_spec = ", ".join(f"{repr(c)}: 'VARCHAR'" for c in all_keys)
            conn.execute(
                f"CREATE TEMP TABLE {_quote_ident(table_name)} AS SELECT * FROM read_json_auto(?, columns={{{col_spec}}})",
                [str(ndjson_flat.resolve())],
            )
        if load_docs_table:
            ndjson_docs = Path(tmpdir) / "docs.ndjson"
            with ndjson_docs.open("w", encoding="utf-8") as fh:
                for obj in raw_doc_rows:
                    fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
            conn.execute("SET allowed_paths = ?", [[str(ndjson_docs.resolve())]])
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS docs (id VARCHAR, collection VARCHAR, external_key VARCHAR, search_text VARCHAR, doc_json VARCHAR, created_at VARCHAR, updated_at VARCHAR)"
            )
            conn.execute(
                "INSERT INTO docs SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at FROM read_json_auto(?, sample_size=-1)",
                [str(ndjson_docs.resolve())],
            )
        conn.execute("SET allowed_paths = []")


def _load_flat_dicts_into_sqlite_conn(
    conn: sqlite3.Connection,
    table_name: str,
    rows: list[dict[str, Any]],
) -> None:
    if not rows:
        conn.execute(
            f"CREATE TEMP TABLE {_quote_ident(table_name)} "
            "(id TEXT, collection TEXT, external_key TEXT, search_text TEXT, doc_json TEXT, created_at TEXT, updated_at TEXT)"
        )
        return
    ordered_cols = list(dict.fromkeys(k for obj in rows for k in obj.keys())) or ["value"]
    clean_cols = _deduplicate_headers(ordered_cols, len(ordered_cols))
    col_map = list(zip(ordered_cols, clean_cols))
    col_types = _infer_sqlite_column_types(clean_cols, rows, col_map)
    col_defs = ", ".join(f"{_quote_ident(c)} {col_types.get(c, 'TEXT')}" for c in clean_cols)
    quoted_cols = ", ".join(_quote_ident(c) for c in clean_cols)
    placeholders = ", ".join("?" for _ in clean_cols)
    conn.execute(f"CREATE TEMP TABLE {_quote_ident(table_name)} ({col_defs})")
    tuples = [
        tuple(_coerce_sqlite_cell(obj.get(orig_k)) for orig_k, _ in col_map)
        for obj in rows
    ]
    conn.executemany(
        f"INSERT INTO {_quote_ident(table_name)} ({quoted_cols}) VALUES ({placeholders})",
        tuples,
    )


def _profile_single_dataset_via_sqlite(
    ds_id: str,
    spec: dict[str, Any],
    parquet_path: Any,
    rows_data: Any,
    secrets: list[str],
) -> dict[str, Any]:
    close_conn = True
    if parquet_path and Path(str(parquet_path)).is_file():
        p_obj = Path(str(parquet_path))
        if not _is_sqlite_store_file(p_obj):
            raise ValueError(
                "Binary Parquet profiling requires a host CPU supporting DuckDB x86-64-v3 (AVX2/BMI2)."
            )
        conn = sqlite3.connect(f"file:{p_obj.resolve()}?mode=ro", uri=True)
        src_table = "data"
    else:
        conn = sqlite3.connect(":memory:")
        src_table = "src"
        flattened_objs, _ = _prepare_sqlite_doc_rows(list(rows_data or []), secrets)
        _load_flat_dicts_into_sqlite_conn(conn, src_table, flattened_objs)

    try:
        row_count = int(
            conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(src_table)}").fetchone()[0] or 0
        )
        pragma_rows = conn.execute(f"PRAGMA table_info({_quote_ident(src_table)})").fetchall()
        col_profiles: list[dict[str, Any]] = []
        for prow in pragma_rows:
            col_name = str(prow[1])
            raw_type = str(prow[2] or "TEXT").upper()
            duck_like_type = (
                "BIGINT" if "INT" in raw_type else ("DOUBLE" if "REAL" in raw_type else "VARCHAR")
            )
            qcol = _quote_ident(col_name)
            qtbl = _quote_ident(src_table)
            stats_row = conn.execute(
                f"SELECT MIN({qcol}), MAX({qcol}), COUNT(DISTINCT {qcol}), "
                f"SUM(CASE WHEN {qcol} IS NULL THEN 1 ELSE 0 END) "
                f"FROM {qtbl}"
            ).fetchone()
            min_v, max_v, uniq_v, null_cnt = stats_row if stats_row else (None, None, 0, 0)
            avg_v = None
            if duck_like_type in {"BIGINT", "DOUBLE"} and row_count > 0:
                avg_row = conn.execute(f"SELECT AVG({qcol}) FROM {qtbl}").fetchone()
                avg_v = avg_row[0] if avg_row else None
            null_pct = round((float(null_cnt or 0) / row_count) * 100.0, 2) if row_count > 0 else 0.0
            entry: dict[str, Any] = {
                "column_name": col_name,
                "column_type": duck_like_type,
                "min": _json_safe(min_v, secrets),
                "max": _json_safe(max_v, secrets),
                "approx_unique": _json_safe(uniq_v, secrets),
                "avg": _json_safe(avg_v, secrets),
                "std": None,
                "q25": None,
                "q50": None,
                "q75": None,
                "null_percentage": null_pct,
            }
            if (
                row_count > 0
                and col_name
                and duck_like_type == "VARCHAR"
                and col_name not in {"doc_json", "text"}
                and isinstance(uniq_v, int)
                and 0 < uniq_v <= 25
            ):
                top_rows = conn.execute(
                    f"SELECT {qcol}, COUNT(*) AS cnt FROM {qtbl} "
                    f"WHERE {qcol} IS NOT NULL GROUP BY 1 ORDER BY cnt DESC LIMIT 5"
                ).fetchall()
                entry["top_values"] = [
                    {"value": _json_safe(tv[0], secrets), "count": int(tv[1])}
                    for tv in top_rows
                ]
            col_profiles.append(entry)

        sample_rel = conn.execute(f"SELECT * FROM {_quote_ident(src_table)} LIMIT 5")
        sample_cols = [d[0] for d in (sample_rel.description or ())]
        sample_rows = [
            {col: _json_safe(val, secrets) for col, val in zip(sample_cols, srow)}
            for srow in sample_rel.fetchall()
        ]
        return {
            "dataset_id": ds_id,
            "alias": str(spec.get("alias") or _sanitize_sql_ident(ds_id)),
            "kind": str(spec.get("kind") or ("parquet" if parquet_path else "collection")),
            "row_count": row_count,
            "is_sampled": row_count > 2000,
            "columns": col_profiles,
            "sample_rows": sample_rows,
        }
    finally:
        if close_conn:
            conn.close()


def profile_datasets(
    dataset_specs: list[dict[str, Any]],
    *,
    secret_values: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Compute compact SUMMARIZE statistics + sample rows for bound datasets (DuckDB or SQLite)."""
    secrets = secret_values or []
    profiles: list[dict[str, Any]] = []
    duck = _get_duckdb()

    for spec in dataset_specs:
        ds_id = str(spec.get("id") or spec.get("collection") or "dataset")
        parquet_path = spec.get("parquet_path")
        rows_data = spec.get("rows")
        has_file = bool(parquet_path and Path(str(parquet_path)).is_file())
        use_sqlite_profile = (duck is None) or (
            has_file and _is_sqlite_store_file(Path(str(parquet_path)))
        )
        if use_sqlite_profile:
            profiles.append(
                _profile_single_dataset_via_sqlite(
                    ds_id, spec, parquet_path, rows_data, secrets
                )
            )
            continue

        conn = duck.connect(database=":memory:")
        try:
            src_table = "src"
            if has_file:
                resolved = str(Path(str(parquet_path)).resolve())
                _configure_sandbox_connection(conn, allowed_paths=[resolved])
                conn.execute(f"CREATE TEMP VIEW src AS SELECT * FROM read_parquet({repr(resolved)})")
            else:
                _configure_sandbox_connection(conn, allowed_paths=[])
                _load_sqlite_docs_into_duckdb(
                    conn,
                    list(rows_data or []),
                    table_name="src",
                    secret_values=secrets,
                )

            row_count = int(conn.execute(f"SELECT COUNT(*) FROM {src_table}").fetchone()[0] or 0)
            sum_rel = conn.execute(f"SUMMARIZE SELECT * FROM {src_table}")
            sum_cols = [d[0] for d in (sum_rel.description or ())]
            col_profiles: list[dict[str, Any]] = []
            for row in sum_rel.fetchall():
                item = dict(zip(sum_cols, row))
                col_name = str(item.get("column_name") or "")
                col_type = str(item.get("column_type") or "")
                approx_unique = item.get("approx_unique")
                entry: dict[str, Any] = {
                    "column_name": col_name,
                    "column_type": col_type,
                    "min": _json_safe(item.get("min"), secrets),
                    "max": _json_safe(item.get("max"), secrets),
                    "approx_unique": _json_safe(approx_unique, secrets),
                    "avg": _json_safe(item.get("avg"), secrets),
                    "std": _json_safe(item.get("std"), secrets),
                    "q25": _json_safe(item.get("q25"), secrets),
                    "q50": _json_safe(item.get("q50"), secrets),
                    "q75": _json_safe(item.get("q75"), secrets),
                    "null_percentage": _json_safe(item.get("null_percentage"), secrets),
                }
                if (
                    row_count > 0
                    and col_name
                    and "VARCHAR" in col_type.upper()
                    and col_name not in {"doc_json", "text"}
                    and isinstance(approx_unique, int)
                    and 0 < approx_unique <= 25
                ):
                    try:
                        _, top_rows = _duckdb_fetch_tz_safe(
                            conn,
                            f"SELECT {_quote_ident(col_name)}, COUNT(*) AS cnt "
                            f"FROM {src_table} WHERE {_quote_ident(col_name)} IS NOT NULL "
                            f"GROUP BY 1 ORDER BY cnt DESC LIMIT 5",
                        )
                        entry["top_values"] = [
                            {"value": _json_safe(tv[0], secrets), "count": int(tv[1])}
                            for tv in top_rows
                        ]
                    except Exception:
                        pass
                col_profiles.append(entry)

            sample_cols, sample_fetched = _duckdb_fetch_tz_safe(
                conn, f"SELECT * FROM {src_table} LIMIT 5"
            )
            sample_rows = [
                {
                    col: _json_safe(val, secrets)
                    for col, val in zip(sample_cols, srow)
                }
                for srow in sample_fetched
            ]
            profiles.append(
                {
                    "dataset_id": ds_id,
                    "alias": str(spec.get("alias") or _sanitize_sql_ident(ds_id)),
                    "kind": str(spec.get("kind") or ("parquet" if parquet_path else "collection")),
                    "row_count": row_count,
                    "is_sampled": row_count > 2000,
                    "columns": col_profiles,
                    "sample_rows": sample_rows,
                }
            )
        finally:
            conn.close()

    return profiles


_FORBIDDEN_SQLITE_FALLBACK_FUNCS = frozenset(
    {
        "load_extension",
        "fts5",
        "fts5_source_id",
        "sqlite_compileoption_get",
        "sqlite_compileoption_used",
        "sqlite_offset",
        "sqlite_source_id",
        "sqlite_version",
        "randomblob",
        "zeroblob",
        "edit",
        "readfile",
        "writefile",
    }
)

_PIVOT_RE = re.compile(
    r"\bPIVOT\s+([A-Za-z_][A-Za-z0-9_]*)\s+ON\s+([A-Za-z_][A-Za-z0-9_]*)\s+USING\s+"
    r"(SUM|COUNT|AVG|MIN|MAX)\s*\(\s*([A-Za-z0-9_*]+)\s*\)"
    r"(?:\s+GROUP\s+BY\s+([A-Za-z0-9_,\s]+?))?"
    r"(?=\s*\)|\s+ORDER\s+BY\b|\s+LIMIT\b|\s*$)",
    re.IGNORECASE,
)
_RANGE_FN_RE = re.compile(r"(?<![A-Za-z0-9_.])\brange\s*\(\s*(\d+)\s*\)", re.IGNORECASE)


def _transform_unquoted_sql(sql: str, replacer: Callable[[str], str]) -> str:
    """Apply replacer only to unquoted/uncommented SQL spans while keeping literals verbatim."""
    out: list[str] = []
    n = len(sql)
    i = 0
    last = 0
    while i < n:
        ch = sql[i]
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            if i > last:
                out.append(replacer(sql[last:i]))
            nl = sql.find("\n", i + 2)
            end = n if nl == -1 else nl + 1
            out.append(sql[i:end])
            i = last = end
            continue
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            if i > last:
                out.append(replacer(sql[last:i]))
            end_pos = sql.find("*/", i + 2)
            end = n if end_pos == -1 else end_pos + 2
            out.append(sql[i:end])
            i = last = end
            continue
        if ch == "'":
            if i > last:
                out.append(replacer(sql[last:i]))
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(sql[i:j])
            i = last = j
            continue
        if ch in {'"', "`", "["}:
            if i > last:
                out.append(replacer(sql[last:i]))
            close_ch = "]" if ch == "[" else ch
            j = i + 1
            while j < n:
                if sql[j] == close_ch:
                    if close_ch != "]" and j + 1 < n and sql[j + 1] == close_ch:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(sql[i:j])
            i = last = j
            continue
        i += 1
    if last < n:
        out.append(replacer(sql[last:]))
    return "".join(out)


def _prepare_sqlite_fallback_sql(
    sql: str,
    conn: sqlite3.Connection,
    known_tables: set[str],
) -> str:
    """Translate safe DuckDB conveniences (ILIKE, PIVOT, range()) into portable SQLite SQL."""
    rewritten = _transform_unquoted_sql(
        sql,
        lambda seg: re.sub(r"\bilike\b", "LIKE", seg, flags=re.IGNORECASE),
    )

    def _rewrite_pivot(chunk: str) -> str:
        def _sub_pivot(match: re.Match[str]) -> str:
            tbl = match.group(1)
            if tbl.lower() not in known_tables:
                return match.group(0)
            p_col = match.group(2)
            agg = match.group(3).upper()
            val_expr = match.group(4)
            grp_raw = (match.group(5) or "").strip()
            vals = [
                r[0]
                for r in conn.execute(
                    f"SELECT DISTINCT {_quote_ident(p_col)} FROM {_quote_ident(tbl)} "
                    f"WHERE {_quote_ident(p_col)} IS NOT NULL ORDER BY 1 LIMIT 50"
                ).fetchall()
            ]
            if not vals:
                return "SELECT NULL AS _empty WHERE 0"
            v_arg = "*" if val_expr == "*" else _quote_ident(val_expr)
            agg_exprs = [
                f"{agg}(CASE WHEN {_quote_ident(p_col)} = '{str(v).replace(chr(39), chr(39) * 2)}' "
                f"THEN {v_arg} END) AS {_quote_ident(str(v))}"
                for v in vals
            ]
            grp_cols = [g.strip() for g in grp_raw.split(",") if g.strip()] if grp_raw else []
            select_prefix = ", ".join(_quote_ident(g) for g in grp_cols)
            all_sel = f"{select_prefix}, {', '.join(agg_exprs)}" if select_prefix else ", ".join(agg_exprs)
            grp_clause = f" GROUP BY {select_prefix}" if select_prefix else ""
            return f"SELECT {all_sel} FROM {_quote_ident(tbl)}{grp_clause}"

        return _PIVOT_RE.sub(_sub_pivot, chunk)

    rewritten = _transform_unquoted_sql(rewritten, _rewrite_pivot)

    range_counter = 0

    def _rewrite_range(chunk: str) -> str:
        nonlocal range_counter

        def _sub_rng(match: re.Match[str]) -> str:
            nonlocal range_counter
            count = min(max(0, int(match.group(1))), 100_000)
            tname = f"__argo_range_{range_counter}"
            range_counter += 1
            conn.execute(f'CREATE TEMP TABLE {_quote_ident(tname)} ("range" INTEGER)')
            if count > 0:
                conn.executemany(
                    f"INSERT INTO {_quote_ident(tname)} VALUES (?)",
                    ((i,) for i in range(count)),
                )
            known_tables.add(tname.lower())
            return _quote_ident(tname)

        return _RANGE_FN_RE.sub(_sub_rng, chunk)

    return _transform_unquoted_sql(rewritten, _rewrite_range)


def _execute_analytics_sqlite_fallback(
    validated_sql: str,
    *,
    datasets: list[dict[str, Any]],
    secrets: list[str],
    params: list[Any] | None,
    capped_rows: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Run read-only analytics SQL in an isolated :memory: SQLite connection with 1.5s watchdog."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    timer: threading.Timer | None = None
    try:
        conn.create_function(
            "hash",
            1,
            lambda v: (hash(v) & 0x7FFFFFFFFFFFFFFF) if v is not None else 0,
        )
        collection_counts: dict[str, int] = {}
        registered_aliases: set[str] = set()
        known_tables: set[str] = set()
        sqlite_datasets_present = any(
            not (d.get("parquet_path") and Path(str(d.get("parquet_path"))).is_file())
            for d in datasets
        )
        if sqlite_datasets_present:
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS docs (id TEXT, collection TEXT, external_key TEXT, search_text TEXT, doc_json TEXT, created_at TEXT, updated_at TEXT)"
            )
            registered_aliases.add("docs")
            known_tables.add("docs")

        def _register_alias(alias: str, target_tbl: str) -> None:
            clean_a = _sanitize_sql_ident(alias)
            if not clean_a or clean_a in registered_aliases:
                return
            registered_aliases.add(clean_a)
            known_tables.add(clean_a.lower())
            conn.execute(
                f"CREATE TEMP VIEW {_quote_ident(clean_a)} AS SELECT * FROM {_quote_ident(target_tbl)}"
            )

        for idx, ds in enumerate(datasets):
            ds_id = str(ds.get("id") or f"t{idx}")
            tbl_name = f"__argo_ds_{idx}"
            p = ds.get("parquet_path")
            if p and Path(str(p)).is_file():
                cols, rows_loaded, total_cnt = read_dataset_rows(
                    Path(str(p)),
                    limit=500_000,
                    secret_values=secrets,
                )
                if not rows_loaded:
                    col_defs = ", ".join(f"{_quote_ident(c)} TEXT" for c in (cols or ["value"]))
                    conn.execute(f"CREATE TEMP TABLE {_quote_ident(tbl_name)} ({col_defs})")
                else:
                    _load_flat_dicts_into_sqlite_conn(conn, tbl_name, rows_loaded)
                collection_counts[ds_id] = total_cnt
            else:
                rows_list = list(ds.get("rows") or [])
                flattened_objs, raw_doc_rows = _prepare_sqlite_doc_rows(rows_list, secrets)
                _load_flat_dicts_into_sqlite_conn(conn, tbl_name, flattened_objs)
                if raw_doc_rows:
                    conn.executemany(
                        "INSERT INTO docs (id, collection, external_key, search_text, doc_json, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [
                            (
                                r["id"],
                                r["collection"],
                                r["external_key"],
                                r["search_text"],
                                r["doc_json"],
                                r["created_at"],
                                r["updated_at"],
                            )
                            for r in raw_doc_rows
                        ],
                    )
                collection_counts[ds_id] = int(ds.get("total_count", len(rows_list)))

            known_tables.add(tbl_name.lower())
            if idx == 0:
                _register_alias("dataset", tbl_name)
            _register_alias(f"t{idx}", tbl_name)
            for cand_alias in ds.get("aliases") or []:
                _register_alias(str(cand_alias), tbl_name)
            if ds_id.startswith("file:"):
                _register_alias(ds_id[5:].replace(":", "_"), tbl_name)
            _register_alias(ds_id.replace(":", "_"), tbl_name)
            if ds_id.endswith(":pages") or ds.get("kind") in {"pdf_pages", "docx_pages"}:
                _register_alias("pages", tbl_name)

        for idx, ds in enumerate(datasets):
            pages_p = ds.get("pages_parquet_path")
            if "pages" not in registered_aliases and pages_p and Path(str(pages_p)).is_file():
                p_cols, p_rows, _ = read_dataset_rows(
                    Path(str(pages_p)),
                    limit=50_000,
                    secret_values=secrets,
                )
                ptbl = f"__argo_pages_{idx}"
                if not p_rows:
                    col_defs = ", ".join(f"{_quote_ident(c)} TEXT" for c in (p_cols or ["page_num", "text"]))
                    conn.execute(f"CREATE TEMP TABLE {_quote_ident(ptbl)} ({col_defs})")
                else:
                    _load_flat_dicts_into_sqlite_conn(conn, ptbl, p_rows)
                known_tables.add(ptbl.lower())
                _register_alias("pages", ptbl)
                break

        if not datasets:
            conn.execute("CREATE TEMP TABLE dataset (empty TEXT)")
            registered_aliases.add("dataset")
            known_tables.add("dataset")

        if not sqlite_datasets_present and "docs" not in registered_aliases and datasets:
            _register_alias("docs", "__argo_ds_0")

        exec_sql = _prepare_sqlite_fallback_sql(validated_sql, conn, known_tables)

        def _authorizer(
            action: int,
            arg1: str | None,
            arg2: str | None,
            db_name: str | None,
            trigger_name: str | None,
        ) -> int:
            del db_name, trigger_name
            if action == sqlite3.SQLITE_SELECT or action == getattr(sqlite3, "SQLITE_RECURSIVE", 33):
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ:
                tbl = str(arg1 or "").lower()
                if tbl.startswith("sqlite_"):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_FUNCTION:
                fn = str(arg2 or "").lower()
                if fn in _FORBIDDEN_SQLITE_FALLBACK_FUNCS:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        deadline = time.monotonic() + float(timeout_seconds)
        conn.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline else 0,
            1000,
        )
        conn.set_authorizer(_authorizer)

        timer = threading.Timer(timeout_seconds, conn.interrupt)
        timer.daemon = True
        timer.start()

        try:
            cur = conn.execute(exec_sql, list(params or []))
            fetched = cur.fetchmany(capped_rows + 1)
        except sqlite3.DatabaseError as exc:
            msg = str(exc)
            lowered = msg.lower()
            if "interrupted" in lowered:
                raise TimeoutError(
                    f"Analytics sandbox query exceeded the {timeout_seconds:.1f}s time limit."
                ) from exc
            if "not authorized" in lowered:
                raise PermissionError(f"Analytics sandbox blocked unauthorized operation: {msg}") from exc
            raise ValueError(f"SQL query error: {msg}") from exc

        raw_cols = [d[0] for d in (cur.description or ())]
        columns: list[str] = []
        seen_cols: dict[str, int] = {}
        for col_name in raw_cols:
            cnt = seen_cols.get(col_name, 0) + 1
            seen_cols[col_name] = cnt
            columns.append(col_name if cnt == 1 else f"{col_name}_{cnt}")

        truncated = len(fetched) > capped_rows
        out_rows = [
            {col: _json_safe(val, secrets) for col, val in zip(columns, r)}
            for r in fetched[:capped_rows]
        ]
        return {
            "columns": columns,
            "rows": out_rows,
            "row_count": len(out_rows),
            "truncated": truncated,
            "collection_counts": collection_counts,
            "engine": "sqlite",
        }
    finally:
        if timer is not None:
            timer.cancel()
        conn.close()


def execute_duckdb_query(
    sql: str,
    *,
    datasets: list[dict[str, Any]],
    secret_values: list[str] | None = None,
    params: list[Any] | None = None,
    row_cap: int = 500,
    timeout_seconds: float = 1.5,
) -> dict[str, Any]:
    """Execute read-only SELECT/WITH SQL over authorized Parquet/collection datasets in locked :memory: DuckDB (or SQLite fallback)."""
    validated_sql = validate_readonly_sandbox_sql(sql, block_duckdb_external_funcs=True)
    secrets = secret_values or []
    capped_rows = max(1, min(int(row_cap), 500))

    parquet_paths: list[str] = []
    total_parquet_bytes = 0
    has_sqlite_store = False
    for d in datasets:
        for key in ("parquet_path", "pages_parquet_path"):
            p = d.get(key)
            if p and Path(str(p)).is_file():
                resolved = Path(str(p)).resolve()
                if _is_sqlite_store_file(resolved):
                    has_sqlite_store = True
                resolved_str = str(resolved)
                if resolved_str not in parquet_paths:
                    parquet_paths.append(resolved_str)
                    try:
                        total_parquet_bytes += resolved.stat().st_size
                    except OSError:
                        pass

    duck = _get_duckdb()
    if duck is None or has_sqlite_store:
        return _execute_analytics_sqlite_fallback(
            validated_sql,
            datasets=datasets,
            secrets=secrets,
            params=params,
            capped_rows=capped_rows,
            timeout_seconds=timeout_seconds,
        )

    materialize_in_memory = total_parquet_bytes <= MAX_IN_MEMORY_PARQUET_LOAD_BYTES

    conn = duck.connect(database=":memory:")
    timer: threading.Timer | None = None
    try:
        _configure_sandbox_connection(conn, allowed_paths=parquet_paths)

        collection_counts: dict[str, int] = {}
        registered_aliases: set[str] = set()
        sqlite_datasets_present = any(
            not (d.get("parquet_path") and Path(str(d.get("parquet_path"))).is_file())
            for d in datasets
        )
        if sqlite_datasets_present:
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS docs (id VARCHAR, collection VARCHAR, external_key VARCHAR, search_text VARCHAR, doc_json VARCHAR, created_at VARCHAR, updated_at VARCHAR)"
            )
            registered_aliases.add("docs")

        def _register_alias(alias: str, target_tbl: str) -> None:
            clean_a = _sanitize_sql_ident(alias)
            if not clean_a or clean_a in registered_aliases:
                return
            registered_aliases.add(clean_a)
            conn.execute(
                f"CREATE TEMP VIEW {_quote_ident(clean_a)} AS SELECT * FROM {_quote_ident(target_tbl)}"
            )

        for idx, ds in enumerate(datasets):
            ds_id = str(ds.get("id") or f"t{idx}")
            tbl_name = f"__argo_ds_{idx}"
            p = ds.get("parquet_path")
            if p and Path(str(p)).is_file():
                if parquet_paths:
                    conn.execute("SET allowed_paths = ?", [parquet_paths])
                resolved_p = str(Path(str(p)).resolve())
                if materialize_in_memory:
                    conn.execute(
                        f"CREATE TEMP TABLE {_quote_ident(tbl_name)} AS SELECT * FROM read_parquet({repr(resolved_p)})"
                    )
                else:
                    conn.execute(
                        f"CREATE TEMP VIEW {_quote_ident(tbl_name)} AS SELECT * FROM read_parquet({repr(resolved_p)})"
                    )
                cnt = int(conn.execute(f"SELECT COUNT(*) FROM {_quote_ident(tbl_name)}").fetchone()[0] or 0)
                collection_counts[ds_id] = cnt
            else:
                rows_list = list(ds.get("rows") or [])
                _load_sqlite_docs_into_duckdb(
                    conn,
                    rows_list,
                    table_name=tbl_name,
                    secret_values=secrets,
                    load_docs_table=True,
                )
                collection_counts[ds_id] = int(ds.get("total_count", len(rows_list)))

            if idx == 0:
                _register_alias("dataset", tbl_name)
            _register_alias(f"t{idx}", tbl_name)
            for cand_alias in ds.get("aliases") or []:
                _register_alias(str(cand_alias), tbl_name)
            if ds_id.startswith("file:"):
                _register_alias(ds_id[5:].replace(":", "_"), tbl_name)
            _register_alias(ds_id.replace(":", "_"), tbl_name)
            if ds_id.endswith(":pages") or ds.get("kind") in {"pdf_pages", "docx_pages"}:
                _register_alias("pages", tbl_name)

        for idx, ds in enumerate(datasets):
            pages_p = ds.get("pages_parquet_path")
            if "pages" not in registered_aliases and pages_p and Path(str(pages_p)).is_file():
                if parquet_paths:
                    conn.execute("SET allowed_paths = ?", [parquet_paths])
                resolved_pages = str(Path(str(pages_p)).resolve())
                if materialize_in_memory:
                    conn.execute(
                        f"CREATE TEMP TABLE __argo_pages_{idx} AS SELECT * FROM read_parquet({repr(resolved_pages)})"
                    )
                else:
                    conn.execute(
                        f"CREATE TEMP VIEW __argo_pages_{idx} AS SELECT * FROM read_parquet({repr(resolved_pages)})"
                    )
                _register_alias("pages", f"__argo_pages_{idx}")
                break

        if not datasets:
            conn.execute("CREATE TEMP TABLE dataset (empty VARCHAR)")
            registered_aliases.add("dataset")

        if not sqlite_datasets_present and "docs" not in registered_aliases and datasets:
            _register_alias("docs", "__argo_ds_0")

        if materialize_in_memory or not parquet_paths:
            conn.execute("SET allowed_paths = []")
            conn.execute("SET enable_external_access = false;")
        else:
            # Large >64 MB Parquet scans stream directly from read-only 0o444 paths;
            # Step A already blocks explicit read_* functions in user SQL.
            conn.execute("SET allowed_directories = []")
            conn.execute("SET allowed_paths = ?", [parquet_paths])
        conn.execute("SET lock_configuration = true;")

        timer = threading.Timer(timeout_seconds, conn.interrupt)
        timer.daemon = True
        timer.start()

        try:
            raw_cols, fetched = _duckdb_fetch_tz_safe(
                conn,
                validated_sql,
                list(params or []),
                max_rows=capped_rows + 1,
            )
        except duck.InterruptException as exc:
            raise TimeoutError(
                f"DuckDB sandbox query exceeded the {timeout_seconds:.1f}s time limit."
            ) from exc
        except duck.PermissionException as exc:
            raise PermissionError(f"DuckDB sandbox blocked unauthorized operation: {exc}") from exc
        except duck.Error as exc:
            msg = str(exc)
            if "interrupted" in msg.lower():
                raise TimeoutError(
                    f"DuckDB sandbox query exceeded the {timeout_seconds:.1f}s time limit."
                ) from exc
            if "permission" in msg.lower() or "disabled by configuration" in msg.lower():
                raise PermissionError(f"DuckDB sandbox blocked unauthorized operation: {msg}") from exc
            raise ValueError(f"SQL query error: {msg}") from exc

        columns: list[str] = []
        seen_cols: dict[str, int] = {}
        for col_name in raw_cols:
            cnt = seen_cols.get(col_name, 0) + 1
            seen_cols[col_name] = cnt
            columns.append(col_name if cnt == 1 else f"{col_name}_{cnt}")

        truncated = len(fetched) > capped_rows
        out_rows = [
            {col: _json_safe(val, secrets) for col, val in zip(columns, r)}
            for r in fetched[:capped_rows]
        ]
        return {
            "columns": columns,
            "rows": out_rows,
            "row_count": len(out_rows),
            "truncated": truncated,
            "collection_counts": collection_counts,
            "engine": "duckdb",
        }
    finally:
        if timer is not None:
            timer.cancel()
        conn.close()


def verify_analytics_runtime() -> dict[str, Any]:
    """Verify analytics wheel presence, native DuckDB (if supported), and SQLite fallback round-trip."""
    duckdb_installed = importlib.util.find_spec("duckdb") is not None
    if not duckdb_installed:
        raise AssertionError("duckdb package spec not found in runtime environment.")

    duckdb_supported = is_duckdb_runtime_supported()
    sample_rows = [
        {"region": "North", "revenue": 120},
        {"region": "South", "revenue": 80},
    ]

    def _run_roundtrip(tmp_dir: Path, expected_engine: str) -> None:
        out_path = tmp_dir / f"{expected_engine}.parquet"
        cnt, cols = write_rows_to_parquet(sample_rows, out_path, columns=["region", "revenue"])
        assert cnt == 2 and cols == ["region", "revenue"]
        profs = profile_datasets([{"id": "smoke", "parquet_path": str(out_path)}])
        assert profs and profs[0]["row_count"] == 2
        res = execute_duckdb_query(
            "SELECT SUM(revenue) AS total_rev FROM dataset",
            datasets=[{"id": "smoke", "parquet_path": str(out_path)}],
        )
        assert res["engine"] == expected_engine
        assert res["rows"] == [{"total_rev": 200}]

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        if duckdb_supported:
            _run_roundtrip(tmp_path, "duckdb")
        prev_disable = os.environ.get("ARGO_DISABLE_DUCKDB")
        os.environ["ARGO_DISABLE_DUCKDB"] = "1"
        try:
            _run_roundtrip(tmp_path, "sqlite")
        finally:
            if prev_disable is None:
                os.environ.pop("ARGO_DISABLE_DUCKDB", None)
            else:
                os.environ["ARGO_DISABLE_DUCKDB"] = prev_disable

    return {
        "duckdb_installed": duckdb_installed,
        "duckdb_supported": duckdb_supported,
        "sqlite_fallback_verified": True,
    }
