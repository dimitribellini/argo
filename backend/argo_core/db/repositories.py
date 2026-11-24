"""Thread-safe SQLite repository layer over Argo's 5 Core Primitives."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import html
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from argo_core.analytics.engine import (
    MAX_ANALYTICS_UPLOAD_BYTES,
    MAX_WORKSPACE_FILE_BYTES,
    dataset_identifier,
    execute_duckdb_query,
    ingest_file_to_analytics,
    is_analytics_or_document_file,
    max_workspace_file_bytes_for_name,
    profile_datasets,
    read_dataset_rows,
    validate_readonly_sandbox_sql,
)
from argo_core.security.tenancy import (
    normalize_email,
    normalize_group_slugs,
    normalize_visibility,
)
from argo_core.security.vault import SecretVault, redact_secrets

_UNSET = object()


class AlreadyResolvedError(Exception):
    """Raised when an approval transition finds zero matching pending rows."""


class NotFoundError(Exception):
    """Raised when a requested record does not exist."""


class FileTooLargeError(Exception):
    """Raised when an uploaded workspace file exceeds the allowed size limit."""


_TEXT_PREVIEW_EXTENSIONS = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
        ".csv",
        ".tsv",
        ".json",
        ".yaml",
        ".yml",
        ".log",
        ".html",
        ".htm",
        ".xml",
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".sh",
        ".sql",
        ".ini",
        ".conf",
        ".env",
    }
)
_IMAGE_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp", "image/gif"})


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_id(prefix: str) -> str:
    """Generate a compact prefixed unique identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def slugify(text: str) -> str:
    """Convert display names into lowercase URL/container-safe slugs."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return slug or "item"


def collection_slug(text: str) -> str:
    """Normalize collection names while preserving snake_case identifiers."""
    slug = re.sub(r"[^a-z0-9_]+", "-", text.strip().lower()).strip("-_")
    return slug or "collection"


def _initials(name: str) -> str:
    parts = [part for part in re.split(r"\s+", name.strip()) if part]
    if not parts:
        return "AB"
    return "".join(part[0].upper() for part in parts[:2])


def _default_permissions(rbac: str, runtime: str) -> list[str]:
    perms = ["collections:read"]
    if runtime == "desktop":
        perms.append("desktop:selkies")
    elif runtime == "sandbox":
        perms.append("sandbox:exec")
    if rbac == "execute":
        perms.extend(["connector:execute", "approvals:request"])
    elif rbac == "draft":
        perms.extend(["collections:write", "connector:draft"])
    else:
        perms.append("collections:write")
    return perms


def _fts_query(raw_query: str) -> str:
    """Quote user tokens for safe FTS5 MATCH queries."""
    tokens = [tok.replace('"', '""') for tok in raw_query.strip().split() if tok.strip()]
    return " ".join(f'"{tok}"' for tok in tokens)


def derive_style_rule_from_diff(
    original_text: str,
    edited_text: str,
    instruction: str | None = None,
) -> str:
    """Synthesize a concise editorial style constraint from an edit diff or operator note."""
    if instruction and instruction.strip():
        cleaned = re.sub(r"\s+", " ", instruction.strip())
        return f"Follow operator revision preference: {cleaned}"[:240]

    orig = original_text.strip()
    edited = edited_text.strip()
    if not edited or orig == edited:
        return ""

    hints: list[str] = []
    if orig:
        ratio = len(edited) / max(len(orig), 1)
        if ratio <= 0.72:
            hints.append(
                f"Keep copy concise (compressed {len(orig)} -> {len(edited)} chars)"
            )
        elif ratio >= 1.35:
            hints.append(
                f"Expand technical context when drafting ({len(orig)} -> {len(edited)} chars)"
            )

    orig_urls = len(re.findall(r"https?://\S+", orig))
    edited_urls = len(re.findall(r"https?://\S+", edited))
    if orig_urls > edited_urls:
        hints.append("omit unnecessary raw URLs unless explicitly requested")
    elif edited_urls > orig_urls:
        hints.append("include direct reference URLs when available")

    orig_bullets = len(re.findall(r"(?m)^\s*[-*•]\s+", orig))
    edited_bullets = len(re.findall(r"(?m)^\s*[-*•]\s+", edited))
    if edited_bullets > orig_bullets:
        hints.append("use concise bulleted takeaways")
    elif orig_bullets > edited_bullets and edited_bullets == 0:
        hints.append("prefer unified prose over bullet lists")

    orig_cvss = bool(re.search(r"\bCVSS[:\s]*\d", orig, re.IGNORECASE))
    edited_cvss = bool(re.search(r"\bCVSS[:\s]*\d", edited, re.IGNORECASE))
    if orig_cvss and not edited_cvss:
        hints.append("omit raw CVSS score vectors in community summaries")

    if not hints:
        snippet = re.sub(r"\s+", " ", edited)[:140]
        return f"Prefer edited phrasing style matching: '{snippet}'"

    joined = "; ".join(hints)
    return (joined[0].upper() + joined[1:])[:240]


_INTERNAL_SYSTEM_COLLECTIONS = frozenset(
    {
        "bot_threads",
        "desktop_snapshots",
        "bot_skills",
        "debug_run_traces",
        "oauth_pending_states",
        "http_feed_cache",
        "ingestion_seen_keys",
        "vault_secrets",
        "bot_rooms",
        "room_threads",
        "workspace_files",
        "thread_read_cursors",
        "delegation_plans",
        "ssh_audit_log",
        "ssh_settings",
        "chat_settings",
        "argo_users",
        "argo_team_groups",
        "argo_auth_sessions",
        "argo_auth_oauth_states",
    }
)

_BOT_READABLE_SYSTEM_COLLECTIONS = frozenset({"ssh_audit_log"})
_READ_FORBIDDEN_SYSTEM_COLLECTIONS = _INTERNAL_SYSTEM_COLLECTIONS - _BOT_READABLE_SYSTEM_COLLECTIONS
_PAGE_FORBIDDEN_INTERNAL_COLLECTIONS = _INTERNAL_SYSTEM_COLLECTIONS - {
    "ssh_audit_log",
}

_SAFE_SANDBOX_SQL_FUNCTIONS = frozenset(
    {
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "total",
        "group_concat",
        "json",
        "json_array",
        "json_array_length",
        "json_extract",
        "json_object",
        "json_quote",
        "json_type",
        "json_valid",
        "json_each",
        "json_tree",
        "json_group_array",
        "json_group_object",
        "->",
        "->>",
        "coalesce",
        "ifnull",
        "nullif",
        "iif",
        "typeof",
        "abs",
        "round",
        "length",
        "lower",
        "upper",
        "trim",
        "ltrim",
        "rtrim",
        "substr",
        "substring",
        "instr",
        "replace",
        "printf",
        "format",
        "like",
        "glob",
        "hex",
        "unicode",
        "char",
        "date",
        "time",
        "datetime",
        "julianday",
        "unixepoch",
        "strftime",
        "cast",
        "row_number",
        "rank",
        "dense_rank",
        "lag",
        "lead",
        "first_value",
        "last_value",
        "ntile",
    }
)

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


def _validate_readonly_sandbox_sql(sql: str) -> str:
    """Validate that SQL is a single read-only SELECT/WITH query free of forbidden tables/statements."""
    return validate_readonly_sandbox_sql(sql, block_duckdb_external_funcs=False)


def _json_value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


def _flatten_json_paths(
    value: Any,
    *,
    prefix: str = "$",
    depth: int = 0,
    max_depth: int = 6,
    out: dict[str, list[Any]] | None = None,
) -> dict[str, list[Any]]:
    """Collect nested JSON paths ($.key, $.arr[], $.arr[].sub) and their observed non-null values."""
    if out is None:
        out = {}
    if value is None or depth > max_depth:
        return out
    if isinstance(value, dict):
        if prefix != "$":
            out.setdefault(prefix, []).append(value)
        if depth == max_depth:
            return out
        for k, v in value.items():
            key_str = str(k)
            if not key_str:
                continue
            child_path = f"{prefix}.{key_str}"
            if isinstance(v, (dict, list)):
                _flatten_json_paths(v, prefix=child_path, depth=depth + 1, max_depth=max_depth, out=out)
            elif v is not None:
                out.setdefault(child_path, []).append(v)
        return out
    if isinstance(value, list):
        out.setdefault(prefix, []).append(value)
        arr_path = f"{prefix}[]"
        if depth == max_depth:
            return out
        for item in value[:25]:
            if item is None:
                continue
            if isinstance(item, dict):
                _flatten_json_paths(
                    item, prefix=arr_path, depth=depth + 1, max_depth=max_depth, out=out
                )
            elif isinstance(item, list):
                _flatten_json_paths(
                    item, prefix=arr_path, depth=depth + 1, max_depth=max_depth, out=out
                )
            else:
                out.setdefault(arr_path, []).append(item)
        return out
    out.setdefault(prefix, []).append(value)
    return out


def _compact_scrubbed_doc(value: Any, secrets_to_scrub: list[str], *, depth: int = 0) -> Any:
    """Recursively scrub secrets and bound oversized strings for schema-on-read sample rows."""
    if depth > 5:
        return "..."
    if isinstance(value, str):
        return redact_secrets(value[:240], secrets_to_scrub)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for idx, (k, v) in enumerate(value.items()):
            if idx >= 24:
                break
            out[str(k)] = _compact_scrubbed_doc(v, secrets_to_scrub, depth=depth + 1)
        return out
    if isinstance(value, list):
        return [_compact_scrubbed_doc(item, secrets_to_scrub, depth=depth + 1) for item in value[:10]]
    return value


def user_workspace_namespace(email: str | None) -> tuple[str, str]:
    """Return normalized (owner_email, safe_directory_namespace) for multi-user file isolation."""
    clean_email = (email or "operator@local").strip().lower() or "operator@local"
    slug_part = (
        re.sub(
            r"[^a-z0-9_-]+",
            "-",
            clean_email.replace("@", "-at-").replace(".", "-"),
        ).strip("-")[:48]
        or "operator"
    )
    digest = hashlib.sha256(clean_email.encode("utf-8")).hexdigest()[:10]
    return clean_email, f"{slug_part}-{digest}"


def _ensure_desktop_tools(tools_list: list[Any]) -> list[Any]:
    """Ensure desktop bots always expose both Chromium CDP (desktop_browse) and Desktop MCP (desktop_mcp)."""
    updated = list(tools_list)
    for req_type, req_name in (("builtin", "desktop_browse"), ("mcp", "desktop_mcp")):
        present = any(
            t == req_name or (isinstance(t, dict) and t.get("name") == req_name)
            for t in updated
        )
        if not present:
            updated.append({"type": req_type, "name": req_name})
    return updated


def _ensure_sandbox_tools(tools_list: list[Any]) -> list[Any]:
    """Ensure headless script sandbox bots always expose sandbox_exec."""
    updated = list(tools_list)
    present = any(
        t == "sandbox_exec" or (isinstance(t, dict) and t.get("name") == "sandbox_exec")
        for t in updated
    )
    if not present:
        updated.append({"type": "builtin", "name": "sandbox_exec"})
    return updated


class ArgoRepository:
    """Thread-safe persistence methods across Argo's 5 Core Primitives."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        vault: SecretVault,
        workspace_files_root: str | Path | None = None,
    ) -> None:
        self._conn = conn
        self._vault = vault
        self._lock = threading.RLock()
        self._vault_secrets_cache: tuple[str, ...] | None = None
        self._sensitive_secrets_cache: tuple[str, ...] | None = None
        if workspace_files_root:
            self._workspace_files_root = Path(workspace_files_root)
        else:
            db_list = conn.execute("PRAGMA database_list").fetchall()
            db_file = str(db_list[0][2]) if db_list and len(db_list[0]) > 2 else ""
            if db_file and db_file != ":memory:":
                self._workspace_files_root = Path(db_file).resolve().parent / "workspace_files"
            else:
                self._workspace_files_root = Path("./data/workspace_files").resolve()
        db_list2 = conn.execute("PRAGMA database_list").fetchall()
        db_file2 = str(db_list2[0][2]) if db_list2 and len(db_list2[0]) > 2 else ""
        if db_file2 and db_file2 != ":memory:":
            self._analytics_root = (Path(db_file2).resolve().parent / "analytics").resolve()
        else:
            self._analytics_root = (self._workspace_files_root.resolve().parent / "analytics").resolve()

    @contextmanager
    def _tx(self) -> Iterator[None]:
        """Serialize SQLite write transactions under self._lock with automatic rollback on failure."""
        with self._lock:
            try:
                yield
                self._conn.commit()
            except BaseException:
                with contextlib.suppress(Exception):
                    self._conn.rollback()
                raise

    def analytics_dir_for_collection(self, collection: str) -> Path:
        """Return isolated analytics Parquet directory under <db_dir>/analytics/<slug>."""
        clean_coll = collection_slug(collection)
        target = (self._analytics_root / clean_coll).resolve()
        if not target.is_relative_to(self._analytics_root):
            raise ValueError("Invalid analytics collection path.")
        target.mkdir(parents=True, exist_ok=True)
        return target

    def workspace_tmp_dir(self) -> Path:
        """Return staging temp directory outside per-user namespaces for streamed uploads."""
        tmp_dir = (self._workspace_files_root.resolve() / ".tmp").resolve()
        tmp_dir.mkdir(parents=True, exist_ok=True)
        return tmp_dir

    def _ensure_collection_locked(
        self,
        slug: str,
        *,
        description: str = "Schema-less document collection",
        created_at: str | None = None,
    ) -> None:
        """Ensure a collection row exists without committing an outer transaction."""
        raw = str(slug or "").strip()
        if not raw or dataset_identifier(raw).startswith("file:"):
            return
        clean_coll = collection_slug(raw)
        self._conn.execute(
            """
            INSERT OR IGNORE INTO collections(slug, description, schema_hint_json, created_at)
            VALUES (?, ?, NULL, ?)
            """,
            (clean_coll, description, created_at or utc_now()),
        )

    def _register_collections_locked(
        self,
        collections_cfg: dict[str, Any] | None,
        *,
        owner_name: str,
        created_at: str | None = None,
    ) -> None:
        """Register non-internal collections declared on a bot card."""
        if not isinstance(collections_cfg, dict):
            return
        seen: set[str] = set()
        for bucket in ("read", "write"):
            for raw_slug in collections_cfg.get(bucket) or []:
                ds_id = dataset_identifier(str(raw_slug))
                if ds_id.startswith("file:"):
                    continue
                clean = collection_slug(str(raw_slug))
                if clean in _INTERNAL_SYSTEM_COLLECTIONS or clean in seen:
                    continue
                seen.add(clean)
                self._ensure_collection_locked(
                    clean,
                    description=f"Workspace data collection for {owner_name}",
                    created_at=created_at,
                )

    def check_wal_enabled(self) -> bool:
        """Return True if SQLite is operating in WAL journal mode."""
        with self._lock:
            row = self._conn.execute("PRAGMA journal_mode").fetchone()
            return bool(row and str(row[0]).lower() == "wal")

    def ensure_defaults(self) -> None:
        """Seed idempotent initial defaults (Gemini model entries and bot_threads collection)."""
        now = utc_now()
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM model_providers").fetchone()[0]
            if count == 0:
                defaults = [
                    (
                        make_id("mdl"),
                        "google_gemini_flash",
                        "google",
                        "google:gemini-3.8-flash",
                        None,
                        None,
                        1,
                        None,
                        100.0,
                        now,
                    ),
                    (
                        make_id("mdl"),
                        "google_gemini_argon",
                        "google",
                        "google:gemini-4-argon",
                        None,
                        None,
                        0,
                        None,
                        100.0,
                        now,
                    ),
                ]
                self._conn.executemany(
                    """
                    INSERT INTO model_providers(
                        id, slug, provider_type, model_id, api_base, encrypted_api_key,
                        is_default, daily_token_limit, monthly_budget_usd, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    defaults,
                )

            self._conn.execute(
                """
                INSERT OR IGNORE INTO collections(slug, description, schema_hint_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                ("bot_threads", "Direct 1:1 operator-to-bot message transcripts", None, now),
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO collections(slug, description, schema_hint_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                ("bot_skills", "Reusable skill playbooks saved from conversations", None, now),
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO collections(slug, description, schema_hint_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                ("ssh_audit_log", "Tamper-evident SSH terminal turn audit log", None, now),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Models & Execution Runs (Primitives 1B & 2)
    # ------------------------------------------------------------------
    def _usage_by_model_locked(self) -> dict[str, dict[str, float | int]]:
        """Aggregate today and month-to-date token/cost usage grouped by llm_model_used."""
        today_prefix = utc_now()[:10]
        month_prefix = today_prefix[:7]
        rows = self._conn.execute(
            """
            SELECT llm_model_used,
                   COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                   COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS today_cost,
                   COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS month_tokens,
                   COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS month_cost
            FROM bot_runs
            WHERE llm_model_used IS NOT NULL AND started_at >= ?
            GROUP BY llm_model_used
            """,
            (today_prefix, today_prefix, month_prefix, month_prefix, month_prefix),
        ).fetchall()
        return {
            row["llm_model_used"]: {
                "today_tokens": int(row["today_tokens"]),
                "today_cost_usd": round(float(row["today_cost"]), 6),
                "month_tokens": int(row["month_tokens"]),
                "month_cost_usd": round(float(row["month_cost"]), 6),
            }
            for row in rows
        }

    @staticmethod
    def _serialize_model_row(
        row: sqlite3.Row,
        usage: dict[str, float | int] | None = None,
    ) -> dict[str, Any]:
        from argo_core.llm.router import resolve_model_pricing

        stats = usage or {}
        row_keys = set(row.keys())
        custom_in = row["input_price_per_million"] if "input_price_per_million" in row_keys else None
        custom_out = row["output_price_per_million"] if "output_price_per_million" in row_keys else None
        resolved = resolve_model_pricing(
            row["model_id"],
            custom_input=custom_in,
            custom_output=custom_out,
        )
        return {
            "id": row["id"],
            "slug": row["slug"],
            "provider_type": row["provider_type"],
            "model_id": row["model_id"],
            "api_base": row["api_base"],
            "has_api_key": row["encrypted_api_key"] is not None,
            "is_default": bool(row["is_default"]),
            "daily_token_limit": row["daily_token_limit"],
            "monthly_budget_usd": row["monthly_budget_usd"],
            "input_price_per_million": float(custom_in) if custom_in is not None else None,
            "output_price_per_million": float(custom_out) if custom_out is not None else None,
            "effective_input_price_per_million": resolved["input_per_million"],
            "effective_output_price_per_million": resolved["output_per_million"],
            "pricing_source": resolved["source"],
            "today_tokens": int(stats.get("today_tokens", 0)),
            "today_cost_usd": float(stats.get("today_cost_usd", 0.0)),
            "month_tokens": int(stats.get("month_tokens", 0)),
            "month_cost_usd": float(stats.get("month_cost_usd", 0.0)),
            "created_at": row["created_at"],
        }

    def provider_usage_totals(self, model_id: str) -> dict[str, Any]:
        """Return today and month-to-date tokens/cost accumulated for a specific model_id."""
        with self._lock:
            stats = self._usage_by_model_locked().get(model_id)
        return stats or {
            "today_tokens": 0,
            "today_cost_usd": 0.0,
            "month_tokens": 0,
            "month_cost_usd": 0.0,
        }

    def provider_type_ephemeral_usage_totals(
        self,
        provider_type: str,
        *,
        parent_model_id: str | None = None,
    ) -> dict[str, Any]:
        """Aggregate usage for a parent model plus any unconfigured sibling models sharing provider_type."""
        clean_type = str(provider_type or "").strip().lower()
        prefix = f"{clean_type}:"
        with self._lock:
            per_model = self._usage_by_model_locked()
            rows = self._conn.execute(
                "SELECT model_id FROM model_providers WHERE LOWER(provider_type) = ?",
                (clean_type,),
            ).fetchall()
            explicit_models = {str(r["model_id"]) for r in rows}

        today_tokens = 0
        today_cost = 0.0
        month_tokens = 0
        month_cost = 0.0
        for mid, st in per_model.items():
            if mid == parent_model_id or (
                prefix and mid.lower().startswith(prefix) and mid not in explicit_models
            ):
                today_tokens += int(st.get("today_tokens", 0))
                today_cost += float(st.get("today_cost_usd", 0.0))
                month_tokens += int(st.get("month_tokens", 0))
                month_cost += float(st.get("month_cost_usd", 0.0))
        return {
            "today_tokens": today_tokens,
            "today_cost_usd": round(today_cost, 6),
            "month_tokens": month_tokens,
            "month_cost_usd": round(month_cost, 6),
        }

    def list_models(
        self,
        *,
        model_id: str | None = None,
        allowed_bot_slugs: set[str] | None = None,
        viewer_email: str | None = None,
    ) -> dict[str, Any]:
        """List configured LLM providers (redacting encrypted keys) and usage totals."""
        today_prefix = utc_now()[:10]
        month_prefix = today_prefix[:7]
        clean_model_filter = str(model_id or "").strip() or None
        clean_viewer = normalize_email(viewer_email) if viewer_email else ""

        scope_clauses = ["started_at >= ?"]
        scope_params: list[Any] = [month_prefix]
        if allowed_bot_slugs is not None or clean_viewer:
            or_parts: list[str] = []
            if allowed_bot_slugs is not None:
                if allowed_bot_slugs:
                    placeholders = ",".join("?" for _ in allowed_bot_slugs)
                    or_parts.append(f"bot_slug IN ({placeholders})")
                    scope_params.extend(sorted(allowed_bot_slugs))
                else:
                    or_parts.append("1 = 0")
            if clean_viewer:
                or_parts.append("LOWER(TRIM(triggered_by_email)) = ?")
                scope_params.append(clean_viewer)
            scope_clauses.append(f"({' OR '.join(or_parts)})")
        scope_where = f"WHERE {' AND '.join(scope_clauses)}"

        user_scope_clauses = ["started_at >= ?"]
        user_scope_params: list[Any] = [month_prefix]
        if clean_viewer:
            user_scope_clauses.append("LOWER(TRIM(triggered_by_email)) = ?")
            user_scope_params.append(clean_viewer)
        user_scope_where = f"WHERE {' AND '.join(user_scope_clauses)}"

        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd,
                       input_price_per_million, output_price_per_million, created_at
                FROM model_providers
                ORDER BY is_default DESC, created_at ASC
                """
            ).fetchall()

            per_model_usage = self._usage_by_model_locked()
            usage_row = self._conn.execute(
                f"""
                SELECT COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS today_cost,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS month_tokens,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS month_cost,
                       COALESCE(SUM(CASE WHEN started_at >= ? AND status = 'success' AND COALESCE(input_tokens, 0) = 0 AND COALESCE(output_tokens, 0) = 0 THEN 1 ELSE 0 END), 0) AS deduplicated_runs_today,
                       COALESCE(SUM(CASE WHEN started_at >= ? AND status = 'success' AND COALESCE(input_tokens, 0) = 0 AND COALESCE(output_tokens, 0) = 0 THEN 1 ELSE 0 END), 0) AS deduplicated_runs_month
                FROM bot_runs
                {scope_where}
                """,
                (
                    today_prefix,
                    today_prefix,
                    month_prefix,
                    month_prefix,
                    today_prefix,
                    month_prefix,
                    *scope_params,
                ),
            ).fetchone()
            bot_usage_rows = self._conn.execute(
                f"""
                SELECT bot_slug,
                       COUNT(*) AS runs_count,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(input_tokens + output_tokens), 0) AS month_tokens,
                       COALESCE(SUM(estimated_cost_usd), 0.0) AS month_cost
                FROM bot_runs
                {scope_where}
                GROUP BY bot_slug
                ORDER BY month_cost DESC, month_tokens DESC, runs_count DESC
                """,
                (today_prefix, *scope_params),
            ).fetchall()
            bot_model_rows = self._conn.execute(
                f"""
                SELECT bot_slug,
                       COALESCE(llm_model_used, 'unknown') AS model_id,
                       COUNT(*) AS runs_count,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(input_tokens + output_tokens), 0) AS month_tokens,
                       COALESCE(SUM(estimated_cost_usd), 0.0) AS month_cost
                FROM bot_runs
                {scope_where}
                GROUP BY bot_slug, COALESCE(llm_model_used, 'unknown')
                ORDER BY month_cost DESC, month_tokens DESC, runs_count DESC
                """,
                (today_prefix, *scope_params),
            ).fetchall()
            bot_trigger_rows = self._conn.execute(
                f"""
                SELECT bot_slug, trigger_type, COUNT(*) AS cnt
                FROM bot_runs
                {scope_where}
                GROUP BY bot_slug, trigger_type
                ORDER BY cnt DESC
                """,
                tuple(scope_params),
            ).fetchall()
            user_usage_rows = self._conn.execute(
                f"""
                SELECT COALESCE(NULLIF(LOWER(TRIM(triggered_by_email)), ''), 'workspace') AS user_email,
                       COUNT(*) AS runs_count,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(input_tokens + output_tokens), 0) AS month_tokens,
                       COALESCE(SUM(estimated_cost_usd), 0.0) AS month_cost
                FROM bot_runs
                {user_scope_where}
                GROUP BY COALESCE(NULLIF(LOWER(TRIM(triggered_by_email)), ''), 'workspace')
                ORDER BY month_cost DESC, month_tokens DESC, runs_count DESC
                """,
                (today_prefix, *user_scope_params),
            ).fetchall()
            bot_meta_rows = self._conn.execute(
                "SELECT slug, name, enabled, card_json FROM bots"
            ).fetchall()

        top_trigger_by_bot: dict[str, str] = {}
        for trow in bot_trigger_rows:
            if trow["bot_slug"] not in top_trigger_by_bot:
                top_trigger_by_bot[trow["bot_slug"]] = str(trow["trigger_type"])

        models_by_bot: dict[str, list[dict[str, Any]]] = {}
        for mrow in bot_model_rows:
            models_by_bot.setdefault(mrow["bot_slug"], []).append(
                {
                    "model_id": str(mrow["model_id"]),
                    "runs_count": int(mrow["runs_count"]),
                    "today_tokens": int(mrow["today_tokens"]),
                    "month_tokens": int(mrow["month_tokens"]),
                    "month_cost_usd": round(float(mrow["month_cost"]), 6),
                }
            )

        bot_lookup: dict[str, dict[str, Any]] = {}
        for brow in bot_meta_rows:
            try:
                card = json.loads(brow["card_json"])
            except Exception:
                card = {}
            bot_lookup[brow["slug"]] = {
                "name": brow["name"],
                "enabled": bool(brow["enabled"]),
                "model": card.get("model", "google:gemini-3.8-flash"),
            }

        usage_by_bot = [
            {
                "bot_slug": row["bot_slug"],
                "bot_name": (bot_lookup.get(row["bot_slug"]) or {}).get("name") or row["bot_slug"],
                "model": (bot_lookup.get(row["bot_slug"]) or {}).get("model") or "",
                "enabled": (bot_lookup.get(row["bot_slug"]) or {}).get("enabled", False),
                "exists": row["bot_slug"] in bot_lookup,
                "runs_count": int(row["runs_count"]),
                "today_tokens": int(row["today_tokens"]),
                "month_tokens": int(row["month_tokens"]),
                "month_cost_usd": round(float(row["month_cost"]), 6),
                "top_trigger_type": top_trigger_by_bot.get(row["bot_slug"], "manual"),
                "models_used": models_by_bot.get(row["bot_slug"], []),
            }
            for row in bot_usage_rows
        ]
        usage_by_user = [
            {
                "email": str(urow["user_email"]),
                "runs_count": int(urow["runs_count"]),
                "today_tokens": int(urow["today_tokens"]),
                "month_tokens": int(urow["month_tokens"]),
                "month_cost_usd": round(float(urow["month_cost"]), 6),
            }
            for urow in user_usage_rows
        ]

        providers = [
            self._serialize_model_row(row, per_model_usage.get(row["model_id"]))
            for row in rows
        ]
        recent_runs = self.list_bot_runs(
            model_id=clean_model_filter,
            allowed_bot_slugs=allowed_bot_slugs,
            triggered_by_email=clean_viewer or None,
            limit=30,
        )
        return {
            "providers": providers,
            "today_tokens": int(usage_row["today_tokens"]) if usage_row else 0,
            "today_cost_usd": round(float(usage_row["today_cost"]), 4) if usage_row else 0.0,
            "month_tokens": int(usage_row["month_tokens"]) if usage_row else 0,
            "month_cost_usd": round(float(usage_row["month_cost"]), 4) if usage_row else 0.0,
            "deduplicated_runs_today": int(usage_row["deduplicated_runs_today"]) if usage_row else 0,
            "deduplicated_runs_month": int(usage_row["deduplicated_runs_month"]) if usage_row else 0,
            "recent_runs": recent_runs,
            "usage_by_bot": usage_by_bot,
            "usage_by_user": usage_by_user,
        }

    def list_model_provider_credentials(self) -> list[dict[str, Any]]:
        """Internal-only helper returning model providers with decrypted API keys."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd,
                       input_price_per_million, output_price_per_million, created_at
                FROM model_providers
                ORDER BY is_default DESC, created_at ASC
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            api_key = (
                self._vault.decrypt_str(row["encrypted_api_key"])
                if row["encrypted_api_key"] is not None
                else None
            )
            result.append(
                {
                    "id": row["id"],
                    "slug": row["slug"],
                    "provider_type": row["provider_type"],
                    "model_id": row["model_id"],
                    "api_base": row["api_base"],
                    "api_key": api_key,
                    "is_default": bool(row["is_default"]),
                    "daily_token_limit": row["daily_token_limit"],
                    "monthly_budget_usd": row["monthly_budget_usd"],
                    "input_price_per_million": (
                        float(row["input_price_per_million"])
                        if row["input_price_per_million"] is not None
                        else None
                    ),
                    "output_price_per_million": (
                        float(row["output_price_per_million"])
                        if row["output_price_per_million"] is not None
                        else None
                    ),
                    "created_at": row["created_at"],
                }
            )
        return result

    def get_model_provider_credentials(self, slug_or_model_id: str) -> dict[str, Any] | None:
        """Internal-only lookup matching exact slug, normalized slug, or model_id."""
        norm = slugify(slug_or_model_id)
        for item in self.list_model_provider_credentials():
            if (
                item["slug"] == slug_or_model_id
                or item["slug"] == norm
                or item["model_id"] == slug_or_model_id
            ):
                return item
        return None

    def upsert_model(
        self,
        *,
        slug: str,
        provider_type: str,
        model_id: str,
        api_base: str | None = None,
        api_key: str | None = None,
        is_default: bool = False,
        daily_token_limit: int | None = None,
        monthly_budget_usd: float | None = None,
        input_price_per_million: float | None = None,
        output_price_per_million: float | None = None,
    ) -> dict[str, Any]:
        """Create or update an LLM provider configuration with encrypted API key storage."""
        now = utc_now()
        clean_slug = slugify(slug)
        encrypted_key = (
            self._vault.encrypt_str(api_key.strip())
            if api_key and api_key.strip()
            else None
        )

        with self._lock:
            existing = self._conn.execute(
                "SELECT slug FROM model_providers WHERE slug = ? OR slug = ?",
                (slug, clean_slug),
            ).fetchone()
            target_slug = existing["slug"] if existing else clean_slug

            if is_default:
                self._conn.execute("UPDATE model_providers SET is_default = 0")

            self._conn.execute(
                """
                INSERT INTO model_providers(
                    id, slug, provider_type, model_id, api_base, encrypted_api_key,
                    is_default, daily_token_limit, monthly_budget_usd,
                    input_price_per_million, output_price_per_million, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    provider_type = excluded.provider_type,
                    model_id = excluded.model_id,
                    api_base = excluded.api_base,
                    encrypted_api_key = COALESCE(excluded.encrypted_api_key, model_providers.encrypted_api_key),
                    is_default = excluded.is_default,
                    daily_token_limit = excluded.daily_token_limit,
                    monthly_budget_usd = excluded.monthly_budget_usd,
                    input_price_per_million = excluded.input_price_per_million,
                    output_price_per_million = excluded.output_price_per_million
                """,
                (
                    make_id("mdl"),
                    target_slug,
                    provider_type,
                    model_id,
                    api_base.strip() if api_base and api_base.strip() else None,
                    encrypted_key,
                    1 if is_default else 0,
                    daily_token_limit,
                    monthly_budget_usd,
                    input_price_per_million,
                    output_price_per_million,
                    now,
                ),
            )
            self._conn.commit()
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None
            row = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd,
                       input_price_per_million, output_price_per_million, created_at
                FROM model_providers WHERE slug = ?
                """,
                (target_slug,),
            ).fetchone()
            usage = self._usage_by_model_locked().get(row["model_id"])

        return self._serialize_model_row(row, usage)

    def set_default_model(self, slug: str) -> dict[str, Any]:
        """Promote a configured model provider to active default."""
        norm = slugify(slug)
        with self._lock:
            row = self._conn.execute(
                "SELECT slug FROM model_providers WHERE slug = ? OR slug = ?",
                (slug, norm),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Model provider '{slug}' not found.")
            target_slug = row["slug"]
            self._conn.execute("UPDATE model_providers SET is_default = 0")
            self._conn.execute(
                "UPDATE model_providers SET is_default = 1 WHERE slug = ?",
                (target_slug,),
            )
            self._conn.commit()
            updated = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd,
                       input_price_per_million, output_price_per_million, created_at
                FROM model_providers WHERE slug = ?
                """,
                (target_slug,),
            ).fetchone()
            usage = self._usage_by_model_locked().get(updated["model_id"])
        return self._serialize_model_row(updated, usage)

    def delete_model(self, slug: str) -> None:
        """Delete a model provider record by slug."""
        norm = slugify(slug)
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM model_providers WHERE slug = ? OR slug = ?",
                (slug, norm),
            )
            self._conn.commit()
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None
            if cursor.rowcount == 0:
                raise NotFoundError(f"Model provider '{slug}' not found.")

    def record_bot_run(
        self,
        *,
        correlation_id: str,
        bot_slug: str,
        trigger_type: str,
        hop_count: int = 1,
        llm_model_used: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
        status: str = "success",
        summary: str | None = None,
        triggered_by_email: str = "",
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        """Persist an execution audit record with token and cost accounting into bot_runs."""
        run_id = make_id("run")
        start_ts = started_at or utc_now()
        end_ts = finished_at or utc_now()
        clean_trigger_email = normalize_email(triggered_by_email)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO bot_runs(
                    id, correlation_id, bot_slug, trigger_type, hop_count,
                    llm_model_used, input_tokens, output_tokens, estimated_cost_usd,
                    status, summary, triggered_by_email, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    correlation_id,
                    bot_slug,
                    trigger_type,
                    int(hop_count),
                    llm_model_used,
                    int(input_tokens),
                    int(output_tokens),
                    round(float(estimated_cost_usd), 6),
                    status,
                    summary,
                    clean_trigger_email,
                    start_ts,
                    end_ts,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM bot_runs WHERE id = ?", (run_id,)).fetchone()
        row_keys = set(row.keys())
        return {
            "id": row["id"],
            "correlation_id": row["correlation_id"],
            "bot_slug": row["bot_slug"],
            "trigger_type": row["trigger_type"],
            "hop_count": int(row["hop_count"]),
            "llm_model_used": row["llm_model_used"],
            "input_tokens": int(row["input_tokens"] or 0),
            "output_tokens": int(row["output_tokens"] or 0),
            "estimated_cost_usd": float(row["estimated_cost_usd"] or 0.0),
            "status": row["status"],
            "summary": row["summary"],
            "triggered_by_email": str(row["triggered_by_email"] or "") if "triggered_by_email" in row_keys else "",
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }

    def list_bot_runs(
        self,
        *,
        bot_slug: str | None = None,
        model_id: str | None = None,
        allowed_bot_slugs: set[str] | None = None,
        triggered_by_email: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List recent bot_runs execution and token accounting records newest first."""
        capped = max(1, min(limit, 200))
        clauses: list[str] = []
        params: list[Any] = []
        if bot_slug:
            clauses.append("bot_slug = ?")
            params.append(bot_slug)
        if model_id:
            clauses.append("llm_model_used = ?")
            params.append(model_id)
        clean_trigger_filter = normalize_email(triggered_by_email) if triggered_by_email else ""
        if allowed_bot_slugs is not None or clean_trigger_filter:
            or_parts: list[str] = []
            if allowed_bot_slugs is not None:
                if allowed_bot_slugs:
                    placeholders = ",".join("?" for _ in allowed_bot_slugs)
                    or_parts.append(f"bot_slug IN ({placeholders})")
                    params.extend(sorted(allowed_bot_slugs))
                else:
                    or_parts.append("1 = 0")
            if clean_trigger_filter:
                or_parts.append("LOWER(TRIM(triggered_by_email)) = ?")
                params.append(clean_trigger_filter)
            clauses.append(f"({' OR '.join(or_parts)})")
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(capped)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM bot_runs
                {where_sql}
                ORDER BY started_at DESC, rowid DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            row_keys = set(row.keys())
            out.append(
                {
                    "id": row["id"],
                    "correlation_id": row["correlation_id"],
                    "bot_slug": row["bot_slug"],
                    "trigger_type": row["trigger_type"],
                    "hop_count": int(row["hop_count"]),
                    "llm_model_used": row["llm_model_used"],
                    "input_tokens": int(row["input_tokens"] or 0),
                    "output_tokens": int(row["output_tokens"] or 0),
                    "estimated_cost_usd": float(row["estimated_cost_usd"] or 0.0),
                    "status": row["status"],
                    "summary": row["summary"],
                    "triggered_by_email": str(row["triggered_by_email"] or "") if "triggered_by_email" in row_keys else "",
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                }
            )
        return out

    # ------------------------------------------------------------------
    # Integrations (Primitive 1)
    # ------------------------------------------------------------------
    @staticmethod
    def _decode_groups(raw: Any) -> list[str]:
        if isinstance(raw, list):
            return normalize_group_slugs(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                return normalize_group_slugs(parsed)
            except Exception:
                return []
        return []

    @classmethod
    def _serialize_integration_row(cls, row: sqlite3.Row) -> dict[str, Any]:
        row_keys = set(row.keys())
        vis = normalize_visibility(
            row["visibility"] if "visibility" in row_keys else "shared", default="shared"
        )
        groups = (
            cls._decode_groups(row["allowed_groups_json"])
            if "allowed_groups_json" in row_keys and vis == "team"
            else []
        )
        return {
            "id": row["id"],
            "slug": row["slug"],
            "provider": row["provider"],
            "display_name": row["display_name"],
            "account_identifier": row["account_identifier"],
            "scopes": json.loads(row["scopes_json"]),
            "status": row["status"],
            "has_secrets": bool(row["encrypted_secrets"]),
            "last_checked_at": row["last_checked_at"],
            "last_error": row["last_error"],
            "owner_email": normalize_email(row["owner_email"]) if "owner_email" in row_keys else "",
            "visibility": vis,
            "allowed_groups": groups,
            "created_at": row["created_at"],
        }

    def list_integrations(self) -> list[dict[str, Any]]:
        """List connected accounts/channels without exposing encrypted secrets."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, owner_email, visibility, allowed_groups_json, created_at
                FROM oauth_accounts
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._serialize_integration_row(row) for row in rows]

    def find_integration_secrets(self, slug: str) -> dict[str, Any] | None:
        """Internal-only lookup returning decrypted oauth_accounts secrets by slug or None."""
        norm = slugify(slug)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, owner_email, visibility, allowed_groups_json, created_at
                FROM oauth_accounts
                WHERE slug = ? OR slug = ?
                """,
                (slug, norm),
            ).fetchone()
        if row is None:
            return None
        decrypted = (
            self._vault.decrypt_json(row["encrypted_secrets"])
            if row["encrypted_secrets"]
            else {}
        )
        return {
            **self._serialize_integration_row(row),
            "secrets": decrypted,
        }

    def get_integration_secrets(self, slug: str) -> dict[str, Any]:
        """Internal-only lookup decrypting oauth_accounts secrets by slug."""
        found = self.find_integration_secrets(slug)
        if found is None:
            raise NotFoundError(f"Integration '{slug}' not found.")
        return found

    def list_integrations_by_provider(self, provider: str) -> list[dict[str, Any]]:
        """Internal-only listing of connector accounts for a provider with decrypted secrets."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, owner_email, visibility, allowed_groups_json, created_at
                FROM oauth_accounts
                WHERE provider = ?
                ORDER BY created_at ASC
                """,
                (provider,),
            ).fetchall()
        accounts: list[dict[str, Any]] = []
        for row in rows:
            decrypted = (
                self._vault.decrypt_json(row["encrypted_secrets"])
                if row["encrypted_secrets"]
                else {}
            )
            accounts.append(
                {
                    **self._serialize_integration_row(row),
                    "secrets": decrypted,
                }
            )
        return accounts

    def list_telegram_integrations(self) -> list[dict[str, Any]]:
        """Internal-only listing of Telegram connector accounts with decrypted secrets."""
        return self.list_integrations_by_provider("telegram")

    def upsert_integration(
        self,
        *,
        slug: str,
        provider: str,
        display_name: str,
        account_identifier: str | None = None,
        scopes: list[str] | None = None,
        secrets: dict[str, Any] | None = None,
        status: str = "ok",
        owner_email: str | None = None,
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create or update an integration account with Fernet-encrypted credentials."""
        now = utc_now()
        clean_slug = slugify(slug)
        scopes_json = json.dumps(scopes or [])

        with self._lock:
            existing = self._conn.execute(
                "SELECT encrypted_secrets, owner_email, visibility, allowed_groups_json FROM oauth_accounts WHERE slug = ?",
                (clean_slug,),
            ).fetchone()
            merged_secrets: dict[str, Any] = {}
            if existing and existing["encrypted_secrets"]:
                merged_secrets = self._vault.decrypt_json(existing["encrypted_secrets"])
            if secrets:
                merged_secrets.update(secrets)

            existing_keys = set(existing.keys()) if existing else set()
            existing_owner = (
                normalize_email(existing["owner_email"])
                if existing and "owner_email" in existing_keys
                else ""
            )
            existing_vis = (
                normalize_visibility(existing["visibility"], default="shared")
                if existing and "visibility" in existing_keys
                else "shared"
            )
            existing_groups = (
                self._decode_groups(existing["allowed_groups_json"])
                if existing and "allowed_groups_json" in existing_keys
                else []
            )
            resolved_owner = (
                normalize_email(owner_email) if owner_email is not None else existing_owner
            )
            resolved_vis = (
                normalize_visibility(visibility) if visibility is not None else existing_vis
            )
            if resolved_vis != "team":
                resolved_groups: list[str] = []
            elif allowed_groups is not None:
                resolved_groups = normalize_group_slugs(allowed_groups)
            else:
                resolved_groups = existing_groups

            encrypted_blob = self._vault.encrypt_json(merged_secrets)
            self._conn.execute(
                """
                INSERT INTO oauth_accounts(
                    id, slug, provider, display_name, account_identifier,
                    scopes_json, encrypted_secrets, status, last_checked_at,
                    last_error, owner_email, visibility, allowed_groups_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    provider = excluded.provider,
                    display_name = excluded.display_name,
                    account_identifier = excluded.account_identifier,
                    scopes_json = excluded.scopes_json,
                    encrypted_secrets = excluded.encrypted_secrets,
                    status = excluded.status,
                    last_checked_at = excluded.last_checked_at,
                    last_error = NULL,
                    owner_email = excluded.owner_email,
                    visibility = excluded.visibility,
                    allowed_groups_json = excluded.allowed_groups_json
                """,
                (
                    make_id("int"),
                    clean_slug,
                    provider,
                    display_name,
                    account_identifier,
                    scopes_json,
                    encrypted_blob,
                    status,
                    now,
                    None,
                    resolved_owner,
                    resolved_vis,
                    json.dumps(resolved_groups),
                    now,
                ),
            )
            if provider == "telegram":
                self._ensure_collection_locked(
                    "telegram_channel_posts",
                    description="Incoming Telegram channel posts and bot messages",
                    created_at=now,
                )
            self._conn.commit()
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None
            row = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, owner_email, visibility, allowed_groups_json, created_at
                FROM oauth_accounts WHERE slug = ?
                """,
                (clean_slug,),
            ).fetchone()

        return self._serialize_integration_row(row)

    def update_integration_health(
        self,
        slug: str,
        *,
        status: str,
        last_error: str | None = None,
    ) -> dict[str, Any]:
        """Record connector health probe outcome (ok | degraded | expired)."""
        now = utc_now()
        norm = slugify(slug)
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE oauth_accounts
                SET status = ?, last_checked_at = ?, last_error = ?
                WHERE slug = ? OR slug = ?
                """,
                (status, now, last_error, slug, norm),
            )
            if cursor.rowcount == 0:
                raise NotFoundError(f"Integration '{slug}' not found.")
            self._conn.commit()
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None
            row = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, owner_email, visibility, allowed_groups_json, created_at
                FROM oauth_accounts WHERE slug = ? OR slug = ?
                """,
                (slug, norm),
            ).fetchone()
        return self._serialize_integration_row(row)

    def delete_integration(self, slug: str) -> None:
        """Delete an integration connector by slug."""
        norm = slugify(slug)
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM oauth_accounts WHERE slug = ? OR slug = ?",
                (slug, norm),
            )
            self._conn.commit()
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None
            if cursor.rowcount == 0:
                raise NotFoundError(f"Integration '{slug}' not found.")

    # ------------------------------------------------------------------
    # Bots & Threads (Primitive 2 + Collection "bot_threads")
    # ------------------------------------------------------------------
    def _serialize_bot(self, row: sqlite3.Row) -> dict[str, Any]:
        card = json.loads(row["card_json"])
        raw_runtime = str(card.get("runtime") or "").strip().lower()
        if raw_runtime in {"api", "sandbox", "desktop"}:
            runtime = raw_runtime
        elif card.get("desktop_policy", "disabled") != "disabled":
            runtime = "desktop"
        elif card.get("sandbox_policy", "disabled") != "disabled":
            runtime = "sandbox"
        else:
            runtime = "api"
        tools_list = list(card.get("tools", []) or [])
        account_tools = [
            slugify(str(t.get("slug") or t.get("account") or ""))
            for t in tools_list
            if isinstance(t, dict)
            and t.get("type") in {"account", "connector"}
            and str(t.get("slug") or t.get("account") or "").strip()
        ]
        if isinstance(card.get("linked_accounts"), list):
            linked_accounts = list(
                dict.fromkeys(slugify(str(a)) for a in card["linked_accounts"] if str(a).strip())
            )
            linked_restricted = bool(card.get("linked_accounts_restricted", True))
        else:
            linked_accounts = list(dict.fromkeys(account_tools))
            linked_restricted = bool(card.get("linked_accounts_restricted") or account_tools)
        raw_boundaries = card.get("boundaries")
        boundaries = (
            [str(b).strip() for b in raw_boundaries if str(b).strip()]
            if isinstance(raw_boundaries, list)
            else []
        )
        row_keys = set(row.keys())
        owner_email = normalize_email(
            (row["owner_email"] if "owner_email" in row_keys else None)
            or card.get("owner_email")
        )
        visibility = normalize_visibility(
            (row["visibility"] if "visibility" in row_keys else None)
            or card.get("visibility"),
            default="shared",
        )
        raw_groups = (
            self._decode_groups(row["allowed_groups_json"])
            if "allowed_groups_json" in row_keys
            else normalize_group_slugs(card.get("allowed_groups"))
        )
        allowed_groups = raw_groups if visibility == "team" else []
        return {
            "id": row["id"],
            "slug": row["slug"],
            "name": row["name"],
            "initials": card.get("initials", _initials(row["name"])),
            "avatar_color": str(card.get("avatar_color") or "slate"),
            "avatar_icon": str(card.get("avatar_icon") or "bot"),
            "pinned": bool(card.get("pinned", False)),
            "section": str(card.get("section") or ""),
            "hidden_in_sidebar": bool(card.get("hidden_in_sidebar", False)),
            "boundaries": boundaries,
            "goal_metric": str(card.get("goal_metric") or ""),
            "handoff_bot_slug": str(card.get("handoff_bot_slug") or ""),
            "owner_email": owner_email,
            "visibility": visibility,
            "allowed_groups": allowed_groups,
            "role": row["role"],
            "enabled": bool(row["enabled"]),
            "runtime": runtime,
            "desktop_policy": card.get("desktop_policy", "disabled"),
            "desktop_state": card.get("desktop_state", "none"),
            "sandbox_policy": card.get(
                "sandbox_policy", "on_demand" if runtime == "sandbox" else "disabled"
            ),
            "sandbox_state": card.get(
                "sandbox_state", "hibernated" if runtime == "sandbox" else "none"
            ),
            "ram_mb": int(card.get("ram_mb", 0)),
            "ram_limit_mb": int(card.get("ram_limit_mb", 512 if runtime == "sandbox" else 2048)),
            "outbound_rbac": card.get("outbound_rbac", "draft"),
            "daily_cap": int(card.get("daily_cap", 10)),
            "max_steps_per_run": max(3, min(25, int(card.get("max_steps_per_run", 10) or 10))),
            "model": card.get("model", "google:gemini-3.8-flash"),
            "role_prompt": card.get("role_prompt", row["role"]),
            "routines": card.get("routines", []),
            "permissions": card.get("permissions", []),
            "tools": tools_list,
            "linked_accounts": linked_accounts,
            "linked_accounts_restricted": linked_restricted,
            "collections": card.get("collections", {"read": [], "write": []}),
            "onboarding_pending": bool(card.get("onboarding_pending", False)),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_bots(self) -> list[dict[str, Any]]:
        """List all declarative bot definitions."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, name, role, enabled, card_json, owner_email, visibility, allowed_groups_json, created_at, updated_at
                FROM bots ORDER BY created_at ASC
                """
            ).fetchall()
        return [self._serialize_bot(row) for row in rows]

    def get_bot(self, slug: str) -> dict[str, Any]:
        """Fetch a single declarative bot by slug."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, slug, name, role, enabled, card_json, owner_email, visibility, allowed_groups_json, created_at, updated_at
                FROM bots WHERE slug = ?
                """,
                (slug,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"Bot '{slug}' not found.")
        return self._serialize_bot(row)

    @staticmethod
    def _normalize_routines(routines: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        if not routines:
            return [
                {
                    "id": make_id("rtn"),
                    "type": "cron",
                    "label": "Scheduled Sync",
                    "schedule": "Every 15m",
                    "timezone": "UTC",
                    "enabled": True,
                }
            ]
        normalized: list[dict[str, Any]] = []
        for idx, item in enumerate(routines):
            if not isinstance(item, dict):
                continue
            r_type = str(item.get("type") or ("on_event" if item.get("event") else "cron"))
            stale_policy = str(item.get("stale_data_policy") or "skip_quietly").strip()
            if stale_policy not in {"skip_quietly", "notify_missing", "always_run"}:
                stale_policy = "skip_quietly"
            skill_slugs = [
                slugify(str(s))
                for s in (item.get("skill_slugs") or [])
                if str(s).strip()
            ]
            sched_raw = str(
                item.get("schedule")
                or (
                    f"on:{item['event']}"
                    if r_type == "on_event" and item.get("event")
                    else "Manual"
                )
            ).strip()
            tz_val = str(item.get("timezone") or "UTC").strip() or "UTC"
            one_shot_flag = bool(item.get("one_shot", False)) or r_type == "once"
            if r_type != "on_event" and re.match(r"^(?:once\s+)?in\s+\d+\s*[smh]\b", sched_raw, re.IGNORECASE):
                from argo_core.runner.scheduler import parse_routine_schedule

                parsed_rel = parse_routine_schedule(sched_raw, tz_val)
                if parsed_rel and parsed_rel.get("kind") == "date" and parsed_rel.get("normalized"):
                    sched_raw = str(parsed_rel["normalized"])
                    r_type = "once"
                    one_shot_flag = True
            entry: dict[str, Any] = {
                **item,
                "id": str(item.get("id") or make_id("rtn")),
                "type": r_type,
                "label": str(
                    item.get("label")
                    or (
                        f"On {item['event']}"
                        if r_type == "on_event" and item.get("event")
                        else f"Routine {idx + 1}"
                    )
                ),
                "schedule": sched_raw,
                "timezone": tz_val,
                "enabled": bool(item.get("enabled", True)),
            }
            if one_shot_flag:
                entry["one_shot"] = True
            if item.get("prompt"):
                entry["prompt"] = str(item["prompt"]).strip()
            if skill_slugs:
                entry["skill_slugs"] = list(dict.fromkeys(skill_slugs))
            if stale_policy != "skip_quietly" or "stale_data_policy" in item:
                entry["stale_data_policy"] = stale_policy
            normalized.append(entry)
        return normalized

    @staticmethod
    def _normalize_collections(collections: dict[str, list[str]] | None) -> dict[str, list[str]]:
        if not collections:
            return {"read": ["bot_threads"], "write": []}
        read_forbidden = _READ_FORBIDDEN_SYSTEM_COLLECTIONS - {"bot_threads"}
        read_list = list(
            dict.fromkeys(
                norm
                for c in collections.get("read", [])
                if str(c).strip()
                for norm in (dataset_identifier(str(c)),)
                if norm not in read_forbidden
            )
        )
        write_list = list(
            dict.fromkeys(
                norm
                for c in collections.get("write", [])
                if str(c).strip()
                for norm in (collection_slug(str(c)),)
                if norm not in _INTERNAL_SYSTEM_COLLECTIONS
            )
        )
        return {"read": read_list, "write": write_list}

    @staticmethod
    def _apply_linked_accounts(
        tools: list[Any],
        linked_accounts: list[str] | None,
        *,
        outbound_rbac: str,
        daily_cap: int,
    ) -> list[Any]:
        if linked_accounts is None:
            return list(tools)
        existing_account_meta: dict[str, dict[str, Any]] = {}
        preserved_tools: list[Any] = []
        for tool in tools:
            if isinstance(tool, dict) and tool.get("type") in {"account", "connector"}:
                acc_slug = slugify(str(tool.get("slug") or tool.get("account") or ""))
                if acc_slug:
                    existing_account_meta[acc_slug] = dict(tool)
            else:
                preserved_tools.append(tool)

        seen: set[str] = set()
        for raw_slug in linked_accounts:
            clean_slug = slugify(str(raw_slug))
            if not raw_slug or not str(raw_slug).strip() or clean_slug in seen:
                continue
            seen.add(clean_slug)
            meta = dict(existing_account_meta.get(clean_slug) or {})
            meta["type"] = "account"
            meta["slug"] = clean_slug
            if outbound_rbac == "internal":
                meta["capability"] = "read"
                meta["max_calls_per_day"] = 0
            else:
                meta.setdefault("capability", outbound_rbac)
                meta.setdefault("max_calls_per_day", daily_cap if outbound_rbac == "execute" else 0)
            preserved_tools.append(meta)
        return preserved_tools

    def create_bot(
        self,
        *,
        name: str,
        role: str,
        runtime: str = "api",
        outbound_rbac: str = "draft",
        model: str = "google:gemini-3.8-flash",
        daily_cap: int = 10,
        max_steps_per_run: int = 10,
        slug: str | None = None,
        role_prompt: str | None = None,
        routines: list[dict[str, Any]] | None = None,
        tools: list[Any] | None = None,
        collections: dict[str, list[str]] | None = None,
        linked_accounts: list[str] | None = None,
        avatar_color: str = "slate",
        avatar_icon: str = "bot",
        pinned: bool = False,
        section: str = "",
        hidden_in_sidebar: bool = False,
        boundaries: list[str] | None = None,
        goal_metric: str = "",
        handoff_bot_slug: str = "",
        onboarding_mode: str = "configured",
        owner_email: str = "",
        visibility: str = "shared",
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register a new declarative bot record in SQLite without code edits or rebuilds."""
        now = utc_now()
        clean_owner = normalize_email(owner_email)
        clean_visibility = normalize_visibility(visibility, default="shared")
        clean_allowed_groups = (
            normalize_group_slugs(allowed_groups) if clean_visibility == "team" else []
        )
        runtime = str(runtime or "api").strip().lower()
        if runtime not in {"api", "sandbox", "desktop"}:
            runtime = "api"
        base_slug = slugify(slug or name)
        desktop_policy = "on_demand" if runtime == "desktop" else "disabled"
        desktop_state = "hibernated" if runtime == "desktop" else "none"
        sandbox_policy = "on_demand" if runtime == "sandbox" else "disabled"
        sandbox_state = "hibernated" if runtime == "sandbox" else "none"
        ram_limit_mb = 512 if runtime == "sandbox" else 2048
        effective_cap = daily_cap if outbound_rbac == "execute" else (daily_cap if outbound_rbac == "draft" else 0)
        resolved_prompt = (role_prompt or role).strip()
        is_interview = onboarding_mode == "interview"
        effective_routines = routines
        if effective_routines is None and is_interview:
            effective_routines = [
                {
                    "id": make_id("rtn"),
                    "type": "manual_trigger",
                    "label": "Manual Run",
                    "schedule": "Manual",
                    "timezone": "UTC",
                    "enabled": True,
                }
            ]
        resolved_routines = self._normalize_routines(effective_routines)
        base_tools = (
            list(tools)
            if tools is not None
            else [{"type": "builtin", "name": "request_human_approval"}]
        )
        resolved_tools = self._apply_linked_accounts(
            base_tools,
            linked_accounts,
            outbound_rbac=outbound_rbac,
            daily_cap=effective_cap,
        )
        if runtime == "desktop":
            resolved_tools = _ensure_desktop_tools(resolved_tools)
        elif runtime == "sandbox":
            resolved_tools = _ensure_sandbox_tools(resolved_tools)
        clean_boundaries = [
            str(b).strip() for b in (boundaries or []) if str(b).strip()
        ]

        with self._lock:
            candidate_slug = base_slug
            suffix = 2
            while self._conn.execute(
                "SELECT 1 FROM bots WHERE slug = ?", (candidate_slug,)
            ).fetchone():
                candidate_slug = f"{base_slug}-{suffix}"
                suffix += 1

            default_items_col = collection_slug(f"bot_{candidate_slug}_items")
            resolved_collections = (
                self._normalize_collections(collections)
                if collections is not None
                else {
                    "read": ["bot_threads", default_items_col],
                    "write": [default_items_col],
                }
            )

            card = {
                "slug": candidate_slug,
                "name": name.strip(),
                "initials": _initials(name),
                "avatar_color": (avatar_color or "slate").strip(),
                "avatar_icon": (avatar_icon or "bot").strip(),
                "pinned": bool(pinned),
                "section": (section or "").strip(),
                "hidden_in_sidebar": bool(hidden_in_sidebar),
                "boundaries": clean_boundaries,
                "goal_metric": (goal_metric or "").strip(),
                "handoff_bot_slug": slugify(handoff_bot_slug) if handoff_bot_slug and handoff_bot_slug.strip() else "",
                "owner_email": clean_owner,
                "visibility": clean_visibility,
                "allowed_groups": clean_allowed_groups,
                "role": role.strip(),
                "enabled": True,
                "model": model,
                "runtime": runtime,
                "desktop_policy": desktop_policy,
                "desktop_state": desktop_state,
                "sandbox_policy": sandbox_policy,
                "sandbox_state": sandbox_state,
                "ram_mb": 0,
                "ram_limit_mb": ram_limit_mb,
                "outbound_rbac": outbound_rbac,
                "daily_cap": effective_cap,
                "max_steps_per_run": max(3, min(25, int(max_steps_per_run or 10))),
                "role_prompt": resolved_prompt,
                "routines": resolved_routines,
                "permissions": _default_permissions(outbound_rbac, runtime),
                "tools": resolved_tools,
                "collections": resolved_collections,
                "onboarding_pending": bool(is_interview),
            }
            has_account_tools = any(
                isinstance(t, dict)
                and t.get("type") in {"account", "connector"}
                and str(t.get("slug") or t.get("account") or "").strip()
                for t in resolved_tools
            )
            if linked_accounts is not None:
                card["linked_accounts"] = list(
                    dict.fromkeys(slugify(str(a)) for a in linked_accounts if str(a).strip())
                )
                card["linked_accounts_restricted"] = True
            elif outbound_rbac == "internal" and not has_account_tools:
                card["linked_accounts"] = []
                card["linked_accounts_restricted"] = True

            self._conn.execute(
                """
                INSERT INTO bots(
                    id, slug, name, role, enabled, card_json, owner_email, visibility, allowed_groups_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    make_id("bot"),
                    candidate_slug,
                    name.strip(),
                    role.strip(),
                    1,
                    json.dumps(card),
                    clean_owner,
                    clean_visibility,
                    json.dumps(clean_allowed_groups),
                    now,
                    now,
                ),
            )
            self._register_collections_locked(
                resolved_collections,
                owner_name=name.strip(),
                created_at=now,
            )
            self._conn.commit()

        rbac_human = {
            "internal": "Read & Organize Only",
            "draft": "Ask Before Sending",
            "execute": "Send Automatically",
        }.get(outbound_rbac, outbound_rbac)
        if is_interview:
            clean_hint = role.strip()
            has_hint = bool(
                clean_hint
                and clean_hint.lower() not in {"workspace automation coworker", name.strip().lower()}
            )
            intro = (
                f"Hi! I'm **{name.strip()}** — here to help with **{clean_hint}**."
                if has_hint
                else f"Hi! I'm **{name.strip()}**. Tell me in your own words how you'd like me to work."
            )
            interview_msg = (
                f"{intro}\n\n"
                "Before we automate anything, let's shape my setup together in plain English:\n"
                "1. **Job & Sources:** What websites, feeds, emails, or tasks should I handle?\n"
                "2. **Boundaries:** What should I always skip, ignore, or never do autonomously?\n"
                f"3. **Sending Mode:** Right now I'm set to **{rbac_human}** — keep that, or stay Read-Only while we test?\n\n"
                "Reply naturally (or pick an option below) and I'll update my own instructions and run a quick test with you first."
            )
            self.append_bot_message(
                candidate_slug,
                "bot",
                interview_msg,
                metadata={
                    "onboarding_interview": True,
                    "quick_replies": [
                        "Propose a starter role and boundaries for me",
                        "Keep Read & Organize Only while we test",
                        "Let's test one sample run together first",
                    ],
                },
            )
        else:
            self.append_bot_message(
                candidate_slug,
                "bot",
                f"Ready! Action mode is set to {rbac_human}.",
            )
        return self.get_bot(candidate_slug)

    def update_bot(self, slug: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update inspector controls on an existing declarative bot."""
        now = utc_now()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, slug, name, role, enabled, card_json, owner_email, visibility, allowed_groups_json, created_at, updated_at
                FROM bots WHERE slug = ?
                """,
                (slug,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Bot '{slug}' not found.")

            row_keys = set(row.keys())
            card = json.loads(row["card_json"])
            owner_email_val = normalize_email(
                (row["owner_email"] if "owner_email" in row_keys else None)
                or card.get("owner_email")
            )
            visibility_val = normalize_visibility(
                (row["visibility"] if "visibility" in row_keys else None)
                or card.get("visibility"),
                default="shared",
            )
            existing_groups = (
                self._decode_groups(row["allowed_groups_json"])
                if "allowed_groups_json" in row_keys
                else normalize_group_slugs(card.get("allowed_groups"))
            )
            if updates.get("owner_email") is not None:
                owner_email_val = normalize_email(str(updates["owner_email"]))
                card["owner_email"] = owner_email_val
            else:
                card["owner_email"] = owner_email_val
            if updates.get("visibility") is not None:
                visibility_val = normalize_visibility(str(updates["visibility"]))
                card["visibility"] = visibility_val
            else:
                card["visibility"] = visibility_val
            if visibility_val != "team":
                allowed_groups_val: list[str] = []
            elif "allowed_groups" in updates and updates["allowed_groups"] is not None:
                allowed_groups_val = normalize_group_slugs(updates["allowed_groups"])
            else:
                allowed_groups_val = existing_groups
            card["allowed_groups"] = allowed_groups_val
            name_text = str(row["name"])
            enabled = bool(row["enabled"])
            role_text = str(row["role"])

            if updates.get("name") and str(updates["name"]).strip():
                name_text = str(updates["name"]).strip()
                card["name"] = name_text
                card["initials"] = _initials(name_text)
            if "enabled" in updates and updates["enabled"] is not None:
                enabled = bool(updates["enabled"])
                card["enabled"] = enabled
            if updates.get("role"):
                role_text = str(updates["role"]).strip()
                card["role"] = role_text
            if updates.get("role_prompt") is not None:
                card["role_prompt"] = str(updates["role_prompt"]).strip()
            if updates.get("model"):
                card["model"] = str(updates["model"])
            if updates.get("avatar_color") is not None:
                card["avatar_color"] = str(updates["avatar_color"]).strip() or "slate"
            if updates.get("avatar_icon") is not None:
                card["avatar_icon"] = str(updates["avatar_icon"]).strip() or "bot"
            if "pinned" in updates and updates["pinned"] is not None:
                card["pinned"] = bool(updates["pinned"])
            if "section" in updates and updates["section"] is not None:
                card["section"] = str(updates["section"]).strip()
            if "hidden_in_sidebar" in updates and updates["hidden_in_sidebar"] is not None:
                card["hidden_in_sidebar"] = bool(updates["hidden_in_sidebar"])
            if "boundaries" in updates and updates["boundaries"] is not None:
                card["boundaries"] = [
                    str(b).strip() for b in updates["boundaries"] if str(b).strip()
                ]
            if "goal_metric" in updates and updates["goal_metric"] is not None:
                card["goal_metric"] = str(updates["goal_metric"]).strip()
            if "onboarding_pending" in updates and updates["onboarding_pending"] is not None:
                card["onboarding_pending"] = bool(updates["onboarding_pending"])
            if "handoff_bot_slug" in updates and updates["handoff_bot_slug"] is not None:
                raw_handoff = str(updates["handoff_bot_slug"]).strip()
                card["handoff_bot_slug"] = slugify(raw_handoff) if raw_handoff else ""
            if updates.get("runtime") in {"api", "sandbox", "desktop"}:
                new_rt = str(updates["runtime"])
                card["runtime"] = new_rt
                card["desktop_policy"] = "on_demand" if new_rt == "desktop" else "disabled"
                card["sandbox_policy"] = "on_demand" if new_rt == "sandbox" else "disabled"
                if new_rt == "desktop":
                    if card.get("desktop_state") in {None, "", "none"}:
                        card["desktop_state"] = "hibernated"
                    card["sandbox_state"] = "none"
                    card["ram_limit_mb"] = 2048
                    card["tools"] = _ensure_desktop_tools(list(card.get("tools", []) or []))
                elif new_rt == "sandbox":
                    card["desktop_state"] = "none"
                    if card.get("sandbox_state") in {None, "", "none"}:
                        card["sandbox_state"] = "hibernated"
                    card["ram_mb"] = 0
                    card["ram_limit_mb"] = 512
                    card["tools"] = _ensure_sandbox_tools(list(card.get("tools", []) or []))
                else:
                    card["desktop_state"] = "none"
                    card["sandbox_state"] = "none"
                    card["ram_mb"] = 0
                    card["ram_limit_mb"] = 2048
                card["permissions"] = _default_permissions(
                    str(card.get("outbound_rbac") or "draft"),
                    new_rt,
                )
            if updates.get("outbound_rbac"):
                prev_rbac = str(card.get("outbound_rbac") or "draft").lower()
                rbac = str(updates["outbound_rbac"]).lower()
                card["outbound_rbac"] = rbac
                runtime = (
                    str(card.get("runtime"))
                    if str(card.get("runtime")) in {"api", "sandbox", "desktop"}
                    else ("desktop" if card.get("desktop_policy", "disabled") != "disabled" else "api")
                )
                card["permissions"] = _default_permissions(rbac, runtime)
                if rbac == "execute" and int(card.get("daily_cap", 0)) < 1:
                    card["daily_cap"] = 10
                if updates.get("tools") is None and "linked_accounts" not in updates:
                    prev_cap = "read" if prev_rbac == "internal" else prev_rbac
                    new_cap = "read" if rbac == "internal" else rbac
                    updated_tools = []
                    for item in card.get("tools", []) or []:
                        if isinstance(item, dict) and item.get("type") in {"account", "connector"}:
                            item_copy = dict(item)
                            cur_cap = str(item_copy.get("capability") or item_copy.get("rbac") or "").lower()
                            if cur_cap in {"", prev_cap}:
                                item_copy["capability"] = new_cap
                                if rbac == "execute" and int(item_copy.get("max_calls_per_day", 0)) < 1:
                                    item_copy["max_calls_per_day"] = max(10, int(card.get("daily_cap") or 10))
                            updated_tools.append(item_copy)
                        else:
                            updated_tools.append(item)
                    card["tools"] = updated_tools
            if updates.get("daily_cap") is not None:
                card["daily_cap"] = max(0, int(updates["daily_cap"]))
            if "max_steps_per_run" in updates and updates["max_steps_per_run"] is not None:
                card["max_steps_per_run"] = max(3, min(25, int(updates["max_steps_per_run"])))
            if updates.get("desktop_state"):
                card["desktop_state"] = str(updates["desktop_state"])
                card["ram_mb"] = 1380 if card["desktop_state"] == "running" else 0
            if updates.get("sandbox_state"):
                card["sandbox_state"] = str(updates["sandbox_state"])
                if updates.get("ram_mb") is not None:
                    card["ram_mb"] = max(0, int(updates["ram_mb"]))
                else:
                    card["ram_mb"] = 48 if card["sandbox_state"] == "running" else 0
            if updates.get("routines") is not None:
                card["routines"] = self._normalize_routines(updates["routines"])
            if updates.get("tools") is not None:
                card["tools"] = list(updates["tools"])
            if "linked_accounts" in updates and updates["linked_accounts"] is not None:
                clean_linked = list(
                    dict.fromkeys(
                        slugify(str(a))
                        for a in updates["linked_accounts"]
                        if str(a).strip()
                    )
                )
                card["linked_accounts"] = clean_linked
                card["linked_accounts_restricted"] = True
                card["tools"] = self._apply_linked_accounts(
                    list(card.get("tools", []) or []),
                    clean_linked,
                    outbound_rbac=str(card.get("outbound_rbac") or "draft"),
                    daily_cap=int(card.get("daily_cap") or 0),
                )
            if updates.get("collections") is not None:
                card["collections"] = self._normalize_collections(updates["collections"])
            if updates.get("toggle_routine_id"):
                target_routine = str(updates["toggle_routine_id"])
                for routine in card.get("routines", []):
                    if routine.get("id") == target_routine:
                        routine["enabled"] = not bool(routine.get("enabled", True))
                        break

            self._conn.execute(
                """
                UPDATE bots
                SET name = ?, role = ?, enabled = ?, card_json = ?,
                    owner_email = ?, visibility = ?, allowed_groups_json = ?, updated_at = ?
                WHERE slug = ?
                """,
                (
                    name_text,
                    role_text,
                    1 if enabled else 0,
                    json.dumps(card),
                    owner_email_val,
                    visibility_val,
                    json.dumps(allowed_groups_val),
                    now,
                    slug,
                ),
            )
            self._register_collections_locked(
                card.get("collections"),
                owner_name=name_text,
                created_at=now,
            )
            self._conn.commit()
        return self.get_bot(slug)

    def delete_bot(self, slug: str) -> dict[str, Any]:
        """Delete a declarative bot and all bot-scoped threads, snapshots, skills, cursors, and room links."""
        bot = self.get_bot(slug)
        clean_slug = bot["slug"]
        now = utc_now()
        superseded_approvals: list[dict[str, Any]] = []
        with self._tx():
            pending_aprs = self._conn.execute(
                """
                SELECT * FROM approvals_outbox
                WHERE bot_slug = ? AND status = 'pending'
                """,
                (clean_slug,),
            ).fetchall()
            superseded_approvals = [self._serialize_approval(arow) for arow in pending_aprs]

            cursor = self._conn.execute("DELETE FROM bots WHERE slug = ?", (clean_slug,))
            if cursor.rowcount == 0:
                raise NotFoundError(f"Bot '{slug}' not found.")

            for col_name, json_field in (
                ("bot_threads", "$.bot_slug"),
                ("desktop_snapshots", "$.bot_slug"),
                ("ingestion_seen_keys", "$.bot_slug"),
                ("debug_run_traces", "$.bot_slug"),
                ("bot_skills", "$.scope_slug"),
            ):
                self._conn.execute(
                    f"""
                    DELETE FROM collection_documents
                    WHERE collection = ? AND json_extract(doc_json, '{json_field}') = ?
                    """,
                    (col_name, clean_slug),
                )

            self._conn.execute(
                """
                DELETE FROM collection_documents
                WHERE collection = 'thread_read_cursors'
                  AND json_extract(doc_json, '$.target_type') = 'bot'
                  AND json_extract(doc_json, '$.slug') = ?
                """,
                (clean_slug,),
            )

            self._conn.execute(
                """
                UPDATE approvals_outbox
                SET status = 'superseded', resolved_at = ?
                WHERE bot_slug = ? AND status = 'pending'
                """,
                (now, clean_slug),
            )
            self._conn.execute(
                "DELETE FROM style_memory WHERE scope_slug = ?",
                (clean_slug,),
            )

            # Clear any remaining handoff_bot_slug pointing to deleted bot
            other_bots = self._conn.execute(
                "SELECT slug, card_json FROM bots"
            ).fetchall()
            for brow in other_bots:
                try:
                    card = json.loads(brow["card_json"])
                except Exception:
                    continue
                if isinstance(card, dict) and card.get("handoff_bot_slug") == clean_slug:
                    card["handoff_bot_slug"] = ""
                    self._conn.execute(
                        "UPDATE bots SET card_json = ?, updated_at = ? WHERE slug = ?",
                        (json.dumps(card), now, brow["slug"]),
                    )

            # Clean deleted bot out of any bot_rooms membership / stage order (remove <2-member Rooms)
            room_rows = self._conn.execute(
                """
                SELECT id, external_key, doc_json
                FROM collection_documents
                WHERE collection = 'bot_rooms'
                """
            ).fetchall()
            for rrow in room_rows:
                try:
                    rdoc = json.loads(rrow["doc_json"])
                except Exception:
                    continue
                if not isinstance(rdoc, dict):
                    continue
                members = [str(m) for m in (rdoc.get("member_bot_slugs") or []) if str(m).strip()]
                if clean_slug not in members:
                    continue
                remaining_members = [m for m in members if m != clean_slug]
                room_slug_val = str(rdoc.get("slug") or rrow["external_key"] or "")
                if len(remaining_members) < 2:
                    self._conn.execute(
                        "DELETE FROM collection_documents WHERE collection = 'bot_rooms' AND id = ?",
                        (rrow["id"],),
                    )
                    if room_slug_val:
                        self._conn.execute(
                            "DELETE FROM collection_documents WHERE collection = 'room_threads' AND json_extract(doc_json, '$.room_slug') = ?",
                            (room_slug_val,),
                        )
                        self._conn.execute(
                            """
                            DELETE FROM collection_documents
                            WHERE collection = 'thread_read_cursors'
                              AND json_extract(doc_json, '$.target_type') = 'room'
                              AND json_extract(doc_json, '$.slug') = ?
                            """,
                            (room_slug_val,),
                        )
                else:
                    rdoc["member_bot_slugs"] = remaining_members
                    stages = [
                        str(s) for s in (rdoc.get("stage_order") or []) if str(s) in remaining_members
                    ]
                    for m in remaining_members:
                        if m not in stages:
                            stages.append(m)
                    rdoc["stage_order"] = stages
                    if rdoc.get("coordinator_bot_slug") == clean_slug:
                        rdoc["coordinator_bot_slug"] = remaining_members[0]
                    search_txt = f"{rdoc.get('title', '')} {' '.join(remaining_members)}".strip()
                    self._conn.execute(
                        """
                        UPDATE collection_documents
                        SET doc_json = ?, search_text = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (json.dumps(rdoc), search_txt, now, rrow["id"]),
                    )

        bot["_superseded_approvals"] = superseded_approvals
        return bot

    @staticmethod
    def _serialize_bot_message(slug: str, row: sqlite3.Row) -> dict[str, Any]:
        doc = json.loads(row["doc_json"])
        return {
            "id": row["id"],
            "bot_slug": doc.get("bot_slug", slug),
            "sender": doc.get("sender", "bot"),
            "text": doc.get("text", ""),
            "metadata": doc.get("metadata") or {},
            "created_at": row["created_at"],
        }

    def list_bot_messages_window(
        self,
        slug: str,
        *,
        limit: int = 40,
        before_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], bool, int]:
        """Retrieve a chronological slice of bot thread messages with pagination metadata."""
        capped = max(1, min(int(limit), 200))
        with self._lock:
            total_row = self._conn.execute(
                """
                SELECT COUNT(*) FROM collection_documents
                WHERE collection = 'bot_threads'
                  AND json_extract(doc_json, '$.bot_slug') = ?
                """,
                (slug,),
            ).fetchone()
            total_count = int(total_row[0]) if total_row else 0

            if before_id:
                anchor = self._conn.execute(
                    """
                    SELECT rowid, created_at FROM collection_documents
                    WHERE collection = 'bot_threads'
                      AND json_extract(doc_json, '$.bot_slug') = ?
                      AND id = ?
                    """,
                    (slug, before_id),
                ).fetchone()
                if anchor is None:
                    return [], False, total_count
                rows = self._conn.execute(
                    """
                    SELECT id, doc_json, created_at
                    FROM collection_documents
                    WHERE collection = 'bot_threads'
                      AND json_extract(doc_json, '$.bot_slug') = ?
                      AND (created_at < ? OR (created_at = ? AND rowid < ?))
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (slug, anchor["created_at"], anchor["created_at"], anchor["rowid"], capped + 1),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, doc_json, created_at
                    FROM collection_documents
                    WHERE collection = 'bot_threads'
                      AND json_extract(doc_json, '$.bot_slug') = ?
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (slug, capped + 1),
                ).fetchall()

        has_more = len(rows) > capped
        window_rows = list(reversed(rows[:capped]))
        messages = [self._serialize_bot_message(slug, row) for row in window_rows]
        return messages, has_more, total_count

    def list_bot_messages(
        self,
        slug: str,
        *,
        limit: int | None = None,
        before_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve direct 1:1 thread messages for a bot from collection_documents."""
        if limit is not None or before_id is not None:
            messages, _, _ = self.list_bot_messages_window(
                slug,
                limit=limit if limit is not None else 40,
                before_id=before_id,
            )
            return messages
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, doc_json, created_at
                FROM collection_documents
                WHERE collection = 'bot_threads'
                  AND json_extract(doc_json, '$.bot_slug') = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (slug,),
            ).fetchall()

        return [self._serialize_bot_message(slug, row) for row in rows]

    def _clear_thread_messages(
        self,
        *,
        collection: str,
        slug_field: str,
        target_type: str,
        target_slug: str,
        keep_last: int = 0,
        older_than_days: int | None = None,
    ) -> dict[str, int]:
        """Delete matching bot/room thread transcript rows without touching non-transcript state."""
        keep = max(0, int(keep_last))
        cutoff_iso: str | None = None
        if older_than_days is not None:
            days = max(1, min(3650, int(older_than_days)))
            cutoff_iso = (
                (datetime.now(UTC) - timedelta(days=days))
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )

        slug_expr = f"json_extract(doc_json, '$.{slug_field}') = ?"
        with self._lock:
            keep_ids: list[str] = []
            if keep > 0:
                keep_rows = self._conn.execute(
                    f"""
                    SELECT id
                    FROM collection_documents
                    WHERE collection = ?
                      AND {slug_expr}
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (collection, target_slug, keep),
                ).fetchall()
                keep_ids = [str(r["id"]) for r in keep_rows]

            clauses = ["collection = ?", slug_expr]
            params: list[Any] = [collection, target_slug]
            if cutoff_iso is not None:
                clauses.append("created_at < ?")
                params.append(cutoff_iso)
            if keep_ids:
                placeholders = ",".join("?" for _ in keep_ids)
                clauses.append(f"id NOT IN ({placeholders})")
                params.extend(keep_ids)

            if keep > 0 and not keep_ids:
                deleted_count = 0
            else:
                cur = self._conn.execute(
                    f"DELETE FROM collection_documents WHERE {' AND '.join(clauses)}",
                    params,
                )
                deleted_count = int(cur.rowcount or 0)

            rem_row = self._conn.execute(
                f"""
                SELECT COUNT(*)
                FROM collection_documents
                WHERE collection = ?
                  AND {slug_expr}
                """,
                (collection, target_slug),
            ).fetchone()
            remaining_count = int(rem_row[0]) if rem_row else 0

            if remaining_count == 0:
                self._conn.execute(
                    """
                    DELETE FROM collection_documents
                    WHERE collection = 'thread_read_cursors'
                      AND json_extract(doc_json, '$.target_type') = ?
                      AND json_extract(doc_json, '$.slug') = ?
                    """,
                    (target_type, target_slug),
                )
            self._conn.commit()

        return {
            "deleted_count": deleted_count,
            "remaining_count": remaining_count,
        }

    def clear_bot_messages(
        self,
        slug: str,
        *,
        keep_last: int = 0,
        older_than_days: int | None = None,
    ) -> dict[str, int]:
        """Clear 1:1 bot chat transcript rows without touching skills, rules, routines, or data."""
        bot = self.get_bot(slug)
        return self._clear_thread_messages(
            collection="bot_threads",
            slug_field="bot_slug",
            target_type="bot",
            target_slug=bot["slug"],
            keep_last=keep_last,
            older_than_days=older_than_days,
        )

    def rewind_last_user_message(
        self,
        *,
        target_type: str,
        target_slug: str,
        message_id: str,
    ) -> dict[str, Any]:
        """Remove the user's most recent message and any subsequent replies so it can be re-submitted."""
        clean_type = "room" if target_type == "room" else "bot"
        if clean_type == "room":
            room = self.get_room(target_slug)
            clean_slug = room["slug"]
            collection = "room_threads"
            slug_field = "room_slug"
        else:
            bot = self.get_bot(target_slug)
            clean_slug = bot["slug"]
            collection = "bot_threads"
            slug_field = "bot_slug"

        slug_expr = f"json_extract(doc_json, '$.{slug_field}') = ?"
        with self._lock:
            target_row = self._conn.execute(
                f"""
                SELECT rowid, id, doc_json, created_at
                FROM collection_documents
                WHERE collection = ?
                  AND {slug_expr}
                  AND id = ?
                """,
                (collection, clean_slug, message_id),
            ).fetchone()
            if target_row is None:
                raise NotFoundError(f"Message '{message_id}' not found in {clean_type} '{clean_slug}'.")

            try:
                target_doc = json.loads(target_row["doc_json"])
            except json.JSONDecodeError:
                target_doc = {}
            sender_val = str(target_doc.get("sender_type") or target_doc.get("sender") or "").strip().lower()
            if sender_val != "user":
                raise ValueError("Only your own user messages can be edited.")

            later_user = self._conn.execute(
                f"""
                SELECT 1
                FROM collection_documents
                WHERE collection = ?
                  AND {slug_expr}
                  AND COALESCE(json_extract(doc_json, '$.sender_type'), json_extract(doc_json, '$.sender')) = 'user'
                  AND (created_at > ? OR (created_at = ? AND rowid > ?))
                LIMIT 1
                """,
                (collection, clean_slug, target_row["created_at"], target_row["created_at"], target_row["rowid"]),
            ).fetchone()
            if later_user is not None:
                raise ValueError("Only your most recent message in this conversation can be edited.")

            tail_rows = self._conn.execute(
                f"""
                SELECT id, doc_json
                FROM collection_documents
                WHERE collection = ?
                  AND {slug_expr}
                  AND (id = ? OR created_at > ? OR (created_at = ? AND rowid > ?))
                ORDER BY created_at ASC, rowid ASC
                """,
                (
                    collection,
                    clean_slug,
                    message_id,
                    target_row["created_at"],
                    target_row["created_at"],
                    target_row["rowid"],
                ),
            ).fetchall()

            deleted_ids = [str(r["id"]) for r in tail_rows]
            corr_ids: list[str] = []
            for r in tail_rows:
                try:
                    rdoc = json.loads(r["doc_json"])
                except json.JSONDecodeError:
                    continue
                rmeta = rdoc.get("metadata") if isinstance(rdoc, dict) else None
                cid = str(rmeta.get("correlation_id") or "").strip() if isinstance(rmeta, dict) else ""
                if cid and cid not in corr_ids:
                    corr_ids.append(cid)

            superseded_approvals = 0
            if corr_ids:
                now = utc_now()
                placeholders = ",".join("?" for _ in corr_ids)
                cur_apr = self._conn.execute(
                    f"""
                    UPDATE approvals_outbox
                    SET status = 'superseded', resolved_at = ?
                    WHERE status = 'pending' AND correlation_id IN ({placeholders})
                    """,
                    [now, *corr_ids],
                )
                superseded_approvals = int(cur_apr.rowcount or 0)

            if deleted_ids:
                id_placeholders = ",".join("?" for _ in deleted_ids)
                self._conn.execute(
                    f"DELETE FROM collection_documents WHERE collection = ? AND id IN ({id_placeholders})",
                    [collection, *deleted_ids],
                )
            self._conn.commit()

        orig_meta = target_doc.get("metadata") if isinstance(target_doc.get("metadata"), dict) else {}
        return {
            "deleted_ids": deleted_ids,
            "original_metadata": dict(orig_meta),
            "superseded_approvals": superseded_approvals,
        }

    def ensure_bot_data_collection(self, slug: str) -> str:
        """Ensure a source-polling bot has a non-internal SQLite data collection for storage and dedup."""
        bot = self.get_bot(slug)
        cols = bot.get("collections") or {}
        read_cols = [collection_slug(str(c)) for c in (cols.get("read") or []) if str(c).strip()]
        write_cols = [collection_slug(str(c)) for c in (cols.get("write") or []) if str(c).strip()]
        non_internal_write = [c for c in write_cols if c not in _INTERNAL_SYSTEM_COLLECTIONS]
        if non_internal_write:
            return non_internal_write[0]

        default_col = collection_slug(f"bot_{bot['slug']}_items")
        new_read = list(dict.fromkeys([*read_cols, default_col]))
        new_write = list(dict.fromkeys([*write_cols, default_col]))
        self.update_bot(bot["slug"], {"collections": {"read": new_read, "write": new_write}})
        return default_col

    def is_ingestion_key_seen(
        self,
        bot_slug: str,
        external_key: str,
        primary_collection: str | None = None,
    ) -> bool:
        """Return True if bot_slug has already seen or saved external_key."""
        clean_key = str(external_key or "").strip()
        if not clean_key:
            return False
        if self.document_exists("ingestion_seen_keys", f"{bot_slug}:{clean_key}"):
            return True
        if primary_collection and primary_collection not in _INTERNAL_SYSTEM_COLLECTIONS:
            return self.document_exists(primary_collection, clean_key)
        return False

    def mark_ingestion_keys_seen(self, bot_slug: str, keys: list[str]) -> None:
        """Persist per-bot seen ingestion keys so discarded or triaged items stay 0-token on subsequent polls."""
        now = utc_now()
        seen: set[str] = set()
        for raw_key in keys:
            ext_key = str(raw_key or "").strip()
            if not ext_key or ext_key in seen:
                continue
            seen.add(ext_key)
            self.upsert_document(
                collection="ingestion_seen_keys",
                external_key=f"{bot_slug}:{ext_key}",
                search_text=f"{bot_slug} {ext_key}"[:300],
                doc={"bot_slug": bot_slug, "external_key": ext_key, "seen_at": now},
                description="Per-bot deduplication cursor for polled sources",
            )

    def _resolve_reply_preview(
        self,
        *,
        collection: str,
        reply_to_id: str | None,
        fallback_bot_name: str | None = None,
    ) -> dict[str, Any] | None:
        if not reply_to_id or not str(reply_to_id).strip():
            return None
        target_id = str(reply_to_id).strip()
        with self._lock:
            row = self._conn.execute(
                "SELECT id, doc_json FROM collection_documents WHERE collection = ? AND id = ?",
                (collection, target_id),
            ).fetchone()
        if row is None:
            return None
        doc = json.loads(row["doc_json"])
        sender = str(doc.get("sender") or doc.get("sender_type") or "bot")
        sender_name = str(
            doc.get("sender_name")
            or ("You" if sender == "user" else (fallback_bot_name or doc.get("bot_slug") or "Bot"))
        )
        return {
            "id": row["id"],
            "sender": sender,
            "sender_slug": str(doc.get("sender_slug") or doc.get("bot_slug") or sender),
            "sender_name": sender_name,
            "excerpt": str(doc.get("text") or "").strip()[:180],
        }

    def toggle_message_reaction(
        self,
        *,
        collection: str,
        message_id: str,
        emoji: str,
        actor: str,
    ) -> dict[str, Any]:
        """Toggle an emoji reaction on a message in bot_threads or room_threads."""
        clean_coll = collection_slug(collection)
        if clean_coll not in {"bot_threads", "room_threads"}:
            raise ValueError("Unsupported message collection for reaction.")
        clean_emoji = str(emoji or "").strip()[:16]
        if not clean_emoji:
            raise ValueError("Emoji cannot be empty.")
        clean_actor = str(actor or "operator").strip()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, external_key, search_text, doc_json, created_at
                FROM collection_documents
                WHERE collection = ? AND id = ?
                """,
                (clean_coll, message_id),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Message '{message_id}' not found.")
            doc = json.loads(row["doc_json"])
            meta = dict(doc.get("metadata") or {})
            reactions = dict(meta.get("reactions") or {})
            actors = [str(a) for a in (reactions.get(clean_emoji) or []) if str(a).strip()]
            if clean_actor in actors:
                actors = [a for a in actors if a != clean_actor]
            else:
                actors.append(clean_actor)
            if actors:
                reactions[clean_emoji] = actors
            else:
                reactions.pop(clean_emoji, None)
            meta["reactions"] = reactions
            doc["metadata"] = meta
            now = utc_now()
            self._conn.execute(
                "UPDATE collection_documents SET doc_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(doc), now, message_id),
            )
            self._conn.commit()
        return {
            "id": message_id,
            "collection": clean_coll,
            "reactions": reactions,
        }

    def append_bot_message(
        self,
        slug: str,
        sender: str,
        text: str,
        *,
        metadata: dict[str, Any] | None = None,
        reply_to_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a message to a bot's 1:1 thread in collection_documents."""
        msg_id = make_id("msg")
        now = utc_now()
        merged_meta = dict(metadata or {})
        if reply_to_id and "reply_to" not in merged_meta:
            try:
                bot_name = self.get_bot(slug).get("name")
            except Exception:
                bot_name = slug
            preview = self._resolve_reply_preview(
                collection="bot_threads",
                reply_to_id=reply_to_id,
                fallback_bot_name=bot_name,
            )
            if preview:
                merged_meta["reply_to"] = preview
        doc: dict[str, Any] = {
            "bot_slug": slug,
            "sender": sender,
            "text": text,
            "created_at": now,
        }
        if merged_meta:
            doc["metadata"] = merged_meta
        saved = self.upsert_document(
            collection="bot_threads",
            external_key=f"{slug}:{msg_id}",
            search_text=f"{slug} {sender} {text}",
            doc=doc,
            description="Direct 1:1 operator-to-bot message transcripts",
            doc_id=msg_id,
        )
        return {
            "id": saved["id"],
            "bot_slug": doc.get("bot_slug", slug),
            "sender": doc.get("sender", sender),
            "text": doc.get("text", text),
            "metadata": doc.get("metadata") or {},
            "created_at": saved["created_at"],
        }

    # ------------------------------------------------------------------
    # Reusable Skills & Sanitized Bot Blueprints
    # ------------------------------------------------------------------
    def list_skills(self, scope_slug: str | None = None) -> list[dict[str, Any]]:
        """List saved reusable skills (optionally filtered to scope_slug + global '*')."""
        docs = self.search_documents("bot_skills", limit=200)
        skills: list[dict[str, Any]] = []
        for item in docs:
            doc = item.get("doc") or {}
            s_scope = str(doc.get("scope_slug") or "*")
            if scope_slug and s_scope not in {scope_slug, "*"}:
                continue
            skills.append(
                {
                    "id": item["id"],
                    "slug": str(doc.get("slug") or item.get("external_key") or slugify(str(doc.get("name") or "skill"))),
                    "name": str(doc.get("name") or "Untitled Skill"),
                    "description": str(doc.get("description") or ""),
                    "instructions": str(doc.get("instructions") or ""),
                    "scope_slug": s_scope,
                    "created_at": item["created_at"],
                    "updated_at": item["updated_at"],
                }
            )
        return skills

    def upsert_skill(
        self,
        *,
        name: str,
        instructions: str,
        description: str = "",
        scope_slug: str = "*",
        skill_slug: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a reusable Skill inside collection 'bot_skills'."""
        clean_name = name.strip()
        clean_slug = slugify(skill_slug or clean_name)
        clean_scope = (scope_slug or "*").strip() or "*"
        clean_desc = description.strip()
        clean_instr = instructions.strip()
        saved = self.upsert_document(
            collection="bot_skills",
            external_key=clean_slug,
            search_text=f"{clean_name} {clean_desc} {clean_instr}"[:1000],
            doc={
                "slug": clean_slug,
                "name": clean_name,
                "description": clean_desc,
                "instructions": clean_instr,
                "scope_slug": clean_scope,
            },
            description="Reusable skill playbooks saved from conversations",
        )
        doc = saved["doc"]
        return {
            "id": saved["id"],
            "slug": doc["slug"],
            "name": doc["name"],
            "description": doc["description"],
            "instructions": doc["instructions"],
            "scope_slug": doc["scope_slug"],
            "created_at": saved["created_at"],
            "updated_at": saved["updated_at"],
        }

    def delete_skill(self, skill_id: str) -> None:
        """Delete a saved skill by document id or slug."""
        docs = self.search_documents("bot_skills", limit=200)
        target = next(
            (d for d in docs if d["id"] == skill_id or (d.get("doc") or {}).get("slug") == skill_id),
            None,
        )
        if target is None:
            raise NotFoundError(f"Skill '{skill_id}' not found.")
        self.delete_document("bot_skills", target["id"])

    def export_bot_blueprint(self, slug: str) -> dict[str, Any]:
        """Export a sanitized, credential-free portable bot blueprint."""
        bot = self.get_bot(slug)
        integrations_by_slug = {acc["slug"]: acc for acc in self.list_integrations()}

        required_providers: list[str] = []
        sanitized_tools: list[Any] = []
        connector_policies: list[dict[str, Any]] = []
        for tool in bot.get("tools", []):
            if isinstance(tool, dict) and tool.get("type") in {"account", "connector"}:
                acc_slug = slugify(str(tool.get("slug") or tool.get("account") or ""))
                acc = integrations_by_slug.get(acc_slug)
                prov = str(acc["provider"]) if acc else str(tool.get("provider") or "").strip().lower()
                if acc and acc["provider"] not in required_providers:
                    required_providers.append(acc["provider"])
                pol: dict[str, Any] = {}
                if prov:
                    pol["provider"] = prov
                if tool.get("capability") or tool.get("rbac"):
                    pol["capability"] = str(tool.get("capability") or tool.get("rbac")).strip().lower()
                if tool.get("target") and str(tool.get("target")).strip():
                    pol["target"] = str(tool["target"]).strip()
                if isinstance(tool.get("targets"), list) and any(str(t).strip() for t in tool["targets"]):
                    pol["targets"] = [str(t).strip() for t in tool["targets"] if str(t).strip()]
                if tool.get("max_calls_per_day") is not None:
                    pol["max_calls_per_day"] = int(tool["max_calls_per_day"])
                if pol:
                    connector_policies.append(pol)
                continue
            sanitized_tools.append(tool)

        for linked_slug in bot.get("linked_accounts", []):
            acc = integrations_by_slug.get(linked_slug)
            if acc and acc["provider"] not in required_providers:
                required_providers.append(acc["provider"])

        sanitized_routines = [
            {k: v for k, v in r.items() if k != "id"}
            for r in bot.get("routines", [])
            if isinstance(r, dict)
        ]
        scoped_skills = [
            {
                "slug": s["slug"],
                "name": s["name"],
                "description": s["description"],
                "instructions": s["instructions"],
            }
            for s in self.list_skills()
            if s["scope_slug"] == bot["slug"]
        ]
        return {
            "schema_version": "argo.bot_blueprint.v1",
            "source_slug": bot["slug"],
            "name": bot["name"],
            "role": bot["role"],
            "role_prompt": bot["role_prompt"],
            "boundaries": list(bot.get("boundaries") or []),
            "goal_metric": bot.get("goal_metric") or "",
            "handoff_bot_slug": bot.get("handoff_bot_slug") or "",
            "avatar_color": bot.get("avatar_color") or "slate",
            "avatar_icon": bot.get("avatar_icon") or "bot",
            "section": bot.get("section") or "",
            "runtime": bot["runtime"],
            "outbound_rbac": bot["outbound_rbac"],
            "daily_cap": bot["daily_cap"],
            "model": bot["model"],
            "routines": sanitized_routines,
            "tools": sanitized_tools,
            "collections": bot.get("collections") or {"read": ["bot_threads"], "write": []},
            "required_providers": required_providers,
            "connector_policies": connector_policies,
            "skills": scoped_skills,
        }

    def import_bot_blueprint(
        self,
        blueprint: dict[str, Any],
        *,
        linked_accounts: list[str] | None = None,
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Instantiate a declarative bot and its bundled skills from a portable blueprint."""
        if not isinstance(blueprint, dict):
            raise ValueError("Blueprint payload must be a JSON object.")
        name = str(blueprint.get("name") or "").strip()
        role = str(blueprint.get("role") or blueprint.get("role_prompt") or "").strip()
        if not name or not role:
            raise ValueError("Blueprint must include non-empty 'name' and 'role'.")

        model = str(blueprint.get("model") or "google:gemini-3.8-flash").strip()
        if "gemini-2.5" in model.lower():
            raise ValueError("Deprecated gemini-2.5-* models are forbidden.")
        if ":" not in model:
            model = "google:gemini-3.8-flash"

        raw_bp_rt = str(blueprint.get("runtime") or "api").strip().lower()
        runtime = raw_bp_rt if raw_bp_rt in {"api", "sandbox", "desktop"} else "api"
        rbac = str(blueprint.get("outbound_rbac") or "draft")
        if rbac not in {"internal", "draft", "execute"}:
            rbac = "draft"

        raw_daily_cap = blueprint.get("daily_cap")
        parsed_daily_cap = max(0, min(500, int(10 if raw_daily_cap is None else raw_daily_cap)))
        orig_slug = slugify(str(blueprint.get("source_slug") or blueprint.get("slug") or name))

        raw_tools = list(blueprint.get("tools")) if isinstance(blueprint.get("tools"), list) else []
        raw_policies = blueprint.get("connector_policies") if isinstance(blueprint.get("connector_policies"), list) else []
        merged_tools: list[Any] = list(raw_tools)
        if linked_accounts and raw_policies:
            integrations_by_slug = {acc["slug"]: acc for acc in self.list_integrations()}
            used_policies: set[int] = set()
            for raw_acc in linked_accounts:
                acc_slug = slugify(str(raw_acc))
                acc = integrations_by_slug.get(acc_slug)
                acc_prov = str(acc["provider"]).lower() if acc else ""
                matched_pol = None
                for p_idx, pol in enumerate(raw_policies):
                    if not isinstance(pol, dict) or p_idx in used_policies:
                        continue
                    pol_prov = str(pol.get("provider") or "").strip().lower()
                    if not pol_prov or not acc_prov or pol_prov == acc_prov:
                        matched_pol = pol
                        used_policies.add(p_idx)
                        break
                if matched_pol is not None:
                    tool_entry: dict[str, Any] = {"type": "account", "slug": acc_slug}
                    for fld in ("capability", "target", "targets", "max_calls_per_day"):
                        if fld in matched_pol and matched_pol[fld] is not None:
                            tool_entry[fld] = matched_pol[fld]
                    merged_tools.append(tool_entry)

        created = self.create_bot(
            name=name[:120],
            role=role[:2000],
            role_prompt=str(blueprint.get("role_prompt") or role)[:8000],
            runtime=runtime,
            outbound_rbac=rbac,
            model=model,
            daily_cap=parsed_daily_cap,
            routines=blueprint.get("routines") if isinstance(blueprint.get("routines"), list) else None,
            tools=merged_tools if (blueprint.get("tools") is not None or raw_policies) else None,
            collections=blueprint.get("collections") if isinstance(blueprint.get("collections"), dict) else None,
            linked_accounts=linked_accounts if linked_accounts else None,
            avatar_color=str(blueprint.get("avatar_color") or "slate"),
            avatar_icon=str(blueprint.get("avatar_icon") or "bot"),
            section=str(blueprint.get("section") or ""),
            boundaries=blueprint.get("boundaries") if isinstance(blueprint.get("boundaries"), list) else None,
            goal_metric=str(blueprint.get("goal_metric") or ""),
            handoff_bot_slug=str(blueprint.get("handoff_bot_slug") or ""),
            owner_email=owner_email,
            visibility=visibility,
            allowed_groups=allowed_groups,
        )
        skill_slug_map: dict[str, str] = {}
        for skill in blueprint.get("skills") or []:
            if isinstance(skill, dict) and skill.get("name") and skill.get("instructions"):
                old_sk_slug = slugify(str(skill.get("slug") or f"{orig_slug}-{skill['name']}"))
                short_sk = f"{created['slug']}-{slugify(str(skill['name']))}"
                saved_sk = self.upsert_skill(
                    name=str(skill["name"]),
                    description=str(skill.get("description") or ""),
                    instructions=str(skill["instructions"]),
                    scope_slug=created["slug"],
                    skill_slug=short_sk,
                )
                skill_slug_map[old_sk_slug] = saved_sk["slug"]
                skill_slug_map[slugify(str(skill["name"]))] = saved_sk["slug"]

        bot_updates: dict[str, Any] = {}
        if orig_slug and orig_slug != created["slug"]:
            old_items = f"bot_{orig_slug}_items"
            new_items = f"bot_{created['slug']}_items"
            cols = dict(created.get("collections") or {"read": ["bot_threads"], "write": []})
            remapped_read = [new_items if c == old_items else c for c in cols.get("read", [])]
            remapped_write = [new_items if c == old_items else c for c in cols.get("write", [])]
            if remapped_read != cols.get("read") or remapped_write != cols.get("write"):
                bot_updates["collections"] = {"read": remapped_read, "write": remapped_write}

        if skill_slug_map and created.get("routines"):
            new_routines = []
            routines_changed = False
            for rtn in created["routines"]:
                if isinstance(rtn, dict) and rtn.get("skill_slugs"):
                    remapped_sk = [
                        skill_slug_map.get(slugify(str(s)), slugify(str(s)))
                        for s in rtn["skill_slugs"]
                    ]
                    if remapped_sk != rtn["skill_slugs"]:
                        rtn = {**rtn, "skill_slugs": remapped_sk}
                        routines_changed = True
                new_routines.append(rtn)
            if routines_changed:
                bot_updates["routines"] = new_routines

        if bot_updates:
            created = self.update_bot(created["slug"], bot_updates)
        return created

    # ------------------------------------------------------------------
    # Multi-Bot Group Rooms ("Rooms"), Team Packs, Per-User Files & Cursors
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize_room(item: dict[str, Any]) -> dict[str, Any]:
        doc = item.get("doc") or {}
        raw_mode = str(doc.get("routing_mode") or "auto").strip().lower()
        routing_mode = raw_mode if raw_mode in {"auto", "lead", "stage"} else "auto"
        return {
            "id": item["id"],
            "slug": str(doc.get("slug") or item.get("external_key") or "room"),
            "title": str(doc.get("title") or "Team Room"),
            "member_bot_slugs": list(doc.get("member_bot_slugs") or []),
            "coordinator_bot_slug": doc.get("coordinator_bot_slug") or None,
            "stage_order": list(doc.get("stage_order") or doc.get("member_bot_slugs") or []),
            "routing_mode": routing_mode,
            "ask_before_bot_handoff": bool(doc.get("ask_before_bot_handoff", False)),
            "max_bot_turns_per_message": max(1, min(5, int(doc.get("max_bot_turns_per_message") or 3))),
            "pinned_page_slug": doc.get("pinned_page_slug") or None,
            "pinned": bool(doc.get("pinned", False)),
            "section": str(doc.get("section") or ""),
            "owner_email": normalize_email(doc.get("owner_email")),
            "visibility": normalize_visibility(doc.get("visibility"), default="shared"),
            "allowed_groups": (
                normalize_group_slugs(doc.get("allowed_groups"))
                if normalize_visibility(doc.get("visibility"), default="shared") == "team"
                else []
            ),
            "created_at": item["created_at"],
            "updated_at": item["updated_at"],
        }

    def list_rooms(self) -> list[dict[str, Any]]:
        """List all multi-bot group chat rooms."""
        docs = self.search_documents("bot_rooms", limit=200)
        rooms = [self._serialize_room(d) for d in docs]
        rooms.sort(key=lambda r: (not r["pinned"], r["created_at"]))
        return rooms

    def get_room(self, slug: str) -> dict[str, Any]:
        """Fetch a multi-bot group chat room by slug."""
        clean_slug = slugify(slug)
        doc = self.get_document_by_external_key("bot_rooms", clean_slug)
        if doc is None:
            raise NotFoundError(f"Room '{slug}' not found.")
        return self._serialize_room(doc)

    def create_room(
        self,
        *,
        title: str,
        member_bot_slugs: list[str],
        coordinator_bot_slug: str | None = None,
        stage_order: list[str] | None = None,
        routing_mode: str = "auto",
        ask_before_bot_handoff: bool = False,
        max_bot_turns_per_message: int = 3,
        pinned_page_slug: str | None = None,
        pinned: bool = False,
        section: str = "",
        slug: str | None = None,
        owner_email: str = "",
        visibility: str = "shared",
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a shared multi-bot group chat Room (2 to 6 member bots)."""
        clean_title = title.strip()
        if not clean_title:
            raise ValueError("Room title cannot be empty.")
        existing_bots = {b["slug"]: b for b in self.list_bots()}
        unique_members: list[str] = []
        for raw_slug in member_bot_slugs:
            bslug = slugify(str(raw_slug))
            if bslug and bslug not in unique_members:
                if bslug not in existing_bots:
                    raise ValueError(f"Member bot '{bslug}' does not exist.")
                unique_members.append(bslug)
        if len(unique_members) < 2 or len(unique_members) > 6:
            raise ValueError("A Room requires between 2 and 6 distinct member bots.")

        coord_slug = slugify(coordinator_bot_slug) if coordinator_bot_slug and coordinator_bot_slug.strip() else None
        if coord_slug and coord_slug not in unique_members:
            coord_slug = unique_members[0]

        ordered_stages = [
            slugify(str(s))
            for s in (stage_order or [])
            if slugify(str(s)) in unique_members
        ]
        for m in unique_members:
            if m not in ordered_stages:
                ordered_stages.append(m)

        clean_mode = str(routing_mode or "auto").strip().lower()
        if clean_mode not in {"auto", "lead", "stage"}:
            clean_mode = "auto"

        base_slug = slugify(slug or clean_title)
        candidate_slug = base_slug
        suffix = 2
        while self.document_exists("bot_rooms", candidate_slug):
            candidate_slug = f"{base_slug}-{suffix}"
            suffix += 1

        room_doc = {
            "slug": candidate_slug,
            "title": clean_title,
            "member_bot_slugs": unique_members,
            "coordinator_bot_slug": coord_slug,
            "stage_order": ordered_stages,
            "routing_mode": clean_mode,
            "ask_before_bot_handoff": bool(ask_before_bot_handoff),
            "max_bot_turns_per_message": max(1, min(5, int(max_bot_turns_per_message))),
            "pinned_page_slug": slugify(pinned_page_slug) if pinned_page_slug and pinned_page_slug.strip() else None,
            "pinned": bool(pinned),
            "section": section.strip(),
            "owner_email": normalize_email(owner_email),
            "visibility": normalize_visibility(visibility, default="shared"),
            "allowed_groups": (
                normalize_group_slugs(allowed_groups)
                if normalize_visibility(visibility, default="shared") == "team"
                else []
            ),
        }
        saved = self.upsert_document(
            collection="bot_rooms",
            external_key=candidate_slug,
            search_text=f"{clean_title} {' '.join(unique_members)}",
            doc=room_doc,
            description="Multi-bot shared group chat rooms",
        )
        lead_slug = coord_slug or ordered_stages[0]
        lead_bot = existing_bots[lead_slug]
        member_names = ", ".join(existing_bots[m]["name"] for m in unique_members)
        self.append_room_message(
            candidate_slug,
            sender_type="bot",
            sender_slug=lead_bot["slug"],
            sender_name=lead_bot["name"],
            text=(
                f"**{clean_title}** is open with {member_names}. "
                f"Tag any `@bot` to address a specific specialist directly, or send a goal and I'll route to the best teammate automatically."
            ),
            metadata={"room_welcome": True},
        )
        return self._serialize_room(saved)

    def update_room(self, slug: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update Room membership, stage routing, or pinned Page."""
        current = self.get_room(slug)
        existing_bots = {b["slug"]: b for b in self.list_bots()}

        members = current["member_bot_slugs"]
        if updates.get("member_bot_slugs") is not None:
            unique_members: list[str] = []
            for raw_s in updates["member_bot_slugs"]:
                bslug = slugify(str(raw_s))
                if bslug and bslug not in unique_members:
                    if bslug not in existing_bots:
                        raise ValueError(f"Member bot '{bslug}' does not exist.")
                    unique_members.append(bslug)
            if len(unique_members) < 2 or len(unique_members) > 6:
                raise ValueError("A Room requires between 2 and 6 distinct member bots.")
            members = unique_members

        coord = current["coordinator_bot_slug"]
        if "coordinator_bot_slug" in updates:
            raw_c = updates.get("coordinator_bot_slug")
            coord = slugify(str(raw_c)) if raw_c and str(raw_c).strip() else None
            if coord and coord not in members:
                coord = members[0]
        elif coord and coord not in members:
            coord = members[0]

        stages = [s for s in current["stage_order"] if s in members]
        if updates.get("stage_order") is not None:
            stages = [slugify(str(s)) for s in updates["stage_order"] if slugify(str(s)) in members]
        for m in members:
            if m not in stages:
                stages.append(m)

        routing_mode = current.get("routing_mode", "auto")
        if updates.get("routing_mode") is not None:
            cand_mode = str(updates["routing_mode"]).strip().lower()
            if cand_mode in {"auto", "lead", "stage"}:
                routing_mode = cand_mode

        new_title = str(updates.get("title") or current["title"]).strip() or current["title"]
        new_doc = {
            "slug": current["slug"],
            "title": new_title,
            "member_bot_slugs": members,
            "coordinator_bot_slug": coord,
            "stage_order": stages,
            "routing_mode": routing_mode,
            "ask_before_bot_handoff": (
                bool(updates["ask_before_bot_handoff"])
                if updates.get("ask_before_bot_handoff") is not None
                else current["ask_before_bot_handoff"]
            ),
            "max_bot_turns_per_message": (
                max(1, min(5, int(updates["max_bot_turns_per_message"])))
                if updates.get("max_bot_turns_per_message") is not None
                else current["max_bot_turns_per_message"]
            ),
            "pinned_page_slug": (
                (slugify(str(updates["pinned_page_slug"])) if str(updates["pinned_page_slug"]).strip() else None)
                if "pinned_page_slug" in updates
                else current["pinned_page_slug"]
            ),
            "pinned": bool(updates["pinned"]) if updates.get("pinned") is not None else current["pinned"],
            "section": str(updates["section"]).strip() if updates.get("section") is not None else current["section"],
            "owner_email": (
                normalize_email(updates["owner_email"])
                if updates.get("owner_email") is not None
                else normalize_email(current.get("owner_email"))
            ),
            "visibility": (
                next_room_vis := (
                    normalize_visibility(updates["visibility"])
                    if updates.get("visibility") is not None
                    else normalize_visibility(current.get("visibility"), default="shared")
                )
            ),
            "allowed_groups": (
                []
                if next_room_vis != "team"
                else (
                    normalize_group_slugs(updates["allowed_groups"])
                    if "allowed_groups" in updates and updates["allowed_groups"] is not None
                    else list(current.get("allowed_groups") or [])
                )
            ),
        }
        saved = self.upsert_document(
            collection="bot_rooms",
            external_key=current["slug"],
            search_text=f"{new_title} {' '.join(members)}",
            doc=new_doc,
            description="Multi-bot shared group chat rooms",
        )
        return self._serialize_room(saved)

    def delete_room(self, slug: str) -> None:
        """Delete a multi-bot Room definition and its transcript."""
        room = self.get_room(slug)
        with self._lock:
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'bot_rooms' AND id = ?",
                (room["id"],),
            )
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'room_threads' AND json_extract(doc_json, '$.room_slug') = ?",
                (room["slug"],),
            )
            self._conn.commit()

    @staticmethod
    def _serialize_room_message(room_slug: str, row: sqlite3.Row) -> dict[str, Any]:
        doc = json.loads(row["doc_json"])
        return {
            "id": row["id"],
            "room_slug": doc.get("room_slug", room_slug),
            "sender": doc.get("sender_type", doc.get("sender", "bot")),
            "sender_slug": doc.get("sender_slug", "bot"),
            "sender_name": doc.get("sender_name", "Bot"),
            "text": doc.get("text", ""),
            "metadata": doc.get("metadata") or {},
            "created_at": row["created_at"],
        }

    def append_room_message(
        self,
        room_slug: str,
        *,
        sender_type: str,
        sender_slug: str,
        sender_name: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        reply_to_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a message to a multi-bot Room thread in collection 'room_threads'."""
        msg_id = make_id("rmsg")
        now = utc_now()
        clean_room = slugify(room_slug)
        merged_meta = dict(metadata or {})
        if reply_to_id and "reply_to" not in merged_meta:
            preview = self._resolve_reply_preview(
                collection="room_threads",
                reply_to_id=reply_to_id,
                fallback_bot_name=sender_name,
            )
            if preview:
                merged_meta["reply_to"] = preview
        doc: dict[str, Any] = {
            "room_slug": clean_room,
            "sender_type": sender_type,
            "sender": sender_type,
            "sender_slug": sender_slug,
            "sender_name": sender_name,
            "text": text,
            "created_at": now,
        }
        if merged_meta:
            doc["metadata"] = merged_meta
        saved = self.upsert_document(
            collection="room_threads",
            external_key=f"{clean_room}:{msg_id}",
            search_text=f"{clean_room} {sender_name} {text}",
            doc=doc,
            description="Multi-bot shared room transcripts",
            doc_id=msg_id,
        )
        return {
            "id": saved["id"],
            "room_slug": clean_room,
            "sender": sender_type,
            "sender_slug": sender_slug,
            "sender_name": sender_name,
            "text": text,
            "metadata": merged_meta,
            "created_at": saved["created_at"],
        }

    def list_room_messages_window(
        self,
        room_slug: str,
        *,
        limit: int = 40,
        before_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], bool, int]:
        """Retrieve paginated chronological messages for a shared Room."""
        clean_room = slugify(room_slug)
        capped = max(1, min(int(limit), 200))
        with self._lock:
            total_row = self._conn.execute(
                """
                SELECT COUNT(*) FROM collection_documents
                WHERE collection = 'room_threads'
                  AND json_extract(doc_json, '$.room_slug') = ?
                """,
                (clean_room,),
            ).fetchone()
            total_count = int(total_row[0]) if total_row else 0

            if before_id:
                anchor = self._conn.execute(
                    """
                    SELECT rowid, created_at FROM collection_documents
                    WHERE collection = 'room_threads'
                      AND json_extract(doc_json, '$.room_slug') = ?
                      AND id = ?
                    """,
                    (clean_room, before_id),
                ).fetchone()
                if anchor is None:
                    return [], False, total_count
                rows = self._conn.execute(
                    """
                    SELECT id, doc_json, created_at
                    FROM collection_documents
                    WHERE collection = 'room_threads'
                      AND json_extract(doc_json, '$.room_slug') = ?
                      AND (created_at < ? OR (created_at = ? AND rowid < ?))
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (clean_room, anchor["created_at"], anchor["created_at"], anchor["rowid"], capped + 1),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, doc_json, created_at
                    FROM collection_documents
                    WHERE collection = 'room_threads'
                      AND json_extract(doc_json, '$.room_slug') = ?
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (clean_room, capped + 1),
                ).fetchall()

        has_more = len(rows) > capped
        window_rows = list(reversed(rows[:capped]))
        return [self._serialize_room_message(clean_room, r) for r in window_rows], has_more, total_count

    def list_room_messages(
        self,
        room_slug: str,
        *,
        limit: int | None = 40,
    ) -> list[dict[str, Any]]:
        clean_room = slugify(room_slug)
        if limit is not None:
            msgs, _, _ = self.list_room_messages_window(clean_room, limit=limit)
            return msgs
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, doc_json, created_at
                FROM collection_documents
                WHERE collection = 'room_threads'
                  AND json_extract(doc_json, '$.room_slug') = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (clean_room,),
            ).fetchall()
        return [self._serialize_room_message(clean_room, row) for row in rows]

    def clear_room_messages(
        self,
        room_slug: str,
        *,
        keep_last: int = 0,
        older_than_days: int | None = None,
    ) -> dict[str, int]:
        """Clear Team Room transcript rows without removing the Room or member bots."""
        room = self.get_room(room_slug)
        return self._clear_thread_messages(
            collection="room_threads",
            slug_field="room_slug",
            target_type="room",
            target_slug=room["slug"],
            keep_last=keep_last,
            older_than_days=older_than_days,
        )

    # ------------------------------------------------------------------
    # Per-User Shared Workspace Files (10 MB cap, isolated namespaces)
    # ------------------------------------------------------------------
    def _user_files_dir(self, owner_email: str | None) -> tuple[str, str, Path]:
        clean_email, user_ns = user_workspace_namespace(owner_email)
        root_dir = self._workspace_files_root.resolve()
        user_dir = (root_dir / user_ns).resolve()
        if not user_dir.is_relative_to(root_dir):
            raise ValueError("Invalid workspace file namespace.")
        user_dir.mkdir(parents=True, exist_ok=True)
        return clean_email, user_ns, user_dir

    def _finalize_workspace_file(
        self,
        *,
        file_id: str,
        clean_email: str,
        user_ns: str,
        user_dir: Path,
        raw_name: str,
        safe_name: str,
        stored_filename: str,
        target_path: Path,
        clean_mime: str,
        size_bytes: int,
        digest: str,
        uploaded_by: str,
    ) -> dict[str, Any]:
        ext = Path(safe_name).suffix.lower()
        is_image = clean_mime in _IMAGE_MIME_TYPES or ext in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
        text_preview = ""
        derived_datasets: list[dict[str, Any]] = []
        default_parquet_rel: str | None = None
        pages_parquet_rel: str | None = None
        page_count: int | None = None
        scanned_pages: list[int] = []
        extracted_tables: list[dict[str, Any]] = []
        secret_vals = self.collect_all_vault_secret_values()

        if not is_image and is_analytics_or_document_file(safe_name, clean_mime):
            derived_dir = (user_dir / ".derived" / file_id).resolve()
            if not derived_dir.is_relative_to(user_dir):
                raise ValueError("Invalid derived analytics path.")
            try:
                ingested = ingest_file_to_analytics(
                    target_path,
                    derived_dir,
                    file_id=file_id,
                    filename=safe_name,
                    mime_type=clean_mime,
                    vault_secrets=secret_vals,
                )
                for ds in ingested.get("derived_datasets") or []:
                    fname = str(ds.get("filename") or "")
                    ds_copy = dict(ds)
                    if fname:
                        ds_copy["rel_parquet"] = f"{user_ns}/.derived/{file_id}/{fname}"
                    derived_datasets.append(ds_copy)
                def_name = ingested.get("default_parquet_name")
                if def_name:
                    default_parquet_rel = f"{user_ns}/.derived/{file_id}/{def_name}"
                pages_name = ingested.get("pages_parquet_name")
                if pages_name:
                    pages_parquet_rel = f"{user_ns}/.derived/{file_id}/{pages_name}"
                page_count = ingested.get("page_count")
                scanned_pages = [int(p) for p in (ingested.get("scanned_pages") or [])]
                extracted_tables = list(ingested.get("extracted_tables") or [])
                text_preview = str(ingested.get("text_preview") or "")[:24_000]
            except Exception:
                shutil.rmtree(derived_dir, ignore_errors=True)
                if clean_mime.startswith("text/") or ext in _TEXT_PREVIEW_EXTENSIONS:
                    try:
                        with target_path.open("rb") as fh:
                            decoded = fh.read(128_000).decode("utf-8", errors="replace")
                        text_preview = redact_secrets(decoded, secret_vals)[:24_000]
                    except Exception:
                        text_preview = ""
        elif not is_image and (
            clean_mime.startswith("text/")
            or clean_mime in {"application/json", "application/xml", "application/csv"}
            or ext in _TEXT_PREVIEW_EXTENSIONS
        ):
            try:
                with target_path.open("rb") as fh:
                    decoded = fh.read(128_000).decode("utf-8", errors="replace")
                text_preview = redact_secrets(decoded, secret_vals)[:24_000]
            except Exception:
                text_preview = ""

        doc: dict[str, Any] = {
            "id": file_id,
            "filename": safe_name,
            "original_filename": raw_name[:200],
            "mime_type": clean_mime,
            "size_bytes": size_bytes,
            "sha256": digest,
            "owner_email": clean_email,
            "user_ns": user_ns,
            "uploaded_by": uploaded_by,
            "rel_path": f"{user_ns}/{stored_filename}",
            "is_image": is_image,
            "text_preview": text_preview,
        }
        if derived_datasets:
            doc["derived_datasets"] = derived_datasets
        if default_parquet_rel:
            doc["default_parquet_rel"] = default_parquet_rel
        if pages_parquet_rel:
            doc["pages_parquet_rel"] = pages_parquet_rel
        if page_count is not None:
            doc["page_count"] = page_count
        if scanned_pages:
            doc["scanned_pages"] = scanned_pages
        if extracted_tables:
            doc["extracted_tables"] = extracted_tables

        saved = self.upsert_document(
            collection="workspace_files",
            external_key=f"{user_ns}:{file_id}",
            search_text=f"{clean_email} {safe_name} {text_preview[:400]}",
            doc=doc,
            description="Per-user shared workspace files",
            doc_id=file_id,
        )
        return self._serialize_workspace_file(saved)

    def save_workspace_file(
        self,
        *,
        owner_email: str | None,
        filename: str,
        mime_type: str,
        content_bytes: bytes,
        uploaded_by: str = "user",
    ) -> dict[str, Any]:
        """Persist a file under the user's isolated directory up to 10 MB (100 MB for analytics/docs)."""
        size_bytes = len(content_bytes)
        clean_mime = (mime_type or "application/octet-stream").strip()[:150]
        raw_name = Path(filename or "attachment.bin").name
        limit_bytes = max_workspace_file_bytes_for_name(raw_name, clean_mime)
        if size_bytes > limit_bytes:
            limit_mb = limit_bytes // (1024 * 1024)
            raise FileTooLargeError(
                f"File exceeds the {limit_mb} MB limit ({size_bytes} bytes > {limit_bytes} bytes)."
            )
        clean_email, user_ns, user_dir = self._user_files_dir(owner_email)
        file_id = make_id("file")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).strip("._")[:120] or "attachment.bin"
        stored_filename = f"{file_id}_{safe_name}"
        target_path = (user_dir / stored_filename).resolve()
        if not target_path.is_relative_to(user_dir):
            raise ValueError("Invalid target file path.")

        target_path.write_bytes(content_bytes)
        digest = hashlib.sha256(content_bytes).hexdigest()
        return self._finalize_workspace_file(
            file_id=file_id,
            clean_email=clean_email,
            user_ns=user_ns,
            user_dir=user_dir,
            raw_name=raw_name,
            safe_name=safe_name,
            stored_filename=stored_filename,
            target_path=target_path,
            clean_mime=clean_mime,
            size_bytes=size_bytes,
            digest=digest,
            uploaded_by=uploaded_by,
        )

    def save_workspace_file_from_path(
        self,
        *,
        owner_email: str | None,
        filename: str,
        mime_type: str,
        source_path: Path,
        size_bytes: int,
        sha256_hex: str,
        uploaded_by: str = "user",
    ) -> dict[str, Any]:
        """Atomically move a streamed temp file into user_dir and materialize Parquet sidecars."""
        clean_mime = (mime_type or "application/octet-stream").strip()[:150]
        raw_name = Path(filename or "attachment.bin").name
        limit_bytes = max_workspace_file_bytes_for_name(raw_name, clean_mime)
        if size_bytes > limit_bytes:
            source_path.unlink(missing_ok=True)
            limit_mb = limit_bytes // (1024 * 1024)
            raise FileTooLargeError(
                f"File exceeds the {limit_mb} MB limit ({size_bytes} bytes > {limit_bytes} bytes)."
            )
        clean_email, user_ns, user_dir = self._user_files_dir(owner_email)
        file_id = make_id("file")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).strip("._")[:120] or "attachment.bin"
        stored_filename = f"{file_id}_{safe_name}"
        target_path = (user_dir / stored_filename).resolve()
        if not target_path.is_relative_to(user_dir):
            source_path.unlink(missing_ok=True)
            raise ValueError("Invalid target file path.")
        shutil.move(str(source_path), str(target_path))
        return self._finalize_workspace_file(
            file_id=file_id,
            clean_email=clean_email,
            user_ns=user_ns,
            user_dir=user_dir,
            raw_name=raw_name,
            safe_name=safe_name,
            stored_filename=stored_filename,
            target_path=target_path,
            clean_mime=clean_mime,
            size_bytes=size_bytes,
            digest=sha256_hex,
            uploaded_by=uploaded_by,
        )

    @staticmethod
    def _serialize_workspace_file(item: dict[str, Any], *, include_preview: bool = False) -> dict[str, Any]:
        doc = item.get("doc") or {}
        derived = list(doc.get("derived_datasets") or [])
        res: dict[str, Any] = {
            "id": item["id"],
            "dataset_id": f"file:{item['id']}",
            "filename": str(doc.get("filename") or "file"),
            "original_filename": str(doc.get("original_filename") or doc.get("filename") or "file"),
            "mime_type": str(doc.get("mime_type") or "application/octet-stream"),
            "size_bytes": int(doc.get("size_bytes") or 0),
            "sha256": str(doc.get("sha256") or ""),
            "owner_email": str(doc.get("owner_email") or ""),
            "uploaded_by": str(doc.get("uploaded_by") or "user"),
            "is_image": bool(doc.get("is_image", False)),
            "is_analytics": bool(derived),
            "has_text_preview": bool(doc.get("text_preview")),
            "created_at": item["created_at"],
            "updated_at": item["updated_at"],
        }
        if derived:
            res["derived_datasets"] = [
                {
                    "id": ds.get("id"),
                    "alias": ds.get("alias"),
                    "kind": ds.get("kind"),
                    "sheet_name": ds.get("sheet_name"),
                    "page_num": ds.get("page_num"),
                    "row_count": ds.get("row_count", 0),
                    "columns": list(ds.get("columns") or []),
                }
                for ds in derived
            ]
        if doc.get("page_count") is not None:
            res["page_count"] = int(doc["page_count"])
        if doc.get("scanned_pages"):
            res["scanned_pages"] = [int(p) for p in doc["scanned_pages"]]
        if doc.get("extracted_tables"):
            res["extracted_tables"] = list(doc["extracted_tables"])
        if include_preview:
            res["text_preview"] = str(doc.get("text_preview") or "")
        return res

    def list_workspace_files(self, owner_email: str | None) -> list[dict[str, Any]]:
        """List files belonging strictly to owner_email."""
        clean_email, _ = user_workspace_namespace(owner_email)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, doc_json, created_at, updated_at
                FROM collection_documents
                WHERE collection = 'workspace_files'
                  AND json_extract(doc_json, '$.owner_email') = ?
                ORDER BY updated_at DESC
                LIMIT 200
                """,
                (clean_email,),
            ).fetchall()
        items = [
            {
                "id": r["id"],
                "doc": json.loads(r["doc_json"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]
        return [self._serialize_workspace_file(item) for item in items]

    def get_workspace_file(
        self,
        file_id_or_name: str,
        *,
        owner_email: str | None,
    ) -> tuple[dict[str, Any], Path]:
        """Fetch a user's workspace file metadata and verified disk path."""
        clean_email, _, user_dir = self._user_files_dir(owner_email)
        key = str(file_id_or_name or "").strip()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, doc_json, created_at, updated_at
                FROM collection_documents
                WHERE collection = 'workspace_files'
                  AND json_extract(doc_json, '$.owner_email') = ?
                  AND (id = ? OR json_extract(doc_json, '$.filename') = ?)
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (clean_email, key, key),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"File '{key}' not found in your workspace.")
        doc = json.loads(row["doc_json"])
        root_dir = self._workspace_files_root.resolve()
        file_path = (root_dir / str(doc.get("rel_path") or "")).resolve()
        if not file_path.is_relative_to(user_dir) or not file_path.is_file():
            raise NotFoundError(f"File '{key}' is unavailable on disk.")
        meta = self._serialize_workspace_file(
            {
                "id": row["id"],
                "doc": doc,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            },
            include_preview=True,
        )
        return meta, file_path

    def delete_workspace_file(self, file_id: str, *, owner_email: str | None) -> None:
        """Delete a user's workspace file and derived Parquet sidecars from disk and SQLite."""
        _, _, user_dir = self._user_files_dir(owner_email)
        meta, file_path = self.get_workspace_file(file_id, owner_email=owner_email)
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass
        derived_dir = (user_dir / ".derived" / meta["id"]).resolve()
        if derived_dir.is_relative_to(user_dir):
            shutil.rmtree(derived_dir, ignore_errors=True)
        self.delete_document("workspace_files", meta["id"])

    def get_workspace_file_derived_paths(
        self,
        file_id: str,
        *,
        owner_email: str | None,
    ) -> dict[str, Any]:
        """Return verified disk paths for a file's derived Parquet artifacts (enforcing SSO ownership)."""
        clean_email, _, user_dir = self._user_files_dir(owner_email)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, doc_json
                FROM collection_documents
                WHERE collection = 'workspace_files' AND id = ?
                LIMIT 1
                """,
                (file_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"Workspace file '{file_id}' not found.")
        doc = json.loads(row["doc_json"])
        if str(doc.get("owner_email") or "") != clean_email:
            raise PermissionError(
                f"User '{clean_email}' does not own workspace file '{file_id}'."
            )
        root_dir = self._workspace_files_root.resolve()
        derived_entries: list[dict[str, Any]] = []
        for ds in doc.get("derived_datasets") or []:
            rel = str(ds.get("rel_parquet") or "")
            if not rel:
                continue
            p = (root_dir / rel).resolve()
            if p.is_relative_to(user_dir) and p.is_file():
                derived_entries.append({**ds, "parquet_path": str(p)})
        def_rel = str(doc.get("default_parquet_rel") or "")
        def_path = (root_dir / def_rel).resolve() if def_rel else None
        if def_path and not (def_path.is_relative_to(user_dir) and def_path.is_file()):
            def_path = None
        pages_rel = str(doc.get("pages_parquet_rel") or "")
        pages_path = (root_dir / pages_rel).resolve() if pages_rel else None
        if pages_path and not (pages_path.is_relative_to(user_dir) and pages_path.is_file()):
            pages_path = None
        return {
            "file_id": file_id,
            "filename": str(doc.get("filename") or file_id),
            "default_parquet_path": str(def_path) if def_path else None,
            "pages_parquet_path": str(pages_path) if pages_path else None,
            "derived_datasets": derived_entries,
            "page_count": doc.get("page_count"),
            "scanned_pages": list(doc.get("scanned_pages") or []),
            "extracted_tables": list(doc.get("extracted_tables") or []),
        }

    # ------------------------------------------------------------------
    # Per-User Thread Read Cursors & Delegation Plans
    # ------------------------------------------------------------------
    def mark_thread_read(
        self,
        *,
        user_email: str | None,
        target_type: str,
        slug: str,
        read_at: str | None = None,
    ) -> dict[str, Any]:
        """Record when user_email last viewed a bot or room thread."""
        clean_email, _ = user_workspace_namespace(user_email)
        clean_type = "room" if target_type == "room" else "bot"
        clean_slug = slugify(slug)
        ts = read_at or utc_now()
        saved = self.upsert_document(
            collection="thread_read_cursors",
            external_key=f"{clean_email}:{clean_type}:{clean_slug}",
            search_text=f"{clean_email} {clean_type} {clean_slug}",
            doc={
                "user_email": clean_email,
                "target_type": clean_type,
                "slug": clean_slug,
                "last_read_at": ts,
            },
            description="Per-user thread read cursors for unread badges",
        )
        return saved["doc"]

    def _list_read_cursors_for_user(self, user_email: str | None) -> dict[tuple[str, str], str]:
        clean_email, _ = user_workspace_namespace(user_email)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT doc_json FROM collection_documents
                WHERE collection = 'thread_read_cursors'
                  AND json_extract(doc_json, '$.user_email') = ?
                """,
                (clean_email,),
            ).fetchall()
        cursors: dict[tuple[str, str], str] = {}
        for r in rows:
            doc = json.loads(r["doc_json"])
            t_type = str(doc.get("target_type") or "bot")
            t_slug = str(doc.get("slug") or "")
            if t_slug and doc.get("last_read_at"):
                cursors[(t_type, t_slug)] = str(doc["last_read_at"])
        return cursors

    def save_delegation_plan(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Persist a Coordinator multi-bot plan so it can be approved and executed round-trip."""
        plan_id = str(plan.get("id") or make_id("plan"))
        payload = {**plan, "id": plan_id}
        saved = self.upsert_document(
            collection="delegation_plans",
            external_key=plan_id,
            search_text=f"{plan.get('coordinator_slug', '')} {plan.get('goal', '')}"[:400],
            doc=payload,
            description="Coordinator delegation plans awaiting execution or completed",
            doc_id=plan_id,
        )
        return saved["doc"]

    def get_delegation_plan(self, plan_id: str) -> dict[str, Any]:
        """Fetch a persisted Coordinator delegation plan by id."""
        item = self.get_document_by_external_key("delegation_plans", plan_id)
        if item is None:
            raise NotFoundError(f"Delegation plan '{plan_id}' not found.")
        return item["doc"]

    # ------------------------------------------------------------------
    # Credential-Free Multi-Bot Team Packs
    # ------------------------------------------------------------------
    def export_team_pack(
        self,
        *,
        bot_slugs: list[str] | None = None,
        room_slugs: list[str] | None = None,
        section: str | None = None,
        title: str | None = None,
    ) -> dict[str, Any]:
        """Export a sanitized multi-bot Team Pack (bots + rooms + skills + pages, zero secrets)."""
        all_bots = self.list_bots()
        selected_slugs: list[str] = []
        if bot_slugs:
            for s in bot_slugs:
                cs = slugify(s)
                if cs and cs not in selected_slugs:
                    selected_slugs.append(cs)
        elif section and section.strip():
            sec_lower = section.strip().lower()
            selected_slugs = [
                b["slug"] for b in all_bots if (b.get("section") or "").strip().lower() == sec_lower
            ]

        all_rooms = self.list_rooms()
        selected_rooms: list[dict[str, Any]] = []
        if room_slugs:
            want_rooms = {slugify(r) for r in room_slugs if r.strip()}
            selected_rooms = [r for r in all_rooms if r["slug"] in want_rooms]
            for r in selected_rooms:
                for m in r["member_bot_slugs"]:
                    if m not in selected_slugs:
                        selected_slugs.append(m)
        elif selected_slugs:
            sel_set = set(selected_slugs)
            selected_rooms = [
                r for r in all_rooms if any(m in sel_set for m in r["member_bot_slugs"])
            ]
        else:
            selected_slugs = [b["slug"] for b in all_bots]
            selected_rooms = all_rooms

        if not selected_slugs:
            raise ValueError("No bots selected for Team Pack export.")

        blueprints: list[dict[str, Any]] = []
        required_providers: list[str] = []
        for bslug in selected_slugs:
            bp = self.export_bot_blueprint(bslug)
            bp["source_slug"] = bslug
            blueprints.append(bp)
            for prov in bp.get("required_providers") or []:
                if prov not in required_providers:
                    required_providers.append(prov)

        sel_set = set(selected_slugs)
        exported_pages = [
            {
                "source_slug": p["slug"],
                "title": p["title"],
                "render_mode": p["render_mode"],
                "content_payload": p["content_payload"],
                "allowed_collections": list(p.get("allowed_collections") or []),
                "owner_bot_slug": p["owner_bot_slug"],
                "pinned": p["pinned"],
            }
            for p in self.list_pages()
            if p.get("owner_bot_slug") in sel_set
            or any(r.get("pinned_page_slug") == p["slug"] for r in selected_rooms)
        ]

        exported_rooms = [
            {
                "source_slug": r["slug"],
                "title": r["title"],
                "member_bot_slugs": list(r["member_bot_slugs"]),
                "coordinator_bot_slug": r.get("coordinator_bot_slug"),
                "stage_order": list(r.get("stage_order") or []),
                "routing_mode": r.get("routing_mode", "auto"),
                "ask_before_bot_handoff": bool(r.get("ask_before_bot_handoff", False)),
                "max_bot_turns_per_message": int(r.get("max_bot_turns_per_message") or 3),
                "pinned_page_slug": r.get("pinned_page_slug"),
                "section": r.get("section") or "",
            }
            for r in selected_rooms
            if sum(1 for m in r["member_bot_slugs"] if m in sel_set) >= 2
        ]

        pack_title = (
            (title or "").strip()
            or (f"{section.strip()} Team Pack" if section and section.strip() else "Argo Team Pack")
        )
        return {
            "schema_version": "argo.team_pack.v1",
            "title": pack_title,
            "description": f"Portable team of {len(blueprints)} bot(s) and {len(exported_rooms)} room(s).",
            "section": (section or "").strip(),
            "required_providers": required_providers,
            "bots": blueprints,
            "rooms": exported_rooms,
            "pages": exported_pages,
        }

    def import_team_pack(
        self,
        pack: dict[str, Any],
        *,
        linked_accounts: list[str] | None = None,
        section_override: str | None = None,
        owner_email: str = "",
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Import a multi-bot Team Pack with automatic slug-collision remapping across bots, rooms & pages."""
        if not isinstance(pack, dict):
            raise ValueError("Team Pack payload must be a JSON object.")
        raw_bots = pack.get("bots")
        if not isinstance(raw_bots, list) or not raw_bots:
            raise ValueError("Team Pack must contain a non-empty 'bots' list.")

        slug_map: dict[str, str] = {}
        created_bots: list[dict[str, Any]] = []
        pending_handoffs: list[tuple[str, str]] = []
        override_sec = (section_override or pack.get("section") or "").strip()

        for bp in raw_bots:
            if not isinstance(bp, dict):
                continue
            orig_slug = slugify(str(bp.get("source_slug") or bp.get("slug") or bp.get("name") or ""))
            bp_copy = dict(bp)
            if override_sec and not bp_copy.get("section"):
                bp_copy["section"] = override_sec
            orig_handoff = str(bp_copy.pop("handoff_bot_slug", "") or "").strip()
            created = self.import_bot_blueprint(
                bp_copy,
                linked_accounts=linked_accounts if linked_accounts else None,
                owner_email=owner_email,
                visibility=visibility,
                allowed_groups=allowed_groups,
            )
            if orig_slug:
                slug_map[orig_slug] = created["slug"]
            if orig_handoff:
                pending_handoffs.append((created["slug"], slugify(orig_handoff)))
            created_bots.append(created)

        for bot_slug, orig_target in pending_handoffs:
            mapped_target = slug_map.get(orig_target, orig_target)
            if mapped_target and mapped_target != bot_slug:
                try:
                    self.update_bot(bot_slug, {"handoff_bot_slug": mapped_target})
                except Exception:
                    pass

        remapped_created_bots: list[dict[str, Any]] = []
        for cb in created_bots:
            cols = dict(cb.get("collections") or {"read": ["bot_threads"], "write": []})
            new_read = list(cols.get("read") or [])
            new_write = list(cols.get("write") or [])
            changed_cols = False
            for old_s, new_s in slug_map.items():
                if old_s != new_s:
                    old_col = f"bot_{old_s}_items"
                    new_col = f"bot_{new_s}_items"
                    if old_col in new_read:
                        new_read = [new_col if c == old_col else c for c in new_read]
                        changed_cols = True
                    if old_col in new_write:
                        new_write = [new_col if c == old_col else c for c in new_write]
                        changed_cols = True
            if changed_cols:
                cb = self.update_bot(cb["slug"], {"collections": {"read": new_read, "write": new_write}})
            remapped_created_bots.append(cb)
        created_bots = remapped_created_bots

        page_slug_map: dict[str, str] = {}
        created_pages: list[dict[str, Any]] = []
        for pg in pack.get("pages") or []:
            if not isinstance(pg, dict) or not pg.get("title"):
                continue
            orig_owner = slugify(str(pg.get("owner_bot_slug") or ""))
            mapped_owner = slug_map.get(orig_owner) or (created_bots[0]["slug"] if created_bots else "")
            remapped_cols: list[str] = []
            for c in pg.get("allowed_collections") or []:
                col_str = str(c)
                for old_s, new_s in slug_map.items():
                    if old_s != new_s and f"bot_{old_s}_items" == col_str:
                        col_str = f"bot_{new_s}_items"
                remapped_cols.append(col_str)
            page_payload = pg.get("content_payload")
            if page_payload is not None:
                payload_str = str(page_payload)
                for old_s, new_s in slug_map.items():
                    if old_s != new_s:
                        old_col = f"bot_{old_s}_items"
                        new_col = f"bot_{new_s}_items"
                        if old_col in payload_str:
                            payload_str = payload_str.replace(old_col, new_col)
                page_payload = payload_str
            if page_payload is None and pg.get("template_key"):
                page_payload = self.build_interactive_page_html(
                    template_key=str(pg["template_key"]),
                    title=str(pg["title"]),
                    description=str(pg.get("description") or ""),
                    allowed_collections=remapped_cols,
                )
            saved_pg = self.create_page(
                title=str(pg["title"]),
                description=str(pg.get("description") or ""),
                render_mode=str(pg.get("render_mode") or "sandboxed_html"),
                content_payload=str(page_payload) if page_payload is not None else None,
                allowed_collections=remapped_cols,
                owner_bot_slug=mapped_owner,
                created_by_email=owner_email,
                visibility=visibility or "shared",
                allowed_groups=allowed_groups,
                pinned=bool(pg.get("pinned", True)),
            )
            src_pg = slugify(str(pg.get("source_slug") or pg.get("slug") or pg["title"]))
            page_slug_map[src_pg] = saved_pg["slug"]
            created_pages.append(saved_pg)

        created_rooms: list[dict[str, Any]] = []
        for rm in pack.get("rooms") or []:
            if not isinstance(rm, dict) or not rm.get("title"):
                continue
            mapped_members = [
                slug_map.get(slugify(str(m)), slugify(str(m)))
                for m in (rm.get("member_bot_slugs") or [])
            ]
            mapped_members = [m for m in dict.fromkeys(mapped_members) if m]
            if len(mapped_members) < 2:
                continue
            raw_coord = rm.get("coordinator_bot_slug")
            mapped_coord = slug_map.get(slugify(str(raw_coord)), slugify(str(raw_coord))) if raw_coord else None
            mapped_stages = [
                slug_map.get(slugify(str(s)), slugify(str(s)))
                for s in (rm.get("stage_order") or [])
            ]
            raw_pinned_pg = rm.get("pinned_page_slug")
            mapped_pinned_pg = page_slug_map.get(slugify(str(raw_pinned_pg)), raw_pinned_pg) if raw_pinned_pg else None
            created_rm = self.create_room(
                title=str(rm["title"]),
                member_bot_slugs=mapped_members[:6],
                coordinator_bot_slug=mapped_coord,
                stage_order=mapped_stages,
                routing_mode=str(rm.get("routing_mode") or "auto"),
                ask_before_bot_handoff=bool(rm.get("ask_before_bot_handoff", False)),
                max_bot_turns_per_message=int(rm.get("max_bot_turns_per_message") or 3),
                pinned_page_slug=mapped_pinned_pg,
                section=str(rm.get("section") or override_sec),
                owner_email=owner_email,
                visibility=visibility,
                allowed_groups=allowed_groups,
            )
            created_rooms.append(created_rm)

        return {
            "bots": created_bots,
            "rooms": created_rooms,
            "pages": created_pages,
            "slug_map": slug_map,
        }

    @staticmethod
    def list_starter_team_packs() -> list[dict[str, Any]]:
        """Return starter Team Packs (empty by default; packs are imported via JSON)."""
        return []

    # ------------------------------------------------------------------
    # Activity / Events Log (Primitive 2)
    # ------------------------------------------------------------------
    def record_event(
        self,
        *,
        correlation_id: str,
        source_slug: str,
        target_slug: str | None,
        event_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an inter-bot bus event to events_log."""
        event_id = make_id("ev")
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO events_log(
                    id, correlation_id, source_slug, target_slug,
                    event_type, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    correlation_id,
                    source_slug,
                    target_slug,
                    event_type,
                    json.dumps(payload),
                    now,
                ),
            )
            self._conn.commit()
        return {
            "id": event_id,
            "correlation_id": correlation_id,
            "source_slug": source_slug,
            "target_slug": target_slug,
            "event_type": event_type,
            "payload": payload,
            "created_at": now,
        }

    def list_events(self, category: str = "all", limit: int = 50) -> list[dict[str, Any]]:
        """List recent Activity stream events ordered newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, correlation_id, source_slug, target_slug,
                       event_type, payload_json, created_at
                FROM events_log
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (max(1, min(limit, 200)),),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            ev_category = payload.get("category", "reviews")
            if category != "all" and ev_category != category:
                continue
            results.append(
                {
                    "id": row["id"],
                    "correlation_id": row["correlation_id"],
                    "source_slug": row["source_slug"],
                    "target_slug": row["target_slug"],
                    "event_type": row["event_type"],
                    "payload": payload,
                    "created_at": row["created_at"],
                }
            )
        return results

    # ------------------------------------------------------------------
    # Approvals & Style Memory (Primitive 4)
    # ------------------------------------------------------------------
    def _serialize_approval(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = json.loads(row["payload_json"])
        edited = json.loads(row["edited_payload_json"]) if row["edited_payload_json"] else None
        return {
            "id": row["id"],
            "correlation_id": row["correlation_id"],
            "bot_slug": row["bot_slug"],
            "target_account_slug": row["target_account_slug"],
            "action_type": row["action_type"],
            "status": row["status"],
            "payload": payload,
            "edited_payload": edited,
            "source_url": row["source_url"],
            "source_excerpt": row["source_excerpt"],
            "escalation_note": row["escalation_note"],
            "approved_by": row["approved_by"],
            "telegram_chat_id": row["telegram_chat_id"],
            "telegram_message_id": row["telegram_message_id"],
            "error_message": row["error_message"],
            "created_at": row["created_at"],
            "resolved_at": row["resolved_at"],
        }

    def create_approval(
        self,
        *,
        correlation_id: str,
        bot_slug: str,
        target_account_slug: str,
        action_type: str,
        payload: dict[str, Any],
        source_url: str | None = None,
        source_excerpt: str | None = None,
        escalation_note: str | None = None,
    ) -> dict[str, Any]:
        """Enqueue a pending outbound action into approvals_outbox."""
        approval_id = make_id("apr")
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approvals_outbox(
                    id, correlation_id, bot_slug, target_account_slug,
                    action_type, status, payload_json, source_url,
                    source_excerpt, escalation_note, created_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    correlation_id,
                    bot_slug,
                    target_account_slug,
                    action_type,
                    json.dumps(payload),
                    source_url,
                    source_excerpt,
                    escalation_note,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM approvals_outbox WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._serialize_approval(row)

    def list_approvals(self, tab: str = "pending") -> list[dict[str, Any]]:
        """List pending or resolved approval items."""
        with self._lock:
            if tab == "pending":
                rows = self._conn.execute(
                    "SELECT * FROM approvals_outbox WHERE status = 'pending' ORDER BY created_at DESC"
                ).fetchall()
            elif tab == "history":
                rows = self._conn.execute(
                    "SELECT * FROM approvals_outbox WHERE status != 'pending' ORDER BY resolved_at DESC, created_at DESC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM approvals_outbox ORDER BY created_at DESC"
                ).fetchall()
        return [self._serialize_approval(row) for row in rows]

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        """Fetch a single approval row by ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals_outbox WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"Approval '{approval_id}' not found.")
        return self._serialize_approval(row)

    def list_approvals_by_correlation(
        self,
        correlation_id: str,
        *,
        bot_slug: str | None = None,
        batch_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List approvals matching correlation_id (optionally filtered by bot_slug and payload.batch_id)."""
        clean_corr = str(correlation_id or "").strip()
        if not clean_corr:
            return []
        with self._lock:
            if bot_slug and bot_slug.strip():
                rows = self._conn.execute(
                    """
                    SELECT * FROM approvals_outbox
                    WHERE correlation_id = ? AND bot_slug = ?
                    ORDER BY created_at ASC, rowid ASC
                    """,
                    (clean_corr, bot_slug.strip()),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM approvals_outbox
                    WHERE correlation_id = ?
                    ORDER BY created_at ASC, rowid ASC
                    """,
                    (clean_corr,),
                ).fetchall()
        items = [self._serialize_approval(row) for row in rows]
        if batch_id and batch_id.strip():
            target_batch = batch_id.strip()
            items = [
                it
                for it in items
                if str((it.get("payload") or {}).get("batch_id") or "").strip() == target_batch
            ]
        return items

    def get_pending_approval_by_telegram_message(
        self,
        *,
        chat_id: str | int,
        message_id: int,
    ) -> dict[str, Any] | None:
        """Look up a pending approval linked to a Telegram permission card."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM approvals_outbox
                WHERE telegram_chat_id = ? AND telegram_message_id = ? AND status = 'pending'
                """,
                (str(chat_id), int(message_id)),
            ).fetchone()
        return self._serialize_approval(row) if row is not None else None

    def set_approval_telegram_card(
        self,
        approval_id: str,
        *,
        chat_id: str | int,
        message_id: int,
    ) -> dict[str, Any]:
        """Persist the Telegram permission card message reference on an approval row."""
        with self._lock:
            self._conn.execute(
                """
                UPDATE approvals_outbox
                SET telegram_chat_id = ?, telegram_message_id = ?
                WHERE id = ?
                """,
                (str(chat_id), int(message_id), approval_id),
            )
            self._conn.commit()
        return self.get_approval(approval_id)

    def mark_approval_dispatch_result(
        self,
        approval_id: str,
        *,
        executed: bool,
        error_message: str | None = None,
        execution_result: dict[str, Any] | None = None,
        revert_to_pending: bool = False,
    ) -> dict[str, Any]:
        """Record downstream connector execution success ('executed') or failure/retryable state."""
        with self._tx():
            updated_payload_json: str | None = None
            if execution_result is not None:
                row = self._conn.execute(
                    "SELECT payload_json FROM approvals_outbox WHERE id = ?",
                    (approval_id,),
                ).fetchone()
                if row is not None:
                    try:
                        existing_payload = json.loads(row["payload_json"] or "{}")
                    except json.JSONDecodeError:
                        existing_payload = {}
                    if not isinstance(existing_payload, dict):
                        existing_payload = {}
                    existing_payload["execution_result"] = execution_result
                    updated_payload_json = json.dumps(existing_payload)
            if executed:
                if updated_payload_json is not None:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET status = 'executed', error_message = NULL, payload_json = ? WHERE id = ?",
                        (updated_payload_json, approval_id),
                    )
                else:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET status = 'executed', error_message = NULL WHERE id = ?",
                        (approval_id,),
                    )
            elif revert_to_pending:
                if updated_payload_json is not None:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET status = 'pending', approved_by = NULL, resolved_at = NULL, error_message = ?, payload_json = ? WHERE id = ?",
                        (error_message, updated_payload_json, approval_id),
                    )
                else:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET status = 'pending', approved_by = NULL, resolved_at = NULL, error_message = ? WHERE id = ?",
                        (error_message, approval_id),
                    )
            else:
                if updated_payload_json is not None:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET error_message = ?, payload_json = ? WHERE id = ?",
                        (error_message, updated_payload_json, approval_id),
                    )
                else:
                    self._conn.execute(
                        "UPDATE approvals_outbox SET error_message = ? WHERE id = ?",
                        (error_message, approval_id),
                    )
        return self.get_approval(approval_id)

    def supersede_approval(self, approval_id: str, *, actor: str) -> dict[str, Any]:
        """Atomically mark a pending approval as superseded by a revised draft."""
        now = utc_now()
        with self._tx():
            cursor = self._conn.execute(
                """
                UPDATE approvals_outbox
                SET status = 'superseded', approved_by = ?, resolved_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (actor, now, approval_id),
            )
            if cursor.rowcount == 0:
                raise AlreadyResolvedError("Already resolved.")
            row = self._conn.execute(
                "SELECT * FROM approvals_outbox WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._serialize_approval(row)

    def count_bot_outbound_executions_today(
        self,
        bot_slug: str,
        account_slug: str | None = None,
    ) -> int:
        """Count direct connector.executed actions for bot_slug today (UTC) in events_log."""
        today_prefix = utc_now()[:10]
        with self._lock:
            if account_slug is not None:
                norm_account = slugify(account_slug)
                row = self._conn.execute(
                    """
                    SELECT COUNT(*) FROM events_log
                    WHERE event_type = 'connector.executed'
                      AND source_slug = ?
                      AND (target_slug = ? OR target_slug = ?)
                      AND substr(created_at, 1, 10) = ?
                    """,
                    (bot_slug, account_slug, norm_account, today_prefix),
                ).fetchone()
            else:
                row = self._conn.execute(
                    """
                    SELECT COUNT(*) FROM events_log
                    WHERE event_type = 'connector.executed'
                      AND source_slug = ?
                      AND substr(created_at, 1, 10) = ?
                    """,
                    (bot_slug, today_prefix),
                ).fetchone()
        return int(row[0]) if row else 0

    def resolve_approval(
        self,
        *,
        approval_id: str,
        action: str,
        actor: str,
        edited_text: str | None = None,
        style_rule: str | None = None,
    ) -> dict[str, Any]:
        """Atomically transition a pending approval row and optionally persist a style rule."""
        target_status = "rejected" if action == "reject" else "approved"
        now = utc_now()

        with self._tx():
            existing = self._conn.execute(
                "SELECT payload_json, bot_slug FROM approvals_outbox WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if existing is None:
                raise AlreadyResolvedError(f"Approval '{approval_id}' not found.")

            original = json.loads(existing["payload_json"])
            orig_text = str(original.get("text") or "")
            edited_payload_json: str | None = None
            diff_json: str | None = None
            clean_edited = edited_text.strip() if edited_text is not None else ""
            if clean_edited:
                edited_payload = {**original, "text": clean_edited}
                edited_payload_json = json.dumps(edited_payload)
                diff_json = json.dumps({"before": orig_text, "after": clean_edited})

            cursor = self._conn.execute(
                """
                UPDATE approvals_outbox
                SET status = ?,
                    edited_payload_json = COALESCE(?, edited_payload_json),
                    approved_by = ?,
                    resolved_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (target_status, edited_payload_json, actor, now, approval_id),
            )
            if cursor.rowcount == 0:
                raise AlreadyResolvedError("Already resolved.")

            resolved_rule = (style_rule or "").strip()
            if not resolved_rule and action == "edit_approve" and clean_edited and clean_edited != orig_text.strip():
                resolved_rule = derive_style_rule_from_diff(orig_text, clean_edited)

            if resolved_rule:
                self._conn.execute(
                    """
                    INSERT INTO style_memory(id, scope_slug, rule_text, example_diff_json, active, created_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                    """,
                    (
                        make_id("sr"),
                        existing["bot_slug"] or "*",
                        resolved_rule,
                        diff_json or "{}",
                        now,
                    ),
                )

            updated = self._conn.execute(
                "SELECT * FROM approvals_outbox WHERE id = ?", (approval_id,)
            ).fetchone()
        return self._serialize_approval(updated)

    def list_style_rules(self) -> list[dict[str, Any]]:
        """List active editorial style rules from style_memory."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, scope_slug, rule_text, example_diff_json, active, created_at
                FROM style_memory
                WHERE active = 1
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [
            {
                "id": row["id"],
                "scope_slug": row["scope_slug"],
                "rule_text": row["rule_text"],
                "active": bool(row["active"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def add_style_rule(
        self,
        *,
        rule_text: str,
        scope_slug: str = "*",
        example_diff: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Insert a new active editorial constraint into style_memory."""
        rule_id = make_id("sr")
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO style_memory(id, scope_slug, rule_text, example_diff_json, active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (
                    rule_id,
                    scope_slug,
                    rule_text.strip(),
                    json.dumps(example_diff) if example_diff else None,
                    now,
                ),
            )
            self._conn.commit()
        return {
            "id": rule_id,
            "scope_slug": scope_slug,
            "rule_text": rule_text.strip(),
            "active": True,
            "created_at": now,
        }

    def delete_style_rule(self, rule_id: str) -> None:
        """Delete a rule from style_memory."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM style_memory WHERE id = ?", (rule_id,))
            self._conn.commit()
            if cursor.rowcount == 0:
                raise NotFoundError(f"Style rule '{rule_id}' not found.")

    # ------------------------------------------------------------------
    # Pages & Collections (Primitives 3 & 5)
    # ------------------------------------------------------------------
    def _serialize_page(self, row: sqlite3.Row) -> dict[str, Any]:
        cols_present = set(row.keys())
        vis = normalize_visibility(
            row["visibility"] if "visibility" in cols_present else "shared", default="shared"
        )
        groups = (
            self._decode_groups(row["allowed_groups_json"])
            if "allowed_groups_json" in cols_present and vis == "team"
            else []
        )
        return {
            "id": row["id"],
            "slug": row["slug"],
            "title": row["title"],
            "icon": row["icon"],
            "render_mode": row["render_mode"],
            "content_payload": row["content_payload"],
            "allowed_collections": json.loads(row["allowed_collections_json"]),
            "owner_bot_slug": row["owner_bot_slug"],
            "created_by_email": str(row["created_by_email"] or "") if "created_by_email" in cols_present else "",
            "visibility": vis,
            "allowed_groups": groups,
            "pinned": bool(row["pinned"]),
            "updated_at": row["updated_at"],
        }

    def list_pages(self) -> list[dict[str, Any]]:
        """List dynamic pages sorted by updated_at."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM pages ORDER BY pinned DESC, updated_at DESC"
            ).fetchall()
        return [self._serialize_page(row) for row in rows]

    def get_page(self, slug: str) -> dict[str, Any]:
        """Fetch a dynamic page by slug."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            raise NotFoundError(f"Page '{slug}' not found.")
        return self._serialize_page(row)

    @staticmethod
    def _default_sandboxed_html_payload(
        *,
        title: str,
        description: str,
        allowed_collections: list[str],
    ) -> str:
        safe_title = html.escape(title)
        safe_desc = html.escape(description or "Sandboxed micro-app backed by SQLite collections.")
        primary_coll = html.escape(allowed_collections[0]) if allowed_collections else ""
        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{safe_title}</title></head>
<body style="font-family:system-ui,-apple-system,sans-serif;margin:0;padding:16px;background:var(--bg,#161920);color:var(--text,#f3f4f6);">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
    <div>
      <h3 style="margin:0;font-size:14px;color:var(--text,#f3f4f6);">{safe_title}</h3>
      <p style="margin:2px 0 0;font-size:11px;color:var(--muted,#9ca3af);">{safe_desc}</p>
    </div>
    <span style="font-size:10px;padding:2px 8px;border-radius:999px;background:var(--surface,#181c23);border:1px solid var(--border,#2d3440);color:var(--muted,#9ca3af);">sandbox="allow-scripts allow-downloads" · postMessage</span>
  </div>
  <div id="kpiRow" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:12px;"></div>
  <div id="recordsBox" style="background:var(--card,#1e232c);border:1px solid var(--border,#2d3440);border-radius:8px;padding:10px;font-size:12px;color:var(--text,#f3f4f6);">
    Waiting for parent postMessage payload...
  </div>
  <script>
    const primaryCollection = {json.dumps(primary_coll)};
    function renderRecords(records) {{
      const kpi = document.getElementById("kpiRow");
      const box = document.getElementById("recordsBox");
      kpi.innerHTML = "";
      const cards = [
        ["Loaded Records", String(records.length)],
        ["Bridge Mode", "postMessage()"],
        ["DOM / Cookies", "Isolated"],
      ];
      for (const [label, val] of cards) {{
        const card = document.createElement("div");
        card.style.cssText = "background:var(--card,#1e232c);border:1px solid var(--border,#2d3440);border-radius:8px;padding:8px;";
        const l = document.createElement("div");
        l.style.cssText = "font-size:10px;color:var(--muted,#9ca3af);";
        l.textContent = label;
        const v = document.createElement("div");
        v.style.cssText = "font-size:15px;font-weight:600;color:var(--text,#f3f4f6);margin-top:2px;";
        v.textContent = val;
        card.appendChild(l);
        card.appendChild(v);
        kpi.appendChild(card);
      }}
      if (!records.length) {{
        box.textContent = "No collection records matched current query.";
        return;
      }}
      box.innerHTML = "";
      for (const item of records.slice(0, 12)) {{
        const row = document.createElement("div");
        row.style.cssText = "padding:6px 0;border-bottom:1px solid var(--border,#2d3440);";
        const doc = item.doc || {{}};
        row.textContent = (doc.title || doc.name || item.external_key || item.id) + " — " + (item.collection || "");
        box.appendChild(row);
      }}
    }}
    window.addEventListener("message", function (event) {{
      const msg = event.data || {{}};
      if (msg.type === "ARGO_PAGE_DATA") {{
        const records = Array.isArray(msg.records) ? msg.records : [];
        renderRecords(records);
        if (!records.length && primaryCollection) {{
          window.parent.postMessage({{ type: "ARGO_QUERY_COLLECTION", collection: primaryCollection }}, "*");
        }}
      }} else if (msg.type === "ARGO_COLLECTION_RESULT") {{
        renderRecords(Array.isArray(msg.records) ? msg.records : []);
      }}
    }});
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

    @staticmethod
    def build_interactive_page_html(
        *,
        template_key: str,
        title: str,
        description: str = "",
        allowed_collections: list[str] | None = None,
        dashboard_spec: dict[str, Any] | None = None,
    ) -> str:
        """Build a clean, sandbox-safe interactive HTML5 Page template respecting Light/Dark theme tokens."""
        safe_title = html.escape(title.strip() or "Interactive View")
        safe_desc = html.escape(description.strip() or "Live workspace view powered by Argo data")
        cols = [
            collection_slug(str(c))
            for c in (allowed_collections or [])
            if str(c).strip() and collection_slug(str(c)) not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
        ]
        primary_coll = cols[0] if cols else ""

        if template_key == "data_dashboard":
            raw_spec = dict(dashboard_spec or {})
            subtitle_text = str(raw_spec.get("subtitle") or description or "Live SQLite JSON1 workspace dashboard").strip()
            safe_sub = html.escape(subtitle_text)
            normalized_spec = {
                "subtitle": subtitle_text,
                "allowed_collections": cols,
                "source_bots": list(raw_spec.get("source_bots") or []),
                "kpis": list(raw_spec.get("kpis") or []),
                "charts": list(raw_spec.get("charts") or []),
                "filters": list(raw_spec.get("filters") or []),
                "table_sql": str(raw_spec.get("table_sql") or "").strip(),
            }
            spec_json = json.dumps(normalized_spec, ensure_ascii=False).replace("</", "<\\/")
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:22px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:13px; line-height:1.5; background:var(--bg,#161920); color:var(--text,#f3f4f6); -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:1240px; margin:0 auto; display:grid; gap:16px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }}
  .title-col {{ min-width:240px; flex:1; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; color:var(--text,#f3f4f6); letter-spacing:-0.01em; }}
  .sub {{ margin:4px 0 0; font-size:13px; color:var(--muted,#9ca3af); }}
  .controls {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
  .source-pills {{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-top:8px; }}
  .bot-pill {{ display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:999px; border:1px solid var(--border,#2d3440); background:var(--card,#1e232c); font-size:12px; color:var(--text,#e5e7eb); }}
  .bot-pill button {{ background:none; border:0; color:var(--accent,#3b72b2); font-size:12px; font-weight:600; cursor:pointer; padding:0 2px; }}
  .bot-pill button:hover {{ text-decoration:underline; }}
  input[type=search] {{ background:var(--surface,#181c23); color:var(--text,#f3f4f6); border:1px solid var(--border,#2d3440); border-radius:8px; padding:7px 11px; font-size:12px; min-width:210px; outline:none; }}
  input[type=search]:focus {{ border-color:var(--accent,#3b72b2); }}
  button.btn {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); color:var(--text,#e5e7eb); border-radius:8px; padding:7px 11px; font-size:12px; font-weight:500; cursor:pointer; }}
  button.btn:hover {{ background:var(--surface,#252b36); }}
  button.primary {{ background:var(--accent,#3b72b2); border-color:var(--accent,#3b72b2); color:#ffffff; }}
  button.primary:hover {{ filter:brightness(0.92); }}
  .filter-bar {{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; }}
  .chip {{ background:var(--surface,#181c23); border:1px solid var(--border,#2d3440); color:var(--text,#d1d5db); border-radius:999px; padding:4px 10px; font-size:12px; cursor:pointer; }}
  .chip.active {{ background:var(--accent,#3b72b2); border-color:var(--accent,#3b72b2); color:#ffffff; font-weight:600; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }}
  .card {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:16px; }}
  .k-label {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted,#9ca3af); }}
  .k-val {{ font-size:24px; font-weight:600; color:var(--text,#f3f4f6); margin-top:6px; }}
  .k-hint {{ font-size:12px; color:var(--muted,#9ca3af); margin-top:4px; }}
  .charts-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:12px; }}
  .chart-head {{ display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:10px; }}
  .chart-title {{ font-size:13px; font-weight:600; color:var(--text,#f3f4f6); }}
  .legend {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }}
  .legend-item {{ display:inline-flex; align-items:center; gap:5px; font-size:12px; color:var(--text,#d1d5db); cursor:pointer; padding:2px 6px; border-radius:6px; }}
  .legend-item.active {{ background:var(--accent,#3b72b2); color:#ffffff; }}
  .swatch {{ width:9px; height:9px; border-radius:2px; display:inline-block; }}
  .table-wrap {{ overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th {{ text-align:left; padding:9px 10px; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted,#9ca3af); border-bottom:1px solid var(--border,#2d3440); background:var(--surface,#181c23); }}
  td {{ padding:9px 10px; border-bottom:1px solid var(--border,#2d3440); color:var(--text,#e5e7eb); max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  tbody tr {{ cursor:pointer; }}
  tbody tr:hover {{ background:var(--surface,#181c23); }}
  .empty {{ background:var(--card,#1e232c); border:1px dashed var(--border,#2d3440); border-radius:12px; padding:28px; text-align:center; display:grid; gap:10px; justify-items:center; }}
  .drawer-backdrop {{ position:fixed; inset:0; background:rgba(10,12,16,0.65); display:none; justify-content:flex-end; z-index:40; }}
  .drawer-backdrop.open {{ display:flex; }}
  .drawer {{ width:min(480px,94vw); height:100%; background:var(--card,#1e232c); border-left:1px solid var(--border,#2d3440); padding:18px; overflow-y:auto; display:grid; gap:12px; align-content:start; }}
  .drawer pre {{ margin:0; background:var(--surface,#181c23); border:1px solid var(--border,#2d3440); border-radius:8px; padding:12px; font-size:12px; line-height:1.45; color:var(--text,#d1d5db); white-space:pre-wrap; word-break:break-word; }}
  .err-banner {{ background:var(--surface,#2c1b20); border:1px solid var(--bad,#c24b4b); color:var(--text,#f3f4f6); border-radius:8px; padding:8px 12px; font-size:12px; display:none; }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="title-col">
        <h1>{safe_title}</h1>
        <p class="sub">{safe_sub}</p>
        <div id="sourcePills" class="source-pills"></div>
      </div>
      <div class="controls">
        <input id="searchInput" type="search" placeholder="Search records & fields...">
        <button id="refreshBtn" class="btn" type="button">Refresh</button>
        <button id="exportBtn" class="btn" type="button">Export CSV</button>
      </div>
    </div>
    <div id="errBanner" class="err-banner"></div>
    <div id="filterBar" class="filter-bar"></div>
    <div id="emptyState" class="empty" style="display:none;"></div>
    <div id="kpiGrid" class="kpis"></div>
    <div id="chartsGrid" class="charts-grid"></div>
    <div id="tableCard" class="card">
      <div class="chart-head">
        <div class="chart-title" id="tableTitle">Records</div>
        <div class="sub" id="tableMeta" style="margin:0;">Waiting for data...</div>
      </div>
      <div class="table-wrap">
        <table>
          <thead id="tableHead"></thead>
          <tbody id="tableBody"></tbody>
        </table>
      </div>
    </div>
  </div>
  <div id="drawerBackdrop" class="drawer-backdrop">
    <div class="drawer">
      <div class="chart-head" style="margin:0;">
        <div class="chart-title" id="drawerTitle">Record Detail</div>
        <button id="drawerClose" class="btn" type="button">Close</button>
      </div>
      <div class="sub" id="drawerMeta" style="margin:0;"></div>
      <pre id="drawerJson"></pre>
    </div>
  </div>
  <script>
    const SPEC = {spec_json};
    const PALETTE = ["#3b72b2", "#3b8c62", "#c98a2c", "#64748b", "#2b8a8e", "#7c6f9f"];
    const state = {{
      records: [],
      collectionCounts: {{}},
      totalRecords: 0,
      kpiResults: {{}},
      chartResults: {{}},
      tableResult: null,
      activeCollection: "",
      activeCrossFilter: "",
      activePresetFilter: "",
      pendingSql: new Map(),
      reqSeq: 0,
    }};

    function esc(v) {{
      return String(v == null ? "" : v)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }}

    function showErr(msg) {{
      const el = document.getElementById("errBanner");
      if (!msg) {{
        el.style.display = "none";
        el.textContent = "";
        return;
      }}
      el.style.display = "block";
      el.textContent = String(msg);
    }}

    function runSql(sql, params, onResult) {{
      if (!sql || !String(sql).trim()) return;
      const requestId = "sql_" + (++state.reqSeq);
      state.pendingSql.set(requestId, onResult);
      window.parent.postMessage({{
        type: "ARGO_QUERY_SQL",
        requestId,
        sql: String(sql),
        params: Array.isArray(params) ? params : [],
      }}, "*");
    }}

    function renderSourcePills() {{
      const host = document.getElementById("sourcePills");
      host.innerHTML = "";
      const bots = Array.isArray(SPEC.source_bots) ? SPEC.source_bots : [];
      for (const b of bots) {{
        const slug = String(b.slug || "").trim();
        const name = String(b.name || slug || "Source Bot");
        if (!slug) continue;
        const pill = document.createElement("span");
        pill.className = "bot-pill";
        const lbl = document.createElement("span");
        lbl.textContent = name;
        const openBtn = document.createElement("button");
        openBtn.type = "button";
        openBtn.textContent = "Open Bot";
        openBtn.addEventListener("click", () => window.parent.postMessage({{ type: "ARGO_OPEN_BOT", botSlug: slug }}, "*"));
        const syncBtn = document.createElement("button");
        syncBtn.type = "button";
        syncBtn.textContent = "Sync Now";
        syncBtn.addEventListener("click", () => window.parent.postMessage({{ type: "ARGO_TRIGGER_BOT", botSlug: slug }}, "*"));
        pill.appendChild(lbl);
        pill.appendChild(openBtn);
        pill.appendChild(syncBtn);
        host.appendChild(pill);
      }}
    }}

    function renderFilters() {{
      const bar = document.getElementById("filterBar");
      bar.innerHTML = "";
      const cols = Object.keys(state.collectionCounts);
      if (cols.length > 1) {{
        const allChip = document.createElement("button");
        allChip.type = "button";
        allChip.className = "chip" + (!state.activeCollection ? " active" : "");
        allChip.textContent = "All Sources (" + state.totalRecords + ")";
        allChip.addEventListener("click", () => {{ state.activeCollection = ""; renderAll(); }});
        bar.appendChild(allChip);
        for (const c of cols) {{
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "chip" + (state.activeCollection === c ? " active" : "");
          chip.textContent = c + " (" + state.collectionCounts[c] + ")";
          chip.addEventListener("click", () => {{ state.activeCollection = state.activeCollection === c ? "" : c; renderAll(); }});
          bar.appendChild(chip);
        }}
      }}
      const presets = Array.isArray(SPEC.filters) ? SPEC.filters : [];
      for (const f of presets) {{
        const label = typeof f === "string" ? f : String(f.label || f.value || "Filter");
        const val = typeof f === "string" ? f : String(f.value || f.label || "");
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "chip" + (state.activePresetFilter === val ? " active" : "");
        chip.textContent = label;
        chip.addEventListener("click", () => {{ state.activePresetFilter = state.activePresetFilter === val ? "" : val; renderAll(); }});
        bar.appendChild(chip);
      }}
      if (state.activeCrossFilter) {{
        const clr = document.createElement("button");
        clr.type = "button";
        clr.className = "chip active";
        clr.textContent = "Filtered: " + state.activeCrossFilter + " ×";
        clr.addEventListener("click", () => {{ state.activeCrossFilter = ""; renderAll(); }});
        bar.appendChild(clr);
      }}
    }}

    function renderKpis() {{
      const grid = document.getElementById("kpiGrid");
      grid.innerHTML = "";
      const kpis = Array.isArray(SPEC.kpis) && SPEC.kpis.length ? SPEC.kpis : [
        {{ label: "Total Records", value: String(state.totalRecords), hint: "Across bound collections" }},
        {{ label: "Active Sources", value: String(Object.keys(state.collectionCounts).length || (SPEC.allowed_collections || []).length), hint: "Scoped collections" }},
        {{ label: "Loaded Rows", value: String(state.records.length), hint: "Live SQLite snapshot" }},
      ];
      kpis.forEach((k, idx) => {{
        const res = state.kpiResults[idx];
        let displayVal = k.value != null ? String(k.value) : "—";
        if (res && Array.isArray(res.rows) && res.rows.length) {{
          const firstRow = res.rows[0];
          const firstKey = Object.keys(firstRow)[0];
          if (firstKey !== undefined && firstRow[firstKey] !== null && firstRow[firstKey] !== undefined) {{
            displayVal = String(firstRow[firstKey]);
          }}
        }}
        const card = document.createElement("div");
        card.className = "card";
        card.innerHTML = `<div class="k-label">${{esc(k.label || "Metric")}}</div><div class="k-val">${{esc(displayVal)}}</div>${{k.hint ? `<div class="k-hint">${{esc(k.hint)}}</div>` : ""}}`;
        grid.appendChild(card);
      }});
    }}

    function normalizeSeriesRows(rows) {{
      if (!Array.isArray(rows) || !rows.length) return [];
      const keys = Object.keys(rows[0]);
      if (keys.length === 1) {{
        return rows.map((r, i) => ({{ label: String(r[keys[0]] ?? ("Item " + (i + 1))), value: 1 }}));
      }}
      const lKey = keys[0];
      const vKey = keys[1];
      return rows.map((r) => ({{
        label: String(r[lKey] ?? "Unknown"),
        value: Number(r[vKey] ?? 0) || 0,
      }}));
    }}

    function buildChartSvg(type, series) {{
      if (!series.length) return "<div class='sub'>No chart data yet.</div>";
      const w = 380, h = 175;
      if (type === "donut") {{
        const total = Math.max(1, series.reduce((a, s) => a + Math.max(0, s.value), 0));
        const cx = 86, cy = 88, r = 56;
        let angle = -Math.PI / 2;
        const paths = series.slice(0, 6).map((s, idx) => {{
          const slice = (Math.max(0, s.value) / total) * Math.PI * 2;
          const x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
          const end = angle + slice;
          const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
          const large = slice > Math.PI ? 1 : 0;
          angle = end;
          const color = PALETTE[idx % PALETTE.length];
          if (slice >= Math.PI * 1.999) {{
            return `<circle cx="${{cx}}" cy="${{cy}}" r="${{r}}" fill="none" stroke="${{color}}" stroke-width="20" data-filter="${{esc(s.label)}}"></circle>`;
          }}
          return `<path d="M ${{x1.toFixed(1)}} ${{y1.toFixed(1)}} A ${{r}} ${{r}} 0 ${{large}} 1 ${{x2.toFixed(1)}} ${{y2.toFixed(1)}}" fill="none" stroke="${{color}}" stroke-width="20" data-filter="${{esc(s.label)}}"><title>${{esc(s.label)}}: ${{s.value}}</title></path>`;
        }}).join("");
        return `<svg viewBox="0 0 ${{w}} ${{h}}" width="100%" height="${{h}}"><circle cx="${{cx}}" cy="${{cy}}" r="${{r}}" fill="none" stroke="var(--surface,#181c23)" stroke-width="20"/>${{paths}}<text x="${{cx}}" y="${{cy + 4}}" text-anchor="middle" fill="var(--text,#f3f4f6)" font-size="14" font-weight="600">${{total}}</text></svg>`;
      }}
      if (type === "line") {{
        const maxV = Math.max(1, ...series.map((s) => s.value));
        const padX = 28, padY = 20, plotW = w - padX * 2, plotH = h - padY * 2;
        const pts = series.map((s, i) => {{
          const x = padX + (series.length === 1 ? plotW / 2 : (i / (series.length - 1)) * plotW);
          const y = padY + plotH - (Math.max(0, s.value) / maxV) * plotH;
          return {{ x, y, s }};
        }});
        const poly = pts.map((p) => `${{p.x.toFixed(1)}},${{p.y.toFixed(1)}}`).join(" ");
        const dots = pts.map((p) => `<circle cx="${{p.x.toFixed(1)}}" cy="${{p.y.toFixed(1)}}" r="4" fill="var(--accent,#3b72b2)" data-filter="${{esc(p.s.label)}}"><title>${{esc(p.s.label)}}: ${{p.s.value}}</title></circle>`).join("");
        const labels = pts.filter((_, i) => i === 0 || i === pts.length - 1 || i === Math.floor(pts.length / 2))
          .map((p) => `<text x="${{p.x.toFixed(1)}}" y="${{h - 4}}" text-anchor="middle" fill="var(--muted,#9ca3af)" font-size="12">${{esc(p.s.label.slice(0, 12))}}</text>`).join("");
        return `<svg viewBox="0 0 ${{w}} ${{h}}" width="100%" height="${{h}}"><line x1="${{padX}}" y1="${{padY + plotH}}" x2="${{w - padX}}" y2="${{padY + plotH}}" stroke="var(--border,#2d3440)"/><polyline fill="none" stroke="var(--accent,#3b72b2)" stroke-width="2.5" points="${{poly}}"/>${{dots}}${{labels}}</svg>`;
      }}
      const items = series.slice(0, 8);
      const maxV = Math.max(1, ...items.map((s) => s.value));
      const padL = 12, padB = 28, plotW = w - padL * 2, plotH = h - padB - 14;
      const bw = Math.max(14, Math.floor(plotW / Math.max(1, items.length)) - 8);
      const bars = items.map((s, idx) => {{
        const bh = Math.max(4, Math.round((Math.max(0, s.value) / maxV) * plotH));
        const x = padL + idx * (plotW / items.length) + 4;
        const y = 14 + (plotH - bh);
        const color = PALETTE[idx % PALETTE.length];
        return `<rect x="${{x.toFixed(1)}}" y="${{y}}" width="${{bw}}" height="${{bh}}" rx="4" fill="${{color}}" data-filter="${{esc(s.label)}}"><title>${{esc(s.label)}}: ${{s.value}}</title></rect><text x="${{(x + bw / 2).toFixed(1)}}" y="${{h - 8}}" text-anchor="middle" fill="var(--muted,#9ca3af)" font-size="12">${{esc(s.label.slice(0, 9))}}</text>`;
      }}).join("");
      return `<svg viewBox="0 0 ${{w}} ${{h}}" width="100%" height="${{h}}">${{bars}}</svg>`;
    }}

    function renderCharts() {{
      const grid = document.getElementById("chartsGrid");
      grid.innerHTML = "";
      const charts = Array.isArray(SPEC.charts) ? SPEC.charts : [];
      if (!charts.length && !state.records.length) return;
      const effectiveCharts = charts.length ? charts : [
        {{ type: "bar", title: "Records by Collection", sql: null }},
      ];
      effectiveCharts.forEach((ch, idx) => {{
        let series = [];
        const res = state.chartResults[idx];
        if (res && Array.isArray(res.rows)) {{
          series = normalizeSeriesRows(res.rows);
        }} else {{
          const counts = new Map();
          for (const r of state.records) {{
            const k = String(r.collection || "items");
            counts.set(k, (counts.get(k) || 0) + 1);
          }}
          series = Array.from(counts.entries()).map(([label, value]) => ({{ label, value }}));
        }}
        const card = document.createElement("div");
        card.className = "card";
        const type = ch.type === "line" || ch.type === "donut" ? ch.type : "bar";
        card.innerHTML = `<div class="chart-head"><div class="chart-title">${{esc(ch.title || "Breakdown")}}</div><span class="sub" style="margin:0;">Click to filter</span></div><div>${{buildChartSvg(type, series)}}</div>`;
        const legend = document.createElement("div");
        legend.className = "legend";
        series.slice(0, 6).forEach((s, sIdx) => {{
          const btn = document.createElement("span");
          btn.className = "legend-item" + (state.activeCrossFilter === s.label ? " active" : "");
          btn.innerHTML = `<span class="swatch" style="background:${{PALETTE[sIdx % PALETTE.length]}}"></span><span>${{esc(s.label)}} (${{s.value}})</span>`;
          btn.addEventListener("click", () => {{
            state.activeCrossFilter = state.activeCrossFilter === s.label ? "" : s.label;
            renderAll();
          }});
          legend.appendChild(btn);
        }});
        card.querySelectorAll("[data-filter]").forEach((node) => {{
          node.style.cursor = "pointer";
          node.addEventListener("click", () => {{
            const val = node.getAttribute("data-filter") || "";
            state.activeCrossFilter = state.activeCrossFilter === val ? "" : val;
            renderAll();
          }});
        }});
        card.appendChild(legend);
        grid.appendChild(card);
      }});
    }}

    function getDisplayTable() {{
      const q = (document.getElementById("searchInput").value || "").trim().toLowerCase();
      const hasSqlTable = state.tableResult && Array.isArray(state.tableResult.rows) && Array.isArray(state.tableResult.columns);
      let columns = [];
      let rows = [];
      let rawByRow = [];
      if (hasSqlTable) {{
        columns = state.tableResult.columns;
        rows = state.tableResult.rows;
        rawByRow = rows;
      }} else {{
        columns = ["collection", "title", "source", "updated_at"];
        rows = state.records.map((r) => {{
          const d = r.doc || {{}};
          return {{
            collection: r.collection || "",
            title: d.subject || d.name || d.summary || d.title || r.external_key || r.id,
            source: d.from || d.mimeType || (d.organizer && d.organizer.email) || d.source_type || "",
            updated_at: String(r.updated_at || "").slice(0, 16),
          }};
        }});
        rawByRow = state.records;
      }}
      const paired = rows.map((row, i) => ({{ row, raw: rawByRow[i] }})).filter(({{ row, raw }}) => {{
        const hay = (JSON.stringify(row) + " " + JSON.stringify(raw)).toLowerCase();
        if (state.activeCollection && String((raw && raw.collection) || row.collection || "") !== state.activeCollection) return false;
        if (state.activeCrossFilter && !hay.includes(state.activeCrossFilter.toLowerCase())) return false;
        if (state.activePresetFilter && !hay.includes(state.activePresetFilter.toLowerCase())) return false;
        if (q && !hay.includes(q)) return false;
        return true;
      }});
      return {{ columns, paired }};
    }}

    function openDrawer(raw) {{
      const d = (raw && raw.doc) ? raw.doc : raw;
      document.getElementById("drawerTitle").textContent = String((d && (d.subject || d.name || d.summary || d.title)) || (raw && raw.external_key) || "Record Detail");
      document.getElementById("drawerMeta").textContent = raw && raw.collection ? `${{raw.collection}} · ${{raw.updated_at || ""}}` : "";
      document.getElementById("drawerJson").textContent = JSON.stringify(raw, null, 2);
      document.getElementById("drawerBackdrop").classList.add("open");
    }}

    function renderTable() {{
      const {{ columns, paired }} = getDisplayTable();
      const head = document.getElementById("tableHead");
      const body = document.getElementById("tableBody");
      const meta = document.getElementById("tableMeta");
      head.innerHTML = "";
      body.innerHTML = "";
      meta.textContent = `${{paired.length}} row(s)`;
      if (!columns.length) return;
      const trH = document.createElement("tr");
      for (const col of columns) {{
        const th = document.createElement("th");
        th.textContent = col;
        trH.appendChild(th);
      }}
      head.appendChild(trH);
      if (!paired.length) {{
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = columns.length;
        td.textContent = "No matching rows.";
        tr.appendChild(td);
        body.appendChild(tr);
        return;
      }}
      for (const item of paired.slice(0, 200)) {{
        const tr = document.createElement("tr");
        for (const col of columns) {{
          const td = document.createElement("td");
          const val = item.row[col];
          td.textContent = typeof val === "object" && val !== null ? JSON.stringify(val) : String(val ?? "");
          tr.appendChild(td);
        }}
        tr.addEventListener("click", () => openDrawer(item.raw));
        body.appendChild(tr);
      }}
    }}

    function renderEmptyState() {{
      const empty = document.getElementById("emptyState");
      const hasData = state.totalRecords > 0 || state.records.length > 0;
      empty.style.display = hasData ? "none" : "grid";
      document.getElementById("tableCard").style.display = hasData ? "block" : "none";
      if (hasData) return;
      const bots = Array.isArray(SPEC.source_bots) ? SPEC.source_bots : [];
      const firstBot = bots[0];
      empty.innerHTML = `
        <div class="chart-title">No records ingested yet</div>
        <div class="sub" style="margin:0;max-width:460px;">Run a Source Bot sync to populate its collection, then refresh this live SQLite dashboard at 0 LLM tokens.</div>
      `;
      if (firstBot && firstBot.slug) {{
        const actions = document.createElement("div");
        actions.className = "controls";
        const syncBtn = document.createElement("button");
        syncBtn.type = "button";
        syncBtn.className = "btn primary";
        syncBtn.textContent = "Sync " + (firstBot.name || firstBot.slug);
        syncBtn.addEventListener("click", () => window.parent.postMessage({{ type: "ARGO_TRIGGER_BOT", botSlug: firstBot.slug }}, "*"));
        const openBtn = document.createElement("button");
        openBtn.type = "button";
        openBtn.className = "btn";
        openBtn.textContent = "Open Bot";
        openBtn.addEventListener("click", () => window.parent.postMessage({{ type: "ARGO_OPEN_BOT", botSlug: firstBot.slug }}, "*"));
        actions.appendChild(syncBtn);
        actions.appendChild(openBtn);
        empty.appendChild(actions);
      }}
    }}

    function renderAll() {{
      renderSourcePills();
      renderFilters();
      renderEmptyState();
      renderKpis();
      renderCharts();
      renderTable();
    }}

    function executeSpecQueries() {{
      if (Array.isArray(SPEC.kpis)) {{
        SPEC.kpis.forEach((k, idx) => {{
          if (k && k.sql) runSql(k.sql, [], (res) => {{ state.kpiResults[idx] = res; renderKpis(); }});
        }});
      }}
      if (Array.isArray(SPEC.charts)) {{
        SPEC.charts.forEach((ch, idx) => {{
          if (ch && ch.sql) runSql(ch.sql, [], (res) => {{ state.chartResults[idx] = res; renderCharts(); }});
        }});
      }}
      if (SPEC.table_sql) {{
        runSql(SPEC.table_sql, [], (res) => {{ state.tableResult = res; renderTable(); }});
      }}
    }}

    document.getElementById("searchInput").addEventListener("input", renderTable);
    document.getElementById("refreshBtn").addEventListener("click", executeSpecQueries);
    document.getElementById("drawerClose").addEventListener("click", () => document.getElementById("drawerBackdrop").classList.remove("open"));
    document.getElementById("drawerBackdrop").addEventListener("click", (ev) => {{
      if (ev.target === ev.currentTarget) ev.currentTarget.classList.remove("open");
    }});
    document.getElementById("exportBtn").addEventListener("click", () => {{
      const {{ columns, paired }} = getDisplayTable();
      const csvCell = (v) => '"' + String(v ?? "").replace(/"/g, '""') + '"';
      const lines = [columns.map(csvCell).join(",")];
      for (const item of paired) {{
        lines.push(columns.map((c) => csvCell(typeof item.row[c] === "object" ? JSON.stringify(item.row[c]) : item.row[c])).join(","));
      }}
      window.parent.postMessage({{
        type: "ARGO_DOWNLOAD_FILE",
        filename: "dashboard-export.csv",
        mimeType: "text/csv",
        data: lines.join("\\n"),
      }}, "*");
    }});

    window.addEventListener("message", function (ev) {{
      const msg = ev.data || {{}};
      if (msg.type === "ARGO_PAGE_DATA") {{
        const data = msg.data || {{}};
        state.records = Array.isArray(data.records) ? data.records : (Array.isArray(msg.records) ? msg.records : []);
        state.collectionCounts = data.collection_counts && typeof data.collection_counts === "object" ? data.collection_counts : {{}};
        state.totalRecords = typeof data.total_records === "number" ? data.total_records : state.records.length;
        renderAll();
        executeSpecQueries();
      }} else if (msg.type === "ARGO_SQL_RESULT") {{
        const reqId = String(msg.requestId || "");
        const cb = state.pendingSql.get(reqId);
        state.pendingSql.delete(reqId);
        showErr("");
        if (cb) cb(msg.result || msg);
      }} else if (msg.type === "ARGO_SQL_ERROR") {{
        const reqId = String(msg.requestId || "");
        state.pendingSql.delete(reqId);
        showErr(msg.error || "SQL query error");
      }}
    }});

    renderAll();
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

        if template_key == "bot_hub_board":
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:22px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:var(--bg,#161920); color:var(--text,#f3f4f6); -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:1180px; margin:0 auto; display:grid; gap:18px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-end; gap:12px; flex-wrap:wrap; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; color:var(--text,#f3f4f6); }}
  .sub {{ margin:4px 0 0; font-size:13px; color:var(--muted,#9ca3af); }}
  .bar {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
  input[type=search] {{ background:var(--surface,#181c23); color:var(--text,#f3f4f6); border:1px solid var(--border,#2d3440); border-radius:8px; padding:7px 11px; font-size:13px; min-width:210px; outline:none; }}
  input[type=search]:focus {{ border-color:var(--accent,#3b72b2); }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; }}
  .kpi {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:14px; }}
  .k-lbl {{ font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted,#9ca3af); font-weight:600; }}
  .k-val {{ font-size:22px; font-weight:600; color:var(--text,#f3f4f6); margin-top:4px; }}
  .sec-title {{ font-size:12px; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted,#9ca3af); font-weight:600; margin:4px 0 8px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:12px; }}
  .card {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:15px; display:flex; flex-direction:column; gap:10px; }}
  .row {{ display:flex; align-items:center; justify-content:space-between; gap:8px; }}
  .title {{ font-size:14px; font-weight:600; color:var(--text,#f3f4f6); }}
  .meta {{ font-size:12px; color:var(--muted,#9ca3af); }}
  .body {{ font-size:13px; color:var(--text,#d1d5db); min-height:36px; }}
  .pill {{ display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:600; border:1px solid var(--border,#2d3440); background:var(--surface,#181c23); color:var(--text,#e5e7eb); }}
  .dot {{ width:8px; height:8px; border-radius:999px; display:inline-block; }}
  .btns {{ display:flex; gap:7px; flex-wrap:wrap; padding-top:8px; border-top:1px solid var(--border,#2d3440); }}
  button.btn {{ background:var(--surface,#181c23); border:1px solid var(--border,#353f50); color:var(--text,#e5e7eb); border-radius:8px; padding:5px 10px; font-size:12px; font-weight:500; cursor:pointer; }}
  button.btn:hover {{ background:var(--card,#252b36); }}
  button.primary {{ background:var(--accent,#3b72b2); border-color:var(--accent,#3b72b2); color:#ffffff; }}
  button.primary:hover {{ filter:brightness(0.92); }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>{safe_title}</h1>
        <p class="sub">{safe_desc}</p>
      </div>
      <div class="bar">
        <input id="hubSearch" type="search" placeholder="Filter bots or rooms...">
        <button class="btn" id="openApprovalsBtn" type="button">Approvals</button>
      </div>
    </div>
    <div id="hubKpis" class="kpis"></div>
    <div id="hubRoomsWrap"></div>
    <div>
      <div class="sec-title">Bot Fleet</div>
      <div id="hubBots" class="grid"></div>
    </div>
  </div>
  <script>
    let latestStatus = null;
    function stateTone(st) {{
      if (st === "running") return {{ label: "Active", dot: "#3b8c62" }};
      if (st === "waiting_approval") return {{ label: "Needs Review", dot: "#c98a2c" }};
      if (st === "takeover_needed") return {{ label: "Needs Sign-In", dot: "#c24b4b" }};
      if (st === "paused") return {{ label: "Paused", dot: "#6b7280" }};
      return {{ label: "Ready", dot: "#3b72b2" }};
    }}
    function renderHub() {{
      const q = (document.getElementById("hubSearch").value || "").trim().toLowerCase();
      const status = latestStatus || {{ bots: [], rooms: [], counts: {{}} }};
      const bots = Array.isArray(status.bots) ? status.bots : [];
      const rooms = Array.isArray(status.rooms) ? status.rooms : [];
      const pending = status.counts ? (status.counts.pending_approvals || 0) : 0;
      const enabledCount = bots.filter(b => b.enabled).length;
      document.getElementById("hubKpis").innerHTML = [
        {{ l: "Active Bots", v: String(enabledCount) + " / " + String(bots.length) }},
        {{ l: "Team Rooms", v: String(rooms.length) }},
        {{ l: "Pending Approvals", v: String(pending) }},
      ].map(k => `<div class="kpi"><div class="k-lbl">${{k.l}}</div><div class="k-val">${{k.v}}</div></div>`).join("");

      const roomsWrap = document.getElementById("hubRoomsWrap");
      const filteredRooms = q ? rooms.filter(r => (r.title || "").toLowerCase().includes(q) || (r.member_bot_slugs || []).join(" ").toLowerCase().includes(q)) : rooms;
      if (filteredRooms.length > 0) {{
        roomsWrap.innerHTML = `<div class="sec-title">Team Rooms (${{filteredRooms.length}})</div><div id="hubRoomsGrid" class="grid"></div>`;
        const rg = document.getElementById("hubRoomsGrid");
        for (const r of filteredRooms) {{
          const c = document.createElement("div");
          c.className = "card";
          const top = document.createElement("div");
          top.className = "row";
          const t = document.createElement("div");
          t.className = "title";
          t.textContent = r.title;
          const badge = document.createElement("span");
          badge.className = "pill";
          badge.textContent = String((r.member_bot_slugs || []).length) + " bots";
          top.appendChild(t); top.appendChild(badge);
          const body = document.createElement("div");
          body.className = "body";
          body.textContent = r.last_message_preview || ("Members: " + (r.member_bot_slugs || []).join(", "));
          const btns = document.createElement("div");
          btns.className = "btns";
          const openRoom = document.createElement("button");
          openRoom.className = "btn primary";
          openRoom.textContent = "Open Room";
          openRoom.onclick = () => window.parent.postMessage({{ type: "ARGO_OPEN_ROOM", roomSlug: r.slug }}, "*");
          btns.appendChild(openRoom);
          c.appendChild(top); c.appendChild(body); c.appendChild(btns);
          rg.appendChild(c);
        }}
      }} else {{
        roomsWrap.innerHTML = "";
      }}

      const filteredBots = q ? bots.filter(b => (b.name || "").toLowerCase().includes(q) || (b.role || "").toLowerCase().includes(q) || (b.section || "").toLowerCase().includes(q)) : bots;
      const bg = document.getElementById("hubBots");
      bg.innerHTML = "";
      if (!filteredBots.length) {{
        bg.innerHTML = "<div class='meta'>No matching bots found.</div>";
        return;
      }}
      for (const b of filteredBots) {{
        const st = stateTone(b.state);
        const c = document.createElement("div");
        c.className = "card";
        const top = document.createElement("div");
        top.className = "row";
        const left = document.createElement("div");
        const nm = document.createElement("div");
        nm.className = "title";
        nm.textContent = b.name;
        const mt = document.createElement("div");
        mt.className = "meta";
        mt.textContent = (b.section ? b.section + " · " : "") + (b.schedule_label || "Manual");
        left.appendChild(nm); left.appendChild(mt);
        const pill = document.createElement("span");
        pill.className = "pill";
        const d = document.createElement("span");
        d.className = "dot"; d.style.background = st.dot;
        pill.appendChild(d); pill.appendChild(document.createTextNode(st.label));
        top.appendChild(left); top.appendChild(pill);
        const body = document.createElement("div");
        body.className = "body";
        body.textContent = b.last_action_subtitle || b.last_summary || b.role || "Ready";
        const btns = document.createElement("div");
        btns.className = "btns";
        const openB = document.createElement("button");
        openB.className = "btn primary";
        openB.textContent = "Open Chat";
        openB.onclick = () => window.parent.postMessage({{ type: "ARGO_OPEN_BOT", botSlug: b.slug }}, "*");
        const runB = document.createElement("button");
        runB.className = "btn";
        runB.textContent = "Run Now";
        runB.onclick = () => window.parent.postMessage({{ type: "ARGO_TRIGGER_BOT", botSlug: b.slug }}, "*");
        btns.appendChild(openB); btns.appendChild(runB);
        c.appendChild(top); c.appendChild(body); c.appendChild(btns);
        bg.appendChild(c);
      }}
    }}
    document.getElementById("hubSearch").addEventListener("input", renderHub);
    document.getElementById("openApprovalsBtn").addEventListener("click", () => window.parent.postMessage({{ type: "ARGO_OPEN_APPROVALS" }}, "*"));
    window.addEventListener("message", function(ev) {{
      const msg = ev.data || {{}};
      if (msg.type === "ARGO_LIVE_STATUS") {{
        latestStatus = msg.liveStatus;
        renderHub();
      }}
    }});
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

        if template_key == "live_operations_map":
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:var(--bg,#161920); color:var(--text,#f3f4f6); -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:1120px; margin:0 auto; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; gap:14px; flex-wrap:wrap; margin-bottom:20px; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; letter-spacing:-0.01em; color:var(--text,#f3f4f6); }}
  .sub {{ margin:5px 0 0; font-size:13px; color:var(--muted,#9ca3af); }}
  .stats {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .pill {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:999px; padding:6px 12px; font-size:12px; font-weight:600; color:var(--text,#e5e7eb); display:inline-flex; align-items:center; gap:7px; }}
  button.pill {{ cursor:pointer; }}
  button.pill:hover {{ border-color:var(--accent,#4b7bec); background:var(--surface,#252b36); }}
  .dot {{ width:8px; height:8px; border-radius:999px; display:inline-block; flex-shrink:0; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(265px,1fr)); gap:12px; }}
  .group-title {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted,#9ca3af); margin:20px 0 10px; }}
  .station {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:16px; display:flex; flex-direction:column; gap:11px; transition:border-color .15s, background .15s; }}
  .station:hover {{ border-color:var(--accent,#3d4759); }}
  .row {{ display:flex; align-items:center; justify-content:space-between; gap:8px; }}
  .avatar {{ width:34px; height:34px; border-radius:10px; background:var(--surface,#252b36); border:1px solid var(--border,#353f50); color:var(--accent,#93b4dc); font-size:12px; font-weight:700; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
  .name {{ font-size:14px; font-weight:600; color:var(--text,#f3f4f6); }}
  .meta {{ font-size:12px; color:var(--muted,#9ca3af); margin-top:2px; }}
  .summary {{ font-size:13px; color:var(--text,#d1d5db); line-height:1.45; min-height:36px; }}
  .actions {{ display:flex; gap:7px; padding-top:8px; border-top:1px solid var(--border,#2d3440); }}
  button.act {{ border:1px solid var(--border,#353f50); background:var(--surface,#181c23); color:var(--text,#e5e7eb); border-radius:8px; padding:6px 11px; font-size:12px; font-weight:500; cursor:pointer; }}
  button.act:hover {{ border-color:var(--accent,#4b5568); }}
  button.primary {{ background:var(--accent,#3b72b2); color:#ffffff; border-color:var(--accent,#3b72b2); }}
  button.primary:hover {{ filter:brightness(0.92); }}
  .badge-run {{ border-color:var(--good,#2e4d3e); }}
  .badge-wait {{ border-color:var(--warn,#524229); }}
  .badge-warn {{ border-color:var(--bad,#543439); }}
  .badge-idle {{ border-color:var(--border,#324869); }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div>
        <h1>{safe_title}</h1>
        <p class="sub">{safe_desc}</p>
      </div>
      <div id="stats" class="stats"></div>
    </div>
    <div id="board" class="sub">Loading live bot stations...</div>
  </div>
  <script>
    function stateStyle(st) {{
      if (st === "running") return {{ label: "Active", cls: "badge-run", dot: "#3b8c62" }};
      if (st === "waiting_approval") return {{ label: "Needs Review", cls: "badge-wait", dot: "#c98a2c" }};
      if (st === "takeover_needed") return {{ label: "Needs Sign-In", cls: "badge-warn", dot: "#c24b4b" }};
      if (st === "paused") return {{ label: "Paused", cls: "badge-idle", dot: "#6b7280" }};
      return {{ label: "Ready", cls: "badge-idle", dot: "#3b72b2" }};
    }}
    function render(status) {{
      const board = document.getElementById("board");
      const stats = document.getElementById("stats");
      const bots = (status && Array.isArray(status.bots)) ? status.bots : [];
      const pending = status && status.counts ? status.counts.pending_approvals || 0 : 0;
      const activeCount = bots.filter(b => b.enabled).length;
      stats.innerHTML = "";
      const pills = [
        {{ text: bots.length + " Bots", dot: "#3b72b2", action: null }},
        {{ text: activeCount + " Enabled", dot: "#3b8c62", action: null }},
        {{ text: pending + " Pending Approvals", dot: pending > 0 ? "#c98a2c" : "#6b7280", action: "ARGO_OPEN_APPROVALS" }},
      ];
      for (const p of pills) {{
        const el = document.createElement(p.action ? "button" : "span");
        el.className = "pill";
        if (p.action) el.onclick = () => window.parent.postMessage({{ type: p.action }}, "*");
        const d = document.createElement("span");
        d.className = "dot";
        d.style.background = p.dot;
        el.appendChild(d);
        el.appendChild(document.createTextNode(p.text));
        stats.appendChild(el);
      }}
      if (!bots.length) {{
        board.textContent = "No bots created yet. Click + New Bot to add your first automation.";
        return;
      }}
      const groups = new Map();
      for (const b of bots) {{
        const sec = (b.section || "General").trim() || "General";
        if (!groups.has(sec)) groups.set(sec, []);
        groups.get(sec).push(b);
      }}
      board.innerHTML = "";
      for (const [secName, list] of groups.entries()) {{
        const h = document.createElement("div");
        h.className = "group-title";
        h.textContent = secName + " (" + list.length + ")";
        board.appendChild(h);
        const grid = document.createElement("div");
        grid.className = "grid";
        for (const b of list) {{
          const st = stateStyle(b.state);
          const card = document.createElement("div");
          card.className = "station";
          const topRow = document.createElement("div");
          topRow.className = "row";
          const left = document.createElement("div");
          left.style.cssText = "display:flex;align-items:center;gap:10px;min-width:0;";
          const av = document.createElement("div");
          av.className = "avatar";
          av.textContent = b.initials || "B";
          const txt = document.createElement("div");
          txt.style.cssText = "min-width:0;";
          const nm = document.createElement("div");
          nm.className = "name";
          nm.textContent = b.name;
          const mt = document.createElement("div");
          mt.className = "meta";
          mt.textContent = b.schedule_label || "Manual";
          txt.appendChild(nm);
          txt.appendChild(mt);
          left.appendChild(av);
          left.appendChild(txt);
          const badge = document.createElement("span");
          badge.className = "pill " + st.cls;
          const dot = document.createElement("span");
          dot.className = "dot";
          dot.style.background = st.dot;
          badge.appendChild(dot);
          badge.appendChild(document.createTextNode(st.label));
          topRow.appendChild(left);
          topRow.appendChild(badge);
          card.appendChild(topRow);
          const sum = document.createElement("div");
          sum.className = "summary";
          sum.textContent = b.last_summary || b.goal_metric || b.role || "Standing by.";
          card.appendChild(sum);
          const act = document.createElement("div");
          act.className = "actions";
          const openBtn = document.createElement("button");
          openBtn.className = "act primary";
          openBtn.textContent = "Open Chat";
          openBtn.onclick = () => window.parent.postMessage({{ type: "ARGO_OPEN_BOT", botSlug: b.slug }}, "*");
          const runBtn = document.createElement("button");
          runBtn.className = "act";
          runBtn.textContent = "Run Now";
          runBtn.onclick = () => window.parent.postMessage({{ type: "ARGO_TRIGGER_BOT", botSlug: b.slug }}, "*");
          act.appendChild(openBtn);
          act.appendChild(runBtn);
          if ((b.pending_approvals_count || 0) > 0) {{
            const revBtn = document.createElement("button");
            revBtn.className = "act";
            revBtn.textContent = "Review (" + b.pending_approvals_count + ")";
            revBtn.onclick = () => window.parent.postMessage({{ type: "ARGO_OPEN_APPROVALS" }}, "*");
            act.appendChild(revBtn);
          }}
          card.appendChild(act);
          grid.appendChild(card);
        }}
        board.appendChild(grid);
      }}
    }}
    window.addEventListener("message", function(ev) {{
      const msg = ev.data || {{}};
      if (msg.type === "ARGO_LIVE_STATUS") render(msg.liveStatus);
    }});
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

        if template_key == "interactive_playground":
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:var(--bg,#161920); color:var(--text,#f3f4f6); -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:920px; margin:0 auto; display:grid; gap:14px; }}
  .card {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:18px; }}
  .head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
  .badge {{ background:var(--surface,#181c23); border:1px solid var(--border,#2d3440); color:var(--accent,#3b72b2); border-radius:999px; padding:4px 10px; font-size:12px; font-weight:600; letter-spacing:0.03em; text-transform:uppercase; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; color:var(--text,#f3f4f6); }}
  .sub {{ margin:5px 0 0; font-size:13px; color:var(--muted,#9ca3af); }}
  .controls {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-top:16px; }}
  label {{ display:flex; flex-direction:column; gap:7px; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted,#9ca3af); }}
  select {{ background:var(--surface,#141820); color:var(--text,#f3f4f6); border:1px solid var(--border,#323a48); border-radius:8px; padding:7px 10px; font-size:13px; outline:none; }}
  input[type=range] {{ width:100%; accent-color:var(--accent,#3b72b2); }}
  canvas {{ width:100%; height:260px; display:block; background:var(--surface,#141820); border-radius:10px; border:1px solid var(--border,#2d3440); }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="head">
        <div>
          <h1>{safe_title}</h1>
          <p class="sub">{safe_desc}</p>
        </div>
        <span class="badge">Interactive Sandbox</span>
      </div>
      <div class="controls">
        <label>Mode
          <select id="curveMode">
            <option value="easeOutCubic">Smooth Deceleration</option>
            <option value="easeInOut">Symmetric S-Curve</option>
            <option value="spring">Spring Overshoot</option>
            <option value="linear">Linear</option>
          </select>
        </label>
        <label>Intensity (<span id="intVal">1.4</span>)
          <input id="intensity" type="range" min="0.5" max="3.0" step="0.1" value="1.4">
        </label>
        <label>Duration (<span id="durVal">600</span> ms)
          <input id="duration" type="range" min="150" max="1500" step="50" value="600">
        </label>
      </div>
    </div>
    <div class="card">
      <canvas id="plot" width="780" height="260"></canvas>
    </div>
  </div>
  <script>
    const canvas = document.getElementById("plot");
    const ctx = canvas.getContext("2d");
    const modeEl = document.getElementById("curveMode");
    const intEl = document.getElementById("intensity");
    const durEl = document.getElementById("duration");
    function evalCurve(t, mode, k) {{
      if (mode === "linear") return t;
      if (mode === "easeOutCubic") return 1 - Math.pow(1 - t, k + 1.2);
      if (mode === "easeInOut") return t < 0.5 ? Math.pow(2 * t, k + 1) / 2 : 1 - Math.pow(2 * (1 - t), k + 1) / 2;
      const damp = Math.exp(-3.5 * t);
      return 1 - damp * Math.cos(t * Math.PI * (1.8 + k));
    }}
    function draw() {{
      const mode = modeEl.value;
      const k = parseFloat(intEl.value);
      document.getElementById("intVal").textContent = k.toFixed(1);
      document.getElementById("durVal").textContent = durEl.value;
      const w = canvas.width, h = canvas.height, pad = 32;
      ctx.clearRect(0, 0, w, h);
      const cs = getComputedStyle(document.documentElement);
      ctx.strokeStyle = cs.getPropertyValue("--border").trim() || "#2d3440";
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {{
        const y = pad + (h - pad * 2) * (i / 4);
        ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
      }}
      ctx.strokeStyle = cs.getPropertyValue("--accent").trim() || "#3b72b2";
      ctx.lineWidth = 2.5;
      ctx.beginPath();
      for (let i = 0; i <= 120; i++) {{
        const t = i / 120;
        const v = evalCurve(t, mode, k);
        const x = pad + t * (w - pad * 2);
        const y = (h - pad) - v * (h - pad * 2);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }}
      ctx.stroke();
    }}
    [modeEl, intEl, durEl].forEach(el => el.addEventListener("input", draw));
    draw();
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:var(--bg,#161920); color:var(--text,#f3f4f6); -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:980px; margin:0 auto; display:grid; gap:16px; }}
  .head {{ display:flex; justify-content:space-between; align-items:flex-end; gap:12px; flex-wrap:wrap; }}
  .title-wrap {{ min-width:0; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; letter-spacing:-0.01em; color:var(--text,#f3f4f6); }}
  .sub {{ margin:5px 0 0; font-size:13px; color:var(--muted,#9ca3af); }}
  .head-right {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .status-pill {{ background:var(--surface,#181c23); border:1px solid var(--good,#3b8c62); color:var(--good,#3b8c62); border-radius:999px; padding:5px 11px; font-size:12px; font-weight:600; letter-spacing:0.03em; text-transform:uppercase; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(175px,1fr)); gap:12px; }}
  .card {{ background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); border-radius:12px; padding:16px; }}
  .kpi-accent-green {{ border-color:var(--good,#3b8c62); }}
  .kpi-accent-sky {{ border-color:var(--accent,#3b72b2); }}
  .k-label {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted,#9ca3af); }}
  .k-val {{ font-size:24px; font-weight:600; margin-top:6px; color:var(--text,#f3f4f6); }}
  .k-val.green {{ color:var(--good,#3b8c62); }}
  .k-val.sky {{ color:var(--accent,#3b72b2); }}
  .bars {{ display:flex; align-items:flex-end; gap:10px; height:128px; padding-top:14px; }}
  .bar-col {{ flex:1; display:flex; flex-direction:column; align-items:center; gap:5px; height:100%; justify-content:flex-end; }}
  .bar {{ width:100%; max-width:52px; background:var(--accent,#3b72b2); border-radius:4px 4px 2px 2px; min-height:4px; }}
  .bar-lbl {{ font-size:12px; color:var(--muted,#9ca3af); }}
  .section-lbl {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted,#9ca3af); margin-bottom:10px; }}
  .item {{ padding:12px 14px; margin-bottom:8px; background:var(--surface,#181c23); border:1px solid var(--border,#2d3440); border-radius:10px; }}
  .item:last-child {{ margin-bottom:0; }}
  .item-top {{ display:flex; align-items:center; justify-content:space-between; gap:10px; }}
  .item-t {{ font-size:14px; font-weight:600; color:var(--text,#f3f4f6); }}
  .item-tag {{ font-size:12px; font-weight:500; padding:2px 8px; border-radius:999px; background:var(--card,#1e232c); border:1px solid var(--border,#2d3440); color:var(--accent,#3b72b2); white-space:nowrap; }}
  .item-m {{ font-size:13px; color:var(--muted,#9ca3af); margin-top:5px; line-height:1.45; }}
  input[type=search] {{ border:1px solid var(--border,#323a48); border-radius:8px; padding:7px 12px; font-size:13px; background:var(--surface,#141820); color:var(--text,#f3f4f6); min-width:220px; outline:none; }}
  input[type=search]::placeholder {{ color:var(--muted,#9ca3af); }}
  input[type=search]:focus {{ border-color:var(--accent,#3b72b2); }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <div class="title-wrap">
        <h1>{safe_title}</h1>
        <p class="sub">{safe_desc}</p>
      </div>
      <div class="head-right">
        <span class="status-pill">Live Collection Feed</span>
        <input id="filter" type="search" placeholder="Filter records...">
      </div>
    </div>
    <div class="kpis" id="kpis"></div>
    <div class="card">
      <div class="k-label">Activity Over Recent Days</div>
      <div class="bars" id="bars"></div>
    </div>
    <div class="card">
      <div class="section-lbl">Recent Records</div>
      <div id="list" class="sub">Loading records...</div>
    </div>
  </div>
  <script>
    const primaryCollection = {json.dumps(primary_coll)};
    let allRecords = [];
    function render(records) {{
      const q = (document.getElementById("filter").value || "").trim().toLowerCase();
      const filtered = q ? records.filter(r => JSON.stringify(r).toLowerCase().includes(q)) : records;
      const kpis = document.getElementById("kpis");
      const collectionsCount = new Set(filtered.map(r => r.collection)).size;
      const latestDay = filtered.length ? String(filtered[0].updated_at || filtered[0].created_at || "").slice(0, 10) : "—";
      kpis.innerHTML = [
        {{ label: "Total Items", val: String(filtered.length), cls: "kpi-accent-green", valCls: "green" }},
        {{ label: "Data Sources", val: String(collectionsCount), cls: "kpi-accent-sky", valCls: "sky" }},
        {{ label: "Latest Activity", val: latestDay || "—", cls: "", valCls: "" }},
        {{ label: "View Filter", val: q ? "Active" : "All", cls: "", valCls: "" }},
      ].map(k => `<div class="card ${{k.cls}}"><div class="k-label">${{k.label}}</div><div class="k-val ${{k.valCls}}">${{k.val}}</div></div>`).join("");

      const byDay = new Map();
      for (const r of filtered) {{
        const day = String(r.created_at || "").slice(0, 10) || "Unknown";
        byDay.set(day, (byDay.get(day) || 0) + 1);
      }}
      const days = Array.from(byDay.entries()).sort((a,b) => a[0].localeCompare(b[0])).slice(-7);
      const maxC = Math.max(1, ...days.map(d => d[1]));
      const bars = document.getElementById("bars");
      bars.innerHTML = days.length ? days.map(([d, c]) =>
        `<div class="bar-col"><div class="bar" style="height:${{Math.round((c/maxC)*92)}}px" title="${{d}}: ${{c}}"></div><div class="bar-lbl">${{d.slice(5)}} (${{c}})</div></div>`
      ).join("") : "<div class='item-m'>No dated records yet.</div>";

      const list = document.getElementById("list");
      list.innerHTML = "";
      if (!filtered.length) {{
        list.innerHTML = "<div class='item-m'>No matching items found.</div>";
        return;
      }}
      for (const r of filtered.slice(0, 30)) {{
        const doc = r.doc || {{}};
        const div = document.createElement("div");
        div.className = "item";
        const top = document.createElement("div");
        top.className = "item-top";
        const t = document.createElement("div");
        t.className = "item-t";
        t.textContent = doc.title || doc.subject || doc.name || r.external_key || r.id;
        const tag = document.createElement("span");
        tag.className = "item-tag";
        tag.textContent = r.collection || "record";
        top.appendChild(t);
        top.appendChild(tag);
        const m = document.createElement("div");
        m.className = "item-m";
        const detail = doc.summary || doc.snippet || doc.from || doc.url || doc.text || "";
        m.textContent = (detail ? String(detail).slice(0, 180) + " · " : "") + String(r.updated_at || "").slice(0, 16);
        div.appendChild(top);
        div.appendChild(m);
        list.appendChild(div);
      }}
    }}
    document.getElementById("filter").addEventListener("input", () => render(allRecords));
    window.addEventListener("message", function(ev) {{
      const msg = ev.data || {{}};
      if (msg.type === "ARGO_PAGE_DATA") {{
        allRecords = (msg.data && Array.isArray(msg.data.records)) ? msg.data.records : (Array.isArray(msg.records) ? msg.records : []);
        render(allRecords);
        if (!allRecords.length && primaryCollection) {{
          window.parent.postMessage({{ type: "ARGO_QUERY_COLLECTION", collection: primaryCollection }}, "*");
        }}
      }} else if (msg.type === "ARGO_COLLECTION_RESULT") {{
        allRecords = Array.isArray(msg.records) ? msg.records : [];
        render(allRecords);
      }}
    }});
    window.parent.postMessage({{ type: "ARGO_READY" }}, "*");
  </script>
</body>
</html>"""

    @staticmethod
    def _validate_page_payload(render_mode: str, payload: str) -> str:
        if render_mode not in {"declarative_json", "sandboxed_html"}:
            raise ValueError(f"Unsupported page render_mode '{render_mode}'.")
        if render_mode == "sandboxed_html":
            lowered = payload.lower()
            if "allow-same-origin" in lowered:
                raise ValueError(
                    "Sandboxed HTML pages must not declare 'allow-same-origin'."
                )
            if re.search(r"<meta\b[^>]*http-equiv\s*=\s*(['\"]?)refresh\1", payload, flags=re.IGNORECASE):
                raise ValueError(
                    "Sandboxed HTML pages must not declare meta refresh redirects."
                )
        return payload

    def _verify_page_file_bindings(
        self,
        allowed_collections: list[str],
        *,
        owner_email: str,
    ) -> None:
        clean_email = str(owner_email or "").strip().lower()
        file_refs = [
            str(c or "").strip()
            for c in allowed_collections
            if str(c or "").strip().lower().startswith("file:")
        ]
        if not file_refs:
            return
        if not clean_email:
            raise PermissionError(
                "Authenticated owner email is required to bind workspace files to a Page."
            )
        for ident in file_refs:
            normalized = dataset_identifier(ident)
            if not normalized.startswith("file:"):
                raise PermissionError(f"Invalid workspace file dataset reference '{ident}'.")
            parts = normalized.split(":", 2)
            file_id = parts[1] if len(parts) > 1 else ""
            if not file_id:
                raise PermissionError(f"Invalid workspace file dataset reference '{ident}'.")
            try:
                self.get_workspace_file_derived_paths(file_id, owner_email=clean_email)
            except NotFoundError as exc:
                raise PermissionError(
                    f"User '{clean_email}' does not own or cannot bind workspace file '{file_id}'."
                ) from exc

    @staticmethod
    def _normalize_page_collections(allowed_collections: list[str] | None) -> list[str]:
        if not allowed_collections:
            return []
        return list(
            dict.fromkeys(
                clean
                for c in allowed_collections
                if str(c).strip()
                for clean in (dataset_identifier(str(c)),)
                if clean not in _PAGE_FORBIDDEN_INTERNAL_COLLECTIONS
            )
        )

    def create_page(
        self,
        *,
        title: str,
        description: str = "",
        render_mode: str = "declarative_json",
        content_payload: str | None = None,
        allowed_collections: list[str] | None = None,
        owner_bot_slug: str = "",
        created_by_email: str = "",
        visibility: str = "shared",
        allowed_groups: list[str] | None = None,
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Create a new declarative_json or sandboxed_html page."""
        now = utc_now()
        base_slug = slugify(title)
        normalized_collections = self._normalize_page_collections(allowed_collections)
        clean_creator = normalize_email(created_by_email)
        clean_visibility = normalize_visibility(visibility, default="shared")
        clean_allowed_groups = (
            normalize_group_slugs(allowed_groups) if clean_visibility == "team" else []
        )
        self._verify_page_file_bindings(list(allowed_collections or []), owner_email=clean_creator)
        payload = content_payload
        if payload is None:
            if render_mode == "sandboxed_html":
                payload = self._default_sandboxed_html_payload(
                    title=title.strip(),
                    description=description,
                    allowed_collections=normalized_collections,
                )
            else:
                payload = json.dumps(
                    {
                        "description": description,
                        "blocks": [
                            {"label": "Collection Status", "value": "Active", "hint": "SQLite WAL + FTS5"},
                            {"label": "Render Mode", "value": "Declarative", "hint": "Zero runtime JSX"},
                            {"label": "Owner Bot", "value": owner_bot_slug or "Unassigned", "hint": "Dynamic view binding"},
                        ],
                        "rows": [],
                    }
                )
        else:
            payload = self._validate_page_payload(render_mode, payload)

        with self._lock:
            candidate_slug = base_slug
            suffix = 2
            while self._conn.execute(
                "SELECT 1 FROM pages WHERE slug = ?", (candidate_slug,)
            ).fetchone():
                candidate_slug = f"{base_slug}-{suffix}"
                suffix += 1

            page_id = make_id("pg")
            self._conn.execute(
                """
                INSERT INTO pages(
                    id, slug, title, icon, render_mode, content_payload,
                    allowed_collections_json, owner_bot_slug, created_by_email, visibility, allowed_groups_json, pinned, updated_at
                ) VALUES (?, ?, ?, 'file-text', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    page_id,
                    candidate_slug,
                    title.strip(),
                    render_mode,
                    payload,
                    json.dumps(normalized_collections),
                    owner_bot_slug,
                    clean_creator,
                    clean_visibility,
                    json.dumps(clean_allowed_groups),
                    1 if pinned else 0,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_page(candidate_slug)

    def update_page(
        self,
        slug: str,
        updates: dict[str, Any],
        *,
        caller_email: str = "",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        """Update an existing declarative_json or sandboxed_html page without container rebuilds."""
        now = utc_now()
        clean_caller = str(caller_email or "").strip().lower()
        with self._lock:
            row = self._conn.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
            if row is None:
                raise NotFoundError(f"Page '{slug}' not found.")

            row_keys = set(row.keys())
            existing_cols = json.loads(row["allowed_collections_json"])
            existing_creator = (
                str(row["created_by_email"] or "").strip().lower()
                if "created_by_email" in row_keys
                else ""
            )
            existing_vis = normalize_visibility(
                row["visibility"] if "visibility" in row_keys else "shared", default="shared"
            )
            title = str(updates["title"]).strip() if updates.get("title") else str(row["title"])
            render_mode = str(updates.get("render_mode") or row["render_mode"])
            raw_updates_cols = updates.get("allowed_collections")
            allowed_collections = (
                self._normalize_page_collections(raw_updates_cols)
                if raw_updates_cols is not None
                else existing_cols
            )
            has_file_refs = any(
                str(c or "").strip().lower().startswith("file:")
                for c in [*existing_cols, *(raw_updates_cols or []), *allowed_collections]
            )
            if (
                not is_admin
                and has_file_refs
                and existing_creator
                and clean_caller
                and clean_caller != existing_creator
            ):
                raise PermissionError(
                    f"User '{clean_caller}' is not permitted to modify file-bound Page '{slug}'."
                )
            refs_to_verify = list(raw_updates_cols) if raw_updates_cols is not None else list(allowed_collections)
            if not is_admin and any(str(c or "").strip().lower().startswith("file:") for c in refs_to_verify):
                effective_owner = clean_caller or existing_creator
                self._verify_page_file_bindings(refs_to_verify, owner_email=effective_owner)
            next_creator = existing_creator or clean_caller
            next_vis = (
                normalize_visibility(str(updates["visibility"]))
                if updates.get("visibility") is not None
                else existing_vis
            )
            existing_groups = (
                self._decode_groups(row["allowed_groups_json"])
                if "allowed_groups_json" in row_keys
                else []
            )
            if next_vis != "team":
                next_groups: list[str] = []
            elif "allowed_groups" in updates and updates["allowed_groups"] is not None:
                next_groups = normalize_group_slugs(updates["allowed_groups"])
            else:
                next_groups = existing_groups

            owner_bot_slug = str(updates.get("owner_bot_slug") or row["owner_bot_slug"])
            pinned = bool(updates["pinned"]) if updates.get("pinned") is not None else bool(row["pinned"])

            if updates.get("content_payload") is not None:
                content_payload = self._validate_page_payload(
                    render_mode, str(updates["content_payload"])
                )
            elif render_mode != row["render_mode"] or updates.get("description") is not None:
                desc = str(updates.get("description") or "")
                if render_mode == "sandboxed_html":
                    content_payload = self._default_sandboxed_html_payload(
                        title=title,
                        description=desc,
                        allowed_collections=allowed_collections,
                    )
                else:
                    content_payload = json.dumps(
                        {
                            "description": desc,
                            "blocks": [
                                {"label": "Collection Status", "value": "Active", "hint": "SQLite WAL + FTS5"},
                                {"label": "Render Mode", "value": "Declarative", "hint": "Zero runtime JSX"},
                                {"label": "Owner Bot", "value": owner_bot_slug or "Unassigned", "hint": "Dynamic view binding"},
                            ],
                            "rows": [],
                        }
                    )
            else:
                content_payload = self._validate_page_payload(render_mode, row["content_payload"])

            self._conn.execute(
                """
                UPDATE pages
                SET title = ?, render_mode = ?, content_payload = ?,
                    allowed_collections_json = ?, owner_bot_slug = ?, created_by_email = ?,
                    visibility = ?, allowed_groups_json = ?, pinned = ?, updated_at = ?
                WHERE slug = ?
                """,
                (
                    title,
                    render_mode,
                    content_payload,
                    json.dumps(allowed_collections),
                    owner_bot_slug,
                    next_creator,
                    next_vis,
                    json.dumps(next_groups),
                    1 if pinned else 0,
                    now,
                    slug,
                ),
            )
            self._conn.commit()
        return self.get_page(slug)

    def upsert_page_by_slug(
        self,
        *,
        slug: str,
        title: str,
        render_mode: str = "declarative_json",
        content_payload: str | None = None,
        allowed_collections: list[str] | None = None,
        owner_bot_slug: str = "",
        created_by_email: str = "",
        visibility: str = "shared",
        allowed_groups: list[str] | None = None,
        description: str = "",
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Idempotently create or update a dynamic Page by slug for runtime bot updates."""
        clean_slug = slugify(slug)
        raw_collections = list(allowed_collections or [])
        normalized_collections = self._normalize_page_collections(raw_collections)
        clean_creator = normalize_email(created_by_email)
        clean_visibility = normalize_visibility(visibility, default="shared")
        clean_allowed_groups = (
            normalize_group_slugs(allowed_groups) if clean_visibility == "team" else []
        )
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM pages WHERE slug = ?", (clean_slug,)
            ).fetchone()
        if exists:
            return self.update_page(
                clean_slug,
                {
                    "title": title,
                    "description": description,
                    "render_mode": render_mode,
                    "content_payload": content_payload,
                    "allowed_collections": raw_collections if allowed_collections is not None else None,
                    "owner_bot_slug": owner_bot_slug,
                    "visibility": visibility,
                    "allowed_groups": clean_allowed_groups,
                    "pinned": pinned,
                },
                caller_email=clean_creator,
            )
        self._verify_page_file_bindings(raw_collections, owner_email=clean_creator)
        now = utc_now()
        payload = (
            self._validate_page_payload(render_mode, content_payload)
            if content_payload is not None
            else (
                self._default_sandboxed_html_payload(
                    title=title.strip(),
                    description=description,
                    allowed_collections=normalized_collections,
                )
                if render_mode == "sandboxed_html"
                else json.dumps(
                    {
                        "description": description,
                        "blocks": [],
                        "rows": [],
                    }
                )
            )
        )
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO pages(
                    id, slug, title, icon, render_mode, content_payload,
                    allowed_collections_json, owner_bot_slug, created_by_email, visibility, allowed_groups_json, pinned, updated_at
                ) VALUES (?, ?, ?, 'file-text', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    make_id("pg"),
                    clean_slug,
                    title.strip(),
                    render_mode,
                    payload,
                    json.dumps(normalized_collections),
                    owner_bot_slug,
                    clean_creator,
                    clean_visibility,
                    json.dumps(clean_allowed_groups),
                    1 if pinned else 0,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_page(clean_slug)

    def delete_page(self, slug: str, *, caller_email: str = "", is_admin: bool = False) -> None:
        """Delete a dynamic page by slug."""
        clean_caller = str(caller_email or "").strip().lower()
        with self._lock:
            row = self._conn.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
            if row is None:
                raise NotFoundError(f"Page '{slug}' not found.")
            existing_cols = json.loads(row["allowed_collections_json"])
            existing_creator = (
                str(row["created_by_email"] or "").strip().lower()
                if "created_by_email" in row.keys()
                else ""
            )
            if (
                not is_admin
                and any(str(c).startswith("file:") for c in existing_cols)
                and existing_creator
                and clean_caller
                and clean_caller != existing_creator
            ):
                raise PermissionError(
                    f"User '{clean_caller}' is not permitted to delete file-bound Page '{slug}'."
                )
            cur = self._conn.execute("DELETE FROM pages WHERE slug = ?", (slug,))
            self._conn.commit()
            if cur.rowcount == 0:
                raise NotFoundError(f"Page '{slug}' not found.")

    def query_page_collection(
        self,
        slug: str,
        *,
        collection: str,
        query: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query an allowed collection scoped to page.allowed_collections."""
        page = self.get_page(slug)
        clean_col = dataset_identifier(collection)
        allowed = {dataset_identifier(c) for c in page["allowed_collections"]}
        if clean_col not in allowed:
            raise PermissionError(
                f"Page '{slug}' is not permitted to query collection '{clean_col}'."
            )
        return self.search_documents(collection=clean_col, query=query, limit=limit)

    def register_analytics_collection(
        self,
        slug: str,
        *,
        parquet_path: Path,
        row_count: int,
        columns: list[str],
        source_url: str = "",
        description: str = "Extracted Parquet dataset",
    ) -> str:
        """Register or update an analytics Parquet collection in SQLite schema_hint_json."""
        clean_coll = collection_slug(slug)
        if clean_coll in _INTERNAL_SYSTEM_COLLECTIONS:
            raise PermissionError(
                f"Cannot overwrite internal system collection '{clean_coll}'."
            )
        resolved_p = parquet_path.resolve()
        if not resolved_p.is_relative_to(self._analytics_root):
            raise ValueError("Analytics parquet path must live under analytics root.")
        rel_p = str(resolved_p.relative_to(self._analytics_root))
        hint_json = json.dumps(
            {
                "kind": "parquet",
                "rel_parquet": rel_p,
                "row_count": int(row_count),
                "columns": list(columns),
                "source_url": str(source_url)[:500],
            }
        )
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO collections(slug, description, schema_hint_json, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    description = excluded.description,
                    schema_hint_json = excluded.schema_hint_json
                """,
                (clean_coll, description[:300], hint_json, now),
            )
            self._conn.commit()
        return clean_coll

    def resolve_authorized_datasets(
        self,
        identifiers: list[str],
        *,
        owner_email: str | None = None,
    ) -> list[dict[str, Any]]:
        """Resolve authorized file:<id>[:<sub>] and collection identifiers to DuckDB dataset specs."""
        clean_ids = [
            c
            for c in self._normalize_page_collections(identifiers)
            if c not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
        ]
        specs: list[dict[str, Any]] = []
        file_cache: dict[str, dict[str, Any]] = {}

        for ident in clean_ids:
            if ident.startswith("file:"):
                parts = ident.split(":", 2)
                file_id = parts[1]
                sub_alias = parts[2] if len(parts) > 2 else None
                if file_id not in file_cache:
                    file_cache[file_id] = self.get_workspace_file_derived_paths(
                        file_id,
                        owner_email=owner_email,
                    )
                finfo = file_cache[file_id]
                derived = finfo.get("derived_datasets") or []
                matched: dict[str, Any] | None = None
                if sub_alias:
                    for ds in derived:
                        if str(ds.get("alias") or "").lower() == sub_alias or str(ds.get("id") or "").lower() == ident:
                            matched = ds
                            break
                    if matched is None:
                        raise NotFoundError(f"Derived dataset '{ident}' not found.")
                    p_path = str(matched.get("parquet_path") or "")
                    aliases = [sub_alias, f"{file_id}_{sub_alias}"]
                    if sub_alias == "pages":
                        aliases.append("pages")
                    specs.append(
                        {
                            "id": ident,
                            "parquet_path": p_path,
                            "kind": matched.get("kind") or "parquet",
                            "aliases": aliases,
                            "alias": sub_alias,
                            "file_id": file_id,
                            "row_count": matched.get("row_count"),
                            "columns": list(matched.get("columns") or []),
                        }
                    )
                else:
                    p_path = str(finfo.get("default_parquet_path") or "")
                    if not p_path and derived:
                        p_path = str(derived[0].get("parquet_path") or "")
                    if not p_path:
                        raise NotFoundError(f"No tabular or document dataset derived for '{ident}'.")
                    first_ds = next(
                        (d for d in derived if str(d.get("parquet_path") or "") == p_path),
                        derived[0] if derived else {},
                    )
                    specs.append(
                        {
                            "id": ident,
                            "parquet_path": p_path,
                            "pages_parquet_path": finfo.get("pages_parquet_path"),
                            "kind": first_ds.get("kind") or "parquet",
                            "aliases": [file_id],
                            "alias": str(first_ds.get("alias") or "main"),
                            "file_id": file_id,
                            "row_count": first_ds.get("row_count"),
                            "columns": list(first_ds.get("columns") or []),
                        }
                    )
                continue

            # Regular SQLite or analytics Parquet collection
            with self._lock:
                col_row = self._conn.execute(
                    "SELECT slug, schema_hint_json FROM collections WHERE slug = ?",
                    (ident,),
                ).fetchone()
                hint: dict[str, Any] = {}
                if col_row and col_row["schema_hint_json"]:
                    try:
                        parsed_hint = json.loads(col_row["schema_hint_json"])
                        if isinstance(parsed_hint, dict):
                            hint = parsed_hint
                    except json.JSONDecodeError:
                        hint = {}
                rel_parquet = str(hint.get("rel_parquet") or "")
                parquet_file: Path | None = None
                if rel_parquet:
                    cand = (self._analytics_root / rel_parquet).resolve()
                    if cand.is_relative_to(self._analytics_root) and cand.is_file():
                        parquet_file = cand

                if parquet_file is not None:
                    specs.append(
                        {
                            "id": ident,
                            "parquet_path": str(parquet_file),
                            "kind": "parquet_collection",
                            "aliases": [ident],
                            "alias": ident,
                            "row_count": hint.get("row_count"),
                            "columns": list(hint.get("columns") or []),
                        }
                    )
                    continue

                cnt_row = self._conn.execute(
                    "SELECT COUNT(*) AS cnt FROM collection_documents WHERE collection = ?",
                    (ident,),
                ).fetchone()
                total_cnt = int(cnt_row["cnt"] or 0) if cnt_row else 0
                raw_rows = self._conn.execute(
                    """
                    SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at
                    FROM collection_documents
                    WHERE collection = ?
                    ORDER BY updated_at DESC, rowid DESC
                    LIMIT 2000
                    """,
                    (ident,),
                ).fetchall()
            parsed_docs: list[dict[str, Any]] = []
            for row in raw_rows:
                try:
                    doc_obj = json.loads(row["doc_json"])
                except json.JSONDecodeError:
                    doc_obj = {}
                parsed_docs.append(
                    {
                        "id": str(row["id"]),
                        "collection": str(row["collection"]),
                        "external_key": row["external_key"],
                        "search_text": row["search_text"],
                        "doc": doc_obj,
                        "created_at": str(row["created_at"]),
                        "updated_at": str(row["updated_at"]),
                    }
                )
            specs.append(
                {
                    "id": ident,
                    "rows": parsed_docs,
                    "total_count": total_cnt,
                    "kind": "collection",
                    "aliases": [ident],
                    "alias": ident,
                }
            )
        return specs

    def describe_collections(
        self,
        allowed_collections: list[str] | None = None,
        sample_limit: int = 30,
        *,
        owner_email: str | None = None,
    ) -> dict[str, Any]:
        """Schema-on-read profiler over SQLite collections + DuckDB SUMMARIZE for Parquet/files."""
        normalized = [
            c
            for c in self._normalize_page_collections(allowed_collections)
            if c not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
        ]
        clean_cols = [c for c in normalized if not c.startswith("file:")]
        capped_sample = max(1, min(int(sample_limit), 100))
        secret_vals = self.collect_all_vault_secret_values()

        owners_write: dict[str, tuple[str, str]] = {}
        with self._lock:
            bot_rows = self._conn.execute(
                "SELECT slug, name, card_json FROM bots ORDER BY created_at ASC"
            ).fetchall()
            for brow in bot_rows:
                try:
                    card = json.loads(brow["card_json"])
                except json.JSONDecodeError:
                    card = {}
                cols_cfg = card.get("collections") if isinstance(card, dict) else {}
                if not isinstance(cols_cfg, dict):
                    continue
                for raw_c in cols_cfg.get("write") or []:
                    c_slug = collection_slug(str(raw_c))
                    if c_slug not in _INTERNAL_SYSTEM_COLLECTIONS:
                        owners_write.setdefault(c_slug, (str(brow["slug"]), str(brow["name"])))

            descriptions: list[dict[str, Any]] = []
            total_documents = 0
            for col in clean_cols:
                agg = self._conn.execute(
                    """
                    SELECT COUNT(*) AS doc_count, MAX(updated_at) AS last_updated_at
                    FROM collection_documents
                    WHERE collection = ?
                    """,
                    (col,),
                ).fetchone()
                doc_count = int(agg["doc_count"] or 0) if agg else 0
                last_updated_at = agg["last_updated_at"] if agg else None
                total_documents += doc_count

                rows = self._conn.execute(
                    """
                    SELECT id, collection, external_key, doc_json, updated_at
                    FROM collection_documents
                    WHERE collection = ?
                    ORDER BY updated_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (col, capped_sample),
                ).fetchall()

                path_types: dict[str, set[str]] = {}
                path_doc_hits: dict[str, int] = {}
                path_samples: dict[str, list[str]] = {}
                sample_rows: list[dict[str, Any]] = []
                parsed_count = 0

                for idx, row in enumerate(rows):
                    try:
                        doc = json.loads(row["doc_json"])
                    except json.JSONDecodeError:
                        doc = {}
                    if not isinstance(doc, dict):
                        doc = {"value": doc}
                    parsed_count += 1
                    flattened = _flatten_json_paths(doc)
                    for path, vals in flattened.items():
                        path_doc_hits[path] = path_doc_hits.get(path, 0) + 1
                        types_set = path_types.setdefault(path, set())
                        samples_list = path_samples.setdefault(path, [])
                        for val in vals:
                            v_type = _json_value_type(val)
                            if v_type != "null":
                                types_set.add(v_type)
                            if v_type in {"string", "number", "boolean"} and len(samples_list) < 5:
                                rendered = redact_secrets(str(val)[:120], secret_vals)
                                if rendered not in samples_list:
                                    samples_list.append(rendered)
                    if idx < 2:
                        sample_rows.append(
                            {
                                "id": row["id"],
                                "collection": row["collection"],
                                "external_key": redact_secrets(str(row["external_key"] or ""), secret_vals)
                                if row["external_key"] is not None
                                else None,
                                "updated_at": row["updated_at"],
                                "doc": _compact_scrubbed_doc(doc, secret_vals),
                            }
                        )

                denom = max(1, parsed_count)
                fields_meta: list[dict[str, Any]] = []
                for path in sorted(path_doc_hits.keys()):
                    types_sorted = sorted(path_types.get(path) or {"string"})
                    fields_meta.append(
                        {
                            "path": path,
                            "type": types_sorted[0] if len(types_sorted) == 1 else "mixed",
                            "types": types_sorted,
                            "coverage_pct": round((path_doc_hits[path] / denom) * 100.0, 1),
                            "sample_values": path_samples.get(path, [])[:5],
                        }
                    )

                owner = owners_write.get(col)
                descriptions.append(
                    {
                        "collection": col,
                        "label": self._humanize_collection_label(col, owner[1] if owner else None),
                        "owner_bot_slug": owner[0] if owner else None,
                        "owner_bot_name": owner[1] if owner else None,
                        "doc_count": doc_count,
                        "sampled_docs": parsed_count,
                        "last_updated_at": last_updated_at,
                        "fields": fields_meta,
                        "sample_rows": sample_rows,
                    }
                )

        dataset_profiles: list[dict[str, Any]] = []
        if normalized:
            specs = self.resolve_authorized_datasets(normalized, owner_email=owner_email)
            parquet_specs = [s for s in specs if s.get("parquet_path")]
            if parquet_specs:
                dataset_profiles = profile_datasets(parquet_specs, secret_values=secret_vals)
                for prof in dataset_profiles:
                    if str(prof.get("dataset_id") or "").startswith("file:"):
                        total_documents += int(prof.get("row_count") or 0)
                    else:
                        # Analytics parquet collection row count
                        for desc in descriptions:
                            if desc["collection"] == prof.get("dataset_id") and desc["doc_count"] == 0:
                                desc["doc_count"] = int(prof.get("row_count") or 0)
                                total_documents += desc["doc_count"]

        return {
            "collections": descriptions,
            "datasets": dataset_profiles,
            "total_documents": total_documents,
        }

    def execute_analytics_query(
        self,
        sql: str,
        *,
        allowed_collections: list[str],
        owner_email: str | None = None,
        params: list[Any] | None = None,
        row_cap: int = 500,
        engine: str = "auto",
    ) -> dict[str, Any]:
        """Validate SQL + ownership, then route between DuckDB 2.0 and legacy SQLite JSON1."""
        _validate_readonly_sandbox_sql(sql)
        clean_ids = [
            c
            for c in self._normalize_page_collections(allowed_collections)
            if c not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
        ]
        dataset_specs = self.resolve_authorized_datasets(clean_ids, owner_email=owner_email)
        has_parquet = any(d.get("parquet_path") for d in dataset_specs)

        wants_sqlite = engine == "sqlite" or (
            engine == "auto"
            and not has_parquet
            and bool(
                re.search(
                    r"\b(?:from\s+docs|json_extract|json_each|json_tree|strftime)\b",
                    sql,
                    re.IGNORECASE,
                )
            )
        )
        if wants_sqlite:
            if any(c.startswith("file:") for c in clean_ids) or has_parquet:
                raise ValueError(
                    "SQLite engine cannot query Parquet or workspace file datasets; use engine='duckdb' or 'auto'."
                )
            return self.execute_sandboxed_json_query(
                sql,
                allowed_collections=clean_ids,
                owner_email=owner_email,
                params=params,
                row_cap=row_cap,
            )

        secret_vals = self.collect_all_vault_secret_values()
        return execute_duckdb_query(
            sql,
            datasets=dataset_specs,
            secret_values=secret_vals,
            params=params,
            row_cap=row_cap,
        )

    def execute_sandboxed_json_query(
        self,
        sql: str,
        *,
        allowed_collections: list[str],
        owner_email: str | None = None,
        params: list[Any] | None = None,
        row_cap: int = 500,
    ) -> dict[str, Any]:
        """Run SELECT/WITH SQLite JSON1 queries inside an ephemeral :memory: sandbox over scrubbed docs."""
        del owner_email  # Reserved for multi-tenant scoping; rows strictly bound to allowed_collections.
        validated_sql = _validate_readonly_sandbox_sql(sql)
        clean_cols = [
            c
            for c in self._normalize_page_collections(allowed_collections)
            if c not in _READ_FORBIDDEN_SYSTEM_COLLECTIONS
        ]
        capped_rows = max(1, min(int(row_cap), 500))
        secret_vals = self.collect_all_vault_secret_values()

        collection_counts: dict[str, int] = {}
        loaded_rows: list[tuple[str, str, str | None, str, str, str, str]] = []
        with self._lock:
            for col in clean_cols:
                cnt_row = self._conn.execute(
                    "SELECT COUNT(*) AS cnt FROM collection_documents WHERE collection = ?",
                    (col,),
                ).fetchone()
                collection_counts[col] = int(cnt_row["cnt"] or 0) if cnt_row else 0

            if clean_cols:
                placeholders = ", ".join("?" for _ in clean_cols)
                raw_rows = self._conn.execute(
                    f"""
                    SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at
                    FROM collection_documents
                    WHERE collection IN ({placeholders})
                    ORDER BY updated_at DESC, rowid DESC
                    LIMIT 2000
                    """,
                    tuple(clean_cols),
                ).fetchall()
                for row in raw_rows:
                    scrubbed_ext = (
                        redact_secrets(str(row["external_key"]), secret_vals)
                        if row["external_key"] is not None
                        else None
                    )
                    scrubbed_search = redact_secrets(str(row["search_text"] or ""), secret_vals)
                    scrubbed_json = redact_secrets(str(row["doc_json"] or "{}"), secret_vals)
                    loaded_rows.append(
                        (
                            str(row["id"]),
                            str(row["collection"]),
                            scrubbed_ext,
                            scrubbed_search,
                            scrubbed_json,
                            str(row["created_at"]),
                            str(row["updated_at"]),
                        )
                    )

        mem_conn = sqlite3.connect(":memory:")
        try:
            mem_conn.execute(
                """
                CREATE TABLE docs (
                    id TEXT,
                    collection TEXT,
                    external_key TEXT,
                    search_text TEXT,
                    doc_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
                """
            )
            mem_conn.execute("CREATE INDEX idx_mem_docs_col ON docs(collection, updated_at)")
            if loaded_rows:
                mem_conn.executemany(
                    """
                    INSERT INTO docs (id, collection, external_key, search_text, doc_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    loaded_rows,
                )
            mem_conn.commit()

            def _authorizer(
                action: int,
                arg1: str | None,
                arg2: str | None,
                db_name: str | None,
                trigger_name: str | None,
            ) -> int:
                del db_name, trigger_name
                if action == sqlite3.SQLITE_SELECT:
                    return sqlite3.SQLITE_OK
                if action == sqlite3.SQLITE_READ:
                    if (arg1 or "").lower() in {"docs", "json_each", "json_tree"}:
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_FUNCTION:
                    if (arg2 or "").lower() in _SAFE_SANDBOX_SQL_FUNCTIONS:
                        return sqlite3.SQLITE_OK
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_DENY

            deadline = time.monotonic() + 0.30
            mem_conn.set_progress_handler(
                lambda: 1 if time.monotonic() > deadline else 0,
                1000,
            )
            mem_conn.set_authorizer(_authorizer)

            try:
                cur = mem_conn.execute(validated_sql, list(params or []))
                fetched = cur.fetchmany(capped_rows + 1)
            except sqlite3.DatabaseError as exc:
                err_msg = str(exc)
                lowered = err_msg.lower()
                if "not authorized" in lowered:
                    raise PermissionError(f"SQL sandbox blocked unauthorized operation: {err_msg}") from exc
                if "interrupted" in lowered:
                    raise TimeoutError("SQL sandbox query exceeded the 300 ms time limit.") from exc
                raise

            raw_cols = [desc[0] for desc in (cur.description or ())]
            columns: list[str] = []
            seen_cols: dict[str, int] = {}
            for col_name in raw_cols:
                cnt = seen_cols.get(col_name, 0) + 1
                seen_cols[col_name] = cnt
                columns.append(col_name if cnt == 1 else f"{col_name}_{cnt}")

            truncated = len(fetched) > capped_rows
            slice_rows = fetched[:capped_rows]
            out_rows = [dict(zip(columns, row)) for row in slice_rows]
            return {
                "columns": columns,
                "rows": out_rows,
                "row_count": len(out_rows),
                "truncated": truncated,
                "collection_counts": collection_counts,
            }
        finally:
            mem_conn.close()

    def resolve_page_data(
        self,
        slug: str,
        *,
        query: str | None = None,
        limit: int = 200,
        owner_email: str | None = None,
    ) -> dict[str, Any]:
        """Resolve a dynamic page alongside SQLite collection records and DuckDB/Parquet datasets."""
        page = self.get_page(slug)
        capped_limit = max(1, min(int(limit), 2000))
        collections_data: dict[str, list[dict[str, Any]]] = {}
        collection_counts: dict[str, int] = {}
        datasets_data: dict[str, list[dict[str, Any]]] = {}
        dataset_profiles: dict[str, Any] = {}
        records: list[dict[str, Any]] = []
        allowed_cols = self._normalize_page_collections(page["allowed_collections"])
        regular_cols = [c for c in allowed_cols if not c.startswith("file:")]
        clean_viewer = str(owner_email or "").strip().lower()
        created_by_email = str(page.get("created_by_email") or "").strip().lower()
        if (
            any(c.startswith("file:") for c in allowed_cols)
            and created_by_email
            and created_by_email != clean_viewer
        ):
            raise PermissionError(
                f"User '{clean_viewer or 'unknown'}' is not permitted to view files bound to Page '{slug}'."
            )

        for col in regular_cols:
            docs = self.search_documents(collection=col, query=query, limit=capped_limit)
            collections_data[col] = docs
            records.extend(docs)
        with self._lock:
            for col in regular_cols:
                cnt_row = self._conn.execute(
                    "SELECT COUNT(*) AS cnt FROM collection_documents WHERE collection = ?",
                    (col,),
                ).fetchone()
                collection_counts[col] = int(cnt_row["cnt"] or 0) if cnt_row else 0

        if allowed_cols:
            specs = self.resolve_authorized_datasets(allowed_cols, owner_email=owner_email)
            secret_vals = self.collect_all_vault_secret_values()
            parquet_specs = [s for s in specs if s.get("parquet_path")]
            if parquet_specs:
                for prof in profile_datasets(parquet_specs, secret_values=secret_vals):
                    ds_id = str(prof["dataset_id"])
                    dataset_profiles[ds_id] = prof
                    collection_counts[ds_id] = int(prof.get("row_count") or 0)
                for spec in parquet_specs:
                    ds_id = str(spec["id"])
                    _, rows_out, _ = read_dataset_rows(
                        Path(str(spec["parquet_path"])),
                        limit=capped_limit,
                        secret_values=secret_vals,
                    )
                    datasets_data[ds_id] = rows_out

        records.sort(key=lambda rec: str(rec.get("updated_at") or ""), reverse=True)
        parsed_payload: dict[str, Any] = {}
        if page["render_mode"] == "declarative_json":
            try:
                parsed = json.loads(page["content_payload"])
                if isinstance(parsed, dict):
                    parsed_payload = parsed
            except json.JSONDecodeError:
                parsed_payload = {"description": page["content_payload"]}

        total_records = sum(collection_counts.values()) if allowed_cols else 0
        return {
            "page": page,
            "parsed_payload": parsed_payload,
            "collections": collections_data,
            "collection_counts": collection_counts,
            "datasets": datasets_data,
            "dataset_profiles": dataset_profiles,
            "records": records[:capped_limit],
            "total_records": total_records,
        }

    @staticmethod
    def _humanize_collection_label(slug: str, owner_bot_name: str | None) -> str:
        if slug == "telegram_channel_posts":
            return "Telegram Posts & DMs"
        if slug == "ssh_audit_log":
            return "SSH Terminal Audit Log"
        if slug.startswith("bot_") and slug.endswith("_items") and owner_bot_name:
            return f"{owner_bot_name} Items"
        return slug.replace("_", " ").replace("-", " ").title()

    def list_collections(self) -> list[dict[str, Any]]:
        """List registered schema-less collections with eager bot/connector registration and owner hints."""
        now = utc_now()
        owners_write: dict[str, tuple[str, str]] = {}
        owners_read: dict[str, tuple[str, str]] = {}
        with self._lock:
            bot_rows = self._conn.execute(
                "SELECT slug, name, card_json FROM bots ORDER BY created_at ASC"
            ).fetchall()
            for brow in bot_rows:
                bslug = str(brow["slug"])
                bname = str(brow["name"])
                try:
                    card = json.loads(brow["card_json"])
                except json.JSONDecodeError:
                    card = {}
                cols_cfg = card.get("collections") if isinstance(card, dict) else {}
                if not isinstance(cols_cfg, dict):
                    continue
                for raw_c in cols_cfg.get("write") or []:
                    ds_c = dataset_identifier(str(raw_c))
                    if ds_c.startswith("file:"):
                        continue
                    clean = collection_slug(str(raw_c))
                    if clean not in _INTERNAL_SYSTEM_COLLECTIONS:
                        owners_write.setdefault(clean, (bslug, bname))
                for raw_c in cols_cfg.get("read") or []:
                    ds_c = dataset_identifier(str(raw_c))
                    if ds_c.startswith("file:"):
                        continue
                    clean = collection_slug(str(raw_c))
                    if clean not in _INTERNAL_SYSTEM_COLLECTIONS:
                        owners_read.setdefault(clean, (bslug, bname))
                self._register_collections_locked(cols_cfg, owner_name=bname, created_at=now)

            has_telegram = self._conn.execute(
                "SELECT 1 FROM oauth_accounts WHERE provider = 'telegram' LIMIT 1"
            ).fetchone()
            if has_telegram is not None:
                self._ensure_collection_locked(
                    "telegram_channel_posts",
                    description="Incoming Telegram channel posts and bot messages",
                    created_at=now,
                )
            self._conn.commit()

            rows = self._conn.execute(
                """
                SELECT c.slug, c.description, c.schema_hint_json, c.created_at,
                       COUNT(d.id) AS doc_count
                FROM collections c
                LEFT JOIN collection_documents d ON d.collection = c.slug
                GROUP BY c.slug
                ORDER BY c.created_at ASC
                """
            ).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            cslug = str(row["slug"])
            owner = owners_write.get(cslug) or owners_read.get(cslug)
            owner_slug = owner[0] if owner else None
            owner_name = owner[1] if owner else None
            hint_count = 0
            if row["schema_hint_json"]:
                try:
                    hint_obj = json.loads(row["schema_hint_json"])
                    if isinstance(hint_obj, dict):
                        hint_count = int(hint_obj.get("row_count") or 0)
                except json.JSONDecodeError:
                    hint_count = 0
            result.append(
                {
                    "slug": cslug,
                    "label": self._humanize_collection_label(cslug, owner_name),
                    "description": row["description"],
                    "doc_count": max(int(row["doc_count"]), hint_count),
                    "owner_bot_slug": owner_slug,
                    "owner_bot_name": owner_name,
                    "is_internal": cslug in _READ_FORBIDDEN_SYSTEM_COLLECTIONS,
                    "read_only_system": cslug in _BOT_READABLE_SYSTEM_COLLECTIONS,
                    "created_at": row["created_at"],
                }
            )
        return result

    def list_collection_external_keys(self, collection: str) -> set[str]:
        """Return all non-null external_key values currently stored in collection."""
        clean_coll = collection_slug(collection)
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT external_key
                FROM collection_documents
                WHERE collection = ? AND external_key IS NOT NULL
                """,
                (clean_coll,),
            ).fetchall()
        return {str(row["external_key"]) for row in rows if row["external_key"]}

    def save_desktop_snapshot(
        self,
        bot_slug: str,
        *,
        png_base64: str,
        caption: str = "",
        url: str = "",
    ) -> str:
        """Persist an immutable post-command desktop screenshot and retain the latest 40 per bot."""
        snap_id = make_id("snap")
        now = utc_now()
        doc = {
            "snapshot_id": snap_id,
            "bot_slug": bot_slug,
            "png_base64": png_base64,
            "caption": caption[:200],
            "url": url[:300],
            "captured_at": now,
        }
        self.upsert_document(
            collection="desktop_snapshots",
            external_key=snap_id,
            doc_id=snap_id,
            search_text=f"{bot_slug} {caption} {url}".strip(),
            doc=doc,
            description="Immutable post-command desktop screenshots",
        )
        with self._lock:
            stale_rows = self._conn.execute(
                """
                SELECT id FROM collection_documents
                WHERE collection = 'desktop_snapshots'
                  AND json_extract(doc_json, '$.bot_slug') = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT -1 OFFSET 40
                """,
                (bot_slug,),
            ).fetchall()
            if stale_rows:
                stale_ids = [r["id"] for r in stale_rows]
                placeholders = ",".join("?" for _ in stale_ids)
                self._conn.execute(
                    f"DELETE FROM collection_documents WHERE collection = 'desktop_snapshots' AND id IN ({placeholders})",
                    stale_ids,
                )
                self._conn.commit()
        return snap_id

    def get_desktop_snapshot(self, bot_slug: str, snapshot_id: str) -> dict[str, Any] | None:
        """Fetch an immutable desktop snapshot for bot_slug by snapshot_id, or None."""
        item = self.get_document_by_external_key("desktop_snapshots", snapshot_id)
        if item is None:
            return None
        doc = item.get("doc") or {}
        if doc.get("bot_slug") != bot_slug or not doc.get("png_base64"):
            return None
        return doc

    # ------------------------------------------------------------------
    # Zero-AI-Exposure Secrets Vault (collection 'vault_secrets')
    # ------------------------------------------------------------------
    @staticmethod
    def vault_env_prefix(slug: str) -> str:
        clean = re.sub(r"[^A-Z0-9]+", "_", slug.strip().upper()).strip("_") or "SECRET"
        return f"ARGO_VAULT_{clean}"

    @classmethod
    def _build_vault_placeholders(
        cls,
        *,
        slug: str,
        host: str,
        port: str,
        url: str,
        secret_keys: list[str],
    ) -> list[str]:
        prefix = cls.vault_env_prefix(slug)
        placeholders: list[str] = []
        if host.strip():
            placeholders.append(f"${prefix}_HOST")
        if port.strip():
            placeholders.append(f"${prefix}_PORT")
        if url.strip():
            placeholders.append(f"${prefix}_URL")
        for key in secret_keys:
            k_upper = re.sub(r"[^A-Z0-9]+", "_", str(key).strip().upper()).strip("_")
            if not k_upper:
                continue
            if k_upper == "USERNAME":
                placeholders.append(f"${prefix}_USER")
            placeholders.append(f"${prefix}_{k_upper}")
        return list(dict.fromkeys(placeholders))

    @staticmethod
    def _compute_ssh_key_fingerprint(key_b64: str) -> str:
        raw_str = str(key_b64 or "").strip()
        try:
            raw_bytes = base64.b64decode(raw_str.encode("ascii"), validate=True)
        except Exception:
            raw_bytes = raw_str.encode("utf-8")
        digest = hashlib.sha256(raw_bytes).digest()
        b64_fp = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{b64_fp}"

    @classmethod
    def _extract_host_key_fingerprints(cls, doc: dict[str, Any]) -> dict[str, str]:
        raw_pinned = doc.get("pinned_host_keys")
        if not isinstance(raw_pinned, dict):
            return {}
        out: dict[str, str] = {}
        for hp, entry in raw_pinned.items():
            key_str = str(hp).strip()
            if not key_str:
                continue
            if isinstance(entry, dict):
                k_type = str(entry.get("key_type") or "").strip()
                fp = str(entry.get("fingerprint") or "").strip()
                if not fp and entry.get("key_b64"):
                    fp = cls._compute_ssh_key_fingerprint(str(entry["key_b64"]))
                if fp:
                    out[key_str] = f"{k_type} {fp}".strip()
            elif isinstance(entry, str) and entry.strip():
                parts = entry.strip().split(None, 1)
                if len(parts) == 2:
                    out[key_str] = f"{parts[0]} {cls._compute_ssh_key_fingerprint(parts[1])}"
                else:
                    out[key_str] = cls._compute_ssh_key_fingerprint(parts[0])
        return out

    @classmethod
    def _normalize_vault_trust_prefixes(cls, raw_prefixes: Any) -> list[str]:
        if not isinstance(raw_prefixes, (list, tuple)):
            return []
        from argo_core.ssh.manager import normalize_and_validate_trust_prefix

        out: list[str] = []
        seen_lower: set[str] = set()
        for raw in raw_prefixes:
            norm = normalize_and_validate_trust_prefix(str(raw or ""))
            if norm and norm.lower() not in seen_lower:
                seen_lower.add(norm.lower())
                out.append(norm)
            if len(out) >= 200:
                break
        return out

    @classmethod
    def _sanitize_vault_item(cls, saved: dict[str, Any]) -> dict[str, Any]:
        doc = saved.get("doc") or {}
        slug = str(doc.get("slug") or saved.get("external_key") or "")
        secret_keys = [str(k) for k in (doc.get("secret_keys") or []) if str(k).strip()]
        host = str(doc.get("host") or "")
        port = str(doc.get("port") or "")
        url = str(doc.get("url") or "")
        raw_allowed = doc.get("allowed_bots")
        if isinstance(raw_allowed, list):
            allowed_bots = [str(b).strip() for b in raw_allowed if str(b).strip()]
        else:
            allowed_bots = ["*"]
        raw_trusted = doc.get("trusted_command_prefixes")
        trusted_prefixes = (
            [str(p).strip() for p in raw_trusted if str(p).strip()]
            if isinstance(raw_trusted, list)
            else []
        )
        return {
            "id": saved["id"],
            "slug": slug,
            "name": str(doc.get("name") or slug),
            "secret_type": str(doc.get("secret_type") or "ssh"),
            "host": host,
            "port": port,
            "url": url,
            "secret_keys": secret_keys,
            "allowed_bots": allowed_bots,
            "trusted_command_prefixes": trusted_prefixes,
            "host_key_fingerprints": cls._extract_host_key_fingerprints(doc),
            "env_placeholders": cls._build_vault_placeholders(
                slug=slug,
                host=host,
                port=port,
                url=url,
                secret_keys=secret_keys,
            ),
            "owner_email": normalize_email(doc.get("owner_email")),
            "visibility": normalize_visibility(doc.get("visibility"), default="shared"),
            "allowed_groups": (
                normalize_group_slugs(doc.get("allowed_groups"))
                if normalize_visibility(doc.get("visibility"), default="shared") == "team"
                else []
            ),
            "created_at": saved["created_at"],
            "updated_at": saved["updated_at"],
        }

    def upsert_vault_secret(
        self,
        *,
        name: str,
        slug: str | None = None,
        secret_type: str = "ssh",
        host: str = "",
        port: str = "22",
        url: str = "",
        secrets: dict[str, str] | None = None,
        allowed_bots: list[str] | None = None,
        pinned_host_keys: dict[str, Any] | None = None,
        trusted_command_prefixes: list[str] | None = None,
        clear_fields: list[str] | None = None,
        owner_email: str | None = None,
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> dict[str, Any]:
        """Encrypt and persist a sensitive credential entry in 'vault_secrets'."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Vault secret name is required.")
        clean_slug = slugify(slug or clean_name)
        existing = self.get_vault_secret_decrypted(clean_slug)

        merged_secrets: dict[str, str] = {}
        if existing and isinstance(existing.get("secrets"), dict):
            merged_secrets.update(
                {str(k): str(v) for k, v in existing["secrets"].items() if v is not None and str(v) != ""}
            )
        for raw_cf in (clear_fields or []):
            clean_cf = re.sub(r"[^a-z0-9_]+", "_", str(raw_cf).strip().lower()).strip("_")
            if clean_cf:
                merged_secrets.pop(clean_cf, None)
        for raw_k, raw_v in (secrets or {}).items():
            clean_k = re.sub(r"[^a-z0-9_]+", "_", str(raw_k).strip().lower()).strip("_")
            if not clean_k:
                continue
            val = "" if raw_v is None else str(raw_v)
            if val != "":
                merged_secrets[clean_k] = val

        token_bytes = self._vault.encrypt_json(merged_secrets)
        ciphertext_b64 = base64.b64encode(token_bytes).decode("ascii")
        if allowed_bots is not None:
            clean_allowed = [str(b).strip() for b in allowed_bots if str(b).strip()]
        elif existing is not None:
            raw_existing_allowed = existing.get("allowed_bots")
            clean_allowed = (
                [str(b).strip() for b in raw_existing_allowed if str(b).strip()]
                if isinstance(raw_existing_allowed, list)
                else ["*"]
            )
        else:
            clean_allowed = ["*"]

        if pinned_host_keys is not None:
            merged_pinned = dict(pinned_host_keys)
        elif existing is not None and isinstance(existing.get("pinned_host_keys"), dict):
            merged_pinned = dict(existing["pinned_host_keys"])
        else:
            merged_pinned = {}

        if trusted_command_prefixes is not None:
            clean_trusted = self._normalize_vault_trust_prefixes(trusted_command_prefixes)
        elif existing is not None:
            clean_trusted = self._normalize_vault_trust_prefixes(
                existing.get("trusted_command_prefixes") or []
            )
        else:
            clean_trusted = []

        resolved_owner = (
            normalize_email(owner_email)
            if owner_email is not None
            else normalize_email(existing.get("owner_email") if existing else "")
        )
        resolved_vis = (
            normalize_visibility(visibility)
            if visibility is not None
            else normalize_visibility(existing.get("visibility") if existing else "shared", default="shared")
        )
        if resolved_vis != "team":
            resolved_groups: list[str] = []
        elif allowed_groups is not None:
            resolved_groups = normalize_group_slugs(allowed_groups)
        elif existing is not None:
            resolved_groups = normalize_group_slugs(existing.get("allowed_groups") or [])
        else:
            resolved_groups = []

        doc = {
            "slug": clean_slug,
            "name": clean_name,
            "secret_type": str(secret_type or (existing.get("secret_type") if existing else "ssh")),
            "host": host.strip(),
            "port": port.strip() or ("22" if secret_type == "ssh" else ""),
            "url": url.strip(),
            "secret_keys": sorted(merged_secrets.keys()),
            "allowed_bots": clean_allowed,
            "trusted_command_prefixes": clean_trusted,
            "pinned_host_keys": merged_pinned,
            "owner_email": resolved_owner,
            "visibility": resolved_vis,
            "allowed_groups": resolved_groups,
            "ciphertext_b64": ciphertext_b64,
        }
        saved = self.upsert_document(
            collection="vault_secrets",
            external_key=clean_slug,
            search_text="",
            doc=doc,
            description="Fernet-encrypted Secrets Vault entries for zero-AI credential injection",
        )
        return self._sanitize_vault_item(saved)

    def add_vault_trusted_command_prefixes(
        self,
        slug: str,
        prefixes: list[str],
    ) -> tuple[dict[str, Any], list[str]]:
        """Append validated dynamic command prefixes onto a Vault credential."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            raise NotFoundError(f"Vault secret '{clean_slug}' not found.")
        doc = dict(saved.get("doc") or {})
        existing_clean = self._normalize_vault_trust_prefixes(doc.get("trusted_command_prefixes") or [])
        existing_lower = {p.lower() for p in existing_clean}
        candidate_clean = self._normalize_vault_trust_prefixes(prefixes)
        added: list[str] = []
        merged = list(existing_clean)
        for pref in candidate_clean:
            if pref.lower() not in existing_lower and len(merged) < 200:
                existing_lower.add(pref.lower())
                merged.append(pref)
                added.append(pref)
        if not added:
            return self._sanitize_vault_item(saved), []
        doc["trusted_command_prefixes"] = merged
        updated = self.upsert_document(
            collection="vault_secrets",
            external_key=clean_slug,
            search_text="",
            doc=doc,
            description="Fernet-encrypted Secrets Vault entries for zero-AI credential injection",
        )
        return self._sanitize_vault_item(updated), added

    def list_vault_secrets(self) -> list[dict[str, Any]]:
        """List sanitized Vault secret metadata (never returning plaintext secrets or ciphertext)."""
        docs = self.search_documents("vault_secrets", limit=200)
        items = [self._sanitize_vault_item(item) for item in docs]
        items.sort(key=lambda item: str(item.get("name") or item.get("slug") or "").lower())
        return items

    def get_vault_secret_decrypted(self, slug: str) -> dict[str, Any] | None:
        """Internal-only decryption of a Secrets Vault entry for Python execution injection."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            return None
        doc = saved.get("doc") or {}
        cipher_b64 = str(doc.get("ciphertext_b64") or "")
        decrypted_secrets: dict[str, str] = {}
        if cipher_b64:
            try:
                raw = self._vault.decrypt_json(base64.b64decode(cipher_b64.encode("ascii")))
                decrypted_secrets = {
                    str(k): str(v) for k, v in raw.items() if v is not None and str(v) != ""
                }
            except Exception:
                decrypted_secrets = {}
        meta = self._sanitize_vault_item(saved)
        raw_pinned = doc.get("pinned_host_keys")
        pinned_map = dict(raw_pinned) if isinstance(raw_pinned, dict) else {}
        return {
            **meta,
            "pinned_host_keys": pinned_map,
            "secrets": decrypted_secrets,
        }

    def pin_vault_host_key(
        self,
        slug: str,
        host: str,
        port: int,
        key_type: str,
        key_b64: str,
    ) -> dict[str, Any]:
        """Persist a TOFU-verified SSH host key under vault_secrets.pinned_host_keys."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            raise NotFoundError(f"Vault secret '{clean_slug}' not found.")
        doc = dict(saved.get("doc") or {})
        pinned = dict(doc.get("pinned_host_keys") or {}) if isinstance(doc.get("pinned_host_keys"), dict) else {}
        host_port = f"{host.strip().lower()}:{int(port)}"
        pinned[host_port] = {
            "key_type": str(key_type).strip(),
            "key_b64": str(key_b64).strip(),
            "fingerprint": self._compute_ssh_key_fingerprint(key_b64),
            "pinned_at": utc_now(),
        }
        doc["pinned_host_keys"] = pinned
        updated = self.upsert_document(
            collection="vault_secrets",
            external_key=clean_slug,
            search_text="",
            doc=doc,
            description="Fernet-encrypted Secrets Vault entries for zero-AI credential injection",
        )
        return self._sanitize_vault_item(updated)

    def reset_vault_host_key(
        self,
        slug: str,
        host_port: str | None = None,
    ) -> dict[str, Any]:
        """Clear one or all pinned SSH host keys on a Vault secret after verified key rotation."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            raise NotFoundError(f"Vault secret '{clean_slug}' not found.")
        doc = dict(saved.get("doc") or {})
        pinned = dict(doc.get("pinned_host_keys") or {}) if isinstance(doc.get("pinned_host_keys"), dict) else {}
        if host_port and host_port.strip():
            pinned.pop(host_port.strip().lower(), None)
        else:
            pinned.clear()
        doc["pinned_host_keys"] = pinned
        updated = self.upsert_document(
            collection="vault_secrets",
            external_key=clean_slug,
            search_text="",
            doc=doc,
            description="Fernet-encrypted Secrets Vault entries for zero-AI credential injection",
        )
        return self._sanitize_vault_item(updated)

    def bulk_create_ssh_vault_secrets(
        self,
        *,
        name_prefix: str,
        hosts: list[str],
        port: str = "22",
        secrets: dict[str, str],
        allowed_bots: list[str] | None = None,
        owner_email: str | None = None,
        visibility: str | None = None,
        allowed_groups: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Create one host-pinned SSH Vault entry per host target cleanly."""
        clean_prefix = name_prefix.strip() or "SSH Server"
        default_port = str(port or "22").strip() or "22"
        clean_allowed = (
            [str(b).strip() for b in allowed_bots if str(b).strip()]
            if allowed_bots is not None
            else []
        )
        existing_slugs = {item["slug"] for item in self.list_vault_secrets()}
        created: list[dict[str, Any]] = []
        seen_targets: set[str] = set()
        for raw_entry in hosts:
            entry = str(raw_entry or "").strip()
            if not entry:
                continue
            target_host = entry
            target_port = default_port
            if entry.startswith("[") and "]:" in entry:
                h_part, p_part = entry[1:].split("]:", 1)
                target_host = h_part.strip()
                target_port = p_part.strip() or default_port
            elif entry.count(":") == 1 and not entry.startswith("["):
                h_part, p_part = entry.split(":", 1)
                if p_part.strip().isdigit():
                    target_host = h_part.strip()
                    target_port = p_part.strip()
            target_host = target_host.strip("[]").strip()
            if not target_host:
                continue
            dedup_key = f"{target_host.lower()}:{target_port}"
            if dedup_key in seen_targets:
                continue
            seen_targets.add(dedup_key)

            base_slug = slugify(f"{clean_prefix}-{target_host}")
            candidate_slug = base_slug
            suffix = 2
            while candidate_slug in existing_slugs:
                candidate_slug = f"{base_slug}-{suffix}"
                suffix += 1
            existing_slugs.add(candidate_slug)
            created.append(
                self.upsert_vault_secret(
                    name=f"{clean_prefix} ({target_host})",
                    slug=candidate_slug,
                    secret_type="ssh",
                    host=target_host,
                    port=target_port,
                    secrets=secrets,
                    allowed_bots=clean_allowed,
                    owner_email=owner_email,
                    visibility=visibility,
                    allowed_groups=allowed_groups,
                )
            )
        return created

    def get_ssh_audit_settings(self, default_retention_hours: int = 24) -> dict[str, Any]:
        """Return SSH audit retention configuration and recording counts."""
        clamped_default = max(1, min(8760, int(default_retention_hours)))
        doc_rec = self.get_document_by_external_key("ssh_settings", "retention_config")
        retention_hours = clamped_default
        if doc_rec and isinstance(doc_rec.get("doc"), dict):
            try:
                retention_hours = max(1, min(8760, int(doc_rec["doc"].get("retention_hours") or clamped_default)))
            except (TypeError, ValueError):
                retention_hours = clamped_default

        sessions: dict[str, bool] = {}
        with self._lock:
            rows = self._conn.execute(
                "SELECT doc_json FROM collection_documents WHERE collection = 'ssh_audit_log'"
            ).fetchall()
        for row in rows:
            try:
                doc = json.loads(row["doc_json"])
            except json.JSONDecodeError:
                continue
            if not isinstance(doc, dict):
                continue
            sid = str(doc.get("session_id") or "").strip()
            if not sid:
                continue
            sessions[sid] = sessions.get(sid, False) or bool(doc.get("pinned"))
        return {
            "retention_hours": retention_hours,
            "total_recordings": len(sessions),
            "pinned_recordings": sum(1 for v in sessions.values() if v),
        }

    def update_ssh_audit_settings(self, retention_hours: int) -> dict[str, Any]:
        """Persist customizable SSH audit retention TTL (1..8760 hours)."""
        clamped = max(1, min(8760, int(retention_hours)))
        self.upsert_document(
            collection="ssh_settings",
            external_key="retention_config",
            search_text="",
            doc={"retention_hours": clamped, "updated_at": utc_now()},
            description="SSH audit recording retention configuration",
        )
        return self.get_ssh_audit_settings(default_retention_hours=clamped)

    def get_chat_retention_settings(self) -> dict[str, Any]:
        """Return workspace chat history retention configuration and saved message counts."""
        doc_rec = self.get_document_by_external_key("chat_settings", "retention_config")
        retention_days = 0
        updated_at: str | None = None
        if doc_rec and isinstance(doc_rec.get("doc"), dict):
            try:
                retention_days = max(0, min(3650, int(doc_rec["doc"].get("retention_days") or 0)))
            except (TypeError, ValueError):
                retention_days = 0
            raw_updated = doc_rec["doc"].get("updated_at")
            if isinstance(raw_updated, str) and raw_updated.strip():
                updated_at = raw_updated.strip()

        with self._lock:
            bot_row = self._conn.execute(
                "SELECT COUNT(*) FROM collection_documents WHERE collection = 'bot_threads'"
            ).fetchone()
            room_row = self._conn.execute(
                "SELECT COUNT(*) FROM collection_documents WHERE collection = 'room_threads'"
            ).fetchone()

        return {
            "retention_days": retention_days,
            "bot_messages_count": int(bot_row[0]) if bot_row else 0,
            "room_messages_count": int(room_row[0]) if room_row else 0,
            "updated_at": updated_at,
        }

    def update_chat_retention_settings(self, retention_days: int) -> dict[str, Any]:
        """Persist workspace chat history retention days (0 = keep forever, 1..3650)."""
        clamped = max(0, min(3650, int(retention_days)))
        self.upsert_document(
            collection="chat_settings",
            external_key="retention_config",
            search_text="",
            doc={"retention_days": clamped, "updated_at": utc_now()},
            description="Workspace chat transcript retention configuration",
        )
        return self.get_chat_retention_settings()

    def prune_expired_chat_messages(self, retention_days: int | None = None) -> dict[str, int]:
        """Delete bot and room transcript rows older than retention_days when > 0."""
        days = (
            self.get_chat_retention_settings()["retention_days"]
            if retention_days is None
            else max(0, min(3650, int(retention_days)))
        )
        if days <= 0:
            return {
                "retention_days": 0,
                "pruned_bot_messages": 0,
                "pruned_room_messages": 0,
                "pruned_total": 0,
            }

        cutoff_iso = (
            (datetime.now(UTC) - timedelta(days=days))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        with self._lock:
            cur_bot = self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'bot_threads' AND created_at < ?",
                (cutoff_iso,),
            )
            cur_room = self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'room_threads' AND created_at < ?",
                (cutoff_iso,),
            )
            pruned_bot = int(cur_bot.rowcount or 0)
            pruned_room = int(cur_room.rowcount or 0)
            self._conn.commit()

        return {
            "retention_days": days,
            "pruned_bot_messages": pruned_bot,
            "pruned_room_messages": pruned_room,
            "pruned_total": pruned_bot + pruned_room,
        }

    def upsert_ssh_audit_turn(self, record: dict[str, Any]) -> dict[str, Any]:
        """Persist or update a sanitized SSH turn audit document in 'ssh_audit_log'."""
        session_id = str(record.get("session_id") or "").strip()
        turn_seq = int(record.get("turn_seq") or 0)
        ext_key = f"{session_id}:{turn_seq}"
        host = str(record.get("host") or "")
        bot_slug = str(record.get("bot_slug") or "")
        command = str(record.get("command") or "")
        screen_excerpt = str(record.get("screen_excerpt") or "")
        search_text = f"{host} {bot_slug} {command} {screen_excerpt[:500]}"[:1000]
        return self.upsert_document(
            collection="ssh_audit_log",
            external_key=ext_key,
            search_text=search_text,
            doc=record,
            description="Tamper-evident SSH terminal turn audit log",
        )

    def set_ssh_session_pinned(self, session_id: str, pinned: bool) -> int:
        """Update pinned retention hold across all ssh_audit_log rows for session_id."""
        now = utc_now()
        updated = 0
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, doc_json
                FROM collection_documents
                WHERE collection = 'ssh_audit_log' AND external_key LIKE ?
                """,
                (f"{session_id}:%",),
            ).fetchall()
            for row in rows:
                try:
                    doc = json.loads(row["doc_json"])
                except json.JSONDecodeError:
                    continue
                if not isinstance(doc, dict):
                    continue
                doc["pinned"] = bool(pinned)
                self._conn.execute(
                    "UPDATE collection_documents SET doc_json = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(doc), now, row["id"]),
                )
                updated += 1
            if updated:
                self._conn.commit()
        return updated

    def list_recent_ssh_sessions_from_log(
        self,
        *,
        bot_slug: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Aggregate distinct retained SSH sessions from 'ssh_audit_log' newest first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT doc_json, created_at, updated_at
                FROM collection_documents
                WHERE collection = 'ssh_audit_log'
                ORDER BY updated_at DESC, rowid DESC
                LIMIT 500
                """
            ).fetchall()
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                doc = json.loads(row["doc_json"])
            except json.JSONDecodeError:
                continue
            if not isinstance(doc, dict):
                continue
            sid = str(doc.get("session_id") or "").strip()
            if not sid:
                continue
            b_slug = str(doc.get("bot_slug") or "")
            if bot_slug and b_slug != bot_slug:
                continue
            existing = grouped.get(sid)
            turn_seq = int(doc.get("turn_seq") or 0)
            if existing is None:
                grouped[sid] = {
                    "session_id": sid,
                    "bot_slug": b_slug,
                    "vault_slug": str(doc.get("vault_slug") or ""),
                    "host": str(doc.get("host") or ""),
                    "port": int(doc.get("port") or 22),
                    "correlation_id": str(doc.get("correlation_id") or ""),
                    "status": "closed",
                    "operator_takeover": False,
                    "paused": False,
                    "pinned": bool(doc.get("pinned")),
                    "last_command": str(doc.get("command") or ""),
                    "screen_text": str(doc.get("screen_excerpt") or ""),
                    "cast_relpath": str(doc.get("cast_relpath") or ""),
                    "cast_sha256": str(doc.get("cast_sha256") or ""),
                    "created_at": str(doc.get("created_at") or row["created_at"]),
                    "expires_at": str(doc.get("expires_at") or ""),
                    "_max_turn": turn_seq,
                    "_updated_at": str(row["updated_at"]),
                }
            else:
                existing["pinned"] = existing["pinned"] or bool(doc.get("pinned"))
                if str(doc.get("created_at") or "") < existing["created_at"]:
                    existing["created_at"] = str(doc.get("created_at") or existing["created_at"])
                if turn_seq >= existing["_max_turn"]:
                    existing["_max_turn"] = turn_seq
                    existing["last_command"] = str(doc.get("command") or existing["last_command"])
                    existing["screen_text"] = str(doc.get("screen_excerpt") or existing["screen_text"])
                    if doc.get("cast_sha256"):
                        existing["cast_sha256"] = str(doc["cast_sha256"])
                    if doc.get("expires_at"):
                        existing["expires_at"] = str(doc["expires_at"])
        out = sorted(grouped.values(), key=lambda x: x["_updated_at"], reverse=True)[:limit]
        for item in out:
            item.pop("_max_turn", None)
            item.pop("_updated_at", None)
        return out

    def purge_expired_ssh_audit_logs(self, now_iso: str) -> list[str]:
        """Delete expired unpinned rows from ssh_audit_log and return affected cast_relpaths."""
        purged_casts: list[str] = []
        ids_to_delete: list[str] = []
        pinned_casts: set[str] = set()
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, doc_json FROM collection_documents WHERE collection = 'ssh_audit_log'"
            ).fetchall()
            for row in rows:
                try:
                    doc = json.loads(row["doc_json"])
                except json.JSONDecodeError:
                    continue
                if not isinstance(doc, dict):
                    continue
                cast_rel = str(doc.get("cast_relpath") or "").strip()
                if doc.get("pinned"):
                    if cast_rel:
                        pinned_casts.add(cast_rel)
                    continue
                expires_at = str(doc.get("expires_at") or "").strip()
                if expires_at and expires_at <= now_iso:
                    ids_to_delete.append(str(row["id"]))
                    if cast_rel and cast_rel not in purged_casts:
                        purged_casts.append(cast_rel)
            if ids_to_delete:
                placeholders = ", ".join("?" for _ in ids_to_delete)
                self._conn.execute(
                    f"DELETE FROM collection_documents WHERE id IN ({placeholders})",
                    tuple(ids_to_delete),
                )
                self._conn.commit()
        return [p for p in purged_casts if p not in pinned_casts]

    def delete_vault_secret(self, slug: str) -> bool:
        """Delete a Vault secret entry by slug."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            raise NotFoundError(f"Vault secret '{clean_slug}' not found.")
        self.delete_document("vault_secrets", saved["id"])
        return True

    _NON_SECRET_VAULT_KEYS = frozenset(
        {"username", "user", "login", "email", "account", "host", "hostname", "domain", "url", "port"}
    )
    _NON_SECRET_OAUTH_KEYS = frozenset(
        {
            "email",
            "account_identifier",
            "client_id",
            "operator_chat_id",
            "bot_username",
            "admin_channels",
            "public_channels",
            "scopes",
            "token_expiry",
            "redirect_uri",
            "provider",
            "label",
            "person_urn",
            "org_urn",
            "url",
            "target_url",
            "webhook_url",
            "outbound_url",
            "channel",
            "channels",
            "handle",
            "name",
            "auth_mode",
            "token_type",
        }
    )

    def _invalidate_sensitive_secrets_cache(self) -> None:
        with self._lock:
            self._vault_secrets_cache = None
            self._sensitive_secrets_cache = None

    def collect_all_vault_secret_values(self) -> list[str]:
        """Collect all decrypted non-empty Vault secret strings for trace/log scrubbing."""
        with self._lock:
            if self._vault_secrets_cache is not None:
                return list(self._vault_secrets_cache)
            values: list[str] = []
            for meta in self.list_vault_secrets():
                dec = self.get_vault_secret_decrypted(meta["slug"])
                if not dec:
                    continue
                for key, val in (dec.get("secrets") or {}).items():
                    if str(key or "").strip().lower() in self._NON_SECRET_VAULT_KEYS:
                        continue
                    s = str(val).strip()
                    if len(s) >= 4:
                        values.append(s)
            deduped = tuple(dict.fromkeys(values))
            self._vault_secrets_cache = deduped
            return list(deduped)

    def collect_all_sensitive_secrets(self) -> list[str]:
        """Collect all decrypted Vault, LLM provider, and integration secret strings (cached)."""
        with self._lock:
            if self._sensitive_secrets_cache is not None:
                return list(self._sensitive_secrets_cache)
            values: list[str] = list(self.collect_all_vault_secret_values())
            for mdl in self.list_model_provider_credentials():
                api_key = str(mdl.get("api_key") or "").strip()
                if len(api_key) >= 6:
                    values.append(api_key)
            rows = self._conn.execute(
                "SELECT encrypted_secrets FROM oauth_accounts"
            ).fetchall()
            for row in rows:
                blob = row["encrypted_secrets"]
                if not blob:
                    continue
                try:
                    sec_map = self._vault.decrypt_json(blob)
                except Exception:
                    continue
                if not isinstance(sec_map, dict):
                    continue
                for key, val in sec_map.items():
                    if str(key or "").strip().lower() in self._NON_SECRET_OAUTH_KEYS:
                        continue
                    if isinstance(val, str):
                        s = val.strip()
                        if len(s) >= 6:
                            values.append(s)
            deduped = tuple(sorted(set(values), key=len, reverse=True))
            self._sensitive_secrets_cache = deduped
            return list(deduped)

    def document_exists(self, collection: str, external_key: str) -> bool:
        """Return True if a document with external_key already exists in collection."""
        clean_coll = collection_slug(collection)
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM collection_documents WHERE collection = ? AND external_key = ?",
                (clean_coll, external_key),
            ).fetchone()
        return row is not None

    def get_document_by_external_key(
        self,
        collection: str,
        external_key: str,
    ) -> dict[str, Any] | None:
        """Fetch a single document by (collection, external_key) or None if absent."""
        clean_coll = collection_slug(collection)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at
                FROM collection_documents
                WHERE collection = ? AND external_key = ?
                """,
                (clean_coll, external_key),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "collection": row["collection"],
            "external_key": row["external_key"],
            "search_text": row["search_text"],
            "doc": json.loads(row["doc_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_document(
        self,
        *,
        collection: str,
        external_key: str | None,
        search_text: str,
        doc: dict[str, Any],
        description: str = "Schema-less document collection",
        doc_id: str | None = None,
    ) -> dict[str, Any]:
        """Insert or deduplicate a JSON document inside a collection with FTS5 indexing."""
        clean_coll = collection_slug(collection)
        now = utc_now()
        new_id = doc_id or make_id("doc")
        doc_json = json.dumps(doc)

        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO collections(slug, description, schema_hint_json, created_at)
                VALUES (?, ?, NULL, ?)
                """,
                (clean_coll, description, now),
            )

            if external_key is not None:
                self._conn.execute(
                    """
                    INSERT INTO collection_documents(
                        id, collection, external_key, search_text, doc_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(collection, external_key) DO UPDATE SET
                        search_text = excluded.search_text,
                        doc_json = excluded.doc_json,
                        updated_at = excluded.updated_at
                    """,
                    (new_id, clean_coll, external_key, search_text, doc_json, now, now),
                )
                row = self._conn.execute(
                    """
                    SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at
                    FROM collection_documents
                    WHERE collection = ? AND external_key = ?
                    """,
                    (clean_coll, external_key),
                ).fetchone()
            else:
                self._conn.execute(
                    """
                    INSERT INTO collection_documents(
                        id, collection, external_key, search_text, doc_json, created_at, updated_at
                    ) VALUES (?, ?, NULL, ?, ?, ?, ?)
                    """,
                    (new_id, clean_coll, search_text, doc_json, now, now),
                )
                row = self._conn.execute(
                    """
                    SELECT id, collection, external_key, search_text, doc_json, created_at, updated_at
                    FROM collection_documents WHERE id = ?
                    """,
                    (new_id,),
                ).fetchone()
            self._conn.commit()
            if clean_coll == "vault_secrets":
                self._vault_secrets_cache = None
                self._sensitive_secrets_cache = None

        return {
            "id": row["id"],
            "collection": row["collection"],
            "external_key": row["external_key"],
            "search_text": row["search_text"],
            "doc": json.loads(row["doc_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def search_documents(
        self,
        collection: str,
        query: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query documents inside a collection using FTS5 full-text search when query is set."""
        clean_coll = collection_slug(collection)
        capped_limit = max(1, min(limit, 200))
        with self._lock:
            if query and query.strip():
                fts_expr = _fts_query(query)
                rows = self._conn.execute(
                    """
                    SELECT d.id, d.collection, d.external_key, d.search_text,
                           d.doc_json, d.created_at, d.updated_at
                    FROM collection_documents d
                    JOIN collection_documents_fts f ON d.rowid = f.rowid
                    WHERE d.collection = ? AND collection_documents_fts MATCH ?
                    ORDER BY d.updated_at DESC
                    LIMIT ?
                    """,
                    (clean_coll, fts_expr, capped_limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, collection, external_key, search_text,
                           doc_json, created_at, updated_at
                    FROM collection_documents
                    WHERE collection = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (clean_coll, capped_limit),
                ).fetchall()

        return [
            {
                "id": row["id"],
                "collection": row["collection"],
                "external_key": row["external_key"],
                "search_text": row["search_text"],
                "doc": json.loads(row["doc_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete_document(self, collection: str, doc_id: str) -> None:
        """Delete a single document from a collection."""
        clean_coll = collection_slug(collection)
        with self._lock:
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = ? AND id = ?",
                (clean_coll, doc_id),
            )
            self._conn.commit()
            if clean_coll == "vault_secrets":
                self._vault_secrets_cache = None
                self._sensitive_secrets_cache = None

    def delete_collection(self, collection: str) -> int:
        """Delete all documents in a collection, remove analytics Parquet files, and return deleted count."""
        clean_coll = collection_slug(collection)
        with self._tx():
            cursor = self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = ?",
                (clean_coll,),
            )
            self._conn.execute("DELETE FROM collections WHERE slug = ?", (clean_coll,))
            deleted_count = int(cursor.rowcount or 0)
        analytics_target = (self._analytics_root / clean_coll).resolve()
        if analytics_target != self._analytics_root and analytics_target.is_relative_to(self._analytics_root):
            shutil.rmtree(analytics_target, ignore_errors=True)
        return deleted_count

    # ------------------------------------------------------------------
    # Workspace Summary & Desktops View
    # ------------------------------------------------------------------
    def list_desktops(self) -> list[dict[str, Any]]:
        """Return isolated per-bot desktop records derived from declarative bots."""
        desktops: list[dict[str, Any]] = []
        for bot in self.list_bots():
            if bot["runtime"] == "desktop":
                desktops.append(
                    {
                        "bot_slug": bot["slug"],
                        "bot_name": bot["name"],
                        "role": bot["role"],
                        "container_name": f"argo-desktop-{bot['slug']}",
                        "desktop_state": bot["desktop_state"],
                        "ram_mb": bot["ram_mb"],
                        "ram_limit_mb": bot["ram_limit_mb"],
                        "cdp_port": 9222,
                        "selkies_port": 3000,
                    }
                )
        return desktops

    def stop_running_desktops(self) -> list[str]:
        """Mark all active desktop bots as hibernated while preserving profile volumes."""
        stopped: list[str] = []
        with self._lock:
            for bot in self.list_bots():
                if bot["runtime"] == "desktop" and bot["desktop_state"] == "running":
                    self.update_bot(bot["slug"], {"desktop_state": "hibernated"})
                    stopped.append(bot["slug"])
        return stopped

    def list_sandboxes(self) -> list[dict[str, Any]]:
        """Return isolated per-bot lightweight headless sandbox records."""
        sandboxes: list[dict[str, Any]] = []
        for bot in self.list_bots():
            if bot["runtime"] == "sandbox":
                sandboxes.append(
                    {
                        "bot_slug": bot["slug"],
                        "bot_name": bot["name"],
                        "role": bot["role"],
                        "container_name": f"argo-sandbox-{bot['slug']}",
                        "sandbox_state": bot.get("sandbox_state", "hibernated"),
                        "ram_mb": bot.get("ram_mb", 0),
                        "ram_limit_mb": bot.get("ram_limit_mb", 512),
                    }
                )
        return sandboxes

    def set_sandbox_state(self, slug: str, state: str, *, ram_mb: int = 0) -> dict[str, Any]:
        """Persist sandbox running/hibernated state for a sandbox-runtime bot."""
        return self.update_bot(slug, {"sandbox_state": state, "ram_mb": ram_mb})

    def stop_running_sandboxes(self) -> list[str]:
        """Mark all active script sandboxes as hibernated while preserving /workspace volumes."""
        stopped: list[str] = []
        with self._lock:
            for bot in self.list_bots():
                if bot["runtime"] == "sandbox" and bot.get("sandbox_state") == "running":
                    self.set_sandbox_state(bot["slug"], "hibernated", ram_mb=0)
                    stopped.append(bot["slug"])
        return stopped

    def workspace_counts(
        self,
        *,
        allowed_bot_slugs: set[str] | None = None,
        allowed_page_slugs: set[str] | None = None,
        allowed_integration_slugs: set[str] | None = None,
        manageable_bot_slugs: set[str] | None = None,
    ) -> dict[str, int]:
        """Compute live sidebar badge and footer summary counts."""
        bots = self.list_bots()
        if allowed_bot_slugs is not None:
            bots = [b for b in bots if b["slug"] in allowed_bot_slugs]
        desktops = [b for b in bots if b["runtime"] == "desktop"]
        desktops_running = sum(1 for b in desktops if b["desktop_state"] == "running")
        sandboxes = [b for b in bots if b["runtime"] == "sandbox"]
        sandboxes_running = sum(1 for b in sandboxes if b.get("sandbox_state") == "running")

        with self._lock:
            if manageable_bot_slugs is not None:
                if not manageable_bot_slugs:
                    pending_approvals = 0
                else:
                    ph = ",".join("?" for _ in manageable_bot_slugs)
                    pending_approvals = self._conn.execute(
                        f"SELECT COUNT(*) FROM approvals_outbox WHERE status = 'pending' AND bot_slug IN ({ph})",
                        tuple(sorted(manageable_bot_slugs)),
                    ).fetchone()[0]
            else:
                pending_approvals = self._conn.execute(
                    "SELECT COUNT(*) FROM approvals_outbox WHERE status = 'pending'"
                ).fetchone()[0]

            if allowed_page_slugs is not None:
                pages_count = len(allowed_page_slugs)
            else:
                pages_count = self._conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]

            if allowed_integration_slugs is not None:
                integrations_count = len(allowed_integration_slugs)
            else:
                integrations_count = self._conn.execute(
                    "SELECT COUNT(*) FROM oauth_accounts"
                ).fetchone()[0]

            models_count = self._conn.execute("SELECT COUNT(*) FROM model_providers").fetchone()[0]

        return {
            "pending_approvals": int(pending_approvals),
            "bots": len(bots),
            "pages": int(pages_count),
            "active_integrations": int(integrations_count),
            "models": int(models_count),
            "desktops_running": desktops_running,
            "desktops_total": len(desktops),
            "sandboxes_running": sandboxes_running,
            "sandboxes_total": len(sandboxes),
        }

    def build_platform_status_snapshot(
        self,
        *,
        host_telemetry: dict[str, Any] | None = None,
        scheduled_jobs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Build a secret-free platform status snapshot for operator queries and bots."""
        models_summary = self.list_models()
        return {
            "generated_at": utc_now(),
            "counts": self.workspace_counts(),
            "host": host_telemetry,
            "bots": [
                {
                    "slug": bot["slug"],
                    "name": bot["name"],
                    "role": bot["role"],
                    "enabled": bot["enabled"],
                    "runtime": bot["runtime"],
                    "desktop_state": bot["desktop_state"],
                    "sandbox_state": bot.get("sandbox_state", "none"),
                    "outbound_rbac": bot["outbound_rbac"],
                    "daily_cap": bot["daily_cap"],
                    "model": bot["model"],
                    "routines": [
                        {
                            "id": r.get("id"),
                            "label": r.get("label"),
                            "type": r.get("type"),
                            "schedule": r.get("schedule"),
                            "enabled": r.get("enabled", True),
                        }
                        for r in bot.get("routines", [])
                        if isinstance(r, dict)
                    ],
                }
                for bot in self.list_bots()
            ],
            "scheduled_jobs": scheduled_jobs or [],
            "recent_runs": self.list_bot_runs(limit=10),
            "pending_approvals": [
                {
                    "id": item["id"],
                    "bot_slug": item["bot_slug"],
                    "action_type": item["action_type"],
                    "target_account_slug": item["target_account_slug"],
                    "escalation_note": item.get("escalation_note"),
                    "created_at": item["created_at"],
                    "text_preview": str(
                        (item.get("edited_payload") or item.get("payload") or {}).get("text") or ""
                    )[:160],
                }
                for item in self.list_approvals(tab="pending")[:10]
            ],
            "integrations": [
                {
                    "slug": acc["slug"],
                    "display_name": acc["display_name"],
                    "provider": acc["provider"],
                    "status": acc["status"],
                    "account_identifier": acc.get("account_identifier"),
                    "last_checked_at": acc.get("last_checked_at"),
                    "last_error": acc.get("last_error"),
                }
                for acc in self.list_integrations()
            ],
            "models": {
                "today_tokens": models_summary["today_tokens"],
                "today_cost_usd": models_summary["today_cost_usd"],
                "month_cost_usd": models_summary["month_cost_usd"],
                "providers": [
                    {
                        "slug": p["slug"],
                        "model_id": p["model_id"],
                        "provider_type": p["provider_type"],
                        "configured": bool(
                            p.get("has_api_key")
                            or (p["provider_type"] == "ollama" and p.get("api_base"))
                        ),
                        "is_default": p["is_default"],
                        "daily_token_limit": p.get("daily_token_limit"),
                        "monthly_budget_usd": p.get("monthly_budget_usd"),
                    }
                    for p in models_summary["providers"]
                ],
            },
            "recent_events": [
                {
                    "event_type": ev["event_type"],
                    "source_slug": ev["source_slug"],
                    "target_slug": ev["target_slug"],
                    "title": ev["payload"].get("title"),
                    "summary": ev["payload"].get("summary"),
                    "created_at": ev["created_at"],
                }
                for ev in self.list_events(limit=8)
            ],
        }

    def build_live_workspace_status(
        self,
        *,
        desktop_states: dict[str, dict[str, Any]] | None = None,
        active_runs: dict[str, dict[str, Any]] | None = None,
        user_email: str | None = None,
        allowed_bot_slugs: set[str] | None = None,
        allowed_room_slugs: set[str] | None = None,
        allowed_page_slugs: set[str] | None = None,
        allowed_integration_slugs: set[str] | None = None,
        manageable_bot_slugs: set[str] | None = None,
    ) -> dict[str, Any]:
        """Return lightweight secret-free live status for bots, rooms, unread cursors & approvals."""
        bots = self.list_bots()
        if allowed_bot_slugs is not None:
            bots = [b for b in bots if b["slug"] in allowed_bot_slugs]
        bot_name_by_slug = {b["slug"]: b["name"] for b in bots}
        rooms = self.list_rooms()
        if allowed_room_slugs is not None:
            rooms = [r for r in rooms if r["slug"] in allowed_room_slugs]
        pending = self.list_approvals(tab="pending")
        if manageable_bot_slugs is not None:
            pending = [p for p in pending if p.get("bot_slug") in manageable_bot_slugs]
        recent_runs = self.list_bot_runs(
            allowed_bot_slugs=allowed_bot_slugs,
            limit=80,
        )
        recent_events = self.list_events(limit=60)
        cursors = self._list_read_cursors_for_user(user_email)
        desktop_map = desktop_states or {}
        running_map = active_runs or {}

        pending_by_bot: dict[str, int] = {}
        for item in pending:
            b = item["bot_slug"]
            pending_by_bot[b] = pending_by_bot.get(b, 0) + 1

        last_run_by_bot: dict[str, dict[str, Any]] = {}
        for run in recent_runs:
            if run["bot_slug"] not in last_run_by_bot:
                last_run_by_bot[run["bot_slug"]] = run

        last_delegation_by_bot: dict[str, dict[str, Any]] = {}
        for ev in recent_events:
            src = str(ev.get("source_slug") or "")
            tgt = str(ev.get("target_slug") or "")
            if ev.get("event_type") == "operator.instruction" and src in bot_name_by_slug and tgt in bot_name_by_slug:
                if src not in last_delegation_by_bot:
                    last_delegation_by_bot[src] = ev

        last_msg_by_bot: dict[str, dict[str, Any]] = {}
        with self._lock:
            msg_rows = self._conn.execute(
                """
                SELECT id, doc_json, created_at
                FROM collection_documents
                WHERE collection = 'bot_threads'
                ORDER BY created_at DESC, rowid DESC
                LIMIT 400
                """
            ).fetchall()
            room_msg_rows = self._conn.execute(
                """
                SELECT id, doc_json, created_at
                FROM collection_documents
                WHERE collection = 'room_threads'
                ORDER BY created_at DESC, rowid DESC
                LIMIT 300
                """
            ).fetchall()

        for row in msg_rows:
            doc = json.loads(row["doc_json"])
            bslug = str(doc.get("bot_slug") or "")
            if bslug and bslug not in last_msg_by_bot:
                last_msg_by_bot[bslug] = {
                    "sender": str(doc.get("sender") or "bot"),
                    "text": str(doc.get("text") or ""),
                    "metadata": doc.get("metadata") or {},
                    "created_at": row["created_at"],
                }

        last_msg_by_room: dict[str, dict[str, Any]] = {}
        for row in room_msg_rows:
            doc = json.loads(row["doc_json"])
            rslug = str(doc.get("room_slug") or "")
            if rslug and rslug not in last_msg_by_room:
                last_msg_by_room[rslug] = {
                    "sender": str(doc.get("sender_type") or doc.get("sender") or "bot"),
                    "sender_name": str(doc.get("sender_name") or "Bot"),
                    "text": str(doc.get("text") or ""),
                    "metadata": doc.get("metadata") or {},
                    "created_at": row["created_at"],
                }

        stations: list[dict[str, Any]] = []
        for bot in bots:
            slug = bot["slug"]
            p_count = pending_by_bot.get(slug, 0)
            last_run = last_run_by_bot.get(slug)
            desk_meta = desktop_map.get(slug) or {}
            active_run = running_map.get(slug)
            if not bot["enabled"]:
                state = "paused"
            elif active_run is not None:
                state = "running"
            elif desk_meta.get("awaiting_takeover"):
                state = "takeover_needed"
            elif p_count > 0:
                state = "waiting_approval"
            else:
                state = "idle"
            routines = [r for r in (bot.get("routines") or []) if isinstance(r, dict)]
            active_routine = next((r for r in routines if r.get("enabled", True)), routines[0] if routines else None)
            last_msg = last_msg_by_bot.get(slug)
            last_del = last_delegation_by_bot.get(slug)
            last_activity_at = (
                (last_msg["created_at"] if last_msg else None)
                or (last_run.get("finished_at") if last_run else None)
            )
            if last_run and last_run.get("finished_at") and last_activity_at and str(last_run["finished_at"]) > str(last_activity_at):
                last_activity_at = str(last_run["finished_at"])

            last_read_at = cursors.get(("bot", slug))
            is_unread = False
            if last_msg and last_msg.get("sender") == "bot":
                msg_meta = last_msg.get("metadata") or {}
                is_initial_welcome = bool(
                    not last_run
                    and not msg_meta.get("correlation_id")
                    and (msg_meta.get("onboarding_interview") or last_msg.get("text", "").startswith("Ready! Action mode"))
                )
                if not is_initial_welcome:
                    if last_read_at is None:
                        is_unread = True
                    elif str(last_msg["created_at"]) > last_read_at:
                        is_unread = True

            raw_run_summary = (
                str(last_run.get("summary") or "").strip().splitlines()[0]
                if last_run and str(last_run.get("summary") or "").strip()
                else ""
            )
            is_telemetry_summary = raw_run_summary.startswith(
                ("Completed on ", "Fallback succeeded on ", "Cancelled on ")
            )
            clean_run_summary = "" if is_telemetry_summary else raw_run_summary[:100]
            raw_msg_line = (
                str(last_msg.get("text") or "").strip().splitlines()[0]
                if last_msg and str(last_msg.get("text") or "").strip()
                else ""
            )
            clean_msg_line = (
                ""
                if not raw_msg_line or raw_msg_line.startswith("Ready! Action mode")
                else raw_msg_line[:100]
            )

            subtitle = ""
            if state == "running":
                subtitle = str(active_run.get("step") or "Working...") if active_run else "Working..."
            elif state == "takeover_needed":
                subtitle = "Sign-in needed"
            elif state == "waiting_approval":
                subtitle = f"{p_count} waiting for approval"
            elif state == "paused":
                subtitle = "Paused"
            elif last_del and (not last_msg or str(last_del["created_at"]) >= str(last_msg["created_at"])):
                tgt_name = bot_name_by_slug.get(str(last_del.get("target_slug") or ""), str(last_del.get("target_slug") or ""))
                subtitle = f"Messaged {tgt_name}"
            elif clean_msg_line:
                subtitle = clean_msg_line
            elif clean_run_summary:
                subtitle = clean_run_summary
            else:
                subtitle = active_routine.get("schedule", "Manual") if active_routine else "Manual"

            stations.append(
                {
                    "slug": slug,
                    "name": bot["name"],
                    "initials": bot["initials"],
                    "avatar_color": bot.get("avatar_color", "slate"),
                    "avatar_icon": bot.get("avatar_icon", "bot"),
                    "pinned": bool(bot.get("pinned", False)),
                    "section": bot.get("section", ""),
                    "goal_metric": bot.get("goal_metric", ""),
                    "owner_email": bot.get("owner_email", ""),
                    "visibility": bot.get("visibility", "shared"),
                    "allowed_groups": list(bot.get("allowed_groups") or []),
                    "role": bot["role"],
                    "enabled": bot["enabled"],
                    "runtime": bot["runtime"],
                    "desktop_state": bot["desktop_state"],
                    "sandbox_state": bot.get("sandbox_state", "none"),
                    "state": state,
                    "active_step": str(active_run.get("step") or "") if active_run else "",
                    "pending_approvals_count": p_count,
                    "schedule_label": active_routine.get("schedule", "Manual") if active_routine else "Manual",
                    "last_run_at": last_run.get("finished_at") if last_run else None,
                    "last_summary": (clean_run_summary or clean_msg_line)[:160],
                    "last_action_subtitle": subtitle[:120],
                    "last_activity_at": last_activity_at,
                    "unread": is_unread,
                }
            )

        room_stations: list[dict[str, Any]] = []
        for room in rooms:
            rslug = room["slug"]
            rmsg = last_msg_by_room.get(rslug)
            last_read_at = cursors.get(("room", rslug))
            room_unread = False
            if rmsg and rmsg.get("sender") == "bot" and not (rmsg.get("metadata") or {}).get("room_welcome"):
                if last_read_at is None or str(rmsg["created_at"]) > last_read_at:
                    room_unread = True
            preview = ""
            if rmsg and rmsg.get("text"):
                prefix = f"{rmsg['sender_name']}: " if rmsg.get("sender") == "bot" else "You: "
                raw_lines = [ln.strip() for ln in str(rmsg["text"]).splitlines() if ln.strip()]
                first_line = raw_lines[0] if raw_lines else str(rmsg["text"]).strip()
                cleaned_line = re.sub(r"^#{1,6}\s+", "", first_line)
                cleaned_line = re.sub(r"^(?:[-*•]+|\d+[.)])\s+", "", cleaned_line)
                cleaned_line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned_line)
                cleaned_line = re.sub(r"[*_`~]+", "", cleaned_line)
                cleaned_line = re.sub(r"\s+", " ", cleaned_line).strip()
                preview = f"{prefix}{cleaned_line}"[:120]
            room_stations.append(
                {
                    "slug": rslug,
                    "title": room["title"],
                    "member_bot_slugs": room["member_bot_slugs"],
                    "owner_email": room.get("owner_email", ""),
                    "visibility": room.get("visibility", "shared"),
                    "allowed_groups": list(room.get("allowed_groups") or []),
                    "last_sender_name": rmsg.get("sender_name") if rmsg else None,
                    "last_message_preview": preview,
                    "last_activity_at": rmsg["created_at"] if rmsg else room["updated_at"],
                    "unread": room_unread,
                }
            )

        return {
            "generated_at": utc_now(),
            "counts": self.workspace_counts(
                allowed_bot_slugs=allowed_bot_slugs,
                allowed_page_slugs=allowed_page_slugs,
                allowed_integration_slugs=allowed_integration_slugs,
                manageable_bot_slugs=manageable_bot_slugs,
            ),
            "bots": stations,
            "rooms": room_stations,
        }

    # ------------------------------------------------------------------
    # Users, Team Groups, Auth Sessions & Google Login OAuth States
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_auth_methods(raw: Any, *, default: list[str] | None = None) -> list[str]:
        valid = {"password", "google"}
        if raw is None:
            return list(default or ["password"])
        cleaned: list[str] = []
        for item in raw:
            val = str(item or "").strip().lower()
            if val in valid and val not in cleaned:
                cleaned.append(val)
        return cleaned

    @staticmethod
    def _sanitize_user(
        doc: dict[str, Any],
        *,
        groups_by_email: dict[str, list[dict[str, str]]] | None = None,
    ) -> dict[str, Any]:
        email = normalize_email(doc.get("email"))
        raw_role = str(doc.get("role") or "member").strip().lower()
        role = raw_role if raw_role in {"admin", "member"} else "member"
        groups = list((groups_by_email or {}).get(email, []))
        return {
            "email": email,
            "display_name": str(doc.get("display_name") or ""),
            "role": role,
            "active": bool(doc.get("active", True)),
            "auth_methods": [
                m
                for m in (doc.get("auth_methods") or [])
                if str(m).strip().lower() in {"password", "google"}
            ],
            "has_password": bool(doc.get("password_hash")),
            "must_change_password": bool(doc.get("must_change_password", False)),
            "max_active_desktops": doc.get("max_active_desktops"),
            "max_active_sandboxes": doc.get("max_active_sandboxes"),
            "token_version": int(doc.get("token_version") or 1),
            "groups": groups,
            "last_login_at": doc.get("last_login_at"),
            "created_by": str(doc.get("created_by") or ""),
            "created_at": doc.get("created_at") or "",
            "updated_at": doc.get("updated_at") or "",
        }

    def list_team_groups(self) -> list[dict[str, Any]]:
        """List all workspace Team Groups sorted by name."""
        rows = self.search_documents("argo_team_groups", limit=500)
        groups: list[dict[str, Any]] = []
        for item in rows:
            doc = item.get("doc") or {}
            slug = slugify(str(doc.get("slug") or item.get("external_key") or ""))
            if not slug:
                continue
            members = sorted(
                {
                    normalize_email(str(m))
                    for m in (doc.get("member_emails") or [])
                    if normalize_email(str(m))
                }
            )
            groups.append(
                {
                    "id": item["id"],
                    "slug": slug,
                    "name": str(doc.get("name") or slug),
                    "description": str(doc.get("description") or ""),
                    "member_emails": members,
                    "created_by": str(doc.get("created_by") or ""),
                    "created_at": item["created_at"],
                    "updated_at": item["updated_at"],
                }
            )
        groups.sort(key=lambda g: (g["name"].lower(), g["slug"]))
        return groups

    def get_team_group(self, slug: str) -> dict[str, Any] | None:
        """Fetch a single Team Group by slug, or None."""
        clean_slug = slugify(slug)
        if not clean_slug:
            return None
        for grp in self.list_team_groups():
            if grp["slug"] == clean_slug:
                return grp
        return None

    def upsert_team_group(
        self,
        *,
        name: str,
        slug: str | None = None,
        description: str | None = None,
        member_emails: list[str] | None = None,
        created_by: str = "",
    ) -> dict[str, Any]:
        """Create or update a workspace Team Group."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Team Group name is required.")
        clean_slug = slugify(slug or clean_name)
        existing = self.get_team_group(clean_slug)
        resolved_desc = (
            description.strip()
            if description is not None
            else (existing["description"] if existing else "")
        )
        if member_emails is not None:
            resolved_members = sorted(
                {
                    normalize_email(str(m))
                    for m in member_emails
                    if normalize_email(str(m))
                }
            )
        elif existing is not None:
            resolved_members = list(existing["member_emails"])
        else:
            resolved_members = []
        doc = {
            "slug": clean_slug,
            "name": clean_name,
            "description": resolved_desc,
            "member_emails": resolved_members,
            "created_by": (
                existing["created_by"]
                if existing and existing.get("created_by")
                else normalize_email(created_by)
            ),
        }
        self.upsert_document(
            collection="argo_team_groups",
            external_key=clean_slug,
            search_text="",
            doc=doc,
            description="Internal workspace Team Groups",
        )
        return self.get_team_group(clean_slug)  # type: ignore[return-value]

    def set_user_groups(self, email: str, group_slugs: list[str]) -> list[str]:
        """Set exact Team Group memberships for a user email."""
        clean_email = normalize_email(email)
        if not clean_email:
            return []
        desired = set(normalize_group_slugs(group_slugs))
        known = self.list_team_groups()
        known_slugs = {g["slug"] for g in known}
        unknown = sorted(desired - known_slugs)
        if unknown:
            raise ValueError(f"Unknown Team Group(s): {', '.join(unknown)}.")
        for grp in known:
            members = set(grp["member_emails"])
            should_be_in = grp["slug"] in desired
            currently_in = clean_email in members
            if should_be_in and not currently_in:
                members.add(clean_email)
                self.upsert_team_group(
                    name=grp["name"],
                    slug=grp["slug"],
                    description=grp["description"],
                    member_emails=sorted(members),
                    created_by=grp.get("created_by", ""),
                )
            elif not should_be_in and currently_in:
                members.discard(clean_email)
                self.upsert_team_group(
                    name=grp["name"],
                    slug=grp["slug"],
                    description=grp["description"],
                    member_emails=sorted(members),
                    created_by=grp.get("created_by", ""),
                )
        return sorted(desired)

    def delete_team_group(self, slug: str) -> None:
        """Delete a Team Group and safely remove it from all resource ACLs."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("argo_team_groups", clean_slug)
        if saved is None:
            raise NotFoundError(f"Team Group '{slug}' not found.")
        with self._lock:
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'argo_team_groups' AND external_key = ?",
                (clean_slug,),
            )
            self._conn.commit()

        # Scrub deleted group slug from resources; empty 'team' becomes 'private' (fail-closed)
        for bot in self.list_bots():
            groups = list(bot.get("allowed_groups") or [])
            if clean_slug in groups or (bot.get("visibility") == "team" and not groups):
                next_groups = [g for g in groups if g != clean_slug]
                next_vis = "private" if (bot.get("visibility") == "team" and not next_groups) else bot.get("visibility", "shared")
                self.update_bot(bot["slug"], {"visibility": next_vis, "allowed_groups": next_groups})

        for acc in self.list_integrations():
            groups = list(acc.get("allowed_groups") or [])
            if clean_slug in groups or (acc.get("visibility") == "team" and not groups):
                next_groups = [g for g in groups if g != clean_slug]
                next_vis = "private" if (acc.get("visibility") == "team" and not next_groups) else acc.get("visibility", "shared")
                self.upsert_integration(
                    slug=acc["slug"],
                    provider=acc["provider"],
                    display_name=acc["display_name"],
                    account_identifier=acc.get("account_identifier"),
                    scopes=list(acc.get("scopes") or []),
                    status=str(acc.get("status") or "ok"),
                    visibility=next_vis,
                    allowed_groups=next_groups,
                )

        for pg in self.list_pages():
            groups = list(pg.get("allowed_groups") or [])
            if clean_slug in groups or (pg.get("visibility") == "team" and not groups):
                next_groups = [g for g in groups if g != clean_slug]
                next_vis = "private" if (pg.get("visibility") == "team" and not next_groups) else pg.get("visibility", "shared")
                self.update_page(
                    pg["slug"],
                    {"visibility": next_vis, "allowed_groups": next_groups},
                    is_admin=True,
                )

        for rm in self.list_rooms():
            groups = list(rm.get("allowed_groups") or [])
            if clean_slug in groups or (rm.get("visibility") == "team" and not groups):
                next_groups = [g for g in groups if g != clean_slug]
                next_vis = "private" if (rm.get("visibility") == "team" and not next_groups) else rm.get("visibility", "shared")
                self.update_room(rm["slug"], {"visibility": next_vis, "allowed_groups": next_groups})

        for vs in self.list_vault_secrets():
            groups = list(vs.get("allowed_groups") or [])
            if clean_slug in groups or (vs.get("visibility") == "team" and not groups):
                next_groups = [g for g in groups if g != clean_slug]
                next_vis = "private" if (vs.get("visibility") == "team" and not next_groups) else vs.get("visibility", "shared")
                self.upsert_vault_secret(
                    name=vs["name"],
                    slug=vs["slug"],
                    secret_type=vs["secret_type"],
                    host=vs.get("host", ""),
                    port=vs.get("port", ""),
                    url=vs.get("url", ""),
                    visibility=next_vis,
                    allowed_groups=next_groups,
                )

    def _groups_by_email_map(self) -> dict[str, list[dict[str, str]]]:
        mapping: dict[str, list[dict[str, str]]] = {}
        for grp in self.list_team_groups():
            entry = {"slug": grp["slug"], "name": grp["name"]}
            for member in grp["member_emails"]:
                mapping.setdefault(member, []).append(entry)
        return mapping

    def get_user(self, email: str, *, include_secret: bool = False) -> dict[str, Any] | None:
        """Fetch an invited/bootstrap user account by email."""
        clean_email = normalize_email(email)
        if not clean_email:
            return None
        saved = self.get_document_by_external_key("argo_users", clean_email)
        if saved is None:
            return None
        doc = dict(saved.get("doc") or {})
        doc.setdefault("email", clean_email)
        doc.setdefault("created_at", saved.get("created_at"))
        doc.setdefault("updated_at", saved.get("updated_at"))
        groups_map = self._groups_by_email_map()
        sanitized = self._sanitize_user(doc, groups_by_email=groups_map)
        if include_secret:
            sanitized["password_hash"] = str(doc.get("password_hash") or "")
        return sanitized

    def list_users(self) -> list[dict[str, Any]]:
        """List all invited and bootstrap users sorted by email."""
        rows = self.search_documents("argo_users", limit=500)
        groups_map = self._groups_by_email_map()
        users: list[dict[str, Any]] = []
        for item in rows:
            doc = dict(item.get("doc") or {})
            doc.setdefault("email", item.get("external_key"))
            doc.setdefault("created_at", item.get("created_at"))
            doc.setdefault("updated_at", item.get("updated_at"))
            sanitized = self._sanitize_user(doc, groups_by_email=groups_map)
            if sanitized["email"]:
                users.append(sanitized)
        users.sort(key=lambda u: u["email"])
        return users

    def upsert_user(
        self,
        *,
        email: str,
        display_name: str | None = None,
        role: str | None = None,
        active: bool | None = None,
        auth_methods: list[str] | None = None,
        password_hash: Any = _UNSET,
        must_change_password: bool | None = None,
        max_active_desktops: Any = _UNSET,
        max_active_sandboxes: Any = _UNSET,
        created_by: str | None = None,
        touch_login: bool = False,
        bump_token_version: bool = False,
    ) -> dict[str, Any]:
        """Create or update an internal workspace user account."""
        clean_email = normalize_email(email)
        if not clean_email or "@" not in clean_email:
            raise ValueError("Valid user email is required.")
        saved = self.get_document_by_external_key("argo_users", clean_email)
        existing = dict(saved.get("doc") or {}) if saved else {}

        next_name = (
            display_name.strip()
            if display_name is not None
            else str(existing.get("display_name") or "")
        )
        raw_role = str(role if role is not None else (existing.get("role") or "member")).strip().lower()
        next_role = raw_role if raw_role in {"admin", "member"} else "member"
        next_active = bool(active if active is not None else existing.get("active", True))
        next_methods = (
            self._normalize_auth_methods(auth_methods)
            if auth_methods is not None
            else self._normalize_auth_methods(existing.get("auth_methods"), default=["password"])
        )
        if password_hash is _UNSET or password_hash is None:
            next_pw_hash = str(existing.get("password_hash") or "")
        else:
            next_pw_hash = str(password_hash)

        next_must_change = (
            bool(must_change_password)
            if must_change_password is not None
            else bool(existing.get("must_change_password", False))
        )
        if max_active_desktops is _UNSET:
            next_desk = existing.get("max_active_desktops")
        elif max_active_desktops is None:
            next_desk = None
        else:
            next_desk = max(0, int(max_active_desktops))

        if max_active_sandboxes is _UNSET:
            next_sb = existing.get("max_active_sandboxes")
        elif max_active_sandboxes is None:
            next_sb = None
        else:
            next_sb = max(0, int(max_active_sandboxes))

        next_token_ver = int(existing.get("token_version") or 1) + (1 if bump_token_version else 0)
        next_login_at = utc_now() if touch_login else existing.get("last_login_at")
        resolved_creator = (
            str(existing.get("created_by") or "")
            or normalize_email(created_by)
        )

        doc = {
            "email": clean_email,
            "display_name": next_name,
            "role": next_role,
            "active": next_active,
            "auth_methods": next_methods,
            "password_hash": next_pw_hash,
            "must_change_password": next_must_change,
            "max_active_desktops": next_desk,
            "max_active_sandboxes": next_sb,
            "token_version": next_token_ver,
            "last_login_at": next_login_at,
            "created_by": resolved_creator,
        }
        self.upsert_document(
            collection="argo_users",
            external_key=clean_email,
            search_text="",
            doc=doc,
            description="Internal workspace invited users and auth credentials",
        )
        return self.get_user(clean_email)  # type: ignore[return-value]

    def delete_user(self, email: str) -> None:
        """Delete a user account, its sessions, and remove it from Team Groups."""
        clean_email = normalize_email(email)
        if not clean_email or self.get_user(clean_email) is None:
            raise NotFoundError(f"User '{email}' not found.")
        self.delete_user_sessions(clean_email)
        for grp in self.list_team_groups():
            if clean_email in grp["member_emails"]:
                remaining = [m for m in grp["member_emails"] if m != clean_email]
                self.upsert_team_group(
                    name=grp["name"],
                    slug=grp["slug"],
                    description=grp["description"],
                    member_emails=remaining,
                    created_by=grp.get("created_by", ""),
                )
        with self._lock:
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'argo_users' AND external_key = ?",
                (clean_email,),
            )
            self._conn.commit()

    def create_auth_session(
        self,
        *,
        token_sha256: str,
        email: str,
        auth_method: str,
        token_version: int,
        ttl_hours: int,
        user_agent: str = "",
    ) -> dict[str, Any]:
        """Persist an active authenticated session in SQLite."""
        clean_email = normalize_email(email)
        now = utc_now()
        expires_at = (
            (datetime.now(UTC) + timedelta(hours=max(1, int(ttl_hours))))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        doc = {
            "token_sha256": token_sha256,
            "email": clean_email,
            "auth_method": str(auth_method or "password"),
            "token_version": int(token_version),
            "user_agent": str(user_agent or "")[:200],
            "created_at": now,
            "expires_at": expires_at,
        }
        self.upsert_document(
            collection="argo_auth_sessions",
            external_key=token_sha256,
            search_text="",
            doc=doc,
            description="Internal active cookie authentication sessions",
        )
        return doc

    def get_auth_session(self, token_sha256: str) -> dict[str, Any] | None:
        """Fetch an active session by SHA-256 token hash, pruning expired sessions."""
        if not token_sha256:
            return None
        saved = self.get_document_by_external_key("argo_auth_sessions", token_sha256)
        if saved is None:
            return None
        doc = dict(saved.get("doc") or {})
        expires_at = str(doc.get("expires_at") or "")
        if not expires_at or expires_at <= utc_now():
            self.delete_auth_session(token_sha256)
            return None
        return doc

    def delete_auth_session(self, token_sha256: str) -> None:
        """Revoke a single authentication session."""
        if not token_sha256:
            return
        with self._lock:
            self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = 'argo_auth_sessions' AND external_key = ?",
                (token_sha256,),
            )
            self._conn.commit()

    def delete_user_sessions(self, email: str) -> int:
        """Revoke all active authentication sessions belonging to an email."""
        clean_email = normalize_email(email)
        if not clean_email:
            return 0
        with self._lock:
            cursor = self._conn.execute(
                """
                DELETE FROM collection_documents
                WHERE collection = 'argo_auth_sessions'
                  AND lower(json_extract(doc_json, '$.email')) = ?
                """,
                (clean_email,),
            )
            self._conn.commit()
            return int(cursor.rowcount or 0)

    def store_auth_oauth_state(self, state_hash: str, doc: dict[str, Any]) -> None:
        """Store short-lived PKCE + nonce verification state for native Google Sign-In."""
        self.upsert_document(
            collection="argo_auth_oauth_states",
            external_key=state_hash,
            search_text="",
            doc=doc,
            description="Ephemeral OAuth login states for native Google Sign-In",
        )

    def consume_auth_oauth_state(self, state_hash: str) -> dict[str, Any] | None:
        """Consume and return a Google Sign-In OAuth state entry once, rejecting expired entries."""
        if not state_hash:
            return None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT doc_json
                FROM collection_documents
                WHERE collection = 'argo_auth_oauth_states' AND external_key = ?
                """,
                (state_hash,),
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    """
                    DELETE FROM collection_documents
                    WHERE collection = 'argo_auth_oauth_states' AND external_key = ?
                    """,
                    (state_hash,),
                )
                self._conn.commit()
        if row is None:
            return None
        try:
            doc = json.loads(row["doc_json"])
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None
        expires_at = str(doc.get("expires_at") or "")
        if not expires_at or expires_at <= utc_now():
            return None
        return doc
