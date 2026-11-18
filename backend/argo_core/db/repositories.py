"""Thread-safe SQLite repository layer over Argo's 5 Core Primitives."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from argo_core.security.vault import SecretVault, redact_secrets


class AlreadyResolvedError(Exception):
    """Raised when an approval transition finds zero matching pending rows."""


class NotFoundError(Exception):
    """Raised when a requested record does not exist."""


class FileTooLargeError(Exception):
    """Raised when an uploaded workspace file exceeds the 10 MB limit."""


MAX_WORKSPACE_FILE_BYTES = 10 * 1024 * 1024
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
    }
)


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
        if workspace_files_root:
            self._workspace_files_root = Path(workspace_files_root)
        else:
            db_list = conn.execute("PRAGMA database_list").fetchall()
            db_file = str(db_list[0][2]) if db_list and len(db_list[0]) > 2 else ""
            if db_file and db_file != ":memory:":
                self._workspace_files_root = Path(db_file).resolve().parent / "workspace_files"
            else:
                self._workspace_files_root = Path("./data/workspace_files").resolve()

    def _ensure_collection_locked(
        self,
        slug: str,
        *,
        description: str = "Schema-less document collection",
        created_at: str | None = None,
    ) -> None:
        """Ensure a collection row exists without committing an outer transaction."""
        raw = str(slug or "").strip()
        if not raw:
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
        stats = usage or {}
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

    def list_models(self) -> dict[str, Any]:
        """List configured LLM providers (redacting encrypted keys) and usage totals."""
        today_prefix = utc_now()[:10]
        month_prefix = today_prefix[:7]
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd, created_at
                FROM model_providers
                ORDER BY is_default DESC, created_at ASC
                """
            ).fetchall()

            per_model_usage = self._usage_by_model_locked()
            usage_row = self._conn.execute(
                """
                SELECT COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS today_cost,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS month_tokens,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN estimated_cost_usd ELSE 0.0 END), 0.0) AS month_cost,
                       COALESCE(SUM(CASE WHEN started_at >= ? AND status = 'success' AND COALESCE(input_tokens, 0) = 0 AND COALESCE(output_tokens, 0) = 0 THEN 1 ELSE 0 END), 0) AS deduplicated_runs_today,
                       COALESCE(SUM(CASE WHEN started_at >= ? AND status = 'success' AND COALESCE(input_tokens, 0) = 0 AND COALESCE(output_tokens, 0) = 0 THEN 1 ELSE 0 END), 0) AS deduplicated_runs_month
                FROM bot_runs
                WHERE started_at >= ?
                """,
                (
                    today_prefix,
                    today_prefix,
                    month_prefix,
                    month_prefix,
                    today_prefix,
                    month_prefix,
                    month_prefix,
                ),
            ).fetchone()
            bot_usage_rows = self._conn.execute(
                """
                SELECT bot_slug,
                       COUNT(*) AS runs_count,
                       COALESCE(SUM(CASE WHEN started_at >= ? THEN input_tokens + output_tokens ELSE 0 END), 0) AS today_tokens,
                       COALESCE(SUM(input_tokens + output_tokens), 0) AS month_tokens,
                       COALESCE(SUM(estimated_cost_usd), 0.0) AS month_cost
                FROM bot_runs
                WHERE started_at >= ?
                GROUP BY bot_slug
                ORDER BY month_tokens DESC, runs_count DESC
                """,
                (today_prefix, month_prefix),
            ).fetchall()
            bot_trigger_rows = self._conn.execute(
                """
                SELECT bot_slug, trigger_type, COUNT(*) AS cnt
                FROM bot_runs
                WHERE started_at >= ?
                GROUP BY bot_slug, trigger_type
                ORDER BY cnt DESC
                """,
                (month_prefix,),
            ).fetchall()
            bot_meta_rows = self._conn.execute(
                "SELECT slug, name, enabled, card_json FROM bots"
            ).fetchall()

        top_trigger_by_bot: dict[str, str] = {}
        for trow in bot_trigger_rows:
            if trow["bot_slug"] not in top_trigger_by_bot:
                top_trigger_by_bot[trow["bot_slug"]] = str(trow["trigger_type"])

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
                "runs_count": int(row["runs_count"]),
                "today_tokens": int(row["today_tokens"]),
                "month_tokens": int(row["month_tokens"]),
                "month_cost_usd": round(float(row["month_cost"]), 6),
                "top_trigger_type": top_trigger_by_bot.get(row["bot_slug"], "manual"),
            }
            for row in bot_usage_rows
        ]

        providers = [
            self._serialize_model_row(row, per_model_usage.get(row["model_id"]))
            for row in rows
        ]
        recent_runs = self.list_bot_runs(limit=20)
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
        }

    def list_model_provider_credentials(self) -> list[dict[str, Any]]:
        """Internal-only helper returning model providers with decrypted API keys."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd, created_at
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
                    is_default, daily_token_limit, monthly_budget_usd, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    provider_type = excluded.provider_type,
                    model_id = excluded.model_id,
                    api_base = excluded.api_base,
                    encrypted_api_key = COALESCE(excluded.encrypted_api_key, model_providers.encrypted_api_key),
                    is_default = excluded.is_default,
                    daily_token_limit = excluded.daily_token_limit,
                    monthly_budget_usd = excluded.monthly_budget_usd
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
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute(
                """
                SELECT id, slug, provider_type, model_id, api_base, encrypted_api_key,
                       is_default, daily_token_limit, monthly_budget_usd, created_at
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
                       is_default, daily_token_limit, monthly_budget_usd, created_at
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
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        """Persist an execution audit record with token and cost accounting into bot_runs."""
        run_id = make_id("run")
        start_ts = started_at or utc_now()
        end_ts = finished_at or utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO bot_runs(
                    id, correlation_id, bot_slug, trigger_type, hop_count,
                    llm_model_used, input_tokens, output_tokens, estimated_cost_usd,
                    status, summary, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    start_ts,
                    end_ts,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM bot_runs WHERE id = ?", (run_id,)).fetchone()
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
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
        }

    def list_bot_runs(
        self,
        *,
        bot_slug: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List recent bot_runs execution and token accounting records newest first."""
        capped = max(1, min(limit, 200))
        with self._lock:
            if bot_slug:
                rows = self._conn.execute(
                    """
                    SELECT * FROM bot_runs
                    WHERE bot_slug = ?
                    ORDER BY started_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (bot_slug, capped),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM bot_runs
                    ORDER BY started_at DESC, rowid DESC
                    LIMIT ?
                    """,
                    (capped,),
                ).fetchall()
        return [
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
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Integrations (Primitive 1)
    # ------------------------------------------------------------------
    @staticmethod
    def _serialize_integration_row(row: sqlite3.Row) -> dict[str, Any]:
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
            "created_at": row["created_at"],
        }

    def list_integrations(self) -> list[dict[str, Any]]:
        """List connected accounts/channels without exposing encrypted secrets."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, created_at
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
                       last_error, created_at
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
                       last_error, created_at
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
    ) -> dict[str, Any]:
        """Create or update an integration account with Fernet-encrypted credentials."""
        now = utc_now()
        clean_slug = slugify(slug)
        scopes_json = json.dumps(scopes or [])

        with self._lock:
            existing = self._conn.execute(
                "SELECT encrypted_secrets FROM oauth_accounts WHERE slug = ?",
                (clean_slug,),
            ).fetchone()
            merged_secrets: dict[str, Any] = {}
            if existing and existing["encrypted_secrets"]:
                merged_secrets = self._vault.decrypt_json(existing["encrypted_secrets"])
            if secrets:
                merged_secrets.update(secrets)

            encrypted_blob = self._vault.encrypt_json(merged_secrets)
            self._conn.execute(
                """
                INSERT INTO oauth_accounts(
                    id, slug, provider, display_name, account_identifier,
                    scopes_json, encrypted_secrets, status, last_checked_at,
                    last_error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    provider = excluded.provider,
                    display_name = excluded.display_name,
                    account_identifier = excluded.account_identifier,
                    scopes_json = excluded.scopes_json,
                    encrypted_secrets = excluded.encrypted_secrets,
                    status = excluded.status,
                    last_checked_at = excluded.last_checked_at,
                    last_error = NULL
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
            row = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, created_at
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
            row = self._conn.execute(
                """
                SELECT id, slug, provider, display_name, account_identifier,
                       scopes_json, encrypted_secrets, status, last_checked_at,
                       last_error, created_at
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
            if cursor.rowcount == 0:
                raise NotFoundError(f"Integration '{slug}' not found.")

    # ------------------------------------------------------------------
    # Bots & Threads (Primitive 2 + Collection "bot_threads")
    # ------------------------------------------------------------------
    def _serialize_bot(self, row: sqlite3.Row) -> dict[str, Any]:
        card = json.loads(row["card_json"])
        runtime = "desktop" if card.get("desktop_policy", "disabled") != "disabled" else "api"
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
            "role": row["role"],
            "enabled": bool(row["enabled"]),
            "runtime": runtime,
            "desktop_policy": card.get("desktop_policy", "disabled"),
            "desktop_state": card.get("desktop_state", "none"),
            "ram_mb": int(card.get("ram_mb", 0)),
            "ram_limit_mb": int(card.get("ram_limit_mb", 2048)),
            "outbound_rbac": card.get("outbound_rbac", "draft"),
            "daily_cap": int(card.get("daily_cap", 10)),
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
                SELECT id, slug, name, role, enabled, card_json, created_at, updated_at
                FROM bots ORDER BY created_at ASC
                """
            ).fetchall()
        return [self._serialize_bot(row) for row in rows]

    def get_bot(self, slug: str) -> dict[str, Any]:
        """Fetch a single declarative bot by slug."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, slug, name, role, enabled, card_json, created_at, updated_at
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
                "schedule": str(
                    item.get("schedule")
                    or (
                        f"on:{item['event']}"
                        if r_type == "on_event" and item.get("event")
                        else "Manual"
                    )
                ),
                "timezone": str(item.get("timezone") or "UTC").strip() or "UTC",
                "enabled": bool(item.get("enabled", True)),
            }
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
            return {"read": ["bot_threads"], "write": ["bot_threads"]}
        read_list = [collection_slug(str(c)) for c in collections.get("read", []) if str(c).strip()]
        write_list = [collection_slug(str(c)) for c in collections.get("write", []) if str(c).strip()]
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
    ) -> dict[str, Any]:
        """Register a new declarative bot record in SQLite without code edits or rebuilds."""
        now = utc_now()
        base_slug = slugify(slug or name)
        desktop_policy = "on_demand" if runtime == "desktop" else "disabled"
        desktop_state = "hibernated" if runtime == "desktop" else "none"
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
                    "write": ["bot_threads", default_items_col],
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
                "role": role.strip(),
                "enabled": True,
                "model": model,
                "desktop_policy": desktop_policy,
                "desktop_state": desktop_state,
                "ram_mb": 0,
                "ram_limit_mb": 2048,
                "outbound_rbac": outbound_rbac,
                "daily_cap": effective_cap,
                "role_prompt": resolved_prompt,
                "routines": resolved_routines,
                "permissions": _default_permissions(outbound_rbac, runtime),
                "tools": resolved_tools,
                "collections": resolved_collections,
                "onboarding_pending": bool(is_interview),
            }
            if linked_accounts is not None:
                card["linked_accounts"] = list(
                    dict.fromkeys(slugify(str(a)) for a in linked_accounts if str(a).strip())
                )
                card["linked_accounts_restricted"] = True

            self._conn.execute(
                """
                INSERT INTO bots(id, slug, name, role, enabled, card_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    make_id("bot"),
                    candidate_slug,
                    name.strip(),
                    role.strip(),
                    1,
                    json.dumps(card),
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
                "SELECT id, slug, name, role, enabled, card_json, created_at, updated_at FROM bots WHERE slug = ?",
                (slug,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Bot '{slug}' not found.")

            card = json.loads(row["card_json"])
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
            if updates.get("runtime") in {"api", "desktop"}:
                new_rt = str(updates["runtime"])
                card["desktop_policy"] = "on_demand" if new_rt == "desktop" else "disabled"
                if new_rt == "desktop":
                    if card.get("desktop_state") in {None, "", "none"}:
                        card["desktop_state"] = "hibernated"
                    card["tools"] = _ensure_desktop_tools(list(card.get("tools", []) or []))
                else:
                    card["desktop_state"] = "none"
                    card["ram_mb"] = 0
                card["permissions"] = _default_permissions(
                    str(card.get("outbound_rbac") or "draft"),
                    new_rt,
                )
            if updates.get("outbound_rbac"):
                rbac = str(updates["outbound_rbac"])
                card["outbound_rbac"] = rbac
                runtime = "desktop" if card.get("desktop_policy", "disabled") != "disabled" else "api"
                card["permissions"] = _default_permissions(rbac, runtime)
                if rbac == "execute" and int(card.get("daily_cap", 0)) < 1:
                    card["daily_cap"] = 10
            if updates.get("daily_cap") is not None:
                card["daily_cap"] = max(0, int(updates["daily_cap"]))
            if updates.get("desktop_state"):
                card["desktop_state"] = str(updates["desktop_state"])
                card["ram_mb"] = 1380 if card["desktop_state"] == "running" else 0
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
                "UPDATE bots SET name = ?, role = ?, enabled = ?, card_json = ?, updated_at = ? WHERE slug = ?",
                (name_text, role_text, 1 if enabled else 0, json.dumps(card), now, slug),
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
        with self._lock:
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

            # Clean deleted bot out of any bot_rooms membership / stage order
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
                if not remaining_members:
                    self._conn.execute(
                        "DELETE FROM collection_documents WHERE collection = 'bot_rooms' AND id = ?",
                        (rrow["id"],),
                    )
                    if room_slug_val:
                        self._conn.execute(
                            "DELETE FROM collection_documents WHERE collection = 'room_threads' AND json_extract(doc_json, '$.room_slug') = ?",
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

            self._conn.commit()
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
        for tool in bot.get("tools", []):
            if isinstance(tool, dict) and tool.get("type") in {"account", "connector"}:
                acc_slug = slugify(str(tool.get("slug") or tool.get("account") or ""))
                acc = integrations_by_slug.get(acc_slug)
                if acc and acc["provider"] not in required_providers:
                    required_providers.append(acc["provider"])
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
                "name": s["name"],
                "description": s["description"],
                "instructions": s["instructions"],
            }
            for s in self.list_skills()
            if s["scope_slug"] == slug
        ]
        return {
            "schema_version": "argo.bot_blueprint.v1",
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
            "collections": bot.get("collections") or {"read": ["bot_threads"], "write": ["bot_threads"]},
            "required_providers": required_providers,
            "skills": scoped_skills,
        }

    def import_bot_blueprint(
        self,
        blueprint: dict[str, Any],
        *,
        linked_accounts: list[str] | None = None,
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

        runtime = "desktop" if str(blueprint.get("runtime")) == "desktop" else "api"
        rbac = str(blueprint.get("outbound_rbac") or "draft")
        if rbac not in {"internal", "draft", "execute"}:
            rbac = "draft"

        created = self.create_bot(
            name=name[:120],
            role=role[:2000],
            role_prompt=str(blueprint.get("role_prompt") or role)[:8000],
            runtime=runtime,
            outbound_rbac=rbac,
            model=model,
            daily_cap=max(0, min(500, int(blueprint.get("daily_cap") or 10))),
            routines=blueprint.get("routines") if isinstance(blueprint.get("routines"), list) else None,
            tools=blueprint.get("tools") if isinstance(blueprint.get("tools"), list) else None,
            collections=blueprint.get("collections") if isinstance(blueprint.get("collections"), dict) else None,
            linked_accounts=linked_accounts if linked_accounts else None,
            avatar_color=str(blueprint.get("avatar_color") or "slate"),
            avatar_icon=str(blueprint.get("avatar_icon") or "bot"),
            section=str(blueprint.get("section") or ""),
            boundaries=blueprint.get("boundaries") if isinstance(blueprint.get("boundaries"), list) else None,
            goal_metric=str(blueprint.get("goal_metric") or ""),
            handoff_bot_slug=str(blueprint.get("handoff_bot_slug") or ""),
        )
        for skill in blueprint.get("skills") or []:
            if isinstance(skill, dict) and skill.get("name") and skill.get("instructions"):
                self.upsert_skill(
                    name=str(skill["name"]),
                    description=str(skill.get("description") or ""),
                    instructions=str(skill["instructions"]),
                    scope_slug=created["slug"],
                    skill_slug=f"{created['slug']}-{slugify(str(skill['name']))}",
                )
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
        limit: int = 40,
    ) -> list[dict[str, Any]]:
        msgs, _, _ = self.list_room_messages_window(room_slug, limit=limit)
        return msgs

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

    def save_workspace_file(
        self,
        *,
        owner_email: str | None,
        filename: str,
        mime_type: str,
        content_bytes: bytes,
        uploaded_by: str = "user",
    ) -> dict[str, Any]:
        """Persist a file under the user's isolated directory up to 10 MB and index metadata."""
        size_bytes = len(content_bytes)
        if size_bytes > MAX_WORKSPACE_FILE_BYTES:
            raise FileTooLargeError(
                f"File exceeds the 10 MB limit ({size_bytes} bytes > {MAX_WORKSPACE_FILE_BYTES} bytes)."
            )
        clean_email, user_ns, user_dir = self._user_files_dir(owner_email)
        file_id = make_id("file")
        raw_name = Path(filename or "attachment.bin").name
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).strip("._")[:120] or "attachment.bin"
        stored_filename = f"{file_id}_{safe_name}"
        target_path = (user_dir / stored_filename).resolve()
        if not target_path.is_relative_to(user_dir):
            raise ValueError("Invalid target file path.")

        target_path.write_bytes(content_bytes)
        digest = hashlib.sha256(content_bytes).hexdigest()
        clean_mime = (mime_type or "application/octet-stream").strip()[:150]
        ext = Path(safe_name).suffix.lower()
        is_image = clean_mime in _IMAGE_MIME_TYPES or ext in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
        text_preview = ""
        if not is_image and (
            clean_mime.startswith("text/")
            or clean_mime in {"application/json", "application/xml", "application/csv"}
            or ext in _TEXT_PREVIEW_EXTENSIONS
        ):
            try:
                decoded = content_bytes[:128_000].decode("utf-8", errors="replace")
                text_preview = redact_secrets(decoded, self.collect_all_vault_secret_values())[:24_000]
            except Exception:
                text_preview = ""

        doc = {
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
        saved = self.upsert_document(
            collection="workspace_files",
            external_key=f"{user_ns}:{file_id}",
            search_text=f"{clean_email} {safe_name} {text_preview[:400]}",
            doc=doc,
            description="Per-user shared workspace files",
            doc_id=file_id,
        )
        return self._serialize_workspace_file(saved)

    @staticmethod
    def _serialize_workspace_file(item: dict[str, Any], *, include_preview: bool = False) -> dict[str, Any]:
        doc = item.get("doc") or {}
        res = {
            "id": item["id"],
            "filename": str(doc.get("filename") or "file"),
            "original_filename": str(doc.get("original_filename") or doc.get("filename") or "file"),
            "mime_type": str(doc.get("mime_type") or "application/octet-stream"),
            "size_bytes": int(doc.get("size_bytes") or 0),
            "sha256": str(doc.get("sha256") or ""),
            "owner_email": str(doc.get("owner_email") or ""),
            "uploaded_by": str(doc.get("uploaded_by") or "user"),
            "is_image": bool(doc.get("is_image", False)),
            "has_text_preview": bool(doc.get("text_preview")),
            "created_at": item["created_at"],
            "updated_at": item["updated_at"],
        }
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
        """Delete a user's workspace file from disk and SQLite."""
        meta, file_path = self.get_workspace_file(file_id, owner_email=owner_email)
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass
        self.delete_document("workspace_files", meta["id"])

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

        page_slug_map: dict[str, str] = {}
        created_pages: list[dict[str, Any]] = []
        for pg in pack.get("pages") or []:
            if not isinstance(pg, dict) or not pg.get("title"):
                continue
            orig_owner = slugify(str(pg.get("owner_bot_slug") or ""))
            mapped_owner = slug_map.get(orig_owner) or (created_bots[0]["slug"] if created_bots else "operations-coordinator")
            remapped_cols: list[str] = []
            for c in pg.get("allowed_collections") or []:
                col_str = str(c)
                for old_s, new_s in slug_map.items():
                    if old_s != new_s and f"bot_{old_s}_items" == col_str:
                        col_str = f"bot_{new_s}_items"
                remapped_cols.append(col_str)
            page_payload = pg.get("content_payload")
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
        """Return built-in, credential-free multi-bot Team Packs ready for 1-click installation."""
        return [
            {
                "id": "operations-coordinator-crew",
                "schema_version": "argo.team_pack.v1",
                "title": "Operations Coordinator Crew",
                "description": "Lead Coordinator + Source Scout + Briefing Writer inside a shared Room with a live Bot Hub Board.",
                "section": "Operations",
                "required_providers": [],
                "bots": [
                    {
                        "source_slug": "operations-lead",
                        "name": "Operations Lead",
                        "role": "Coordinate specialists, propose delegation plans, and synthesize one final reply",
                        "role_prompt": "Act as the Team Coordinator. When given a multi-step goal, propose a clear delegation plan across @source-scout and @briefing-writer, wait for results, and return one unified answer.",
                        "avatar_color": "indigo",
                        "avatar_icon": "shield",
                        "pinned": True,
                        "section": "Operations",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "model": "google:gemini-4-argon",
                        "boundaries": ["Never send external messages without approval"],
                        "routines": [{"type": "manual_trigger", "label": "Manual Run", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "platform_status"}, {"type": "builtin", "name": "request_human_approval"}],
                    },
                    {
                        "source_slug": "source-scout",
                        "name": "Source Scout",
                        "role": "Monitor configured websites and feeds for unseen items",
                        "role_prompt": "Check configured sources for unseen updates, skip marketing promos, save structured findings, and hand off relevant items.",
                        "avatar_color": "blue",
                        "avatar_icon": "rss",
                        "section": "Operations",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "model": "google:gemini-3.8-flash",
                        "boundaries": ["Never send external messages", "Skip duplicate items"],
                        "routines": [{"type": "manual_trigger", "label": "Manual Check", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "fetch_rss_feed"}, {"type": "builtin", "name": "fetch_public_webpage"}],
                    },
                    {
                        "source_slug": "briefing-writer",
                        "name": "Briefing Writer",
                        "role": "Draft crisp bulleted briefings and queue outbound updates for review",
                        "role_prompt": "Turn collected findings into concise, cited briefings and queue outbound drafts in Approvals for human review.",
                        "avatar_color": "violet",
                        "avatar_icon": "pen",
                        "section": "Operations",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "model": "google:gemini-4-argon",
                        "boundaries": ["Always cite source URLs", "Ask before sending externally"],
                        "routines": [{"type": "manual_trigger", "label": "Manual Draft", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "request_human_approval"}],
                    },
                ],
                "pages": [
                    {
                        "source_slug": "team-hub-board",
                        "title": "Team Hub Board",
                        "description": "Live status board for the Operations Coordinator Crew",
                        "render_mode": "sandboxed_html",
                        "template_key": "bot_hub_board",
                        "owner_bot_slug": "operations-lead",
                        "allowed_collections": [],
                        "pinned": True,
                    }
                ],
                "rooms": [
                    {
                        "source_slug": "operations-room",
                        "title": "Operations Room",
                        "member_bot_slugs": ["operations-lead", "source-scout", "briefing-writer"],
                        "coordinator_bot_slug": "operations-lead",
                        "stage_order": ["operations-lead", "source-scout", "briefing-writer"],
                        "ask_before_bot_handoff": False,
                        "max_bot_turns_per_message": 3,
                        "pinned_page_slug": "team-hub-board",
                        "section": "Operations",
                    }
                ],
            },
            {
                "id": "website-release-qa-crew",
                "schema_version": "argo.team_pack.v1",
                "title": "Website & Release QA Crew",
                "description": "Release Watcher + Visual Inspector + QA Summary Writer collaborating in a dedicated QA Room.",
                "section": "QA",
                "required_providers": [],
                "bots": [
                    {
                        "source_slug": "release-watcher",
                        "name": "Release Watcher",
                        "role": "Track changelog pages and release feeds for new versions",
                        "role_prompt": "Monitor release feeds and websites, record version changes, and tag @visual-inspector when live UI verification is needed.",
                        "avatar_color": "emerald",
                        "avatar_icon": "rss",
                        "section": "QA",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "model": "google:gemini-3.8-flash",
                        "boundaries": ["Ignore non-release marketing posts"],
                        "routines": [{"type": "manual_trigger", "label": "Manual Check", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "fetch_public_webpage"}, {"type": "builtin", "name": "fetch_rss_feed"}],
                    },
                    {
                        "source_slug": "visual-inspector",
                        "name": "Visual Inspector",
                        "role": "Verify pages, links, and layout health on request",
                        "role_prompt": "Inspect requested URLs, check status and structure cleanly, and report verified findings back to the Room.",
                        "avatar_color": "amber",
                        "avatar_icon": "globe",
                        "section": "QA",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "model": "google:gemini-3.8-flash",
                        "boundaries": ["Never attempt to bypass login gates or CAPTCHAs"],
                        "routines": [{"type": "manual_trigger", "label": "Inspect URL", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "fetch_public_webpage"}],
                    },
                    {
                        "source_slug": "qa-reporter",
                        "name": "QA Reporter",
                        "role": "Compile verified checks into a clean report or Page",
                        "role_prompt": "Summarize findings from @release-watcher and @visual-inspector into a concise report or interactive Page.",
                        "avatar_color": "slate",
                        "avatar_icon": "bot",
                        "section": "QA",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "model": "google:gemini-4-argon",
                        "boundaries": ["Only report directly observed checks"],
                        "routines": [{"type": "manual_trigger", "label": "Build QA Report", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "request_human_approval"}],
                    },
                ],
                "pages": [
                    {
                        "source_slug": "qa-status-board",
                        "title": "Release QA Board",
                        "description": "Live status across QA watchers and inspectors",
                        "render_mode": "sandboxed_html",
                        "template_key": "bot_hub_board",
                        "owner_bot_slug": "qa-reporter",
                        "allowed_collections": [],
                        "pinned": True,
                    }
                ],
                "rooms": [
                    {
                        "source_slug": "release-qa-room",
                        "title": "Release QA Room",
                        "member_bot_slugs": ["release-watcher", "visual-inspector", "qa-reporter"],
                        "coordinator_bot_slug": "qa-reporter",
                        "stage_order": ["release-watcher", "visual-inspector", "qa-reporter"],
                        "ask_before_bot_handoff": False,
                        "max_bot_turns_per_message": 3,
                        "pinned_page_slug": "qa-status-board",
                        "section": "QA",
                    }
                ],
            },
            {
                "id": "inbox-briefing-crew",
                "schema_version": "argo.team_pack.v1",
                "title": "Inbox & Briefing Crew",
                "description": "Inbox Triage + Follow-Up Drafter working together with human-approved drafts.",
                "section": "Inbox",
                "required_providers": ["google"],
                "bots": [
                    {
                        "source_slug": "inbox-triage",
                        "name": "Inbox Triage",
                        "role": "Screen unread messages, filter automated noise, and surface priorities",
                        "role_prompt": "Check unread inbox threads, ignore automated receipts and newsletters, and flag messages needing replies.",
                        "avatar_color": "blue",
                        "avatar_icon": "mail",
                        "section": "Inbox",
                        "runtime": "api",
                        "outbound_rbac": "internal",
                        "daily_cap": 0,
                        "model": "google:gemini-3.8-flash",
                        "boundaries": ["Never send replies autonomously", "Skip promotional newsletters"],
                        "routines": [{"type": "manual_trigger", "label": "Triage Inbox", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "gmail_search"}],
                    },
                    {
                        "source_slug": "follow-up-drafter",
                        "name": "Follow-Up Drafter",
                        "role": "Draft concise replies in Approvals matching operator writing style",
                        "role_prompt": "Draft clear, polite replies for flagged messages and queue them in Approvals for sign-off.",
                        "avatar_color": "violet",
                        "avatar_icon": "pen",
                        "section": "Inbox",
                        "runtime": "api",
                        "outbound_rbac": "draft",
                        "daily_cap": 10,
                        "model": "google:gemini-4-argon",
                        "boundaries": ["Always queue drafts in Approvals before sending"],
                        "routines": [{"type": "manual_trigger", "label": "Draft Replies", "schedule": "Manual", "enabled": True}],
                        "tools": [{"type": "builtin", "name": "request_human_approval"}],
                    },
                ],
                "pages": [],
                "rooms": [
                    {
                        "source_slug": "inbox-team-room",
                        "title": "Inbox Team Room",
                        "member_bot_slugs": ["inbox-triage", "follow-up-drafter"],
                        "coordinator_bot_slug": "inbox-triage",
                        "stage_order": ["inbox-triage", "follow-up-drafter"],
                        "ask_before_bot_handoff": False,
                        "max_bot_turns_per_message": 2,
                        "section": "Inbox",
                    }
                ],
            },
        ]

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
    ) -> dict[str, Any]:
        """Record downstream connector execution success ('executed') or error note."""
        with self._lock:
            if executed:
                self._conn.execute(
                    "UPDATE approvals_outbox SET status = 'executed', error_message = NULL WHERE id = ?",
                    (approval_id,),
                )
            else:
                self._conn.execute(
                    "UPDATE approvals_outbox SET error_message = ? WHERE id = ?",
                    (error_message, approval_id),
                )
            self._conn.commit()
        return self.get_approval(approval_id)

    def supersede_approval(self, approval_id: str, *, actor: str) -> dict[str, Any]:
        """Atomically mark a pending approval as superseded by a revised draft."""
        now = utc_now()
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE approvals_outbox
                SET status = 'superseded', approved_by = ?, resolved_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (actor, now, approval_id),
            )
            if cursor.rowcount == 0:
                self._conn.rollback()
                raise AlreadyResolvedError("Already resolved.")
            self._conn.commit()
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

        with self._lock:
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
                self._conn.rollback()
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

            self._conn.commit()
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
        return {
            "id": row["id"],
            "slug": row["slug"],
            "title": row["title"],
            "icon": row["icon"],
            "render_mode": row["render_mode"],
            "content_payload": row["content_payload"],
            "allowed_collections": json.loads(row["allowed_collections_json"]),
            "owner_bot_slug": row["owner_bot_slug"],
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
<body style="font-family:system-ui,-apple-system,sans-serif;margin:0;padding:16px;background:#f8fafc;color:#0f172a;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
    <div>
      <h3 style="margin:0;font-size:14px;">{safe_title}</h3>
      <p style="margin:2px 0 0;font-size:11px;color:#475569;">{safe_desc}</p>
    </div>
    <span style="font-size:10px;padding:2px 8px;border-radius:999px;background:#e2e8f0;color:#334155;">sandbox="allow-scripts allow-downloads" · postMessage</span>
  </div>
  <div id="kpiRow" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:12px;"></div>
  <div id="recordsBox" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:10px;font-size:12px;color:#334155;">
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
        card.style.cssText = "background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:8px;";
        const l = document.createElement("div");
        l.style.cssText = "font-size:10px;color:#64748b;";
        l.textContent = label;
        const v = document.createElement("div");
        v.style.cssText = "font-size:15px;font-weight:600;color:#0f172a;margin-top:2px;";
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
        row.style.cssText = "padding:6px 0;border-bottom:1px solid #f1f5f9;";
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
    ) -> str:
        """Build a clean, sandbox-safe interactive HTML5 Page template in dark executive style."""
        safe_title = html.escape(title.strip() or "Interactive View")
        safe_desc = html.escape(description.strip() or "Live workspace view powered by Argo data")
        cols = list(allowed_collections or [])
        primary_coll = cols[0] if cols else ""

        if template_key == "bot_hub_board":
            return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  * {{ box-sizing: border-box; }}
  html {{ color-scheme: dark; scrollbar-width: thin; scrollbar-color: #363e4d #161920; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: #161920; }}
  ::-webkit-scrollbar-thumb {{ background: #363e4d; border-radius: 9999px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}
  body {{ margin:0; padding:22px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:#161920; color:#f3f4f6; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:1180px; margin:0 auto; display:grid; gap:18px; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-end; gap:12px; flex-wrap:wrap; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; color:#f3f4f6; }}
  .sub {{ margin:4px 0 0; font-size:13px; color:#9ca3af; }}
  .bar {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
  input[type=search] {{ background:#141820; color:#f3f4f6; border:1px solid #2d3440; border-radius:8px; padding:7px 11px; font-size:13px; min-width:210px; outline:none; }}
  input[type=search]:focus {{ border-color:#3b72b2; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; }}
  .kpi {{ background:#1e232c; border:1px solid #2d3440; border-radius:12px; padding:14px; }}
  .k-lbl {{ font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:#9ca3af; font-weight:600; }}
  .k-val {{ font-size:22px; font-weight:600; color:#f3f4f6; margin-top:4px; }}
  .sec-title {{ font-size:12px; text-transform:uppercase; letter-spacing:0.05em; color:#9ca3af; font-weight:600; margin:4px 0 8px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:12px; }}
  .card {{ background:#1e232c; border:1px solid #2d3440; border-radius:12px; padding:15px; display:flex; flex-direction:column; gap:10px; }}
  .row {{ display:flex; align-items:center; justify-content:space-between; gap:8px; }}
  .title {{ font-size:14px; font-weight:600; color:#f3f4f6; }}
  .meta {{ font-size:12px; color:#9ca3af; }}
  .body {{ font-size:13px; color:#d1d5db; min-height:36px; }}
  .pill {{ display:inline-flex; align-items:center; gap:6px; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:600; border:1px solid #2d3440; background:#181c23; color:#e5e7eb; }}
  .dot {{ width:8px; height:8px; border-radius:999px; display:inline-block; }}
  .btns {{ display:flex; gap:7px; flex-wrap:wrap; padding-top:8px; border-top:1px solid #2d3440; }}
  button.btn {{ background:#181c23; border:1px solid #353f50; color:#e5e7eb; border-radius:8px; padding:5px 10px; font-size:12px; font-weight:500; cursor:pointer; }}
  button.btn:hover {{ background:#252b36; }}
  button.primary {{ background:#3b72b2; border-color:#3b72b2; color:#ffffff; }}
  button.primary:hover {{ background:#31629c; }}
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
  html {{ color-scheme: dark; scrollbar-width: thin; scrollbar-color: #363e4d #161920; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: #161920; }}
  ::-webkit-scrollbar-thumb {{ background: #363e4d; border-radius: 9999px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:#161920; color:#f3f4f6; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:1120px; margin:0 auto; }}
  .top {{ display:flex; justify-content:space-between; align-items:flex-start; gap:14px; flex-wrap:wrap; margin-bottom:20px; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; letter-spacing:-0.01em; color:#f3f4f6; }}
  .sub {{ margin:5px 0 0; font-size:13px; color:#9ca3af; }}
  .stats {{ display:flex; gap:8px; flex-wrap:wrap; }}
  .pill {{ background:#1e232c; border:1px solid #2d3440; border-radius:999px; padding:6px 12px; font-size:12px; font-weight:600; color:#e5e7eb; display:inline-flex; align-items:center; gap:7px; }}
  button.pill {{ cursor:pointer; }}
  button.pill:hover {{ border-color:#4b7bec; background:#252b36; }}
  .dot {{ width:8px; height:8px; border-radius:999px; display:inline-block; flex-shrink:0; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(265px,1fr)); gap:12px; }}
  .group-title {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.06em; color:#9ca3af; margin:20px 0 10px; }}
  .station {{ background:#1e232c; border:1px solid #2d3440; border-radius:12px; padding:16px; display:flex; flex-direction:column; gap:11px; transition:border-color .15s, background .15s; }}
  .station:hover {{ border-color:#3d4759; background:#222833; }}
  .row {{ display:flex; align-items:center; justify-content:space-between; gap:8px; }}
  .avatar {{ width:34px; height:34px; border-radius:10px; background:#252b36; border:1px solid #353f50; color:#93b4dc; font-size:12px; font-weight:700; display:flex; align-items:center; justify-content:center; flex-shrink:0; }}
  .name {{ font-size:14px; font-weight:600; color:#f3f4f6; }}
  .meta {{ font-size:12px; color:#9ca3af; margin-top:2px; }}
  .summary {{ font-size:13px; color:#d1d5db; line-height:1.45; min-height:36px; }}
  .actions {{ display:flex; gap:7px; padding-top:8px; border-top:1px solid #2d3440; }}
  button.act {{ border:1px solid #353f50; background:#181c23; color:#e5e7eb; border-radius:8px; padding:6px 11px; font-size:12px; font-weight:500; cursor:pointer; }}
  button.act:hover {{ background:#252b36; border-color:#4b5568; }}
  button.primary {{ background:#3b72b2; color:#ffffff; border-color:#3b72b2; }}
  button.primary:hover {{ background:#31629c; }}
  .badge-run {{ background:#1f3329; color:#a8d5ba; border-color:#2e4d3e; }}
  .badge-wait {{ background:#362c1c; color:#e6c88a; border-color:#524229; }}
  .badge-warn {{ background:#382326; color:#e8a8ad; border-color:#543439; }}
  .badge-idle {{ background:#213047; color:#b6cff0; border-color:#324869; }}
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
  html {{ color-scheme: dark; scrollbar-width: thin; scrollbar-color: #363e4d #161920; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: #161920; }}
  ::-webkit-scrollbar-thumb {{ background: #363e4d; border-radius: 9999px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:#161920; color:#f3f4f6; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:920px; margin:0 auto; display:grid; gap:14px; }}
  .card {{ background:#1e232c; border:1px solid #2d3440; border-radius:12px; padding:18px; }}
  .head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
  .badge {{ background:#213047; border:1px solid #324869; color:#b6cff0; border-radius:999px; padding:4px 10px; font-size:12px; font-weight:600; letter-spacing:0.03em; text-transform:uppercase; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; color:#f3f4f6; }}
  .sub {{ margin:5px 0 0; font-size:13px; color:#9ca3af; }}
  .controls {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-top:16px; }}
  label {{ display:flex; flex-direction:column; gap:7px; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:#9ca3af; }}
  select {{ background:#141820; color:#f3f4f6; border:1px solid #323a48; border-radius:8px; padding:7px 10px; font-size:13px; outline:none; }}
  input[type=range] {{ width:100%; accent-color:#3b72b2; }}
  canvas {{ width:100%; height:260px; display:block; background:#141820; border-radius:10px; border:1px solid #2d3440; }}
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
      ctx.strokeStyle = "#2d3440";
      ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {{
        const y = pad + (h - pad * 2) * (i / 4);
        ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
      }}
      ctx.strokeStyle = "#5c8cc7";
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
  html {{ color-scheme: dark; scrollbar-width: thin; scrollbar-color: #363e4d #161920; }}
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: #161920; }}
  ::-webkit-scrollbar-thumb {{ background: #363e4d; border-radius: 9999px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}
  body {{ margin:0; padding:24px; font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; font-size:14px; line-height:1.5; background:#161920; color:#f3f4f6; -webkit-font-smoothing:antialiased; }}
  .wrap {{ max-width:980px; margin:0 auto; display:grid; gap:16px; }}
  .head {{ display:flex; justify-content:space-between; align-items:flex-end; gap:12px; flex-wrap:wrap; }}
  .title-wrap {{ min-width:0; }}
  h1 {{ margin:0; font-size:20px; font-weight:600; letter-spacing:-0.01em; color:#f3f4f6; }}
  .sub {{ margin:5px 0 0; font-size:13px; color:#9ca3af; }}
  .head-right {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .status-pill {{ background:#1f3329; border:1px solid #2e4d3e; color:#a8d5ba; border-radius:999px; padding:5px 11px; font-size:12px; font-weight:600; letter-spacing:0.03em; text-transform:uppercase; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(175px,1fr)); gap:12px; }}
  .card {{ background:#1e232c; border:1px solid #2d3440; border-radius:12px; padding:16px; }}
  .kpi-accent-green {{ border-color:#2e4d3e; }}
  .kpi-accent-sky {{ border-color:#324869; }}
  .k-label {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; color:#9ca3af; }}
  .k-val {{ font-size:24px; font-weight:600; margin-top:6px; color:#f3f4f6; }}
  .k-val.green {{ color:#7ec298; }}
  .k-val.sky {{ color:#8eb2db; }}
  .bars {{ display:flex; align-items:flex-end; gap:10px; height:128px; padding-top:14px; }}
  .bar-col {{ flex:1; display:flex; flex-direction:column; align-items:center; gap:5px; height:100%; justify-content:flex-end; }}
  .bar {{ width:100%; max-width:52px; background:#3b72b2; border-radius:4px 4px 2px 2px; min-height:4px; }}
  .bar-lbl {{ font-size:12px; color:#9ca3af; }}
  .section-lbl {{ font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:#9ca3af; margin-bottom:10px; }}
  .item {{ padding:12px 14px; margin-bottom:8px; background:#181c23; border:1px solid #2d3440; border-radius:10px; }}
  .item:last-child {{ margin-bottom:0; }}
  .item-top {{ display:flex; align-items:center; justify-content:space-between; gap:10px; }}
  .item-t {{ font-size:14px; font-weight:600; color:#f3f4f6; }}
  .item-tag {{ font-size:12px; font-weight:500; padding:2px 8px; border-radius:999px; background:#213047; border:1px solid #324869; color:#b6cff0; white-space:nowrap; }}
  .item-m {{ font-size:13px; color:#d1d5db; margin-top:5px; line-height:1.45; }}
  input[type=search] {{ border:1px solid #323a48; border-radius:8px; padding:7px 12px; font-size:13px; background:#141820; color:#f3f4f6; min-width:220px; outline:none; }}
  input[type=search]::placeholder {{ color:#9ca3af; }}
  input[type=search]:focus {{ border-color:#5c8cc7; }}
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
            if "allow-same-origin" in payload.lower():
                raise ValueError(
                    "Sandboxed HTML pages must not declare 'allow-same-origin'."
                )
        return payload

    @staticmethod
    def _normalize_page_collections(allowed_collections: list[str] | None) -> list[str]:
        if not allowed_collections:
            return []
        return list(
            dict.fromkeys(
                collection_slug(str(c)) for c in allowed_collections if str(c).strip()
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
        owner_bot_slug: str = "operations-coordinator",
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Create a new declarative_json or sandboxed_html page."""
        now = utc_now()
        base_slug = slugify(title)
        normalized_collections = self._normalize_page_collections(allowed_collections)
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
                            {"label": "Owner Bot", "value": owner_bot_slug, "hint": "Dynamic view binding"},
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
                    allowed_collections_json, owner_bot_slug, pinned, updated_at
                ) VALUES (?, ?, ?, 'file-text', ?, ?, ?, ?, ?, ?)
                """,
                (
                    page_id,
                    candidate_slug,
                    title.strip(),
                    render_mode,
                    payload,
                    json.dumps(normalized_collections),
                    owner_bot_slug,
                    1 if pinned else 0,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_page(candidate_slug)

    def update_page(self, slug: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an existing declarative_json or sandboxed_html page without container rebuilds."""
        now = utc_now()
        with self._lock:
            row = self._conn.execute("SELECT * FROM pages WHERE slug = ?", (slug,)).fetchone()
            if row is None:
                raise NotFoundError(f"Page '{slug}' not found.")

            title = str(updates["title"]).strip() if updates.get("title") else str(row["title"])
            render_mode = str(updates.get("render_mode") or row["render_mode"])
            allowed_collections = (
                self._normalize_page_collections(updates["allowed_collections"])
                if updates.get("allowed_collections") is not None
                else json.loads(row["allowed_collections_json"])
            )
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
                                {"label": "Owner Bot", "value": owner_bot_slug, "hint": "Dynamic view binding"},
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
                    allowed_collections_json = ?, owner_bot_slug = ?, pinned = ?, updated_at = ?
                WHERE slug = ?
                """,
                (
                    title,
                    render_mode,
                    content_payload,
                    json.dumps(allowed_collections),
                    owner_bot_slug,
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
        owner_bot_slug: str = "operations-coordinator",
        description: str = "",
        pinned: bool = True,
    ) -> dict[str, Any]:
        """Idempotently create or update a dynamic Page by slug for runtime bot updates."""
        clean_slug = slugify(slug)
        normalized_collections = self._normalize_page_collections(allowed_collections)
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
                    "allowed_collections": normalized_collections,
                    "owner_bot_slug": owner_bot_slug,
                    "pinned": pinned,
                },
            )
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
                    allowed_collections_json, owner_bot_slug, pinned, updated_at
                ) VALUES (?, ?, ?, 'file-text', ?, ?, ?, ?, ?, ?)
                """,
                (
                    make_id("pg"),
                    clean_slug,
                    title.strip(),
                    render_mode,
                    payload,
                    json.dumps(normalized_collections),
                    owner_bot_slug,
                    1 if pinned else 0,
                    now,
                ),
            )
            self._conn.commit()
        return self.get_page(clean_slug)

    def delete_page(self, slug: str) -> None:
        """Delete a dynamic page by slug."""
        with self._lock:
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
        clean_col = collection_slug(collection)
        allowed = {collection_slug(c) for c in page["allowed_collections"]}
        if clean_col not in allowed:
            raise PermissionError(
                f"Page '{slug}' is not permitted to query collection '{clean_col}'."
            )
        return self.search_documents(collection=clean_col, query=query, limit=limit)

    def resolve_page_data(
        self,
        slug: str,
        *,
        query: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Resolve a dynamic page alongside its allowed SQLite collection records."""
        page = self.get_page(slug)
        collections_data: dict[str, list[dict[str, Any]]] = {}
        records: list[dict[str, Any]] = []
        for col in self._normalize_page_collections(page["allowed_collections"]):
            docs = self.search_documents(collection=col, query=query, limit=limit)
            collections_data[col] = docs
            records.extend(docs)

        parsed_payload: dict[str, Any] = {}
        if page["render_mode"] == "declarative_json":
            try:
                parsed = json.loads(page["content_payload"])
                if isinstance(parsed, dict):
                    parsed_payload = parsed
            except json.JSONDecodeError:
                parsed_payload = {"description": page["content_payload"]}

        return {
            "page": page,
            "parsed_payload": parsed_payload,
            "collections": collections_data,
            "records": records[:limit],
            "total_records": len(records),
        }

    @staticmethod
    def _humanize_collection_label(slug: str, owner_bot_name: str | None) -> str:
        if slug == "telegram_channel_posts":
            return "Telegram Posts & DMs"
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
                    clean = collection_slug(str(raw_c))
                    if clean not in _INTERNAL_SYSTEM_COLLECTIONS:
                        owners_write.setdefault(clean, (bslug, bname))
                for raw_c in cols_cfg.get("read") or []:
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
            result.append(
                {
                    "slug": cslug,
                    "label": self._humanize_collection_label(cslug, owner_name),
                    "description": row["description"],
                    "doc_count": int(row["doc_count"]),
                    "owner_bot_slug": owner_slug,
                    "owner_bot_name": owner_name,
                    "is_internal": cslug in _INTERNAL_SYSTEM_COLLECTIONS,
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
            "env_placeholders": cls._build_vault_placeholders(
                slug=slug,
                host=host,
                port=port,
                url=url,
                secret_keys=secret_keys,
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

        doc = {
            "slug": clean_slug,
            "name": clean_name,
            "secret_type": str(secret_type or (existing.get("secret_type") if existing else "ssh")),
            "host": host.strip(),
            "port": port.strip() or ("22" if secret_type == "ssh" else ""),
            "url": url.strip(),
            "secret_keys": sorted(merged_secrets.keys()),
            "allowed_bots": clean_allowed,
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
        return {
            **meta,
            "secrets": decrypted_secrets,
        }

    def delete_vault_secret(self, slug: str) -> bool:
        """Delete a Vault secret entry by slug."""
        clean_slug = slugify(slug)
        saved = self.get_document_by_external_key("vault_secrets", clean_slug)
        if saved is None:
            raise NotFoundError(f"Vault secret '{clean_slug}' not found.")
        self.delete_document("vault_secrets", saved["id"])
        return True

    def collect_all_vault_secret_values(self) -> list[str]:
        """Collect all decrypted non-empty Vault secret strings for trace/log scrubbing."""
        values: list[str] = []
        for meta in self.list_vault_secrets():
            dec = self.get_vault_secret_decrypted(meta["slug"])
            if not dec:
                continue
            for val in (dec.get("secrets") or {}).values():
                s = str(val).strip()
                if len(s) >= 4:
                    values.append(s)
        return values

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

    def delete_collection(self, collection: str) -> int:
        """Delete all documents in a collection and return deleted count."""
        clean_coll = collection_slug(collection)
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM collection_documents WHERE collection = ?",
                (clean_coll,),
            )
            self._conn.execute("DELETE FROM collections WHERE slug = ?", (clean_coll,))
            self._conn.commit()
            return int(cursor.rowcount or 0)

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

    def workspace_counts(self) -> dict[str, int]:
        """Compute live sidebar badge and footer summary counts."""
        bots = self.list_bots()
        desktops = [b for b in bots if b["runtime"] == "desktop"]
        desktops_running = sum(1 for b in desktops if b["desktop_state"] == "running")

        with self._lock:
            pending_approvals = self._conn.execute(
                "SELECT COUNT(*) FROM approvals_outbox WHERE status = 'pending'"
            ).fetchone()[0]
            pages_count = self._conn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
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
    ) -> dict[str, Any]:
        """Return lightweight secret-free live status for bots, rooms, unread cursors & approvals."""
        bots = self.list_bots()
        bot_name_by_slug = {b["slug"]: b["name"] for b in bots}
        rooms = self.list_rooms()
        pending = self.list_approvals(tab="pending")
        recent_runs = self.list_bot_runs(limit=80)
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
                    "role": bot["role"],
                    "enabled": bot["enabled"],
                    "runtime": bot["runtime"],
                    "desktop_state": bot["desktop_state"],
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
                preview = f"{prefix}{str(rmsg['text']).strip().splitlines()[0]}"[:120]
            room_stations.append(
                {
                    "slug": rslug,
                    "title": room["title"],
                    "member_bot_slugs": room["member_bot_slugs"],
                    "last_sender_name": rmsg.get("sender_name") if rmsg else None,
                    "last_message_preview": preview,
                    "last_activity_at": rmsg["created_at"] if rmsg else room["updated_at"],
                    "unread": room_unread,
                }
            )

        return {
            "generated_at": utc_now(),
            "counts": self.workspace_counts(),
            "bots": stations,
            "rooms": room_stations,
        }
