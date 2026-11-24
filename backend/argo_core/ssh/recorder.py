"""Dual-layer SSH forensic audit recorder (.cast.zst asciicast v3 + ssh_audit_log collection)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from argo_core.security.vault import redact_secrets

try:
    from compression import zstd as _stdlib_zstd  # type: ignore[import-not-found]
except ImportError:
    _stdlib_zstd = None

try:
    import zstandard as _zstd_pkg  # type: ignore[import-not-found]
except ImportError:
    _zstd_pkg = None


def zstd_compress_frame(raw: bytes) -> bytes:
    """Compress raw bytes as a self-contained Zstandard frame (Python 3.15 stdlib or zstandard)."""
    if _stdlib_zstd is not None:
        return _stdlib_zstd.compress(raw)
    if _zstd_pkg is not None:
        return _zstd_pkg.ZstdCompressor(level=3).compress(raw)
    raise RuntimeError("Neither stdlib compression.zstd nor zstandard package is installed.")


def zstd_decompress_bytes(compressed: bytes) -> bytes:
    """Decompress single- or multi-frame Zstandard payloads cleanly."""
    if not compressed:
        return b""
    if _stdlib_zstd is not None:
        if hasattr(_stdlib_zstd, "decompress"):
            return _stdlib_zstd.decompress(compressed)
    if _zstd_pkg is not None:
        dctx = _zstd_pkg.ZstdDecompressor()
        with dctx.stream_reader(io.BytesIO(compressed)) as reader:
            return reader.read()
    raise RuntimeError("Neither stdlib compression.zstd nor zstandard package is installed.")


def read_cast_ndjson(cast_path: Path, secret_values: list[str] | tuple[str, ...] = ()) -> str:
    """Decompress a .cast.zst recording to UTF-8 asciicast v3 NDJSON, re-scrubbing any secrets."""
    raw = zstd_decompress_bytes(cast_path.read_bytes())
    text = raw.decode("utf-8", errors="replace")
    if secret_values:
        text = redact_secrets(text, secret_values)
    return text


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of an audit recording file."""
    if not path.is_file():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class SSHSessionRecorder:
    """Thread-safe dual-layer asciicast v3 (.cast.zst) + SQLite ssh_audit_log recorder."""

    def __init__(
        self,
        *,
        audit_root: str | Path,
        session_id: str,
        bot_slug: str,
        vault_slug: str,
        host: str,
        port: int,
        correlation_id: str,
        repo: Any,
        cols: int = 120,
        rows: int = 36,
        retention_hours: int = 24,
        secrets_provider: Callable[[], list[str]] | None = None,
    ) -> None:
        self.audit_root = Path(audit_root)
        self.session_id = session_id
        self.bot_slug = bot_slug
        self.vault_slug = vault_slug
        self.host = host
        self.port = int(port)
        self.correlation_id = correlation_id
        self._repo = repo
        self.cols = cols
        self.rows = rows
        self.retention_hours = max(1, min(8760, int(retention_hours)))
        self._secrets_provider = secrets_provider

        now_dt = datetime.now(UTC)
        self.created_at_dt = now_dt
        self.created_at = now_dt.isoformat()
        self.expires_at = (now_dt + timedelta(hours=self.retention_hours)).isoformat()
        date_dir = now_dt.strftime("%Y-%m-%d")

        self.cast_relpath = f"{date_dir}/{session_id}.cast.zst"
        self.cast_path = (self.audit_root / self.cast_relpath).resolve()
        self.pinned = False
        self.cast_sha256 = ""
        self._closed = False
        self._lock = threading.Lock()
        self._last_event_mono = time.monotonic()

        self._ensure_header_written()

    def _get_secrets(self) -> list[str]:
        if self._secrets_provider is not None:
            return self._secrets_provider()
        return self._repo.collect_all_vault_secret_values()

    def _scrub(self, text: str) -> str:
        return redact_secrets(text, self._get_secrets())

    def _append_compressed_line(self, line: str) -> None:
        encoded = (line if line.endswith("\n") else line + "\n").encode("utf-8", errors="replace")
        frame = zstd_compress_frame(encoded)
        self.audit_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.audit_root, 0o700)
        parent_dir = self.cast_path.parent
        parent_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(parent_dir, 0o700)
        fd = os.open(self.cast_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, frame)
        finally:
            os.close(fd)
        os.chmod(self.cast_path, 0o600)

    def _ensure_header_written(self) -> None:
        with self._lock:
            if self.cast_path.exists() and self.cast_path.stat().st_size > 0:
                return
            header = {
                "version": 3,
                "term": {
                    "cols": self.cols,
                    "rows": self.rows,
                    "type": "xterm-256color",
                },
                "timestamp": int(self.created_at_dt.timestamp()),
                "title": self._scrub(f"{self.vault_slug} ({self.host})"),
            }
            self._append_compressed_line(json.dumps(header, ensure_ascii=False))
            self._last_event_mono = time.monotonic()

    def _write_event(self, code: str, data: str) -> None:
        with self._lock:
            now_mono = time.monotonic()
            delta = round(max(0.0, now_mono - self._last_event_mono), 6)
            self._last_event_mono = now_mono
            scrubbed = self._scrub(data)
            line = json.dumps([delta, code, scrubbed], ensure_ascii=False)
            self._append_compressed_line(line)

    def write_output(self, data: bytes | str) -> None:
        """Append a redacted PTY output frame ('o') to .cast.zst."""
        text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)
        if not text:
            return
        self._write_event("o", text)

    def write_input(self, data: bytes | str) -> None:
        """Append a redacted input frame ('i') to .cast.zst."""
        text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)
        if not text:
            return
        self._write_event("i", text)

    def write_marker(self, label: str) -> None:
        """Append an audit timeline marker ('m') to .cast.zst."""
        self._write_event("m", str(label))

    def write_resize(self, cols: int, rows: int) -> None:
        """Append a terminal resize event ('r') to .cast.zst."""
        self.cols = int(cols)
        self.rows = int(rows)
        self._write_event("r", f"{self.cols}x{self.rows}")

    def write_exit(self, exit_code: int) -> None:
        """Append a command exit status event ('x') to .cast.zst."""
        self._write_event("x", str(int(exit_code)))

    def refresh_sha256(self) -> str:
        """Compute and cache the current SHA-256 hex digest of .cast.zst."""
        with self._lock:
            self.cast_sha256 = compute_file_sha256(self.cast_path)
            return self.cast_sha256

    def finalize(self) -> str:
        """Mark the recording finalized and return the final SHA-256 hex digest."""
        with self._lock:
            self._closed = True
            self.cast_sha256 = compute_file_sha256(self.cast_path)
            return self.cast_sha256

    def set_pinned(self, pinned: bool) -> None:
        """Persist pinned status on this recorder and all matching ssh_audit_log turns."""
        self.pinned = bool(pinned)
        self._repo.set_ssh_session_pinned(self.session_id, self.pinned)

    def record_turn(
        self,
        *,
        turn_seq: int,
        command: str,
        input_kind: str,
        status: str,
        exit_code: int | None,
        screen_excerpt: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Upsert a sanitized turn audit record into ssh_audit_log."""
        digest = self.refresh_sha256()
        scrubbed_cmd = self._scrub(str(command or ""))[:1000]
        scrubbed_screen = self._scrub(str(screen_excerpt or ""))[:8000]
        record: dict[str, Any] = {
            "session_id": self.session_id,
            "turn_seq": int(turn_seq),
            "correlation_id": self.correlation_id,
            "bot_slug": self.bot_slug,
            "vault_slug": self.vault_slug,
            "host": self.host,
            "port": self.port,
            "command": scrubbed_cmd,
            "input_kind": input_kind,
            "status": status,
            "exit_code": exit_code,
            "screen_excerpt": scrubbed_screen,
            "cast_relpath": self.cast_relpath,
            "cast_sha256": digest,
            "pinned": self.pinned,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if extra:
            for k, v in extra.items():
                if k not in record:
                    record[k] = self._scrub(v) if isinstance(v, str) else v
        return self._repo.upsert_ssh_audit_turn(record)


def sweep_expired_ssh_recordings(
    *,
    audit_root: str | Path,
    repo: Any,
    active_session_ids: set[str] | None = None,
    now_dt: datetime | None = None,
    retention_hours_override: int | None = None,
) -> dict[str, int]:
    """Delete expired unpinned ssh_audit_log rows and .cast.zst files; preserve pinned records."""
    now = now_dt or datetime.now(UTC)
    now_iso = now.isoformat()
    active_ids = active_session_ids or set()
    root_path = Path(audit_root)

    purged_cast_relpaths = repo.purge_expired_ssh_audit_logs(now_iso)
    deleted_files = 0
    for rel in purged_cast_relpaths:
        if not rel:
            continue
        stem = Path(rel).name.removesuffix(".cast.zst")
        if stem in active_ids:
            continue
        candidate = (root_path / rel).resolve()
        if candidate.is_relative_to(root_path.resolve()) and candidate.is_file():
            try:
                candidate.unlink()
                deleted_files += 1
            except OSError:
                pass

    # Also enforce age cutoff on any orphaned unpinned .cast.zst files older than configured retention
    settings = repo.get_ssh_audit_settings()
    retention_hours = (
        int(retention_hours_override)
        if retention_hours_override is not None
        else int(settings.get("retention_hours") or 24)
    )
    cutoff_epoch = (now - timedelta(hours=max(1, retention_hours))).timestamp()
    pinned_casts: set[str] = set()
    retained_casts: set[str] = set()
    for sess in repo.list_recent_ssh_sessions_from_log(limit=2000):
        rel = str(sess.get("cast_relpath") or "").strip()
        if rel:
            retained_casts.add(rel)
            if sess.get("pinned"):
                pinned_casts.add(rel)

    if root_path.is_dir():
        for cast_file in list(root_path.rglob("*.cast.zst")):
            try:
                rel = cast_file.resolve().relative_to(root_path.resolve()).as_posix()
            except ValueError:
                continue
            sid = cast_file.name.removesuffix(".cast.zst")
            if sid in active_ids or rel in pinned_casts:
                continue
            # If still referenced in un-expired ssh_audit_log rows, keep unless expired above
            if rel in retained_casts:
                continue
            try:
                if cast_file.stat().st_mtime <= cutoff_epoch:
                    cast_file.unlink()
                    deleted_files += 1
            except OSError:
                pass

        for sub in sorted(root_path.iterdir(), reverse=True):
            if sub.is_dir():
                try:
                    if not any(sub.iterdir()):
                        sub.rmdir()
                except OSError:
                    pass

    return {
        "purged_log_casts": len(purged_cast_relpaths),
        "deleted_files": deleted_files,
    }
