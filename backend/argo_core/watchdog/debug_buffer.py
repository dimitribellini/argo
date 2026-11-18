"""Bounded, thread-safe, secret-redacted in-memory log buffer for on-demand debugging."""

from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any

from argo_core.security.vault import redact_secrets


class DebugLogBuffer(logging.Handler):
    """Captures recent backend log records in memory with automatic secret scrubbing."""

    def __init__(self, max_records: int = 500, level: int = logging.INFO) -> None:
        super().__init__(level=level)
        self._records: deque[dict[str, Any]] = deque(maxlen=max(50, max_records))
        self._lock = threading.Lock()
        self._seq = 0

    def emit(self, record: logging.LogRecord) -> None:
        """Store a formatted, secret-redacted log record without raising."""
        try:
            raw_message = record.getMessage()
            if record.exc_info:
                formatter = self.formatter or logging.Formatter()
                exc_text = formatter.formatException(record.exc_info)
                if exc_text:
                    raw_message = f"{raw_message}\n{exc_text}"
            entry = {
                "seq": self._next_seq(),
                "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": redact_secrets(raw_message),
            }
            with self._lock:
                self._records.append(entry)
        except Exception:
            self.handleError(record)

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def list_logs(
        self,
        *,
        limit: int = 200,
        level: str | None = None,
        contains: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return newest-first redacted log entries filtered optionally by level or substring."""
        normalized_level = (level or "").strip().upper()
        needle = (contains or "").strip().lower()
        with self._lock:
            items = list(self._records)
        items.reverse()
        filtered: list[dict[str, Any]] = []
        for item in items:
            if normalized_level and normalized_level != "ALL" and item["level"] != normalized_level:
                continue
            if needle:
                haystack = f"{item['logger']} {item['message']}".lower()
                if needle not in haystack:
                    continue
            filtered.append(dict(item))
            if len(filtered) >= max(1, min(limit, 500)):
                break
        return filtered

    def clear(self) -> int:
        """Remove all buffered log entries and return how many were cleared."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
            return count
