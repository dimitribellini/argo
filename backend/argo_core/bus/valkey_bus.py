"""Valkey 9.1 Streams, distributed mutex locks, idempotency, and live SSE subscribers."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from argo_core.db.repositories import ArgoRepository

logger = logging.getLogger(__name__)

MAX_HOP_COUNT = 5
STREAM_NAME = "argo:events"
CONSUMER_GROUP = "argo-runner"


class HopLimitExceededError(ValueError):
    """Raised when an inter-bot handoff exceeds the Valkey loop guard (hop_count > 5)."""


class EventBus:
    """Async Valkey Streams + mutex bus with graceful in-memory fallback for offline tests."""

    def __init__(self, valkey_url: str, repo: ArgoRepository) -> None:
        self._valkey_url = valkey_url
        self._repo = repo
        self._client: Any = None
        self.connected = False
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._fallback_locks: dict[str, tuple[str, float]] = {}
        self._fallback_seen: dict[str, float] = {}
        self._state_lock = asyncio.Lock()

    async def connect(self) -> bool:
        """Connect to Valkey 9.1 and ensure the consumer group exists."""
        try:
            import valkey.asyncio as valkey_async  # type: ignore[import-not-found]
        except ImportError:
            self.connected = False
            logger.info("valkey-py not installed; EventBus running with in-memory fallback.")
            return False

        try:
            client = valkey_async.from_url(self._valkey_url, decode_responses=True)
            await asyncio.wait_for(client.ping(), timeout=1.5)
            try:
                await client.xgroup_create(STREAM_NAME, CONSUMER_GROUP, id="0", mkstream=True)
            except Exception as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
            self._client = client
            self.connected = True
            return True
        except Exception as exc:
            logger.warning("Valkey unavailable (%s); using in-memory bus fallback.", exc)
            self._client = None
            self.connected = False
            return False

    async def close(self) -> None:
        """Close the Valkey client if connected."""
        if self._client is not None:
            close_fn = getattr(self._client, "aclose", None) or getattr(self._client, "close", None)
            if close_fn is not None:
                res = close_fn()
                if asyncio.iscoroutine(res):
                    await res
        self._client = None
        self.connected = False

    def _prune_expired(self, now: float) -> None:
        expired_locks = [k for k, (_, exp) in self._fallback_locks.items() if exp <= now]
        for key in expired_locks:
            del self._fallback_locks[key]
        expired_seen = [k for k, exp in self._fallback_seen.items() if exp <= now]
        for key in expired_seen:
            del self._fallback_seen[key]

    async def acquire_lock(
        self,
        resource_type: str,
        resource_id: str,
        bot_slug: str,
        ttl_seconds: int = 300,
    ) -> bool:
        """Acquire a distributed resource mutex: SET argo:lock:<type>:<id> <bot> NX EX <ttl>."""
        key = f"argo:lock:{resource_type}:{resource_id}"
        if self.connected and self._client is not None:
            result = await self._client.set(key, bot_slug, nx=True, ex=ttl_seconds)
            return bool(result)

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            if key in self._fallback_locks:
                return False
            self._fallback_locks[key] = (bot_slug, now + ttl_seconds)
            return True

    async def release_lock(self, resource_type: str, resource_id: str, bot_slug: str) -> bool:
        """Release a distributed mutex only when held by the requesting bot."""
        key = f"argo:lock:{resource_type}:{resource_id}"
        if self.connected and self._client is not None:
            holder = await self._client.get(key)
            if holder == bot_slug:
                await self._client.delete(key)
                return True
            return False

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            entry = self._fallback_locks.get(key)
            if entry and entry[0] == bot_slug:
                del self._fallback_locks[key]
                return True
            return False

    async def check_and_mark_seen(self, event_id: str, ttl_seconds: int = 86400) -> bool:
        """Return True on first observation of event_id; False if already seen."""
        key = f"argo:seen:{event_id}"
        if self.connected and self._client is not None:
            result = await self._client.set(key, "1", nx=True, ex=ttl_seconds)
            return bool(result)

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            if key in self._fallback_seen:
                return False
            self._fallback_seen[key] = now + ttl_seconds
            return True

    async def publish(
        self,
        correlation_id: str,
        source_slug: str,
        event_type: str,
        payload: dict[str, Any],
        target_slug: str | None = None,
        hop_count: int = 1,
    ) -> dict[str, Any]:
        """Validate loop hop limit, persist to SQLite, emit to Valkey, and notify SSE clients."""
        if hop_count > MAX_HOP_COUNT:
            raise HopLimitExceededError(
                f"Event {event_type} halted: hop_count={hop_count} exceeds limit {MAX_HOP_COUNT}."
            )

        enriched_payload = {**payload, "hop_count": hop_count}
        event_record = self._repo.record_event(
            correlation_id=correlation_id,
            source_slug=source_slug,
            target_slug=target_slug,
            event_type=event_type,
            payload=enriched_payload,
        )

        if self.connected and self._client is not None:
            try:
                await self._client.xadd(
                    STREAM_NAME,
                    {
                        "id": event_record["id"],
                        "correlation_id": correlation_id,
                        "source_slug": source_slug,
                        "target_slug": target_slug or "",
                        "event_type": event_type,
                        "hop_count": str(hop_count),
                    },
                )
            except Exception as exc:
                logger.warning("Failed to append event to Valkey stream: %s", exc)

        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(event_record)

        return event_record

    async def emit_ephemeral(self, event_name: str, payload: dict[str, Any]) -> None:
        """Broadcast a lightweight ephemeral event over SSE without persisting to SQLite or Valkey."""
        enriched: dict[str, Any] = {**payload, "_sse_event": event_name}
        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(enriched)

    async def emit_progress(
        self,
        bot_slug: str,
        state: str,
        step: str = "",
        correlation_id: str = "",
    ) -> None:
        """Broadcast lightweight live bot execution progress over SSE without persisting to SQLite."""
        await self.emit_ephemeral(
            "bot_progress",
            {
                "bot_slug": bot_slug,
                "state": state,
                "step": step,
                "correlation_id": correlation_id,
            },
        )

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        """Subscribe to live bus events for SSE streaming."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
