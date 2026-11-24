"""Valkey 9.1 Streams, consumer groups, atomic Lua mutex locks, idempotency, and live SSE subscribers."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

from argo_core.db.repositories import ArgoRepository

logger = logging.getLogger(__name__)

MAX_HOP_COUNT = 5
STREAM_NAME = "argo:events"
CONSUMER_GROUP = "argo-runner"
STREAM_MAXLEN = 10000

_RELEASE_LOCK_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) "
    "else return 0 end"
)
_RENEW_LOCK_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('expire', KEYS[1], tonumber(ARGV[2])) "
    "else return 0 end"
)


class HopLimitExceededError(ValueError):
    """Raised when an inter-bot handoff exceeds the Valkey loop guard (hop_count > 5)."""


class DurableEventConsumer:
    """Durable consumer wrapping Valkey XREADGROUP/XACK with isolated in-memory fallback."""

    def __init__(
        self,
        bus: EventBus,
        consumer_name: str,
        *,
        fallback_queue: asyncio.Queue[tuple[str | None, dict[str, Any]]] | None = None,
    ) -> None:
        self._bus = bus
        self._consumer_name = consumer_name
        self._fallback_queue = fallback_queue
        self._buffer: asyncio.Queue[tuple[str | None, dict[str, Any]]] = asyncio.Queue()
        self._read_pending = True

    def empty(self) -> bool:
        if not self._buffer.empty():
            return False
        if self._fallback_queue is not None:
            return self._fallback_queue.empty()
        return True

    def get_nowait(self) -> tuple[str | None, dict[str, Any]]:
        if not self._buffer.empty():
            return self._buffer.get_nowait()
        if self._fallback_queue is not None:
            return self._fallback_queue.get_nowait()
        raise asyncio.QueueEmpty()

    async def get(self, *, count: int = 20, block_ms: int = 250) -> tuple[str | None, dict[str, Any]]:
        if not self._buffer.empty():
            return self._buffer.get_nowait()

        if self._bus.connected and self._bus._client is not None:
            while True:
                if not self._buffer.empty():
                    return self._buffer.get_nowait()
                stream_id = "0" if self._read_pending else ">"
                raw = await self._bus._client.xreadgroup(
                    CONSUMER_GROUP,
                    self._consumer_name,
                    {STREAM_NAME: stream_id},
                    count=count,
                    block=None if self._read_pending else block_ms,
                )
                entries = self._bus._extract_xreadgroup_entries(raw)
                if self._read_pending:
                    self._read_pending = False
                    if not entries:
                        continue
                if entries:
                    for item in entries:
                        await self._buffer.put(item)
                    return self._buffer.get_nowait()
                if self._fallback_queue is not None and not self._fallback_queue.empty():
                    return self._fallback_queue.get_nowait()
                await asyncio.sleep(0)

        assert self._fallback_queue is not None
        return await self._fallback_queue.get()

    async def ack(self, entry_id: str | None) -> None:
        await self._bus.ack_event(entry_id)


class EventBus:
    """Async Valkey Streams + atomic mutex bus separated cleanly from ephemeral SSE frames."""

    def __init__(self, valkey_url: str, repo: ArgoRepository) -> None:
        self._valkey_url = valkey_url
        self._repo = repo
        self._client: Any = None
        self.connected = False
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._durable_subscribers: set[asyncio.Queue[tuple[str | None, dict[str, Any]]]] = set()
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
        owner_token: str,
        ttl_seconds: int = 300,
    ) -> bool:
        """Acquire a distributed resource mutex: SET argo:lock:<type>:<id> <owner_token> NX EX <ttl>."""
        key = f"argo:lock:{resource_type}:{resource_id}"
        if self.connected and self._client is not None:
            result = await self._client.set(key, owner_token, nx=True, ex=ttl_seconds)
            return bool(result)

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            if key in self._fallback_locks:
                return False
            self._fallback_locks[key] = (owner_token, now + ttl_seconds)
            return True

    async def renew_lock(
        self,
        resource_type: str,
        resource_id: str,
        owner_token: str,
        ttl_seconds: int = 300,
    ) -> bool:
        """Atomically extend lock TTL only when still held by owner_token."""
        key = f"argo:lock:{resource_type}:{resource_id}"
        if self.connected and self._client is not None:
            eval_fn = getattr(self._client, "eval", None)
            if callable(eval_fn):
                res = await eval_fn(_RENEW_LOCK_LUA, 1, key, owner_token, str(int(ttl_seconds)))
                return bool(res)
            holder = await self._client.get(key)
            if holder == owner_token and hasattr(self._client, "expire"):
                return bool(await self._client.expire(key, int(ttl_seconds)))
            return False

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            entry = self._fallback_locks.get(key)
            if entry and entry[0] == owner_token:
                self._fallback_locks[key] = (owner_token, now + ttl_seconds)
                return True
            return False

    async def release_lock(self, resource_type: str, resource_id: str, owner_token: str) -> bool:
        """Atomically release a distributed mutex only when held by owner_token."""
        key = f"argo:lock:{resource_type}:{resource_id}"
        if self.connected and self._client is not None:
            eval_fn = getattr(self._client, "eval", None)
            if callable(eval_fn):
                res = await eval_fn(_RELEASE_LOCK_LUA, 1, key, owner_token)
                return bool(res)
            holder = await self._client.get(key)
            if holder == owner_token:
                await self._client.delete(key)
                return True
            return False

        async with self._state_lock:
            now = time.monotonic()
            self._prune_expired(now)
            entry = self._fallback_locks.get(key)
            if entry and entry[0] == owner_token:
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

    def _decode_stream_entry(self, entry_id: Any, fields: Any) -> tuple[str | None, dict[str, Any]] | None:
        if isinstance(fields, list):
            it = iter(fields)
            fields_map = {str(k): v for k, v in zip(it, it)}
        elif isinstance(fields, dict):
            fields_map = {str(k): v for k, v in fields.items()}
        else:
            return None
        raw_payload = fields_map.get("payload_json")
        payload_obj: dict[str, Any] = {}
        if isinstance(raw_payload, str) and raw_payload.strip():
            with suppress(Exception):
                loaded = json.loads(raw_payload)
                if isinstance(loaded, dict):
                    payload_obj = loaded
        record = {
            "id": str(fields_map.get("id") or ""),
            "correlation_id": str(fields_map.get("correlation_id") or ""),
            "source_slug": str(fields_map.get("source_slug") or ""),
            "target_slug": str(fields_map.get("target_slug") or "") or None,
            "event_type": str(fields_map.get("event_type") or ""),
            "payload": payload_obj,
        }
        return str(entry_id) if entry_id is not None else None, record

    def _extract_xreadgroup_entries(self, raw: Any) -> list[tuple[str | None, dict[str, Any]]]:
        items: list[tuple[str | None, dict[str, Any]]] = []
        if not raw:
            return items
        if isinstance(raw, dict):
            stream_batches = list(raw.values())
        elif isinstance(raw, list):
            stream_batches = [
                batch[1]
                for batch in raw
                if isinstance(batch, (list, tuple)) and len(batch) >= 2
            ]
        else:
            return items
        for batch in stream_batches:
            if not isinstance(batch, list):
                continue
            for pair in batch:
                if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                    continue
                decoded = self._decode_stream_entry(pair[0], pair[1])
                if decoded is not None:
                    items.append(decoded)
        return items

    async def ack_event(self, entry_id: str | None) -> None:
        """Acknowledge processed Valkey Stream entry via XACK."""
        if entry_id and self.connected and self._client is not None:
            with suppress(Exception):
                await self._client.xack(STREAM_NAME, CONSUMER_GROUP, entry_id)

    async def publish(
        self,
        correlation_id: str,
        source_slug: str,
        event_type: str,
        payload: dict[str, Any],
        target_slug: str | None = None,
        hop_count: int = 1,
    ) -> dict[str, Any]:
        """Validate loop hop limit, persist to SQLite, emit to bounded Valkey Stream, and notify subscribers."""
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

        stream_written = False
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
                        "payload_json": json.dumps(enriched_payload, ensure_ascii=False, default=str),
                    },
                    maxlen=STREAM_MAXLEN,
                    approximate=True,
                )
                stream_written = True
            except Exception as exc:
                logger.warning("Failed to append event to Valkey stream: %s", exc)

        if not stream_written:
            for dqueue in list(self._durable_subscribers):
                await dqueue.put((None, event_record))

        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(event_record)

        return event_record

    async def emit_ephemeral(self, event_name: str, payload: dict[str, Any]) -> None:
        """Broadcast a lightweight ephemeral event over SSE without polluting durable queues."""
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
    async def subscribe_durable(
        self,
        consumer_name: str = "runner-main",
    ) -> AsyncIterator[DurableEventConsumer]:
        """Subscribe to durable domain/orchestration events isolated from ephemeral SSE traffic."""
        fallback_queue: asyncio.Queue[tuple[str | None, dict[str, Any]]] = asyncio.Queue(maxsize=2000)
        self._durable_subscribers.add(fallback_queue)
        consumer = DurableEventConsumer(
            self,
            consumer_name=consumer_name,
            fallback_queue=fallback_queue,
        )
        try:
            yield consumer
        finally:
            self._durable_subscribers.discard(fallback_queue)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        """Subscribe to live bus events for SSE streaming."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
