"""Regression tests for chunked aiohttp reading, public JSON fetch handling, DuckDB JSON fallbacks, and per-action runner resilience."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.analytics.engine import ingest_file_to_analytics, read_dataset_rows  # noqa: E402
from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.security.ssrf import (  # noqa: E402
    AntiBotHaltError,
    PublicFetchError,
    PublicHttpResponse,
    SafePublicHttpFetcher,
    SSRFBlockedError,
)
from argo_core.tools.public_web import fetch_public_webpage  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class TestWebFetchAndActionResilience(unittest.TestCase):
    """Verify full-EOF aiohttp reads, paginated JSON fetching, DuckDB fallback, and error isolation."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport: Any = None, public_http_fetcher: Any = None) -> Any:
        db_path = Path(tmp) / "web_resilience.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text("<html><body>Argo</body></html>", encoding="utf-8")
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 32.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 12.0,
                "disk_percent": 20.0,
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            valkey_url="valkey://127.0.0.1:1/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            workspace_files_root=str(Path(tmp) / "workspace_files"),
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            public_http_fetcher=public_http_fetcher,
        )

    def test_aiohttp_chunked_stream_reads_full_body_to_eof_and_respects_max_bytes(self) -> None:
        large_payload = json.dumps(
            {
                "items": [
                    {
                        "id": idx,
                        "product": "grafana",
                        "version": f"13.{idx % 10}.{idx}",
                        "padding": "x" * 64,
                    }
                    for idx in range(4000)
                ]
            }
        ).encode("utf-8")
        self.assertGreater(len(large_payload), 450_000)

        read_calls: list[int] = []

        class _ChunkedStreamReader:
            def __init__(self, data: bytes, chunk_cap: int = 31_744) -> None:
                self._data = data
                self._pos = 0
                self._chunk_cap = chunk_cap

            async def read(self, n: int = -1) -> bytes:
                read_calls.append(n)
                if self._pos >= len(self._data):
                    return b""
                take = len(self._data) - self._pos if n < 0 else min(n, self._chunk_cap, len(self._data) - self._pos)
                chunk = self._data[self._pos : self._pos + take]
                self._pos += take
                return chunk

        class _FakeAiohttpResponse:
            def __init__(self, url: str, payload: bytes) -> None:
                self.url = url
                self.status = 200
                self.headers = {"Content-Type": "application/json; charset=utf-8"}
                self.content = _ChunkedStreamReader(payload)

            async def __aenter__(self) -> _FakeAiohttpResponse:
                return self

            async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                return False

        def _make_fake_aiohttp(payload: bytes) -> types.ModuleType:
            mod = types.ModuleType("aiohttp")
            mod.abc = types.SimpleNamespace(AbstractResolver=object)  # type: ignore[attr-defined]
            mod.ClientTimeout = lambda **_kw: None  # type: ignore[attr-defined]
            mod.TCPConnector = lambda **_kw: None  # type: ignore[attr-defined]

            class _FakeSession:
                def __init__(self, **_kw: Any) -> None:
                    pass

                async def __aenter__(self) -> _FakeSession:
                    return self

                async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                    return False

                def request(self, _method: str, req_url: str, **_kw: Any) -> _FakeAiohttpResponse:
                    return _FakeAiohttpResponse(req_url, payload)

            mod.ClientSession = _FakeSession  # type: ignore[attr-defined]
            return mod

        fetcher = SafePublicHttpFetcher(resolver=lambda _host: ["93.184.216.34"])

        # 1) Full-EOF read stitches all partial chunks > 251 KB cleanly without truncation
        read_calls.clear()
        with patch.dict(sys.modules, {"aiohttp": _make_fake_aiohttp(large_payload)}):
            res_full = asyncio.run(
                fetcher.fetch("https://grafana.com/api/grafana/versions", max_bytes=10_485_760)
            )
        self.assertGreater(len(read_calls), 10)
        self.assertEqual(len(res_full.raw_bytes), len(large_payload))
        parsed = json.loads(res_full.body)
        self.assertEqual(len(parsed["items"]), 4000)
        self.assertEqual(parsed["items"][-1]["version"], f"13.{3999 % 10}.3999")

        # 2) Tight max_bytes cap truncates cleanly without reading past limit
        read_calls.clear()
        with patch.dict(sys.modules, {"aiohttp": _make_fake_aiohttp(large_payload)}):
            res_capped = asyncio.run(
                fetcher.fetch("https://grafana.com/api/grafana/versions", max_bytes=50_000)
            )
        self.assertEqual(len(res_capped.raw_bytes), 50_000)
        self.assertLessEqual(len(read_calls), 3)

    def test_fetch_public_webpage_json_apis_pagination_redaction_and_malformed_json(self) -> None:
        secret_val = "secret-grafana-api-key-98765"
        items = [
            {
                "id": idx,
                "version": "13.3.1" if idx == 65 else f"13.4.0-nightly-{idx}",
                "stable": idx == 65,
                "notes": secret_val if idx == 1 else "release build",
            }
            for idx in range(120)
        ]
        grafana_json = json.dumps({"items": items}, indent=2)
        self.assertGreater(len(grafana_json), 10_000)
        self.assertGreater(grafana_json.find("13.3.1"), 5_000)

        malformed_json = '{"items": [{"id": 1, "version": "13.3.1"'

        class _RoutingStubFetcher:
            async def fetch(
                self, url: str, headers: dict[str, str] | None = None, max_bytes: int = 10_485_760
            ) -> PublicHttpResponse:
                del headers, max_bytes
                if url == "https://grafana.com/api/grafana/versions":
                    return PublicHttpResponse(
                        url=url,
                        status_code=200,
                        headers={"content-type": "application/json; charset=utf-8"},
                        body=grafana_json,
                        raw_bytes=grafana_json.encode("utf-8"),
                    )
                if url == "https://api.github.com/repos/grafana/grafana/releases/latest":
                    gh_body = json.dumps({"tag_name": "v13.3.1", "prerelease": False})
                    return PublicHttpResponse(
                        url=url,
                        status_code=200,
                        headers={"content-type": "application/vnd.github+json"},
                        body=gh_body,
                        raw_bytes=gh_body.encode("utf-8"),
                    )
                if url == "https://bad.example.org/truncated.json":
                    return PublicHttpResponse(
                        url=url,
                        status_code=200,
                        headers={"content-type": "application/json"},
                        body=malformed_json,
                        raw_bytes=malformed_json.encode("utf-8"),
                    )
                if url == "https://bad.example.org/broken.pdf":
                    raw = b"%PDF-not-a-valid-pdf-stream"
                    return PublicHttpResponse(
                        url=url,
                        status_code=200,
                        headers={"content-type": "application/pdf"},
                        body=raw.decode("utf-8", errors="replace"),
                        raw_bytes=raw,
                    )
                raise AssertionError(f"Unexpected URL: {url}")

        fetcher = _RoutingStubFetcher()
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, public_http_fetcher=fetcher)
            with TestClient(app) as client:
                vault_resp = client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Grafana Key",
                        "slug": "grafana-key",
                        "secret_type": "api_token",
                        "secrets": {"token": secret_val},
                        "allowed_bots": [],
                    },
                )
                self.assertEqual(vault_resp.status_code, 201, vault_resp.text)
                repo = app.state.repo

                p1 = asyncio.run(
                    fetch_public_webpage(
                        "https://grafana.com/api/grafana/versions",
                        repo=repo,
                        fetcher=fetcher,
                        max_chars=5000,
                        offset=0,
                    )
                )
                self.assertEqual(p1["title"], "versions")
                self.assertTrue(p1["has_more"])
                self.assertEqual(p1["next_offset"], 5000)
                self.assertNotIn(secret_val, p1["markdown"])
                self.assertIn("REDACTED", p1["markdown"])
                self.assertNotIn("items |", p1["markdown"])

                p2 = asyncio.run(
                    fetch_public_webpage(
                        "https://grafana.com/api/grafana/versions",
                        repo=repo,
                        fetcher=fetcher,
                        max_chars=5000,
                        offset=5000,
                    )
                )
                self.assertIn('"13.3.1"', p2["markdown"])

                gh = asyncio.run(
                    fetch_public_webpage(
                        "https://api.github.com/repos/grafana/grafana/releases/latest",
                        repo=repo,
                        fetcher=fetcher,
                        max_chars=5000,
                    )
                )
                self.assertIn('"tag_name": "v13.3.1"', gh["markdown"])

                bad_json_res = asyncio.run(
                    fetch_public_webpage(
                        "https://bad.example.org/truncated.json",
                        repo=repo,
                        fetcher=fetcher,
                        max_chars=5000,
                    )
                )
                self.assertEqual(bad_json_res["title"], "truncated.json")
                self.assertIn('"version": "13.3.1"', bad_json_res["markdown"])

                with self.assertRaises(PublicFetchError):
                    asyncio.run(
                        fetch_public_webpage(
                            "https://bad.example.org/broken.pdf",
                            repo=repo,
                            fetcher=fetcher,
                        )
                    )

    def test_ingest_file_to_analytics_json_ndjson_recovery_and_malformed_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            valid_src = root / "valid.json"
            valid_src.write_text(
                json.dumps([{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]),
                encoding="utf-8",
            )
            valid_der = root / "valid_derived"
            res_ok = ingest_file_to_analytics(
                valid_src,
                valid_der,
                file_id="file_ok",
                filename="valid.json",
                mime_type="application/json",
            )
            self.assertEqual(res_ok["derived_datasets"][0]["row_count"], 2)

            ndjson_src = root / "partial.ndjson"
            ndjson_src.write_text('{"id": 1}\n{"id": 2}\n{"id": 3', encoding="utf-8")
            ndjson_der = root / "ndjson_derived"
            res_ndjson = ingest_file_to_analytics(
                ndjson_src,
                ndjson_der,
                file_id="file_ndjson",
                filename="partial.ndjson",
                mime_type="application/x-ndjson",
            )
            self.assertEqual(res_ndjson["derived_datasets"][0]["row_count"], 2)
            _cols, rows, total = read_dataset_rows(ndjson_der / res_ndjson["default_parquet_name"])
            self.assertEqual(total, 2)
            self.assertEqual([r["id"] for r in rows], [1, 2])

            corrupt_src = root / "corrupt.json"
            corrupt_src.write_text('{"broken": [not_valid_json', encoding="utf-8")
            corrupt_der = root / "corrupt_derived"
            with self.assertRaises(ValueError) as ctx:
                ingest_file_to_analytics(
                    corrupt_src,
                    corrupt_der,
                    file_id="file_bad",
                    filename="corrupt.json",
                    mime_type="application/json",
                )
            self.assertIn("Malformed JSON", str(ctx.exception))

    def test_bot_runner_action_error_boundary_and_queued_thread_error_persistence(self) -> None:
        observed_errors: list[dict[str, Any]] = []

        class _ErrorRaisingFetcher:
            async def fetch(
                self, url: str, headers: dict[str, str] | None = None, max_bytes: int = 10_485_760
            ) -> PublicHttpResponse:
                del headers, max_bytes
                if "antibot" in url:
                    raise AntiBotHaltError(
                        url=url,
                        status_code=403,
                        reason="Halted cleanly on anti-bot gate (HTTP 403).",
                    )
                if "ssrf" in url:
                    raise SSRFBlockedError("Loopback address '127.0.0.1' is disallowed.")
                raise PublicFetchError(url=url, status_code=502, message="Upstream HTTP 502 bad gateway")

        async def _error_aware_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            obs = list(env.get("tool_observations") or [])
            text = str(env.get("text") or env.get("task") or "")
            if not obs:
                target_url = "https://example.com/fail"
                if "antibot" in text.lower():
                    target_url = "https://example.com/antibot"
                elif "ssrf" in text.lower():
                    target_url = "http://127.0.0.1/ssrf"
                return {
                    "text": json.dumps(
                        {
                            "summary": "",
                            "actions": [{"type": "fetch_public_webpage", "url": target_url}],
                        }
                    ),
                    "input_tokens": 10,
                    "output_tokens": 12,
                }
            observed_errors.append(dict(obs[-1]))
            return {
                "text": json.dumps(
                    {
                        "summary": f"Handled tool error ({obs[-1].get('status')}): {obs[-1].get('detail')}",
                        "actions": [],
                    }
                ),
                "input_tokens": 15,
                "output_tokens": 14,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=_error_aware_llm,
                public_http_fetcher=_ErrorRaisingFetcher(),
            )
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "web-checker",
                        "name": "Web Checker",
                        "role": "Check public websites",
                        "outbound_rbac": "internal",
                        "tools": ["fetch_public_webpage"],
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "helper-bot",
                        "name": "Helper Bot",
                        "role": "General helper",
                        "outbound_rbac": "internal",
                    },
                )
                room_resp = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Check Room",
                        "member_bot_slugs": ["web-checker", "helper-bot"],
                        "coordinator_bot_slug": "web-checker",
                        "routing_mode": "auto",
                    },
                )
                self.assertEqual(room_resp.status_code, 201, room_resp.text)
                room = room_resp.json()

                # 1) Room turn recovers gracefully when fetch_public_webpage raises PublicFetchError
                r_room = client.post(
                    f"/api/rooms/{room['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "@web-checker please check https://example.com/fail"},
                )
                self.assertEqual(r_room.status_code, 200, r_room.text)
                last_msg = r_room.json()["messages"][-1]
                self.assertEqual(last_msg["sender_slug"], "web-checker")
                self.assertIn("Handled tool error (error): Upstream HTTP 502 bad gateway", last_msg["text"])
                self.assertEqual(observed_errors[-1]["status"], "error")

                # 2) AntiBotHaltError and SSRFBlockedError are caught per action and suppress habit_proposal
                r_ab = client.post(
                    "/api/bots/web-checker/messages",
                    headers=self._sso_headers(),
                    json={"text": "Check antibot page"},
                )
                self.assertEqual(r_ab.status_code, 200, r_ab.text)
                ab_res = r_ab.json()["result"]
                self.assertIn("halted_antibot", ab_res["summary"])
                self.assertNotIn("habit_proposal", ab_res.get("metadata") or {})
                self.assertEqual(observed_errors[-1]["status"], "halted_antibot")

                r_ssrf = client.post(
                    "/api/bots/web-checker/messages",
                    headers=self._sso_headers(),
                    json={"text": "Check ssrf page"},
                )
                self.assertEqual(r_ssrf.status_code, 200, r_ssrf.text)
                ssrf_res = r_ssrf.json()["result"]
                self.assertIn("blocked_ssrf", ssrf_res["summary"])
                self.assertNotIn("habit_proposal", ssrf_res.get("metadata") or {})
                self.assertEqual(observed_errors[-1]["status"], "blocked_ssrf")

                # 3) Uncaught exception inside queued Room turn persists visible failure message + run_finished(error)
                captured_stream: list[dict[str, Any]] = []
                orig_emit = app.state.bus.emit_ephemeral

                async def _spy_emit(event_name: str, payload: dict[str, Any]) -> None:
                    if event_name == "turn_stream":
                        captured_stream.append(dict(payload))
                    await orig_emit(event_name, payload)

                app.state.bus.emit_ephemeral = _spy_emit

                async def _exercise_queued_failure() -> Any:
                    async def _boom(_item: Any) -> dict[str, Any]:
                        raise RuntimeError("Simulated fatal turn failure")

                    item, _ = app.state.bot_runner.enqueue_thread_turn(
                        thread_key=f"room:{room['slug']}",
                        target_type="room",
                        target_slug=room["slug"],
                        correlation_id="corr_fatal_test",
                        bot_slug="web-checker",
                        bot_name="Web Checker",
                        work=_boom,
                    )
                    await asyncio.wait_for(item.done_event.wait(), timeout=3.0)
                    return item

                assert client.portal is not None
                failed_item = client.portal.call(_exercise_queued_failure)
                self.assertEqual(failed_item.status, "error")
                self.assertIsNotNone(failed_item.message_id)

                room_msgs, _, _ = app.state.repo.list_room_messages_window(room["slug"], limit=20)
                err_msgs = [m for m in room_msgs if (m.get("metadata") or {}).get("run_error") is True]
                self.assertEqual(len(err_msgs), 1)
                self.assertEqual(err_msgs[0]["id"], failed_item.message_id)
                self.assertIn("Run failed before completing: Simulated fatal turn failure", err_msgs[0]["text"])
                self.assertTrue(
                    any(
                        e.get("type") == "run_finished"
                        and e.get("run_id") == failed_item.run_id
                        and e.get("status") == "error"
                        and e.get("message_id") == failed_item.message_id
                        for e in captured_stream
                    )
                )


if __name__ == "__main__":
    unittest.main()
