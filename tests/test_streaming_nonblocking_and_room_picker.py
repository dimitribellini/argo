"""Tests for live streaming replies, tool chips, non-blocking send queue, mid-run cancel, and Group Room auto-picker."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.llm.router import LLMRequest, LLMRouter  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.runner.bot_runner import (  # noqa: E402
    _IncrementalSummaryExtractor,
    _compose_envelope_reply_text,
    _extract_json_envelope_with_prose,
)
from argo_core.security.ssrf import PublicHttpResponse  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class TestStreamingNonBlockingAndRoomPicker(unittest.TestCase):
    """Verify SSE token streaming, tool chips, async queueing, cancellation, and <800ms Room routing."""

    @staticmethod
    def _sso_headers(email: str = "operator@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None, public_http_fetcher=None):
        db_path = Path(tmp) / "argo.db"
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
            valkey_url="valkey://127.0.0.1:6399/0",
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

    def test_incremental_summary_extractor_handles_actions_first_escapes_and_surrogates(self) -> None:
        raw_envelope = (
            '```json\n'
            '{"actions": [{"type": "upsert_document", "summary": "NESTED_MUST_NOT_LEAK"}], '
            '"summary": "Hello \\"Argo\\"\\nLine 2 \\uD83D\\uDE80 rocket ready!"}'
            '\n```'
        )
        extractor = _IncrementalSummaryExtractor()
        emitted: list[str] = []
        for idx in range(0, len(raw_envelope), 3):
            out = extractor.feed(raw_envelope[idx : idx + 3])
            if out:
                emitted.append(out)
        tail = extractor.finish()
        if tail:
            emitted.append(tail)

        combined = "".join(emitted)
        self.assertEqual(combined, 'Hello "Argo"\nLine 2 🚀 rocket ready!')
        self.assertNotIn("NESTED_MUST_NOT_LEAK", combined)
        self.assertNotIn("{", combined)
        self.assertNotIn('"actions"', combined)

        # Plain-text passthrough
        plain = _IncrementalSummaryExtractor()
        self.assertEqual(plain.feed("Plain ") + plain.feed("answer.") + plain.finish(), "Plain answer.")

    def test_streaming_summary_scrubs_chunk_split_secrets_and_reconciles_tokens(self) -> None:
        secret_value = "s3cr3t-vault-token-XYZ987"

        async def streaming_llm(_req: LLMRequest) -> dict[str, Any]:
            full_json = json.dumps(
                {
                    "summary": f"Deployment verified cleanly using secret {secret_value} for host.",
                    "actions": [{"type": "remember_rule", "rule_text": "Keep deploys crisp"}],
                }
            )
            # Split deliberately inside the secret and across JSON framing
            chunks = [full_json[i : i + 5] for i in range(0, len(full_json), 5)]
            return {
                "chunks": chunks,
                "chunk_delay_s": 0.005,
                "input_tokens": 42,
                "output_tokens": 18,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=streaming_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/vault",
                    headers=self._sso_headers(),
                    json={
                        "name": "Deploy Token",
                        "slug": "deploy-token",
                        "secret_type": "api_token",
                        "secrets": {"token": secret_value},
                        "allowed_bots": ["*"],
                    },
                )
                bot = client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "stream-bot",
                        "name": "Stream Bot",
                        "role": "Deployment checker",
                    },
                ).json()

                captured_events: list[dict[str, Any]] = []

                async def run_and_collect() -> None:
                    async with app.state.bus.subscribe() as queue:
                        res = await app.state.bot_runner.execute_bot(
                            bot["slug"],
                            trigger_type="manual",
                            trigger_payload={
                                "input_text": "Check deploy status",
                                "text": "Check deploy status",
                                "from_chat_thread": True,
                            },
                        )
                        self.assertEqual(res["status"], "completed")
                        while not queue.empty():
                            ev = queue.get_nowait()
                            if ev.get("_sse_event") == "turn_stream":
                                captured_events.append(ev)

                asyncio.run(run_and_collect())

                deltas = [e["delta"] for e in captured_events if e.get("type") == "text_delta"]
                streamed_text = "".join(deltas)
                self.assertIn("Deployment verified cleanly", streamed_text)
                self.assertNotIn(secret_value, streamed_text)
                self.assertIn("<REDACTED>", streamed_text)
                self.assertNotIn('"actions"', streamed_text)
                self.assertNotIn("{", streamed_text)

                runs = client.get(f"/api/runs?bot_slug={bot['slug']}", headers=self._sso_headers()).json()
                self.assertEqual(runs[0]["status"], "success")
                self.assertEqual(runs[0]["input_tokens"], 42)
                self.assertEqual(runs[0]["output_tokens"], 18)

    def test_async_nonblocking_followup_queue_and_live_tool_chips(self) -> None:
        class SlowRssFetcher:
            def __init__(self) -> None:
                self.calls = 0

            async def fetch(self, url: str, **kwargs: Any) -> PublicHttpResponse:
                self.calls += 1
                await asyncio.sleep(0.18)
                rss_xml = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    "<rss version='2.0'><channel><title>Updates</title>"
                    "<item><title>Release 2.0</title><link>https://example.org/r2</link>"
                    "<guid>r2</guid><description>Highlights</description></item>"
                    "</channel></rss>"
                )
                return PublicHttpResponse(status_code=200, url=url, headers={}, body=rss_xml)

        call_order: list[str] = []

        async def chip_llm(req: LLMRequest) -> dict[str, Any]:
            if "tool_observations" not in req.user_prompt:
                parsed_prompt = json.loads(req.user_prompt)
                cur_input = str(parsed_prompt.get("trigger_payload", {}).get("input_text") or "")
                if "First request" in cur_input:
                    call_order.append("first_tool")
                    return {
                        "chunks": [
                            '{"summary": "Checking feed first...", ',
                            '"actions": [{"type": "fetch_rss_feed", "url": "https://example.org/feed.xml"}]}',
                        ],
                        "chunk_delay_s": 0.01,
                        "input_tokens": 20,
                        "output_tokens": 12,
                    }
                call_order.append("second_reply")
                return {
                    "chunks": ['{"summary": "Follow-up answered cleanly.", "actions": []}'],
                    "input_tokens": 15,
                    "output_tokens": 8,
                }
            call_order.append("first_synthesis")
            return {
                "chunks": ['{"summary": "Found Release 2.0 in the RSS feed.", "actions": []}'],
                "input_tokens": 22,
                "output_tokens": 11,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(
                tmp,
                llm_transport=chip_llm,
                public_http_fetcher=SlowRssFetcher(),
            )
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "queue-bot",
                        "name": "Queue Bot",
                        "role": "RSS specialist",
                    },
                )

                captured_stream: list[dict[str, Any]] = []
                orig_emit = app.state.bus.emit_ephemeral

                async def spy_emit(event_name: str, payload: dict[str, Any]) -> None:
                    if event_name == "turn_stream":
                        captured_stream.append(dict(payload))
                    await orig_emit(event_name, payload)

                app.state.bus.emit_ephemeral = spy_emit

                t0 = time.monotonic()
                resp1 = client.post(
                    "/api/bots/queue-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "First request", "async_mode": True},
                )
                elapsed1_ms = (time.monotonic() - t0) * 1000
                self.assertEqual(resp1.status_code, 202, resp1.text)
                self.assertLess(elapsed1_ms, 100.0)
                body1 = resp1.json()
                self.assertEqual(body1["status"], "queued")
                self.assertTrue(body1["run_id"])
                self.assertEqual(body1["user_message"]["text"], "First request")

                # Send follow-up immediately while first turn is running
                resp2 = client.post(
                    "/api/bots/queue-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Second follow-up", "async_mode": True},
                )
                self.assertEqual(resp2.status_code, 202, resp2.text)
                body2 = resp2.json()
                self.assertGreaterEqual(body2["queued_behind"], 1)

                # Wait for queued background worker to complete both turns sequentially
                deadline = time.monotonic() + 5.0
                msgs: list[dict[str, Any]] = []
                while time.monotonic() < deadline:
                    msgs = client.get("/api/bots/queue-bot/messages", headers=self._sso_headers()).json()
                    bot_replies = [m for m in msgs if m["sender"] == "bot" and "Found Release 2.0" in m["text"] or "Follow-up answered cleanly." in m["text"]]
                    if len(bot_replies) >= 2:
                        break
                    time.sleep(0.05)

                self.assertEqual(call_order, ["first_tool", "first_synthesis", "second_reply"])
                user_texts = [m["text"] for m in msgs if m["sender"] == "user"]
                self.assertEqual(user_texts, ["First request", "Second follow-up"])
                bot_texts = [m["text"] for m in msgs if m["sender"] == "bot" and (m.get("metadata") or {}).get("run_id")]
                self.assertIn("Found Release 2.0 in the RSS feed.", bot_texts[0])
                self.assertIn("Follow-up answered cleanly.", bot_texts[1])

                chip_starts = [e for e in captured_stream if e.get("type") == "chip_started"]
                chip_finishes = [e for e in captured_stream if e.get("type") == "chip_finished"]
                self.assertTrue(any(c.get("action_type") == "fetch_rss_feed" for c in chip_starts))
                self.assertTrue(
                    any(c.get("action_type") == "fetch_rss_feed" and c.get("status") == "done" and c.get("elapsed_ms", 0) >= 100 for c in chip_finishes)
                )
                # Discovery preface reset before final synthesis
                self.assertTrue(any(e.get("type") == "text_reset" for e in captured_stream))

    def test_mid_run_cancel_saves_partial_text_and_releases_locks(self) -> None:
        async def slow_stream_llm(req: LLMRequest) -> dict[str, Any]:
            if "Quick follow-up" in req.user_prompt:
                return {
                    "chunks": ['{"summary": "Follow-up ran cleanly after cancel.", "actions": []}'],
                    "input_tokens": 10,
                    "output_tokens": 8,
                }
            return {
                "chunks": [
                    '{"summary": "Partial progress saved ',
                    'before stop ',
                    'should_not_appear_1 ',
                    'should_not_appear_2 ',
                    'should_not_appear_3 ',
                    'should_not_appear_4", "actions": []}',
                ],
                "chunk_delay_s": 0.2,
                "input_tokens": 25,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=slow_stream_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "cancel-bot", "name": "Cancel Bot", "role": "Long runner"},
                )

                captured_stream: list[dict[str, Any]] = []
                orig_emit = app.state.bus.emit_ephemeral

                async def spy_emit(event_name: str, payload: dict[str, Any]) -> None:
                    if event_name == "turn_stream":
                        captured_stream.append(dict(payload))
                    await orig_emit(event_name, payload)

                app.state.bus.emit_ephemeral = spy_emit

                res = client.post(
                    "/api/bots/cancel-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Start long stream", "async_mode": True},
                )
                self.assertEqual(res.status_code, 202)
                run_id = res.json()["run_id"]

                # Wait until initial text_delta has been emitted
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    if any(
                        e.get("type") == "text_delta" and "Partial progress" in str(e.get("delta", ""))
                        for e in captured_stream
                    ):
                        break
                    time.sleep(0.02)

                cancel_resp = client.post(f"/api/runs/{run_id}/cancel", headers=self._sso_headers())
                self.assertEqual(cancel_resp.status_code, 200, cancel_resp.text)
                self.assertEqual(cancel_resp.json()["status"], "cancelled")
                self.assertTrue(cancel_resp.json()["message_id"])

                msgs = client.get("/api/bots/cancel-bot/messages", headers=self._sso_headers()).json()
                stopped_msg = msgs[-1]
                self.assertTrue(stopped_msg["metadata"].get("stopped_by_user"))
                self.assertIn("Partial progress saved", stopped_msg["text"])
                self.assertIn("(Stopped)", stopped_msg["text"])
                self.assertNotIn("should_not_appear_4", stopped_msg["text"])

                runs = client.get("/api/runs?bot_slug=cancel-bot", headers=self._sso_headers()).json()
                self.assertEqual(runs[0]["status"], "cancelled")
                self.assertTrue(any(e.get("type") == "run_cancelled" and e.get("run_id") == run_id for e in captured_stream))

                # Lock must be released: immediate follow-up works without locked_conflict
                followup = client.post(
                    "/api/bots/cancel-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Quick follow-up"},
                )
                self.assertEqual(followup.status_code, 200, followup.text)
                self.assertIn("Follow-up ran cleanly after cancel.", followup.json()["messages"][-1]["text"])

    def test_group_room_auto_picker_tiers_mentions_and_timeout_fallback(self) -> None:
        classifier_calls: list[str] = []
        slow_classifier = False

        async def room_picker_llm(req: LLMRequest) -> dict[str, Any]:
            if "Pick the single best Room member" in req.system_prompt:
                classifier_calls.append(req.user_prompt)
                if slow_classifier:
                    await asyncio.sleep(1.5)
                if "executive summary report" in req.user_prompt.lower():
                    return {
                        "text": json.dumps(
                            {"speaker": "report-writer", "reason": "Executive report drafting"}
                        ),
                        "input_tokens": 30,
                        "output_tokens": 12,
                    }
                return {
                    "text": json.dumps({"speaker": "lead-coord", "reason": "General coordination"}),
                    "input_tokens": 25,
                    "output_tokens": 10,
                }
            if "Visual Inspector" in req.system_prompt:
                return {"text": json.dumps({"summary": "Checked SSL and screenshot.", "actions": []}), "input_tokens": 10, "output_tokens": 8}
            if "Report Writer" in req.system_prompt:
                return {"text": json.dumps({"summary": "Drafted the executive summary.", "actions": []}), "input_tokens": 10, "output_tokens": 8}
            return {"text": json.dumps({"summary": "Lead coordinator handled request.", "actions": []}), "input_tokens": 10, "output_tokens": 8}

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=room_picker_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "lead-coord",
                        "name": "Lead Coord",
                        "role": "Team coordinator",
                        "role_prompt": "Lead Coord",
                        "runtime": "api",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "visual-inspector",
                        "name": "Visual Inspector",
                        "role": "Browser and SSL inspection specialist",
                        "role_prompt": "Visual Inspector",
                        "runtime": "desktop",
                    },
                )
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "report-writer",
                        "name": "Report Writer",
                        "role": "Executive summary and report writer",
                        "role_prompt": "Report Writer",
                        "runtime": "api",
                    },
                )

                rm = client.post(
                    "/api/rooms",
                    headers=self._sso_headers(),
                    json={
                        "title": "Ops Specialist Room",
                        "member_bot_slugs": ["lead-coord", "visual-inspector", "report-writer"],
                        "coordinator_bot_slug": "lead-coord",
                        "routing_mode": "auto",
                    },
                ).json()
                self.assertEqual(rm["routing_mode"], "auto")

                # 1. Tier 1 unique capability match (0 classifier LLM calls)
                classifier_calls.clear()
                r_cap = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Take a browser screenshot and inspect the SSL certificate"},
                )
                self.assertEqual(r_cap.status_code, 200, r_cap.text)
                self.assertEqual(len(classifier_calls), 0)
                reply_cap = r_cap.json()["messages"][-1]
                self.assertEqual(reply_cap["sender_slug"], "visual-inspector")
                self.assertEqual(reply_cap["metadata"]["routing_source"], "capability")
                self.assertIn("SSL", reply_cap["metadata"]["routed_reason"])

                # 2. Tier 2 micro-classifier picks Report Writer
                classifier_calls.clear()
                r_clf = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Draft the executive summary report for leadership"},
                )
                self.assertEqual(r_clf.status_code, 200, r_clf.text)
                self.assertEqual(len(classifier_calls), 1)
                reply_clf = r_clf.json()["messages"][-1]
                self.assertEqual(reply_clf["sender_slug"], "report-writer")
                self.assertEqual(reply_clf["metadata"]["routing_source"], "auto_picker")
                self.assertEqual(reply_clf["metadata"]["routed_reason"], "Executive report drafting")

                # 3. Explicit @mention and quote-reply bypass classifier (0 LLM calls)
                classifier_calls.clear()
                r_mention = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "@lead-coord please confirm next steps"},
                )
                self.assertEqual(r_mention.status_code, 200)
                self.assertEqual(len(classifier_calls), 0)
                self.assertEqual(r_mention.json()["messages"][-1]["sender_slug"], "lead-coord")
                self.assertEqual(r_mention.json()["messages"][-1]["metadata"]["routing_source"], "mention")

                classifier_calls.clear()
                r_reply = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Expand bullet one.", "reply_to_id": reply_clf["id"]},
                )
                self.assertEqual(r_reply.status_code, 200)
                self.assertEqual(len(classifier_calls), 0)
                self.assertEqual(r_reply.json()["messages"][-1]["sender_slug"], "report-writer")
                self.assertEqual(r_reply.json()["messages"][-1]["metadata"]["routing_source"], "reply")

                # 4. Simulated 1.5s slow classifier times out at <=0.8s and falls back to lead
                slow_classifier = True
                classifier_calls.clear()
                t_start = time.monotonic()
                r_timeout = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Summarize quarterly metrics"},
                )
                elapsed_s = time.monotonic() - t_start
                self.assertEqual(r_timeout.status_code, 200)
                self.assertLess(elapsed_s, 1.15)
                reply_to = r_timeout.json()["messages"][-1]
                self.assertEqual(reply_to["sender_slug"], "lead-coord")
                self.assertEqual(reply_to["metadata"]["routing_source"], "lead_fallback")
                slow_classifier = False

                # 5. PATCH routing_mode='stage' selects stage_order[0]
                rm_stage = client.patch(
                    f"/api/rooms/{rm['slug']}",
                    headers=self._sso_headers(),
                    json={"routing_mode": "stage", "stage_order": ["report-writer", "lead-coord", "visual-inspector"]},
                )
                self.assertEqual(rm_stage.status_code, 200)
                self.assertEqual(rm_stage.json()["routing_mode"], "stage")
                classifier_calls.clear()
                r_stage = client.post(
                    f"/api/rooms/{rm['slug']}/messages",
                    headers=self._sso_headers(),
                    json={"text": "Take a screenshot"},
                )
                self.assertEqual(r_stage.status_code, 200)
                self.assertEqual(len(classifier_calls), 0)
                self.assertEqual(r_stage.json()["messages"][-1]["sender_slug"], "report-writer")
                self.assertEqual(r_stage.json()["messages"][-1]["metadata"]["routing_source"], "stage")

    def test_pydantic_ai_stream_branch_and_ttfb_cancel(self) -> None:
        class _FakeStreamedResult:
            def __init__(self, *, chunks: list[str], slow_enter_s: float = 0.0, model_name: str = "") -> None:
                self._chunks = chunks
                self._slow_enter_s = slow_enter_s
                self.response = SimpleNamespace(model_name=model_name)

            async def __aenter__(self) -> _FakeStreamedResult:
                if self._slow_enter_s > 0:
                    await asyncio.sleep(self._slow_enter_s)
                return self

            async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
                return False

            async def stream_text(self, *, delta: bool = True):
                assert delta is True
                for chunk in self._chunks:
                    yield chunk
                    await asyncio.sleep(0.005)

            async def get_output(self) -> str:
                return "".join(self._chunks)

            @staticmethod
            def usage() -> Any:
                return SimpleNamespace(input_tokens=64, output_tokens=24)

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=None)
            with TestClient(app) as client:
                client.post(
                    "/api/models",
                    headers=self._sso_headers(),
                    json={
                        "slug": "google-primary",
                        "provider_type": "google",
                        "model_id": "google:gemini-3.8-flash",
                        "api_key": "test-google-key-AAA111",
                        "is_default": True,
                    },
                )
                client.post(
                    "/api/models",
                    headers=self._sso_headers(),
                    json={
                        "slug": "anthropic-backup",
                        "provider_type": "anthropic",
                        "model_id": "anthropic:claude-4-sonnet",
                        "api_key": "sk-ant-fallback-BBB222",
                        "is_default": False,
                    },
                )

                # 1. Normal PydanticAI streaming + FallbackModel model_name matching + secret redaction
                def fake_builder_ok(
                    candidates: list[dict[str, Any]], **_kwargs: Any
                ) -> tuple[Any, str, str]:
                    stream_ctx = _FakeStreamedResult(
                        chunks=["Streamed ", "ok via ", "sk-ant-fallback", "-BBB222 done."],
                        model_name="claude-4-sonnet",
                    )
                    fake_agent = SimpleNamespace(run_stream=lambda _inp: stream_ctx)
                    return fake_agent, "prompt", candidates[0]["model_id"]

                deltas: list[str] = []

                async def on_delta(chunk: str) -> None:
                    deltas.append(chunk)

                async def run_ok() -> Any:
                    with patch.object(LLMRouter, "_build_pydantic_ai_agent", staticmethod(fake_builder_ok)):
                        return await app.state.llm_router.stream(
                            bot_slug="stream-bot",
                            prompt="Check fallback streaming",
                            requested_model="google:gemini-3.8-flash",
                            on_delta=on_delta,
                        )

                res_ok = asyncio.run(run_ok())
                self.assertFalse(res_ok.cancelled)
                self.assertTrue(res_ok.used_fallback)
                self.assertEqual(res_ok.model_used, "anthropic:claude-4-sonnet")
                self.assertEqual(res_ok.input_tokens, 64)
                self.assertEqual(res_ok.output_tokens, 24)
                streamed_joined = "".join(deltas)
                self.assertNotIn("sk-ant-fallback-BBB222", streamed_joined)
                self.assertIn("<REDACTED", streamed_joined)

                # 2. TTFB cancellation during slow __aenter__ aborts promptly and audits cancelled
                def fake_builder_slow(
                    candidates: list[dict[str, Any]], **_kwargs: Any
                ) -> tuple[Any, str, str]:
                    stream_ctx = _FakeStreamedResult(
                        chunks=["Should never arrive"],
                        slow_enter_s=2.0,
                        model_name="gemini-3.8-flash",
                    )
                    fake_agent = SimpleNamespace(run_stream=lambda _inp: stream_ctx)
                    return fake_agent, "prompt", candidates[0]["model_id"]

                async def run_ttfb_cancel() -> tuple[Any, float]:
                    cancel_ev = asyncio.Event()

                    async def trigger_cancel() -> None:
                        await asyncio.sleep(0.05)
                        cancel_ev.set()

                    t0 = time.monotonic()
                    with patch.object(LLMRouter, "_build_pydantic_ai_agent", staticmethod(fake_builder_slow)):
                        canceller = asyncio.create_task(trigger_cancel())
                        try:
                            res = await app.state.llm_router.stream(
                                bot_slug="stream-bot",
                                prompt="Slow TTFB",
                                requested_model="google:gemini-3.8-flash",
                                cancel_event=cancel_ev,
                            )
                        finally:
                            await canceller
                    return res, (time.monotonic() - t0)

                res_cancel, elapsed_s = asyncio.run(run_ttfb_cancel())
                self.assertTrue(res_cancel.cancelled)
                self.assertEqual(res_cancel.run_record["status"], "cancelled")
                self.assertLess(elapsed_s, 0.5)

    def test_incremental_extractor_actions_and_live_building_page_chip(self) -> None:
        raw_envelope = (
            '{"summary": "Prepared your table view.", '
            '"actions": [{"type": "upsert_page", "slug": "sales-view", "title": "Sales View", '
            '"render_mode": "sandboxed_html", "content_payload": "<!DOCTYPE html><body>Hi</body></html>"}]}'
        )
        extractor = _IncrementalSummaryExtractor()
        emitted: list[str] = []
        detected: list[str] = []
        for idx in range(0, len(raw_envelope), 4):
            out = extractor.feed(raw_envelope[idx : idx + 4])
            if out:
                emitted.append(out)
            detected.extend(extractor.drain_detected_actions())
        tail = extractor.finish()
        if tail:
            emitted.append(tail)
        detected.extend(extractor.drain_detected_actions())

        self.assertEqual("".join(emitted), "Prepared your table view.")
        self.assertEqual(detected, ["__actions__", "upsert_page"])

        async def streaming_page_llm(_req: LLMRequest) -> dict[str, Any]:
            chunks = [raw_envelope[i : i + 12] for i in range(0, len(raw_envelope), 12)]
            return {
                "chunks": chunks,
                "chunk_delay_s": 0.005,
                "input_tokens": 30,
                "output_tokens": 25,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=streaming_page_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={"slug": "page-bot", "name": "Page Bot", "role": "Build pages", "outbound_rbac": "internal"},
                )
                captured_stream: list[dict[str, Any]] = []
                orig_emit = app.state.bus.emit_ephemeral

                async def spy_emit(event_name: str, payload: dict[str, Any]) -> None:
                    if event_name == "turn_stream":
                        captured_stream.append(dict(payload))
                    await orig_emit(event_name, payload)

                app.state.bus.emit_ephemeral = spy_emit
                resp = client.post(
                    "/api/bots/page-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Build a clean table page"},
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                stream_starts = [
                    e for e in captured_stream
                    if e.get("type") == "chip_started" and e.get("action_type") == "stream_page"
                ]
                stream_finishes = [
                    e for e in captured_stream
                    if e.get("type") == "chip_finished" and e.get("action_type") == "stream_page"
                ]
                self.assertEqual(len(stream_starts), 1)
                self.assertEqual(stream_starts[0]["label"], "Building Page...")
                self.assertEqual(len(stream_finishes), 1)
                self.assertEqual(stream_finishes[0]["status"], "done")
                saved_chips = resp.json()["messages"][-1]["metadata"].get("chips") or []
                self.assertFalse(any(c.get("action_type") == "stream_page" for c in saved_chips))

    def test_envelope_prose_recovery_outside_json_extra_keys_and_live_streaming(self) -> None:
        # 1. Post-JSON Markdown with code blocks containing `{}` must be preserved cleanly
        post_json_raw = (
            '```json\n{"summary": "Here are the full details.", "actions": []}\n```\n\n'
            "### Root Cause\n"
            "Run:\n```sh\nstatus_cmd | awk '{print $1}'\n```\n"
        )
        env1, out1 = _extract_json_envelope_with_prose(post_json_raw)
        self.assertIsNotNone(env1)
        self.assertEqual(env1["actions"], [])
        self.assertIn("### Root Cause", out1)
        self.assertIn("awk '{print $1}'", out1)
        composed1 = _compose_envelope_reply_text(env1, post_json_raw, out1)
        self.assertIn("Here are the full details.", composed1)
        self.assertIn("### Root Cause", composed1)
        self.assertIn("awk '{print $1}'", composed1)

        # 2. Pre-JSON Markdown + fenced JSON envelope preserves prose cleanly
        pre_json_raw = (
            "Detailed diagnosis above.\n\n"
            '```json\n{"summary": "Saved rule.", "actions": [{"type": "remember_rule", "rule_text": "Be concise"}]}\n```'
        )
        env2, out2 = _extract_json_envelope_with_prose(pre_json_raw)
        self.assertIsNotNone(env2)
        self.assertEqual(len(env2["actions"]), 1)
        self.assertEqual(out2, "Detailed diagnosis above.")
        composed2 = _compose_envelope_reply_text(env2, pre_json_raw, out2)
        self.assertIn("Saved rule.", composed2)
        self.assertIn("Detailed diagnosis above.", composed2)

        # 3. Extra user-facing JSON keys render cleanly while internal CoT keys stay hidden
        env3 = {
            "summary": "Analysis completed.",
            "root_cause": "NIC flap on subnet 192.0.2.0/24",
            "solution": ["Check link state", "Replace faulty transceiver"],
            "thought": "SECRET_INTERNAL_COT_DO_NOT_SHOW",
            "actions": [],
        }
        composed3 = _compose_envelope_reply_text(env3, json.dumps(env3), "")
        self.assertIn("Analysis completed.", composed3)
        self.assertIn("### Root Cause\nNIC flap on subnet 192.0.2.0/24", composed3)
        self.assertIn("### Solution\n- Check link state\n- Replace faulty transceiver", composed3)
        self.assertNotIn("SECRET_INTERNAL_COT_DO_NOT_SHOW", composed3)

        # 4. Plain Markdown containing an illustrative JSON example (without actions/emit_event) stays untouched
        plain_with_sample = (
            "Here is the config format to use:\n\n"
            '```json\n{"summary": "example"}\n```'
        )
        env4, _ = _extract_json_envelope_with_prose(plain_with_sample)
        self.assertIsNone(env4)
        self.assertEqual(_compose_envelope_reply_text(env4, plain_with_sample, ""), plain_with_sample)

        # 5. Live streaming _IncrementalSummaryExtractor emits post-JSON Markdown without leaking fence/JSON
        stream_payload = (
            '```json\n{"summary": "Intro.", "actions": []}\n```\n\n'
            "### Solution\n1. Fix it cleanly\n```sh\necho ok | awk '{print $1}'\n```"
        )
        extractor = _IncrementalSummaryExtractor()
        chunks: list[str] = []
        for idx in range(0, len(stream_payload), 4):
            piece = extractor.feed(stream_payload[idx : idx + 4])
            if piece:
                chunks.append(piece)
        tail = extractor.finish()
        if tail:
            chunks.append(tail)
        streamed_text = "".join(chunks)
        self.assertEqual(
            streamed_text,
            "Intro.\n\n### Solution\n1. Fix it cleanly\n```sh\necho ok | awk '{print $1}'\n```",
        )
        self.assertNotIn('"actions"', streamed_text)

        # 6. End-to-end bot chat message preserves extra `details` after discovery turn
        turn_count = [0]

        async def troubleshooting_llm(req: LLMRequest) -> dict[str, Any]:
            turn_count[0] += 1
            if turn_count[0] == 1:
                self.assertIn("NEVER write a 1–2 sentence teaser", req.system_prompt)
                return {
                    "text": json.dumps(
                        {
                            "summary": "",
                            "actions": [{"type": "data_describe"}],
                        }
                    ),
                    "input_tokens": 15,
                    "output_tokens": 10,
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Here are the details.",
                        "details": "### Root Cause\nFlapping NIC\n\n### Solution\n1. Inspect dmesg",
                        "actions": [],
                    }
                ),
                "input_tokens": 20,
                "output_tokens": 24,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=troubleshooting_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "diag-bot",
                        "name": "Diag Bot",
                        "role": "Troubleshoot logs and return remediation steps",
                        "outbound_rbac": "internal",
                    },
                )
                post_res = client.post(
                    "/api/bots/diag-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Verify the logs and provide a solution"},
                )
                self.assertEqual(post_res.status_code, 200, post_res.text)
                thread = client.get("/api/bots/diag-bot/messages", headers=self._sso_headers()).json()
                bot_reply = [m for m in thread if m.get("sender") == "bot"][-1]
                self.assertIn("### Root Cause", bot_reply["text"])
                self.assertIn("Flapping NIC", bot_reply["text"])
                self.assertIn("### Solution", bot_reply["text"])
                self.assertIn("1. Inspect dmesg", bot_reply["text"])

    def test_malformed_json_action_envelope_retry_fallback_and_plain_text_url_fetch(self) -> None:
        from argo_core.tools.public_web import fetch_public_webpage

        # 1. Self-correction retry recovers cleanly when turn 1 emits broken JSON fence
        turn_calls: list[list[dict[str, Any]]] = []

        async def retry_llm(req: LLMRequest) -> dict[str, Any]:
            env = json.loads(req.user_prompt)
            obs = list(env.get("tool_observations") or [])
            turn_calls.append(obs)
            if not obs:
                return {
                    "text": '```json\n{"summary": "", "actions": [{"type": "desktop_exec", "commands": ["python3 -c \'\nimport broken\n',
                    "input_tokens": 12,
                    "output_tokens": 20,
                }
            return {
                "text": json.dumps({"summary": "Recovered clean answer after retrying.", "actions": []}),
                "input_tokens": 18,
                "output_tokens": 12,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=retry_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "recover-bot",
                        "name": "Recover Bot",
                        "role": "Test malformed envelope recovery",
                        "outbound_rbac": "internal",
                    },
                )
                r1 = client.post(
                    "/api/bots/recover-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Fetch setup script"},
                ).json()["result"]
                self.assertEqual(r1["summary"], "Recovered clean answer after retrying.")
                self.assertGreaterEqual(len(turn_calls), 2)
                self.assertEqual(turn_calls[1][-1].get("type"), "envelope_parse_error")

        # 2. Repeated broken JSON envelopes NEVER leak raw JSON or emit habit_proposal
        async def always_broken_llm(req: LLMRequest) -> dict[str, Any]:
            return {
                "text": '```json\n{"summary": "", "actions": [{"type": "desktop_exec", "commands": ["python3 -c \'\nunterminated',
                "input_tokens": 10,
                "output_tokens": 15,
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=always_broken_llm)
            with TestClient(app) as client:
                client.post(
                    "/api/bots",
                    headers=self._sso_headers(),
                    json={
                        "slug": "broken-bot",
                        "name": "Broken Bot",
                        "role": "Test malformed envelope fallback",
                        "outbound_rbac": "internal",
                    },
                )
                r2 = client.post(
                    "/api/bots/broken-bot/messages",
                    headers=self._sso_headers(),
                    json={"text": "Run broken output"},
                ).json()["result"]
                self.assertNotIn('"actions"', r2["summary"])
                self.assertNotIn('"summary"', r2["summary"])
                self.assertIn("formatting error", r2["summary"])
                self.assertNotIn("habit_proposal", r2.get("metadata") or {})

        # 3. fetch_public_webpage returns text/plain raw shell scripts verbatim without HTML mangling
        raw_script = (
            "#!/usr/bin/env bash\n"
            "cat <<'EOF' > /etc/modprobe.d/r8152.conf\n"
            "options r8152 power_save=0\n"
            "EOF\n"
            "modprobe -r r8152 2>/dev/null || true\n"
        )

        class _PlainScriptFetcher:
            async def fetch(
                self, url: str, headers: dict[str, str] | None = None, max_bytes: int = 10_485_760
            ) -> PublicHttpResponse:
                del headers, max_bytes
                return PublicHttpResponse(
                    url=url,
                    status_code=200,
                    headers={"content-type": "text/plain; charset=utf-8"},
                    body=raw_script,
                )

        fetched = asyncio.run(
            fetch_public_webpage(
                "https://raw.githubusercontent.com/org/repo/main/setup.sh",
                fetcher=_PlainScriptFetcher(),
            )
        )
        self.assertEqual(fetched["title"], "setup.sh")
        self.assertEqual(fetched["markdown"], raw_script)
        self.assertIn("2>/dev/null", fetched["markdown"])
        self.assertIn("cat <<'EOF' > /etc/modprobe.d/r8152.conf", fetched["markdown"])


if __name__ == "__main__":
    unittest.main()
