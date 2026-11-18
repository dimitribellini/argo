"""In-process multi-provider LLM router powered by PydanticAI v2.68+."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from argo_core.db.repositories import ArgoRepository, make_id, utc_now
from argo_core.security.vault import redact_secrets

logger = logging.getLogger(__name__)

_SUPPORTED_PROVIDERS = {"google", "anthropic", "openai", "xai", "openrouter", "ollama"}

# Approximate USD per 1M tokens for transparent cost tracking in bot_runs.
_PRICING_PER_MILLION: dict[str, tuple[float, float]] = {
    "google:gemini-3.8-flash": (0.15, 0.60),
    "google:gemini-4-argon": (1.25, 5.00),
    "google": (0.50, 2.00),
    "anthropic": (3.00, 15.00),
    "openai": (1.50, 6.00),
    "xai": (2.00, 10.00),
    "openrouter": (2.00, 8.00),
    "ollama": (0.0, 0.0),
}


class ModelConfigurationError(ValueError):
    """Raised on invalid, unsupported, deprecated, or unconfigured model IDs."""


class BudgetExceededError(RuntimeError):
    """Raised when daily token limits or monthly USD budgets block execution."""


class LLMExecutionError(RuntimeError):
    """Raised when all candidate model providers fail during inference."""


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """Normalized request passed to PydanticAI or a custom test/local transport."""

    model_id: str
    provider_type: str
    model_name: str
    api_key: str | None
    api_base: str | None
    system_prompt: str
    user_prompt: str
    thinking_level: str
    images: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class LLMResult:
    """Normalized response + token accounting returned after persistence in bot_runs."""

    output_text: str
    model_used: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    latency_ms: int
    used_fallback: bool
    unconfigured_local: bool
    run_record: dict[str, Any]
    cancelled: bool = False


LLMTransport = Callable[[LLMRequest], Awaitable[Any]]


def validate_model_id(model_id: str) -> tuple[str, str]:
    """Parse provider:model_name and reject deprecated gemini-2.5-* models."""
    cleaned = model_id.strip()
    if not cleaned or ":" not in cleaned:
        raise ModelConfigurationError(
            f"Invalid model_id '{model_id}'; expected '<provider>:<model_name>'."
        )
    if "gemini-2.5" in cleaned.lower():
        raise ModelConfigurationError(
            "Deprecated gemini-2.5-* models are forbidden; use gemini-3.8-flash or gemini-4-argon."
        )
    provider_type, model_name = cleaned.split(":", 1)
    provider_norm = provider_type.strip().lower()
    name_clean = model_name.strip()
    if provider_norm not in _SUPPORTED_PROVIDERS or not name_clean:
        raise ModelConfigurationError(
            f"Unsupported LLM provider '{provider_type}' in '{model_id}'."
        )
    return provider_norm, name_clean


def default_thinking_level(model_id: str) -> str:
    """Assign high reasoning depth to gemini-4-argon and low latency triage to others."""
    lower = model_id.lower()
    if "gemini-4-argon" in lower or "reasoning" in lower:
        return "high"
    return "low"


def estimate_cost_usd(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Compute estimated USD cost for a single LLM invocation."""
    cleaned = model_id.strip()
    provider_type = cleaned.split(":", 1)[0].lower() if ":" in cleaned else "google"
    in_rate, out_rate = _PRICING_PER_MILLION.get(
        cleaned,
        _PRICING_PER_MILLION.get(provider_type, (0.50, 2.00)),
    )
    cost = (max(0, input_tokens) * in_rate + max(0, output_tokens) * out_rate) / 1_000_000.0
    return round(cost, 6)


def _is_provider_configured(
    candidate: dict[str, Any],
    *,
    has_custom_transport: bool,
    is_primary: bool,
) -> bool:
    if has_custom_transport and is_primary:
        return True
    if candidate["provider_type"] == "ollama":
        return bool(candidate.get("api_base") or candidate.get("api_key"))
    return bool(candidate.get("api_key"))


def _build_single_pydantic_ai_model(candidate: dict[str, Any]) -> Any:
    """Construct a typed PydanticAI v2.68+ model instance using stored Vault credentials."""
    provider_type = candidate["provider_type"]
    _, model_name = validate_model_id(candidate["model_id"])
    api_key = candidate.get("api_key") or None
    api_base = candidate.get("api_base") or None

    if provider_type == "google":
        from pydantic_ai.models.google import GoogleModel
        from pydantic_ai.providers.google import GoogleProvider

        return GoogleModel(
            model_name,
            provider=GoogleProvider(api_key=api_key, base_url=api_base),
        )
    if provider_type == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from pydantic_ai.providers.anthropic import AnthropicProvider

        return AnthropicModel(
            model_name,
            provider=AnthropicProvider(api_key=api_key, base_url=api_base),
        )
    if provider_type == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider

        return OpenAIChatModel(
            model_name,
            provider=OpenAIProvider(api_key=api_key, base_url=api_base),
        )
    if provider_type == "xai":
        from pydantic_ai.models.xai import XaiModel
        from pydantic_ai.providers.xai import XaiProvider

        return XaiModel(
            model_name,
            provider=XaiProvider(api_key=api_key, api_host=api_base),
        )
    if provider_type == "openrouter":
        from pydantic_ai.models.openrouter import OpenRouterModel
        from pydantic_ai.providers.openrouter import OpenRouterProvider

        return OpenRouterModel(
            model_name,
            provider=OpenRouterProvider(api_key=api_key),
        )
    if provider_type == "ollama":
        from pydantic_ai.models.ollama import OllamaModel
        from pydantic_ai.providers.ollama import OllamaProvider

        return OllamaModel(
            model_name,
            provider=OllamaProvider(
                base_url=api_base or "http://localhost:11434/v1",
                api_key=api_key or "ollama",
            ),
        )
    raise ModelConfigurationError(f"Unsupported LLM provider '{provider_type}'.")


def _extract_transport_output(raw: tuple[str, int, int] | dict[str, Any]) -> tuple[str, int, int]:
    if isinstance(raw, tuple):
        text, in_tok, out_tok = raw
        return str(text), int(in_tok), int(out_tok)
    if isinstance(raw, dict):
        return (
            str(raw.get("output_text", raw.get("text", ""))),
            int(raw.get("input_tokens", 0)),
            int(raw.get("output_tokens", 0)),
        )
    return str(raw), 0, 0


class _StreamDeltaEmitter:
    """Coalesce and secret-scrub streamed text chunks safely across chunk boundaries."""

    _TOKEN_PREFIXES = ("sk-", "ya29.", "1//", "GOCSPX-", "Bearer ")
    _TG_TOKEN_TAIL_RE = re.compile(r"(?:bot)?\d{4,}:?[A-Za-z0-9_-]*$")

    def __init__(
        self,
        *,
        all_secrets: Sequence[str],
        on_delta: Callable[[str], Awaitable[None]] | None,
    ) -> None:
        self._secrets = [s.strip() for s in all_secrets if isinstance(s, str) and len(s.strip()) >= 4]
        self._on_delta = on_delta
        self._buffer = ""
        self._emitted_raw: list[str] = []
        self._last_emit_ts = time.monotonic()

    def _safe_split_index(self) -> int:
        buf = self._buffer
        if not buf:
            return 0
        # Hold back any trailing non-whitespace word (up to 64 chars) so multi-chunk secrets
        # and word boundaries are scrubbed atomically before leaving the router.
        last_ws = -1
        for i in range(len(buf) - 1, -1, -1):
            if buf[i].isspace():
                last_ws = i
                break
        if last_ws >= 0 and len(buf) - last_ws - 1 <= 64:
            split_at = last_ws + 1
        elif len(buf) > 64:
            split_at = len(buf) - 64
        else:
            split_at = 0

        # Additionally check if any secret or token prefix straddles split_at or the buffer tail.
        tail = buf[:split_at]
        for secret in self._secrets:
            max_check = min(len(secret) - 1, len(tail))
            for k in range(max_check, 0, -1):
                if tail.endswith(secret[:k]):
                    split_at = min(split_at, len(tail) - k)
                    break
        for prefix in self._TOKEN_PREFIXES:
            idx = tail.rfind(prefix)
            if idx >= 0 and len(tail) - idx < 48:
                split_at = min(split_at, idx)
        tg_tail = self._TG_TOKEN_TAIL_RE.search(tail)
        if tg_tail and len(tail) - tg_tail.start() < 48:
            split_at = min(split_at, tg_tail.start())
        return max(0, split_at)

    async def feed(self, chunk: str) -> None:
        if not chunk:
            return
        self._buffer += chunk
        now = time.monotonic()
        split_at = self._safe_split_index()
        if split_at <= 0:
            return
        candidate = self._buffer[:split_at]
        if (now - self._last_emit_ts) >= 0.06 or len(candidate) >= 18 or "\n" in candidate:
            await self._emit_slice(split_at)

    async def flush(self) -> str:
        if self._buffer:
            await self._emit_slice(len(self._buffer))
        return "".join(self._emitted_raw)

    async def _emit_slice(self, length: int) -> None:
        raw_slice = self._buffer[:length]
        self._buffer = self._buffer[length:]
        if not raw_slice:
            return
        safe_slice = redact_secrets(raw_slice, self._secrets)
        self._emitted_raw.append(safe_slice)
        self._last_emit_ts = time.monotonic()
        if self._on_delta is not None:
            await self._on_delta(safe_slice)

    @property
    def current_text(self) -> str:
        partial_tail = redact_secrets(self._buffer, self._secrets) if self._buffer else ""
        return "".join(self._emitted_raw) + partial_tail


class LLMRouter:
    """In-process multi-LLM router with budget guardrails, failover, and bot_runs auditing."""

    def __init__(
        self,
        repo: ArgoRepository,
        transport: LLMTransport | None = None,
    ) -> None:
        self._repo = repo
        self._transport = transport

    def _compose_system_prompt(self, base_prompt: str, bot_slug: str) -> str:
        rules = [
            rule["rule_text"]
            for rule in self._repo.list_style_rules()
            if rule["scope_slug"] in ("*", bot_slug)
        ]
        parts = [base_prompt.strip()] if base_prompt.strip() else []
        if rules:
            formatted = "\n".join(f"- {item}" for item in rules)
            parts.append(f"Active editorial style rules:\n{formatted}")
        return "\n\n".join(parts)

    def _select_candidates(
        self,
        *,
        requested_model: str | None,
        strict_provider: bool,
    ) -> list[dict[str, Any]]:
        all_providers = self._repo.list_model_provider_credentials()
        ordered: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        if requested_model:
            matched = self._repo.get_model_provider_credentials(requested_model)
            if matched is not None:
                ordered.append(matched)
                seen_ids.add(matched["id"])
            else:
                provider_type, _ = validate_model_id(requested_model)
                matching_provider = next(
                    (
                        p
                        for p in all_providers
                        if p["provider_type"] == provider_type
                        and (p.get("api_key") or p.get("api_base"))
                    ),
                    None,
                )
                ordered.append(
                    {
                        "id": f"ephemeral:{requested_model}",
                        "slug": requested_model,
                        "provider_type": provider_type,
                        "model_id": requested_model,
                        "api_base": matching_provider["api_base"] if matching_provider else None,
                        "api_key": matching_provider["api_key"] if matching_provider else None,
                        "is_default": False,
                        "daily_token_limit": None,
                        "monthly_budget_usd": None,
                    }
                )

        if not strict_provider:
            for item in all_providers:
                if item["id"] not in seen_ids:
                    ordered.append(item)
                    seen_ids.add(item["id"])

        return ordered

    def _partition_candidates(
        self,
        candidates: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Filter candidates into executable providers vs budget-blocked reasons."""
        eligible: list[dict[str, Any]] = []
        budget_reasons: list[str] = []
        has_transport = self._transport is not None

        for idx, candidate in enumerate(candidates):
            if not _is_provider_configured(
                candidate,
                has_custom_transport=has_transport,
                is_primary=(idx == 0),
            ):
                continue

            usage = self._repo.provider_usage_totals(candidate["model_id"])
            daily_limit = candidate.get("daily_token_limit")
            if daily_limit is not None and usage["today_tokens"] >= int(daily_limit):
                budget_reasons.append(
                    f"{candidate['model_id']} reached daily_token_limit "
                    f"({usage['today_tokens']}/{daily_limit})."
                )
                continue

            monthly_budget = candidate.get("monthly_budget_usd")
            if monthly_budget is not None and usage["month_cost_usd"] >= float(monthly_budget):
                budget_reasons.append(
                    f"{candidate['model_id']} reached monthly_budget_usd "
                    f"(${usage['month_cost_usd']:.4f}/${float(monthly_budget):.2f})."
                )
                continue

            eligible.append(candidate)

        return eligible, budget_reasons

    async def _run_with_pydantic_ai(
        self,
        candidates: list[dict[str, Any]],
        *,
        system_prompt: str,
        user_prompt: str,
        thinking_level: str,
        images: Sequence[bytes] | None = None,
    ) -> tuple[str, str, int, int, bool]:
        """Execute inference via PydanticAI v2.68+ Agent and optional FallbackModel."""
        from pydantic_ai import Agent
        from pydantic_ai.models.fallback import FallbackModel
        from pydantic_ai.settings import ModelSettings

        built_models = [_build_single_pydantic_ai_model(c) for c in candidates]
        model_spec = built_models[0] if len(built_models) == 1 else FallbackModel(*built_models)
        agent = Agent(
            model=model_spec,
            instructions=system_prompt or None,
            model_settings=ModelSettings(thinking=thinking_level),  # type: ignore[arg-type]
        )
        run_input: Any = user_prompt
        image_items = [img for img in (images or ()) if img]
        if image_items:
            from pydantic_ai import BinaryContent

            run_input = [
                user_prompt,
                *[BinaryContent(data=img, media_type="image/png") for img in image_items],
            ]
        result = await agent.run(run_input)
        usage = result.usage()
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)

        response_model = getattr(result.response, "model_name", None) or ""
        primary_model_id = candidates[0]["model_id"]
        matched_model_id = primary_model_id
        for candidate in candidates:
            _, short_name = validate_model_id(candidate["model_id"])
            if response_model and (
                response_model == candidate["model_id"] or response_model == short_name
            ):
                matched_model_id = candidate["model_id"]
                break

        used_fallback = matched_model_id != primary_model_id
        return str(result.output), matched_model_id, input_tokens, output_tokens, used_fallback

    @staticmethod
    def _build_pydantic_ai_agent(
        candidates: list[dict[str, Any]],
        *,
        system_prompt: str,
        user_prompt: str,
        thinking_level: str,
        images: Sequence[bytes] | None = None,
    ) -> tuple[Any, Any, str]:
        from pydantic_ai import Agent
        from pydantic_ai.models.fallback import FallbackModel
        from pydantic_ai.settings import ModelSettings

        built_models = [_build_single_pydantic_ai_model(c) for c in candidates]
        model_spec = built_models[0] if len(built_models) == 1 else FallbackModel(*built_models)
        agent = Agent(
            model=model_spec,
            instructions=system_prompt or None,
            model_settings=ModelSettings(thinking=thinking_level),  # type: ignore[arg-type]
        )
        run_input: Any = user_prompt
        image_items = [img for img in (images or ()) if img]
        if image_items:
            from pydantic_ai import BinaryContent

            run_input = [
                user_prompt,
                *[BinaryContent(data=img, media_type="image/png") for img in image_items],
            ]
        return agent, run_input, candidates[0]["model_id"]

    @staticmethod
    def _match_response_model(candidates: list[dict[str, Any]], response_model: str) -> str:
        primary_model_id = candidates[0]["model_id"]
        for candidate in candidates:
            _, short_name = validate_model_id(candidate["model_id"])
            if response_model and (
                response_model == candidate["model_id"] or response_model == short_name
            ):
                return candidate["model_id"]
        return primary_model_id

    async def _stream_with_pydantic_ai(
        self,
        candidates: list[dict[str, Any]],
        *,
        system_prompt: str,
        user_prompt: str,
        thinking_level: str,
        images: Sequence[bytes] | None = None,
        emitter: _StreamDeltaEmitter,
        cancel_event: asyncio.Event | None = None,
    ) -> tuple[str, str, int, int, bool, bool]:
        """Stream live text deltas from PydanticAI v2.68+ Agent.run_stream with cancellation."""
        agent, run_input, primary_model_id = self._build_pydantic_ai_agent(
            candidates,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            thinking_level=thinking_level,
            images=images,
        )
        matched_model_id = primary_model_id
        input_tokens = 0
        output_tokens = 0

        async def _consume() -> None:
            nonlocal matched_model_id, input_tokens, output_tokens
            async with agent.run_stream(run_input) as streamed:
                async for delta in streamed.stream_text(delta=True):
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    if delta:
                        await emitter.feed(str(delta))
                if not (cancel_event is not None and cancel_event.is_set()) and not emitter.current_text:
                    with contextlib.suppress(Exception):
                        fallback_output = await streamed.get_output()
                        if fallback_output:
                            await emitter.feed(str(fallback_output))
                with contextlib.suppress(Exception):
                    usage = streamed.usage()
                    input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
                    output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
                with contextlib.suppress(Exception):
                    resp = getattr(streamed, "response", None)
                    resp_model = getattr(resp, "model_name", None) or ""
                    if resp_model:
                        matched_model_id = self._match_response_model(candidates, resp_model)

        cancelled, _ = await self._await_or_cancel(_consume(), cancel_event)
        cancelled = cancelled or bool(cancel_event and cancel_event.is_set())
        final_text = await emitter.flush()
        if cancelled and output_tokens == 0 and final_text:
            output_tokens = max(1, len(final_text) // 4)
        used_fallback = matched_model_id != primary_model_id
        return final_text, matched_model_id, input_tokens, output_tokens, used_fallback, cancelled

    async def complete(
        self,
        *,
        bot_slug: str,
        prompt: str,
        requested_model: str | None = None,
        system_prompt: str = "",
        trigger_type: str = "manual",
        correlation_id: str | None = None,
        hop_count: int = 1,
        thinking_level: str | None = None,
        outbound_rbac: str = "draft",
        strict_provider: bool = False,
        images: Sequence[bytes] | None = None,
    ) -> LLMResult:
        """Route an LLM request through PydanticAI/FallbackModel and audit bot_runs."""
        corr_id = correlation_id or make_id("corr")
        started_ts = utc_now()
        t0 = time.monotonic()

        if requested_model and self._repo.get_model_provider_credentials(requested_model) is None:
            validate_model_id(requested_model)

        candidates = self._select_candidates(
            requested_model=requested_model,
            strict_provider=strict_provider,
        )
        if not candidates:
            raise ModelConfigurationError("No LLM model providers are registered.")

        eligible, budget_reasons = self._partition_candidates(candidates)
        primary_model_id = candidates[0]["model_id"]
        resolved_thinking = thinking_level or default_thinking_level(primary_model_id)
        effective_system = self._compose_system_prompt(system_prompt, bot_slug)
        all_secrets = [c["api_key"] for c in candidates if c.get("api_key")]

        if not eligible:
            if budget_reasons:
                reason = "; ".join(budget_reasons)
                self._repo.record_bot_run(
                    correlation_id=corr_id,
                    bot_slug=bot_slug,
                    trigger_type=trigger_type,
                    hop_count=hop_count,
                    llm_model_used=primary_model_id,
                    status="blocked",
                    summary=reason,
                    started_at=started_ts,
                    finished_at=utc_now(),
                )
                raise BudgetExceededError(reason)

            if strict_provider:
                reason = (
                    f"Provider '{primary_model_id}' has no API key or Ollama endpoint configured."
                )
                self._repo.record_bot_run(
                    correlation_id=corr_id,
                    bot_slug=bot_slug,
                    trigger_type=trigger_type,
                    hop_count=hop_count,
                    llm_model_used=primary_model_id,
                    status="blocked",
                    summary=reason,
                    started_at=started_ts,
                    finished_at=utc_now(),
                )
                raise ModelConfigurationError(reason)

            ack = (
                f"Acknowledged under `{outbound_rbac}` connector RBAC on `{primary_model_id}`. "
                "Configure a provider API key or Ollama endpoint in Models to enable live inference."
            )
            run_rec = self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=primary_model_id,
                input_tokens=0,
                output_tokens=0,
                estimated_cost_usd=0.0,
                status="success",
                summary=f"Local acknowledgment (no API key stored for {primary_model_id}).",
                started_at=started_ts,
                finished_at=utc_now(),
            )
            return LLMResult(
                output_text=ack,
                model_used=primary_model_id,
                input_tokens=0,
                output_tokens=0,
                estimated_cost_usd=0.0,
                latency_ms=int((time.monotonic() - t0) * 1000),
                used_fallback=False,
                unconfigured_local=True,
                run_record=run_rec,
            )

        if self._transport is not None:
            errors: list[str] = []
            for idx, candidate in enumerate(eligible):
                provider_type, model_name = validate_model_id(candidate["model_id"])
                req = LLMRequest(
                    model_id=candidate["model_id"],
                    provider_type=provider_type,
                    model_name=model_name,
                    api_key=candidate.get("api_key"),
                    api_base=candidate.get("api_base"),
                    system_prompt=effective_system,
                    user_prompt=prompt,
                    thinking_level=thinking_level or default_thinking_level(candidate["model_id"]),
                    images=tuple(images or ()),
                )
                try:
                    raw = await self._transport(req)
                    text, in_tokens, out_tokens = _extract_transport_output(raw)
                    cost_usd = estimate_cost_usd(candidate["model_id"], in_tokens, out_tokens)
                    used_fallback = idx > 0 or candidate["model_id"] != primary_model_id
                    run_rec = self._repo.record_bot_run(
                        correlation_id=corr_id,
                        bot_slug=bot_slug,
                        trigger_type=trigger_type,
                        hop_count=hop_count,
                        llm_model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        status="success",
                        summary=(
                            f"Fallback succeeded on {candidate['model_id']}"
                            if used_fallback
                            else f"Completed on {candidate['model_id']}"
                        ),
                        started_at=started_ts,
                        finished_at=utc_now(),
                    )
                    return LLMResult(
                        output_text=text,
                        model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        latency_ms=int((time.monotonic() - t0) * 1000),
                        used_fallback=used_fallback,
                        unconfigured_local=False,
                        run_record=run_rec,
                    )
                except Exception as exc:
                    safe_err = redact_secrets(str(exc), all_secrets)
                    errors.append(f"{candidate['model_id']}: {safe_err}")
                    logger.warning("Candidate LLM failed: %s (%s)", candidate["model_id"], safe_err)

            combined = "; ".join(errors)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=combined[:500],
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"All candidate LLM providers failed: {combined}")

        try:
            text, model_used, in_tokens, out_tokens, used_fallback = await self._run_with_pydantic_ai(
                eligible,
                system_prompt=effective_system,
                user_prompt=prompt,
                thinking_level=resolved_thinking,
                images=images,
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc), all_secrets)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=safe_err[:500],
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"PydanticAI execution failed: {safe_err}") from exc

        cost_usd = estimate_cost_usd(model_used, in_tokens, out_tokens)
        run_rec = self._repo.record_bot_run(
            correlation_id=corr_id,
            bot_slug=bot_slug,
            trigger_type=trigger_type,
            hop_count=hop_count,
            llm_model_used=model_used,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            estimated_cost_usd=cost_usd,
            status="success",
            summary=(
                f"Fallback succeeded on {model_used}"
                if used_fallback
                else f"Completed on {model_used}"
            ),
            started_at=started_ts,
            finished_at=utc_now(),
        )
        return LLMResult(
            output_text=text,
            model_used=model_used,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            estimated_cost_usd=cost_usd,
            latency_ms=int((time.monotonic() - t0) * 1000),
            used_fallback=used_fallback,
            unconfigured_local=False,
            run_record=run_rec,
        )

    @staticmethod
    async def _await_or_cancel(
        awaitable: Any,
        cancel_event: asyncio.Event | None,
    ) -> tuple[bool, Any]:
        """Await a coroutine while waking promptly if cancel_event is triggered."""
        if cancel_event is None:
            return False, await awaitable
        if cancel_event.is_set():
            if asyncio.iscoroutine(awaitable):
                awaitable.close()
            return True, None
        work_task = asyncio.ensure_future(awaitable)
        cancel_task = asyncio.create_task(cancel_event.wait())
        try:
            done, _ = await asyncio.wait(
                {work_task, cancel_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_task in done and cancel_event.is_set():
                work_task.cancel()
                with contextlib.suppress(BaseException):
                    await work_task
                return True, None
            return False, await work_task
        finally:
            cancel_task.cancel()
            with contextlib.suppress(BaseException):
                await cancel_task

    async def stream(
        self,
        *,
        bot_slug: str,
        prompt: str,
        on_delta: Callable[[str], Awaitable[None]] | None = None,
        cancel_event: asyncio.Event | None = None,
        extra_secrets: Sequence[str] | None = None,
        requested_model: str | None = None,
        system_prompt: str = "",
        trigger_type: str = "manual",
        correlation_id: str | None = None,
        hop_count: int = 1,
        thinking_level: str | None = None,
        outbound_rbac: str = "draft",
        strict_provider: bool = False,
        images: Sequence[bytes] | None = None,
    ) -> LLMResult:
        """Stream an LLM response via PydanticAI or test transport with budget & cancel guardrails."""
        corr_id = correlation_id or make_id("corr")
        started_ts = utc_now()
        t0 = time.monotonic()

        if requested_model and self._repo.get_model_provider_credentials(requested_model) is None:
            validate_model_id(requested_model)

        candidates = self._select_candidates(
            requested_model=requested_model,
            strict_provider=strict_provider,
        )
        if not candidates:
            raise ModelConfigurationError("No LLM model providers are registered.")

        eligible, budget_reasons = self._partition_candidates(candidates)
        primary_model_id = candidates[0]["model_id"]
        resolved_thinking = thinking_level or default_thinking_level(primary_model_id)
        effective_system = self._compose_system_prompt(system_prompt, bot_slug)
        all_secrets = [
            *[c["api_key"] for c in candidates if c.get("api_key")],
            *[str(s) for s in (extra_secrets or ()) if str(s).strip()],
        ]

        if not eligible:
            if budget_reasons:
                reason = "; ".join(budget_reasons)
                self._repo.record_bot_run(
                    correlation_id=corr_id,
                    bot_slug=bot_slug,
                    trigger_type=trigger_type,
                    hop_count=hop_count,
                    llm_model_used=primary_model_id,
                    status="blocked",
                    summary=reason,
                    started_at=started_ts,
                    finished_at=utc_now(),
                )
                raise BudgetExceededError(reason)

            if strict_provider:
                reason = (
                    f"Provider '{primary_model_id}' has no API key or Ollama endpoint configured."
                )
                self._repo.record_bot_run(
                    correlation_id=corr_id,
                    bot_slug=bot_slug,
                    trigger_type=trigger_type,
                    hop_count=hop_count,
                    llm_model_used=primary_model_id,
                    status="blocked",
                    summary=reason,
                    started_at=started_ts,
                    finished_at=utc_now(),
                )
                raise ModelConfigurationError(reason)

            ack = (
                f"Acknowledged under `{outbound_rbac}` connector RBAC on `{primary_model_id}`. "
                "Configure a provider API key or Ollama endpoint in Models to enable live inference."
            )
            cancelled_now = cancel_event is not None and cancel_event.is_set()
            if not cancelled_now and on_delta is not None:
                await on_delta(ack)
            run_rec = self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=primary_model_id,
                input_tokens=0,
                output_tokens=0,
                estimated_cost_usd=0.0,
                status="cancelled" if cancelled_now else "success",
                summary=(
                    f"Cancelled on {primary_model_id}"
                    if cancelled_now
                    else f"Local acknowledgment (no API key stored for {primary_model_id})."
                ),
                started_at=started_ts,
                finished_at=utc_now(),
            )
            return LLMResult(
                output_text="" if cancelled_now else ack,
                model_used=primary_model_id,
                input_tokens=0,
                output_tokens=0,
                estimated_cost_usd=0.0,
                latency_ms=int((time.monotonic() - t0) * 1000),
                used_fallback=False,
                unconfigured_local=True,
                run_record=run_rec,
                cancelled=cancelled_now,
            )

        if self._transport is not None:
            errors: list[str] = []
            for idx, candidate in enumerate(eligible):
                provider_type, model_name = validate_model_id(candidate["model_id"])
                req = LLMRequest(
                    model_id=candidate["model_id"],
                    provider_type=provider_type,
                    model_name=model_name,
                    api_key=candidate.get("api_key"),
                    api_base=candidate.get("api_base"),
                    system_prompt=effective_system,
                    user_prompt=prompt,
                    thinking_level=thinking_level or default_thinking_level(candidate["model_id"]),
                    images=tuple(images or ()),
                )
                emitter = _StreamDeltaEmitter(all_secrets=all_secrets, on_delta=on_delta)
                try:
                    cancelled_mid, raw = await self._await_or_cancel(
                        self._transport(req), cancel_event
                    )
                    in_tokens = 0
                    out_tokens = 0
                    if not cancelled_mid:
                        if isinstance(raw, dict) and "chunks" in raw:
                            chunks_src = raw["chunks"]
                            in_tokens = int(raw.get("input_tokens", 0))
                            out_tokens = int(raw.get("output_tokens", 0))
                            chunk_delay = float(raw.get("chunk_delay_s") or 0.0)
                            if hasattr(chunks_src, "__aiter__"):
                                async_iter = chunks_src.__aiter__()
                                while True:
                                    was_cancelled, item = await self._await_or_cancel(
                                        async_iter.__anext__(), cancel_event
                                    )
                                    if was_cancelled:
                                        cancelled_mid = True
                                        break
                                    await emitter.feed(str(item))
                            else:
                                for chunk in chunks_src:
                                    if cancel_event is not None and cancel_event.is_set():
                                        cancelled_mid = True
                                        break
                                    await emitter.feed(str(chunk))
                                    if chunk_delay > 0:
                                        was_cancelled, _ = await self._await_or_cancel(
                                            asyncio.sleep(chunk_delay), cancel_event
                                        )
                                        if was_cancelled:
                                            cancelled_mid = True
                                            break
                        elif hasattr(raw, "__aiter__"):
                            async_iter = raw.__aiter__()
                            while True:
                                was_cancelled, item = await self._await_or_cancel(
                                    async_iter.__anext__(), cancel_event
                                )
                                if was_cancelled:
                                    cancelled_mid = True
                                    break
                                await emitter.feed(str(item))
                        else:
                            text, in_tokens, out_tokens = _extract_transport_output(raw)
                            await emitter.feed(text)

                    final_text = await emitter.flush()
                    if cancelled_mid and out_tokens == 0 and final_text:
                        out_tokens = max(1, len(final_text) // 4)
                    cost_usd = estimate_cost_usd(candidate["model_id"], in_tokens, out_tokens)
                    used_fallback = idx > 0 or candidate["model_id"] != primary_model_id
                    run_status = "cancelled" if cancelled_mid else "success"
                    run_summary = (
                        f"Cancelled on {candidate['model_id']}"
                        if cancelled_mid
                        else (
                            f"Fallback succeeded on {candidate['model_id']}"
                            if used_fallback
                            else f"Completed on {candidate['model_id']}"
                        )
                    )
                    run_rec = self._repo.record_bot_run(
                        correlation_id=corr_id,
                        bot_slug=bot_slug,
                        trigger_type=trigger_type,
                        hop_count=hop_count,
                        llm_model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        status=run_status,
                        summary=run_summary,
                        started_at=started_ts,
                        finished_at=utc_now(),
                    )
                    return LLMResult(
                        output_text=final_text,
                        model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        latency_ms=int((time.monotonic() - t0) * 1000),
                        used_fallback=used_fallback,
                        unconfigured_local=False,
                        run_record=run_rec,
                        cancelled=cancelled_mid,
                    )
                except StopAsyncIteration:
                    final_text = await emitter.flush()
                    cost_usd = estimate_cost_usd(candidate["model_id"], in_tokens, out_tokens)
                    used_fallback = idx > 0 or candidate["model_id"] != primary_model_id
                    run_rec = self._repo.record_bot_run(
                        correlation_id=corr_id,
                        bot_slug=bot_slug,
                        trigger_type=trigger_type,
                        hop_count=hop_count,
                        llm_model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        status="success",
                        summary=(
                            f"Fallback succeeded on {candidate['model_id']}"
                            if used_fallback
                            else f"Completed on {candidate['model_id']}"
                        ),
                        started_at=started_ts,
                        finished_at=utc_now(),
                    )
                    return LLMResult(
                        output_text=final_text,
                        model_used=candidate["model_id"],
                        input_tokens=in_tokens,
                        output_tokens=out_tokens,
                        estimated_cost_usd=cost_usd,
                        latency_ms=int((time.monotonic() - t0) * 1000),
                        used_fallback=used_fallback,
                        unconfigured_local=False,
                        run_record=run_rec,
                        cancelled=False,
                    )
                except Exception as exc:
                    safe_err = redact_secrets(str(exc), all_secrets)
                    errors.append(f"{candidate['model_id']}: {safe_err}")
                    logger.warning("Candidate LLM failed: %s (%s)", candidate["model_id"], safe_err)

            combined = "; ".join(errors)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=combined[:500],
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"All candidate LLM providers failed: {combined}")

        emitter = _StreamDeltaEmitter(all_secrets=all_secrets, on_delta=on_delta)
        try:
            (
                text,
                model_used,
                in_tokens,
                out_tokens,
                used_fallback,
                cancelled_mid,
            ) = await self._stream_with_pydantic_ai(
                eligible,
                system_prompt=effective_system,
                user_prompt=prompt,
                thinking_level=resolved_thinking,
                images=images,
                emitter=emitter,
                cancel_event=cancel_event,
            )
        except Exception as exc:
            safe_err = redact_secrets(str(exc), all_secrets)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=safe_err[:500],
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"PydanticAI streaming failed: {safe_err}") from exc

        cost_usd = estimate_cost_usd(model_used, in_tokens, out_tokens)
        run_status = "cancelled" if cancelled_mid else "success"
        run_summary = (
            f"Cancelled on {model_used}"
            if cancelled_mid
            else (
                f"Fallback succeeded on {model_used}"
                if used_fallback
                else f"Completed on {model_used}"
            )
        )
        run_rec = self._repo.record_bot_run(
            correlation_id=corr_id,
            bot_slug=bot_slug,
            trigger_type=trigger_type,
            hop_count=hop_count,
            llm_model_used=model_used,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            estimated_cost_usd=cost_usd,
            status=run_status,
            summary=run_summary,
            started_at=started_ts,
            finished_at=utc_now(),
        )
        return LLMResult(
            output_text=text,
            model_used=model_used,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            estimated_cost_usd=cost_usd,
            latency_ms=int((time.monotonic() - t0) * 1000),
            used_fallback=used_fallback,
            unconfigured_local=False,
            run_record=run_rec,
            cancelled=cancelled_mid,
        )
