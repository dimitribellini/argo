"""In-process multi-provider LLM router powered by PydanticAI v2.68+."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
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
DEFAULT_TURN_TIMEOUT_SECONDS = 180.0

# Approximate USD per 1M tokens for transparent cost tracking in bot_runs.
_PRICING_PER_MILLION: dict[str, tuple[float, float]] = {
    # Google Gemini
    "google:gemini-3.8-flash": (0.15, 0.60),
    "google:gemini-3.8-flash-lite": (0.075, 0.30),
    "google:gemini-4-argon": (1.25, 5.00),
    "google:gemini-4-pro": (1.25, 10.00),
    "google:gemini-3.5-flash": (0.15, 0.60),
    "google:gemini-3.5-pro": (1.25, 10.00),
    # Anthropic Claude
    "anthropic:claude-4.5-sonnet": (3.00, 15.00),
    "anthropic:claude-4.5-haiku": (0.80, 4.00),
    "anthropic:claude-4-opus": (15.00, 75.00),
    "anthropic:claude-3-7-sonnet": (3.00, 15.00),
    "anthropic:claude-3-5-haiku": (0.80, 4.00),
    # OpenAI
    "openai:gpt-5": (1.25, 10.00),
    "openai:gpt-5-mini": (0.25, 2.00),
    "openai:gpt-5-nano": (0.05, 0.40),
    "openai:gpt-4.1": (2.00, 8.00),
    "openai:gpt-4.1-mini": (0.40, 1.60),
    "openai:gpt-4o": (2.50, 10.00),
    "openai:gpt-4o-mini": (0.15, 0.60),
    "openai:o3": (2.00, 8.00),
    "openai:o4-mini": (1.10, 4.40),
    # xAI Grok
    "xai:grok-4": (3.00, 15.00),
    "xai:grok-4-fast": (0.20, 0.50),
    "xai:grok-3": (3.00, 15.00),
    "xai:grok-3-mini": (0.30, 0.50),
    # Provider-level fallbacks
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


class NativeToolsUnsupportedError(RuntimeError):
    """Raised when a target model/provider rejects native function tool schemas."""


@dataclass(frozen=True, slots=True)
class NativeToolCall:
    """Single native function/tool invocation returned by the LLM provider."""

    tool_call_id: str
    tool_name: str
    args: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NativeToolResultItem:
    """Executed tool result paired back to a specific tool_call_id for the next turn."""

    tool_call_id: str
    tool_name: str
    result: Any
    images: tuple[bytes, ...] = ()


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
    tools: tuple[Any, ...] = ()
    tool_choice: str = "auto"
    message_history: Any = None
    deferred_tool_results: tuple[NativeToolResultItem, ...] = ()


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
    tool_calls: tuple[NativeToolCall, ...] = ()
    native_tools_used: bool = False
    message_history: Any = None


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


def resolve_model_pricing(
    model_id: str,
    *,
    custom_input: float | None = None,
    custom_output: float | None = None,
) -> dict[str, Any]:
    """Resolve effective USD per 1M input/output token pricing and its provenance."""
    cleaned = str(model_id or "").strip()
    lower = cleaned.lower()
    provider_type = lower.split(":", 1)[0] if ":" in lower else "google"

    base_in, base_out = _PRICING_PER_MILLION.get(provider_type, (0.50, 2.00))
    source = "local" if provider_type == "ollama" else "provider_default"

    if lower in _PRICING_PER_MILLION:
        base_in, base_out = _PRICING_PER_MILLION[lower]
        source = "local" if provider_type == "ollama" else "catalog"
    else:
        for key, rates in _PRICING_PER_MILLION.items():
            if ":" in key and (lower.startswith(f"{key}-") or lower.startswith(f"{key}.")):
                base_in, base_out = rates
                source = "local" if provider_type == "ollama" else "catalog"
                break

    has_custom = custom_input is not None or custom_output is not None
    eff_in = float(custom_input) if custom_input is not None else float(base_in)
    eff_out = float(custom_output) if custom_output is not None else float(base_out)
    if has_custom:
        source = "custom"
    return {
        "input_per_million": round(max(0.0, eff_in), 6),
        "output_per_million": round(max(0.0, eff_out), 6),
        "source": source,
    }


def estimate_cost_usd(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    *,
    input_price_per_million: float | None = None,
    output_price_per_million: float | None = None,
) -> float:
    """Compute estimated USD cost for a single LLM invocation."""
    resolved = resolve_model_pricing(
        model_id,
        custom_input=input_price_per_million,
        custom_output=output_price_per_million,
    )
    in_rate = float(resolved["input_per_million"])
    out_rate = float(resolved["output_per_million"])
    cost = (max(0, input_tokens) * in_rate + max(0, output_tokens) * out_rate) / 1_000_000.0
    return round(cost, 6)


_NON_CHAT_OPENAI_TOKENS = (
    "embedding",
    "whisper",
    "tts",
    "dall-e",
    "moderation",
    "transcribe",
    "realtime",
    "audio",
    "babbage",
    "davinci",
    "sora",
    "gpt-image",
)


async def discover_provider_models(
    provider_type: str,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Query a provider's live model catalog API and attach live or estimated pricing."""
    prov = provider_type.strip().lower()
    if prov not in _SUPPORTED_PROVIDERS:
        raise ModelConfigurationError(f"Unsupported LLM provider '{provider_type}'.")

    key = (api_key or "").strip()
    base = (api_base or "").strip().rstrip("/")
    scrub_values = [key] if key else []

    if prov in {"google", "anthropic", "openai", "xai"} and not key:
        raise ModelConfigurationError(
            f"An API key is required to fetch available models from {prov}."
        )

    import aiohttp

    url = ""
    headers: dict[str, str] = {"Accept": "application/json"}
    params: dict[str, str] | None = None

    if prov == "google":
        root = base or "https://generativelanguage.googleapis.com"
        if root.endswith("/v1beta") or root.endswith("/v1"):
            url = f"{root}/models"
        else:
            url = f"{root}/v1beta/models"
        params = {"key": key, "pageSize": "100"}
    elif prov == "openai":
        root = base or "https://api.openai.com/v1"
        url = f"{root}/models"
        headers["Authorization"] = f"Bearer {key}"
    elif prov == "anthropic":
        root = base or "https://api.anthropic.com/v1"
        url = f"{root}/models"
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    elif prov == "xai":
        root = base or "https://api.x.ai/v1"
        url = f"{root}/models"
        headers["Authorization"] = f"Bearer {key}"
    elif prov == "openrouter":
        root = base or "https://openrouter.ai/api/v1"
        url = f"{root}/models"
        if key:
            headers["Authorization"] = f"Bearer {key}"
    elif prov == "ollama":
        root = base or "http://localhost:11434"
        if root.endswith("/v1"):
            root = root[:-3].rstrip("/")
        url = f"{root}/api/tags"

    try:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, params=params) as resp:
                body_text = await resp.text()
                if resp.status >= 400:
                    safe_body = redact_secrets(body_text[:240], scrub_values)
                    raise LLMExecutionError(
                        f"Provider '{prov}' returned HTTP {resp.status}: {safe_body}"
                    )
                payload = json.loads(body_text) if body_text.strip() else {}
    except (ModelConfigurationError, LLMExecutionError):
        raise
    except Exception as exc:
        safe_err = redact_secrets(str(exc), scrub_values)
        raise LLMExecutionError(f"Failed to query {prov} models endpoint: {safe_err}") from exc

    models: list[dict[str, Any]] = []
    pricing_mode = "estimated"
    source_note = (
        "Model list fetched live from provider API. Pricing is estimated from Argo's catalog "
        "(you can override Input/Output $/1M below)."
    )

    if prov == "google":
        for item in payload.get("models") or []:
            if not isinstance(item, dict):
                continue
            methods = item.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            raw_name = str(item.get("name") or "").strip()
            if raw_name.startswith("models/"):
                raw_name = raw_name[len("models/") :]
            if not raw_name or "gemini-2.5" in raw_name.lower():
                continue
            full_id = f"google:{raw_name}"
            pricing = resolve_model_pricing(full_id)
            models.append(
                {
                    "model_id": full_id,
                    "display_name": str(item.get("displayName") or raw_name),
                    "context_window": item.get("inputTokenLimit"),
                    "input_price_per_million": pricing["input_per_million"],
                    "output_price_per_million": pricing["output_per_million"],
                    "pricing_source": pricing["source"],
                }
            )
    elif prov in {"openai", "xai"}:
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            raw_id = str(item.get("id") or "").strip()
            if not raw_id:
                continue
            lower_id = raw_id.lower()
            if prov == "openai" and any(tok in lower_id for tok in _NON_CHAT_OPENAI_TOKENS):
                continue
            full_id = f"{prov}:{raw_id}"
            pricing = resolve_model_pricing(full_id)
            models.append(
                {
                    "model_id": full_id,
                    "display_name": raw_id,
                    "context_window": None,
                    "input_price_per_million": pricing["input_per_million"],
                    "output_price_per_million": pricing["output_per_million"],
                    "pricing_source": pricing["source"],
                }
            )
    elif prov == "anthropic":
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            raw_id = str(item.get("id") or "").strip()
            if not raw_id:
                continue
            full_id = f"anthropic:{raw_id}"
            pricing = resolve_model_pricing(full_id)
            models.append(
                {
                    "model_id": full_id,
                    "display_name": str(item.get("display_name") or raw_id),
                    "context_window": None,
                    "input_price_per_million": pricing["input_per_million"],
                    "output_price_per_million": pricing["output_per_million"],
                    "pricing_source": pricing["source"],
                }
            )
    elif prov == "openrouter":
        pricing_mode = "live"
        source_note = "Model list and per-1M token pricing fetched live from OpenRouter."
        for item in payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            raw_id = str(item.get("id") or "").strip()
            if not raw_id or "gemini-2.5" in raw_id.lower():
                continue
            full_id = f"openrouter:{raw_id}"
            pr = item.get("pricing") or {}
            try:
                in_rate = round(max(0.0, float(pr.get("prompt") or 0.0) * 1_000_000.0), 6)
                out_rate = round(max(0.0, float(pr.get("completion") or 0.0) * 1_000_000.0), 6)
                p_src = "live"
            except (TypeError, ValueError):
                fallback = resolve_model_pricing(full_id)
                in_rate = fallback["input_per_million"]
                out_rate = fallback["output_per_million"]
                p_src = fallback["source"]
            models.append(
                {
                    "model_id": full_id,
                    "display_name": str(item.get("name") or raw_id),
                    "context_window": item.get("context_length"),
                    "input_price_per_million": in_rate,
                    "output_price_per_million": out_rate,
                    "pricing_source": p_src,
                }
            )
    elif prov == "ollama":
        pricing_mode = "local"
        source_note = "Locally installed Ollama models ($0.00 / $0.00 per 1M tokens)."
        for item in payload.get("models") or []:
            if not isinstance(item, dict):
                continue
            raw_name = str(item.get("name") or item.get("model") or "").strip()
            if not raw_name:
                continue
            models.append(
                {
                    "model_id": f"ollama:{raw_name}",
                    "display_name": raw_name,
                    "context_window": None,
                    "input_price_per_million": 0.0,
                    "output_price_per_million": 0.0,
                    "pricing_source": "local",
                }
            )

    models.sort(key=lambda m: str(m.get("model_id") or "").lower())
    return {
        "provider_type": prov,
        "models": models,
        "pricing_mode": pricing_mode,
        "source_note": source_note,
    }


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


_UNSUPPORTED_TOOL_PATTERNS = (
    "does not support tools",
    "tool calling is not supported",
    "tools are not supported",
    "function calling is not supported",
    "does not support function calling",
    "unsupported parameter: tools",
)


def _is_unsupported_tools_error(exc: BaseException) -> bool:
    """Return True when an exception chain indicates the model lacks native tool support."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        msg = str(cur).lower()
        if any(pat in msg for pat in _UNSUPPORTED_TOOL_PATTERNS):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _parse_native_transport_dict(
    raw: Any,
) -> tuple[bool, tuple[NativeToolCall, ...], Any]:
    """Parse optional native tool call payloads returned by a test/custom LLMTransport."""
    if not isinstance(raw, dict):
        return False, (), None
    has_flag = bool(raw.get("native_tools")) or ("tool_calls" in raw)
    if not has_flag:
        return False, (), None
    raw_calls = raw.get("tool_calls") or []
    parsed: list[NativeToolCall] = []
    if isinstance(raw_calls, (list, tuple)):
        for entry in raw_calls:
            if isinstance(entry, NativeToolCall):
                parsed.append(entry)
                continue
            if not isinstance(entry, dict):
                continue
            t_name = str(
                entry.get("tool_name") or entry.get("name") or entry.get("type") or ""
            ).strip()
            if not t_name:
                continue
            t_id = str(
                entry.get("tool_call_id") or entry.get("id") or make_id("tc")
            ).strip()
            raw_args = entry.get("args")
            if isinstance(raw_args, str):
                try:
                    decoded = json.loads(raw_args)
                    args_dict = decoded if isinstance(decoded, dict) else {}
                except ValueError:
                    args_dict = {}
            elif isinstance(raw_args, dict):
                args_dict = dict(raw_args)
            else:
                args_dict = {
                    k: v
                    for k, v in entry.items()
                    if k not in {"tool_call_id", "id", "tool_name", "name", "type"}
                }
            parsed.append(NativeToolCall(tool_call_id=t_id, tool_name=t_name, args=args_dict))
    return True, tuple(parsed), raw.get("message_history")


class _StreamDeltaEmitter:
    """Coalesce and secret-scrub streamed text chunks safely across chunk boundaries."""

    _TOKEN_PREFIXES = (
        "sk-",
        "ya29.",
        "1//",
        "GOCSPX-",
        "AIza",
        "xai-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "AKIA",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
    )
    _TG_TOKEN_TAIL_RE = re.compile(r"(?:bot)?\d{4,}:?[A-Za-z0-9_-]*$")
    _BEARER_TAIL_RE = re.compile(r"\bBearer\s+$")
    _PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
    _PEM_END_RE = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
    _MAX_SECRET_HOLDBACK = 4096

    def __init__(
        self,
        *,
        all_secrets: Sequence[str],
        on_delta: Callable[[str], Awaitable[None]] | None,
    ) -> None:
        self._secrets = sorted(
            {s.strip() for s in all_secrets if isinstance(s, str) and len(s.strip()) >= 4},
            key=len,
            reverse=True,
        )
        self._on_delta = on_delta
        self._buffer = ""
        self._emitted_raw: list[str] = []
        self._raw_parts: list[str] = []
        self._last_emit_ts = time.monotonic()
        self._swallowing_kind: str | None = None
        self._swallow_pem_tail = ""

    def _active_secret_hold_start(self, buf: str) -> tuple[int | None, str]:
        """Return (hold_start_index, kind) when buf contains an incomplete secret/PEM span."""
        hold_start: int | None = None
        kind = "token"

        # 1. Open PEM private key block without matching END marker
        for m in self._PEM_BEGIN_RE.finditer(buf):
            after = buf[m.end() :]
            if not self._PEM_END_RE.search(after):
                if hold_start is None or m.start() < hold_start:
                    hold_start = m.start()
                    kind = "pem"
        # Partial "-----BEGIN" header at tail after any completed END marker
        last_pem_end = max((m.end() for m in self._PEM_END_RE.finditer(buf)), default=0)
        search_from = max(last_pem_end, len(buf) - 64)
        dash_idx = buf.rfind("-----", search_from)
        if dash_idx >= search_from:
            tail_after_dash = buf[dash_idx:]
            after_dashes = tail_after_dash[5:]
            if "BEGIN".startswith(after_dashes) or tail_after_dash.startswith("-----BEGIN"):
                if not self._PEM_END_RE.search(tail_after_dash):
                    if hold_start is None or dash_idx < hold_start:
                        hold_start = dash_idx
                        kind = "pem"

        # 2. Trailing non-whitespace word (plus preceding "Bearer " if any)
        last_ws = -1
        for i in range(len(buf) - 1, -1, -1):
            if buf[i].isspace():
                last_ws = i
                break
        word_start = last_ws + 1
        bearer_m = self._BEARER_TAIL_RE.search(buf[:word_start])
        if bearer_m:
            word_start = bearer_m.start()

        trailing_span = buf[word_start:]
        if trailing_span:
            word_only = buf[last_ws + 1 :]
            if (
                bearer_m is not None
                or any(pref in word_only for pref in self._TOKEN_PREFIXES)
                or self._TG_TOKEN_TAIL_RE.search(word_only)
                or any(
                    sec.startswith(word_only) or word_only.startswith(sec[:6])
                    for sec in self._secrets
                    if len(sec) >= 6
                )
            ):
                if hold_start is None or word_start < hold_start:
                    hold_start = word_start
                    kind = "token"

        return hold_start, kind

    def _safe_split_index(self) -> int:
        buf = self._buffer
        if not buf:
            return 0
        last_ws = -1
        for i in range(len(buf) - 1, -1, -1):
            if buf[i].isspace():
                last_ws = i
                break
        if last_ws >= 0 and len(buf) - last_ws - 1 <= 64:
            split_at = last_ws + 1
        elif last_ws >= 0:
            split_at = last_ws + 1
        elif len(buf) > 64:
            split_at = len(buf) - 64
        else:
            split_at = 0

        hold_start, _ = self._active_secret_hold_start(buf)
        if hold_start is not None:
            split_at = min(split_at, hold_start)

        # Additionally check if any known secret or token prefix straddles split_at
        tail = buf[:split_at]
        for secret in self._secrets:
            max_check = min(len(secret) - 1, len(tail))
            for k in range(max_check, 0, -1):
                if tail.endswith(secret[:k]):
                    split_at = min(split_at, len(tail) - k)
                    break
        for prefix in (*self._TOKEN_PREFIXES, "Bearer "):
            idx = tail.rfind(prefix)
            if idx >= 0 and len(tail) - idx < 64:
                split_at = min(split_at, idx)
        tg_tail = self._TG_TOKEN_TAIL_RE.search(tail)
        if tg_tail and len(tail) - tg_tail.start() < 64:
            split_at = min(split_at, tg_tail.start())
        # Never slice across a completed PEM END boundary whose internal spaces could expose the block
        for m in self._PEM_END_RE.finditer(buf):
            if m.start() < split_at < m.end():
                split_at = m.end()
        return max(0, split_at)

    async def feed(self, chunk: str) -> None:
        if not chunk:
            return
        self._buffer += chunk

        if self._swallowing_kind == "pem":
            combined = self._swallow_pem_tail + self._buffer
            end_m = self._PEM_END_RE.search(combined)
            if not end_m:
                self._raw_parts.append(self._buffer)
                self._swallow_pem_tail = combined[-64:]
                self._buffer = ""
                return
            consumed_len = max(0, end_m.end() - len(self._swallow_pem_tail))
            self._raw_parts.append(self._buffer[:consumed_len])
            self._buffer = self._buffer[consumed_len:]
            self._swallowing_kind = None
            self._swallow_pem_tail = ""
            if not self._buffer:
                return

        if self._swallowing_kind == "token":
            ws_idx = -1
            for idx, ch in enumerate(self._buffer):
                if ch.isspace():
                    ws_idx = idx
                    break
            if ws_idx == -1:
                self._raw_parts.append(self._buffer)
                self._buffer = ""
                return
            self._raw_parts.append(self._buffer[:ws_idx])
            self._buffer = self._buffer[ws_idx:]
            self._swallowing_kind = None

        hold_start, hold_kind = self._active_secret_hold_start(self._buffer)
        if hold_start is not None and len(self._buffer) - hold_start >= self._MAX_SECRET_HOLDBACK:
            if hold_start > 0:
                await self._emit_slice(hold_start)
            # Emit placeholder once and enter swallowing mode for the remaining unspaced tail
            raw_secret_prefix = self._buffer
            self._raw_parts.append(raw_secret_prefix)
            self._buffer = ""
            marker = "<REDACTED_PRIVATE_KEY>" if hold_kind == "pem" else "<REDACTED_TOKEN>"
            self._emitted_raw.append(marker)
            self._last_emit_ts = time.monotonic()
            if self._on_delta is not None:
                await self._on_delta(marker)
            self._swallowing_kind = hold_kind
            self._swallow_pem_tail = raw_secret_prefix[-64:] if hold_kind == "pem" else ""
            return

        now = time.monotonic()
        split_at = self._safe_split_index()
        if split_at <= 0:
            return
        candidate = self._buffer[:split_at]
        if (now - self._last_emit_ts) >= 0.06 or len(candidate) >= 18 or "\n" in candidate:
            await self._emit_slice(split_at)

    async def flush(self) -> str:
        if self._swallowing_kind is not None:
            if self._buffer:
                self._raw_parts.append(self._buffer)
                self._buffer = ""
            self._swallowing_kind = None
            self._swallow_pem_tail = ""
        elif self._buffer:
            await self._emit_slice(len(self._buffer))
        return "".join(self._raw_parts)

    async def _emit_slice(self, length: int) -> None:
        raw_slice = self._buffer[:length]
        self._buffer = self._buffer[length:]
        if not raw_slice:
            return
        self._raw_parts.append(raw_slice)
        safe_slice = redact_secrets(raw_slice, self._secrets)
        self._emitted_raw.append(safe_slice)
        self._last_emit_ts = time.monotonic()
        if self._on_delta is not None:
            await self._on_delta(safe_slice)

    @property
    def current_text(self) -> str:
        if self._swallowing_kind is not None:
            return "".join(self._emitted_raw)
        partial_tail = redact_secrets(self._buffer, self._secrets) if self._buffer else ""
        return "".join(self._emitted_raw) + partial_tail


class LLMRouter:
    """In-process multi-LLM router with budget guardrails, failover, and bot_runs auditing."""

    def __init__(
        self,
        repo: ArgoRepository,
        transport: LLMTransport | None = None,
        *,
        native_transport_tools: bool = False,
        turn_timeout_seconds: float | None = DEFAULT_TURN_TIMEOUT_SECONDS,
    ) -> None:
        self._repo = repo
        self._transport = transport
        self._native_transport_tools = bool(native_transport_tools)
        self._turn_timeout_seconds = turn_timeout_seconds
        self._non_tool_models: set[str] = set()

    def uses_native_tools(self, *, requested_model: str | None = None) -> bool:
        """Return whether native PydanticAI tool calling is enabled for this model/transport."""
        if self._transport is not None:
            return self._native_transport_tools
        try:
            candidates = self._select_candidates(
                requested_model=requested_model,
                strict_provider=False,
            )
            primary_id = candidates[0]["model_id"] if candidates else (requested_model or "")
        except ModelConfigurationError:
            primary_id = requested_model or ""
        return primary_id not in self._non_tool_models

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
                        "daily_token_limit": matching_provider.get("daily_token_limit") if matching_provider else None,
                        "monthly_budget_usd": matching_provider.get("monthly_budget_usd") if matching_provider else None,
                        "input_price_per_million": matching_provider.get("input_price_per_million") if matching_provider else None,
                        "output_price_per_million": matching_provider.get("output_price_per_million") if matching_provider else None,
                        "budget_parent_model_id": matching_provider["model_id"] if matching_provider else None,
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

            usage = dict(self._repo.provider_usage_totals(candidate["model_id"]))
            parent_model = str(candidate.get("budget_parent_model_id") or "").strip()
            if parent_model:
                if hasattr(self._repo, "provider_type_ephemeral_usage_totals"):
                    usage = self._repo.provider_type_ephemeral_usage_totals(
                        str(candidate.get("provider_type") or ""),
                        parent_model_id=parent_model,
                    )
                elif parent_model != candidate["model_id"]:
                    parent_usage = self._repo.provider_usage_totals(parent_model)
                    usage = {
                        "today_tokens": int(usage.get("today_tokens", 0)) + int(parent_usage.get("today_tokens", 0)),
                        "month_cost_usd": float(usage.get("month_cost_usd", 0.0)) + float(parent_usage.get("month_cost_usd", 0.0)),
                    }
            else:
                # Also roll up any unconfigured sibling usage under this provider_type onto the configured model
                if hasattr(self._repo, "provider_type_ephemeral_usage_totals"):
                    combined = self._repo.provider_type_ephemeral_usage_totals(
                        str(candidate.get("provider_type") or ""),
                        parent_model_id=candidate["model_id"],
                    )
                    usage = combined
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
        matched_model_id = (
            self._match_response_model(candidates, response_model)
            if response_model
            else primary_model_id
        )

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
        raw_resp = str(response_model or "").strip()
        if not raw_resp:
            return primary_model_id

        def _strip_model_norm(val: str) -> str:
            cleaned = val.strip().lower()
            if ":" in cleaned:
                cleaned = cleaned.split(":", 1)[1]
            if cleaned.startswith("models/"):
                cleaned = cleaned[len("models/"):]
            return cleaned

        resp_lower = raw_resp.lower()
        resp_norm = _strip_model_norm(raw_resp)

        # Pass 1: exact full or normalized name match
        for candidate in candidates:
            cand_id = str(candidate["model_id"])
            _, short_name = validate_model_id(cand_id)
            cand_norm = _strip_model_norm(short_name)
            if (
                resp_lower == cand_id.lower()
                or resp_lower == short_name.lower()
                or resp_norm == cand_norm
            ):
                return cand_id

        # Pass 2: version/snapshot-suffixed prefix match (prefer longest matching model name)
        best_match: tuple[int, str] | None = None
        for candidate in candidates:
            cand_id = str(candidate["model_id"])
            _, short_name = validate_model_id(cand_id)
            cand_norm = _strip_model_norm(short_name)
            if not cand_norm:
                continue
            for sep in ("-", "@", ":"):
                if resp_norm.startswith(f"{cand_norm}{sep}"):
                    if best_match is None or len(cand_norm) > best_match[0]:
                        best_match = (len(cand_norm), cand_id)
                    break
        if best_match is not None:
            return best_match[1]
        return primary_model_id

    @staticmethod
    def _compact_tool_return_value(value: Any, *, _depth: int = 0) -> Any:
        """Compact an older ToolReturnPart/observation payload while preserving list results across providers."""
        if isinstance(value, str):
            return value[:400] + ("..." if len(value) > 400 else "")
        if isinstance(value, list):
            return [
                "[Earlier binary attachment omitted to save context]"
                if (hasattr(item, "media_type") and hasattr(item, "data"))
                else LLMRouter._compact_tool_return_value(item, _depth=_depth + 1)
                for item in value[:8]
            ]
        if not isinstance(value, dict):
            return value
        compact: dict[str, Any] = {"compacted": True}
        scalar_keys = (
            "type",
            "action",
            "status",
            "id",
            "name",
            "provider",
            "account_slug",
            "vault_slug",
            "host",
            "port",
            "session_id",
            "command",
            "exit_code",
            "url",
            "title",
            "subject",
            "from",
            "to",
            "date",
            "path",
            "alias",
            "dataset_id",
            "scroll_y",
            "screen_hash",
            "slug",
            "collection",
            "approval_id",
            "row_count",
            "count",
            "total",
            "detail",
            "note",
            "runner_notice",
            "columns",
        )
        for key in scalar_keys:
            if key in value and value[key] is not None and value[key] != "":
                val = value[key]
                compact[key] = (
                    val[:400] + ("..." if len(val) > 400 else "")
                    if isinstance(val, str) and len(val) > 400
                    else (val[:30] if isinstance(val, list) else val)
                )
        for long_scalar in ("summary",):
            s_val = value.get(long_scalar)
            if isinstance(s_val, str) and s_val.strip():
                compact[long_scalar] = s_val[:600] + ("..." if len(s_val) > 600 else "")
        for text_key in ("screen_text", "stdout", "stderr", "content", "markdown", "prompt_line", "text", "body", "snippet"):
            val = value.get(text_key)
            if isinstance(val, str) and val.strip():
                compact[text_key] = val[:400] + ("..." if len(val) > 400 else "")
        skip_list_keys = {
            "images",
            "attachments_bytes",
            "raw_bytes",
            "image_base64",
            "columns",
            "interactive_elements",
        }
        if _depth < 2:
            for key, val in value.items():
                if key in skip_list_keys or not isinstance(val, list) or not val:
                    continue
                if all(hasattr(item, "media_type") and hasattr(item, "data") for item in val):
                    compact[key] = f"[{len(val)} earlier binary attachment(s) omitted]"
                    continue
                max_items = 5 if _depth == 0 else 3
                compact[key] = [
                    LLMRouter._compact_tool_return_value(item, _depth=_depth + 1)
                    for item in val[:max_items]
                ]
                if len(val) > max_items:
                    compact[f"{key}_truncated_from"] = len(val)
        return compact

    @staticmethod
    def _compact_native_message_history(
        message_history: Sequence[Any] | None,
        *,
        keep_recent_tool_requests: int = 4,
        keep_recent_vision_requests: int = 2,
    ) -> list[Any] | None:
        """Compact old ToolReturnPart/BinaryContent entries without mutating ModelResponses."""
        if message_history is None:
            return None
        history_list = list(message_history)
        if not history_list:
            return history_list

        tool_request_indices: list[int] = []
        vision_request_indices: list[int] = []
        for idx, msg in enumerate(history_list):
            if getattr(msg, "kind", None) != "request":
                continue
            parts = getattr(msg, "parts", None) or ()
            if any(getattr(p, "part_kind", None) == "tool-return" for p in parts):
                tool_request_indices.append(idx)
            has_binary = False
            for p in parts:
                p_content = getattr(p, "content", None)
                if isinstance(p_content, (list, tuple)) and any(
                    hasattr(item, "media_type") and hasattr(item, "data") for item in p_content
                ):
                    has_binary = True
                    break
            if has_binary:
                vision_request_indices.append(idx)

        recent_tool_set = set(tool_request_indices[-keep_recent_tool_requests:])
        recent_vision_set = set(vision_request_indices[-keep_recent_vision_requests:])

        compacted_messages: list[Any] = []
        for idx, msg in enumerate(history_list):
            if getattr(msg, "kind", None) != "request":
                compacted_messages.append(msg)
                continue
            compact_tools_here = idx in tool_request_indices and idx not in recent_tool_set
            compact_vision_here = idx in vision_request_indices and idx not in recent_vision_set
            if not compact_tools_here and not compact_vision_here:
                compacted_messages.append(msg)
                continue
            try:
                parts = list(getattr(msg, "parts", None) or ())
                new_parts: list[Any] = []
                changed = False
                for part in parts:
                    p_kind = getattr(part, "part_kind", None)
                    if compact_tools_here and p_kind == "tool-return":
                        new_parts.append(
                            dataclasses.replace(
                                part,
                                content=LLMRouter._compact_tool_return_value(
                                    getattr(part, "content", None)
                                ),
                            )
                        )
                        changed = True
                    elif compact_vision_here and p_kind == "user-prompt":
                        raw_c = getattr(part, "content", None)
                        if isinstance(raw_c, (list, tuple)):
                            stripped_c = [
                                "[Earlier screenshot omitted to save context]"
                                if (hasattr(item, "media_type") and hasattr(item, "data"))
                                else item
                                for item in raw_c
                            ]
                            new_parts.append(dataclasses.replace(part, content=stripped_c))
                            changed = True
                        else:
                            new_parts.append(part)
                    else:
                        new_parts.append(part)
                compacted_messages.append(
                    dataclasses.replace(msg, parts=new_parts) if changed else msg
                )
            except Exception:
                compacted_messages.append(msg)

        return compacted_messages

    async def _run_native_with_pydantic_ai(
        self,
        candidates: list[dict[str, Any]],
        *,
        system_prompt: str,
        user_prompt: str,
        thinking_level: str,
        tools: Sequence[Any] = (),
        tool_choice: str = "auto",
        message_history: Any = None,
        deferred_tool_results: Sequence[NativeToolResultItem] = (),
        images: Sequence[bytes] | None = None,
        emitter: _StreamDeltaEmitter | None = None,
        on_tool_start: Callable[[str], Awaitable[None]] | None = None,
        cancel_event: asyncio.Event | None = None,
        stream_output: bool = True,
    ) -> tuple[str, str, int, int, bool, bool, tuple[NativeToolCall, ...], Any]:
        """Run one PydanticAI native tool-calling turn with ExternalToolset and agent.iter()."""
        from pydantic_ai import (
            Agent,
            BinaryContent,
            DeferredToolRequests,
            DeferredToolResults,
            ExternalToolset,
            ToolDefinition,
            ToolReturn,
        )
        from pydantic_ai.messages import (
            PartDeltaEvent,
            PartStartEvent,
            TextPart,
            TextPartDelta,
            ToolCallPart,
        )
        from pydantic_ai.models.fallback import FallbackModel
        from pydantic_ai.settings import ModelSettings

        built_models = [_build_single_pydantic_ai_model(c) for c in candidates]
        primary_model_id = candidates[0]["model_id"]
        model_spec = built_models[0] if len(built_models) == 1 else FallbackModel(*built_models)

        tool_defs: list[Any] = []
        for t in tools:
            if isinstance(t, ToolDefinition):
                tool_defs.append(t)
            else:
                tool_defs.append(
                    ToolDefinition(
                        name=t.name,
                        description=t.description,
                        parameters_json_schema=dict(t.parameters_json_schema),
                        kind="external",
                    )
                )

        toolsets = [ExternalToolset(tool_defs)] if tool_defs else []
        output_type: Any = [str, DeferredToolRequests] if toolsets else str
        settings_kwargs: dict[str, Any] = {"thinking": thinking_level}
        if tool_choice == "none" and toolsets:
            settings_kwargs["tool_choice"] = "none"

        agent = Agent(
            model=model_spec,
            instructions=system_prompt or None,
            toolsets=toolsets,
            output_type=output_type,
            model_settings=ModelSettings(**settings_kwargs),  # type: ignore[arg-type]
        )

        compacted_history = self._compact_native_message_history(message_history)
        pydantic_deferred: Any = None
        if deferred_tool_results:
            calls_map: dict[str, Any] = {}
            for item in deferred_tool_results:
                if item.images:
                    calls_map[item.tool_call_id] = ToolReturn(
                        return_value=item.result,
                        content=[
                            "Updated visual screenshot after tool execution:",
                            *[
                                BinaryContent(data=img, media_type="image/png")
                                for img in item.images
                                if img
                            ],
                        ],
                    )
                else:
                    calls_map[item.tool_call_id] = item.result
            pydantic_deferred = DeferredToolResults(calls=calls_map)
            run_input: Any = None
        else:
            run_input = user_prompt
            image_items = [img for img in (images or ()) if img]
            if image_items:
                run_input = [
                    user_prompt,
                    *[BinaryContent(data=img, media_type="image/png") for img in image_items],
                ]

        def _extract_calls_from_output(output_obj: Any) -> list[NativeToolCall]:
            out_calls: list[NativeToolCall] = []
            if not isinstance(output_obj, DeferredToolRequests):
                return out_calls
            for call_part in output_obj.calls:
                t_name = str(getattr(call_part, "tool_name", "") or "").strip()
                t_id = str(getattr(call_part, "tool_call_id", "") or "").strip() or make_id("tc")
                if hasattr(call_part, "args_as_dict"):
                    raw_args = call_part.args_as_dict()
                else:
                    raw_args = getattr(call_part, "args", {})
                args_dict = dict(raw_args) if isinstance(raw_args, dict) else {}
                if t_name:
                    out_calls.append(
                        NativeToolCall(tool_call_id=t_id, tool_name=t_name, args=args_dict)
                    )
            return out_calls

        matched_model_id = primary_model_id
        input_tokens = 0
        output_tokens = 0
        extracted_calls: list[NativeToolCall] = []
        updated_history: Any = compacted_history
        text_parts: list[str] = []

        if not stream_output:
            run_coro = agent.run(
                run_input,
                message_history=compacted_history,
                deferred_tool_results=pydantic_deferred,
            )
            if self._turn_timeout_seconds is not None and self._turn_timeout_seconds > 0:
                try:
                    result = await asyncio.wait_for(run_coro, timeout=self._turn_timeout_seconds)
                except asyncio.TimeoutError as exc:
                    raise TimeoutError(
                        f"LLM turn timed out after {self._turn_timeout_seconds:.0f}s."
                    ) from exc
            else:
                result = await run_coro
            with contextlib.suppress(Exception):
                usage = result.usage()
                input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
                output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
            with contextlib.suppress(Exception):
                resp = getattr(result, "response", None)
                resp_model = getattr(resp, "model_name", None) or ""
                if resp_model:
                    matched_model_id = self._match_response_model(candidates, resp_model)
            with contextlib.suppress(Exception):
                updated_history = result.all_messages()
            final_out = getattr(result, "output", None)
            if isinstance(final_out, DeferredToolRequests):
                extracted_calls = _extract_calls_from_output(final_out)
                final_text = ""
            elif final_out is not None:
                final_text = str(final_out)
            else:
                final_text = ""
            used_fallback = matched_model_id != primary_model_id
            return (
                final_text,
                matched_model_id,
                input_tokens,
                output_tokens,
                used_fallback,
                False,
                tuple(extracted_calls),
                updated_history,
            )

        final_output_val: Any = None
        seen_started_call_ids: set[str] = set()

        async def _consume() -> None:
            nonlocal matched_model_id, input_tokens, output_tokens, updated_history, final_output_val
            async with agent.iter(
                run_input,
                message_history=compacted_history,
                deferred_tool_results=pydantic_deferred,
            ) as agent_run:
                async for node in agent_run:
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    if Agent.is_model_request_node(node):
                        async with node.stream(agent_run.ctx) as request_stream:
                            async for event in request_stream:
                                if cancel_event is not None and cancel_event.is_set():
                                    break
                                if isinstance(event, PartStartEvent):
                                    part = event.part
                                    if isinstance(part, TextPart) and part.content:
                                        chunk = str(part.content)
                                        text_parts.append(chunk)
                                        if emitter is not None:
                                            await emitter.feed(chunk)
                                    elif isinstance(part, ToolCallPart) and part.tool_name:
                                        tc_id = str(getattr(part, "tool_call_id", "") or "")
                                        if tc_id:
                                            seen_started_call_ids.add(tc_id)
                                        if on_tool_start is not None:
                                            await on_tool_start(str(part.tool_name))
                                elif isinstance(event, PartDeltaEvent):
                                    delta = event.delta
                                    if isinstance(delta, TextPartDelta) and delta.content_delta:
                                        chunk = str(delta.content_delta)
                                        text_parts.append(chunk)
                                        if emitter is not None:
                                            await emitter.feed(chunk)
                        with contextlib.suppress(Exception):
                            resp = request_stream.get()
                            resp_model = getattr(resp, "model_name", None) or ""
                            if resp_model:
                                matched_model_id = self._match_response_model(candidates, resp_model)

                if agent_run.result is not None:
                    run_res = agent_run.result
                    final_output_val = getattr(run_res, "output", None)
                    with contextlib.suppress(Exception):
                        usage = run_res.usage()
                        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
                        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
                    with contextlib.suppress(Exception):
                        resp = getattr(run_res, "response", None)
                        resp_model = getattr(resp, "model_name", None) or ""
                        if resp_model:
                            matched_model_id = self._match_response_model(candidates, resp_model)
                    with contextlib.suppress(Exception):
                        updated_history = run_res.all_messages()

            if (
                not (cancel_event is not None and cancel_event.is_set())
                and not text_parts
                and isinstance(final_output_val, str)
                and final_output_val
            ):
                text_parts.append(final_output_val)
                if emitter is not None:
                    await emitter.feed(final_output_val)

        cancelled, _ = await self._await_or_cancel(
            _consume(),
            cancel_event,
            timeout_seconds=self._turn_timeout_seconds,
        )
        cancelled = cancelled or bool(cancel_event and cancel_event.is_set())
        if isinstance(final_output_val, DeferredToolRequests):
            extracted_calls = _extract_calls_from_output(final_output_val)
            if not cancelled and on_tool_start is not None:
                for call in extracted_calls:
                    if call.tool_call_id not in seen_started_call_ids:
                        await on_tool_start(call.tool_name)
        final_text = await emitter.flush() if emitter is not None else "".join(text_parts)
        if cancelled and output_tokens == 0 and final_text:
            output_tokens = max(1, len(final_text) // 4)
        used_fallback = matched_model_id != primary_model_id
        return (
            final_text,
            matched_model_id,
            input_tokens,
            output_tokens,
            used_fallback,
            cancelled,
            tuple(extracted_calls),
            updated_history,
        )

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

        cancelled, _ = await self._await_or_cancel(
            _consume(),
            cancel_event,
            timeout_seconds=self._turn_timeout_seconds,
        )
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
        triggered_by_email: str = "",
        strict_provider: bool = False,
        images: Sequence[bytes] | None = None,
        tools: Sequence[Any] = (),
        tool_choice: str = "auto",
        message_history: Any = None,
        deferred_tool_results: Sequence[NativeToolResultItem] = (),
    ) -> LLMResult:
        """Route an LLM request through PydanticAI/FallbackModel and audit bot_runs."""
        corr_id = correlation_id or make_id("corr")
        started_ts = utc_now()
        t0 = time.monotonic()
        use_native = bool(tools or message_history is not None or deferred_tool_results)

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
        repo_secrets = (
            self._repo.collect_all_sensitive_secrets()
            if hasattr(self._repo, "collect_all_sensitive_secrets")
            else ()
        )
        all_secrets = [
            *[c["api_key"] for c in candidates if c.get("api_key")],
            *[str(s) for s in repo_secrets if str(s).strip()],
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
                    triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                    triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                    tools=tuple(tools),
                    tool_choice=tool_choice,
                    message_history=message_history,
                    deferred_tool_results=tuple(deferred_tool_results),
                )
                try:
                    raw = await self._transport(req)
                    text, in_tokens, out_tokens = _extract_transport_output(raw)
                    native_used, parsed_calls, next_hist = _parse_native_transport_dict(raw)
                    cost_usd = estimate_cost_usd(
                        candidate["model_id"],
                        in_tokens,
                        out_tokens,
                        input_price_per_million=candidate.get("input_price_per_million"),
                        output_price_per_million=candidate.get("output_price_per_million"),
                    )
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
                        triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                        tool_calls=parsed_calls,
                        native_tools_used=native_used,
                        message_history=next_hist,
                    )
                except NativeToolsUnsupportedError:
                    self._non_tool_models.add(candidate["model_id"])
                    raise
                except Exception as exc:
                    if use_native and _is_unsupported_tools_error(exc):
                        self._non_tool_models.add(candidate["model_id"])
                        raise NativeToolsUnsupportedError(
                            redact_secrets(str(exc), all_secrets)
                        ) from exc
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
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"All candidate LLM providers failed: {combined}")

        parsed_calls: tuple[NativeToolCall, ...] = ()
        next_hist: Any = None
        native_used = False
        try:
            if use_native:
                (
                    text,
                    model_used,
                    in_tokens,
                    out_tokens,
                    used_fallback,
                    _cancelled,
                    parsed_calls,
                    next_hist,
                ) = await self._run_native_with_pydantic_ai(
                    eligible,
                    system_prompt=effective_system,
                    user_prompt=prompt,
                    thinking_level=resolved_thinking,
                    tools=tools,
                    tool_choice=tool_choice,
                    message_history=message_history,
                    deferred_tool_results=deferred_tool_results,
                    images=images,
                    stream_output=False,
                )
                native_used = True
            else:
                text, model_used, in_tokens, out_tokens, used_fallback = await self._run_with_pydantic_ai(
                    eligible,
                    system_prompt=effective_system,
                    user_prompt=prompt,
                    thinking_level=resolved_thinking,
                    images=images,
                )
        except NativeToolsUnsupportedError as exc:
            if len(eligible) == 1:
                self._non_tool_models.add(eligible[0]["model_id"])
            else:
                msg_low = str(exc).lower()
                for cand in eligible:
                    _, short_n = validate_model_id(cand["model_id"])
                    if short_n and short_n.lower() in msg_low:
                        self._non_tool_models.add(cand["model_id"])
            raise
        except Exception as exc:
            if use_native and _is_unsupported_tools_error(exc):
                if len(eligible) == 1:
                    self._non_tool_models.add(eligible[0]["model_id"])
                else:
                    msg_low = str(exc).lower()
                    for cand in eligible:
                        _, short_n = validate_model_id(cand["model_id"])
                        if short_n and short_n.lower() in msg_low:
                            self._non_tool_models.add(cand["model_id"])
                raise NativeToolsUnsupportedError(redact_secrets(str(exc), all_secrets)) from exc
            safe_err = redact_secrets(str(exc), all_secrets)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=safe_err[:500],
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"PydanticAI execution failed: {safe_err}") from exc

        matched_cand = next(
            (c for c in eligible if c["model_id"] == model_used),
            eligible[0] if eligible else {},
        )
        cost_usd = estimate_cost_usd(
            model_used,
            in_tokens,
            out_tokens,
            input_price_per_million=matched_cand.get("input_price_per_million"),
            output_price_per_million=matched_cand.get("output_price_per_million"),
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
            status="success",
            summary=(
                f"Fallback succeeded on {model_used}"
                if used_fallback
                else f"Completed on {model_used}"
            ),
            triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
            tool_calls=parsed_calls,
            native_tools_used=native_used,
            message_history=next_hist,
        )

    @staticmethod
    async def _await_or_cancel(
        awaitable: Any,
        cancel_event: asyncio.Event | None,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[bool, Any]:
        """Await a coroutine while waking promptly if cancel_event is triggered or timeout expires."""
        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None and float(timeout_seconds) > 0
            else None
        )
        if cancel_event is None:
            if effective_timeout is not None:
                try:
                    return False, await asyncio.wait_for(awaitable, timeout=effective_timeout)
                except asyncio.TimeoutError as exc:
                    raise TimeoutError(f"LLM turn timed out after {effective_timeout:.0f}s.") from exc
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
                timeout=effective_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                work_task.cancel()
                with contextlib.suppress(BaseException):
                    await work_task
                raise TimeoutError(f"LLM turn timed out after {effective_timeout:.0f}s.")
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
        on_tool_start: Callable[[str], Awaitable[None]] | None = None,
        cancel_event: asyncio.Event | None = None,
        extra_secrets: Sequence[str] | None = None,
        requested_model: str | None = None,
        system_prompt: str = "",
        trigger_type: str = "manual",
        correlation_id: str | None = None,
        hop_count: int = 1,
        thinking_level: str | None = None,
        outbound_rbac: str = "draft",
        triggered_by_email: str = "",
        strict_provider: bool = False,
        images: Sequence[bytes] | None = None,
        tools: Sequence[Any] = (),
        tool_choice: str = "auto",
        message_history: Any = None,
        deferred_tool_results: Sequence[NativeToolResultItem] = (),
    ) -> LLMResult:
        """Stream an LLM response via PydanticAI or test transport with budget & cancel guardrails."""
        corr_id = correlation_id or make_id("corr")
        started_ts = utc_now()
        t0 = time.monotonic()
        use_native = bool(tools or message_history is not None or deferred_tool_results)

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
        repo_secrets = (
            self._repo.collect_all_sensitive_secrets()
            if hasattr(self._repo, "collect_all_sensitive_secrets")
            else ()
        )
        all_secrets = [
            *[c["api_key"] for c in candidates if c.get("api_key")],
            *[str(s) for s in (extra_secrets or ()) if str(s).strip()],
            *[str(s) for s in repo_secrets if str(s).strip()],
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
                    triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                    triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                    tools=tuple(tools),
                    tool_choice=tool_choice,
                    message_history=message_history,
                    deferred_tool_results=tuple(deferred_tool_results),
                )
                emitter = _StreamDeltaEmitter(all_secrets=all_secrets, on_delta=on_delta)
                native_used = False
                parsed_calls: tuple[NativeToolCall, ...] = ()
                next_hist: Any = None
                try:
                    cancelled_mid, raw = await self._await_or_cancel(
                        self._transport(req), cancel_event
                    )
                    in_tokens = 0
                    out_tokens = 0
                    if not cancelled_mid:
                        native_used, parsed_calls, next_hist = _parse_native_transport_dict(raw)
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

                    if not cancelled_mid and native_used and on_tool_start is not None:
                        for call in parsed_calls:
                            await on_tool_start(call.tool_name)

                    final_text = await emitter.flush()
                    if cancelled_mid and out_tokens == 0 and final_text:
                        out_tokens = max(1, len(final_text) // 4)
                    cost_usd = estimate_cost_usd(
                        candidate["model_id"],
                        in_tokens,
                        out_tokens,
                        input_price_per_million=candidate.get("input_price_per_million"),
                        output_price_per_million=candidate.get("output_price_per_million"),
                    )
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
                        triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                        tool_calls=parsed_calls if not cancelled_mid else (),
                        native_tools_used=native_used,
                        message_history=next_hist,
                    )
                except StopAsyncIteration:
                    if native_used and on_tool_start is not None:
                        for call in parsed_calls:
                            await on_tool_start(call.tool_name)
                    final_text = await emitter.flush()
                    cost_usd = estimate_cost_usd(
                        candidate["model_id"],
                        in_tokens,
                        out_tokens,
                        input_price_per_million=candidate.get("input_price_per_million"),
                        output_price_per_million=candidate.get("output_price_per_million"),
                    )
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
                        triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
                        tool_calls=parsed_calls,
                        native_tools_used=native_used,
                        message_history=next_hist,
                    )
                except NativeToolsUnsupportedError:
                    self._non_tool_models.add(candidate["model_id"])
                    raise
                except Exception as exc:
                    if use_native and _is_unsupported_tools_error(exc):
                        self._non_tool_models.add(candidate["model_id"])
                        raise NativeToolsUnsupportedError(
                            redact_secrets(str(exc), all_secrets)
                        ) from exc
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
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"All candidate LLM providers failed: {combined}")

        emitter = _StreamDeltaEmitter(all_secrets=all_secrets, on_delta=on_delta)
        parsed_calls = ()
        next_hist = None
        native_used = False
        try:
            if use_native:
                (
                    text,
                    model_used,
                    in_tokens,
                    out_tokens,
                    used_fallback,
                    cancelled_mid,
                    parsed_calls,
                    next_hist,
                ) = await self._run_native_with_pydantic_ai(
                    eligible,
                    system_prompt=effective_system,
                    user_prompt=prompt,
                    thinking_level=resolved_thinking,
                    tools=tools,
                    tool_choice=tool_choice,
                    message_history=message_history,
                    deferred_tool_results=deferred_tool_results,
                    images=images,
                    emitter=emitter,
                    on_tool_start=on_tool_start,
                    cancel_event=cancel_event,
                    stream_output=True,
                )
                native_used = True
            else:
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
        except NativeToolsUnsupportedError as exc:
            if len(eligible) == 1:
                self._non_tool_models.add(eligible[0]["model_id"])
            else:
                msg_low = str(exc).lower()
                for cand in eligible:
                    _, short_n = validate_model_id(cand["model_id"])
                    if short_n and short_n.lower() in msg_low:
                        self._non_tool_models.add(cand["model_id"])
            raise
        except Exception as exc:
            if use_native and _is_unsupported_tools_error(exc):
                if len(eligible) == 1:
                    self._non_tool_models.add(eligible[0]["model_id"])
                else:
                    msg_low = str(exc).lower()
                    for cand in eligible:
                        _, short_n = validate_model_id(cand["model_id"])
                        if short_n and short_n.lower() in msg_low:
                            self._non_tool_models.add(cand["model_id"])
                raise NativeToolsUnsupportedError(redact_secrets(str(exc), all_secrets)) from exc
            safe_err = redact_secrets(str(exc), all_secrets)
            self._repo.record_bot_run(
                correlation_id=corr_id,
                bot_slug=bot_slug,
                trigger_type=trigger_type,
                hop_count=hop_count,
                llm_model_used=eligible[0]["model_id"],
                status="error",
                summary=safe_err[:500],
                triggered_by_email=str(triggered_by_email or "").strip().lower(),
                started_at=started_ts,
                finished_at=utc_now(),
            )
            raise LLMExecutionError(f"PydanticAI streaming failed: {safe_err}") from exc

        matched_cand = next(
            (c for c in eligible if c["model_id"] == model_used),
            eligible[0] if eligible else {},
        )
        cost_usd = estimate_cost_usd(
            model_used,
            in_tokens,
            out_tokens,
            input_price_per_million=matched_cand.get("input_price_per_million"),
            output_price_per_million=matched_cand.get("output_price_per_million"),
        )
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
            triggered_by_email=str(triggered_by_email or "").strip().lower(),
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
            tool_calls=parsed_calls if not cancelled_mid else (),
            native_tools_used=native_used,
            message_history=next_hist,
        )
