"""Conversational runtime Bot Builder generating validated declarative Bot JSON specs."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from argo_core.db.repositories import ArgoRepository, collection_slug, make_id, slugify
from argo_core.llm.router import LLMRouter, validate_model_id

_API_SERVICE_MARKERS = (
    "gmail",
    "google calendar",
    "google drive",
    "google meet",
    "linkedin",
    "telegram",
    "rss",
    "atom",
    "webhook",
)

_LEGACY_DESKTOP_MARKERS = (
    "legacy portal",
    "selkies",
    "no api",
    "without api",
    "lacks public api",
    "partner portal",
    "browser desktop",
)

_ON_EVENT_RE = re.compile(
    r"(?:on_event\s*[:=]\s*|subscribe\s+to\s+|when\s+)([a-z0-9]+(?:[._-][a-z0-9]+)+)",
    re.IGNORECASE,
)
_EVERY_INTERVAL_RE = re.compile(r"every\s+(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours)\b", re.IGNORECASE)
_COLLECTION_QUOTED_RE = re.compile(r"collection[s]?\s+['\"`]?([a-zA-Z0-9_-]+)['\"`]?", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>'\"`)\]]+", re.IGNORECASE)


def _extract_urls(prompt: str) -> tuple[list[str], list[str]]:
    feed_urls: list[str] = []
    webpage_urls: list[str] = []
    for raw in _URL_RE.findall(prompt or ""):
        cleaned = raw.rstrip(".,;:!?)")
        if not cleaned or cleaned in feed_urls or cleaned in webpage_urls:
            continue
        lowered = cleaned.lower()
        if (
            lowered.endswith((".xml", ".rss", ".atom"))
            or "/feed" in lowered
            or "/rss" in lowered
            or "format=rss" in lowered
            or "format=atom" in lowered
        ):
            feed_urls.append(cleaned)
        else:
            webpage_urls.append(cleaned)
    return feed_urls, webpage_urls


def _infer_bot_name(prompt: str) -> str:
    cleaned = prompt.strip()
    lower = cleaned.lower()
    if "news collector" in lower or ("rss" in lower and "collect" in lower):
        return "News Collector"
    if "editorial reviewer" in lower or ("review" in lower and "audit" in lower):
        return "Editorial Reviewer"
    if "gatekeeper" in lower:
        return "Release Gatekeeper"
    if "portal" in lower and any(tok in lower for tok in ("extract", "read", "legacy", "partner")):
        return "Portal Extractor"

    named_match = re.search(
        r"\b(?:called|named)\s+[\"']?([A-Za-z0-9][A-Za-z0-9 _-]{1,40}?)(?:[\"']|\s+(?:that|to|for|with|every|on_event)\b|$)",
        cleaned,
        re.IGNORECASE,
    )
    if named_match:
        candidate = " ".join(named_match.group(1).split()).strip(" .,-")
        if candidate:
            return candidate[:60]

    feed_urls, webpage_urls = _extract_urls(cleaned)
    first_url = (feed_urls or webpage_urls or [None])[0]
    if first_url:
        parsed = urllib.parse.urlparse(first_url)
        host = (parsed.hostname or "").lower()
        parts = [p for p in host.split(".") if p and p not in {"www", "feeds", "feed", "rss"}]
        if len(parts) > 1 and parts[-1] in {
            "com",
            "org",
            "net",
            "io",
            "dev",
            "ai",
            "app",
            "co",
            "uk",
            "de",
            "eu",
            "it",
        }:
            parts = parts[:-1]
        if parts:
            if len(parts) >= 2 and parts[0] in {"blog", "news", "docs", "updates"}:
                ordered = [parts[1], parts[0], *parts[2:]]
            else:
                ordered = parts
            brand = " ".join(p.capitalize() for p in ordered[:3])
            suffix = (
                "Digest"
                if any(kw in lower for kw in ("digest", "newsletter", "summary"))
                else "Monitor"
            )
            return f"{brand} {suffix}"

    stripped = _URL_RE.sub(" ", cleaned)
    words = [w for w in re.split(r"[^a-zA-Z0-9]+", stripped) if w]
    stop = {"create", "a", "an", "the", "bot", "that", "to", "for", "and", "with", "fetch", "from", "into"}
    meaningful = [w.capitalize() for w in words if w.lower() not in stop][:4]
    return " ".join(meaningful) if meaningful else "Custom Automation Bot"


def _infer_boundaries(prompt: str, outbound_rbac: str) -> list[str]:
    boundaries: list[str] = []
    for match in re.finditer(
        r"\b((?:never|do\s+not|don't|ask\s+before|skip|discard|ignore)\s+[^.,;\n]{4,90})",
        prompt,
        re.IGNORECASE,
    ):
        clause = " ".join(match.group(1).split()).strip(" ,.")
        if clause and clause not in boundaries:
            boundaries.append(clause[0].upper() + clause[1:])
    if outbound_rbac == "draft" and not any("approv" in b.lower() or "ask" in b.lower() for b in boundaries):
        boundaries.append("Ask for approval before sending external messages")
    elif outbound_rbac == "internal" and not any("external" in b.lower() or "send" in b.lower() for b in boundaries):
        boundaries.append("Never send messages to external apps")
    return boundaries[:6]


def _infer_avatar(lower_prompt: str, runtime: str) -> tuple[str, str]:
    if runtime == "desktop":
        return "amber", "globe"
    if any(
        kw in lower_prompt
        for kw in ("supervisor", "coordinator", "oversee", "all bots", "fleet", "manage bots")
    ):
        return "indigo", "shield"
    if any(
        kw in lower_prompt
        for kw in ("writer", "story", "copywriter", "editorial", "blog post", "linkedin post")
    ):
        return "violet", "pen"
    if any(kw in lower_prompt for kw in ("gmail", "email", "inbox", "mail")):
        return "blue", "mail"
    if any(kw in lower_prompt for kw in ("telegram", "slack", "linkedin", "publish", "post")):
        return "indigo", "send"
    if any(kw in lower_prompt for kw in ("rss", "blog", "news", "feed", "article")):
        return "emerald", "rss"
    return "slate", "bot"


def _infer_routines(prompt: str, name: str, *, runtime: str = "api") -> list[dict[str, Any]]:
    lower = prompt.lower()
    event_match = _ON_EVENT_RE.search(prompt)
    if event_match:
        ev = event_match.group(1).lower()
        return [
            {
                "id": make_id("rtn"),
                "type": "on_event",
                "event": ev,
                "label": f"On {ev}",
                "schedule": f"on:{ev}",
                "enabled": True,
            }
        ]

    is_approval_notifier = (
        ("approval" in lower or "approvals" in lower)
        and any(
            kw in lower
            for kw in (
                "notify",
                "alert",
                "forward",
                "relay",
                "send me",
                "whenever",
                "when any bot queues",
                "approval notifier",
            )
        )
        and "for approval" not in lower
        and "for human approval" not in lower
        and "for review" not in lower
        and not _URL_RE.search(prompt)
        and "approval.queued" not in lower
        and not _EVERY_INTERVAL_RE.search(prompt)
    )
    if is_approval_notifier:
        return [
            {
                "id": make_id("rtn"),
                "type": "on_event",
                "event": "approval.queued",
                "label": "On approval queued",
                "schedule": "on:approval.queued",
                "enabled": True,
            }
        ]

    is_telegram_responder = (
        "telegram" in lower
        and "public channel" not in lower
        and "t.me/s/" not in lower
        and not _EVERY_INTERVAL_RE.search(prompt)
        and any(
            kw in lower
            for kw in (
                "answer",
                "reply",
                "respond",
                "incoming",
                "request",
                "message",
                "query",
                "queries",
                "ask",
                "chat",
            )
        )
    )
    if is_telegram_responder:
        return [
            {
                "id": make_id("rtn"),
                "type": "on_event",
                "event": "telegram.message",
                "label": "On Telegram Operator Message",
                "schedule": "on:telegram.message",
                "enabled": True,
            }
        ]

    interval_match = _EVERY_INTERVAL_RE.search(prompt)
    if interval_match:
        qty = int(interval_match.group(1))
        unit = interval_match.group(2).lower()
        label_unit = "h" if unit.startswith("h") else "m"
        return [
            {
                "id": make_id("rtn"),
                "type": "cron",
                "label": f"{name} Sync",
                "schedule": f"Every {qty}{label_unit}",
                "enabled": True,
            }
        ]

    if "hourly" in lower:
        schedule = "Every 1h"
    elif "daily" in lower:
        schedule = "Every 24h"
    elif "manual" in lower and "cron" not in lower:
        schedule = "Manual"
    elif runtime == "desktop":
        schedule = "Manual"
    else:
        schedule = "Every 15m"

    return [
        {
            "id": make_id("rtn"),
            "type": "manual_trigger" if schedule == "Manual" else "cron",
            "label": "Manual Run" if schedule == "Manual" else "Scheduled Sync",
            "schedule": schedule,
            "enabled": True,
        }
    ]


class ConversationalBotBuilder:
    """Synthesizes validated declarative JSON bot definitions from natural language."""

    def __init__(
        self,
        *,
        repo: ArgoRepository,
        llm_router: LLMRouter | None = None,
    ) -> None:
        self._repo = repo
        self._llm_router = llm_router

    async def draft_bot_spec(
        self,
        prompt: str,
        *,
        preferred_runtime: str = "auto",
        preferred_rbac: str = "auto",
        preferred_model: str | None = None,
        linked_accounts: list[str] | None = None,
    ) -> dict[str, Any]:
        """Convert natural language operator instructions into a complete Bot JSON preview."""
        cleaned_prompt = prompt.strip()
        if not cleaned_prompt:
            raise ValueError("Builder prompt cannot be empty.")

        lower = cleaned_prompt.lower()
        warnings: list[str] = []

        if preferred_model is not None and preferred_model.strip():
            provider_type, model_name = validate_model_id(preferred_model.strip())
            model = f"{provider_type}:{model_name}"
        elif any(
            kw in lower
            for kw in ("editorial", "reviewer", "audit", "synthesis", "reasoning", "gemini-4-argon")
        ):
            model = "google:gemini-4-argon"
        else:
            model = "google:gemini-3.8-flash"

        mentions_api_service = any(marker in lower for marker in _API_SERVICE_MARKERS)
        mentions_legacy_desktop = any(marker in lower for marker in _LEGACY_DESKTOP_MARKERS)

        if preferred_runtime == "desktop":
            runtime = "desktop"
            if mentions_api_service and not mentions_legacy_desktop:
                warnings.append(
                    "API-First recommendation: Gmail, Google Workspace, Telegram, LinkedIn, and RSS "
                    "use native 0 MB connectors inside argo-core without launching a Selkies container."
                )
        elif preferred_runtime == "api":
            runtime = "api"
        else:
            if mentions_legacy_desktop and not mentions_api_service:
                runtime = "desktop"
            else:
                runtime = "api"
                if mentions_api_service and ("browser" in lower or "chrome" in lower or "desktop" in lower):
                    warnings.append(
                        "API-First guard kept runtime='api' (0 MB): native API connectors handle "
                        "Google/Telegram/LinkedIn/RSS without spawning a 2 GB desktop container."
                    )

        if preferred_rbac in {"internal", "draft", "execute"}:
            outbound_rbac = preferred_rbac
        else:
            has_outbound = any(
                kw in lower
                for kw in (
                    "publish",
                    "send ",
                    "post ",
                    "email",
                    "reply",
                    "gatekeeper",
                    "telegram",
                    "linkedin",
                )
            )
            wants_execute = any(
                kw in lower for kw in ("execute", "auto-publish", "direct send", "gatekeeper")
            )
            if not has_outbound and any(
                kw in lower
                for kw in (
                    "collect",
                    "ingest",
                    "read-only",
                    "read only",
                    "internal",
                    "review",
                    "audit",
                    "triage",
                )
            ):
                outbound_rbac = "internal"
            elif has_outbound and wants_execute:
                outbound_rbac = "execute"
            else:
                outbound_rbac = "draft"

        name = _infer_bot_name(cleaned_prompt)
        slug = slugify(name)
        feed_urls, webpage_urls = _extract_urls(cleaned_prompt)
        routines = _infer_routines(cleaned_prompt, name, runtime=runtime)
        for routine in routines:
            if isinstance(routine, dict) and routine.get("type") != "on_event":
                if feed_urls:
                    routine["feed_urls"] = list(feed_urls)
                if webpage_urls:
                    routine["webpage_urls"] = list(webpage_urls)

        handles_telegram_dm = any(
            isinstance(r, dict) and r.get("event") == "telegram.message" for r in routines
        )
        handles_approval_queued = any(
            isinstance(r, dict) and r.get("event") == "approval.queued" for r in routines
        )
        if (handles_telegram_dm or handles_approval_queued) and preferred_rbac == "auto" and "draft" not in lower:
            outbound_rbac = "execute"

        is_supervisor = any(
            kw in lower
            for kw in (
                "supervisor",
                "coordinator",
                "oversee",
                "all bots",
                "fleet",
                "manage bots",
                "monitor bots",
            )
        )

        col_matches = [collection_slug(m) for m in _COLLECTION_QUOTED_RE.findall(cleaned_prompt)]
        if col_matches:
            data_cols = list(dict.fromkeys(col_matches))
        elif "news" in lower or "rss" in lower or "article" in lower:
            data_cols = ["news_items"]
        elif not is_supervisor and not handles_telegram_dm and not handles_approval_queued:
            data_cols = [collection_slug(f"bot_{slug}_items")]
        else:
            data_cols = []

        read_cols = list(dict.fromkeys([*data_cols, "bot_threads"]))
        if "style_memory" in lower and "style_memory" not in read_cols:
            read_cols.append("style_memory")
        write_cols = (
            list(dict.fromkeys([*data_cols, "bot_threads"]))
            if data_cols
            else ["bot_threads"]
        )

        tools: list[Any] = []
        if feed_urls or "rss" in lower or "feed" in lower:
            rss_tool: dict[str, Any] = {"type": "builtin", "name": "fetch_rss_feed"}
            if feed_urls:
                rss_tool["urls"] = list(feed_urls)
            tools.append(rss_tool)
        if webpage_urls or "web" in lower or "webpage" in lower or "article" in lower or "blog" in lower:
            web_tool: dict[str, Any] = {"type": "builtin", "name": "fetch_public_webpage"}
            if webpage_urls:
                web_tool["urls"] = list(webpage_urls)
            tools.append(web_tool)
        if "t.me/s/" in lower or "public channel" in lower:
            tools.append({"type": "builtin", "name": "fetch_telegram_public_channel"})
        if any(kw in lower for kw in ("gmail", "email", "inbox", "newsletter", "mail")):
            tools.append({"type": "builtin", "name": "gmail_search"})
        if runtime == "desktop":
            tools.append({"type": "builtin", "name": "desktop_browse"})
            tools.append({"type": "mcp", "name": "desktop_mcp"})
        if handles_telegram_dm or is_supervisor:
            tools.append({"type": "builtin", "name": "platform_status"})

        default_execute_cap = 50 if (handles_telegram_dm or handles_approval_queued) else 10
        integrations = self._repo.list_integrations()
        resolved_linked_accounts: list[str] | None = None
        if linked_accounts is not None:
            resolved_linked_accounts = list(
                dict.fromkeys(slugify(str(a)) for a in linked_accounts if str(a).strip())
            )
            capability = "read" if outbound_rbac == "internal" else outbound_rbac
            for acc_slug in resolved_linked_accounts:
                tools.append(
                    {
                        "type": "account",
                        "slug": acc_slug,
                        "capability": capability,
                        "max_calls_per_day": default_execute_cap if capability == "execute" else 0,
                    }
                )
        elif outbound_rbac in {"draft", "execute"}:
            for acc in integrations:
                if acc["provider"] in {"telegram", "linkedin", "google"} or (
                    acc["provider"] == "webhook" and ("webhook" in lower or "slack" in lower)
                ):
                    if (
                        acc["provider"] in lower
                        or ("email" in lower and acc["provider"] == "google")
                        or ("gmail" in lower and acc["provider"] == "google")
                        or len(integrations) == 1
                    ):
                        tools.append(
                            {
                                "type": "account",
                                "slug": acc["slug"],
                                "capability": outbound_rbac,
                                "max_calls_per_day": default_execute_cap if outbound_rbac == "execute" else 0,
                            }
                        )
        if outbound_rbac in {"draft", "execute"}:
            tools.append({"type": "builtin", "name": "request_human_approval"})

        if not tools:
            tools.append({"type": "builtin", "name": "request_human_approval"})

        boundaries = _infer_boundaries(cleaned_prompt, outbound_rbac)
        avatar_color, avatar_icon = _infer_avatar(lower, runtime)

        draft: dict[str, Any] = {
            "name": name,
            "slug": slug,
            "avatar_color": avatar_color,
            "avatar_icon": avatar_icon,
            "boundaries": boundaries,
            "role": cleaned_prompt[:240],
            "role_prompt": cleaned_prompt,
            "runtime": runtime,
            "desktop_policy": "on_demand" if runtime == "desktop" else "disabled",
            "outbound_rbac": outbound_rbac,
            "daily_cap": default_execute_cap if outbound_rbac == "execute" else 0,
            "model": model,
            "routines": routines,
            "tools": tools,
            "collections": {"read": read_cols, "write": write_cols},
        }
        if resolved_linked_accounts is not None:
            draft["linked_accounts"] = resolved_linked_accounts

        used_llm = False
        if self._llm_router is not None:
            has_live_key = any(
                p.get("api_key") for p in self._repo.list_model_provider_credentials()
            )
            has_custom_transport = getattr(self._llm_router, "_transport", None) is not None
            if has_live_key or has_custom_transport:
                try:
                    llm_res = await self._llm_router.complete(
                        bot_slug="bot-builder",
                        prompt=(
                            "Refine this Argo declarative bot JSON spec into clean engineering JSON "
                            "matching keys: name, role, role_prompt, model, outbound_rbac, daily_cap, "
                            "boundaries, collections, routines. User request: "
                            f"{cleaned_prompt}\nBaseline JSON: {json.dumps(draft)}"
                        ),
                        requested_model=model,
                        system_prompt="Return a single valid JSON object describing the Argo bot.",
                        trigger_type="bot_builder",
                        hop_count=1,
                    )
                    parsed = json.loads(llm_res.output_text)
                    if isinstance(parsed, dict):
                        if parsed.get("name"):
                            draft["name"] = str(parsed["name"])[:120]
                            draft["slug"] = slugify(draft["name"])
                        if parsed.get("role"):
                            draft["role"] = str(parsed["role"])[:2000]
                        if parsed.get("role_prompt"):
                            draft["role_prompt"] = str(parsed["role_prompt"])[:8000]
                        if parsed.get("model") and preferred_model is None:
                            p_type, m_name = validate_model_id(str(parsed["model"]))
                            draft["model"] = f"{p_type}:{m_name}"
                        if (
                            parsed.get("outbound_rbac") in {"internal", "draft", "execute"}
                            and preferred_rbac == "auto"
                        ):
                            draft["outbound_rbac"] = parsed["outbound_rbac"]
                        if isinstance(parsed.get("daily_cap"), int):
                            draft["daily_cap"] = max(0, min(500, parsed["daily_cap"]))
                        if isinstance(parsed.get("boundaries"), list):
                            cleaned_b = [str(b).strip() for b in parsed["boundaries"] if str(b).strip()]
                            if cleaned_b:
                                draft["boundaries"] = cleaned_b[:6]
                        if isinstance(parsed.get("collections"), dict):
                            cols = parsed["collections"]
                            draft["collections"] = {
                                "read": [collection_slug(str(c)) for c in cols.get("read", read_cols)],
                                "write": [collection_slug(str(c)) for c in cols.get("write", write_cols)],
                            }
                        if isinstance(parsed.get("routines"), list) and parsed["routines"]:
                            draft["routines"] = self._repo._normalize_routines(parsed["routines"])
                        used_llm = True
                except Exception:
                    # Fallback cleanly to deterministic baseline if LLM output is non-JSON or unavailable.
                    used_llm = False

        autonomy_human = {
            "internal": "Read & Organize Only (never sends externally)",
            "draft": "Ask Before Sending (queues drafts for your approval)",
            "execute": f"Send Automatically (up to {draft['daily_cap']}/day)",
        }.get(draft["outbound_rbac"], draft["outbound_rbac"])
        schedule_human = (
            str(draft["routines"][0].get("schedule") or "Manual")
            if draft.get("routines")
            else "Manual"
        )
        restated_summary = {
            "job": draft["role"],
            "schedule": schedule_human,
            "autonomy": autonomy_human,
            "boundaries": draft.get("boundaries") or [],
        }

        return {
            "draft": draft,
            "restated_summary": restated_summary,
            "warnings": warnings,
            "used_llm": used_llm,
        }
