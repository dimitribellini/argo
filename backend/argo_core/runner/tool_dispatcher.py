"""Modular tool dispatcher for built-in kernel primitives, script sandbox, and dynamic connectors."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from argo_core.analytics.engine import dataset_identifier, execute_duckdb_query, profile_datasets
from argo_core.approvals.coordinator import ConnectorPermissionError
from argo_core.bus.valkey_bus import MAX_HOP_COUNT
from argo_core.connectors.gateway import ConnectorToolContext
from argo_core.connectors.telegram_channels import fetch_telegram_public_channel
from argo_core.db.repositories import (
    _INTERNAL_SYSTEM_COLLECTIONS,
    _READ_FORBIDDEN_SYSTEM_COLLECTIONS,
    collection_slug,
    slugify,
)
from argo_core.runner.bot_builder import ConversationalBotBuilder
from argo_core.sandbox.manager import (
    SandboxConfigError,
    SandboxRuntimeError,
    SandboxStartupBlockedError,
)
from argo_core.security.ssrf import SSRFBlockedError
from argo_core.security.vault import redact_secrets
from argo_core.tools.public_web import extract_web_data, fetch_public_webpage, fetch_rss_feed

if TYPE_CHECKING:
    from argo_core.runner.bot_runner import UniversalBotRunner


@dataclass
class ToolDispatchContext:
    """Per-action execution context passed from UniversalBotRunner into ToolDispatcher."""

    bot: dict[str, Any]
    action: dict[str, Any]
    correlation_id: str
    hop_count: int
    allowed_write: set[str]
    data_write_cols: list[str]
    operator_email: str | None
    file_owner_email: str
    in_room_turn: bool
    target_page_slug: str
    trigger_type: str
    t_payload: dict[str, Any]
    turn_screenshots: list[bytes] | None
    results: list[dict[str, Any]]
    await_delegations: list[dict[str, Any]]
    turn_batch_id: str = ""
    chip_meta: dict[str, Any] | None = None


class ToolDispatcher:
    """Dispatches non-control-flow built-in actions, script sandbox calls, and dynamic connectors."""

    def __init__(self, runner: UniversalBotRunner) -> None:
        self._runner = runner

    async def dispatch(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        """Execute a_type if owned by ToolDispatcher; return False for runner control-flow actions."""
        if a_type == "sandbox_exec":
            return await self._handle_sandbox_exec(a_type, ctx)
        if await self._dispatch_core_part1(a_type, ctx):
            return True
        if await self._dispatch_core_part2(a_type, ctx):
            return True
        if await self._dispatch_core_part3(a_type, ctx):
            return True
        if await self._dispatch_core_part4(a_type, ctx):
            return True
        return await self._handle_dynamic_connector_tool(a_type, ctx)

    async def _handle_sandbox_exec(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        results = ctx.results

        if bot.get("runtime") != "sandbox":
            results.append(
                {
                    "type": a_type,
                    "status": "blocked_sandbox_policy",
                    "detail": (
                        f"Bot '{bot['slug']}' runs in '{bot.get('runtime', 'api')}' mode "
                        "and cannot invoke sandbox_exec."
                    ),
                }
            )
            return True

        if runner._sandbox_manager is None:
            results.append(
                {
                    "type": a_type,
                    "status": "error",
                    "detail": "SandboxManager is not configured.",
                }
            )
            return True

        cmd_str = str(action.get("command") or "")
        cmds_list = [str(c) for c in (action.get("commands") or []) if str(c).strip()] if isinstance(action.get("commands"), list) else []
        script_str = str(action.get("script") or "")

        raw_vault_refs: list[str] = []
        for v_key in ("vault_slugs", "vault_secrets"):
            raw_v = action.get(v_key)
            if isinstance(raw_v, list):
                raw_vault_refs.extend(str(item).strip() for item in raw_v if str(item).strip())
            elif isinstance(raw_v, str) and raw_v.strip():
                raw_vault_refs.append(raw_v.strip())

        combined_script_text = "\n".join(x for x in (cmd_str, *cmds_list, script_str) if x)
        vault_action: dict[str, Any] = {
            "vault_secrets": raw_vault_refs,
            "commands": [x for x in (cmd_str, *cmds_list, script_str) if x],
            "text": combined_script_text,
        }
        env_vars, placeholder_values, secret_values, vault_block = (
            await runner._resolve_vault_for_desktop_action(
                bot=bot,
                a_type=a_type,
                action=vault_action,
                correlation_id=ctx.correlation_id,
                hop_count=ctx.hop_count,
            )
        )
        if vault_block is not None:
            results.append(vault_block)
            return True

        def _subst_vault(text_in: str) -> str:
            if not text_in or not placeholder_values:
                return text_in
            return runner._VAULT_TYPE_TEMPLATE_RE.sub(
                lambda m: placeholder_values.get(
                    f"{slugify(m.group(1))}.{m.group(2).strip().lower()}",
                    m.group(0),
                ),
                text_in,
            )

        raw_interp = str(action.get("interpreter") or "bash").strip().lower()
        if raw_interp == "sh":
            interp = "bash"
        elif raw_interp == "python":
            interp = "python3"
        else:
            interp = raw_interp

        redact_vals = list(dict.fromkeys([*secret_values, *runner._sensitive_secrets()]))
        try:
            sb_res = await runner._sandbox_manager.exec_script(
                bot["slug"],
                command=_subst_vault(cmd_str) or None,
                commands=[_subst_vault(c) for c in cmds_list] or None,
                script=_subst_vault(script_str) or None,
                interpreter=interp,
                save_as=str(action.get("save_as")).strip() if action.get("save_as") else None,
                workdir=str(action.get("workdir")).strip() if action.get("workdir") else None,
                timeout_seconds=action.get("timeout_seconds"),
                extra_env=env_vars or None,
                redact_values=redact_vals,
                correlation_id=ctx.correlation_id,
            )
            cleaned = runner._scrub_vault_observation(sb_res, redact_vals)
            results.append({"type": a_type, **cleaned})
        except SandboxStartupBlockedError as exc:
            results.append(
                {
                    "type": a_type,
                    "status": "queued_ram_gate",
                    "ram_percent": exc.ram_percent,
                    "detail": str(exc),
                }
            )
        except SandboxConfigError as exc:
            results.append({"type": a_type, "status": "error", "detail": str(exc)})
        except SandboxRuntimeError as exc:
            results.append(
                {
                    "type": a_type,
                    "status": "error",
                    "detail": runner._scrub_text(str(exc)),
                }
            )
        return True

    async def _handle_dynamic_connector_tool(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        results = ctx.results

        raw_hint = runner._extract_action_account_hint(action)
        all_integrations = runner._repo.list_integrations()
        matching_pairs: list[tuple[Any, dict[str, Any]]] = []
        for acc in all_integrations:
            provider = str(acc.get("provider") or "").strip().lower()
            adapter = runner._connector_gateway.get(provider)
            if adapter is not None and adapter.owns_tool(a_type, acc):
                matching_pairs.append((adapter, acc))

        if not matching_pairs:
            owning_adapter = next(
                (
                    ad
                    for ad in runner._connector_gateway.list_adapters()
                    if ad.owns_tool(a_type, {})
                ),
                None,
            )
            if owning_adapter is None and not a_type.startswith("mcp__"):
                return False
            if raw_hint and not runner._is_account_permitted(bot, raw_hint):
                results.append(
                    await runner._publish_unlinked_account_block(
                        bot=bot,
                        correlation_id=ctx.correlation_id,
                        hop_count=ctx.hop_count,
                        action_type=a_type,
                        account_slug=raw_hint,
                    )
                )
                return True
            provider_label = (
                owning_adapter.provider.title() if owning_adapter is not None else "MCP"
            )
            results.append(
                {
                    "type": a_type,
                    "status": "skipped_invalid_action",
                    "detail": f"No linked {provider_label} integration available for {a_type}.",
                }
            )
            return True

        owner_providers = {ad.provider for ad, _ in matching_pairs}
        preferred_provider = next(iter(owner_providers)) if len(owner_providers) == 1 else None

        adapter: Any = None
        acct_meta: dict[str, Any] | None = None
        if raw_hint:
            resolved_slug, _ = runner._resolve_action_account_slug(
                bot, action, preferred_provider=preferred_provider
            )
            for cand_adapter, cand_acc in matching_pairs:
                if str(cand_acc.get("slug") or "") == resolved_slug:
                    adapter, acct_meta = cand_adapter, cand_acc
                    break
            if acct_meta is None:
                if resolved_slug and not runner._is_account_permitted(bot, resolved_slug):
                    results.append(
                        await runner._publish_unlinked_account_block(
                            bot=bot,
                            correlation_id=ctx.correlation_id,
                            hop_count=ctx.hop_count,
                            action_type=a_type,
                            account_slug=resolved_slug,
                        )
                    )
                    return True
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": (
                            f"Integration '{resolved_slug or raw_hint}' does not support tool '{a_type}'."
                        ),
                    }
                )
                return True
        else:
            sorted_pairs = sorted(
                matching_pairs,
                key=lambda pair: (
                    0 if runner._is_account_permitted(bot, pair[1]["slug"]) else 1,
                    0 if pair[1].get("status") != "expired" else 1,
                ),
            )
            adapter, acct_meta = sorted_pairs[0]

        acct_slug = str(acct_meta.get("slug") or "")
        if not runner._is_account_permitted(bot, acct_slug):
            results.append(
                await runner._publish_unlinked_account_block(
                    bot=bot,
                    correlation_id=ctx.correlation_id,
                    hop_count=ctx.hop_count,
                    action_type=a_type,
                    account_slug=acct_slug,
                )
            )
            return True

        acct_full = runner._repo.find_integration_secrets(acct_slug) or acct_meta

        def _mark_seen(keys: list[str]) -> None:
            if keys:
                runner._repo.mark_ingestion_keys_seen(bot["slug"], keys)

        async def _outbound_cb(**kw: Any) -> dict[str, Any]:
            if (
                ctx.trigger_type == "on_event:approval.queued"
                and str(bot.get("outbound_rbac") or "draft").lower() != "execute"
            ):
                return {
                    "status": "blocked_rbac",
                    "detail": (
                        "Approval handler bots cannot queue recursive approvals; "
                        "enable Auto-Send (execute)."
                    ),
                }
            try:
                return await runner._approvals.execute_or_queue_outbound(
                    bot=bot,
                    correlation_id=ctx.correlation_id,
                    hop_count=ctx.hop_count,
                    **kw,
                )
            except ConnectorPermissionError as exc:
                return {"status": "blocked_rbac", "detail": str(exc)}

        tool_ctx = ConnectorToolContext(
            bot=bot,
            account=acct_full,
            correlation_id=ctx.correlation_id,
            hop_count=ctx.hop_count,
            data_write_cols=list(ctx.data_write_cols),
            upsert_doc=runner._repo.upsert_document,
            mark_seen=_mark_seen,
            scrub_text=runner._scrub_text,
            execute_or_queue_outbound=_outbound_cb,
            is_internal_bot=(str(bot.get("outbound_rbac") or "draft").lower() == "internal"),
            trigger_type=ctx.trigger_type,
        )
        try:
            res = await runner._connector_gateway.execute_tool(
                adapter,
                tool_name=a_type,
                action=action,
                ctx=tool_ctx,
            )
        except SSRFBlockedError as exc:
            results.append({"type": a_type, "status": "blocked_ssrf", "detail": str(exc)})
            return True
        except Exception as exc:
            results.append(
                {
                    "type": a_type,
                    "status": "error",
                    "account": acct_slug,
                    "detail": runner._scrub_text(str(exc)),
                }
            )
            return True

        if res is None:
            results.append(
                {
                    "type": a_type,
                    "status": "error",
                    "account": acct_slug,
                    "detail": f"{adapter.provider.title()} service is not configured.",
                }
            )
            return True
        results.append(res)
        return True

    async def _dispatch_core_part1(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        correlation_id = ctx.correlation_id
        hop_count = ctx.hop_count
        allowed_write = ctx.allowed_write
        data_write_cols = ctx.data_write_cols
        file_owner_email = ctx.file_owner_email
        target_page_slug = ctx.target_page_slug
        trigger_type = ctx.trigger_type
        t_payload = ctx.t_payload
        results = ctx.results
        if a_type == "upsert_document":
            raw_col = str(action.get("collection") or "").strip()
            target_col = (
                collection_slug(raw_col)
                if raw_col
                else (data_write_cols[0] if data_write_cols else "")
            )
            if target_col not in allowed_write:
                msg = f"Bot '{bot['slug']}' lacks write permission on collection '{target_col}'."
                await runner._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=target_col,
                    event_type="connector.blocked",
                    payload={
                        "category": "alerts",
                        "title": f"Blocked Collection Write ({bot['name']})",
                        "badge": "Collection ACL",
                        "badge_tone": "red",
                        "summary": msg,
                        "meta": f"Allowed write: {sorted(allowed_write)}",
                    },
                    hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                )
                results.append({"type": a_type, "status": "blocked_collection_acl", "detail": msg})
                return True

            ext_key = action.get("external_key")
            doc = (
                action.get("doc")
                if isinstance(action.get("doc"), dict)
                else (
                    action.get("document")
                    if isinstance(action.get("document"), dict)
                    else (
                        action.get("data")
                        if isinstance(action.get("data"), dict)
                        else {
                            k: v
                            for k, v in action.items()
                            if k not in {"type", "collection", "external_key", "search_text"}
                        }
                    )
                )
            )
            saved = runner._repo.upsert_document(
                collection=target_col,
                external_key=str(ext_key) if ext_key is not None else None,
                search_text=str(action.get("search_text") or json.dumps(doc))[:1000],
                doc=doc,
            )
            results.append(
                {
                    "type": a_type,
                    "status": "ok",
                    "collection": saved["collection"],
                    "external_key": saved["external_key"],
                    "id": saved["id"],
                }
            )

        elif a_type == "fetch_public_webpage":
            url = str(action.get("url") or "").strip()
            if url:
                fetched = await fetch_public_webpage(
                    url,
                    repo=runner._repo,
                    bus=runner._bus,
                    fetcher=runner._http_fetcher,
                    max_chars=int(action.get("max_chars") or 24000),
                    offset=int(action.get("offset") or 0),
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "url": fetched["url"],
                        "title": fetched["title"],
                        "discovered_feeds": fetched.get("discovered_feeds") or [],
                        "structured_json_ld": fetched.get("structured_json_ld") or [],
                        "offset": fetched.get("offset", 0),
                        "total_chars": fetched.get("total_chars", 0),
                        "has_more": bool(fetched.get("has_more", False)),
                        "next_offset": fetched.get("next_offset"),
                        "markdown": str(fetched.get("markdown") or "")[:48_000],
                    }
                )

        elif a_type == "extract_web_data":
            url = str(action.get("url") or "").strip()
            if not url:
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": "Missing url for extract_web_data.",
                    }
                )
                return True
            target_coll_raw = action.get("target_collection")
            target_coll_arg: str | None = None
            if target_coll_raw is not None and str(target_coll_raw).strip():
                clean_target = collection_slug(str(target_coll_raw).strip())
                if clean_target in _INTERNAL_SYSTEM_COLLECTIONS or clean_target not in allowed_write:
                    msg = (
                        f"Bot '{bot['slug']}' cannot extract web data into unpermitted "
                        f"collection '{clean_target}'."
                    )
                    await runner._bus.publish(
                        correlation_id=correlation_id,
                        source_slug=bot["slug"],
                        target_slug=clean_target,
                        event_type="connector.blocked",
                        payload={
                            "category": "alerts",
                            "title": f"Blocked Web Collection Write ({bot['name']})",
                            "badge": "Collection ACL",
                            "badge_tone": "red",
                            "summary": msg,
                            "meta": f"Allowed write: {sorted(allowed_write)}",
                        },
                        hop_count=min(MAX_HOP_COUNT, max(1, hop_count)),
                    )
                    results.append(
                        {"type": a_type, "status": "blocked_collection_acl", "detail": msg}
                    )
                    return True
                target_coll_arg = clean_target
            extracted = await extract_web_data(
                url,
                selector=str(action["selector"]).strip() if action.get("selector") else None,
                target_collection=target_coll_arg,
                save_as_file=bool(action.get("save_as_file", False)),
                repo=runner._repo,
                bus=runner._bus,
                fetcher=runner._http_fetcher,
                bot_slug=bot["slug"],
                owner_email=file_owner_email,
                correlation_id=correlation_id,
                source_slug=bot["slug"],
            )
            ds_id = extracted.get("dataset_id")
            if ds_id:
                sess_list = t_payload.setdefault("session_authorized_datasets", [])
                if ds_id not in sess_list:
                    sess_list.append(ds_id)
            results.append({"type": a_type, **extracted})

        elif a_type == "fetch_rss_feed":
            url = str(action.get("url") or "").strip()
            if url:
                fetched = await fetch_rss_feed(
                    url,
                    repo=runner._repo,
                    bus=runner._bus,
                    fetcher=runner._http_fetcher,
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "url": fetched["url"],
                        "feed_title": fetched.get("feed_title") or "",
                        "entries": len(fetched["entries"]),
                        "items": [
                            {
                                "external_key": e.get("external_key"),
                                "title": e.get("title"),
                                "url": e.get("url"),
                                "published": e.get("published"),
                                "summary": str(e.get("summary") or "")[:300],
                            }
                            for e in fetched.get("entries", [])[:10]
                        ],
                    }
                )

        elif a_type == "fetch_telegram_public_channel":
            channel = str(action.get("channel") or action.get("target") or "").strip()
            if channel:
                posts = await fetch_telegram_public_channel(
                    channel,
                    fetcher=runner._http_fetcher,
                    limit=int(action.get("limit") or 15),
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "channel": channel,
                        "posts": posts[:15],
                    }
                )

        elif a_type == "data_describe":
            authorized_read = runner._compute_authorized_read_collections(
                bot,
                trigger_type,
                t_payload,
                target_page_slug=target_page_slug,
            )
            req_raw = action.get("collections")
            if req_raw is None and action.get("collection"):
                req_raw = [action.get("collection")]
            req_cols = [
                dataset_identifier(str(c))
                for c in (req_raw if isinstance(req_raw, list) else ([req_raw] if req_raw else []))
                if str(c).strip()
            ]
            if req_cols:
                disallowed = [
                    c
                    for c in req_cols
                    if c in _READ_FORBIDDEN_SYSTEM_COLLECTIONS or c not in authorized_read
                ]
                if disallowed:
                    results.append(
                        await runner._publish_collection_acl_block(
                            bot=bot,
                            correlation_id=correlation_id,
                            hop_count=hop_count,
                            action_type=a_type,
                            target_slug=disallowed[0],
                            detail=f"Bot '{bot['slug']}' cannot inspect unpermitted collections: {', '.join(disallowed)}.",
                            allowed_cols=authorized_read,
                        )
                    )
                    return True
                target_cols = req_cols
            else:
                target_cols = authorized_read
            described = runner._repo.describe_collections(
                target_cols,
                sample_limit=int(action.get("sample_limit") or 30),
                owner_email=file_owner_email,
            )
            results.append({"type": a_type, "status": "ok", **described})

        elif a_type == "data_query":
            sql_str = str(action.get("sql") or "").strip()
            if not sql_str:
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": "Missing SQL query string for data_query.",
                    }
                )
                return True
            authorized_read = runner._compute_authorized_read_collections(
                bot,
                trigger_type,
                t_payload,
                target_page_slug=target_page_slug,
            )
            authorized_set = set(authorized_read)
            req_raw = action.get("collections")
            if req_raw is None and action.get("collection"):
                req_raw = [action.get("collection")]
            req_cols = [
                dataset_identifier(str(c))
                for c in (req_raw if isinstance(req_raw, list) else ([req_raw] if req_raw else []))
                if str(c).strip()
            ]
            disallowed_explicit = [
                c
                for c in req_cols
                if c in _READ_FORBIDDEN_SYSTEM_COLLECTIONS or c not in authorized_set
            ]
            all_known_cols = {c["slug"] for c in runner._repo.list_collections()} | set(
                _READ_FORBIDDEN_SYSTEM_COLLECTIONS
            )
            disallowed_in_sql: list[str] = []
            for raw_lit in re.findall(r"'((?:[^']|'')*)'", sql_str):
                lit_clean = raw_lit.replace("''", "'").strip().lower()
                if (
                    lit_clean in all_known_cols
                    or re.fullmatch(r"bot_[a-z0-9_-]+_items", lit_clean)
                ) and lit_clean not in authorized_set:
                    disallowed_in_sql.append(lit_clean)

            blocked_cols = list(dict.fromkeys([*disallowed_explicit, *disallowed_in_sql]))
            if blocked_cols:
                results.append(
                    await runner._publish_collection_acl_block(
                        bot=bot,
                        correlation_id=correlation_id,
                        hop_count=hop_count,
                        action_type=a_type,
                        target_slug=blocked_cols[0],
                        detail=f"Bot '{bot['slug']}' lacks read access to collection(s): {', '.join(blocked_cols)}.",
                        allowed_cols=authorized_read,
                    )
                )
                return True

            target_cols = req_cols or authorized_read
            try:
                query_res = runner._repo.execute_analytics_query(
                    sql_str,
                    allowed_collections=target_cols,
                    owner_email=file_owner_email,
                    params=list(action.get("params") or []),
                    row_cap=int(action.get("row_cap") or 500),
                    engine=str(action.get("engine") or "auto"),
                )
                results.append({"type": a_type, "status": "ok", **query_res})
            except PermissionError as exc:
                results.append(
                    {
                        "type": a_type,
                        "status": "blocked_sql_sandbox",
                        "detail": str(exc),
                    }
                )
            except (ValueError, TimeoutError, sqlite3.Error) as exc:
                results.append(
                    {
                        "type": a_type,
                        "status": "error",
                        "detail": runner._scrub_text(str(exc)),
                    }
                )

        elif a_type == "emit_event":
            ev_type = str(action.get("event_type") or "").strip()
            if not ev_type:
                return True
            next_hop = hop_count + 1
            if next_hop > MAX_HOP_COUNT:
                await runner._bus.publish(
                    correlation_id=correlation_id,
                    source_slug=bot["slug"],
                    target_slug=action.get("target_slug"),
                    event_type="bot.hop_limit_halted",
                    payload={
                        "category": "alerts",
                        "title": f"Loop Guard Halted Event Chain ({bot['name']})",
                        "badge": f"Halted · Hop {next_hop}/{MAX_HOP_COUNT}",
                        "badge_tone": "amber",
                        "summary": f"Halted '{ev_type}' emit because hop {next_hop} exceeds limit {MAX_HOP_COUNT}.",
                        "meta": f"Correlation: {correlation_id}",
                        "attempted_event": ev_type,
                        "attempted_hop_count": next_hop,
                    },
                    hop_count=MAX_HOP_COUNT,
                )
                results.append({"type": a_type, "status": "halted_hop_limit", "event_type": ev_type})
                return True

            ev_payload = dict(action.get("payload") or {})
            ev_payload.setdefault("category", "reviews")
            ev_payload.setdefault("title", f"{bot['name']} -> {ev_type}")
            ev_payload.setdefault("badge", f"Hop {next_hop}/{MAX_HOP_COUNT}")
            ev_payload.setdefault("badge_tone", "sky")
            ev_payload.setdefault(
                "summary",
                f"Emitted {ev_type} from {bot['slug']} for downstream subscribers.",
            )
            emitted = await runner._bus.publish(
                correlation_id=correlation_id,
                source_slug=bot["slug"],
                target_slug=action.get("target_slug"),
                event_type=ev_type,
                payload=ev_payload,
                hop_count=next_hop,
            )
            results.append(
                {"type": a_type, "status": "ok", "event_type": ev_type, "event_id": emitted["id"], "hop_count": next_hop}
            )

        elif a_type == "notify_approval" or (
            trigger_type == "on_event:approval.queued"
            and a_type in runner._connector_gateway.all_action_types()
            and bool(action.get("approval_id") or (t_payload or {}).get("approval_id"))
        ):
            approval_id = str(
                action.get("approval_id") or (t_payload or {}).get("approval_id") or ""
            ).strip()
            pref = runner._connector_gateway.resolve_provider_for_action(a_type)
            account_slug, _ = runner._resolve_action_account_slug(bot, action, preferred_provider=pref)
            if not approval_id or not account_slug:
                results.append(
                    {
                        "type": "notify_approval",
                        "status": "skipped_invalid_action",
                        "detail": "Missing approval_id or linked notification account.",
                    }
                )
                return True
            if not runner._is_account_permitted(bot, account_slug):
                results.append(
                    await runner._publish_unlinked_account_block(
                        bot=bot,
                        correlation_id=correlation_id,
                        hop_count=hop_count,
                        action_type="notify_approval",
                        account_slug=account_slug,
                    )
                )
                return True
            if str(bot.get("outbound_rbac") or "draft").lower() != "execute":
                results.append(
                    {
                        "type": "notify_approval",
                        "status": "blocked_rbac",
                        "detail": "Approval notification bots must be set to Auto-Send (execute) to deliver notifications without recursive approval loops.",
                    }
                )
                return True
            try:
                deliv = await runner._approvals.deliver_approval_notification(
                    approval_id=approval_id,
                    account_slug=account_slug,
                    text=runner.extract_action_text(action) or None,
                    target=str(action.get("target") or "").strip() or None,
                )
                results.append(
                    {
                        "type": "notify_approval",
                        "status": "ok",
                        "approval_id": approval_id,
                        "account": account_slug,
                        **deliv,
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "type": "notify_approval",
                        "status": "error",
                        "approval_id": approval_id,
                        "account": account_slug,
                        "detail": runner._scrub_text(str(exc)),
                    }
                )

        elif a_type in runner._connector_gateway.all_action_types():
            raw_action_type = str(action.get("action_type") or "").strip()
            resolved_action = (
                runner.normalize_action_type(raw_action_type)
                if raw_action_type
                else ("connector_publish" if a_type == "connector_publish" else a_type)
            )
            preferred_provider = (
                runner._connector_gateway.resolve_provider_for_action(resolved_action)
                or runner._connector_gateway.resolve_provider_for_action(a_type)
            )
            account_slug, _ = runner._resolve_action_account_slug(
                bot, action, preferred_provider=preferred_provider
            )
            text = runner.extract_action_text(action)
            payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
            source_url = (
                action.get("source_url")
                or action.get("url")
                or payload_obj.get("source_url")
            )
            source_excerpt = action.get("source_excerpt") or payload_obj.get("source_excerpt")
            is_internal_bot = str(bot.get("outbound_rbac") or "draft").lower() == "internal"
            if not text or (not account_slug and not is_internal_bot):
                missing = "text" if not text else "account"
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": f"Missing {missing} for {a_type}.",
                    }
                )
                return True
            if is_internal_bot:
                account_slug = account_slug or "outbound"
            elif not runner._is_account_permitted(bot, account_slug):
                results.append(
                    await runner._publish_unlinked_account_block(
                        bot=bot,
                        correlation_id=correlation_id,
                        hop_count=hop_count,
                        action_type=resolved_action,
                        account_slug=account_slug,
                    )
                )
                return True

            acct_rec = runner._repo.find_integration_secrets(account_slug)
            acct_provider = (
                str(acct_rec.get("provider") or "").strip().lower()
                if isinstance(acct_rec, dict)
                else None
            ) or preferred_provider
            extra_payload, target_dest = runner._connector_gateway.normalize_action_payload(
                provider=acct_provider,
                action_type=resolved_action,
                action=action,
            )

            try:
                if (
                    trigger_type == "on_event:approval.queued"
                    and str(bot.get("outbound_rbac") or "draft").lower() != "execute"
                ):
                    results.append(
                        {
                            "type": a_type,
                            "status": "blocked_rbac",
                            "detail": "Approval handler bots cannot queue recursive approvals; enable Auto-Send (execute).",
                        }
                    )
                    return True
                gate_res = await runner._approvals.execute_or_queue_outbound(
                    bot=bot,
                    correlation_id=correlation_id,
                    hop_count=hop_count,
                    account_slug=account_slug,
                    action_type=resolved_action,
                    text=text,
                    target=target_dest,
                    source_url=source_url,
                    source_excerpt=source_excerpt,
                    extra_payload=extra_payload,
                )
                results.append({"type": a_type, **gate_res})
            except ConnectorPermissionError as exc:
                results.append({"type": a_type, "status": "blocked_rbac", "detail": str(exc)})

        elif a_type == "request_human_approval":
            resolved_action = (
                runner.normalize_action_type(action.get("action_type") or "publish_telegram")
                or "publish_telegram"
            )
            preferred_provider = runner._connector_gateway.resolve_provider_for_action(
                resolved_action
            )
            account_slug, was_explicit = runner._resolve_action_account_slug(
                bot, action, preferred_provider=preferred_provider
            )
            if not account_slug:
                account_slug = "tg-ops"
            text = runner.extract_action_text(action)
            if not text:
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": f"Missing text for {a_type}.",
                    }
                )
                return True
            if (
                (was_explicit or bot.get("linked_accounts_restricted"))
                and account_slug != "tg-ops"
                and not runner._is_account_permitted(bot, account_slug)
            ):
                results.append(
                    await runner._publish_unlinked_account_block(
                        bot=bot,
                        correlation_id=correlation_id,
                        hop_count=hop_count,
                        action_type=resolved_action,
                        account_slug=account_slug,
                    )
                )
                return True
            payload_obj = action.get("payload") if isinstance(action.get("payload"), dict) else {}
            acct_rec = runner._repo.find_integration_secrets(account_slug)
            acct_provider = (
                str(acct_rec.get("provider") or "").strip().lower()
                if isinstance(acct_rec, dict)
                else None
            ) or preferred_provider
            extra_meta, norm_target = runner._connector_gateway.normalize_action_payload(
                provider=acct_provider,
                action_type=resolved_action,
                action=action,
            )
            payload_dict: dict[str, Any] = {**(extra_meta or {}), "text": text}
            if norm_target:
                payload_dict["target"] = norm_target
            source_url = (
                action.get("source_url")
                or action.get("url")
                or payload_obj.get("source_url")
            )
            source_excerpt = action.get("source_excerpt") or payload_obj.get("source_excerpt")
            queued = await runner._approvals.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug=account_slug,
                action_type=resolved_action,
                payload=payload_dict,
                source_url=source_url,
                source_excerpt=source_excerpt,
                escalation_note=str(
                    action.get("escalation_note")
                    or f"Explicit request_human_approval escalation by {bot['slug']}."
                ),
                hop_count=hop_count,
            )
            results.append({"type": a_type, "status": "queued_approval", "approval_id": queued["id"]})

        elif a_type == "remember_rule":
            if not runner._is_interactive_operator_trigger(trigger_type):
                results.append(
                    {
                        "type": a_type,
                        "status": "blocked_untrusted_trigger",
                        "detail": "remember_rule is only permitted during interactive operator chat turns.",
                    }
                )
                return True
            rule_text = str(action.get("rule_text") or action.get("rule") or "").strip()
            if not rule_text:
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": "Missing rule_text for remember_rule.",
                    }
                )
                return True
            scope = bot["slug"]
            saved_rule = runner._repo.add_style_rule(rule_text=rule_text, scope_slug=scope)
            results.append(
                {
                    "type": a_type,
                    "status": "ok",
                    "rule_id": saved_rule["id"],
                    "rule_text": saved_rule["rule_text"],
                    "scope_slug": saved_rule["scope_slug"],
                }
            )
        else:
            return False
        return True

    async def _dispatch_core_part2(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        file_owner_email = ctx.file_owner_email
        target_page_slug = ctx.target_page_slug
        t_payload = ctx.t_payload
        results = ctx.results
        if a_type == "open_page":
            raw_slug = str(action.get("slug") or action.get("page") or action.get("title") or "").strip()
            mode = "full" if str(action.get("mode") or "").lower() == "full" else "split"
            pages = runner._repo.list_pages()
            target_page_rec: dict[str, Any] | None = None
            if raw_slug:
                cand_s = slugify(raw_slug)
                target_page_rec = next(
                    (
                        p
                        for p in pages
                        if p["slug"] == cand_s
                        or p["slug"] == raw_slug
                        or p["title"].strip().lower() == raw_slug.lower()
                    ),
                    None,
                )
                if target_page_rec is None:
                    target_page_rec = next(
                        (p for p in pages if raw_slug.lower() in p["title"].lower() or cand_s in p["slug"]),
                        None,
                    )
                if target_page_rec is None:
                    results.append(
                        {
                            "type": a_type,
                            "status": "not_found",
                            "slug": cand_s or raw_slug,
                            "detail": f"No Page matching '{raw_slug}' exists yet.",
                        }
                    )
                    return True
            else:
                room_ctx = t_payload.get("room_context")
                pinned_room_slug = str(
                    (room_ctx.get("pinned_page_slug") if isinstance(room_ctx, dict) else None)
                    or target_page_slug
                    or ""
                ).strip()
                if not pinned_room_slug and isinstance(room_ctx, dict) and room_ctx.get("room_slug"):
                    with suppress(Exception):
                        pinned_room_slug = str(
                            runner._repo.get_room(str(room_ctx["room_slug"])).get("pinned_page_slug") or ""
                        ).strip()
                if pinned_room_slug:
                    target_page_rec = next(
                        (p for p in pages if p["slug"] == pinned_room_slug),
                        None,
                    )
                if target_page_rec is None:
                    target_page_rec = next(
                        (p for p in pages if p["owner_bot_slug"] == bot["slug"]),
                        None,
                    )
                if target_page_rec is None and len(pages) == 1:
                    target_page_rec = pages[0]
                if target_page_rec is None:
                    results.append(
                        {
                            "type": a_type,
                            "status": "not_found",
                            "slug": "",
                            "detail": "No Page exists for this bot yet.",
                        }
                    )
                    return True
            results.append(
                {
                    "type": a_type,
                    "status": "ok",
                    "slug": target_page_rec["slug"],
                    "page_slug": target_page_rec["slug"],
                    "title": target_page_rec["title"],
                    "mode": mode,
                }
            )

        elif a_type == "list_workspace_files":
            files = runner._repo.list_workspace_files(file_owner_email)
            results.append(
                {
                    "type": a_type,
                    "status": "ok",
                    "files": [
                        {
                            "id": f["id"],
                            "filename": f["filename"],
                            "mime_type": f["mime_type"],
                            "size_bytes": f["size_bytes"],
                            "updated_at": f["updated_at"],
                        }
                        for f in files[:30]
                    ],
                }
            )

        elif a_type == "read_workspace_file":
            key = str(action.get("file_id") or action.get("id") or action.get("filename") or "").strip()
            if not key:
                results.append({"type": a_type, "status": "skipped_invalid_action", "detail": "Missing file_id or filename."})
                return True
            try:
                meta, fpath = runner._repo.get_workspace_file(key, owner_email=file_owner_email)
                secret_vals = runner._repo.collect_all_vault_secret_values()
                derived_info: dict[str, Any] = {}
                with suppress(Exception):
                    derived_info = runner._repo.get_workspace_file_derived_paths(
                        meta["id"], owner_email=file_owner_email
                    )
                pages_parquet = derived_info.get("pages_parquet_path")
                derived_list = derived_info.get("derived_datasets") or []

                if pages_parquet and Path(str(pages_parquet)).is_file():
                    page_start = max(1, int(action.get("page_start") or 1))
                    page_end = max(page_start, int(action.get("page_end") or (page_start + 9)))
                    search_q = str(action.get("query") or "").strip() or None
                    if search_q:
                        q_res = execute_duckdb_query(
                            "SELECT page_num, char_count, is_scanned, text FROM dataset WHERE text ILIKE '%' || ? || '%' ORDER BY page_num ASC LIMIT 20",
                            datasets=[{"id": f"file:{meta['id']}:pages", "parquet_path": pages_parquet}],
                            secret_values=secret_vals,
                            params=[search_q],
                            row_cap=20,
                        )
                    else:
                        q_res = execute_duckdb_query(
                            "SELECT page_num, char_count, is_scanned, text FROM dataset WHERE page_num BETWEEN ? AND ? ORDER BY page_num ASC",
                            datasets=[{"id": f"file:{meta['id']}:pages", "parquet_path": pages_parquet}],
                            secret_values=secret_vals,
                            params=[page_start, page_end],
                            row_cap=50,
                        )
                    total_pages = int(derived_info.get("page_count") or len(q_res["rows"]))
                    rendered_pages = "\n\n".join(
                        f"[Page {r.get('page_num')}]\n{r.get('text') or ''}"
                        for r in q_res["rows"]
                    )[:24_000]
                    if not rendered_pages and derived_info.get("scanned_pages"):
                        rendered_pages = (
                            f"[Scanned PDF: {total_pages} page(s); vision frames attached when uploaded in chat]"
                        )
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "file_id": meta["id"],
                            "filename": meta["filename"],
                            "mime_type": meta["mime_type"],
                            "size_bytes": meta["size_bytes"],
                            "total_pages": total_pages,
                            "page_start": page_start,
                            "page_end": page_end,
                            "has_more_pages": (not search_q) and page_end < total_pages,
                            "extracted_tables": derived_info.get("extracted_tables") or [],
                            "scanned_pages": derived_info.get("scanned_pages") or [],
                            "dataset_ids": [d.get("id") for d in derived_list if d.get("id")],
                            "content": rendered_pages,
                        }
                    )
                elif derived_list:
                    specs = [
                        {"id": d["id"], "parquet_path": d["parquet_path"], "kind": d.get("kind")}
                        for d in derived_list[:6]
                        if d.get("parquet_path")
                    ]
                    profs = profile_datasets(specs, secret_values=secret_vals) if specs else []
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "file_id": meta["id"],
                            "filename": meta["filename"],
                            "mime_type": meta["mime_type"],
                            "size_bytes": meta["size_bytes"],
                            "dataset_ids": list(
                                dict.fromkeys(
                                    [f"file:{meta['id']}", *[d.get("id") for d in derived_list if d.get("id")]]
                                )
                            ),
                            "derived_datasets": meta.get("derived_datasets") or [],
                            "profile": profs,
                            "content": str(meta.get("text_preview") or "")[:16_000],
                        }
                    )
                else:
                    text_body = meta.get("text_preview") or ""
                    lower_name = str(meta.get("filename") or "").lower()
                    is_binary_doc = lower_name.endswith(
                        (".pdf", ".xlsx", ".xlsm", ".xlsb", ".xls", ".ods", ".docx", ".parquet")
                    )
                    if not text_body and not meta.get("is_image") and not is_binary_doc:
                        raw_bytes = fpath.read_bytes()[:64_000]
                        text_body = redact_secrets(
                            raw_bytes.decode("utf-8", errors="replace"),
                            secret_vals,
                        )[:16_000]
                    results.append(
                        {
                            "type": a_type,
                            "status": "ok",
                            "file_id": meta["id"],
                            "filename": meta["filename"],
                            "mime_type": meta["mime_type"],
                            "size_bytes": meta["size_bytes"],
                            "content": text_body[:16_000],
                        }
                    )
            except Exception as exc:
                results.append({"type": a_type, "status": "not_found", "detail": str(exc)})

        elif a_type == "write_workspace_file":
            fname = str(action.get("filename") or action.get("name") or "output.md").strip()
            content = str(action.get("content") or action.get("text") or "").encode("utf-8")
            scrubbed_text = redact_secrets(
                content.decode("utf-8", errors="replace"),
                runner._repo.collect_all_vault_secret_values(),
            ).encode("utf-8")
            lower_fn = fname.lower()
            mime_guess = (
                "text/html"
                if lower_fn.endswith((".html", ".htm"))
                else (
                    "image/svg+xml"
                    if lower_fn.endswith(".svg")
                    else (
                        "text/markdown"
                        if lower_fn.endswith(".md")
                        else (
                            "text/csv"
                            if lower_fn.endswith(".csv")
                            else (
                                "application/json"
                                if lower_fn.endswith(".json")
                                else "text/plain"
                            )
                        )
                    )
                )
            )
            try:
                saved_f = runner._repo.save_workspace_file(
                    owner_email=file_owner_email,
                    filename=fname,
                    mime_type=str(action.get("mime_type") or mime_guess),
                    content_bytes=scrubbed_text,
                    uploaded_by=f"bot:{bot['slug']}",
                )
                results.append(
                    {
                        "type": a_type,
                        "status": "ok",
                        "file": saved_f,
                    }
                )
            except Exception as exc:
                results.append({"type": a_type, "status": "error", "detail": str(exc)})
        else:
            return False
        return True

    async def _dispatch_core_part3(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        trigger_type = ctx.trigger_type
        results = ctx.results
        if a_type == "save_skill":
            if not runner._is_interactive_operator_trigger(trigger_type):
                results.append(
                    {
                        "type": a_type,
                        "status": "blocked_untrusted_trigger",
                        "detail": "save_skill is only permitted during interactive operator chat turns.",
                    }
                )
                return True
            skill_name = str(action.get("name") or "").strip()
            instructions = str(action.get("instructions") or "").strip()
            if not skill_name or not instructions:
                results.append(
                    {
                        "type": a_type,
                        "status": "skipped_invalid_action",
                        "detail": "Missing name or instructions for save_skill.",
                    }
                )
                return True
            scope = bot["slug"]
            saved_skill = runner._repo.upsert_skill(
                name=skill_name,
                description=str(action.get("description") or "").strip(),
                instructions=instructions,
                scope_slug=scope,
            )
            results.append(
                {
                    "type": a_type,
                    "status": "ok",
                    "skill": saved_skill,
                }
            )
        else:
            return False
        return True

    async def _dispatch_core_part4(self, a_type: str, ctx: ToolDispatchContext) -> bool:
        runner = self._runner
        bot = ctx.bot
        action = ctx.action
        correlation_id = ctx.correlation_id
        hop_count = ctx.hop_count
        results = ctx.results
        if a_type == "propose_specialist_bot":
            spec_prompt = str(
                action.get("prompt") or action.get("role") or action.get("name") or ""
            ).strip()
            if not spec_prompt:
                return True
            from argo_core.runner.bot_builder import ConversationalBotBuilder

            builder = ConversationalBotBuilder(repo=runner._repo)
            drafted = await builder.draft_bot_spec(spec_prompt)
            bot_spec = dict(drafted["draft"])
            if action.get("name"):
                bot_spec["name"] = str(action["name"]).strip()[:120]
                bot_spec["slug"] = slugify(bot_spec["name"])
            if action.get("role"):
                bot_spec["role"] = str(action["role"]).strip()[:2000]
            if action.get("section"):
                bot_spec["section"] = str(action["section"]).strip()[:80]
            queued = await runner._approvals.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug="argo_workspace",
                action_type="create_specialist_bot",
                payload={
                    "title": f"Create Specialist Bot: {bot_spec['name']}",
                    "text": f"Role: {bot_spec['role']}\nSchedule: {bot_spec['routines'][0].get('schedule', 'Manual') if bot_spec.get('routines') else 'Manual'}",
                    "bot_spec": bot_spec,
                },
                escalation_note=f"Proposed by {bot['name']} for human confirmation.",
                hop_count=hop_count,
            )
            results.append(
                {
                    "type": a_type,
                    "status": "queued_approval",
                    "approval_id": queued["id"],
                    "proposed_name": bot_spec["name"],
                }
            )

        elif a_type == "propose_fleet_cleanup":
            operations = [
                op for op in (action.get("operations") or []) if isinstance(op, dict) and op.get("bot_slug")
            ]
            if not operations:
                return True
            reason = str(action.get("reason") or "Bot audit cleanup proposal").strip()
            lines = []
            for op in operations:
                changes = []
                if op.get("delete"):
                    changes.append("delete")
                if op.get("enabled") is False:
                    changes.append("pause")
                if op.get("hidden_in_sidebar"):
                    changes.append("hide from sidebar")
                if op.get("section"):
                    changes.append(f"move to section '{op['section']}'")
                lines.append(f"- {op['bot_slug']}: {', '.join(changes) or 'update'}")
            queued = await runner._approvals.enqueue_human_approval(
                correlation_id=correlation_id,
                bot_slug=bot["slug"],
                target_account_slug="argo_workspace",
                action_type="fleet_cleanup",
                payload={
                    "title": f"Bot Fleet Audit ({len(operations)} changes)",
                    "text": f"{reason}\n\n" + "\n".join(lines),
                    "operations": operations,
                },
                escalation_note=reason,
                hop_count=hop_count,
            )
            results.append(
                {
                    "type": a_type,
                    "status": "queued_approval",
                    "approval_id": queued["id"],
                    "operations_count": len(operations),
                }
            )
        else:
            return False
        return True
