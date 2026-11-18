"""REST and SSE endpoints for the Argo 3-pane workspace."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
import urllib.parse
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse

from argo_core import __version__
from argo_core.bus.valkey_bus import EventBus, HopLimitExceededError
from argo_core.connectors.google_oauth import (
    GoogleOAuthConfigError,
    GoogleOAuthIntegrationError,
    GoogleOAuthService,
)
from argo_core.connectors.linkedin import (
    LinkedInConfigError,
    LinkedInIntegrationError,
    LinkedInService,
)
from argo_core.connectors.manager import ConnectorManager
from argo_core.connectors.telegram_bot import (
    TelegramBotService,
    TelegramConfigError,
    TelegramIntegrationError,
)
from argo_core.connectors.webhooks import (
    WebhookConfigError,
    WebhookService,
    WebhookSignatureError,
)
from argo_core.db.repositories import (
    MAX_WORKSPACE_FILE_BYTES,
    AlreadyResolvedError,
    ArgoRepository,
    FileTooLargeError,
    NotFoundError,
    make_id,
    slugify,
)
from argo_core.desktop.cdp_bridge import DesktopTakeoverRequiredError
from argo_core.desktop.manager import (
    SELKIES_HTTP_PORT,
    DesktopConfigError,
    DesktopRuntimeError,
    DesktopStartupBlockedError,
    DesktopStateError,
    DockerSdkDriver,
    validate_desktop_slug,
)
from argo_core.desktop.mcp_bridge import DesktopMCPError
from argo_core.llm.router import (
    BudgetExceededError,
    LLMExecutionError,
    LLMRouter,
    ModelConfigurationError,
)
from argo_core.models import (
    AppendBotMessageRequest,
    AppendRoomMessageRequest,
    CompleteGoogleOAuthRequest,
    CreateApprovalRequest,
    CreateBotRequest,
    CreatePageRequest,
    CreateRoomRequest,
    CreateSkillRequest,
    CreateStyleRuleRequest,
    DesktopActionRequest,
    DesktopBrowseRequest,
    DesktopRecordingSaveRequest,
    DesktopRecordingStopRequest,
    DispatchActivityRequest,
    DraftBotSpecRequest,
    ExecuteDelegationPlanRequest,
    FetchRssRequest,
    FetchWebpageRequest,
    GeneratePageRequest,
    ImportBotBlueprintRequest,
    ImportMemoryRequest,
    ImportTeamPackRequest,
    MarkThreadReadRequest,
    OnboardLinkedInRequest,
    OnboardTelegramPublicMonitorRequest,
    OnboardTelegramRequest,
    OnboardWebhookRequest,
    PageCollectionQueryRequest,
    ProbeIntegrationRequest,
    PublishLinkedInPostRequest,
    ResolveApprovalRequest,
    StartGoogleOAuthRequest,
    SyncTelegramPublicRequest,
    TestModelRequest,
    ToggleMessageReactionRequest,
    TriggerBotRequest,
    UpdateBotRequest,
    UpdatePageRequest,
    UpdateRoomRequest,
    UploadWorkspaceFileJsonRequest,
    UpsertDocumentRequest,
    UpsertIntegrationRequest,
    UpsertModelRequest,
    VaultSecretUpdateRequest,
    VaultSecretUpsertRequest,
)
from argo_core.security.ssrf import AntiBotHaltError, PublicFetchError, SSRFBlockedError
from argo_core.security.sso import extract_sso_principal
from argo_core.security.vault import SecretVault, redact_secrets
from argo_core.tools.public_web import fetch_public_webpage, fetch_rss_feed
from argo_core.watchdog.resource_guard import HostResourceGuard

router = APIRouter(prefix="/api")
hooks_router = APIRouter(prefix="/hooks")


def _deps(request: Request) -> tuple[ArgoRepository, EventBus, HostResourceGuard, SecretVault]:
    state = request.app.state
    return state.repo, state.bus, state.guard, state.vault


def _services(request: Request) -> tuple[LLMRouter, TelegramBotService]:
    state = request.app.state
    return state.llm_router, state.telegram_service


def _connector_services(
    request: Request,
) -> tuple[GoogleOAuthService, LinkedInService, WebhookService, ConnectorManager]:
    state = request.app.state
    return (
        state.google_oauth_service,
        state.linkedin_service,
        state.webhook_service,
        state.connector_manager,
    )


@router.get("/health")
def health_check(request: Request) -> dict[str, Any]:
    repo, bus, guard, vault = _deps(request)
    telemetry = guard.sample()
    return {
        "status": "ok",
        "version": __version__,
        "sqlite_wal": repo.check_wal_enabled(),
        "valkey_connected": bus.connected,
        "vault_configured": vault.is_configured,
        "host": telemetry.to_dict(),
    }


@router.get("/me")
def current_principal(request: Request) -> dict[str, Any]:
    return extract_sso_principal(request)


@router.get("/workspace/summary")
def workspace_summary(request: Request) -> dict[str, Any]:
    repo, bus, guard, vault = _deps(request)
    telemetry = guard.sample()
    return {
        "version": __version__,
        "sqlite_wal": repo.check_wal_enabled(),
        "valkey_connected": bus.connected,
        "vault_configured": vault.is_configured,
        "counts": repo.workspace_counts(),
        "host": telemetry.to_dict(),
    }


@router.get("/workspace/live-status")
def workspace_live_status(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    desktop_states: dict[str, dict[str, Any]] = {}
    if desktop_manager is not None:
        try:
            desk_info = desktop_manager.list_desktops_status()
            for d in desk_info.get("desktops", []):
                if isinstance(d, dict) and d.get("bot_slug"):
                    desktop_states[str(d["bot_slug"])] = d
        except Exception:
            pass
    bot_runner = getattr(request.app.state, "bot_runner", None)
    active_runs = bot_runner.active_runs() if bot_runner is not None else {}
    return repo.build_live_workspace_status(
        desktop_states=desktop_states,
        active_runs=active_runs,
        user_email=principal["email"],
    )


@router.get("/activity")
def list_activity(
    request: Request,
    category: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_events(category=category, limit=limit)


@router.post("/activity/dispatch", status_code=status.HTTP_201_CREATED)
async def dispatch_activity(
    request: Request,
    body: DispatchActivityRequest,
) -> dict[str, Any]:
    _, bus, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        return await bus.publish(
            correlation_id=make_id("corr"),
            source_slug=principal["actor"],
            target_slug=body.target_slug,
            event_type="operator.instruction",
            payload={
                "category": "reviews",
                "title": "Operator Instruction Dispatched",
                "badge": "Queued · Valkey Stream",
                "badge_tone": "indigo",
                "summary": body.instruction,
                "meta": "Valkey argo:events · hop_count=1/5",
            },
            hop_count=1,
        )
    except HopLimitExceededError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/activity/stream")
async def activity_stream(
    request: Request,
    max_events: int | None = Query(default=None, ge=1, le=100),
) -> StreamingResponse:
    _, bus, _, _ = _deps(request)

    async def event_generator() -> AsyncIterator[str]:
        sent = 0
        async with bus.subscribe() as queue:
            yield f"event: connected\ndata: {json.dumps({'status': 'connected'})}\n\n"
            sent += 1
            if max_events is not None and sent >= max_events:
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    if isinstance(event, dict) and event.get("_sse_event"):
                        sse_name = str(event["_sse_event"])
                        payload = {k: v for k, v in event.items() if k != "_sse_event"}
                        yield f"event: {sse_name}\ndata: {json.dumps(payload)}\n\n"
                    else:
                        yield f"event: activity\ndata: {json.dumps(event)}\n\n"
                    sent += 1
                    if max_events is not None and sent >= max_events:
                        break
                except TimeoutError:
                    yield ": heartbeat\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/bots")
def list_bots(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_bots()


@router.post("/bots", status_code=status.HTTP_201_CREATED)
async def create_bot(request: Request, body: CreateBotRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    bot = repo.create_bot(
        name=body.name,
        role=body.role,
        runtime=body.runtime,
        outbound_rbac=body.outbound_rbac,
        model=body.model,
        daily_cap=body.daily_cap,
        slug=body.slug,
        role_prompt=body.role_prompt,
        routines=body.routines,
        tools=body.tools,
        collections=body.collections,
        linked_accounts=body.linked_accounts,
        avatar_color=body.avatar_color,
        avatar_icon=body.avatar_icon,
        pinned=body.pinned,
        section=body.section,
        hidden_in_sidebar=body.hidden_in_sidebar,
        boundaries=body.boundaries,
        goal_metric=body.goal_metric,
        handoff_bot_slug=body.handoff_bot_slug,
        onboarding_mode=body.onboarding_mode,
    )
    scheduler = getattr(request.app.state, "bot_scheduler", None)
    if scheduler is not None:
        scheduler.sync_bots()
    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug="system",
        target_slug=bot["slug"],
        event_type="bot.registered",
        payload={
            "category": "alerts",
            "title": f"Registered Bot: {bot['name']}",
            "badge": f"{bot['runtime'].upper()} · {bot['outbound_rbac']}",
            "badge_tone": "slate",
            "summary": bot["role"],
            "meta": f"Model: {bot['model']}",
        },
        hop_count=1,
    )
    return bot


@router.post("/bots/import-blueprint", status_code=status.HTTP_201_CREATED)
async def import_bot_blueprint(
    request: Request,
    body: ImportBotBlueprintRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    try:
        bot = repo.import_bot_blueprint(
            body.blueprint,
            linked_accounts=body.linked_accounts or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scheduler = getattr(request.app.state, "bot_scheduler", None)
    if scheduler is not None:
        scheduler.sync_bots()
    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug="system",
        target_slug=bot["slug"],
        event_type="bot.registered",
        payload={
            "category": "alerts",
            "title": f"Imported Bot Blueprint: {bot['name']}",
            "badge": f"{bot['runtime'].upper()} · {bot['outbound_rbac']}",
            "badge_tone": "indigo",
            "summary": bot["role"],
            "meta": f"Model: {bot['model']}",
        },
        hop_count=1,
    )
    return bot


@router.post("/bots/builder/draft")
async def draft_bot_spec(request: Request, body: DraftBotSpecRequest) -> dict[str, Any]:
    bot_builder = request.app.state.bot_builder
    try:
        return await bot_builder.draft_bot_spec(
            body.prompt,
            preferred_runtime=body.preferred_runtime,
            preferred_rbac=body.preferred_rbac,
            preferred_model=body.preferred_model,
            linked_accounts=body.linked_accounts,
        )
    except (ValueError, ModelConfigurationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/bots/{slug}")
def get_bot(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.get_bot(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/bots/{slug}")
def update_bot(request: Request, slug: str, body: UpdateBotRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        updated = repo.update_bot(slug, body.model_dump(exclude_none=True))
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    scheduler = getattr(request.app.state, "bot_scheduler", None)
    if scheduler is not None:
        scheduler.sync_bots()
    return updated


@router.delete("/bots/{slug}")
async def delete_bot(request: Request, slug: str) -> dict[str, str]:
    repo, bus, _, _ = _deps(request)
    try:
        deleted_bot = repo.delete_bot(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    clean_slug = str(deleted_bot.get("slug") or slug)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    if desktop_manager is not None:
        with contextlib.suppress(Exception):
            await desktop_manager.destroy_desktop(clean_slug)
    desktop_mcp_bridge = getattr(request.app.state, "desktop_mcp_bridge", None)
    if desktop_mcp_bridge is not None and hasattr(desktop_mcp_bridge, "_sim_states"):
        desktop_mcp_bridge._sim_states.pop(clean_slug, None)
    bot_runner = getattr(request.app.state, "bot_runner", None)
    if bot_runner is not None:
        if hasattr(bot_runner, "cancel_thread_runs"):
            with contextlib.suppress(Exception):
                await bot_runner.cancel_thread_runs(f"bot:{clean_slug}")
        if hasattr(bot_runner, "_active_runs"):
            bot_runner._active_runs.pop(clean_slug, None)

    scheduler = getattr(request.app.state, "bot_scheduler", None)
    if scheduler is not None:
        scheduler.sync_bots()

    with contextlib.suppress(Exception):
        await bus.publish(
            correlation_id=make_id("corr"),
            source_slug="system",
            target_slug=clean_slug,
            event_type="bot.deleted",
            payload={
                "category": "alerts",
                "title": f"Deleted Bot: {deleted_bot.get('name') or clean_slug}",
                "badge": "Removed",
                "badge_tone": "slate",
                "summary": f"Removed bot '{clean_slug}' and cleaned associated threads, snapshots, and desktop resources.",
                "meta": f"Runtime: {deleted_bot.get('runtime', 'api')}",
            },
            hop_count=1,
        )
    return {"status": "deleted", "slug": clean_slug}


@router.get("/bots/{slug}/blueprint")
def export_bot_blueprint(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.export_bot_blueprint(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/bots/{slug}/trigger")
async def trigger_bot(
    request: Request,
    slug: str,
    body: TriggerBotRequest | None = None,
) -> dict[str, Any]:
    bot_runner = request.app.state.bot_runner
    req_body = body or TriggerBotRequest()
    payload = dict(req_body.payload)
    if req_body.input_text and req_body.input_text.strip():
        payload.setdefault("input_text", req_body.input_text.strip())
    try:
        result = await bot_runner.execute_bot(
            slug,
            trigger_type="manual_trigger",
            correlation_id=req_body.correlation_id,
            hop_count=1,
            trigger_payload=payload,
            routine_id=req_body.routine_id,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ModelConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, LLMExecutionError, DesktopRuntimeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if req_body.wait_for_chain:
        await bot_runner.wait_for_idle(timeout=10.0)
    return result


@router.get("/bots/{slug}/messages")
def list_bot_messages(
    request: Request,
    response: Response,
    slug: str,
    limit: int = Query(default=40, ge=1, le=200),
    before_id: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        repo.get_bot(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    messages, has_more, total_count = repo.list_bot_messages_window(
        slug, limit=limit, before_id=before_id
    )
    if before_id is None:
        repo.mark_thread_read(user_email=principal["email"], target_type="bot", slug=slug)
    response.headers["X-Has-More"] = "true" if has_more else "false"
    response.headers["X-Total-Count"] = str(total_count)
    return messages


@router.post("/bots/{slug}/messages")
async def post_bot_message(
    request: Request,
    slug: str,
    body: AppendBotMessageRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    bot_runner = request.app.state.bot_runner
    try:
        bot = repo.get_bot(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    user_text = body.text.strip()
    if not user_text and not body.attachment_ids:
        raise HTTPException(status_code=400, detail="Message text or an attachment is required.")
    effective_text = user_text or "Review the attached workspace file(s)."
    corr_id = make_id("corr")

    mention_tokens = [tok.lower() for tok in re.findall(r"@([a-zA-Z0-9._-]+)", user_text)]
    all_bots = {b["slug"]: b for b in repo.list_bots()}
    all_integrations = {acc["slug"]: acc for acc in repo.list_integrations()}
    all_skills = {s["slug"]: s for s in repo.list_skills()}

    mentioned_bots = [
        tok for tok in mention_tokens if tok in all_bots and tok != slug
    ]
    mentioned_integrations = [
        acc_slug
        for acc_slug, acc in all_integrations.items()
        if any(
            tok == acc_slug.lower()
            or tok == slugify(acc["display_name"])
            or (acc.get("account_identifier") and tok == str(acc["account_identifier"]).lstrip("@").lower())
            for tok in mention_tokens
        )
    ]
    requested_skill_slugs = list(
        dict.fromkeys(
            [slugify(s) for s in body.skill_slugs if str(s).strip()]
            + [tok for tok in mention_tokens if tok in all_skills]
        )
    )
    active_skills = [
        {
            "slug": all_skills[s_slug]["slug"],
            "name": all_skills[s_slug]["name"],
            "description": all_skills[s_slug]["description"],
            "instructions": all_skills[s_slug]["instructions"],
        }
        for s_slug in requested_skill_slugs
        if s_slug in all_skills
    ]

    attachments_meta: list[dict[str, Any]] = []
    valid_attachment_ids: list[str] = []
    for fid in body.attachment_ids:
        try:
            fmeta, _ = repo.get_workspace_file(fid, owner_email=principal["email"])
            valid_attachment_ids.append(fmeta["id"])
            attachments_meta.append(
                {
                    "id": fmeta["id"],
                    "filename": fmeta["filename"],
                    "mime_type": fmeta["mime_type"],
                    "size_bytes": fmeta["size_bytes"],
                    "is_image": fmeta["is_image"],
                }
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    quoted_message = (
        repo._resolve_reply_preview(
            collection="bot_threads",
            reply_to_id=body.reply_to_id,
            fallback_bot_name=bot["name"],
        )
        if body.reply_to_id
        else None
    )

    msg_meta: dict[str, Any] = {}
    if mentioned_bots:
        msg_meta["mentioned_bots"] = mentioned_bots
    if mentioned_integrations:
        msg_meta["mentioned_integrations"] = mentioned_integrations
    if requested_skill_slugs:
        msg_meta["skill_slugs"] = requested_skill_slugs
    if body.target_page_slug and body.target_page_slug.strip():
        msg_meta["target_page_slug"] = body.target_page_slug.strip()
    if attachments_meta:
        msg_meta["attachments"] = attachments_meta

    trigger_payload: dict[str, Any] = {
        "input_text": effective_text,
        "text": effective_text,
        "from_chat_thread": True,
        "operator_email": principal["email"],
    }
    if valid_attachment_ids:
        trigger_payload["attachment_ids"] = valid_attachment_ids
    if quoted_message:
        trigger_payload["quoted_message"] = quoted_message
    if mentioned_bots:
        trigger_payload["mentioned_bots"] = mentioned_bots
    if mentioned_integrations:
        trigger_payload["mentioned_integrations"] = mentioned_integrations
    if active_skills:
        trigger_payload["active_skills"] = active_skills
    if body.target_page_slug:
        trigger_payload["target_page_slug"] = body.target_page_slug.strip()
    if any(kw in effective_text.lower() for kw in ("audit", "fleet", "all bots", "cleanup")):
        trigger_payload["include_platform_status"] = True
    if body.context_correlation_id:
        prior_events = [
            {
                "event_type": ev["event_type"],
                "title": ev["payload"].get("title"),
                "summary": ev["payload"].get("summary"),
                "created_at": ev["created_at"],
            }
            for ev in repo.list_events(limit=100)
            if ev["correlation_id"] == body.context_correlation_id
        ]
        if prior_events:
            trigger_payload["continued_from_run"] = {
                "correlation_id": body.context_correlation_id,
                "events": prior_events,
            }

    if not bot["enabled"]:
        raise HTTPException(status_code=400, detail=f"Bot '{slug}' is disabled.")

    user_msg = repo.append_bot_message(
        slug,
        "user",
        user_text or "(Attached workspace file)",
        metadata=msg_meta or None,
        reply_to_id=body.reply_to_id,
    )
    if body.async_mode:
        repo.mark_thread_read(user_email=principal["email"], target_type="bot", slug=slug)

        async def _run_async_bot_turn(run_item: Any) -> dict[str, Any]:
            result = await bot_runner.execute_bot(
                slug,
                trigger_type="manual",
                correlation_id=corr_id,
                hop_count=1,
                trigger_payload=trigger_payload,
                run_item=run_item,
            )
            if not run_item.cancel_event.is_set() and result.get("status") != "cancelled":
                tokens_used = int(result.get("tokens_used") or 0)
                run_rec = result.get("run") or {}
                await bus.publish(
                    correlation_id=corr_id,
                    source_slug="operator",
                    target_slug=slug,
                    event_type="bot.message",
                    payload={
                        "category": "reviews",
                        "title": f"Thread Message -> {bot['name']}",
                        "badge": f"RBAC · {bot['outbound_rbac']}",
                        "badge_tone": "slate",
                        "summary": effective_text,
                        "meta": (
                            f"Model: {result.get('model_used') or bot['model']} · {tokens_used} tok "
                            f"(${float(run_rec.get('estimated_cost_usd') or 0.0):.4f})"
                        ),
                    },
                    hop_count=1,
                )
            repo.mark_thread_read(user_email=principal["email"], target_type="bot", slug=slug)
            return result

        item, queued_behind = bot_runner.enqueue_thread_turn(
            thread_key=f"bot:{bot['slug']}",
            target_type="bot",
            target_slug=bot["slug"],
            correlation_id=corr_id,
            bot_slug=bot["slug"],
            bot_name=bot["name"],
            work=_run_async_bot_turn,
        )
        if queued_behind > 0:
            await bus.emit_ephemeral(
                "turn_stream",
                {
                    "type": "run_queued",
                    "run_id": item.run_id,
                    "thread_key": item.thread_key,
                    "target_type": "bot",
                    "target_slug": bot["slug"],
                    "queued_behind": queued_behind,
                },
            )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "queued",
                "run_id": item.run_id,
                "user_message": user_msg,
                "queued_behind": queued_behind,
            },
        )

    try:
        result = await bot_runner.execute_bot(
            slug,
            trigger_type="manual",
            correlation_id=corr_id,
            hop_count=1,
            trigger_payload=trigger_payload,
        )
    except ModelConfigurationError as exc:
        repo.delete_document("bot_threads", user_msg["id"])
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        repo.delete_document("bot_threads", user_msg["id"])
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except SSRFBlockedError as exc:
        repo.delete_document("bot_threads", user_msg["id"])
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, LLMExecutionError, DesktopRuntimeError) as exc:
        repo.delete_document("bot_threads", user_msg["id"])
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if result.get("status") == "skipped_disabled":
        repo.delete_document("bot_threads", user_msg["id"])
        raise HTTPException(status_code=400, detail=f"Bot '{slug}' is disabled.")

    tokens_used = int(result.get("tokens_used") or 0)
    run_rec = result.get("run") or {}
    await bus.publish(
        correlation_id=corr_id,
        source_slug="operator",
        target_slug=slug,
        event_type="bot.message",
        payload={
            "category": "reviews",
            "title": f"Thread Message -> {bot['name']}",
            "badge": f"RBAC · {bot['outbound_rbac']}",
            "badge_tone": "slate",
            "summary": effective_text,
            "meta": (
                f"Model: {result.get('model_used') or bot['model']} · {tokens_used} tok "
                f"(${float(run_rec.get('estimated_cost_usd') or 0.0):.4f})"
            ),
        },
        hop_count=1,
    )
    repo.mark_thread_read(user_email=principal["email"], target_type="bot", slug=slug)
    messages_window, has_more, total_count = repo.list_bot_messages_window(slug, limit=40)
    return {
        "messages": messages_window,
        "has_more": has_more,
        "total_count": total_count,
        "run": run_rec,
        "result": result,
    }


@router.post("/runs/{run_id}/cancel")
async def cancel_active_run(request: Request, run_id: str) -> dict[str, Any]:
    bot_runner = request.app.state.bot_runner
    item = await bot_runner.cancel_run(run_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return {
        "status": "cancelled",
        "run_id": item.run_id,
        "message_id": item.message_id,
    }


@router.get("/runs")
def list_bot_runs(
    request: Request,
    bot_slug: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_bot_runs(bot_slug=bot_slug, limit=limit)


@router.get("/approvals")
def list_approvals(
    request: Request,
    tab: str = Query(default="pending"),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_approvals(tab=tab)


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
async def create_approval(
    request: Request,
    body: CreateApprovalRequest,
) -> dict[str, Any]:
    coordinator = request.app.state.approval_coordinator
    return await coordinator.enqueue_human_approval(
        correlation_id=body.correlation_id,
        bot_slug=body.bot_slug,
        target_account_slug=body.target_account_slug,
        action_type=body.action_type,
        payload=body.payload,
        source_url=body.source_url,
        source_excerpt=body.source_excerpt,
        escalation_note=body.escalation_note,
    )


@router.post("/approvals/{approval_id}/resolve")
async def resolve_approval(
    request: Request,
    approval_id: str,
    body: ResolveApprovalRequest,
) -> dict[str, Any]:
    coordinator = request.app.state.approval_coordinator
    principal = extract_sso_principal(request)
    actor = (
        f"{principal['actor']}:{body.channel}"
        if body.channel == "telegram"
        else principal["actor"]
    )
    try:
        return await coordinator.resolve_approval(
            approval_id=approval_id,
            action=body.action,
            actor=actor,
            edited_text=body.edited_text,
            style_rule=body.style_rule,
        )
    except AlreadyResolvedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/style-rules")
def list_style_rules(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_style_rules()


@router.post("/style-rules", status_code=status.HTTP_201_CREATED)
def add_style_rule(request: Request, body: CreateStyleRuleRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.add_style_rule(rule_text=body.rule_text, scope_slug=body.scope_slug)


@router.delete("/style-rules/{rule_id}")
def delete_style_rule(request: Request, rule_id: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_style_rule(rule_id)
        return {"status": "deleted", "id": rule_id}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/style-rules/import", status_code=status.HTTP_201_CREATED)
async def import_style_rules(request: Request, body: ImportMemoryRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    llm_router, _ = _services(request)
    raw = body.raw_text.strip()
    extracted: list[str] = []

    has_live_key = any(p.get("api_key") for p in repo.list_model_provider_credentials())
    has_custom_transport = getattr(llm_router, "_transport", None) is not None
    if has_live_key or has_custom_transport:
        try:
            res = await llm_router.complete(
                bot_slug="memory-importer",
                prompt=(
                    "Extract concise, reusable writing, tone, and workflow preference rules from these "
                    "pasted user notes. Return JSON: {\"rules\": [\"...\"]}.\n\n"
                    f"Notes:\n{raw[:8000]}"
                ),
                system_prompt="Return valid JSON with a 'rules' array of concise strings.",
                trigger_type="memory_import",
                hop_count=1,
            )
            parsed = json.loads(res.output_text)
            if isinstance(parsed, dict) and isinstance(parsed.get("rules"), list):
                extracted = [str(r).strip() for r in parsed["rules"] if str(r).strip()]
        except Exception:
            extracted = []

    if not extracted:
        for line in raw.splitlines():
            cleaned = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", line).strip()
            if len(cleaned) >= 4 and not cleaned.startswith("#"):
                extracted.append(cleaned[:300])
        if not extracted and len(raw) >= 4:
            extracted = [raw[:300]]

    existing_texts = {r["rule_text"].strip().lower() for r in repo.list_style_rules()}
    created: list[dict[str, Any]] = []
    for rule_text in extracted[:25]:
        norm = rule_text.strip().lower()
        if not norm or norm in existing_texts:
            continue
        existing_texts.add(norm)
        created.append(repo.add_style_rule(rule_text=rule_text.strip(), scope_slug=body.scope_slug))

    return {"imported_count": len(created), "rules": created}


@router.get("/skills")
def list_skills(
    request: Request,
    scope_slug: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_skills(scope_slug=scope_slug)


@router.post("/skills", status_code=status.HTTP_201_CREATED)
def upsert_skill(request: Request, body: CreateSkillRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.upsert_skill(
        name=body.name,
        description=body.description,
        instructions=body.instructions,
        scope_slug=body.scope_slug,
    )


@router.delete("/skills/{skill_id}")
def delete_skill(request: Request, skill_id: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_skill(skill_id)
        return {"status": "deleted", "id": skill_id}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/pages")
def list_pages(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_pages()


@router.post("/pages/generate", status_code=status.HTTP_201_CREATED)
async def generate_page(request: Request, body: GeneratePageRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    llm_router, _ = _services(request)
    prompt_lower = body.prompt.lower()

    resolved_template = body.template_key
    if resolved_template == "auto":
        if any(
            kw in prompt_lower
            for kw in ("hub board", "bot hub", "hub page", "command board")
        ):
            resolved_template = "bot_hub_board"
        elif any(
            kw in prompt_lower
            for kw in (
                "operations map",
                "live map",
                "bot map",
                "bot city",
                "every bot has a desk",
                "station",
                "floorplan",
            )
        ):
            resolved_template = "live_operations_map"
        elif any(
            kw in prompt_lower
            for kw in ("playground", "easing", "curve", "slider", "interactive explainer")
        ):
            resolved_template = "interactive_playground"
        else:
            resolved_template = "collection_analytics"

    existing_page: dict[str, Any] | None = None
    if body.existing_page_slug and body.existing_page_slug.strip():
        try:
            existing_page = repo.get_page(body.existing_page_slug.strip())
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    effective_collections = (
        list(body.allowed_collections)
        if body.allowed_collections
        else (list(existing_page.get("allowed_collections") or []) if existing_page else [])
    )

    default_titles = {
        "live_operations_map": "Live Bot Operations Map",
        "bot_hub_board": "Bot Hub Board",
        "interactive_playground": "Interactive Concept Playground",
        "collection_analytics": "Data Explorer & Analytics",
    }
    page_title = (
        (body.title or "").strip()
        or (existing_page["title"] if existing_page else "")
        or default_titles[resolved_template]
    )

    html_payload: str | None = None
    has_live_key = any(p.get("api_key") for p in repo.list_model_provider_credentials())
    has_custom_transport = getattr(llm_router, "_transport", None) is not None
    if has_live_key or (body.template_key == "auto" and has_custom_transport):
        sample_records: list[dict[str, Any]] = []
        for col in effective_collections[:4]:
            for doc in repo.search_documents(col, limit=8):
                sample_records.append(
                    {
                        "collection": doc["collection"],
                        "external_key": doc.get("external_key"),
                        "updated_at": doc.get("updated_at"),
                        "doc": doc.get("doc"),
                    }
                )
        compact_bots = [
            {
                "slug": b["slug"],
                "name": b["name"],
                "role": str(b.get("role") or "")[:100],
                "runtime": b.get("runtime", "api"),
            }
            for b in repo.list_bots()
        ]
        existing_block = (
            f"Existing Page HTML to redesign/refine in-place (preserve ARGO_READY / ARGO_PAGE_DATA wiring):\n"
            f"{str(existing_page.get('content_payload') or '')[:14000]}\n\n"
            if existing_page is not None
            else ""
        )
        try:
            res = await llm_router.complete(
                bot_slug=body.owner_bot_slug or "page-generator",
                prompt=(
                    f"{'Redesign/update' if existing_page else 'Generate'} a complete self-contained HTML5 page titled '{page_title}' "
                    f"(layout preference: {resolved_template}) for this request:\n{body.prompt}\n\n"
                    f"{existing_block}"
                    "Sober Professional Design System (MUST FOLLOW):\n"
                    "- Background canvas #161920, card surface #1e232c with 1px solid #2d3440 borders and 12px radius, nested row panels #181c23.\n"
                    "- Typography: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; crisp legible contrast with headings #f3f4f6, body 14px #e5e7eb, secondary labels >= 12px #9ca3af.\n"
                    "- Scrollbars: include `html { color-scheme: dark; scrollbar-width: thin; scrollbar-color: #363e4d #161920; } ::-webkit-scrollbar { width: 6px; height: 6px; } ::-webkit-scrollbar-track { background: #161920; } ::-webkit-scrollbar-thumb { background: #363e4d; border-radius: 9999px; }` so iframe scrollbars match the host workspace.\n"
                    "- Restrained, non-fluorescent, flat opaque neutral colors only (#2d3440 card borders — NEVER neon green or cyan borders — with #3b72b2 steel blue, #3b8c62 muted green, #c98a2c muted amber, #c24b4b muted red used strictly for tiny status dots; zero rgba transparency). STRICTLY NO fluo/neon/cyberpunk colors, NO purple/magenta/cyan gradients, and NO glowing borders or shadows.\n"
                    "- Clean executive header with title, concise subtitle, live status pill, interactive search/filter bar, and top KPI tiles.\n"
                    "- Wire window message handlers for ARGO_PAGE_DATA (msg.data.records) and ARGO_LIVE_STATUS (msg.liveStatus.bots) with initial render from embedded sample_records so the page looks rich immediately.\n"
                    "- Post window.parent.postMessage({type:'ARGO_READY'}, '*') on load. Never use same-origin sandbox relaxations; client-side file exports (<a download>, Blob, MediaRecorder, or ARGO_DOWNLOAD_FILE postMessage with 15s URL.revokeObjectURL delay) work natively inside Living Pages.\n\n"
                    f"Allowed collections: {effective_collections}\n"
                    f"Sample records: {json.dumps(sample_records[:12], default=str)[:4000]}\n"
                    f"Workspace bots: {json.dumps(compact_bots[:12], default=str)}\n"
                    "Return only valid HTML starting with <!DOCTYPE html>."
                ),
                system_prompt="Return a clean standalone dark-mode HTML5 executive dashboard document with inline CSS/JS.",
                trigger_type="page_generate",
                hop_count=1,
            )
            cand = res.output_text.strip()
            if cand.startswith("```"):
                cand = re.sub(r"^```(?:html)?\s*|\s*```$", "", cand, flags=re.IGNORECASE | re.DOTALL).strip()
            if (
                "<html" in cand.lower()
                and "allow-same-origin" not in cand.lower()
                and (
                    resolved_template not in {"live_operations_map", "bot_hub_board"}
                    or "ARGO_LIVE_STATUS" in cand
                )
            ):
                html_payload = cand
        except Exception:
            html_payload = None

    if html_payload is None:
        html_payload = repo.build_interactive_page_html(
            template_key=resolved_template,
            title=page_title,
            description=body.prompt[:200],
            allowed_collections=effective_collections,
        )

    try:
        if existing_page is not None:
            saved = repo.update_page(
                existing_page["slug"],
                {
                    "title": page_title,
                    "description": body.prompt[:200],
                    "render_mode": "sandboxed_html",
                    "content_payload": html_payload,
                    "allowed_collections": effective_collections,
                    "owner_bot_slug": body.owner_bot_slug or existing_page["owner_bot_slug"],
                },
            )
        else:
            saved = repo.create_page(
                title=page_title,
                description=body.prompt[:200],
                render_mode="sandboxed_html",
                content_payload=html_payload,
                allowed_collections=effective_collections,
                owner_bot_slug=body.owner_bot_slug,
            )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug=saved["owner_bot_slug"],
        target_slug=saved["slug"],
        event_type="page.updated",
        payload={
            "category": "reviews",
            "title": f"Generated Page: {saved['title']}",
            "badge": resolved_template,
            "badge_tone": "indigo",
            "summary": body.prompt[:200],
            "meta": f"Owner: {saved['owner_bot_slug']}",
        },
        hop_count=1,
    )
    return saved


@router.post("/pages", status_code=status.HTTP_201_CREATED)
def create_page(request: Request, body: CreatePageRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.create_page(
            title=body.title,
            description=body.description,
            render_mode=body.render_mode,
            content_payload=body.content_payload,
            allowed_collections=body.allowed_collections,
            owner_bot_slug=body.owner_bot_slug,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/pages/{slug}")
def get_page(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.get_page(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/pages/{slug}")
async def update_page(request: Request, slug: str, body: UpdatePageRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    try:
        updated = repo.update_page(slug, body.model_dump(exclude_none=True))
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug=updated["owner_bot_slug"],
        target_slug=updated["slug"],
        event_type="page.updated",
        payload={
            "category": "reviews",
            "title": f"Updated Page: {updated['title']}",
            "badge": updated["render_mode"],
            "badge_tone": "indigo",
            "summary": f"Allowed collections: {', '.join(updated['allowed_collections']) or 'none'}",
            "meta": "Dynamic view synchronized without rebuild",
        },
        hop_count=1,
    )
    return updated


@router.delete("/pages/{slug}")
def delete_page(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_page(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/pages/{slug}/data")
def get_page_data(
    request: Request,
    slug: str,
    q: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.resolve_page_data(slug, query=q, limit=limit)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/pages/{slug}/query")
def query_page_collection(
    request: Request,
    slug: str,
    body: PageCollectionQueryRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        records = repo.query_page_collection(
            slug,
            collection=body.collection,
            query=body.query,
            limit=body.limit,
        )
        return {
            "page_slug": slug,
            "collection": body.collection,
            "records": records,
        }
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/collections")
def list_collections(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_collections()


@router.post("/collections/{slug}/documents", status_code=status.HTTP_201_CREATED)
def upsert_collection_document(
    request: Request,
    slug: str,
    body: UpsertDocumentRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.upsert_document(
        collection=slug,
        external_key=body.external_key,
        search_text=body.search_text,
        doc=body.doc,
        description=body.description,
    )


@router.get("/collections/{slug}/documents")
def search_collection_documents(
    request: Request,
    slug: str,
    q: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.search_documents(collection=slug, query=q, limit=limit)


@router.get("/desktops")
def list_desktops(request: Request) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    return desktop_manager.list_desktops_status()


@router.post("/desktops/stop-all")
async def stop_all_desktops(request: Request) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    stopped = await desktop_manager.stop_all_desktops(reason="manual_stop_all")
    return {"stopped_desktops": stopped}


@router.post("/desktops/sweep-idle")
async def sweep_idle_desktops(request: Request) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    hibernated = await desktop_manager.sweep_idle_desktops()
    return {"hibernated_desktops": hibernated}


@router.post("/desktops/{slug}/toggle")
async def toggle_desktop(request: Request, slug: str) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    try:
        return await desktop_manager.toggle_desktop(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DesktopRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/desktops/{slug}/takeover/start")
async def start_desktop_takeover(request: Request, slug: str) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    principal = extract_sso_principal(request)
    try:
        return await desktop_manager.start_takeover(slug, actor=principal["actor"])
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DesktopRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/desktops/{slug}/takeover/release")
async def release_desktop_takeover(request: Request, slug: str) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    principal = extract_sso_principal(request)
    try:
        return await desktop_manager.release_takeover(slug, actor=principal["actor"])
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/desktops/{slug}/browse")
async def browse_via_desktop_cdp(
    request: Request,
    slug: str,
    body: DesktopBrowseRequest,
) -> dict[str, Any]:
    cdp_bridge = request.app.state.cdp_bridge
    try:
        return await cdp_bridge.navigate_and_extract(
            slug,
            body.url,
            selector=body.selector,
            max_chars=body.max_chars,
        )
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (
        DesktopStartupBlockedError,
        DesktopStateError,
        DesktopTakeoverRequiredError,
    ) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DesktopRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/desktops/{slug}/screenshot")
async def get_desktop_screenshot(
    request: Request,
    slug: str,
    refresh: bool = False,
    download: bool = False,
    max_width: int = Query(default=1280, ge=0, le=3840),
) -> Response:
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")

        if not refresh:
            cached = desktop_manager.get_cached_screenshot(clean_slug)
            if cached is not None:
                png_bytes, meta = cached
            elif bot["desktop_state"] != "running":
                raise HTTPException(
                    status_code=404,
                    detail="No cached screenshot while desktop is sleeping.",
                )
            else:
                png_bytes, meta = await desktop_mcp_bridge.capture_screenshot(
                    clean_slug, max_width=max_width
                )
        else:
            png_bytes, meta = await desktop_mcp_bridge.capture_screenshot(
                clean_slug, max_width=max_width
            )
    except HTTPException:
        raise
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DesktopRuntimeError, DesktopMCPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    headers = {
        "Cache-Control": "no-store",
        "X-Argo-Width": str(meta.get("width", "")),
        "X-Argo-Height": str(meta.get("height", "")),
        "X-Argo-Display": str(meta.get("display", ":1")),
    }
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{clean_slug}-desktop.png"'
    return Response(content=png_bytes, media_type="image/png", headers=headers)


@router.get("/desktops/{slug}/snapshots/{snapshot_id}")
def get_desktop_snapshot_image(
    request: Request,
    slug: str,
    snapshot_id: str,
    download: bool = False,
) -> Response:
    """Serve an immutable post-command desktop PNG snapshot without waking the container."""
    repo = request.app.state.repo
    try:
        clean_slug = validate_desktop_slug(slug)
        repo.get_bot(clean_slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    snap = repo.get_desktop_snapshot(clean_slug, snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="Snapshot not found.")
    try:
        png_bytes = base64.b64decode(str(snap.get("png_base64") or ""))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Corrupt snapshot payload.") from exc

    headers = {
        "Cache-Control": "private, max-age=86400, immutable",
        "X-Argo-Snapshot-Id": str(snap.get("snapshot_id") or snapshot_id),
    }
    if download:
        headers["Content-Disposition"] = (
            f'attachment; filename="{clean_slug}-{snapshot_id}.png"'
        )
    return Response(content=png_bytes, media_type="image/png", headers=headers)


@router.get("/desktops/{slug}/inspect")
async def inspect_desktop_agent(request: Request, slug: str) -> dict[str, Any]:
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        return await desktop_mcp_bridge.inspect_desktop(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DesktopRuntimeError, DesktopMCPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/desktops/{slug}/action")
async def execute_desktop_agent_action(
    request: Request,
    slug: str,
    body: DesktopActionRequest,
) -> dict[str, Any]:
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        res = await desktop_mcp_bridge.execute_action(
            slug,
            body.action,
            body.model_dump(exclude={"action"}, exclude_none=True),
        )
        if res.get("status") == "error" and "SSRF" in str(res.get("detail") or ""):
            raise HTTPException(status_code=403, detail=str(res["detail"]))
        return res
    except HTTPException:
        raise
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DesktopRuntimeError, DesktopMCPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def _build_deterministic_recorded_skill(
    *,
    bot_name: str,
    trace: dict[str, Any],
    notes: str | None = None,
) -> str:
    lines = [
        f"Recorded Virtual Desktop playbook from {bot_name}:",
    ]
    if notes and notes.strip():
        lines.append(f"Operator Notes: {notes.strip()}")
    commands = [
        str(c.get("cmd") or "").strip()
        for c in (trace.get("commands") or [])
        if isinstance(c, dict) and str(c.get("cmd") or "").strip()
    ]
    if commands:
        lines.append("")
        lines.append("Shell Commands (execute via desktop_exec):")
        for idx, cmd in enumerate(commands, 1):
            lines.append(f"{idx}. `{cmd}`")
    urls = [
        str(u.get("url") or "").strip()
        for u in (trace.get("visited_urls") or [])
        if isinstance(u, dict) and str(u.get("url") or "").strip()
    ]
    if urls:
        lines.append("")
        lines.append("Visited Web URLs (open via desktop_browse or desktop_launch):")
        for u in urls:
            lines.append(f"- {u}")
    dom_events = trace.get("dom_events") or []
    if dom_events:
        lines.append("")
        lines.append("Browser UI Interactions (replay via desktop_click / desktop_type / desktop_key):")
        for idx, ev in enumerate(dom_events[:60], 1):
            if not isinstance(ev, dict):
                continue
            kind = str(ev.get("kind") or "action")
            label = str(ev.get("label") or ev.get("selector") or ev.get("tag") or "element").strip()
            coords = f" at ({ev.get('x')}, {ev.get('y')})" if ev.get("x") is not None and ev.get("y") is not None else ""
            if kind == "input":
                lines.append(f"{idx}. Set `{label}`{coords} = `{ev.get('value')}`")
            elif kind == "key":
                lines.append(f"{idx}. Press key `{ev.get('key')}` on `{label}`")
            else:
                lines.append(f"{idx}. Click `{label}`{coords}")
    typed_inputs = trace.get("typed_inputs") or []
    if typed_inputs:
        lines.append("")
        lines.append("Keyboard Input Sequence:")
        for ti in typed_inputs[:40]:
            if isinstance(ti, dict) and str(ti.get("text") or "").strip():
                lines.append(f"- `{ti.get('text')}` (key/text)")
    windows = [
        str(w.get("window") or "").strip()
        for w in (trace.get("window_events") or [])
        if isinstance(w, dict) and str(w.get("window") or "").strip()
    ]
    if windows:
        lines.append("")
        lines.append("Window Focus Sequence: " + " -> ".join(dict.fromkeys(windows)))
    clicks = trace.get("clicks") or []
    if clicks:
        lines.append("")
        lines.append("Recorded Pointer Clicks:")
        for clk in clicks[:40]:
            if isinstance(clk, dict):
                lines.append(
                    f"- Click ({clk.get('x')}, {clk.get('y')}) in \"{clk.get('window') or 'Desktop'}\""
                )
    if not (commands or urls or dom_events or typed_inputs or windows or clicks):
        lines.append("- No terminal commands, browser URLs, or GUI interactions were captured during this session.")
    lines.append("")
    lines.append(
        "Replay ALL steps in order until the task completes cleanly (batch sequential clicks/types/keys across turns, inspect each screenshot to verify progress, and never stop prematurely after only the first field)."
    )
    return "\n".join(lines)


async def _compile_and_save_recorded_skill(
    *,
    repo: ArgoRepository,
    bus: EventBus,
    llm_router: LLMRouter,
    bot: dict[str, Any],
    raw_trace: dict[str, Any],
    skill_name: str | None,
    notes: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    clean_slug = bot["slug"]
    vault_secrets = repo.collect_all_vault_secret_values()
    scrubbed_json = redact_secrets(json.dumps(raw_trace, ensure_ascii=False), vault_secrets)
    scrubbed_trace = json.loads(scrubbed_json)

    fallback_instructions = _build_deterministic_recorded_skill(
        bot_name=bot["name"],
        trace=scrubbed_trace,
        notes=notes,
    )
    instructions = fallback_instructions
    has_live_key = any(bool(p.get("api_key")) for p in repo.list_model_provider_credentials())
    has_custom_transport = getattr(llm_router, "_transport", None) is not None
    if has_live_key or has_custom_transport:
        try:
            res = await llm_router.complete(
                bot_slug=clean_slug,
                prompt=(
                    f"Convert this recorded Virtual Desktop operator session for bot '{bot['name']}' into a complete, deterministic step-by-step replay playbook for Argo's bot runner (using desktop_exec, desktop_browse, desktop_launch, desktop_focus_window, desktop_click, desktop_type, desktop_key):\n\n"
                    f"{json.dumps(scrubbed_trace, ensure_ascii=False)[:10000]}\n"
                    + (f"\nOperator notes: {notes}" if notes else "")
                ),
                system_prompt="Produce clean plain-text numbered replay steps covering the entire workflow end-to-end. Never invent credentials; keep placeholders intact.",
                trigger_type="recording_compile",
                hop_count=1,
            )
            candidate = (res.output_text or "").strip()
            if candidate and not res.unconfigured_local:
                instructions = redact_secrets(candidate, vault_secrets)
        except Exception:
            instructions = fallback_instructions

    cmd_n = len(scrubbed_trace.get("commands") or [])
    url_n = len(scrubbed_trace.get("visited_urls") or [])
    dom_n = len(scrubbed_trace.get("dom_events") or [])
    click_n = len(scrubbed_trace.get("clicks") or [])
    input_n = len(scrubbed_trace.get("typed_inputs") or [])
    total_steps = cmd_n + url_n + dom_n + click_n + input_n
    skill_title = (skill_name or "").strip() or f"Recorded Session ({bot['name']} · {total_steps} steps)"
    saved_skill = repo.upsert_skill(
        name=skill_title,
        description=f"Recorded desktop workflow ({cmd_n} cmd, {url_n} url, {dom_n + click_n} ui, {input_n} input)",
        instructions=instructions,
        scope_slug=clean_slug,
    )
    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug=clean_slug,
        target_slug="skills",
        event_type="desktop.recording.saved",
        payload={
            "category": "reviews",
            "title": f"Saved Recorded Skill · {saved_skill['name']}",
            "badge": f"@{saved_skill['slug']}",
            "badge_tone": "slate",
            "summary": f"Saved {total_steps} captured step(s) from {bot['name']}.",
        },
        hop_count=1,
    )
    return scrubbed_trace, saved_skill


@router.post("/desktops/{slug}/recording/start")
async def start_desktop_recording(request: Request, slug: str) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    desktop_manager = request.app.state.desktop_manager
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")
        await desktop_manager.start_desktop(clean_slug)
        res = await desktop_mcp_bridge.execute_action(clean_slug, "record_start", {})
        await bus.publish(
            correlation_id=make_id("corr"),
            source_slug=clean_slug,
            target_slug="desktop",
            event_type="desktop.recording.started",
            payload={
                "category": "alerts",
                "title": f"Started Session Recording · {bot['name']}",
                "badge": "Recording",
                "badge_tone": "red",
                "summary": "Capturing terminal commands, browser URLs, window switches, and clicks.",
            },
            hop_count=1,
        )
        return res
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DesktopRuntimeError, DesktopMCPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/desktops/{slug}/recording/status")
async def get_desktop_recording_status(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")
        if bot["desktop_state"] != "running":
            return {"status": "ok", "recording": False, "elapsed_seconds": 0}
        return await desktop_mcp_bridge.execute_action(clean_slug, "record_status", {})
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError, DesktopRuntimeError, DesktopMCPError):
        return {"status": "ok", "recording": False, "elapsed_seconds": 0}


@router.post("/desktops/{slug}/recording/stop")
async def stop_desktop_recording(
    request: Request,
    slug: str,
    body: DesktopRecordingStopRequest | None = None,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    llm_router, _ = _services(request)
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    req_body = body or DesktopRecordingStopRequest()
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")
        raw_trace = await desktop_mcp_bridge.execute_action(clean_slug, "record_stop", {})
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (DesktopRuntimeError, DesktopMCPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if req_body.save_skill:
        scrubbed_trace, saved_skill = await _compile_and_save_recorded_skill(
            repo=repo,
            bus=bus,
            llm_router=llm_router,
            bot=bot,
            raw_trace=raw_trace,
            skill_name=req_body.skill_name,
            notes=req_body.notes,
        )
    else:
        vault_secrets = repo.collect_all_vault_secret_values()
        scrubbed_json = redact_secrets(json.dumps(raw_trace, ensure_ascii=False), vault_secrets)
        scrubbed_trace = json.loads(scrubbed_json)
        saved_skill = None
        await bus.publish(
            correlation_id=make_id("corr"),
            source_slug=clean_slug,
            target_slug="desktop",
            event_type="desktop.recording.stopped",
            payload={
                "category": "alerts",
                "title": f"Stopped Session Recording · {bot['name']}",
                "badge": "Stopped",
                "badge_tone": "slate",
                "summary": "Desktop session recording stopped.",
            },
            hop_count=1,
        )

    return {
        "status": "ok",
        "discarded": not req_body.save_skill,
        "recording": scrubbed_trace,
        "skill": saved_skill,
    }


@router.post("/desktops/{slug}/recording/save")
async def save_desktop_recording(
    request: Request,
    slug: str,
    body: DesktopRecordingSaveRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    llm_router, _ = _services(request)
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scrubbed_trace, saved_skill = await _compile_and_save_recorded_skill(
        repo=repo,
        bus=bus,
        llm_router=llm_router,
        bot=bot,
        raw_trace=body.recording or {},
        skill_name=body.skill_name,
        notes=body.notes,
    )
    return {
        "status": "ok",
        "discarded": False,
        "recording": scrubbed_trace,
        "skill": saved_skill,
    }


@router.get("/desktops/{slug}/selkies")
async def redirect_selkies_root(request: Request, slug: str) -> RedirectResponse:
    try:
        clean_slug = validate_desktop_slug(slug)
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    target = f"/api/desktops/{clean_slug}/selkies/"
    if request.url.query:
        target = f"{target}?{request.url.query}"
    return RedirectResponse(url=target, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.api_route(
    "/desktops/{slug}/selkies/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def proxy_selkies_desktop(
    request: Request,
    slug: str,
    subpath: str = "",
) -> Response:
    desktop_manager = request.app.state.desktop_manager
    try:
        req_body = await request.body() if request.method in {"POST", "PUT", "PATCH"} else None
        status_code, media_type, content, resp_headers = await desktop_manager.proxy_selkies_request(
            slug,
            subpath=subpath,
            query_string=request.url.query,
            method=request.method,
            body=req_body,
            headers=dict(request.headers),
        )
        return Response(
            content=content,
            status_code=status_code,
            media_type=media_type,
            headers=resp_headers,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DesktopConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DesktopStartupBlockedError, DesktopStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DesktopRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


async def _relay_selkies_websocket(websocket: WebSocket, slug: str, subpath: str) -> None:
    repo = websocket.app.state.repo
    desktop_manager = websocket.app.state.desktop_manager
    try:
        clean_slug = validate_desktop_slug(slug)
        if any(tok in subpath.lower() for tok in ("vnc", "novnc", "rfb", "5900", "6080")):
            await websocket.close(code=1008)
            return
        bot = repo.get_bot(clean_slug)
        if bot["runtime"] != "desktop":
            await websocket.close(code=1008)
            return
    except (NotFoundError, DesktopConfigError):
        await websocket.close(code=1008)
        return

    if not isinstance(desktop_manager.driver, DockerSdkDriver):
        if bot["desktop_state"] != "running":
            await websocket.close(code=1008)
            return
        await websocket.accept()
        desktop_manager.touch_activity(clean_slug)
        await websocket.send_text(
            json.dumps({"type": "selkies_fallback", "bot_slug": clean_slug})
        )
        await websocket.close()
        return

    try:
        import aiohttp  # type: ignore[import-not-found]
    except ImportError:
        await websocket.accept()
        await websocket.send_text(
            json.dumps({"type": "selkies_fallback", "bot_slug": clean_slug})
        )
        await websocket.close()
        return

    if bot["desktop_state"] != "running":
        try:
            await desktop_manager.start_desktop(clean_slug, reason="selkies_ws")
        except Exception:
            await websocket.close(code=1011)
            return

    clean_sub = subpath.lstrip("/")
    subfolder_prefix = f"/api/desktops/{clean_slug}/selkies"
    if clean_sub.startswith(subfolder_prefix.lstrip("/") + "/"):
        clean_sub = clean_sub[len(subfolder_prefix.lstrip("/") + "/") :]

    qs = f"?{websocket.url.query}" if websocket.url.query else ""
    primary_url = f"ws://argo-desktop-{clean_slug}:{SELKIES_HTTP_PORT}{subfolder_prefix}/{clean_sub}{qs}"
    fallback_url = f"ws://argo-desktop-{clean_slug}:{SELKIES_HTTP_PORT}/{clean_sub}{qs}"

    raw_proto = websocket.headers.get("sec-websocket-protocol", "")
    protocols = [p.strip() for p in raw_proto.split(",") if p.strip()]

    try:
        async with aiohttp.ClientSession() as session:
            upstream_ws = None
            for attempt_url in (primary_url, fallback_url):
                for retry in range(6):
                    try:
                        upstream_ws = await session.ws_connect(
                            attempt_url,
                            protocols=protocols or (),
                            heartbeat=20.0,
                            receive_timeout=3600.0,
                            max_msg_size=0,
                            timeout=15,
                        )
                        break
                    except aiohttp.WSServerHandshakeError:
                        upstream_ws = None
                        break
                    except (aiohttp.ClientConnectorError, TimeoutError, OSError):
                        upstream_ws = None
                        if retry < 5:
                            await asyncio.sleep(0.5)
                if upstream_ws is not None:
                    break

            if upstream_ws is None:
                await websocket.close(code=1011)
                return

            async with upstream_ws:
                await websocket.accept(subprotocol=upstream_ws.protocol)
                desktop_manager.touch_activity(clean_slug)

                async def _client_to_upstream() -> None:
                    while True:
                        msg = await websocket.receive()
                        if msg.get("type") == "websocket.disconnect":
                            break
                        desktop_manager.touch_activity(clean_slug)
                        if msg.get("text") is not None:
                            await upstream_ws.send_str(msg["text"])
                        elif msg.get("bytes") is not None:
                            await upstream_ws.send_bytes(msg["bytes"])

                async def _upstream_to_client() -> None:
                    async for frame in upstream_ws:
                        desktop_manager.touch_activity(clean_slug)
                        if frame.type == aiohttp.WSMsgType.TEXT:
                            await websocket.send_text(frame.data)
                        elif frame.type == aiohttp.WSMsgType.BINARY:
                            await websocket.send_bytes(frame.data)

                t1 = asyncio.create_task(_client_to_upstream())
                t2 = asyncio.create_task(_upstream_to_client())
                try:
                    _, pending = await asyncio.wait(
                        {t1, t2},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for task in pending:
                        task.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await task
                except WebSocketDisconnect:
                    for task in (t1, t2):
                        task.cancel()
    except Exception:
        with contextlib.suppress(Exception):
            await websocket.close(code=1011)


@router.websocket("/desktops/{slug}/selkies/ws")
async def selkies_websocket_default(websocket: WebSocket, slug: str) -> None:
    await _relay_selkies_websocket(websocket, slug, "ws")


@router.websocket("/desktops/{slug}/selkies/{subpath:path}")
async def selkies_websocket_subpath(websocket: WebSocket, slug: str, subpath: str) -> None:
    await _relay_selkies_websocket(websocket, slug, subpath)


@router.get("/integrations")
def list_integrations(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_integrations()


@router.post("/integrations", status_code=status.HTTP_201_CREATED)
def upsert_integration(
    request: Request,
    body: UpsertIntegrationRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.upsert_integration(
        slug=body.slug,
        provider=body.provider,
        display_name=body.display_name,
        account_identifier=body.account_identifier,
        scopes=body.scopes,
        secrets=body.secrets,
    )


@router.get("/integrations/google/wizard-config")
def get_google_wizard_config(request: Request) -> dict[str, Any]:
    google_service, _, _, _ = _connector_services(request)
    settings = request.app.state.settings
    return google_service.get_wizard_config(settings.public_base_url)


@router.post("/integrations/google/authorize")
def start_google_oauth(
    request: Request,
    body: StartGoogleOAuthRequest,
) -> dict[str, Any]:
    google_service, _, _, _ = _connector_services(request)
    settings = request.app.state.settings
    try:
        return google_service.start_authorization(
            public_base_url=settings.public_base_url,
            in_production_confirmed=body.in_production_confirmed,
            client_id=body.client_id,
            client_secret=body.client_secret,
            reuse_saved_client=body.reuse_saved_client,
            slug=body.slug,
            display_name=body.display_name,
            login_hint=body.login_hint,
            scope_groups=body.scope_groups,
            extra_scopes=body.extra_scopes,
        )
    except GoogleOAuthConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/integrations/google/callback")
async def google_oauth_redirect_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    google_service, _, _, _ = _connector_services(request)
    try:
        record = await google_service.complete_callback(
            code=code,
            state=state,
            error=error,
        )
        qs = urllib.parse.urlencode(
            {
                "view": "integrations",
                "oauth": "google_connected",
                "slug": record["slug"],
            }
        )
    except (GoogleOAuthConfigError, GoogleOAuthIntegrationError) as exc:
        qs = urllib.parse.urlencode(
            {
                "view": "integrations",
                "oauth": "google_error",
                "detail": str(exc)[:240],
            }
        )
    return RedirectResponse(url=f"/?{qs}", status_code=status.HTTP_302_FOUND)


@router.post("/integrations/google/callback", status_code=status.HTTP_201_CREATED)
async def google_oauth_complete_callback(
    request: Request,
    body: CompleteGoogleOAuthRequest,
) -> dict[str, Any]:
    google_service, _, _, _ = _connector_services(request)
    try:
        return await google_service.complete_callback(
            code=body.code,
            state=body.state,
        )
    except GoogleOAuthConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GoogleOAuthIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/linkedin/onboard", status_code=status.HTTP_201_CREATED)
async def onboard_linkedin(
    request: Request,
    body: OnboardLinkedInRequest,
) -> dict[str, Any]:
    _, linkedin_service, _, _ = _connector_services(request)
    try:
        return await linkedin_service.onboard_account(
            access_token=body.access_token,
            author_urn=body.author_urn,
            linkedin_version=body.linkedin_version,
            slug=body.slug,
            display_name=body.display_name,
        )
    except LinkedInConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LinkedInIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/linkedin/{slug}/posts", status_code=status.HTTP_201_CREATED)
async def publish_linkedin_post(
    request: Request,
    slug: str,
    body: PublishLinkedInPostRequest,
) -> dict[str, Any]:
    _, linkedin_service, _, _ = _connector_services(request)
    try:
        return await linkedin_service.publish_post(
            slug,
            commentary=body.commentary,
            visibility=body.visibility,
            article_url=body.article_url,
            article_title=body.article_title,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except LinkedInConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LinkedInIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/webhook/onboard", status_code=status.HTTP_201_CREATED)
async def onboard_webhook(
    request: Request,
    body: OnboardWebhookRequest,
) -> dict[str, Any]:
    _, _, webhook_service, _ = _connector_services(request)
    try:
        return await webhook_service.onboard_webhook(
            display_name=body.display_name,
            slug=body.slug,
            signing_secret=body.signing_secret,
            event_type=body.event_type,
            target_collection=body.target_collection,
        )
    except WebhookConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/integrations/telegram/onboard", status_code=status.HTTP_201_CREATED)
async def onboard_telegram_bot(
    request: Request,
    body: OnboardTelegramRequest,
) -> dict[str, Any]:
    _, telegram_service = _services(request)
    settings = request.app.state.settings
    try:
        return await telegram_service.onboard_bot(
            bot_token=body.bot_token,
            slug=body.slug,
            display_name=body.display_name,
            operator_chat_id=body.operator_chat_id,
            admin_channels=body.admin_channels,
            public_channels=body.public_channels,
            register_webhook=body.register_webhook,
            public_base_url=settings.public_base_url,
        )
    except TelegramConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TelegramIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/telegram/public-monitor", status_code=status.HTTP_201_CREATED)
async def onboard_telegram_public_monitor(
    request: Request,
    body: OnboardTelegramPublicMonitorRequest,
) -> dict[str, Any]:
    _, telegram_service = _services(request)
    try:
        return await telegram_service.onboard_public_monitor(
            channel_handle=body.channel_handle,
            slug=body.slug,
            display_name=body.display_name,
            sync_immediately=body.sync_immediately,
        )
    except (TelegramConfigError, SSRFBlockedError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, TelegramIntegrationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/probe-all")
async def probe_all_integrations(request: Request) -> dict[str, Any]:
    _, _, _, connector_manager = _connector_services(request)
    return await connector_manager.probe_all_integrations()


@router.post("/integrations/{slug}/sync")
async def sync_telegram_integration(
    request: Request,
    slug: str,
    body: SyncTelegramPublicRequest | None = None,
) -> dict[str, Any]:
    _, telegram_service = _services(request)
    req_body = body or SyncTelegramPublicRequest()
    try:
        return await telegram_service.sync_public_channels(
            slug,
            limit_per_channel=req_body.limit_per_channel,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (TelegramConfigError, SSRFBlockedError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, TelegramIntegrationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/{slug}/test")
async def test_integration(
    request: Request,
    slug: str,
    body: ProbeIntegrationRequest | None = None,
) -> dict[str, Any]:
    _, _, _, connector_manager = _connector_services(request)
    req_body = body or ProbeIntegrationRequest()
    try:
        return await connector_manager.probe_integration(
            slug,
            send_test_message=req_body.send_test_message,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (
        TelegramConfigError,
        GoogleOAuthConfigError,
        LinkedInConfigError,
        WebhookConfigError,
    ) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (
        TelegramIntegrationError,
        GoogleOAuthIntegrationError,
        LinkedInIntegrationError,
    ) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.delete("/integrations/{slug}")
def delete_integration(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_integration(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/vault")
def list_vault_secrets(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_vault_secrets()


@router.post("/vault", status_code=status.HTTP_201_CREATED)
def upsert_vault_secret(request: Request, body: VaultSecretUpsertRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.upsert_vault_secret(
            name=body.name,
            slug=body.slug,
            secret_type=body.secret_type,
            host=body.host,
            port=body.port,
            url=body.url,
            secrets=body.secrets,
            allowed_bots=body.allowed_bots,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/vault/{slug}")
def update_vault_secret(
    request: Request,
    slug: str,
    body: VaultSecretUpdateRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    existing = repo.get_vault_secret_decrypted(slug)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Vault secret '{slug}' not found.")
    return repo.upsert_vault_secret(
        name=body.name or existing["name"],
        slug=existing["slug"],
        secret_type=body.secret_type or existing["secret_type"],
        host=body.host if body.host is not None else existing["host"],
        port=body.port if body.port is not None else existing["port"],
        url=body.url if body.url is not None else existing["url"],
        secrets=body.secrets,
        allowed_bots=body.allowed_bots if body.allowed_bots is not None else existing["allowed_bots"],
    )


@router.delete("/vault/{slug}")
def delete_vault_secret(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_vault_secret(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/models")
def list_models(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.list_models()


@router.post("/models", status_code=status.HTTP_201_CREATED)
def upsert_model(request: Request, body: UpsertModelRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    return repo.upsert_model(
        slug=body.slug,
        provider_type=body.provider_type,
        model_id=body.model_id,
        api_base=body.api_base,
        api_key=body.api_key,
        is_default=body.is_default,
        daily_token_limit=body.daily_token_limit,
        monthly_budget_usd=body.monthly_budget_usd,
    )


@router.post("/models/{slug}/default")
def set_default_model(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.set_default_model(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/models/{slug}/test")
async def test_model(
    request: Request,
    slug: str,
    body: TestModelRequest | None = None,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    llm_router, _ = _services(request)
    provider = repo.get_model_provider_credentials(slug)
    if provider is None:
        raise HTTPException(status_code=404, detail=f"Model provider '{slug}' not found.")

    req_body = body or TestModelRequest()
    corr_id = make_id("corr")
    try:
        result = await llm_router.complete(
            bot_slug="models-router",
            prompt=req_body.prompt,
            requested_model=provider["slug"],
            system_prompt="Confirm operational readiness concisely.",
            trigger_type="model_test",
            correlation_id=corr_id,
            hop_count=1,
            strict_provider=True,
        )
    except ModelConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except LLMExecutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    await bus.publish(
        correlation_id=corr_id,
        source_slug="models-router",
        target_slug=provider["slug"],
        event_type="model.tested",
        payload={
            "category": "alerts",
            "title": f"Model Route Verified: {result.model_used}",
            "badge": f"{result.latency_ms} ms",
            "badge_tone": "emerald",
            "summary": result.output_text[:240],
            "meta": (
                f"{result.input_tokens + result.output_tokens} tok · "
                f"${result.estimated_cost_usd:.4f}"
            ),
        },
        hop_count=1,
    )
    return {
        "status": "ok",
        "model_id": result.model_used,
        "latency_ms": result.latency_ms,
        "output_text": result.output_text,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "estimated_cost_usd": result.estimated_cost_usd,
        "run": result.run_record,
    }


@router.delete("/models/{slug}")
def delete_model(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        repo.delete_model(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/scheduler/jobs")
def list_scheduler_jobs(request: Request) -> list[dict[str, Any]]:
    scheduler = getattr(request.app.state, "bot_scheduler", None)
    return scheduler.list_scheduled_jobs() if scheduler is not None else []


@router.post("/tools/fetch-rss")
async def tool_fetch_rss(request: Request, body: FetchRssRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    fetcher = getattr(request.app.state, "public_http_fetcher", None)
    try:
        return await fetch_rss_feed(
            body.url,
            repo=repo,
            bus=bus,
            fetcher=fetcher,
            limit=body.limit,
        )
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/tools/fetch-webpage")
async def tool_fetch_webpage(request: Request, body: FetchWebpageRequest) -> dict[str, Any]:
    _, bus, _, _ = _deps(request)
    fetcher = getattr(request.app.state, "public_http_fetcher", None)
    try:
        return await fetch_public_webpage(
            body.url,
            bus=bus,
            fetcher=fetcher,
            max_chars=body.max_chars,
        )
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/watchdog/evaluate")
async def evaluate_watchdog(request: Request) -> dict[str, Any]:
    repo, bus, guard, _ = _deps(request)
    _, telegram_service = _services(request)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    return await guard.evaluate_and_enforce(
        repo=repo,
        bus=bus,
        telegram=telegram_service,
        desktop_manager=desktop_manager,
        force_notify=True,
    )


@router.get("/debug/overview")
def debug_overview(
    request: Request,
    bot_slug: str | None = Query(default=None),
    level: str | None = Query(default=None),
    contains: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    debug_buffer = getattr(request.app.state, "debug_buffer", None)
    raw_traces = repo.search_documents(
        "debug_run_traces",
        query=contains if contains and not bot_slug else None,
        limit=min(limit, 150),
    )
    traces: list[dict[str, Any]] = []
    needle = (contains or "").strip().lower()
    for row in raw_traces:
        doc = row.get("doc") or {}
        if bot_slug and doc.get("bot_slug") != bot_slug:
            continue
        if needle and needle not in json.dumps(doc, ensure_ascii=False).lower():
            continue
        traces.append({"id": row["id"], **doc})

    logs = (
        debug_buffer.list_logs(limit=limit, level=level, contains=contains)
        if debug_buffer is not None
        else []
    )
    return {
        "traces": traces,
        "logs": logs,
        "integrations": repo.list_integrations(),
        "counts": repo.workspace_counts(),
    }


@router.post("/debug/clear")
def clear_debug_data(request: Request) -> dict[str, int]:
    repo, _, _, _ = _deps(request)
    debug_buffer = getattr(request.app.state, "debug_buffer", None)
    cleared_logs = debug_buffer.clear() if debug_buffer is not None else 0
    cleared_traces = repo.delete_collection("debug_run_traces")
    return {"cleared_logs": cleared_logs, "cleared_traces": cleared_traces}


# ------------------------------------------------------------------
# Per-User Unread Cursors, Message Reactions & Delegation Plans
# ------------------------------------------------------------------
@router.post("/threads/read")
def mark_thread_read_endpoint(
    request: Request,
    body: MarkThreadReadRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    return repo.mark_thread_read(
        user_email=principal["email"],
        target_type=body.target_type,
        slug=body.slug,
    )


@router.post("/messages/{message_id}/reactions")
def toggle_message_reaction_endpoint(
    request: Request,
    message_id: str,
    body: ToggleMessageReactionRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        return repo.toggle_message_reaction(
            collection=body.collection,
            message_id=message_id,
            emoji=body.emoji,
            actor=principal["email"],
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/bots/{slug}/plans/{plan_id}/execute")
async def execute_bot_delegation_plan(
    request: Request,
    slug: str,
    plan_id: str,
    body: ExecuteDelegationPlanRequest | None = None,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    bot_runner = request.app.state.bot_runner
    req_body = body or ExecuteDelegationPlanRequest()
    try:
        plan = repo.get_delegation_plan(plan_id)
        if plan.get("coordinator_slug") and slugify(slug) != slugify(str(plan["coordinator_slug"])):
            raise HTTPException(status_code=400, detail="Plan does not belong to this coordinator bot.")
        return await bot_runner.execute_delegation_plan(
            plan_id,
            operator_email=principal["email"],
            edited_steps=req_body.edited_steps,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@router.post("/rooms/{slug}/plans/{plan_id}/execute")
async def execute_room_delegation_plan(
    request: Request,
    slug: str,
    plan_id: str,
    body: ExecuteDelegationPlanRequest | None = None,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    bot_runner = request.app.state.bot_runner
    req_body = body or ExecuteDelegationPlanRequest()
    try:
        room = repo.get_room(slug)
        plan = repo.get_delegation_plan(plan_id)
        if plan.get("room_slug") and slugify(str(plan["room_slug"])) != room["slug"]:
            raise HTTPException(status_code=400, detail="Plan does not belong to this room.")
        return await bot_runner.execute_delegation_plan(
            plan_id,
            operator_email=principal["email"],
            edited_steps=req_body.edited_steps,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


# ------------------------------------------------------------------
# Multi-Bot Group Chat Rooms
# ------------------------------------------------------------------
@router.get("/rooms")
def list_rooms_endpoint(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_rooms()


@router.post("/rooms", status_code=status.HTTP_201_CREATED)
async def create_room_endpoint(
    request: Request,
    body: CreateRoomRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    try:
        room = repo.create_room(
            title=body.title,
            member_bot_slugs=body.member_bot_slugs,
            coordinator_bot_slug=body.coordinator_bot_slug,
            stage_order=body.stage_order,
            routing_mode=body.routing_mode,
            ask_before_bot_handoff=body.ask_before_bot_handoff,
            max_bot_turns_per_message=body.max_bot_turns_per_message,
            pinned_page_slug=body.pinned_page_slug,
            pinned=body.pinned,
            section=body.section,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug="system",
        target_slug=room["slug"],
        event_type="room.created",
        payload={
            "category": "alerts",
            "title": f"Created Team Room: {room['title']}",
            "badge": f"{len(room['member_bot_slugs'])} Bots",
            "badge_tone": "indigo",
            "summary": f"Members: {', '.join(room['member_bot_slugs'])}",
        },
        hop_count=1,
    )
    return room


@router.get("/rooms/{slug}")
def get_room_endpoint(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.get_room(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/rooms/{slug}")
def update_room_endpoint(
    request: Request,
    slug: str,
    body: UpdateRoomRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        return repo.update_room(slug, body.model_dump(exclude_none=True))
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/rooms/{slug}")
async def delete_room_endpoint(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    bot_runner = getattr(request.app.state, "bot_runner", None)
    if bot_runner is not None and hasattr(bot_runner, "cancel_thread_runs"):
        with contextlib.suppress(Exception):
            await bot_runner.cancel_thread_runs(f"room:{slugify(slug)}")
    try:
        repo.delete_room(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/rooms/{slug}/messages")
def list_room_messages_endpoint(
    request: Request,
    response: Response,
    slug: str,
    limit: int = Query(default=40, ge=1, le=200),
    before_id: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        repo.get_room(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    messages, has_more, total_count = repo.list_room_messages_window(
        slug, limit=limit, before_id=before_id
    )
    if before_id is None:
        repo.mark_thread_read(user_email=principal["email"], target_type="room", slug=slug)
    response.headers["X-Has-More"] = "true" if has_more else "false"
    response.headers["X-Total-Count"] = str(total_count)
    return messages


@router.post("/rooms/{slug}/messages")
async def post_room_message_endpoint(
    request: Request,
    slug: str,
    body: AppendRoomMessageRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    bot_runner = request.app.state.bot_runner
    if (
        not body.text.strip()
        and not body.attachment_ids
        and not body.approved_handoff_bot_slug
    ):
        raise HTTPException(
            status_code=400,
            detail="Room message text, attachment, or handoff target is required.",
        )

    if body.async_mode:
        try:
            room = repo.get_room(slug)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
        member_order = list(room.get("stage_order") or room["member_bot_slugs"])
        lead_slug = str(room.get("coordinator_bot_slug") or member_order[0])
        lead_bot = bots_by_slug.get(lead_slug) or next(
            (bots_by_slug[s] for s in member_order if s in bots_by_slug),
            None,
        )
        if lead_bot is None:
            raise HTTPException(status_code=400, detail=f"Room '{room['slug']}' has no active bots.")

        attachments_meta: list[dict[str, Any]] = []
        for fid in body.attachment_ids:
            try:
                fmeta, _ = repo.get_workspace_file(fid, owner_email=principal["email"])
                attachments_meta.append(
                    {
                        "id": fmeta["id"],
                        "filename": fmeta["filename"],
                        "mime_type": fmeta["mime_type"],
                        "size_bytes": fmeta["size_bytes"],
                        "is_image": fmeta["is_image"],
                    }
                )
            except NotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc

        clean_text = body.text.strip()
        user_msg: dict[str, Any] | None = None
        if not body.approved_handoff_bot_slug and (clean_text or attachments_meta):
            user_meta: dict[str, Any] = {}
            if attachments_meta:
                user_meta["attachments"] = attachments_meta
            if body.skill_slugs:
                user_meta["skill_slugs"] = list(body.skill_slugs)
            if body.target_page_slug:
                user_meta["target_page_slug"] = body.target_page_slug
            user_msg = repo.append_room_message(
                room["slug"],
                sender_type="user",
                sender_slug="user",
                sender_name="You",
                text=clean_text,
                metadata=user_meta,
                reply_to_id=body.reply_to_id,
            )
            repo.mark_thread_read(user_email=principal["email"], target_type="room", slug=room["slug"])

        corr_id = make_id("roomturn")

        async def _run_async_room_turn(run_item: Any) -> dict[str, Any]:
            result = await bot_runner.execute_room_turn(
                room["slug"],
                user_text=body.text,
                operator_email=principal["email"],
                reply_to_id=body.reply_to_id,
                attachment_ids=body.attachment_ids,
                skill_slugs=body.skill_slugs,
                target_page_slug=body.target_page_slug,
                approved_handoff_bot_slug=body.approved_handoff_bot_slug,
                run_item=run_item,
                precreated_user_message=user_msg,
            )
            if not run_item.cancel_event.is_set() and result.get("status") != "cancelled":
                await bus.publish(
                    correlation_id=corr_id,
                    source_slug="operator",
                    target_slug=room["slug"],
                    event_type="room.message",
                    payload={
                        "category": "reviews",
                        "title": f"Room Turn -> {room['slug']}",
                        "badge": f"{len(result.get('results') or [])} Reply",
                        "badge_tone": "indigo",
                        "summary": (body.text or f"Approved handoff to {body.approved_handoff_bot_slug}")[:240],
                    },
                    hop_count=1,
                )
            return result

        item, queued_behind = bot_runner.enqueue_thread_turn(
            thread_key=f"room:{room['slug']}",
            target_type="room",
            target_slug=room["slug"],
            correlation_id=corr_id,
            bot_slug=lead_bot["slug"],
            bot_name=lead_bot["name"],
            work=_run_async_room_turn,
        )
        if queued_behind > 0:
            await bus.emit_ephemeral(
                "turn_stream",
                {
                    "type": "run_queued",
                    "run_id": item.run_id,
                    "thread_key": item.thread_key,
                    "target_type": "room",
                    "target_slug": room["slug"],
                    "queued_behind": queued_behind,
                },
            )
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "queued",
                "run_id": item.run_id,
                "user_message": user_msg,
                "queued_behind": queued_behind,
            },
        )

    try:
        result = await bot_runner.execute_room_turn(
            slug,
            user_text=body.text,
            operator_email=principal["email"],
            reply_to_id=body.reply_to_id,
            attachment_ids=body.attachment_ids,
            skill_slugs=body.skill_slugs,
            target_page_slug=body.target_page_slug,
            approved_handoff_bot_slug=body.approved_handoff_bot_slug,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, ModelConfigurationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except BudgetExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, LLMExecutionError, DesktopRuntimeError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    await bus.publish(
        correlation_id=make_id("room"),
        source_slug="operator",
        target_slug=slug,
        event_type="room.message",
        payload={
            "category": "reviews",
            "title": f"Room Turn -> {slug}",
            "badge": f"{len(result.get('results') or [])} Reply",
            "badge_tone": "indigo",
            "summary": (body.text or f"Approved handoff to {body.approved_handoff_bot_slug}")[:240],
        },
        hop_count=1,
    )
    return result


# ------------------------------------------------------------------
# Per-User Shared Workspace Files (Strict SSO Owner Isolation, 10 MB Cap)
# ------------------------------------------------------------------
@router.get("/files")
def list_workspace_files_endpoint(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    return repo.list_workspace_files(principal["email"])


@router.post("/files", status_code=status.HTTP_201_CREATED)
async def upload_workspace_file_endpoint(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    content_type = (request.headers.get("content-type") or "").lower()

    if "application/json" in content_type:
        try:
            raw_json = await request.json()
            parsed = UploadWorkspaceFileJsonRequest.model_validate(raw_json)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid file upload payload: {exc}") from exc
        if parsed.content_base64 is not None:
            try:
                content_bytes = base64.b64decode(parsed.content_base64, validate=True)
            except Exception as exc:
                raise HTTPException(status_code=400, detail="Invalid base64 content.") from exc
        elif parsed.text is not None:
            content_bytes = parsed.text.encode("utf-8")
        else:
            raise HTTPException(status_code=400, detail="Provide either content_base64 or text.")
        filename = parsed.filename
        mime_type = parsed.mime_type
    else:
        buf = bytearray()
        async for chunk in request.stream():
            if len(buf) + len(chunk) > MAX_WORKSPACE_FILE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail="File exceeds 10 MB per-file upload limit.",
                )
            buf.extend(chunk)
        content_bytes = bytes(buf)
        raw_name = (
            request.headers.get("x-file-name")
            or request.query_params.get("filename")
            or "attachment.bin"
        )
        filename = urllib.parse.unquote(raw_name).strip() or "attachment.bin"
        mime_type = content_type.split(";", 1)[0].strip() or "application/octet-stream"

    try:
        return repo.save_workspace_file(
            owner_email=principal["email"],
            filename=filename,
            mime_type=mime_type,
            content_bytes=content_bytes,
            uploaded_by="user",
        )
    except FileTooLargeError as exc:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/files/{file_id}/content")
def download_workspace_file_endpoint(
    request: Request,
    file_id: str,
    download: bool = Query(default=False),
) -> Response:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        meta, fpath = repo.get_workspace_file(file_id, owner_email=principal["email"])
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raw_bytes = fpath.read_bytes()
    mime = str(meta.get("mime_type") or "application/octet-stream")
    disposition = "attachment" if (download or mime in {"text/html", "image/svg+xml"}) else "inline"
    raw_filename = str(meta.get("filename") or "download").strip() or "download"
    ascii_name = re.sub(r"[^A-Za-z0-9._ -]", "_", raw_filename).strip() or "download"
    quoted_name = urllib.parse.quote(raw_filename, safe="")
    return Response(
        content=raw_bytes,
        media_type=mime,
        headers={
            "Content-Disposition": (
                f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted_name}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.delete("/files/{file_id}")
def delete_workspace_file_endpoint(request: Request, file_id: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        repo.delete_workspace_file(file_id, owner_email=principal["email"])
        return {"status": "deleted", "id": file_id}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ------------------------------------------------------------------
# Credential-Free Multi-Bot Team Packs
# ------------------------------------------------------------------
@router.get("/team-packs/starters")
def list_starter_team_packs_endpoint(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    return repo.list_starter_team_packs()


@router.get("/team-packs/export")
def export_team_pack_endpoint(
    request: Request,
    section: str | None = Query(default=None),
    room_slug: str | None = Query(default=None),
    bot_slugs: str | None = Query(default=None),
    title: str | None = Query(default=None),
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    parsed_bots = [s.strip() for s in (bot_slugs or "").split(",") if s.strip()] or None
    parsed_rooms = [room_slug.strip()] if room_slug and room_slug.strip() else None
    try:
        return repo.export_team_pack(
            bot_slugs=parsed_bots,
            room_slugs=parsed_rooms,
            section=section,
            title=title,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/team-packs/import", status_code=status.HTTP_201_CREATED)
async def import_team_pack_endpoint(
    request: Request,
    body: ImportTeamPackRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    try:
        imported = repo.import_team_pack(
            body.pack,
            linked_accounts=body.linked_accounts or None,
            section_override=body.section_override,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scheduler = getattr(request.app.state, "bot_scheduler", None)
    if scheduler is not None:
        scheduler.sync_bots()

    pack_title = str(body.pack.get("title") or "Argo Team Pack")
    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug="system",
        target_slug="team-pack",
        event_type="team_pack.imported",
        payload={
            "category": "alerts",
            "title": f"Imported Team Pack: {pack_title}",
            "badge": f"{len(imported['bots'])} Bots · {len(imported['rooms'])} Rooms",
            "badge_tone": "emerald",
            "summary": f"Bots: {', '.join(b['slug'] for b in imported['bots'])}",
        },
        hop_count=1,
    )
    return imported


@hooks_router.post("/telegram/{slug}")
async def telegram_webhook(
    request: Request,
    slug: str,
    x_telegram_bot_api_secret_token: str | None = Header(
        default=None, alias="X-Telegram-Bot-Api-Secret-Token"
    ),
) -> dict[str, Any]:
    _, telegram_service = _services(request)
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON webhook payload.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object.")

    try:
        return await telegram_service.handle_webhook(
            slug,
            secret_header=x_telegram_bot_api_secret_token,
            payload=payload,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@hooks_router.post("/webhook/{slug}")
async def signed_webhook(
    request: Request,
    slug: str,
    x_argo_signature_256: str | None = Header(default=None, alias="X-Argo-Signature-256"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_argo_delivery: str | None = Header(default=None, alias="X-Argo-Delivery"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
) -> dict[str, Any]:
    _, _, webhook_service, _ = _connector_services(request)
    raw_body = await request.body()
    signature = x_argo_signature_256 or x_hub_signature_256
    delivery_id = x_argo_delivery or x_github_delivery or x_request_id
    try:
        return await webhook_service.handle_inbound(
            slug,
            raw_body=raw_body,
            signature_header=signature,
            delivery_id=delivery_id,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except WebhookSignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except WebhookConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
