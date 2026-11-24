"""REST and SSE endpoints for the Argo 3-pane workspace."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import re
import sqlite3
import tempfile
import urllib.parse
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse

from argo_core import __commit__, __version__
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
from argo_core.connectors.mcp_client import MCPClientError, MCPConfigError
from argo_core.connectors.telegram_bot import (
    TelegramBotService,
    TelegramConfigError,
    TelegramIntegrationError,
)
from argo_core.connectors.webhooks import (
    MAX_WEBHOOK_BODY_BYTES,
    WebhookConfigError,
    WebhookService,
    WebhookSignatureError,
)
from argo_core.db.repositories import (
    _INTERNAL_SYSTEM_COLLECTIONS,
    MAX_ANALYTICS_UPLOAD_BYTES,
    MAX_WORKSPACE_FILE_BYTES,
    AlreadyResolvedError,
    ArgoRepository,
    FileTooLargeError,
    NotFoundError,
    collection_slug,
    make_id,
    max_workspace_file_bytes_for_name,
    slugify,
    utc_now,
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
from argo_core.sandbox.manager import (
    SandboxConfigError,
    SandboxRuntimeError,
    SandboxStartupBlockedError,
    validate_sandbox_slug,
)
from argo_core.llm.router import (
    BudgetExceededError,
    LLMExecutionError,
    LLMRouter,
    ModelConfigurationError,
    discover_provider_models,
)
from argo_core.models import (
    AdminCreateUserRequest,
    AdminResetPasswordRequest,
    AdminUpdateUserRequest,
    AppendBotMessageRequest,
    AppendRoomMessageRequest,
    AuthBootstrapRequest,
    AuthChangePasswordRequest,
    AuthLoginRequest,
    BatchResolveApprovalRequest,
    ChatRetentionSettingsUpdateRequest,
    CompleteGoogleOAuthRequest,
    CreateApprovalRequest,
    CreateBotRequest,
    CreatePageRequest,
    CreateRoomRequest,
    CreateSkillRequest,
    CreateStyleRuleRequest,
    CreateTeamGroupRequest,
    DesktopActionRequest,
    DesktopBrowseRequest,
    DesktopRecordingSaveRequest,
    DesktopRecordingStopRequest,
    DiscoverModelsRequest,
    DispatchActivityRequest,
    DraftBotSpecRequest,
    EditLastMessageRequest,
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
    PageSqlQueryRequest,
    ProbeIntegrationRequest,
    PublishLinkedInPostRequest,
    ResolveApprovalRequest,
    SSHAuditSettingsUpdateRequest,
    SSHSessionControlRequest,
    StartGoogleOAuthRequest,
    SyncTelegramPublicRequest,
    TestModelRequest,
    ToggleMessageReactionRequest,
    TriggerBotRequest,
    UpdateBotRequest,
    UpdatePageRequest,
    UpdateRoomRequest,
    UpdateTeamGroupRequest,
    UploadWorkspaceFileJsonRequest,
    UpsertDocumentRequest,
    UpsertIntegrationRequest,
    UpsertModelRequest,
    VaultBulkSSHRequest,
    VaultResetHostKeyRequest,
    VaultSecretUpdateRequest,
    VaultSecretUpsertRequest,
)
from argo_core.security.auth import (
    OAUTH_NONCE_COOKIE_NAME,
    OAUTH_STATE_TTL_SECONDS,
    SESSION_COOKIE_NAME,
    GoogleAuthLoginError,
    clear_session_cookie,
    generate_session_token,
    hash_password,
    hash_token,
    is_https_public_url,
    needs_initial_setup,
    set_session_cookie,
    validate_password_strength,
    verify_password,
)
from argo_core.security.ssrf import AntiBotHaltError, PublicFetchError, SSRFBlockedError
from argo_core.ssh.host_guard import SSHTargetBlockedError, validate_ssh_target_not_self
from argo_core.ssh.recorder import read_cast_ndjson
from argo_core.security.sso import extract_sso_principal, normalize_peer_ip
from argo_core.security.tenancy import (
    can_manage_resource,
    can_read_resource,
    default_visibility_for_new,
    enrich_principal,
    is_auth_rbac_active,
    is_multi_user_enabled,
    is_scope_subset,
    is_workspace_admin,
    normalize_email,
    normalize_group_slugs,
    normalize_visibility,
    user_group_slugs,
)
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


def _res_owner(resource: dict[str, Any]) -> str:
    return str(resource.get("owner_email") or resource.get("created_by_email") or "")


def _caller(request: Any) -> tuple[Any, dict[str, Any], str, bool, bool]:
    app_state = getattr(request.app, "state", None)
    settings = getattr(app_state, "settings", None)
    repo = getattr(app_state, "repo", None)
    principal = extract_sso_principal(request)
    multi_user = is_multi_user_enabled(settings)
    caller_email = normalize_email(principal.get("email"))
    admin = is_workspace_admin(caller_email, settings, repo=repo)
    return settings, principal, caller_email, multi_user, admin


def _require_admin(request: Any) -> tuple[Any, dict[str, Any], str]:
    settings, principal, caller_email, _, admin = _caller(request)
    if is_auth_rbac_active(settings) and not admin:
        raise HTTPException(
            status_code=403,
            detail="Workspace admin privileges are required for this action.",
        )
    return settings, principal, caller_email


def _require_writer_identity(request: Any) -> tuple[Any, dict[str, Any], str]:
    settings, principal, caller_email, multi_user, _ = _caller(request)
    if (multi_user or is_auth_rbac_active(settings)) and not caller_email:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user email identity is required.",
        )
    return settings, principal, caller_email


def _require_resource_read(request: Any, resource: dict[str, Any], *, kind: str = "Resource") -> None:
    settings, _, caller_email, multi_user, _ = _caller(request)
    if not multi_user:
        return
    repo = getattr(getattr(request.app, "state", None), "repo", None)
    if not can_read_resource(
        caller_email,
        owner_email=_res_owner(resource),
        visibility=resource.get("visibility"),
        allowed_groups=resource.get("allowed_groups"),
        settings=settings,
        repo=repo,
    ):
        raise HTTPException(status_code=403, detail=f"{kind} is private to another user or team.")


def _require_resource_manage(request: Any, resource: dict[str, Any], *, kind: str = "Resource") -> None:
    settings, _, caller_email, multi_user, _ = _caller(request)
    if not multi_user:
        return
    repo = getattr(getattr(request.app, "state", None), "repo", None)
    if not can_manage_resource(
        caller_email,
        owner_email=_res_owner(resource),
        visibility=resource.get("visibility"),
        settings=settings,
        repo=repo,
    ):
        raise HTTPException(
            status_code=403,
            detail=f"Only the owner or workspace admin may modify this {kind.lower()}.",
        )


def _validate_visibility_and_groups(
    request: Any,
    repo: ArgoRepository,
    *,
    visibility: str | None,
    allowed_groups: list[str] | None,
    existing: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    settings, _, caller_email, _, admin = _caller(request)
    if visibility is not None:
        vis = normalize_visibility(visibility)
    elif existing is not None:
        vis = normalize_visibility(existing.get("visibility"), default="shared")
    else:
        vis = default_visibility_for_new(settings, None)

    if vis != "team":
        return vis, []

    if allowed_groups is not None:
        cand_groups = normalize_group_slugs(allowed_groups)
    elif existing is not None:
        cand_groups = normalize_group_slugs(existing.get("allowed_groups") or [])
    else:
        cand_groups = []

    if not cand_groups:
        raise HTTPException(
            status_code=400,
            detail="Select at least one Team Group when visibility is set to 'team'.",
        )
    known_slugs = {g["slug"] for g in repo.list_team_groups()}
    unknown = [g for g in cand_groups if g not in known_slugs]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown Team Group(s): {', '.join(unknown)}.",
        )
    if is_multi_user_enabled(settings) and not admin:
        my_groups = user_group_slugs(caller_email, repo=repo)
        unauthorized = [g for g in cand_groups if g not in my_groups]
        if unauthorized:
            raise HTTPException(
                status_code=403,
                detail=f"You must belong to Team Group '{unauthorized[0]}' to share resources with it.",
            )
    return vis, cand_groups


def _require_bot_read(request: Any, repo: ArgoRepository, slug: str) -> dict[str, Any]:
    bot = repo.get_bot(slug)
    _require_resource_read(request, bot, kind="Bot")
    return bot


def _require_bot_manage(request: Any, repo: ArgoRepository, slug: str) -> dict[str, Any]:
    bot = repo.get_bot(slug)
    _require_resource_manage(request, bot, kind="Bot")
    return bot


def _visible_slug_sets(
    request: Any,
    repo: ArgoRepository,
) -> tuple[set[str] | None, set[str] | None, set[str] | None, set[str] | None, set[str] | None]:
    settings, _, caller_email, multi_user, admin = _caller(request)
    if not multi_user or admin:
        return None, None, None, None, None
    caller_groups = user_group_slugs(caller_email, repo=repo)
    bots = repo.list_bots()
    vis_bots = {
        b["slug"]
        for b in bots
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(b),
            visibility=b.get("visibility"),
            allowed_groups=b.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    }
    mgr_bots = {
        b["slug"]
        for b in bots
        if can_manage_resource(
            caller_email,
            owner_email=_res_owner(b),
            visibility=b.get("visibility"),
            settings=settings,
            repo=repo,
        )
    }
    vis_rooms = {
        r["slug"]
        for r in repo.list_rooms()
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(r),
            visibility=r.get("visibility"),
            allowed_groups=r.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    }
    vis_pages = {
        p["slug"]
        for p in repo.list_pages()
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(p),
            visibility=p.get("visibility"),
            allowed_groups=p.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    }
    vis_ints = {
        i["slug"]
        for i in repo.list_integrations()
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(i),
            visibility=i.get("visibility"),
            allowed_groups=i.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    }
    return vis_bots, mgr_bots, vis_rooms, vis_pages, vis_ints


def _validate_bot_linked_accounts(
    request: Any,
    repo: ArgoRepository,
    *,
    linked_accounts: list[str] | None,
    tools: list[Any] | None,
    visibility: str,
    allowed_groups: list[str] | None = None,
) -> None:
    settings, _, caller_email, multi_user, _ = _caller(request)
    if not multi_user:
        return
    req_slugs: list[str] = []
    for a in (linked_accounts or []):
        s = slugify(str(a or ""))
        if s and s not in req_slugs:
            req_slugs.append(s)
    for t in (tools or []):
        if isinstance(t, dict) and t.get("type") in {"account", "connector"}:
            s = slugify(str(t.get("slug") or t.get("account") or ""))
            if s and s not in req_slugs:
                req_slugs.append(s)
    if not req_slugs:
        return
    by_slug = {i["slug"]: i for i in repo.list_integrations()}
    for acc_slug in req_slugs:
        acc = by_slug.get(acc_slug)
        if acc is None:
            continue
        _require_resource_read(request, acc, kind="Integration")
        if not is_scope_subset(
            visibility,
            allowed_groups,
            acc.get("visibility"),
            acc.get("allowed_groups"),
            child_owner=caller_email,
            parent_owner=_res_owner(acc),
            settings=settings,
            repo=repo,
        ):
            raise HTTPException(
                status_code=403,
                detail=f"Bot scope ({visibility}) cannot link narrower integration '{acc_slug}'.",
            )


def _require_integration_slug_writable(
    request: Any,
    repo: ArgoRepository,
    raw_slug: str | None,
) -> dict[str, Any] | None:
    if not raw_slug or not str(raw_slug).strip():
        return None
    clean_slug = slugify(str(raw_slug))
    existing = next((i for i in repo.list_integrations() if i["slug"] == clean_slug), None)
    if existing is not None:
        _require_resource_manage(request, existing, kind="Integration")
    return existing


def _require_vault_slug_writable(
    request: Any,
    repo: ArgoRepository,
    raw_slug: str | None,
) -> dict[str, Any] | None:
    if not raw_slug or not str(raw_slug).strip():
        return None
    clean_slug = slugify(str(raw_slug))
    existing = next((v for v in repo.list_vault_secrets() if v["slug"] == clean_slug), None)
    if existing is not None:
        _require_resource_manage(request, existing, kind="Vault secret")
    return existing


def _is_approval_visible_to_caller(
    approval: dict[str, Any],
    *,
    caller_email: str,
    multi_user: bool,
    admin: bool,
    settings: Any,
    bots_by_slug: dict[str, dict[str, Any]],
    ints_by_slug: dict[str, dict[str, Any]],
    vault_by_slug: dict[str, dict[str, Any]] | None = None,
    caller_groups: set[str] | None = None,
    repo: ArgoRepository | None = None,
) -> bool:
    if not multi_user or admin:
        return True
    bot_slug = str(approval.get("bot_slug") or "")
    bot_obj = bots_by_slug.get(bot_slug)
    acc_slug = str(approval.get("target_account_slug") or "")
    acc_obj = ints_by_slug.get(acc_slug)
    if bot_obj is not None:
        if not can_manage_resource(
            caller_email,
            owner_email=_res_owner(bot_obj),
            visibility=bot_obj.get("visibility"),
            settings=settings,
            repo=repo,
        ):
            return False
    elif acc_obj is not None:
        if not can_manage_resource(
            caller_email,
            owner_email=_res_owner(acc_obj),
            visibility=acc_obj.get("visibility"),
            settings=settings,
            repo=repo,
        ):
            return False
    else:
        return False

    if acc_obj is not None and not can_read_resource(
        caller_email,
        owner_email=_res_owner(acc_obj),
        visibility=acc_obj.get("visibility"),
        allowed_groups=acc_obj.get("allowed_groups"),
        caller_groups=caller_groups,
        settings=settings,
        repo=repo,
    ):
        return False
    if vault_by_slug is not None:
        payload = approval.get("payload") or {}
        v_slug = str(payload.get("vault_slug") or "")
        v_obj = vault_by_slug.get(v_slug)
        if v_obj is not None and not can_read_resource(
            caller_email,
            owner_email=_res_owner(v_obj),
            visibility=v_obj.get("visibility"),
            allowed_groups=v_obj.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        ):
            return False
    return True


def _can_access_collection(
    repo: ArgoRepository,
    *,
    slug: str,
    caller_email: str,
    multi_user: bool,
    admin: bool,
    settings: Any,
    caller_groups: set[str] | None = None,
) -> bool:
    if not multi_user or admin:
        return True
    clean_slug = collection_slug(slug)
    refs: list[dict[str, Any]] = []
    for bot in repo.list_bots():
        cols = bot.get("collections") or {}
        all_c = [collection_slug(str(c)) for c in (cols.get("read") or []) + (cols.get("write") or []) if str(c).strip()]
        if clean_slug in all_c:
            refs.append(bot)
    for page in repo.list_pages():
        allowed_c = [collection_slug(str(c)) for c in (page.get("allowed_collections") or []) if str(c).strip()]
        if clean_slug in allowed_c:
            refs.append(page)
    if not refs:
        return True
    groups = caller_groups if caller_groups is not None else user_group_slugs(caller_email, repo=repo)
    return any(
        can_read_resource(
            caller_email,
            owner_email=_res_owner(ref),
            visibility=ref.get("visibility"),
            allowed_groups=ref.get("allowed_groups"),
            caller_groups=groups,
            settings=settings,
            repo=repo,
        )
        for ref in refs
    )


def _is_event_visible_to_caller(
    ev: dict[str, Any],
    *,
    vis_bots: set[str] | None,
    vis_rooms: set[str] | None,
    vis_pages: set[str] | None,
    vis_ints: set[str] | None,
    known_bots: set[str],
    known_rooms: set[str],
    known_pages: set[str],
    known_ints: set[str],
) -> bool:
    if vis_bots is None:
        return True

    def _slug_allowed(raw: Any) -> bool:
        s = str(raw or "").strip()
        if not s:
            return True
        if s in known_bots and s not in vis_bots:
            return False
        if vis_rooms is not None and s in known_rooms and s not in vis_rooms:
            return False
        if vis_pages is not None and s in known_pages and s not in vis_pages:
            return False
        if vis_ints is not None and s in known_ints and s not in vis_ints:
            return False
        return True

    sse_kind = ev.get("_sse_event")
    if sse_kind == "turn_stream" or ev.get("type") in {
        "run_started",
        "text_delta",
        "chip_started",
        "chip_finished",
        "run_finished",
        "run_queued",
    }:
        if not _slug_allowed(ev.get("bot_slug")):
            return False
        t_slug = str(ev.get("target_slug") or "")
        if ev.get("target_type") == "room" and vis_rooms is not None and t_slug in known_rooms and t_slug not in vis_rooms:
            return False
        return _slug_allowed(t_slug)

    if sse_kind == "boot_progress":
        return _slug_allowed(ev.get("bot_slug") or ev.get("slug"))

    if not _slug_allowed(ev.get("source_slug")) or not _slug_allowed(ev.get("target_slug")):
        return False
    payload = ev.get("payload")
    if isinstance(payload, dict):
        if not _slug_allowed(payload.get("bot_slug")) or not _slug_allowed(payload.get("room_slug")):
            return False
    return True


def _format_transcript_markdown(
    *,
    title: str,
    target_type: str,
    messages: list[dict[str, Any]],
    fallback_bot_name: str = "Bot",
    secrets: list[str] | tuple[str, ...] = (),
) -> str:
    """Format a chronological bot or room chat transcript as secret-scrubbed Markdown."""
    kind_label = "Team Room" if target_type == "room" else "Bot"
    lines: list[str] = [
        f"# {title} ({kind_label}) — Chat Transcript",
        "",
        f"Exported: {utc_now()} | Messages: {len(messages)}",
        "",
        "---",
        "",
    ]
    if not messages:
        lines.append("_No messages in this conversation._")
    else:
        for msg in messages:
            sender_raw = str(msg.get("sender") or "").strip().lower()
            if target_type == "room":
                sender_label = str(
                    msg.get("sender_name")
                    or msg.get("sender_slug")
                    or ("Operator" if sender_raw == "user" else "Bot")
                ).strip()
            else:
                sender_label = (
                    "Operator"
                    if sender_raw == "user"
                    else str(msg.get("sender_name") or fallback_bot_name).strip()
                )
            ts = str(msg.get("created_at") or "").strip()
            lines.append(f"### {sender_label}" + (f" · {ts}" if ts else ""))
            lines.append("")
            body = str(msg.get("text") or "").strip()
            lines.append(body or "_(empty message)_")
            meta = msg.get("metadata") if isinstance(msg.get("metadata"), dict) else {}
            attachments = meta.get("attachments") if isinstance(meta.get("attachments"), list) else []
            att_names = [
                str(att.get("filename") or att.get("name") or "").strip()
                for att in attachments
                if isinstance(att, dict)
            ]
            att_names = [n for n in att_names if n]
            if att_names:
                lines.append("")
                lines.append(f"Attachments: {', '.join(att_names)}")
            lines.append("")
    rendered = "\n".join(lines).rstrip() + "\n"
    return redact_secrets(rendered, secrets)


async def _clear_thread_messages_response(
    *,
    request: Request,
    repo: ArgoRepository,
    bus: EventBus,
    target_type: str,
    target_slug: str,
    keep_last: int,
    older_than_days: int | None,
) -> dict[str, Any]:
    """Shared handler to clear bot/room messages, reject active turns, and broadcast SSE."""
    thread_key = f"{target_type}:{target_slug}"
    bot_runner = getattr(request.app.state, "bot_runner", None)
    if bot_runner is not None and bot_runner.has_active_thread_run(thread_key):
        raise HTTPException(
            status_code=409,
            detail="Cannot clear chat while a reply is actively running on this thread.",
        )

    if target_type == "room":
        stats = repo.clear_room_messages(
            target_slug, keep_last=keep_last, older_than_days=older_than_days
        )
        messages, has_more, total_count = repo.list_room_messages_window(target_slug, limit=40)
    else:
        stats = repo.clear_bot_messages(
            target_slug, keep_last=keep_last, older_than_days=older_than_days
        )
        messages, has_more, total_count = repo.list_bot_messages_window(target_slug, limit=40)

    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug=target_slug,
        target_slug=target_slug,
        event_type="thread.cleared",
        payload={
            "target_type": target_type,
            "slug": target_slug,
            "deleted_count": stats["deleted_count"],
            "remaining_count": stats["remaining_count"],
            "keep_last": keep_last,
            "older_than_days": older_than_days,
        },
    )
    return {
        "status": "cleared",
        "target_type": target_type,
        "slug": target_slug,
        "deleted_count": stats["deleted_count"],
        "remaining_count": stats["remaining_count"],
        "messages": messages,
        "has_more": has_more,
        "total_count": total_count,
    }


def _extract_rewind_submission_meta(
    repo: ArgoRepository,
    owner_email: str,
    orig_meta: dict[str, Any],
) -> dict[str, Any]:
    """Preserve valid attachment IDs, skills, reply quote, and target page when re-submitting."""
    valid_attachment_ids: list[str] = []
    for att in orig_meta.get("attachments") or []:
        if not isinstance(att, dict):
            continue
        fid = str(att.get("id") or "").strip()
        if not fid:
            continue
        try:
            repo.get_workspace_file(fid, owner_email=owner_email)
            valid_attachment_ids.append(fid)
        except NotFoundError:
            continue
    skill_slugs = [
        str(s).strip() for s in (orig_meta.get("skill_slugs") or []) if str(s).strip()
    ]
    raw_page = str(orig_meta.get("target_page_slug") or "").strip()
    reply_obj = orig_meta.get("reply_to") if isinstance(orig_meta.get("reply_to"), dict) else {}
    reply_id = str(reply_obj.get("id") or "").strip() or None
    return {
        "attachment_ids": valid_attachment_ids,
        "skill_slugs": skill_slugs,
        "target_page_slug": raw_page or None,
        "reply_to_id": reply_id,
    }


def _merge_removed_ids_response(result: Any, removed_ids: list[str]) -> Any:
    """Attach removed_message_ids to either a sync dict or a 202 JSONResponse ack."""
    if isinstance(result, JSONResponse):
        try:
            payload = json.loads(bytes(result.body).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = {}
        if isinstance(payload, dict):
            payload["removed_message_ids"] = list(removed_ids)
        return JSONResponse(status_code=result.status_code, content=payload)
    if isinstance(result, dict):
        return {**result, "removed_message_ids": list(removed_ids)}
    return result


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
        "commit_sha": __commit__,
        "sqlite_wal": repo.check_wal_enabled(),
        "valkey_connected": bus.connected,
        "vault_configured": vault.is_configured,
        "host": telemetry.to_dict(),
    }


@router.get("/me")
def current_principal(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, principal, _, _, _ = _caller(request)
    return enrich_principal(principal, settings, repo=repo)


@router.get("/auth/config")
def get_auth_config(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    return {
        "auth_mode": settings.resolved_auth_mode(),
        "multi_user": is_multi_user_enabled(settings),
        "google_auth_enabled": settings.google_auth_configured(),
        "needs_setup": needs_initial_setup(repo, settings),
        "public_base_url": settings.public_base_url,
    }


@router.post("/auth/bootstrap", status_code=status.HTTP_201_CREATED)
def auth_bootstrap(request: Request, body: AuthBootstrapRequest, response: Response) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    if settings.resolved_auth_mode() == "sso":
        raise HTTPException(
            status_code=400,
            detail="Bootstrap setup is disabled when ARGO_AUTH_MODE=sso.",
        )
    if not needs_initial_setup(repo, settings):
        raise HTTPException(
            status_code=403,
            detail="Initial admin setup is already locked.",
        )
    clean_email = normalize_email(body.email)
    if not clean_email or "@" not in clean_email:
        raise HTTPException(status_code=400, detail="Valid admin email address is required.")
    configured_admins = {
        normalize_email(str(a))
        for a in (getattr(settings, "admin_emails", ()) or ())
        if normalize_email(str(a))
    }
    if configured_admins and clean_email not in configured_admins:
        raise HTTPException(
            status_code=403,
            detail="Bootstrap email must match ARGO_ADMIN_EMAILS.",
        )
    try:
        pw_hash = hash_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    user = repo.upsert_user(
        email=clean_email,
        display_name=body.display_name.strip() or clean_email.split("@", 1)[0].replace(".", " ").title(),
        role="admin",
        active=True,
        auth_methods=["password", "google"],
        password_hash=pw_hash,
        must_change_password=False,
        created_by="bootstrap",
        touch_login=True,
    )
    raw_tok, tok_sha = generate_session_token()
    repo.create_auth_session(
        token_sha256=tok_sha,
        email=clean_email,
        auth_method="password",
        token_version=int(user.get("token_version") or 1),
        ttl_hours=int(getattr(settings, "session_ttl_hours", 168) or 168),
        user_agent=str(request.headers.get("user-agent") or ""),
    )
    set_session_cookie(response, raw_tok, settings)
    return {"status": "bootstrapped", "user": user}


@router.post("/auth/login")
async def auth_login(request: Request, body: AuthLoginRequest, response: Response) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    if settings.resolved_auth_mode() == "sso":
        raise HTTPException(
            status_code=400,
            detail="Password login is disabled when ARGO_AUTH_MODE=sso.",
        )
    if needs_initial_setup(repo, settings):
        raise HTTPException(
            status_code=409,
            detail="Initial admin setup must be completed before signing in.",
        )
    clean_email = normalize_email(body.email)
    peer_ip = normalize_peer_ip(str(request.client.host if request.client else "")) or "unknown"
    limiter = getattr(request.app.state, "login_rate_limiter", None)
    if limiter is not None:
        for bucket in (f"ip:{peer_ip}", f"email:{clean_email or 'blank'}"):
            allowed, retry_after = await limiter.check_allowed(bucket)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many failed login attempts. Try again in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )

    user = repo.get_user(clean_email, include_secret=True) if clean_email else None
    valid_pw = (
        user is not None
        and user.get("active", True)
        and "password" in (user.get("auth_methods") or [])
        and bool(user.get("password_hash"))
        and verify_password(body.password, str(user.get("password_hash") or ""))
    )
    if not valid_pw:
        if limiter is not None:
            await limiter.record_failure(f"ip:{peer_ip}")
            await limiter.record_failure(f"email:{clean_email or 'blank'}")
        if user is not None and not user.get("active", True):
            raise HTTPException(status_code=403, detail="Account is disabled.")
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if limiter is not None:
        await limiter.reset(f"ip:{peer_ip}")
        await limiter.reset(f"email:{clean_email}")

    updated_user = repo.upsert_user(email=clean_email, touch_login=True)
    raw_tok, tok_sha = generate_session_token()
    repo.create_auth_session(
        token_sha256=tok_sha,
        email=clean_email,
        auth_method="password",
        token_version=int(updated_user.get("token_version") or 1),
        ttl_hours=int(getattr(settings, "session_ttl_hours", 168) or 168),
        user_agent=str(request.headers.get("user-agent") or ""),
    )
    set_session_cookie(response, raw_tok, settings)
    return {"status": "ok", "user": updated_user}


@router.post("/auth/logout")
def auth_logout(request: Request, response: Response) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    raw_cookie = str(request.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if raw_cookie:
        repo.delete_auth_session(hash_token(raw_cookie))
    clear_session_cookie(response, settings)
    return {"status": "logged_out"}


@router.post("/auth/change-password")
def auth_change_password(
    request: Request,
    body: AuthChangePasswordRequest,
    response: Response,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, _, _ = _caller(request)
    if settings.resolved_auth_mode() == "sso":
        raise HTTPException(status_code=400, detail="Password management is unavailable in SSO mode.")
    if not caller_email:
        raise HTTPException(status_code=401, detail="Authentication required.")
    user = repo.get_user(caller_email, include_secret=True)
    if user is None:
        raise HTTPException(status_code=404, detail="User account not found.")
    if user.get("password_hash") and not verify_password(
        str(body.current_password or ""), str(user.get("password_hash") or "")
    ):
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    try:
        new_hash = hash_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    methods = list(dict.fromkeys([*(user.get("auth_methods") or []), "password"]))
    updated = repo.upsert_user(
        email=caller_email,
        password_hash=new_hash,
        must_change_password=False,
        auth_methods=methods,
        bump_token_version=True,
    )
    repo.delete_user_sessions(caller_email)
    raw_tok, tok_sha = generate_session_token()
    repo.create_auth_session(
        token_sha256=tok_sha,
        email=caller_email,
        auth_method="password",
        token_version=int(updated.get("token_version") or 1),
        ttl_hours=int(getattr(settings, "session_ttl_hours", 168) or 168),
        user_agent=str(request.headers.get("user-agent") or ""),
    )
    set_session_cookie(response, raw_tok, settings)
    return {"status": "updated", "user": updated}


def _auth_error_redirect(settings: Any, reason: str) -> RedirectResponse:
    qs = urllib.parse.urlencode({"auth_error": reason})
    resp = RedirectResponse(url=f"/?{qs}", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(
        key=OAUTH_NONCE_COOKIE_NAME,
        path="/api/auth/google/callback",
        httponly=True,
        secure=is_https_public_url(getattr(settings, "public_base_url", "")),
        samesite="lax",
    )
    return resp


@router.get("/auth/google/start")
def auth_google_start(request: Request) -> RedirectResponse:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    if settings.resolved_auth_mode() != "hybrid" or not settings.google_auth_configured():
        return _auth_error_redirect(settings, "google_disabled")
    google_login_service = request.app.state.google_login_service
    try:
        auth_url, raw_nonce = google_login_service.start_login(repo, settings)
    except GoogleAuthLoginError:
        return _auth_error_redirect(settings, "google_failed")
    resp = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=OAUTH_NONCE_COOKIE_NAME,
        value=raw_nonce,
        max_age=OAUTH_STATE_TTL_SECONDS,
        path="/api/auth/google/callback",
        httponly=True,
        secure=is_https_public_url(getattr(settings, "public_base_url", "")),
        samesite="lax",
    )
    return resp


@router.get("/auth/google/callback")
async def auth_google_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    repo, _, _, _ = _deps(request)
    settings = request.app.state.settings
    if settings.resolved_auth_mode() != "hybrid" or not settings.google_auth_configured():
        return _auth_error_redirect(settings, "google_disabled")
    if error or not code or not state:
        return _auth_error_redirect(settings, "google_failed")
    raw_nonce = str(request.cookies.get(OAUTH_NONCE_COOKIE_NAME) or "").strip()
    google_login_service = request.app.state.google_login_service
    try:
        email, name = await google_login_service.complete_login(
            repo,
            settings,
            code=code,
            state=state,
            raw_nonce=raw_nonce,
        )
    except GoogleAuthLoginError:
        return _auth_error_redirect(settings, "google_failed")

    # Strict invite-only policy: user must be pre-created or configured in ARGO_ADMIN_EMAILS
    user = repo.get_user(email)
    if user is None:
        return _auth_error_redirect(settings, "not_invited")
    if not user.get("active", True):
        return _auth_error_redirect(settings, "account_disabled")
    if "google" not in (user.get("auth_methods") or []):
        return _auth_error_redirect(settings, "google_not_enabled")

    updated = repo.upsert_user(
        email=email,
        display_name=name if (name and not user.get("display_name")) else None,
        touch_login=True,
    )
    raw_tok, tok_sha = generate_session_token()
    repo.create_auth_session(
        token_sha256=tok_sha,
        email=email,
        auth_method="google",
        token_version=int(updated.get("token_version") or 1),
        ttl_hours=int(getattr(settings, "session_ttl_hours", 168) or 168),
        user_agent=str(request.headers.get("user-agent") or ""),
    )
    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    set_session_cookie(resp, raw_tok, settings)
    resp.delete_cookie(
        key=OAUTH_NONCE_COOKIE_NAME,
        path="/api/auth/google/callback",
        httponly=True,
        secure=is_https_public_url(getattr(settings, "public_base_url", "")),
        samesite="lax",
    )
    return resp


@router.get("/teams")
def list_my_teams(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, _, admin = _caller(request)
    if is_auth_rbac_active(settings) and not caller_email and settings.resolved_auth_mode() != "sso":
        raise HTTPException(status_code=401, detail="Authentication required.")
    groups = repo.list_team_groups()
    if not is_auth_rbac_active(settings) or admin:
        return groups
    return [
        g
        for g in groups
        if caller_email in {normalize_email(str(m)) for m in (g.get("member_emails") or [])}
    ]


@router.get("/admin/users")
def admin_list_users(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    return repo.list_users()


@router.post("/admin/users", status_code=status.HTTP_201_CREATED)
def admin_create_user(request: Request, body: AdminCreateUserRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, _, caller_email = _require_admin(request)
    clean_email = normalize_email(body.email)
    if not clean_email or "@" not in clean_email:
        raise HTTPException(status_code=400, detail="Valid user email is required.")
    if repo.get_user(clean_email) is not None:
        raise HTTPException(status_code=409, detail=f"User '{clean_email}' already exists.")
    if not body.auth_methods:
        raise HTTPException(status_code=400, detail="Select at least one sign-in method (password or google).")
    pw_hash: str | None = None
    must_change = False
    if body.password and body.password.strip():
        try:
            pw_hash = hash_password(body.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        must_change = bool(body.must_change_password)
    elif "password" in body.auth_methods and "google" not in body.auth_methods:
        raise HTTPException(
            status_code=400,
            detail="An initial password is required for password-only accounts.",
        )

    known_groups = {g["slug"] for g in repo.list_team_groups()}
    clean_groups = normalize_group_slugs(body.group_slugs)
    unknown = [g for g in clean_groups if g not in known_groups]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown Team Group(s): {', '.join(unknown)}.")

    created = repo.upsert_user(
        email=clean_email,
        display_name=body.display_name.strip(),
        role=body.role,
        active=True,
        auth_methods=list(body.auth_methods),
        password_hash=pw_hash,
        must_change_password=must_change,
        max_active_desktops=body.max_active_desktops,
        max_active_sandboxes=body.max_active_sandboxes,
        created_by=caller_email,
    )
    if clean_groups:
        repo.set_user_groups(clean_email, clean_groups)
        created = repo.get_user(clean_email) or created
    return created


def _active_admin_count(repo: ArgoRepository, settings: Any) -> int:
    active_admins = {
        u["email"]
        for u in repo.list_users()
        if u.get("active", True) and u.get("role") == "admin"
    }
    env_admins = {
        normalize_email(str(a))
        for a in (getattr(settings, "admin_emails", ()) or ())
        if normalize_email(str(a))
    }
    disabled_env = {
        u["email"] for u in repo.list_users() if not u.get("active", True)
    }
    return len(active_admins | (env_admins - disabled_env))


@router.patch("/admin/users/{email}")
def admin_update_user(
    request: Request,
    email: str,
    body: AdminUpdateUserRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email = _require_admin(request)
    target_email = normalize_email(email)
    existing = repo.get_user(target_email, include_secret=True)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"User '{email}' not found.")

    if target_email == caller_email:
        if body.active is False:
            raise HTTPException(status_code=400, detail="You cannot disable your own active admin account.")
        if body.role is not None and body.role != "admin":
            raise HTTPException(status_code=400, detail="You cannot demote your own active admin role.")

    losing_admin = (
        existing.get("active", True)
        and existing.get("role") == "admin"
        and ((body.active is False) or (body.role is not None and body.role != "admin"))
    )
    if losing_admin and _active_admin_count(repo, settings) <= 1:
        raise HTTPException(
            status_code=400,
            detail="Cannot remove or disable the last remaining active workspace admin.",
        )

    if body.auth_methods is not None and not body.auth_methods:
        raise HTTPException(status_code=400, detail="User must retain at least one sign-in method.")
    if body.group_slugs is not None:
        known_groups = {g["slug"] for g in repo.list_team_groups()}
        cand_groups = normalize_group_slugs(body.group_slugs)
        unknown = [g for g in cand_groups if g not in known_groups]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown Team Group(s): {', '.join(unknown)}.")

    revoke_sessions = (body.active is False) or (
        body.auth_methods is not None and list(body.auth_methods) != list(existing.get("auth_methods") or [])
    )
    kwargs: dict[str, Any] = {
        "email": target_email,
        "display_name": body.display_name,
        "role": body.role,
        "active": body.active,
        "auth_methods": list(body.auth_methods) if body.auth_methods is not None else None,
        "bump_token_version": revoke_sessions,
    }
    if body.clear_quota_overrides:
        kwargs["max_active_desktops"] = None
        kwargs["max_active_sandboxes"] = None
    if body.max_active_desktops is not None:
        kwargs["max_active_desktops"] = body.max_active_desktops
    if body.max_active_sandboxes is not None:
        kwargs["max_active_sandboxes"] = body.max_active_sandboxes

    updated = repo.upsert_user(**kwargs)
    if body.group_slugs is not None:
        repo.set_user_groups(target_email, body.group_slugs)
        updated = repo.get_user(target_email) or updated
    if revoke_sessions:
        repo.delete_user_sessions(target_email)
    return updated


@router.post("/admin/users/{email}/reset-password")
def admin_reset_user_password(
    request: Request,
    email: str,
    body: AdminResetPasswordRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    target_email = normalize_email(email)
    existing = repo.get_user(target_email)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"User '{email}' not found.")
    try:
        pw_hash = hash_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    methods = list(dict.fromkeys([*(existing.get("auth_methods") or []), "password"]))
    updated = repo.upsert_user(
        email=target_email,
        auth_methods=methods,
        password_hash=pw_hash,
        must_change_password=body.must_change_password,
        bump_token_version=True,
    )
    repo.delete_user_sessions(target_email)
    return updated


@router.delete("/admin/users/{email}")
def admin_delete_user(request: Request, email: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email = _require_admin(request)
    target_email = normalize_email(email)
    existing = repo.get_user(target_email)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"User '{email}' not found.")
    if target_email == caller_email:
        raise HTTPException(status_code=400, detail="You cannot delete your own active account.")
    env_admins = {
        normalize_email(str(a))
        for a in (getattr(settings, "admin_emails", ()) or ())
        if normalize_email(str(a))
    }
    if target_email in env_admins:
        raise HTTPException(
            status_code=400,
            detail="Admins configured in ARGO_ADMIN_EMAILS cannot be deleted from the UI.",
        )
    if existing.get("active", True) and existing.get("role") == "admin" and _active_admin_count(repo, settings) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining active admin.")
    repo.delete_user(target_email)
    return {"status": "deleted", "email": target_email}


@router.post("/admin/teams", status_code=status.HTTP_201_CREATED)
def admin_create_team(request: Request, body: CreateTeamGroupRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, _, caller_email = _require_admin(request)
    cand_slug = slugify(body.slug or body.name)
    if repo.get_team_group(cand_slug) is not None:
        raise HTTPException(status_code=409, detail=f"Team Group '{cand_slug}' already exists.")
    try:
        return repo.upsert_team_group(
            name=body.name,
            slug=cand_slug,
            description=body.description,
            member_emails=body.member_emails,
            created_by=caller_email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/admin/teams/{slug}")
def admin_update_team(
    request: Request,
    slug: str,
    body: UpdateTeamGroupRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    existing = repo.get_team_group(slug)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Team Group '{slug}' not found.")
    try:
        return repo.upsert_team_group(
            name=body.name or existing["name"],
            slug=existing["slug"],
            description=body.description if body.description is not None else existing["description"],
            member_emails=body.member_emails if body.member_emails is not None else existing["member_emails"],
            created_by=existing.get("created_by", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/admin/teams/{slug}")
def admin_delete_team(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    try:
        repo.delete_team_group(slug)
        return {"status": "deleted", "slug": slugify(slug)}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/workspace/summary")
def workspace_summary(request: Request) -> dict[str, Any]:
    repo, bus, guard, vault = _deps(request)
    vis_bots, mgr_bots, _, vis_pages, vis_ints = _visible_slug_sets(request, repo)
    telemetry = guard.sample()
    return {
        "version": __version__,
        "commit_sha": __commit__,
        "sqlite_wal": repo.check_wal_enabled(),
        "valkey_connected": bus.connected,
        "vault_configured": vault.is_configured,
        "counts": repo.workspace_counts(
            allowed_bot_slugs=vis_bots,
            allowed_page_slugs=vis_pages,
            allowed_integration_slugs=vis_ints,
            manageable_bot_slugs=mgr_bots,
        ),
        "host": telemetry.to_dict(),
    }


@router.get("/workspace/live-status")
def workspace_live_status(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    vis_bots, mgr_bots, vis_rooms, vis_pages, vis_ints = _visible_slug_sets(request, repo)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    desktop_states: dict[str, dict[str, Any]] = {}
    if desktop_manager is not None:
        try:
            desk_info = desktop_manager.list_desktops_status(allowed_bot_slugs=vis_bots)
            for d in desk_info.get("desktops", []):
                if isinstance(d, dict) and d.get("bot_slug"):
                    desktop_states[str(d["bot_slug"])] = d
        except Exception:
            pass
    sandbox_manager = getattr(request.app.state, "sandbox_manager", None)
    if sandbox_manager is not None:
        try:
            sandbox_manager.list_sandboxes_status(allowed_bot_slugs=vis_bots)
        except Exception:
            pass
    bot_runner = getattr(request.app.state, "bot_runner", None)
    active_runs = bot_runner.active_runs() if bot_runner is not None else {}
    return repo.build_live_workspace_status(
        desktop_states=desktop_states,
        active_runs=active_runs,
        user_email=principal["email"],
        allowed_bot_slugs=vis_bots,
        allowed_room_slugs=vis_rooms,
        allowed_page_slugs=vis_pages,
        allowed_integration_slugs=vis_ints,
        manageable_bot_slugs=mgr_bots,
    )


@router.get("/activity")
def list_activity(
    request: Request,
    category: str = Query(default="all"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    _, _, _, multi_user, admin = _caller(request)
    if not multi_user or admin:
        return repo.list_events(category=category, limit=limit)
    vis_bots, _, vis_rooms, vis_pages, vis_ints = _visible_slug_sets(request, repo)
    known_bots = {b["slug"] for b in repo.list_bots()}
    known_rooms = {r["slug"] for r in repo.list_rooms()}
    known_pages = {p["slug"] for p in repo.list_pages()}
    known_ints = {i["slug"] for i in repo.list_integrations()}
    events = repo.list_events(category=category, limit=min(200, limit * 3))
    filtered = [
        ev
        for ev in events
        if _is_event_visible_to_caller(
            ev,
            vis_bots=vis_bots,
            vis_rooms=vis_rooms,
            vis_pages=vis_pages,
            vis_ints=vis_ints,
            known_bots=known_bots,
            known_rooms=known_rooms,
            known_pages=known_pages,
            known_ints=known_ints,
        )
    ]
    return filtered[:limit]


@router.post("/activity/dispatch", status_code=status.HTTP_201_CREATED)
async def dispatch_activity(
    request: Request,
    body: DispatchActivityRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, principal, caller_email, multi_user, admin = _caller(request)
    resolved_target = (body.target_slug or "").strip()
    if resolved_target:
        if multi_user and not admin:
            bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
            if resolved_target in bots_by_slug:
                _require_resource_read(request, bots_by_slug[resolved_target], kind="Bot")
            else:
                _require_admin(request)
    else:
        existing_bots = repo.list_bots()
        if multi_user and not admin:
            caller_groups = user_group_slugs(caller_email, repo=repo)
            existing_bots = [
                b
                for b in existing_bots
                if can_read_resource(
                    caller_email,
                    owner_email=_res_owner(b),
                    visibility=b.get("visibility"),
                    allowed_groups=b.get("allowed_groups"),
                    caller_groups=caller_groups,
                    settings=settings,
                    repo=repo,
                )
            ]
        first_bot = next((b for b in existing_bots if b.get("enabled")), None) or (
            existing_bots[0] if existing_bots else None
        )
        if first_bot is None:
            raise HTTPException(
                status_code=400,
                detail="Create a bot before dispatching workspace instructions.",
            )
        resolved_target = first_bot["slug"]
    try:
        return await bus.publish(
            correlation_id=make_id("corr"),
            source_slug=principal["actor"],
            target_slug=resolved_target,
            event_type="operator.instruction",
            payload={
                "category": "reviews",
                "title": "Operator Instruction Dispatched",
                "badge": "Queued · Valkey Stream",
                "badge_tone": "indigo",
                "summary": body.instruction,
                "meta": "Valkey argo:events · hop_count=1/5",
                "operator_email": principal["email"],
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
    repo, bus, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)

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
                    if multi_user and not admin and isinstance(event, dict):
                        caller_groups = user_group_slugs(caller_email, repo=repo)
                        bots = repo.list_bots()
                        rooms = repo.list_rooms()
                        pages = repo.list_pages()
                        ints = repo.list_integrations()
                        vis_bots = {
                            b["slug"]
                            for b in bots
                            if can_read_resource(
                                caller_email,
                                owner_email=_res_owner(b),
                                visibility=b.get("visibility"),
                                allowed_groups=b.get("allowed_groups"),
                                caller_groups=caller_groups,
                                settings=settings,
                                repo=repo,
                            )
                        }
                        vis_rooms = {
                            r["slug"]
                            for r in rooms
                            if can_read_resource(
                                caller_email,
                                owner_email=_res_owner(r),
                                visibility=r.get("visibility"),
                                allowed_groups=r.get("allowed_groups"),
                                caller_groups=caller_groups,
                                settings=settings,
                                repo=repo,
                            )
                        }
                        vis_pages = {
                            p["slug"]
                            for p in pages
                            if can_read_resource(
                                caller_email,
                                owner_email=_res_owner(p),
                                visibility=p.get("visibility"),
                                allowed_groups=p.get("allowed_groups"),
                                caller_groups=caller_groups,
                                settings=settings,
                                repo=repo,
                            )
                        }
                        vis_ints = {
                            i["slug"]
                            for i in ints
                            if can_read_resource(
                                caller_email,
                                owner_email=_res_owner(i),
                                visibility=i.get("visibility"),
                                allowed_groups=i.get("allowed_groups"),
                                caller_groups=caller_groups,
                                settings=settings,
                                repo=repo,
                            )
                        }
                        if not _is_event_visible_to_caller(
                            event,
                            vis_bots=vis_bots,
                            vis_rooms=vis_rooms,
                            vis_pages=vis_pages,
                            vis_ints=vis_ints,
                            known_bots={b["slug"] for b in bots},
                            known_rooms={r["slug"] for r in rooms},
                            known_pages={p["slug"] for p in pages},
                            known_ints={i["slug"] for i in ints},
                        ):
                            continue
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
    settings, _, caller_email, multi_user, admin = _caller(request)
    bots = repo.list_bots()
    if not multi_user or admin:
        return bots
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        b
        for b in bots
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(b),
            visibility=b.get("visibility"),
            allowed_groups=b.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    ]


@router.post("/bots", status_code=status.HTTP_201_CREATED)
async def create_bot(request: Request, body: CreateBotRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    _validate_bot_linked_accounts(
        request,
        repo,
        linked_accounts=body.linked_accounts,
        tools=body.tools,
        visibility=vis,
        allowed_groups=groups,
    )
    bot = repo.create_bot(
        name=body.name,
        role=body.role,
        runtime=body.runtime,
        outbound_rbac=body.outbound_rbac,
        model=body.model,
        daily_cap=body.daily_cap,
        max_steps_per_run=body.max_steps_per_run,
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
        owner_email=caller_email,
        visibility=vis,
        allowed_groups=groups,
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
    settings, _, caller_email = _require_writer_identity(request)
    vis = default_visibility_for_new(settings, None)
    _validate_bot_linked_accounts(
        request,
        repo,
        linked_accounts=body.linked_accounts,
        tools=[],
        visibility=vis,
    )
    try:
        bot = repo.import_bot_blueprint(
            body.blueprint,
            linked_accounts=body.linked_accounts or None,
            owner_email=caller_email,
            visibility=vis,
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
    repo, _, _, _ = _deps(request)
    if body.linked_accounts:
        _validate_bot_linked_accounts(
            request,
            repo,
            linked_accounts=body.linked_accounts,
            tools=[],
            visibility="private",
        )
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
        return _require_bot_read(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/bots/{slug}")
async def update_bot(request: Request, slug: str, body: UpdateBotRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        prev_bot = _require_bot_manage(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    patch_data = body.model_dump(exclude_none=True)
    next_visibility, next_groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
        existing=prev_bot,
    )
    if body.visibility is not None or body.allowed_groups is not None:
        patch_data["visibility"] = next_visibility
        patch_data["allowed_groups"] = next_groups
    _validate_bot_linked_accounts(
        request,
        repo,
        linked_accounts=(
            body.linked_accounts
            if body.linked_accounts is not None
            else list(prev_bot.get("linked_accounts") or [])
        ),
        tools=body.tools if body.tools is not None else list(prev_bot.get("tools") or []),
        visibility=next_visibility,
        allowed_groups=next_groups,
    )
    new_runtime = patch_data.get("runtime")
    if new_runtime is not None and new_runtime != prev_bot.get("runtime"):
        if prev_bot.get("runtime") == "sandbox":
            sandbox_manager = getattr(request.app.state, "sandbox_manager", None)
            if sandbox_manager is not None:
                with contextlib.suppress(Exception):
                    if prev_bot.get("sandbox_state") == "running":
                        await sandbox_manager.stop_sandbox(slug, reason="runtime_changed")
                    else:
                        await sandbox_manager._driver.ensure_stopped(f"argo-sandbox-{slug}")
        elif prev_bot.get("runtime") == "desktop":
            desktop_manager = getattr(request.app.state, "desktop_manager", None)
            if desktop_manager is not None:
                with contextlib.suppress(Exception):
                    if prev_bot.get("desktop_state") == "running":
                        await desktop_manager.hibernate_desktop(slug, reason="runtime_changed")
                    else:
                        await desktop_manager._driver.ensure_stopped(f"argo-desktop-{slug}")
    try:
        updated = repo.update_bot(slug, patch_data)
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
        _require_bot_manage(request, repo, slug)
        deleted_bot = repo.delete_bot(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    clean_slug = str(deleted_bot.get("slug") or slug)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    if desktop_manager is not None:
        with contextlib.suppress(Exception):
            await desktop_manager.destroy_desktop(clean_slug)
    sandbox_manager = getattr(request.app.state, "sandbox_manager", None)
    if sandbox_manager is not None:
        with contextlib.suppress(Exception):
            await sandbox_manager.destroy_sandbox(clean_slug)
    desktop_mcp_bridge = getattr(request.app.state, "desktop_mcp_bridge", None)
    if desktop_mcp_bridge is not None and hasattr(desktop_mcp_bridge, "_sim_states"):
        desktop_mcp_bridge._sim_states.pop(clean_slug, None)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is not None and hasattr(ssh_manager, "list_sessions"):
        for sess in list(ssh_manager.list_sessions(bot_slug=clean_slug)):
            sid = sess.get("id")
            if sid and hasattr(ssh_manager, "close_session"):
                with contextlib.suppress(Exception):
                    await ssh_manager.close_session(str(sid))
    approval_coordinator = getattr(request.app.state, "approval_coordinator", None)
    for sup_appr in (deleted_bot.get("_superseded_approvals") or []):
        if approval_coordinator is not None and hasattr(approval_coordinator, "_lock_telegram_card"):
            with contextlib.suppress(Exception):
                await approval_coordinator._lock_telegram_card(
                    sup_appr,
                    status_line="Superseded — bot deleted.",
                )
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
        _require_bot_read(request, repo, slug)
        return repo.export_bot_blueprint(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/bots/{slug}/trigger")
async def trigger_bot(
    request: Request,
    slug: str,
    body: TriggerBotRequest | None = None,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, principal, _, _, _ = _caller(request)
    try:
        _require_bot_read(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    bot_runner = request.app.state.bot_runner
    req_body = body or TriggerBotRequest()
    payload = dict(req_body.payload)
    payload.setdefault("operator_email", principal["email"])
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
        _require_bot_read(request, repo, slug)
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


@router.delete("/bots/{slug}/messages")
async def clear_bot_messages_endpoint(
    request: Request,
    slug: str,
    keep_last: int = Query(default=0, ge=0, le=500),
    older_than_days: int | None = Query(default=None, ge=1, le=3650),
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    extract_sso_principal(request)
    try:
        bot = _require_bot_manage(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return await _clear_thread_messages_response(
        request=request,
        repo=repo,
        bus=bus,
        target_type="bot",
        target_slug=bot["slug"],
        keep_last=keep_last,
        older_than_days=older_than_days,
    )


@router.get("/bots/{slug}/messages/export")
def export_bot_messages_endpoint(
    request: Request,
    slug: str,
) -> Response:
    repo, _, _, _ = _deps(request)
    extract_sso_principal(request)
    try:
        bot = _require_bot_read(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    messages = repo.list_bot_messages(bot["slug"], limit=None)
    md = _format_transcript_markdown(
        title=bot["name"],
        target_type="bot",
        messages=messages,
        fallback_bot_name=bot["name"],
        secrets=repo.collect_all_vault_secret_values(),
    )
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{bot["slug"]}-chat.md"'},
    )


@router.patch("/bots/{slug}/messages/{message_id}")
async def edit_last_bot_message_endpoint(
    request: Request,
    slug: str,
    message_id: str,
    body: EditLastMessageRequest,
) -> Any:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    bot_runner = getattr(request.app.state, "bot_runner", None)
    clean_text = body.text.strip()
    if not clean_text:
        raise HTTPException(status_code=400, detail="Edited message text cannot be empty.")
    try:
        bot = _require_bot_read(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not bot["enabled"]:
        raise HTTPException(status_code=400, detail=f"Bot '{slug}' is disabled.")
    if bot_runner is not None and bot_runner.has_active_thread_run(f"bot:{bot['slug']}"):
        raise HTTPException(
            status_code=409,
            detail="Wait for the current reply to finish or stop it before editing your message.",
        )
    try:
        rewound = repo.rewind_last_user_message(
            target_type="bot",
            target_slug=bot["slug"],
            message_id=message_id,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    preserved = _extract_rewind_submission_meta(repo, principal["email"], rewound["original_metadata"])
    res = await post_bot_message(
        request,
        bot["slug"],
        AppendBotMessageRequest(
            text=clean_text,
            skill_slugs=preserved["skill_slugs"],
            target_page_slug=preserved["target_page_slug"],
            reply_to_id=preserved["reply_to_id"],
            attachment_ids=preserved["attachment_ids"],
            async_mode=body.async_mode,
        ),
    )
    return _merge_removed_ids_response(res, rewound["deleted_ids"])


@router.post("/bots/{slug}/messages")
async def post_bot_message(
    request: Request,
    slug: str,
    body: AppendBotMessageRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, principal, caller_email, multi_user, admin = _caller(request)
    bot_runner = request.app.state.bot_runner
    try:
        bot = _require_bot_read(request, repo, slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    user_text = body.text.strip()
    if not user_text and not body.attachment_ids:
        raise HTTPException(status_code=400, detail="Message text or an attachment is required.")
    effective_text = user_text or "Review the attached workspace file(s)."
    corr_id = make_id("corr")

    mention_tokens = [tok.lower() for tok in re.findall(r"@([a-zA-Z0-9._-]+)", user_text)]
    raw_bots = repo.list_bots()
    raw_integrations = repo.list_integrations()
    if multi_user and not admin:
        caller_groups = user_group_slugs(caller_email, repo=repo)
        raw_bots = [
            b
            for b in raw_bots
            if can_read_resource(
                caller_email,
                owner_email=_res_owner(b),
                visibility=b.get("visibility"),
                allowed_groups=b.get("allowed_groups"),
                caller_groups=caller_groups,
                settings=settings,
                repo=repo,
            )
        ]
        raw_integrations = [
            acc
            for acc in raw_integrations
            if can_read_resource(
                caller_email,
                owner_email=_res_owner(acc),
                visibility=acc.get("visibility"),
                allowed_groups=acc.get("allowed_groups"),
                caller_groups=caller_groups,
                settings=settings,
                repo=repo,
            )
        ]
    all_bots = {b["slug"]: b for b in raw_bots}
    all_integrations = {acc["slug"]: acc for acc in raw_integrations}
    all_skills = {s["slug"]: s for s in repo.list_skills()}

    mentioned_bots = list(
        dict.fromkeys(
            [tok for tok in mention_tokens if tok in all_bots and tok != slug]
            + bot_runner._extract_room_member_mentions(
                user_text,
                [b for b in all_bots.values() if b["slug"] != slug],
            )
        )
    )
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
    repo, _, _, _ = _deps(request)
    bot_runner = request.app.state.bot_runner
    active_item = getattr(bot_runner, "_runs_by_id", {}).get(run_id)
    if active_item is not None:
        t_type = str(getattr(active_item, "target_type", "") or "")
        t_slug = str(getattr(active_item, "target_slug", "") or "")
        b_slug = str(getattr(active_item, "bot_slug", "") or "")
        if t_type == "room" and t_slug:
            try:
                room_obj = repo.get_room(t_slug)
            except NotFoundError:
                room_obj = None
            if room_obj is not None:
                _require_resource_read(request, room_obj, kind="Room")
        elif b_slug:
            try:
                _require_bot_read(request, repo, b_slug)
            except NotFoundError:
                pass
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
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    if bot_slug and bot_slug.strip():
        try:
            _require_bot_read(request, repo, bot_slug)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return repo.list_bot_runs(
        bot_slug=bot_slug,
        allowed_bot_slugs=vis_bots,
        limit=limit,
    )


@router.get("/approvals")
def list_approvals(
    request: Request,
    tab: str = Query(default="pending"),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    items = repo.list_approvals(tab=tab)
    if not multi_user or admin:
        return items
    bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
    ints_by_slug = {i["slug"]: i for i in repo.list_integrations()}
    vault_by_slug = {v["slug"]: v for v in repo.list_vault_secrets()}
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        a
        for a in items
        if _is_approval_visible_to_caller(
            a,
            caller_email=caller_email,
            multi_user=multi_user,
            admin=admin,
            settings=settings,
            bots_by_slug=bots_by_slug,
            ints_by_slug=ints_by_slug,
            vault_by_slug=vault_by_slug,
            caller_groups=caller_groups,
            repo=repo,
        )
    ]


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
async def create_approval(
    request: Request,
    body: CreateApprovalRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, _, _, multi_user, admin = _caller(request)
    if multi_user and not admin:
        try:
            bot_obj = repo.get_bot(body.bot_slug)
        except NotFoundError:
            bot_obj = None
        if bot_obj is not None:
            _require_resource_manage(request, bot_obj, kind="Bot")
        else:
            _require_admin(request)
        acc_obj = next(
            (i for i in repo.list_integrations() if i["slug"] == slugify(body.target_account_slug)),
            None,
        )
        if acc_obj is not None:
            _require_resource_read(request, acc_obj, kind="Integration")
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
    repo, _, _, _ = _deps(request)
    settings, principal, caller_email, multi_user, admin = _caller(request)
    if multi_user and not admin:
        try:
            appr = repo.get_approval(approval_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
        ints_by_slug = {i["slug"]: i for i in repo.list_integrations()}
        vault_by_slug = {v["slug"]: v for v in repo.list_vault_secrets()}
        caller_groups = user_group_slugs(caller_email, repo=repo)
        if not _is_approval_visible_to_caller(
            appr,
            caller_email=caller_email,
            multi_user=multi_user,
            admin=admin,
            settings=settings,
            bots_by_slug=bots_by_slug,
            ints_by_slug=ints_by_slug,
            vault_by_slug=vault_by_slug,
            caller_groups=caller_groups,
            repo=repo,
        ):
            raise HTTPException(status_code=403, detail="Not permitted to resolve this approval.")
    coordinator = request.app.state.approval_coordinator
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
            trust_command=body.trust_command,
            trust_prefixes=body.trust_prefixes,
        )
    except AlreadyResolvedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/approvals/batch-resolve")
async def batch_resolve_approvals(
    request: Request,
    body: BatchResolveApprovalRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, principal, caller_email, multi_user, admin = _caller(request)
    if multi_user and not admin and body.approval_ids:
        bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
        ints_by_slug = {i["slug"]: i for i in repo.list_integrations()}
        vault_by_slug = {v["slug"]: v for v in repo.list_vault_secrets()}
        caller_groups = user_group_slugs(caller_email, repo=repo)
        for aid in body.approval_ids:
            try:
                appr = repo.get_approval(aid)
            except NotFoundError:
                continue
            if not _is_approval_visible_to_caller(
                appr,
                caller_email=caller_email,
                multi_user=multi_user,
                admin=admin,
                settings=settings,
                bots_by_slug=bots_by_slug,
                ints_by_slug=ints_by_slug,
                vault_by_slug=vault_by_slug,
                caller_groups=caller_groups,
                repo=repo,
            ):
                raise HTTPException(
                    status_code=403,
                    detail=f"Not permitted to resolve approval '{aid}'.",
                )
    coordinator = request.app.state.approval_coordinator
    return await coordinator.resolve_approval_batch(
        approval_ids=body.approval_ids,
        action=body.action,
        actor=principal["actor"],
        trust_command=body.trust_command,
    )


def _require_scope_manage(request: Request, repo: ArgoRepository, scope_slug: str | None) -> None:
    clean_scope = str(scope_slug or "").strip()
    if not clean_scope or clean_scope.lower() == "global":
        _require_admin(request)
        return
    try:
        bot_obj = repo.get_bot(slugify(clean_scope))
    except NotFoundError:
        _require_admin(request)
        return
    _require_resource_manage(request, bot_obj, kind="Bot")


@router.get("/style-rules")
def list_style_rules(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    _, _, _, multi_user, admin = _caller(request)
    rules = repo.list_style_rules()
    if not multi_user or admin:
        return rules
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    known_bots = {b["slug"] for b in repo.list_bots()}
    return [
        r
        for r in rules
        if slugify(str(r.get("scope_slug") or "")) not in known_bots
        or (vis_bots is not None and slugify(str(r.get("scope_slug") or "")) in vis_bots)
    ]


@router.post("/style-rules", status_code=status.HTTP_201_CREATED)
def add_style_rule(request: Request, body: CreateStyleRuleRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_scope_manage(request, repo, body.scope_slug)
    return repo.add_style_rule(rule_text=body.rule_text, scope_slug=body.scope_slug)


@router.delete("/style-rules/{rule_id}")
def delete_style_rule(request: Request, rule_id: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    _, _, _, multi_user, admin = _caller(request)
    if multi_user and not admin:
        existing = next((r for r in repo.list_style_rules() if r["id"] == rule_id), None)
        if existing is not None:
            _require_scope_manage(request, repo, existing.get("scope_slug"))
    try:
        repo.delete_style_rule(rule_id)
        return {"status": "deleted", "id": rule_id}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/style-rules/import", status_code=status.HTTP_201_CREATED)
async def import_style_rules(request: Request, body: ImportMemoryRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, _, caller_email, _, _ = _caller(request)
    _require_scope_manage(request, repo, body.scope_slug)
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
                triggered_by_email=caller_email,
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
    _, _, _, multi_user, admin = _caller(request)
    skills = repo.list_skills(scope_slug=scope_slug)
    if not multi_user or admin:
        return skills
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    known_bots = {b["slug"] for b in repo.list_bots()}
    return [
        s
        for s in skills
        if slugify(str(s.get("scope_slug") or "")) not in known_bots
        or (vis_bots is not None and slugify(str(s.get("scope_slug") or "")) in vis_bots)
    ]


@router.post("/skills", status_code=status.HTTP_201_CREATED)
def upsert_skill(request: Request, body: CreateSkillRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_scope_manage(request, repo, body.scope_slug)
    return repo.upsert_skill(
        name=body.name,
        description=body.description,
        instructions=body.instructions,
        scope_slug=body.scope_slug,
    )


@router.delete("/skills/{skill_id}")
def delete_skill(request: Request, skill_id: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    _, _, _, multi_user, admin = _caller(request)
    if multi_user and not admin:
        existing = next(
            (s for s in repo.list_skills() if s["id"] == skill_id or s.get("slug") == skill_id),
            None,
        )
        if existing is not None:
            _require_scope_manage(request, repo, existing.get("scope_slug"))
    try:
        repo.delete_skill(skill_id)
        return {"status": "deleted", "id": skill_id}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/pages")
def list_pages(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    pages = repo.list_pages()
    if not multi_user or admin:
        return pages
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        p
        for p in pages
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(p),
            visibility=p.get("visibility"),
            allowed_groups=p.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    ]


@router.post("/pages/generate", status_code=status.HTTP_201_CREATED)
async def generate_page(request: Request, body: GeneratePageRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    llm_router, _ = _services(request)
    settings, principal, caller_email = _require_writer_identity(request)
    _, _, _, multi_user, admin = _caller(request)
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
        _require_resource_manage(request, existing_page, kind="Page")

    if body.owner_bot_slug and body.owner_bot_slug.strip():
        try:
            _require_bot_read(request, repo, body.owner_bot_slug.strip())
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    raw_collections = (
        list(body.allowed_collections)
        if body.allowed_collections
        else (list(existing_page.get("allowed_collections") or []) if existing_page else [])
    )
    effective_collections = repo._normalize_page_collections(raw_collections)
    if multi_user and not admin:
        for col in effective_collections:
            if not _can_access_collection(
                repo,
                slug=col,
                caller_email=caller_email,
                multi_user=multi_user,
                admin=admin,
                settings=settings,
            ):
                raise HTTPException(
                    status_code=403,
                    detail=f"Collection '{col}' is private to another user.",
                )

    default_titles = {
        "live_operations_map": "Live Bot Operations Map",
        "bot_hub_board": "Bot Hub Board",
        "interactive_playground": "Interactive Concept Playground",
        "collection_analytics": "Data Explorer & Analytics",
        "data_dashboard": "Live Workspace Dashboard",
    }
    page_title = (
        (body.title or "").strip()
        or (existing_page["title"] if existing_page else "")
        or default_titles[resolved_template]
    )

    html_payload: str | None = None
    has_live_key = any(p.get("api_key") for p in repo.list_model_provider_credentials())
    has_custom_transport = getattr(llm_router, "_transport", None) is not None
    if (
        has_live_key or (body.template_key == "auto" and has_custom_transport)
    ) and resolved_template != "data_dashboard":
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
        raw_bots = repo.list_bots()
        if multi_user and not admin:
            caller_groups = user_group_slugs(caller_email, repo=repo)
            raw_bots = [
                b
                for b in raw_bots
                if can_read_resource(
                    caller_email,
                    owner_email=_res_owner(b),
                    visibility=b.get("visibility"),
                    allowed_groups=b.get("allowed_groups"),
                    caller_groups=caller_groups,
                    settings=settings,
                    repo=repo,
                )
            ]
        compact_bots = [
            {
                "slug": b["slug"],
                "name": b["name"],
                "role": str(b.get("role") or "")[:100],
                "runtime": b.get("runtime", "api"),
            }
            for b in raw_bots
        ]
        existing_block = (
            f"Existing Page HTML to redesign/refine in-place (preserve ARGO_READY / ARGO_PAGE_DATA wiring):\n"
            f"{str(existing_page.get('content_payload') or '')[:48000]}\n\n"
            if existing_page is not None
            else ""
        )
        try:
            res = await llm_router.complete(
                bot_slug=body.owner_bot_slug or "page-generator",
                prompt=(
                    f"{'Redesign/update' if existing_page else 'Generate'} a complete self-contained HTML5 page titled '{page_title}' "
                    f"(layout hint: {resolved_template}) for this request:\n{body.prompt}\n\n"
                    f"{existing_block}"
                    "Theme-Neutral Living Page Design Contract (MUST FOLLOW):\n"
                    "- Use the host-injected Light/Dark [data-theme] CSS variables: var(--bg), var(--surface), var(--card), var(--border), var(--text), var(--muted), var(--accent), var(--good), var(--warn), var(--bad) with clean fallbacks so both Light and Dark themes render legibly.\n"
                    "- Typography: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; crisp contrast, >= 12px secondary labels, 1px solid var(--border) cards with 12px radius. STRICTLY NO neon/fluorescent/cyberpunk colors, NO linear-gradient backgrounds, and NO glowing borders or shadows.\n"
                    "- Match the layout strictly to the user request (e.g., pure searchable table, concise report/brief, card grid, calendar, interactive simulator, or Apache ECharts window.echarts dashboard) — only add KPI tiles or filters when helpful for the request.\n"
                    "- Runtime bridge: post window.parent.postMessage({type:'ARGO_READY'}, '*') on load; use window.Argo (Argo.onData, Argo.querySQL, Argo.mediaCover, Argo.prefillChat) or handle ARGO_PAGE_DATA (msg.data.records) and ARGO_LIVE_STATUS (msg.liveStatus.bots) with initial render from embedded sample_records.\n"
                    "- Never use same-origin sandbox relaxations; client-side file exports (<a download>, Blob, MediaRecorder, or ARGO_DOWNLOAD_FILE postMessage with 15s URL.revokeObjectURL delay) work natively inside Living Pages.\n\n"
                    f"Allowed collections: {effective_collections}\n"
                    f"Sample records: {json.dumps(sample_records[:12], default=str)[:4000]}\n"
                    f"Workspace bots: {json.dumps(compact_bots[:12], default=str)}\n"
                    "Return only valid HTML starting with <!DOCTYPE html>."
                ),
                system_prompt="Return a clean standalone HTML5 Living Page document using semantic CSS variables (var(--bg), var(--card), var(--text), var(--border)) and inline CSS/JS.",
                trigger_type="page_generate",
                hop_count=1,
                triggered_by_email=caller_email,
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
            next_vis, next_groups = _validate_visibility_and_groups(
                request,
                repo,
                visibility=body.visibility,
                allowed_groups=body.allowed_groups,
                existing=existing_page,
            )
            page_updates: dict[str, Any] = {
                "title": page_title,
                "description": body.prompt[:200],
                "render_mode": "sandboxed_html",
                "content_payload": html_payload,
                "allowed_collections": effective_collections,
                "owner_bot_slug": body.owner_bot_slug or existing_page["owner_bot_slug"],
            }
            if body.visibility is not None or body.allowed_groups is not None:
                page_updates["visibility"] = next_vis
                page_updates["allowed_groups"] = next_groups
            saved = repo.update_page(
                existing_page["slug"],
                page_updates,
                caller_email=principal["email"],
                is_admin=(multi_user and admin),
            )
        else:
            vis, groups = _validate_visibility_and_groups(
                request,
                repo,
                visibility=body.visibility,
                allowed_groups=body.allowed_groups,
            )
            saved = repo.create_page(
                title=page_title,
                description=body.prompt[:200],
                render_mode="sandboxed_html",
                content_payload=html_payload,
                allowed_collections=effective_collections,
                owner_bot_slug=body.owner_bot_slug,
                created_by_email=caller_email or principal["email"],
                visibility=vis,
                allowed_groups=groups,
            )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await bus.publish(
        correlation_id=make_id("corr"),
        source_slug=saved["owner_bot_slug"] or "workspace",
        target_slug=saved["slug"],
        event_type="page.updated",
        payload={
            "category": "reviews",
            "title": f"Generated Page: {saved['title']}",
            "badge": resolved_template,
            "badge_tone": "indigo",
            "summary": body.prompt[:200],
            "meta": f"Owner: {saved['owner_bot_slug'] or 'Unassigned'}",
        },
        hop_count=1,
    )
    return saved


@router.post("/pages", status_code=status.HTTP_201_CREATED)
def create_page(request: Request, body: CreatePageRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, principal, caller_email = _require_writer_identity(request)
    _, _, _, multi_user, admin = _caller(request)
    if body.owner_bot_slug and body.owner_bot_slug.strip():
        try:
            _require_bot_read(request, repo, body.owner_bot_slug.strip())
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    if multi_user and not admin:
        for col in body.allowed_collections:
            if not _can_access_collection(
                repo,
                slug=col,
                caller_email=caller_email,
                multi_user=multi_user,
                admin=admin,
                settings=settings,
            ):
                raise HTTPException(
                    status_code=403,
                    detail=f"Collection '{col}' is private to another user.",
                )
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    try:
        return repo.create_page(
            title=body.title,
            description=body.description,
            render_mode=body.render_mode,
            content_payload=body.content_payload,
            allowed_collections=body.allowed_collections,
            owner_bot_slug=body.owner_bot_slug,
            created_by_email=caller_email or principal["email"],
            visibility=vis,
            allowed_groups=groups,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/pages/{slug}")
def get_page(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        page = repo.get_page(slug)
        _require_resource_read(request, page, kind="Page")
        return page
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/pages/{slug}")
async def update_page(request: Request, slug: str, body: UpdatePageRequest) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, principal, caller_email, multi_user, admin = _caller(request)
    try:
        existing_page = repo.get_page(slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    _require_resource_manage(request, existing_page, kind="Page")
    patch_data = body.model_dump(exclude_none=True)
    if body.visibility is not None or body.allowed_groups is not None:
        next_vis, next_groups = _validate_visibility_and_groups(
            request,
            repo,
            visibility=body.visibility,
            allowed_groups=body.allowed_groups,
            existing=existing_page,
        )
        patch_data["visibility"] = next_vis
        patch_data["allowed_groups"] = next_groups
    if patch_data.get("owner_bot_slug"):
        try:
            _require_bot_read(request, repo, str(patch_data["owner_bot_slug"]))
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    if multi_user and not admin and "allowed_collections" in patch_data:
        for col in (patch_data.get("allowed_collections") or []):
            if not _can_access_collection(
                repo,
                slug=str(col),
                caller_email=caller_email,
                multi_user=multi_user,
                admin=admin,
                settings=settings,
            ):
                raise HTTPException(
                    status_code=403,
                    detail=f"Collection '{col}' is private to another user.",
                )
    try:
        updated = repo.update_page(
            slug,
            patch_data,
            caller_email=principal["email"],
            is_admin=(multi_user and admin),
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
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
    _, principal, _, multi_user, admin = _caller(request)
    try:
        existing_page = repo.get_page(slug)
        _require_resource_manage(request, existing_page, kind="Page")
        repo.delete_page(slug, caller_email=principal["email"], is_admin=(multi_user and admin))
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/pages/{slug}/data")
def get_page_data(
    request: Request,
    slug: str,
    q: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    try:
        page = repo.get_page(slug)
        _require_resource_read(request, page, kind="Page")
        return repo.resolve_page_data(
            slug,
            query=q,
            limit=limit,
            owner_email=principal["email"],
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/pages/{slug}/query")
def query_page_collection(
    request: Request,
    slug: str,
    body: PageCollectionQueryRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    try:
        page = repo.get_page(slug)
        _require_resource_read(request, page, kind="Page")
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


@router.post("/pages/{slug}/sql")
def query_page_sql(
    request: Request,
    slug: str,
    body: PageSqlQueryRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, principal, _, _, admin = _caller(request)
    try:
        page = repo.get_page(slug)
        _require_resource_read(request, page, kind="Page")
        clean_viewer = str(principal["email"] or "").strip().lower()
        created_by_email = str(page.get("created_by_email") or "").strip().lower()
        if (
            not admin
            and any(str(c).startswith("file:") for c in (page.get("allowed_collections") or []))
            and created_by_email
            and created_by_email != clean_viewer
        ):
            raise PermissionError(
                f"User '{clean_viewer or 'unknown'}' is not permitted to query files bound to Page '{slug}'."
            )
        res = repo.execute_analytics_query(
            body.sql,
            allowed_collections=list(page.get("allowed_collections") or []),
            owner_email=principal["email"],
            params=body.params,
            row_cap=body.row_cap,
            engine=body.engine,
        )
        return {"page_slug": page["slug"], **res}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=408, detail=str(exc)) from exc
    except (ValueError, sqlite3.Error) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/collections")
def list_collections(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    collections = repo.list_collections()
    if not multi_user or admin:
        return collections
    return [
        c
        for c in collections
        if _can_access_collection(
            repo,
            slug=str(c.get("slug") or ""),
            caller_email=caller_email,
            multi_user=multi_user,
            admin=admin,
            settings=settings,
        )
    ]


@router.post("/collections/{slug}/documents", status_code=status.HTTP_201_CREATED)
def upsert_collection_document(
    request: Request,
    slug: str,
    body: UpsertDocumentRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    clean_slug = collection_slug(slug)
    if clean_slug in _INTERNAL_SYSTEM_COLLECTIONS:
        raise HTTPException(
            status_code=403,
            detail=f"Collection '{clean_slug}' is an internal system collection.",
        )
    if not _can_access_collection(
        repo,
        slug=clean_slug,
        caller_email=caller_email,
        multi_user=multi_user,
        admin=admin,
        settings=settings,
    ):
        raise HTTPException(status_code=403, detail=f"Collection '{clean_slug}' is private to another user.")
    return repo.upsert_document(
        collection=clean_slug,
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
    settings, _, caller_email, multi_user, admin = _caller(request)
    clean_slug = collection_slug(slug)
    if clean_slug in _INTERNAL_SYSTEM_COLLECTIONS:
        raise HTTPException(
            status_code=403,
            detail=f"Collection '{clean_slug}' is an internal system collection.",
        )
    if not _can_access_collection(
        repo,
        slug=clean_slug,
        caller_email=caller_email,
        multi_user=multi_user,
        admin=admin,
        settings=settings,
    ):
        raise HTTPException(status_code=403, detail=f"Collection '{clean_slug}' is private to another user.")
    return repo.search_documents(collection=clean_slug, query=q, limit=limit)


@router.get("/desktops")
def list_desktops(request: Request) -> dict[str, Any]:
    repo = request.app.state.repo
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    desktop_manager = request.app.state.desktop_manager
    data = dict(desktop_manager.list_desktops_status(allowed_bot_slugs=vis_bots))
    sandbox_manager = getattr(request.app.state, "sandbox_manager", None)
    if sandbox_manager is not None:
        sb_status = sandbox_manager.list_sandboxes_status(allowed_bot_slugs=vis_bots)
        data["sandboxes"] = list(sb_status.get("sandboxes") or [])
    return data


@router.get("/sandboxes")
def list_sandboxes(request: Request) -> dict[str, Any]:
    repo = request.app.state.repo
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    sandbox_manager = request.app.state.sandbox_manager
    return sandbox_manager.list_sandboxes_status(allowed_bot_slugs=vis_bots)


@router.post("/sandboxes/stop-all")
async def stop_all_sandboxes(request: Request) -> dict[str, Any]:
    sandbox_manager = request.app.state.sandbox_manager
    _, _, caller_email, multi_user, admin = _caller(request)
    owner_scope = None if (not multi_user or admin) else (caller_email or "__none__")
    stopped = await sandbox_manager.stop_all_sandboxes(
        reason="manual_stop_all",
        owner_email=owner_scope,
    )
    return {"stopped_sandboxes": stopped}


@router.post("/sandboxes/{slug}/start")
async def start_sandbox(request: Request, slug: str) -> dict[str, Any]:
    repo = request.app.state.repo
    sandbox_manager = request.app.state.sandbox_manager
    try:
        clean_slug = validate_sandbox_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await sandbox_manager.ensure_started(clean_slug, reason="manual")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SandboxConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SandboxStartupBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except SandboxRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/sandboxes/{slug}/stop")
async def stop_sandbox(request: Request, slug: str) -> dict[str, Any]:
    repo = request.app.state.repo
    sandbox_manager = request.app.state.sandbox_manager
    try:
        clean_slug = validate_sandbox_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await sandbox_manager.stop_sandbox(clean_slug, reason="manual")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SandboxConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SandboxRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/sandboxes/{slug}/toggle")
async def toggle_sandbox(request: Request, slug: str) -> dict[str, Any]:
    repo = request.app.state.repo
    sandbox_manager = request.app.state.sandbox_manager
    try:
        clean_slug = validate_sandbox_slug(slug)
        bot = _require_bot_manage(request, repo, clean_slug)
        if bot.get("sandbox_state") == "running":
            return await sandbox_manager.stop_sandbox(clean_slug, reason="manual")
        return await sandbox_manager.ensure_started(clean_slug, reason="manual")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SandboxConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SandboxStartupBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except SandboxRuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/sandboxes/sweep-idle")
async def sweep_idle_sandboxes(request: Request) -> dict[str, Any]:
    sandbox_manager = request.app.state.sandbox_manager
    _, _, caller_email, multi_user, admin = _caller(request)
    owner_scope = None if (not multi_user or admin) else (caller_email or "__none__")
    hibernated = await sandbox_manager.sweep_idle_sandboxes(owner_email=owner_scope)
    return {"hibernated_sandboxes": hibernated}


@router.post("/desktops/stop-all")
async def stop_all_desktops(request: Request) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    _, _, caller_email, multi_user, admin = _caller(request)
    owner_scope = None if (not multi_user or admin) else (caller_email or "__none__")
    stopped = await desktop_manager.stop_all_desktops(
        reason="manual_stop_all",
        owner_email=owner_scope,
    )
    return {"stopped_desktops": stopped}


@router.post("/desktops/sweep-idle")
async def sweep_idle_desktops(request: Request) -> dict[str, Any]:
    desktop_manager = request.app.state.desktop_manager
    _, _, caller_email, multi_user, admin = _caller(request)
    owner_scope = None if (not multi_user or admin) else (caller_email or "__none__")
    hibernated = await desktop_manager.sweep_idle_desktops(owner_email=owner_scope)
    return {"hibernated_desktops": hibernated}


@router.post("/desktops/{slug}/toggle")
async def toggle_desktop(request: Request, slug: str) -> dict[str, Any]:
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await desktop_manager.toggle_desktop(clean_slug)
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
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    principal = extract_sso_principal(request)
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await desktop_manager.start_takeover(clean_slug, actor=principal["actor"])
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
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    principal = extract_sso_principal(request)
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await desktop_manager.release_takeover(clean_slug, actor=principal["actor"])
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
    repo = request.app.state.repo
    cdp_bridge = request.app.state.cdp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        return await cdp_bridge.navigate_and_extract(
            clean_slug,
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
    passive: bool = False,
    max_width: int = Query(default=1280, ge=0, le=3840),
) -> Response:
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        bot = _require_bot_read(request, repo, clean_slug)
        if bot["runtime"] != "desktop":
            raise DesktopConfigError(f"Bot '{clean_slug}' is API-only.")

        cached = desktop_manager.get_cached_screenshot(clean_slug)
        if passive:
            if bot["desktop_state"] != "running":
                if cached is not None:
                    png_bytes, meta = cached
                else:
                    raise HTTPException(
                        status_code=404,
                        detail="No cached screenshot while desktop is sleeping.",
                    )
            elif not refresh and cached is not None:
                png_bytes, meta = cached
            else:
                try:
                    png_bytes, meta = await desktop_mcp_bridge.capture_screenshot(
                        clean_slug,
                        max_width=max_width,
                        passive=True,
                    )
                except (DesktopRuntimeError, DesktopMCPError) as exc:
                    if cached is not None:
                        png_bytes, meta = cached
                    else:
                        raise HTTPException(
                            status_code=404,
                            detail="Desktop screen warming up.",
                        ) from exc
        elif not refresh:
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
        _require_bot_read(request, repo, clean_slug)
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
    repo = request.app.state.repo
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_read(request, repo, clean_slug)
        return await desktop_mcp_bridge.inspect_desktop(clean_slug)
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
    repo = request.app.state.repo
    desktop_mcp_bridge = request.app.state.desktop_mcp_bridge
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        res = await desktop_mcp_bridge.execute_action(
            clean_slug,
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
        bot = _require_bot_manage(request, repo, clean_slug)
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
        bot = _require_bot_read(request, repo, clean_slug)
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
        bot = _require_bot_manage(request, repo, clean_slug)
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
        bot = _require_bot_manage(request, repo, clean_slug)
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
    repo = request.app.state.repo
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
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
    repo = request.app.state.repo
    desktop_manager = request.app.state.desktop_manager
    try:
        clean_slug = validate_desktop_slug(slug)
        _require_bot_manage(request, repo, clean_slug)
        req_body = await request.body() if request.method in {"POST", "PUT", "PATCH"} else None
        status_code, media_type, content, resp_headers = await desktop_manager.proxy_selkies_request(
            clean_slug,
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
        settings, _, caller_email, multi_user, _ = _caller(websocket)
        if multi_user and not can_manage_resource(
            caller_email,
            owner_email=_res_owner(bot),
            visibility=bot.get("visibility"),
            settings=settings,
            repo=repo,
        ):
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
    settings, _, caller_email, multi_user, admin = _caller(request)
    items = repo.list_integrations()
    if not multi_user or admin:
        return items
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        acc
        for acc in items
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(acc),
            visibility=acc.get("visibility"),
            allowed_groups=acc.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    ]


@router.post("/integrations", status_code=status.HTTP_201_CREATED)
def upsert_integration(
    request: Request,
    body: UpsertIntegrationRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    existing = _require_integration_slug_writable(request, repo, body.slug)
    resolved_owner = (_res_owner(existing) or caller_email) if existing is not None else caller_email
    resolved_vis, resolved_groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
        existing=existing,
    )
    saved = repo.upsert_integration(
        slug=body.slug,
        provider=body.provider,
        display_name=body.display_name,
        account_identifier=body.account_identifier,
        scopes=body.scopes,
        secrets=body.secrets,
        owner_email=resolved_owner,
        visibility=resolved_vis,
        allowed_groups=resolved_groups,
    )
    mcp_service = getattr(request.app.state, "mcp_service", None)
    if mcp_service is not None:
        mcp_service.invalidate(saved.get("slug") or body.slug)
    return saved


@router.get("/integrations/google/wizard-config")
def get_google_wizard_config(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    google_service, _, _, _ = _connector_services(request)
    settings = request.app.state.settings
    cfg = dict(google_service.get_wizard_config(settings.public_base_url))
    _, _, _, _, vis_ints = _visible_slug_sets(request, repo)
    if vis_ints is not None and isinstance(cfg.get("saved_accounts"), list):
        cfg["saved_accounts"] = [
            acc
            for acc in cfg["saved_accounts"]
            if isinstance(acc, dict) and str(acc.get("slug") or "") in vis_ints
        ]
    return cfg


@router.post("/integrations/google/authorize")
def start_google_oauth(
    request: Request,
    body: StartGoogleOAuthRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    google_service, _, _, _ = _connector_services(request)
    settings, _, caller_email = _require_writer_identity(request)
    _, _, _, _, admin = _caller(request)
    if body.slug and body.slug.strip():
        _require_integration_slug_writable(request, repo, body.slug)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
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
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
            is_admin=admin,
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
        code = 403 if "owned by another user" in str(exc).lower() else 400
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except GoogleOAuthIntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/linkedin/onboard", status_code=status.HTTP_201_CREATED)
async def onboard_linkedin(
    request: Request,
    body: OnboardLinkedInRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, linkedin_service, _, _ = _connector_services(request)
    settings, _, caller_email = _require_writer_identity(request)
    if body.slug and body.slug.strip():
        _require_integration_slug_writable(request, repo, body.slug)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    try:
        return await linkedin_service.onboard_account(
            access_token=body.access_token,
            author_urn=body.author_urn,
            linkedin_version=body.linkedin_version,
            slug=body.slug,
            display_name=body.display_name,
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
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
    repo, _, _, _ = _deps(request)
    _, linkedin_service, _, _ = _connector_services(request)
    _require_integration_slug_writable(request, repo, slug)
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
    repo, _, _, _ = _deps(request)
    _, _, webhook_service, _ = _connector_services(request)
    settings, _, caller_email = _require_writer_identity(request)
    derived_slug = slugify(body.slug or body.display_name)
    _require_integration_slug_writable(request, repo, derived_slug)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    try:
        return await webhook_service.onboard_webhook(
            display_name=body.display_name,
            slug=body.slug,
            signing_secret=body.signing_secret,
            event_type=body.event_type,
            target_collection=body.target_collection,
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
        )
    except WebhookConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/integrations/telegram/onboard", status_code=status.HTTP_201_CREATED)
async def onboard_telegram_bot(
    request: Request,
    body: OnboardTelegramRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, telegram_service = _services(request)
    settings, _, caller_email = _require_writer_identity(request)
    if body.slug and body.slug.strip():
        _require_integration_slug_writable(request, repo, body.slug)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
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
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
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
    repo, _, _, _ = _deps(request)
    _, telegram_service = _services(request)
    settings, _, caller_email = _require_writer_identity(request)
    raw_handle_tail = body.channel_handle.strip().rstrip("/").split("/")[-1].lstrip("@")
    if body.slug and body.slug.strip():
        _require_integration_slug_writable(request, repo, body.slug)
    elif raw_handle_tail:
        _require_integration_slug_writable(request, repo, f"tg-pub-{raw_handle_tail}")
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    try:
        return await telegram_service.onboard_public_monitor(
            channel_handle=body.channel_handle,
            slug=body.slug,
            display_name=body.display_name,
            sync_immediately=body.sync_immediately,
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
        )
    except (TelegramConfigError, SSRFBlockedError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (AntiBotHaltError, PublicFetchError, TelegramIntegrationError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/integrations/probe-all")
async def probe_all_integrations(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, _, _, connector_manager = _connector_services(request)
    _, _, _, _, vis_ints = _visible_slug_sets(request, repo)
    if vis_ints is None:
        return await connector_manager.probe_all_integrations()
    results: list[dict[str, Any]] = []
    ok_c = 0
    deg_c = 0
    exp_c = 0
    for acc_slug in sorted(vis_ints):
        try:
            probe_res = await connector_manager.probe_integration(acc_slug)
        except Exception as exc:
            probe_res = {
                "slug": acc_slug,
                "provider": "unknown",
                "status": "degraded",
                "last_error": str(exc),
            }
        st = str(probe_res.get("status") or "")
        if st == "ok":
            ok_c += 1
        elif st == "expired":
            exp_c += 1
        else:
            deg_c += 1
        results.append(
            {
                "slug": str(probe_res.get("slug") or acc_slug),
                "provider": str(probe_res.get("provider") or "unknown"),
                "status": st or "degraded",
                "last_error": probe_res.get("last_error"),
            }
        )
    return {
        "total": len(results),
        "ok": ok_c,
        "degraded": deg_c,
        "expired": exp_c,
        "results": results,
    }


@router.post("/integrations/{slug}/sync")
async def sync_telegram_integration(
    request: Request,
    slug: str,
    body: SyncTelegramPublicRequest | None = None,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, telegram_service = _services(request)
    _require_integration_slug_writable(request, repo, slug)
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
    repo, _, _, _ = _deps(request)
    _, _, _, connector_manager = _connector_services(request)
    _require_integration_slug_writable(request, repo, slug)
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
        MCPConfigError,
    ) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (
        TelegramIntegrationError,
        GoogleOAuthIntegrationError,
        LinkedInIntegrationError,
        MCPClientError,
    ) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.delete("/integrations/{slug}")
def delete_integration(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    _require_integration_slug_writable(request, repo, slug)
    try:
        repo.delete_integration(slug)
        mcp_service = getattr(request.app.state, "mcp_service", None)
        if mcp_service is not None:
            mcp_service.invalidate(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/vault")
def list_vault_secrets(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    items = repo.list_vault_secrets()
    if not multi_user or admin:
        return items
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        v
        for v in items
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(v),
            visibility=v.get("visibility"),
            allowed_groups=v.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    ]


@router.post("/vault", status_code=status.HTTP_201_CREATED)
def upsert_vault_secret(request: Request, body: VaultSecretUpsertRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    derived_slug = slugify(body.slug or body.name)
    existing = _require_vault_slug_writable(request, repo, derived_slug)
    resolved_owner = (_res_owner(existing) or caller_email) if existing is not None else caller_email
    resolved_vis, resolved_groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
        existing=existing,
    )
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
            trusted_command_prefixes=body.trusted_command_prefixes,
            owner_email=resolved_owner,
            visibility=resolved_vis,
            allowed_groups=resolved_groups,
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
    _require_resource_manage(request, existing, kind="Vault secret")
    next_vis, next_groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
        existing=existing,
    )
    return repo.upsert_vault_secret(
        name=body.name or existing["name"],
        slug=existing["slug"],
        secret_type=body.secret_type or existing["secret_type"],
        host=body.host if body.host is not None else existing["host"],
        port=body.port if body.port is not None else existing["port"],
        url=body.url if body.url is not None else existing["url"],
        secrets=body.secrets,
        clear_fields=body.clear_fields,
        allowed_bots=body.allowed_bots if body.allowed_bots is not None else existing["allowed_bots"],
        trusted_command_prefixes=(
            body.trusted_command_prefixes
            if body.trusted_command_prefixes is not None
            else existing.get("trusted_command_prefixes")
        ),
        owner_email=_res_owner(existing) or existing.get("owner_email") or "",
        visibility=next_vis,
        allowed_groups=next_groups,
    )


@router.delete("/vault/{slug}")
def delete_vault_secret(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    _require_vault_slug_writable(request, repo, slug)
    try:
        repo.delete_vault_secret(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/vault/bulk-ssh", status_code=status.HTTP_201_CREATED)
def bulk_create_ssh_vault(
    request: Request,
    body: VaultBulkSSHRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    raw_lines = [
        ln.strip()
        for ln in body.hosts_text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not raw_lines:
        raise HTTPException(status_code=400, detail="Provide at least one host or IP line.")
    default_port_raw = body.port.strip() or "22"
    try:
        default_port = int(default_port_raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid SSH port '{default_port_raw}'.") from exc

    validated_hosts: list[str] = []
    for line in raw_lines:
        try:
            norm_host, norm_port = validate_ssh_target_not_self(
                line,
                port=default_port,
                resolve_dns=False,
            )
            validated_hosts.append(f"{norm_host}:{norm_port}" if norm_port != default_port else norm_host)
        except SSHTargetBlockedError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    clean_prefix = (body.name_prefix or "SSH Server").strip() or "SSH Server"
    for target in validated_hosts:
        _require_vault_slug_writable(request, repo, f"{clean_prefix}-{target}")

    created = repo.bulk_create_ssh_vault_secrets(
        name_prefix=body.name_prefix,
        hosts=validated_hosts,
        port=str(default_port),
        secrets=body.secrets,
        allowed_bots=body.allowed_bots,
        owner_email=caller_email,
        visibility=vis,
        allowed_groups=groups,
    )
    return {"created": created, "count": len(created)}


@router.post("/vault/{slug}/reset-host-key")
def reset_vault_host_key(
    request: Request,
    slug: str,
    body: VaultResetHostKeyRequest | None = None,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    extract_sso_principal(request)
    _require_vault_slug_writable(request, repo, slug)
    try:
        return repo.reset_vault_host_key(slug, body.host_port if body else None)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/settings/ssh-audit")
def get_ssh_audit_settings(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    extract_sso_principal(request)
    settings = request.app.state.settings
    return repo.get_ssh_audit_settings(default_retention_hours=settings.ssh_default_retention_hours)


@router.patch("/settings/ssh-audit")
def update_ssh_audit_settings(
    request: Request,
    body: SSHAuditSettingsUpdateRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    return repo.update_ssh_audit_settings(body.retention_hours)


@router.get("/settings/chat-retention")
def get_chat_retention_settings(request: Request) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    extract_sso_principal(request)
    return repo.get_chat_retention_settings()


@router.patch("/settings/chat-retention")
async def update_chat_retention_settings(
    request: Request,
    body: ChatRetentionSettingsUpdateRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    _require_admin(request)
    updated = repo.update_chat_retention_settings(body.retention_days)
    pruned = {"pruned_bot_messages": 0, "pruned_room_messages": 0, "pruned_total": 0}
    if body.prune_now and body.retention_days > 0:
        pruned = repo.prune_expired_chat_messages(body.retention_days)
        updated = repo.get_chat_retention_settings()
        if pruned["pruned_total"] > 0:
            await bus.publish(
                correlation_id=make_id("corr"),
                source_slug="system",
                target_slug="*",
                event_type="thread.cleared",
                payload={
                    "target_type": "all",
                    "slug": "*",
                    "deleted_count": pruned["pruned_total"],
                    "retention_days": body.retention_days,
                },
            )
    return {
        **updated,
        "pruned_bot_messages": pruned["pruned_bot_messages"],
        "pruned_room_messages": pruned["pruned_room_messages"],
        "pruned_total": pruned["pruned_total"],
    }


@router.get("/ssh/sessions")
def list_ssh_sessions(
    request: Request,
    bot_slug: str | None = Query(default=None),
    include_closed: bool = Query(default=True),
) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is None:
        return []
    clean_bot = slugify(bot_slug) if bot_slug and bot_slug.strip() else None
    if clean_bot is not None:
        try:
            _require_bot_read(request, repo, clean_bot)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    sessions = ssh_manager.list_sessions(bot_slug=clean_bot, include_closed=include_closed)
    if vis_bots is None:
        return sessions
    return [s for s in sessions if str(s.get("bot_slug") or "") in vis_bots]


@router.get("/ssh/sessions/{session_id}/cast")
def get_ssh_session_cast(
    request: Request,
    session_id: str,
    format: str = Query(default="ndjson"),
) -> Response:
    del format
    repo, _, _, _ = _deps(request)
    extract_sso_principal(request)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is None:
        raise HTTPException(status_code=404, detail="SSH subsystem is unavailable.")
    live_sess = ssh_manager.get_session(session_id)
    sess_bot_slug = str(getattr(live_sess, "bot_slug", "") or "")
    if not sess_bot_slug:
        hist_match = next(
            (s for s in ssh_manager.list_sessions(include_closed=True) if s.get("session_id") == session_id),
            None,
        )
        sess_bot_slug = str(hist_match.get("bot_slug") or "") if hist_match else ""
    if sess_bot_slug:
        with contextlib.suppress(NotFoundError):
            _require_bot_read(request, repo, sess_bot_slug)
    try:
        cast_path, sha_hex = ssh_manager.get_cast_path_for_session(session_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    ndjson_text = read_cast_ndjson(cast_path, repo.collect_all_vault_secret_values())
    headers = {"X-Cast-Sha256": sha_hex} if sha_hex else {}
    return Response(
        content=ndjson_text,
        media_type="application/x-ndjson; charset=utf-8",
        headers=headers,
    )


@router.post("/ssh/sessions/{session_id}/takeover")
async def takeover_ssh_session(request: Request, session_id: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is None:
        raise HTTPException(status_code=404, detail="SSH subsystem is unavailable.")
    session = ssh_manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"SSH session '{session_id}' not found.")
    with contextlib.suppress(NotFoundError):
        _require_bot_manage(request, repo, session.bot_slug)
    try:
        return await ssh_manager.takeover(session_id, actor=principal["actor"])
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/ssh/sessions/{session_id}/handback")
async def handback_ssh_session(request: Request, session_id: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is None:
        raise HTTPException(status_code=404, detail="SSH subsystem is unavailable.")
    session = ssh_manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"SSH session '{session_id}' not found.")
    with contextlib.suppress(NotFoundError):
        _require_bot_manage(request, repo, session.bot_slug)
    try:
        return await ssh_manager.handback(session_id, actor=principal["actor"])
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/ssh/sessions/{session_id}/control")
async def control_ssh_session(
    request: Request,
    session_id: str,
    body: SSHSessionControlRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    principal = extract_sso_principal(request)
    ssh_manager = getattr(request.app.state, "ssh_manager", None)
    if ssh_manager is None:
        raise HTTPException(status_code=404, detail="SSH subsystem is unavailable.")
    session = ssh_manager.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"SSH session '{session_id}' not found.")
    with contextlib.suppress(NotFoundError):
        _require_bot_manage(request, repo, session.bot_slug)
    try:
        return await ssh_manager.control_session(
            session_id,
            operation=body.operation,
            reason=body.reason,
            actor=principal["actor"],
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.websocket("/ssh/sessions/{session_id}/ws")
async def ssh_session_websocket(websocket: WebSocket, session_id: str) -> None:
    repo = websocket.app.state.repo
    settings, _, caller_email, multi_user, _ = _caller(websocket)
    ssh_manager = getattr(websocket.app.state, "ssh_manager", None)
    if ssh_manager is None:
        await websocket.close(code=1008)
        return
    session = ssh_manager.get_session(session_id)
    if session is None or session.status == "closed":
        await websocket.close(code=1008)
        return
    if multi_user and getattr(session, "bot_slug", ""):
        try:
            bot_obj = repo.get_bot(session.bot_slug)
        except NotFoundError:
            await websocket.close(code=1008)
            return
        if not can_manage_resource(
            caller_email,
            owner_email=_res_owner(bot_obj),
            visibility=bot_obj.get("visibility"),
            settings=settings,
            repo=repo,
        ):
            await websocket.close(code=1008)
            return

    await websocket.accept()
    ws_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
    session.ws_subscribers.add(ws_queue)
    try:
        screen_lines = ssh_manager._scrub_text(session.vt.render_text())
        crlf_screen = "\r\n".join(screen_lines.splitlines())
        await websocket.send_text(
            json.dumps(
                {
                    "type": "snapshot",
                    "data": crlf_screen,
                    "status": session.status,
                    "operator_takeover": session.operator_takeover,
                    "paused": session.paused,
                    "pinned": session.pinned,
                }
            )
        )

        async def _ws_to_ssh() -> None:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                raw_text = msg.get("text")
                raw_bytes = msg.get("bytes")
                if raw_text is not None:
                    stripped = raw_text.strip()
                    if stripped.startswith("{"):
                        try:
                            frame = json.loads(stripped)
                        except json.JSONDecodeError:
                            frame = None
                        if isinstance(frame, dict):
                            f_type = str(frame.get("type") or "")
                            if f_type == "input":
                                ok = await ssh_manager.send_operator_ws_input(
                                    session_id, str(frame.get("data") or "")
                                )
                                if not ok:
                                    await websocket.send_text(
                                        json.dumps(
                                            {
                                                "type": "locked",
                                                "detail": "Read-only preview. Click 'Take Over' to type.",
                                            }
                                        )
                                    )
                            elif f_type == "resize":
                                await ssh_manager.resize_session(
                                    session_id,
                                    int(frame.get("cols") or 120),
                                    int(frame.get("rows") or 36),
                                )
                            continue
                    ok = await ssh_manager.send_operator_ws_input(session_id, raw_text)
                    if not ok:
                        await websocket.send_text(
                            json.dumps(
                                {
                                    "type": "locked",
                                    "detail": "Read-only preview. Click 'Take Over' to type.",
                                }
                            )
                        )
                elif raw_bytes is not None:
                    await ssh_manager.send_operator_ws_input(
                        session_id, raw_bytes.decode("utf-8", errors="replace")
                    )

        async def _ssh_to_ws() -> None:
            while True:
                ev = await ws_queue.get()
                await websocket.send_text(json.dumps(ev))
                if ev.get("type") == "closed":
                    break

        t_in = asyncio.create_task(_ws_to_ssh())
        t_out = asyncio.create_task(_ssh_to_ws())
        try:
            _, pending = await asyncio.wait(
                {t_in, t_out},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await t
        except WebSocketDisconnect:
            for t in (t_in, t_out):
                t.cancel()
    finally:
        session.ws_subscribers.discard(ws_queue)


@router.get("/models")
def list_models(request: Request, model_id: str | None = None) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    if (multi_user or is_auth_rbac_active(settings)) and not admin:
        vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
        return repo.list_models(
            model_id=model_id,
            allowed_bot_slugs=vis_bots,
            viewer_email=caller_email,
        )
    return repo.list_models(model_id=model_id)


@router.post("/models/discover")
async def discover_models(request: Request, body: DiscoverModelsRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    api_key = (body.api_key or "").strip() or None
    api_base = (body.api_base or "").strip() or None

    if not api_key or not api_base:
        stored: dict[str, Any] | None = None
        if body.provider_slug:
            stored = repo.get_model_provider_credentials(body.provider_slug)
        if stored is None:
            for item in repo.list_model_provider_credentials():
                if item["provider_type"] == body.provider_type and (
                    item.get("api_key") or item.get("api_base")
                ):
                    stored = item
                    break
        if stored is not None:
            if not api_key and stored.get("api_key"):
                api_key = str(stored["api_key"])
            if not api_base and stored.get("api_base"):
                api_base = str(stored["api_base"])

    try:
        return await discover_provider_models(
            body.provider_type,
            api_key=api_key,
            api_base=api_base,
        )
    except ModelConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LLMExecutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/models", status_code=status.HTTP_201_CREATED)
def upsert_model(request: Request, body: UpsertModelRequest) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
    return repo.upsert_model(
        slug=body.slug,
        provider_type=body.provider_type,
        model_id=body.model_id,
        api_base=body.api_base,
        api_key=body.api_key,
        is_default=body.is_default,
        daily_token_limit=body.daily_token_limit,
        monthly_budget_usd=body.monthly_budget_usd,
        input_price_per_million=body.input_price_per_million,
        output_price_per_million=body.output_price_per_million,
    )


@router.post("/models/{slug}/default")
def set_default_model(request: Request, slug: str) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _require_admin(request)
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
    _, _, caller_email = _require_admin(request)
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
            triggered_by_email=caller_email,
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
    _require_admin(request)
    try:
        repo.delete_model(slug)
        return {"status": "deleted", "slug": slug}
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/scheduler/jobs")
def list_scheduler_jobs(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    vis_bots, _, _, _, _ = _visible_slug_sets(request, repo)
    scheduler = getattr(request.app.state, "bot_scheduler", None)
    jobs = scheduler.list_scheduled_jobs() if scheduler is not None else []
    if vis_bots is None:
        return jobs
    return [j for j in jobs if str(j.get("bot_slug") or "") in vis_bots]


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
    _require_admin(request)
    _, telegram_service = _services(request)
    desktop_manager = getattr(request.app.state, "desktop_manager", None)
    sandbox_manager = getattr(request.app.state, "sandbox_manager", None)
    return await guard.evaluate_and_enforce(
        repo=repo,
        bus=bus,
        telegram=telegram_service,
        desktop_manager=desktop_manager,
        sandbox_manager=sandbox_manager,
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
    _require_admin(request)
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
    _require_admin(request)
    debug_buffer = getattr(request.app.state, "debug_buffer", None)
    cleared_logs = debug_buffer.clear() if debug_buffer is not None else 0
    cleared_traces = repo.delete_collection("debug_run_traces")
    return {"cleared_logs": cleared_logs, "cleared_traces": cleared_traces}


# ------------------------------------------------------------------
# Per-User Unread Cursors, Message Reactions & Delegation Plans
# ------------------------------------------------------------------
def _validate_delegation_plan_steps_read(
    request: Request,
    repo: ArgoRepository,
    steps: list[Any],
) -> None:
    """Ensure every existing specialist bot referenced by a delegation plan is readable."""
    for st in steps:
        if not isinstance(st, dict):
            continue
        b_slug = slugify(str(st.get("bot_slug") or st.get("target_bot") or ""))
        if not b_slug:
            continue
        try:
            _require_bot_read(request, repo, b_slug)
        except NotFoundError:
            continue


@router.post("/threads/read")
def mark_thread_read_endpoint(
    request: Request,
    body: MarkThreadReadRequest,
) -> dict[str, Any]:
    repo, _, _, _ = _deps(request)
    _, principal, caller_email = _require_writer_identity(request)
    try:
        if body.target_type == "room":
            room = repo.get_room(body.slug)
            _require_resource_read(request, room, kind="Room")
        else:
            _require_bot_read(request, repo, body.slug)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return repo.mark_thread_read(
        user_email=caller_email or principal["email"],
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
    settings, principal, caller_email = _require_writer_identity(request)
    if is_multi_user_enabled(settings):
        with repo._lock:
            row = repo._conn.execute(
                "SELECT doc_json FROM collection_documents WHERE collection = ? AND id = ?",
                (body.collection, message_id),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Message '{message_id}' not found.")
        try:
            doc = json.loads(row["doc_json"])
        except Exception:
            doc = {}
        if body.collection == "bot_threads" and doc.get("bot_slug"):
            try:
                _require_bot_read(request, repo, str(doc["bot_slug"]))
            except NotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        elif body.collection == "room_threads" and doc.get("room_slug"):
            try:
                room = repo.get_room(str(doc["room_slug"]))
                _require_resource_read(request, room, kind="Room")
            except NotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
        else:
            _require_admin(request)
    try:
        return repo.toggle_message_reaction(
            collection=body.collection,
            message_id=message_id,
            emoji=body.emoji,
            actor=caller_email or principal["email"],
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
    _, principal, caller_email = _require_writer_identity(request)
    bot_runner = request.app.state.bot_runner
    req_body = body or ExecuteDelegationPlanRequest()
    try:
        _require_bot_read(request, repo, slug)
        plan = repo.get_delegation_plan(plan_id)
        if plan.get("coordinator_slug") and slugify(slug) != slugify(str(plan["coordinator_slug"])):
            raise HTTPException(status_code=400, detail="Plan does not belong to this coordinator bot.")
        if plan.get("room_slug"):
            _require_resource_read(request, repo.get_room(str(plan["room_slug"])), kind="Room")
        steps_to_check = (
            list(req_body.edited_steps)
            if req_body.edited_steps is not None
            else list(plan.get("steps") or [])
        )
        _validate_delegation_plan_steps_read(request, repo, steps_to_check)
        return await bot_runner.execute_delegation_plan(
            plan_id,
            operator_email=caller_email or principal["email"],
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
    _, principal, caller_email = _require_writer_identity(request)
    bot_runner = request.app.state.bot_runner
    req_body = body or ExecuteDelegationPlanRequest()
    try:
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
        plan = repo.get_delegation_plan(plan_id)
        if plan.get("room_slug") and slugify(str(plan["room_slug"])) != room["slug"]:
            raise HTTPException(status_code=400, detail="Plan does not belong to this room.")
        if plan.get("coordinator_slug"):
            _require_bot_read(request, repo, str(plan["coordinator_slug"]))
        steps_to_check = (
            list(req_body.edited_steps)
            if req_body.edited_steps is not None
            else list(plan.get("steps") or [])
        )
        _validate_delegation_plan_steps_read(request, repo, steps_to_check)
        return await bot_runner.execute_delegation_plan(
            plan_id,
            operator_email=caller_email or principal["email"],
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
def _validate_room_references(
    request: Request,
    repo: ArgoRepository,
    *,
    member_bot_slugs: list[str],
    pinned_page_slug: str | None,
    visibility: str,
    allowed_groups: list[str] | None = None,
    strict_missing_page: bool = True,
) -> None:
    """Validate read ACLs and scope-subset consistency for a Room's bots and pinned page."""
    settings, _, caller_email, multi_user, _ = _caller(request)
    if not multi_user:
        return
    for raw_member in member_bot_slugs:
        m_slug = slugify(str(raw_member or ""))
        if not m_slug:
            continue
        try:
            bot = _require_bot_read(request, repo, m_slug)
        except NotFoundError:
            continue
        if not is_scope_subset(
            visibility,
            allowed_groups,
            bot.get("visibility"),
            bot.get("allowed_groups"),
            child_owner=caller_email,
            parent_owner=_res_owner(bot),
            settings=settings,
            repo=repo,
        ):
            raise HTTPException(
                status_code=403,
                detail=f"Room scope ({visibility}) cannot include narrower bot '{m_slug}'.",
            )
    if pinned_page_slug and str(pinned_page_slug).strip():
        try:
            page = repo.get_page(slugify(str(pinned_page_slug)))
        except NotFoundError as exc:
            if strict_missing_page:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            return
        _require_resource_read(request, page, kind="Page")
        if not is_scope_subset(
            visibility,
            allowed_groups,
            page.get("visibility"),
            page.get("allowed_groups"),
            child_owner=caller_email,
            parent_owner=_res_owner(page),
            settings=settings,
            repo=repo,
        ):
            raise HTTPException(
                status_code=403,
                detail=f"Room scope ({visibility}) cannot pin narrower page '{page['slug']}'.",
            )


@router.get("/rooms")
def list_rooms_endpoint(request: Request) -> list[dict[str, Any]]:
    repo, _, _, _ = _deps(request)
    settings, _, caller_email, multi_user, admin = _caller(request)
    rooms = repo.list_rooms()
    if not multi_user or admin:
        return rooms
    caller_groups = user_group_slugs(caller_email, repo=repo)
    return [
        r
        for r in rooms
        if can_read_resource(
            caller_email,
            owner_email=_res_owner(r),
            visibility=r.get("visibility"),
            allowed_groups=r.get("allowed_groups"),
            caller_groups=caller_groups,
            settings=settings,
            repo=repo,
        )
    ]


@router.post("/rooms", status_code=status.HTTP_201_CREATED)
async def create_room_endpoint(
    request: Request,
    body: CreateRoomRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    vis, groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
    )
    _validate_room_references(
        request,
        repo,
        member_bot_slugs=body.member_bot_slugs,
        pinned_page_slug=body.pinned_page_slug,
        visibility=vis,
        allowed_groups=groups,
        strict_missing_page=True,
    )
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
            owner_email=caller_email,
            visibility=vis,
            allowed_groups=groups,
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
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
        return room
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
        prev_room = repo.get_room(slug)
        _require_resource_manage(request, prev_room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    patch_data = body.model_dump(exclude_none=True)
    next_visibility, next_groups = _validate_visibility_and_groups(
        request,
        repo,
        visibility=body.visibility,
        allowed_groups=body.allowed_groups,
        existing=prev_room,
    )
    if body.visibility is not None or body.allowed_groups is not None:
        patch_data["visibility"] = next_visibility
        patch_data["allowed_groups"] = next_groups
    effective_members = (
        body.member_bot_slugs
        if body.member_bot_slugs is not None
        else list(prev_room.get("member_bot_slugs") or [])
    )
    effective_pinned_page = (
        body.pinned_page_slug
        if "pinned_page_slug" in patch_data
        else prev_room.get("pinned_page_slug")
    )
    _validate_room_references(
        request,
        repo,
        member_bot_slugs=effective_members,
        pinned_page_slug=effective_pinned_page,
        visibility=next_visibility,
        allowed_groups=next_groups,
        strict_missing_page=("pinned_page_slug" in patch_data and bool(body.pinned_page_slug)),
    )
    try:
        return repo.update_room(slug, patch_data)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/rooms/{slug}")
async def delete_room_endpoint(request: Request, slug: str) -> dict[str, str]:
    repo, _, _, _ = _deps(request)
    try:
        room = repo.get_room(slug)
        _require_resource_manage(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    bot_runner = getattr(request.app.state, "bot_runner", None)
    if bot_runner is not None and hasattr(bot_runner, "cancel_thread_runs"):
        with contextlib.suppress(Exception):
            await bot_runner.cancel_thread_runs(f"room:{room['slug']}")
    try:
        repo.delete_room(room["slug"])
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
    _, principal, caller_email, _, _ = _caller(request)
    try:
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    messages, has_more, total_count = repo.list_room_messages_window(
        slug, limit=limit, before_id=before_id
    )
    if before_id is None:
        repo.mark_thread_read(
            user_email=caller_email or principal["email"],
            target_type="room",
            slug=slug,
        )
    response.headers["X-Has-More"] = "true" if has_more else "false"
    response.headers["X-Total-Count"] = str(total_count)
    return messages


@router.delete("/rooms/{slug}/messages")
async def clear_room_messages_endpoint(
    request: Request,
    slug: str,
    keep_last: int = Query(default=0, ge=0, le=500),
    older_than_days: int | None = Query(default=None, ge=1, le=3650),
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    try:
        room = repo.get_room(slug)
        _require_resource_manage(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return await _clear_thread_messages_response(
        request=request,
        repo=repo,
        bus=bus,
        target_type="room",
        target_slug=room["slug"],
        keep_last=keep_last,
        older_than_days=older_than_days,
    )


@router.get("/rooms/{slug}/messages/export")
def export_room_messages_endpoint(
    request: Request,
    slug: str,
) -> Response:
    repo, _, _, _ = _deps(request)
    try:
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    messages = repo.list_room_messages(room["slug"], limit=None)
    md = _format_transcript_markdown(
        title=room["title"],
        target_type="room",
        messages=messages,
        secrets=repo.collect_all_vault_secret_values(),
    )
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{room["slug"]}-room-chat.md"'},
    )


@router.patch("/rooms/{slug}/messages/{message_id}")
async def edit_last_room_message_endpoint(
    request: Request,
    slug: str,
    message_id: str,
    body: EditLastMessageRequest,
) -> Any:
    repo, _, _, _ = _deps(request)
    _, principal, caller_email = _require_writer_identity(request)
    effective_email = caller_email or principal["email"]
    bot_runner = getattr(request.app.state, "bot_runner", None)
    clean_text = body.text.strip()
    if not clean_text:
        raise HTTPException(status_code=400, detail="Edited message text cannot be empty.")
    try:
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    bots_by_slug = {b["slug"]: b for b in repo.list_bots()}
    member_order = list(room.get("stage_order") or room["member_bot_slugs"])
    if not any(s in bots_by_slug for s in member_order):
        raise HTTPException(status_code=400, detail=f"Room '{room['slug']}' has no active bots.")
    if bot_runner is not None and bot_runner.has_active_thread_run(f"room:{room['slug']}"):
        raise HTTPException(
            status_code=409,
            detail="Wait for the current reply to finish or stop it before editing your message.",
        )
    try:
        rewound = repo.rewind_last_user_message(
            target_type="room",
            target_slug=room["slug"],
            message_id=message_id,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    preserved = _extract_rewind_submission_meta(repo, effective_email, rewound["original_metadata"])
    res = await post_room_message_endpoint(
        request,
        room["slug"],
        AppendRoomMessageRequest(
            text=clean_text,
            reply_to_id=preserved["reply_to_id"],
            attachment_ids=preserved["attachment_ids"],
            skill_slugs=preserved["skill_slugs"],
            target_page_slug=preserved["target_page_slug"],
            async_mode=body.async_mode,
        ),
    )
    return _merge_removed_ids_response(res, rewound["deleted_ids"])


@router.post("/rooms/{slug}/messages")
async def post_room_message_endpoint(
    request: Request,
    slug: str,
    body: AppendRoomMessageRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    _, principal, caller_email = _require_writer_identity(request)
    effective_email = caller_email or principal["email"]
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

    try:
        room = repo.get_room(slug)
        _require_resource_read(request, room, kind="Room")
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if body.target_page_slug and body.target_page_slug.strip():
        try:
            _require_resource_read(
                request,
                repo.get_page(slugify(body.target_page_slug)),
                kind="Page",
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    if body.approved_handoff_bot_slug and body.approved_handoff_bot_slug.strip():
        try:
            _require_bot_read(request, repo, body.approved_handoff_bot_slug)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    if body.async_mode:
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
                fmeta, _ = repo.get_workspace_file(fid, owner_email=effective_email)
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
            repo.mark_thread_read(user_email=effective_email, target_type="room", slug=room["slug"])

        corr_id = make_id("roomturn")

        async def _run_async_room_turn(run_item: Any) -> dict[str, Any]:
            result = await bot_runner.execute_room_turn(
                room["slug"],
                user_text=body.text,
                operator_email=effective_email,
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
            room["slug"],
            user_text=body.text,
            operator_email=effective_email,
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


# ------------------------------------------------------------------
# Per-User Shared Workspace Files (Strict SSO Owner Isolation, 10 MB / 100 MB Cap)
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
        try:
            return await asyncio.to_thread(
                repo.save_workspace_file,
                owner_email=principal["email"],
                filename=parsed.filename,
                mime_type=parsed.mime_type,
                content_bytes=content_bytes,
                uploaded_by="user",
            )
        except FileTooLargeError as exc:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    raw_name = (
        request.headers.get("x-file-name")
        or request.query_params.get("filename")
        or "attachment.bin"
    )
    filename = urllib.parse.unquote(raw_name).strip() or "attachment.bin"
    mime_type = content_type.split(";", 1)[0].strip() or "application/octet-stream"
    byte_limit = max_workspace_file_bytes_for_name(filename, mime_type)
    limit_mb = byte_limit // (1024 * 1024)

    tmp_dir = repo.workspace_tmp_dir()
    tmp_path: Path | None = None
    total_bytes = 0
    hasher = hashlib.sha256()
    try:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as tf:
            tmp_path = Path(tf.name)
            async for chunk in request.stream():
                if not chunk:
                    continue
                total_bytes += len(chunk)
                if total_bytes > byte_limit:
                    tf.close()
                    tmp_path.unlink(missing_ok=True)
                    tmp_path = None
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=f"File exceeds {limit_mb} MB per-file upload limit.",
                    )
                tf.write(chunk)
                hasher.update(chunk)
        return await asyncio.to_thread(
            repo.save_workspace_file_from_path,
            owner_email=principal["email"],
            filename=filename,
            mime_type=mime_type,
            source_path=tmp_path,
            size_bytes=total_bytes,
            sha256_hex=hasher.hexdigest(),
            uploaded_by="user",
        )
    except HTTPException:
        raise
    except FileTooLargeError as exc:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


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
    mime = str(meta.get("mime_type") or "application/octet-stream")
    disposition = "attachment" if (download or mime in {"text/html", "image/svg+xml"}) else "inline"
    raw_filename = str(meta.get("filename") or "download").strip() or "download"
    ascii_name = re.sub(r"[^A-Za-z0-9._ -]", "_", raw_filename).strip() or "download"
    quoted_name = urllib.parse.quote(raw_filename, safe="")
    return FileResponse(
        path=fpath,
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
    settings, _, caller_email, multi_user, admin = _caller(request)
    parsed_bots = [s.strip() for s in (bot_slugs or "").split(",") if s.strip()] or None
    parsed_rooms = [room_slug.strip()] if room_slug and room_slug.strip() else None
    vis_bots, _, vis_rooms, vis_pages, _ = _visible_slug_sets(request, repo)
    if multi_user and not admin:
        assert vis_bots is not None and vis_rooms is not None
        if parsed_rooms:
            for r_slug in parsed_rooms:
                try:
                    room = repo.get_room(r_slug)
                except NotFoundError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc
                _require_resource_read(request, room, kind="Room")
                for m_slug in room.get("member_bot_slugs") or []:
                    if m_slug not in vis_bots:
                        raise HTTPException(
                            status_code=403,
                            detail=f"Room references private bot '{m_slug}'.",
                        )
        if parsed_bots:
            for b_slug in parsed_bots:
                try:
                    _require_bot_read(request, repo, b_slug)
                except NotFoundError as exc:
                    raise HTTPException(status_code=404, detail=str(exc)) from exc
        elif not parsed_rooms:
            sec_lower = (section or "").strip().lower()
            eligible = [
                b["slug"]
                for b in repo.list_bots()
                if b["slug"] in vis_bots
                and (not sec_lower or (b.get("section") or "").strip().lower() == sec_lower)
            ]
            if not eligible:
                raise HTTPException(
                    status_code=400,
                    detail="No accessible bots selected for Team Pack export.",
                )
            parsed_bots = eligible
    try:
        pack = repo.export_team_pack(
            bot_slugs=parsed_bots,
            room_slugs=parsed_rooms,
            section=section,
            title=title,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if multi_user and not admin:
        assert vis_bots is not None and vis_rooms is not None and vis_pages is not None
        pack["bots"] = [
            b for b in (pack.get("bots") or [])
            if b.get("source_slug") in vis_bots
        ]
        pack["rooms"] = [
            r for r in (pack.get("rooms") or [])
            if r.get("source_slug") in vis_rooms
            and all(m in vis_bots for m in (r.get("member_bot_slugs") or []))
        ]
        if "pages" in pack and isinstance(pack.get("pages"), list):
            pack["pages"] = [
                p for p in pack["pages"]
                if p.get("source_slug") in vis_pages
            ]
        pack["description"] = (
            f"Portable team of {len(pack.get('bots') or [])} bot(s) and {len(pack.get('rooms') or [])} room(s)."
        )
    return pack


@router.post("/team-packs/import", status_code=status.HTTP_201_CREATED)
async def import_team_pack_endpoint(
    request: Request,
    body: ImportTeamPackRequest,
) -> dict[str, Any]:
    repo, bus, _, _ = _deps(request)
    settings, _, caller_email = _require_writer_identity(request)
    vis = default_visibility_for_new(settings, None)
    _validate_bot_linked_accounts(
        request,
        repo,
        linked_accounts=body.linked_accounts,
        tools=[],
        visibility=vis,
    )
    try:
        imported = repo.import_team_pack(
            body.pack,
            linked_accounts=body.linked_accounts or None,
            section_override=body.section_override,
            owner_email=caller_email,
            visibility=vis,
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
            "bot_slug": imported["bots"][0]["slug"] if imported.get("bots") else "",
            "room_slug": imported["rooms"][0]["slug"] if imported.get("rooms") else "",
        },
        hop_count=1,
    )
    return imported


async def _read_bounded_body(request: Request, max_bytes: int) -> bytes:
    """Stream request body up to max_bytes, raising HTTP 413 before parsing huge payloads."""
    raw_len = request.headers.get("content-length")
    if raw_len is not None:
        try:
            if int(raw_len) > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Webhook payload exceeds {max_bytes} bytes limit.",
                )
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Webhook payload exceeds {max_bytes} bytes limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


@hooks_router.post("/telegram/{slug}")
async def telegram_webhook(
    request: Request,
    slug: str,
    x_telegram_bot_api_secret_token: str | None = Header(
        default=None, alias="X-Telegram-Bot-Api-Secret-Token"
    ),
) -> dict[str, Any]:
    _, telegram_service = _services(request)
    raw_body = await _read_bounded_body(request, MAX_WEBHOOK_BODY_BYTES)
    try:
        payload = json.loads(raw_body.decode("utf-8"))
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
    raw_body = await _read_bounded_body(request, MAX_WEBHOOK_BODY_BYTES)
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
