"""Pydantic request schemas for argo-core REST APIs."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def _validate_supported_model(value: str) -> str:
    cleaned = value.strip()
    if "gemini-2.5" in cleaned.lower():
        raise ValueError("Deprecated gemini-2.5-* models are forbidden.")
    if ":" not in cleaned or not all(part.strip() for part in cleaned.split(":", 1)):
        raise ValueError("Model ID must follow PydanticAI '<provider>:<model>' syntax.")
    return cleaned


class DispatchActivityRequest(BaseModel):
    instruction: str = Field(min_length=1, max_length=4000)
    target_slug: str = Field(default="operations-coordinator", min_length=1)


class CreateBotRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(default="Workspace automation coworker", min_length=1, max_length=2000)
    runtime: Literal["api", "desktop"] = "api"
    outbound_rbac: Literal["internal", "draft", "execute"] = "draft"
    model: str = Field(default="google:gemini-3.8-flash", min_length=1)
    daily_cap: int = Field(default=10, ge=0, le=500)
    slug: str | None = None
    role_prompt: str | None = Field(default=None, max_length=8000)
    routines: list[dict[str, Any]] | None = None
    tools: list[Any] | None = None
    collections: dict[str, list[str]] | None = None
    linked_accounts: list[str] | None = None
    avatar_color: str = "slate"
    avatar_icon: str = "bot"
    pinned: bool = False
    section: str = ""
    hidden_in_sidebar: bool = False
    boundaries: list[str] = Field(default_factory=list)
    goal_metric: str = ""
    handoff_bot_slug: str = ""
    onboarding_mode: Literal["configured", "interview"] = "configured"

    @field_validator("model")
    @classmethod
    def check_bot_model(cls, value: str) -> str:
        return _validate_supported_model(value)


class UpdateBotRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    runtime: Literal["api", "desktop"] | None = None
    role: str | None = Field(default=None, min_length=1, max_length=2000)
    role_prompt: str | None = Field(default=None, max_length=8000)
    model: str | None = None
    outbound_rbac: Literal["internal", "draft", "execute"] | None = None
    daily_cap: int | None = Field(default=None, ge=0, le=500)
    toggle_routine_id: str | None = None
    routines: list[dict[str, Any]] | None = None
    tools: list[Any] | None = None
    collections: dict[str, list[str]] | None = None
    linked_accounts: list[str] | None = None
    avatar_color: str | None = None
    avatar_icon: str | None = None
    pinned: bool | None = None
    section: str | None = None
    hidden_in_sidebar: bool | None = None
    boundaries: list[str] | None = None
    goal_metric: str | None = None
    handoff_bot_slug: str | None = None
    onboarding_pending: bool | None = None

    @field_validator("model")
    @classmethod
    def check_update_model(cls, value: str | None) -> str | None:
        return _validate_supported_model(value) if value is not None else None


class TriggerBotRequest(BaseModel):
    routine_id: str | None = None
    input_text: str | None = Field(default=None, max_length=12000)
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = Field(default=None, max_length=120)
    wait_for_chain: bool = True


class AppendBotMessageRequest(BaseModel):
    text: str = Field(default="", max_length=4000)
    skill_slugs: list[str] = Field(default_factory=list)
    context_correlation_id: str | None = None
    target_page_slug: str | None = None
    reply_to_id: str | None = Field(default=None, max_length=120)
    attachment_ids: list[str] = Field(default_factory=list)
    async_mode: bool = False


class MarkThreadReadRequest(BaseModel):
    target_type: Literal["bot", "room"] = "bot"
    slug: str = Field(min_length=1, max_length=120)


class ToggleMessageReactionRequest(BaseModel):
    collection: Literal["bot_threads", "room_threads"] = "bot_threads"
    emoji: str = Field(min_length=1, max_length=16)


class CreateRoomRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    member_bot_slugs: list[str] = Field(min_length=2, max_length=6)
    coordinator_bot_slug: str | None = Field(default=None, max_length=120)
    stage_order: list[str] | None = None
    routing_mode: Literal["auto", "lead", "stage"] = "auto"
    ask_before_bot_handoff: bool = False
    max_bot_turns_per_message: int = Field(default=3, ge=1, le=5)
    pinned_page_slug: str | None = Field(default=None, max_length=120)
    pinned: bool = False
    section: str = Field(default="", max_length=80)


class UpdateRoomRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    member_bot_slugs: list[str] | None = Field(default=None, min_length=2, max_length=6)
    coordinator_bot_slug: str | None = None
    stage_order: list[str] | None = None
    routing_mode: Literal["auto", "lead", "stage"] | None = None
    ask_before_bot_handoff: bool | None = None
    max_bot_turns_per_message: int | None = Field(default=None, ge=1, le=5)
    pinned_page_slug: str | None = None
    pinned: bool | None = None
    section: str | None = None


class AppendRoomMessageRequest(BaseModel):
    text: str = Field(default="", max_length=4000)
    reply_to_id: str | None = Field(default=None, max_length=120)
    attachment_ids: list[str] = Field(default_factory=list)
    skill_slugs: list[str] = Field(default_factory=list)
    target_page_slug: str | None = None
    approved_handoff_bot_slug: str | None = Field(default=None, max_length=120)
    async_mode: bool = False


class ExecuteDelegationPlanRequest(BaseModel):
    edited_steps: list[dict[str, Any]] | None = None


class UploadWorkspaceFileJsonRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str = Field(default="text/plain", max_length=150)
    content_base64: str | None = None
    text: str | None = None


class ImportTeamPackRequest(BaseModel):
    pack: dict[str, Any]
    linked_accounts: list[str] = Field(default_factory=list)
    section_override: str | None = Field(default=None, max_length=80)


class CreateSkillRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    instructions: str = Field(min_length=1, max_length=8000)
    scope_slug: str = "*"


class ImportMemoryRequest(BaseModel):
    raw_text: str = Field(min_length=3, max_length=20000)
    scope_slug: str = "*"


class ImportBotBlueprintRequest(BaseModel):
    blueprint: dict[str, Any]
    linked_accounts: list[str] = Field(default_factory=list)


class GeneratePageRequest(BaseModel):
    prompt: str = Field(min_length=3, max_length=4000)
    title: str | None = Field(default=None, max_length=120)
    owner_bot_slug: str = "operations-coordinator"
    allowed_collections: list[str] = Field(default_factory=list)
    existing_page_slug: str | None = None
    template_key: Literal[
        "auto",
        "live_operations_map",
        "bot_hub_board",
        "collection_analytics",
        "interactive_playground",
    ] = "auto"


class CreateApprovalRequest(BaseModel):
    correlation_id: str = Field(default="corr_manual", min_length=1)
    bot_slug: str = Field(min_length=1)
    target_account_slug: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    payload: dict[str, Any]
    source_url: str | None = None
    source_excerpt: str | None = None
    escalation_note: str | None = None


class ResolveApprovalRequest(BaseModel):
    action: Literal["approve", "reject", "edit_approve"]
    edited_text: str | None = None
    style_rule: str | None = None
    channel: Literal["web_ui", "telegram"] = "web_ui"


class CreateStyleRuleRequest(BaseModel):
    rule_text: str = Field(min_length=1, max_length=1000)
    scope_slug: str = "*"


class CreatePageRequest(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str = ""
    render_mode: Literal["declarative_json", "sandboxed_html"] = "declarative_json"
    content_payload: str | None = None
    allowed_collections: list[str] = Field(default_factory=list)
    owner_bot_slug: str = "operations-coordinator"


class UpsertDocumentRequest(BaseModel):
    external_key: str | None = None
    search_text: str = ""
    doc: dict[str, Any]
    description: str = "Schema-less document collection"


class UpsertIntegrationRequest(BaseModel):
    slug: str = Field(min_length=1, max_length=100)
    provider: Literal["google", "telegram", "linkedin", "webhook", "mcp"]
    display_name: str = Field(min_length=1, max_length=150)
    account_identifier: str | None = None
    scopes: list[str] = Field(default_factory=list)
    secrets: dict[str, Any] = Field(default_factory=dict)


class UpsertModelRequest(BaseModel):
    slug: str = Field(min_length=1, max_length=100)
    provider_type: Literal["google", "anthropic", "openai", "xai", "openrouter", "ollama"]
    model_id: str = Field(min_length=1, max_length=150)
    api_base: str | None = None
    api_key: str | None = None
    is_default: bool = False
    daily_token_limit: int | None = Field(default=None, ge=1)
    monthly_budget_usd: float | None = Field(default=None, ge=0.0)

    @field_validator("model_id")
    @classmethod
    def check_provider_model(cls, value: str) -> str:
        return _validate_supported_model(value)


class TestModelRequest(BaseModel):
    prompt: str = Field(
        default="Confirm operational readiness in one concise sentence.",
        min_length=1,
        max_length=1000,
    )


class OnboardTelegramRequest(BaseModel):
    bot_token: str = Field(min_length=10, max_length=300)
    slug: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=150)
    operator_chat_id: str | None = Field(default=None, max_length=100)
    admin_channels: list[str] = Field(default_factory=list)
    public_channels: list[str] = Field(default_factory=list)
    register_webhook: bool = False


class ProbeIntegrationRequest(BaseModel):
    send_test_message: bool = False


class StartGoogleOAuthRequest(BaseModel):
    in_production_confirmed: bool = False
    client_id: str | None = Field(default=None, max_length=300)
    client_secret: str | None = Field(default=None, max_length=300)
    reuse_saved_client: bool = False
    slug: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=150)
    login_hint: str | None = Field(default=None, max_length=200)
    scope_groups: list[str] = Field(default_factory=lambda: ["gmail_read", "calendar"])
    extra_scopes: list[str] = Field(default_factory=list)


class CompleteGoogleOAuthRequest(BaseModel):
    code: str = Field(min_length=1, max_length=2000)
    state: str = Field(min_length=1, max_length=500)


class OnboardLinkedInRequest(BaseModel):
    access_token: str = Field(min_length=8, max_length=4000)
    author_urn: str | None = Field(default=None, max_length=200)
    linkedin_version: str = Field(default="202611", min_length=1, max_length=50)
    slug: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=150)


class PublishLinkedInPostRequest(BaseModel):
    commentary: str = Field(min_length=1, max_length=3000)
    visibility: Literal["PUBLIC", "CONNECTIONS"] = "PUBLIC"
    article_url: str | None = Field(default=None, max_length=2000)
    article_title: str | None = Field(default=None, max_length=300)


class OnboardWebhookRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=150)
    slug: str | None = Field(default=None, max_length=100)
    signing_secret: str | None = Field(default=None, max_length=500)
    event_type: str = Field(default="webhook.received", min_length=3, max_length=80)
    target_collection: str | None = Field(default="webhook_events", max_length=100)


class OnboardTelegramPublicMonitorRequest(BaseModel):
    channel_handle: str = Field(min_length=2, max_length=250)
    slug: str | None = Field(default=None, max_length=100)
    display_name: str | None = Field(default=None, max_length=150)
    sync_immediately: bool = True


class SyncTelegramPublicRequest(BaseModel):
    limit_per_channel: int = Field(default=20, ge=1, le=100)


class FetchRssRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    limit: int = Field(default=20, ge=1, le=100)


class FetchWebpageRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    max_chars: int = Field(default=12000, ge=200, le=100000)


class DraftBotSpecRequest(BaseModel):
    prompt: str = Field(min_length=4, max_length=4000)
    preferred_runtime: Literal["auto", "api", "desktop"] = "auto"
    preferred_rbac: Literal["auto", "internal", "draft", "execute"] = "auto"
    preferred_model: str | None = None
    linked_accounts: list[str] | None = None

    @field_validator("preferred_model")
    @classmethod
    def check_preferred_model(cls, value: str | None) -> str | None:
        return _validate_supported_model(value) if value is not None else None


class UpdatePageRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    render_mode: Literal["declarative_json", "sandboxed_html"] | None = None
    content_payload: str | None = None
    allowed_collections: list[str] | None = None
    owner_bot_slug: str | None = Field(default=None, min_length=1, max_length=120)
    pinned: bool | None = None


class PageCollectionQueryRequest(BaseModel):
    collection: str = Field(min_length=1, max_length=100)
    query: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


class DesktopBrowseRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    selector: str | None = Field(default=None, max_length=300)
    max_chars: int = Field(default=12000, ge=200, le=100000)


class DesktopActionRequest(BaseModel):
    action: Literal[
        "inspect",
        "screenshot",
        "check_app",
        "launch",
        "focus_window",
        "click",
        "move",
        "type",
        "key",
        "scroll",
        "exec",
        "record_start",
        "record_status",
        "record_stop",
    ]
    app: str | None = Field(default=None, max_length=120)
    url: str | None = Field(default=None, max_length=2000)
    args: list[str] | None = None
    title: str | None = Field(default=None, max_length=300)
    x: int | None = Field(default=None, ge=0, le=10000)
    y: int | None = Field(default=None, ge=0, le=10000)
    button: int | None = Field(default=None, ge=1, le=5)
    double: bool | None = None
    text: str | None = Field(default=None, max_length=4000)
    keys: str | None = Field(default=None, max_length=120)
    direction: Literal["up", "down"] | None = None
    clicks: int | None = Field(default=None, ge=1, le=20)
    max_width: int | None = Field(default=None, ge=0, le=3840)
    command: str | None = Field(default=None, max_length=8000)
    commands: list[str] | None = None
    cwd: str | None = Field(default=None, max_length=500)
    timeout_seconds: int | None = Field(default=None, ge=2, le=180)
    continue_on_error: bool | None = None
    show_terminal: bool | None = None
    env: dict[str, str] | None = None


class DesktopRecordingStopRequest(BaseModel):
    skill_name: str | None = Field(default=None, max_length=120)
    save_skill: bool = True
    notes: str | None = Field(default=None, max_length=2000)


class DesktopRecordingSaveRequest(BaseModel):
    skill_name: str | None = Field(default=None, max_length=120)
    notes: str | None = Field(default=None, max_length=2000)
    recording: dict[str, Any] = Field(default_factory=dict)


class VaultSecretUpsertRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: str | None = Field(default=None, max_length=100)
    secret_type: Literal["ssh", "login", "api_token", "custom"] = "ssh"
    host: str = Field(default="", max_length=300)
    port: str = Field(default="22", max_length=20)
    url: str = Field(default="", max_length=2000)
    secrets: dict[str, str] = Field(default_factory=dict)
    allowed_bots: list[str] | None = None


class VaultSecretUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    secret_type: Literal["ssh", "login", "api_token", "custom"] | None = None
    host: str | None = Field(default=None, max_length=300)
    port: str | None = Field(default=None, max_length=20)
    url: str | None = Field(default=None, max_length=2000)
    secrets: dict[str, str] | None = None
    allowed_bots: list[str] | None = None
