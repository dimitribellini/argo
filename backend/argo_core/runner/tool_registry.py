"""Gemini-safe native PydanticAI tool definitions and dynamic per-bot tool scoping."""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from argo_core.tool_schema import (
    _FORBIDDEN_SCHEMA_KEYS,
    ToolSpec,
    _resolve_json_ref,
    _sanitize_schema_node,
    _simplify_union_branches,
    sanitize_tool_json_schema,
    validate_gemini_safe_schema,
)


# ---------------------------------------------------------------------------
# Flat Pydantic v2 parameter models for every Argo action
# ---------------------------------------------------------------------------


class _AskOperatorOption(BaseModel):
    label: str = Field(..., description="Short button label shown to the operator.")
    reply: str = Field(..., description="Instruction text sent back if clicked.")
    tone: str | None = Field(default=None, description="Optional visual tone: primary, secondary, or danger.")


class _DelegationPlanStep(BaseModel):
    bot_slug: str = Field(..., description="Target teammate bot slug.")
    task: str = Field(..., description="Specific task instruction for this teammate step.")
    parallel_group: int | None = Field(default=None, description="Execution stage integer (1, 2, ...).")


class _FleetCleanupOperation(BaseModel):
    bot_slug: str = Field(..., description="Target bot slug to update, pause, hide, or delete.")
    enabled: bool | None = Field(default=None, description="Set false to pause or true to enable.")
    hidden_in_sidebar: bool | None = Field(default=None, description="Set true to hide from sidebar.")
    delete: bool | None = Field(default=None, description="Set true to delete the bot.")
    section: str | None = Field(default=None, description="Target sidebar section name.")


class _UpsertDocumentArgs(BaseModel):
    collection: str | None = Field(default=None, description="Target write collection slug.")
    external_key: str | None = Field(default=None, description="Unique deduplication key such as a URL or ID.")
    search_text: str | None = Field(default=None, description="Plain-text summary indexed for full-text search.")
    title: str | None = Field(default=None, description="Document title.")
    url: str | None = Field(default=None, description="Source URL if applicable.")
    summary: str | None = Field(default=None, description="Concise document summary.")
    doc_json: str | None = Field(default=None, description="Optional JSON object string with structured document fields.")


class _DataDescribeArgs(BaseModel):
    collections: list[str] | None = Field(default=None, description="Authorized collection slugs or file:<id> datasets to inspect.")
    sample_limit: int | None = Field(default=None, description="Maximum sample records per dataset (default 30).")


class _DataQueryArgs(BaseModel):
    sql: str = Field(..., description="Read-only SELECT/WITH SQL query executed inside DuckDB or SQLite sandbox.")
    collections: list[str] | None = Field(default=None, description="Authorized collections or file:<id> datasets to bind.")
    params: list[str] | None = Field(default=None, description="Positional query parameters matching ? placeholders.")
    row_cap: int | None = Field(default=None, description="Maximum rows to return (default 200).")
    engine: str | None = Field(default=None, description="Query engine: auto, duckdb, or sqlite.")


class _FetchPublicWebpageArgs(BaseModel):
    url: str = Field(..., description="Public HTTP or HTTPS URL to fetch and read.")
    max_chars: int | None = Field(default=None, description="Maximum characters to return (default 12000).")
    offset: int | None = Field(default=None, description="Character offset for paginating long pages (default 0).")


class _ExtractWebDataArgs(BaseModel):
    url: str = Field(..., description="Public webpage URL to extract structured elements or tables from.")
    selector: str | None = Field(default=None, description="Optional CSS or XPath selector to focus extraction.")
    target_collection: str | None = Field(default=None, description="Optional collection slug to save extracted rows.")
    save_as_file: bool | None = Field(default=None, description="Set true to store extracted output as a workspace file.")


class _FetchRssFeedArgs(BaseModel):
    url: str = Field(..., description="Public RSS or Atom feed URL.")


class _FetchTelegramPublicChannelArgs(BaseModel):
    channel: str = Field(..., description="Public Telegram channel handle (without @ or t.me/ prefix).")
    limit: int | None = Field(default=None, description="Maximum recent posts to fetch (default 20).")


class _GmailSearchArgs(BaseModel):
    account: str | None = Field(default=None, description="Permitted Google integration slug.")
    query: str | None = Field(default=None, description="Gmail search query string (e.g. is:unread newer_than:2d).")
    max_results: int | None = Field(default=None, description="Maximum messages to return (default 10).")


class _GdriveSearchArgs(BaseModel):
    account: str | None = Field(default=None, description="Permitted Google integration slug.")
    query: str | None = Field(default=None, description="Google Drive search query or filename keywords.")
    page_size: int | None = Field(default=None, description="Maximum files to return (default 25).")
    page_token: str | None = Field(default=None, description="Pagination token from a previous search.")


class _GdriveReadFileArgs(BaseModel):
    file_id: str = Field(..., description="Google Drive file ID.")
    account: str | None = Field(default=None, description="Permitted Google integration slug.")
    max_chars: int | None = Field(default=None, description="Maximum characters to read (default 16000).")


class _GcalEventsArgs(BaseModel):
    account: str | None = Field(default=None, description="Permitted Google integration slug.")
    calendar_id: str | None = Field(default=None, description="Calendar ID (default primary).")
    time_min: str | None = Field(default=None, description="RFC3339 lower time bound.")
    time_max: str | None = Field(default=None, description="RFC3339 upper time bound.")
    query: str | None = Field(default=None, description="Free-text event filter.")
    max_results: int | None = Field(default=None, description="Maximum events to return (default 25).")


class _EmailOutboundArgs(BaseModel):
    to: str = Field(..., description="Recipient email address.")
    subject: str = Field(..., description="Email subject line.")
    text: str = Field(..., description="Email body text.")
    account: str | None = Field(default=None, description="Permitted Google integration slug.")
    source_url: str | None = Field(default=None, description="Optional source reference URL.")
    source_excerpt: str | None = Field(default=None, description="Optional short reference excerpt.")
    cc: str | None = Field(default=None, description="Optional CC email addresses.")
    thread_id: str | None = Field(default=None, description="Optional Gmail thread ID when replying.")
    in_reply_to: str | None = Field(default=None, description="Optional Message-ID header when replying.")


class _PublishTelegramArgs(BaseModel):
    text: str = Field(..., description="Telegram message content in clean Markdown.")
    account: str | None = Field(default=None, description="Linked Telegram integration slug.")
    target: str | None = Field(default=None, description="Optional target chat_id or channel handle override.")
    source_url: str | None = Field(default=None, description="Optional source reference URL.")


class _PublishLinkedinArgs(BaseModel):
    text: str = Field(..., description="LinkedIn post text.")
    account: str | None = Field(default=None, description="LinkedIn integration slug.")
    source_url: str | None = Field(default=None, description="Optional source reference URL.")


class _ConnectorPublishArgs(BaseModel):
    action_type: str = Field(..., description="Target connector action (e.g. publish_telegram, publish_linkedin, send_email).")
    text: str = Field(..., description="Message or post content.")
    account: str | None = Field(default=None, description="Linked integration slug.")
    target: str | None = Field(default=None, description="Optional destination handle, chat ID, or URL.")
    source_url: str | None = Field(default=None, description="Optional source reference URL.")


class _NotifyApprovalArgs(BaseModel):
    approval_id: str = Field(..., description="ID of the queued approval item to notify.")
    account: str | None = Field(default=None, description="Linked Telegram, webhook, or Google integration slug.")
    text: str | None = Field(default=None, description="Optional formatted notification message.")
    target: str | None = Field(default=None, description="Optional destination chat ID or recipient.")


class _RequestHumanApprovalArgs(BaseModel):
    action_type: str = Field(..., description="Action waiting for operator review (e.g. publish_telegram, send_email).")
    text: str = Field(..., description="Proposed draft content or action details for approval.")
    account: str | None = Field(default=None, description="Target linked integration slug.")
    target: str | None = Field(default=None, description="Optional destination handle, recipient, or chat ID.")
    to: str | None = Field(default=None, description="Optional email To recipient.")
    cc: str | None = Field(default=None, description="Optional email CC recipients.")
    bcc: str | None = Field(default=None, description="Optional email BCC recipients.")
    subject: str | None = Field(default=None, description="Optional email subject line.")
    thread_id: str | None = Field(default=None, description="Optional thread ID when replying.")
    in_reply_to: str | None = Field(default=None, description="Optional Message-ID header when replying.")
    payload_json: str | None = Field(default=None, description="Optional JSON object string with extra action metadata.")
    source_url: str | None = Field(default=None, description="Optional source reference URL.")
    source_excerpt: str | None = Field(default=None, description="Optional short excerpt supporting the draft.")
    escalation_note: str | None = Field(default=None, description="Reason why operator review is requested.")


class _EmitEventArgs(BaseModel):
    event_type: str = Field(..., description="Event topic name to publish onto the Valkey bus.")
    target_slug: str | None = Field(default=None, description="Target stream or subscriber slug (default activity).")
    payload_json: str | None = Field(default=None, description="JSON object string containing the event payload fields.")


class _UpsertPageArgs(BaseModel):
    slug: str = Field(..., description="URL slug of the Page to create or update.")
    title: str = Field(..., description="Human-readable Page title.")
    render_mode: str | None = Field(default=None, description="Render mode: sandboxed_html or declarative_json.")
    allowed_collections: list[str] | None = Field(default=None, description="Collection slugs or file:<id> datasets bound to this Page.")
    content_payload: str | None = Field(default=None, description="Full HTML document for sandboxed_html or JSON string for declarative_json.")
    description: str | None = Field(default=None, description="Concise subtitle describing the Page.")
    template_key: str | None = Field(default=None, description="Optional built-in Page template such as data_dashboard.")
    dashboard_spec_json: str | None = Field(default=None, description="Optional JSON object string for data_dashboard template configuration.")


class _OpenPageArgs(BaseModel):
    slug: str = Field(..., description="Slug or title of the workspace Page to dock open.")
    mode: str | None = Field(default=None, description="Display mode: split or full.")


class _ListWorkspaceFilesArgs(BaseModel):
    query: str | None = Field(default=None, description="Optional filename substring filter.")


class _ReadWorkspaceFileArgs(BaseModel):
    file_id: str | None = Field(default=None, description="Uploaded workspace file ID.")
    filename: str | None = Field(default=None, description="Filename if file_id is unknown.")
    page_start: int | None = Field(default=None, description="Starting 1-based page number for multi-page PDFs.")
    page_end: int | None = Field(default=None, description="Ending 1-based page number for multi-page PDFs.")
    query: str | None = Field(default=None, description="Search phrase inside a multi-page PDF.")


class _WriteWorkspaceFileArgs(BaseModel):
    filename: str = Field(..., description="Output filename with extension (e.g. report.md, export.csv).")
    content: str = Field(..., description="UTF-8 text content to write to the downloadable file.")
    mime_type: str | None = Field(default=None, description="Optional explicit MIME type (e.g. text/markdown, text/csv).")


class _RememberRuleArgs(BaseModel):
    rule_text: str = Field(..., description="Concise persistent editorial or tone preference rule to remember.")
    scope_slug: str | None = Field(default=None, description="Optional bot slug or '*' for workspace-wide scope.")


class _SaveSkillArgs(BaseModel):
    name: str = Field(..., description="Short readable name of the reusable Skill.")
    description: str = Field(..., description="One-sentence summary of when to apply this Skill.")
    instructions: str = Field(..., description="Step-by-step reusable instructions for the Skill.")
    scope_slug: str | None = Field(default=None, description="Optional bot slug or '*' for shared scope.")


class _AskOperatorArgs(BaseModel):
    question: str = Field(..., description="Clear question waiting for the operator's decision.")
    context: str | None = Field(default=None, description="Optional concise context for the decision.")
    options: list[_AskOperatorOption] | None = Field(default=None, description="Optional clickable choice buttons.")
    allow_custom_reply: bool | None = Field(default=None, description="Allow free-text custom reply in addition to options.")


class _DelegateToBotArgs(BaseModel):
    target_bot: str = Field(..., description="Teammate bot slug to delegate work to.")
    instruction: str = Field(..., description="Clear task instruction and relevant details for the teammate.")
    await_result: bool | None = Field(default=None, description="Set true to wait synchronously and receive the teammate's result.")


class _ProposeDelegationPlanArgs(BaseModel):
    goal: str = Field(..., description="Overall goal of the multi-bot plan.")
    steps: list[_DelegationPlanStep] = Field(..., description="Ordered or parallel delegation steps.")
    summary: str | None = Field(default=None, description="Optional summary shown with the plan card.")


class _UpdateSelfConfigArgs(BaseModel):
    role: str | None = Field(default=None, description="Updated short role summary.")
    role_prompt: str | None = Field(default=None, description="Updated system role prompt.")
    add_boundaries: list[str] | None = Field(default=None, description="New strict boundary rules to append.")
    boundaries: list[str] | None = Field(default=None, description="Full replacement list of boundary rules.")
    handoff_bot_slug: str | None = Field(default=None, description="Teammate bot slug for automatic handoff.")
    outbound_rbac: str | None = Field(default=None, description="Permission mode: internal, draft, or execute.")
    runtime: str | None = Field(default=None, description="Execution mode: api or desktop.")
    linked_accounts: list[str] | None = Field(default=None, description="Integration slugs to request access to.")
    read_collections: list[str] | None = Field(default=None, description="Collection slugs to request read access to.")
    max_steps_per_run: int | None = Field(default=None, description="Maximum tool steps per run (3 to 25).")
    daily_cap: int | None = Field(default=None, description="Daily outbound send cap.")
    model: str | None = Field(default=None, description="Override model ID (provider:model_name).")
    section: str | None = Field(default=None, description="Sidebar section name.")
    goal_metric: str | None = Field(default=None, description="Primary goal metric description.")
    onboarding_pending: bool | None = Field(default=None, description="Set false once conversational onboarding setup is complete.")


class _ConfigureRoutineArgs(BaseModel):
    operation: str | None = Field(
        default=None,
        description="Operation: add, upsert, update, or delete. Use 'add' when creating a new one-shot or separate routine so existing recurring routines are kept.",
    )
    routine_id: str | None = Field(default=None, description="Existing routine ID when updating or deleting.")
    label: str | None = Field(default=None, description="Human-readable routine label.")
    schedule: str | None = Field(default=None, description="Schedule phrase such as 'Every weekday at 08:30', 'Once at YYYY-MM-DD HH:MM', 'In 30m', or 'Manual'.")
    timezone: str | None = Field(default=None, description="IANA timezone name such as UTC or Europe/Rome.")
    mode: str | None = Field(
        default=None,
        description="Execution mode: 'poll' (source monitoring), 'task' (scheduled LLM task using prompt), or 'action' (0-token deterministic outbound connector action using action_json).",
    )
    prompt: str | None = Field(default=None, description="Task instructions run when a task or poll routine fires.")
    action_json: str | None = Field(
        default=None,
        description="JSON object string describing a 0-token scheduled outbound connector action (e.g. {\"action_type\": \"...\", \"account\": \"<integration_slug>\", \"text\": \"...\", \"target\": \"...\"}). Used when mode='action'.",
    )
    skill_slugs: list[str] | None = Field(default=None, description="Skill slugs attached to this routine.")
    stale_data_policy: str | None = Field(default=None, description="Behavior when polled sources have no new items: skip_quietly, notify_missing, or always_run.")
    delivery_mode: str | None = Field(default=None, description="Delivery mode: chat_and_activity, activity_only, or silent.")
    enabled: bool | None = Field(default=None, description="Enable or pause this routine.")
    one_shot: bool | None = Field(default=None, description="Set true for a one-time scheduled routine.")
    source_query: str | None = Field(default=None, description="Optional query filter associated with a polled connector routine.")


class _RunRoutineArgs(BaseModel):
    routine_id: str = Field(..., description="Routine ID or exact routine label to load and run now.")


class _ProposeSpecialistBotArgs(BaseModel):
    name: str = Field(..., description="Name for the proposed specialist bot.")
    role: str = Field(..., description="Concise role description.")
    prompt: str = Field(..., description="Task prompt describing what the new bot should automate.")
    section: str | None = Field(default=None, description="Optional sidebar section.")


class _ProposeFleetCleanupArgs(BaseModel):
    operations: list[_FleetCleanupOperation] = Field(..., description="Proposed per-bot pause, hide, move, or delete changes.")
    reason: str | None = Field(default=None, description="Explanation shown on the approval card.")


class _DesktopBrowseArgs(BaseModel):
    url: str = Field(..., description="Public URL to open inside Virtual Desktop Chromium.")
    selector: str | None = Field(default=None, description="Optional CSS selector to extract specific content.")
    save_to_collection: str | None = Field(default=None, description="Optional write collection slug to save the page.")
    max_chars: int | None = Field(default=None, description="Maximum characters to extract (default 12000).")


class _DesktopBrowserActionArgs(BaseModel):
    action: str = Field(..., description="Browser action: click, fill, select, scroll, key, wait, snapshot, back, forward, tabs, or switch_tab.")
    index: int | None = Field(default=None, description="Target interactive_elements index from the latest snapshot.")
    selector: str | None = Field(default=None, description="CSS selector of target element.")
    text: str | None = Field(default=None, description="Visible button/link text when clicking.")
    value: str | None = Field(default=None, description="Text to fill or option value to select.")
    placeholder: str | None = Field(default=None, description="Input placeholder attribute match.")
    submit: bool | None = Field(default=None, description="Set true to press Enter after fill.")
    direction: str | None = Field(default=None, description="Scroll direction: down or up.")
    amount: int | None = Field(default=None, description="Scroll distance in pixels.")
    key: str | None = Field(default=None, description="Keyboard key name (e.g. Enter, Tab, Escape).")
    seconds: float | None = Field(default=None, description="Seconds to wait when action is wait.")
    tab_index: int | None = Field(default=None, description="Zero-based tab index for switch_tab.")
    max_chars: int | None = Field(default=None, description="Maximum page text characters to return.")


class _DesktopExecArgs(BaseModel):
    commands: list[str] = Field(..., description="Shell commands to run sequentially inside this bot's Virtual Desktop container.")
    cwd: str | None = Field(default=None, description="Working directory inside the desktop container (default /config).")
    continue_on_error: bool | None = Field(default=None, description="Continue executing later commands if a command exits non-zero.")
    vault_secrets: list[str] | None = Field(default=None, description="Permitted Vault secret slugs injected as placeholder env vars.")


class _DesktopInspectArgs(BaseModel):
    detail_level: str | None = Field(default=None, description="Inspection level: summary or full.")


class _DesktopScreenshotArgs(BaseModel):
    max_width: int | None = Field(default=None, description="Maximum PNG width in pixels (default 1280).")


class _DesktopCheckAppArgs(BaseModel):
    app: str = Field(..., description="Desktop application binary or name (e.g. chromium, xfce4-terminal).")


class _DesktopLaunchArgs(BaseModel):
    app: str = Field(..., description="Desktop application to launch.")
    url: str | None = Field(default=None, description="Optional URL to pass when launching a browser.")
    args: list[str] | None = Field(default=None, description="Optional CLI arguments.")


class _DesktopFocusWindowArgs(BaseModel):
    title: str | None = Field(default=None, description="Substring of target window title.")
    window_id: str | None = Field(default=None, description="Window identifier from desktop_inspect.")


class _DesktopClickArgs(BaseModel):
    x: int = Field(..., description="X screen coordinate in pixels.")
    y: int = Field(..., description="Y screen coordinate in pixels.")
    button: int | None = Field(default=None, description="Mouse button (1=left, 2=middle, 3=right).")
    clicks: int | None = Field(default=None, description="Click count (1=single, 2=double).")
    double: bool | None = Field(default=None, description="Set true for double-click.")


class _DesktopTypeArgs(BaseModel):
    text: str = Field(..., description="Text to type; may reference {{vault:slug.field}} placeholders.")
    vault_secrets: list[str] | None = Field(default=None, description="Permitted Vault secret slugs referenced by placeholders.")


class _DesktopKeyArgs(BaseModel):
    keys: str = Field(..., description="X11 key name or chord (e.g. Return, ctrl+l, Escape).")


class _DesktopScrollArgs(BaseModel):
    direction: str | None = Field(default=None, description="Scroll direction: down or up.")
    clicks: int | None = Field(default=None, description="Number of scroll wheel steps.")
    x: int | None = Field(default=None, description="Optional X coordinate.")
    y: int | None = Field(default=None, description="Optional Y coordinate.")


class _SshExecArgs(BaseModel):
    vault_slug: str = Field(..., description="Permitted SSH Vault slug (without @ prefix).")
    command: str = Field(..., description="Shell command to run on the target remote SSH host(s).")
    host: str | None = Field(default=None, description="Single hostname or IP override (must appear in operator request).")
    hosts: list[str] | None = Field(default=None, description="Multiple target hostnames/IPs to run the same command in parallel or batch approval.")
    port: int | None = Field(default=None, description="Optional SSH TCP port override.")
    session_id: str | None = Field(default=None, description="Optional active SSH session_id to reuse on the same host.")


class _SshWaitArgs(BaseModel):
    session_id: str = Field(..., description="Active SSH session_id returning running_timeout.")
    timeout_seconds: int | None = Field(default=None, description="Seconds to wait for terminal output (default 45).")


class _SshInputArgs(BaseModel):
    session_id: str = Field(..., description="Active SSH session_id waiting for interactive prompt input.")
    text: str = Field(..., description="Input string sent to the terminal prompt (include trailing newline if submitting).")


class _SshCloseArgs(BaseModel):
    session_id: str = Field(..., description="Active SSH session_id to close cleanly.")


class _SshSessionControlArgs(BaseModel):
    session_id: str = Field(..., description="Target SSH session_id.")
    operation: str = Field(..., description="Safety control operation: pause, terminate, or pin_audit.")
    pin_audit: bool | None = Field(default=None, description="Pin audit log entry for security review.")
    reason: str | None = Field(default=None, description="Reason for pausing, terminating, or pinning audit.")


class _SandboxExecArgs(BaseModel):
    command: str | None = Field(
        default=None,
        description="Single shell command to execute inside the bot's isolated Fedora 45 sandbox.",
    )
    commands: list[str] | None = Field(
        default=None,
        description="Sequential list of shell commands executed inside the sandbox.",
    )
    script: str | None = Field(
        default=None,
        description="Multi-line script source to write to /workspace (or a temporary file) and execute.",
    )
    interpreter: str | None = Field(
        default=None,
        description="Script interpreter when `script` is provided: bash, sh, or python3 (default bash).",
    )
    save_as: str | None = Field(
        default=None,
        description="Optional relative filename inside /workspace (e.g. 'check_site.py') to save and run.",
    )
    workdir: str | None = Field(
        default=None,
        description="Optional working directory inside the sandbox (defaults to /workspace).",
    )
    timeout_seconds: int | None = Field(
        default=None,
        description="Execution timeout in seconds (1..120, default 45).",
    )
    vault_slugs: list[str] | None = Field(
        default=None,
        description="Optional permitted Vault secret slugs to inject as ARGO_VAULT_* environment variables.",
    )


_TOOL_SCHEMA_DEFS: tuple[tuple[str, str, type[BaseModel]], ...] = (
    (
        "upsert_document",
        "Save or update a structured item inside an authorized write collection (deduplicated by external_key).",
        _UpsertDocumentArgs,
    ),
    (
        "data_describe",
        "Inspect schema, column types, and sample records across authorized collections or attached files.",
        _DataDescribeArgs,
    ),
    (
        "data_query",
        "Execute a read-only SQL SELECT/WITH query over authorized collections or uploaded datasets.",
        _DataQueryArgs,
    ),
    (
        "fetch_public_webpage",
        "Fetch and read a public HTTP/HTTPS webpage directly without a browser container.",
        _FetchPublicWebpageArgs,
    ),
    (
        "extract_web_data",
        "Extract structured tables/lists from a public webpage and optionally save to a collection or file.",
        _ExtractWebDataArgs,
    ),
    (
        "fetch_rss_feed",
        "Fetch and parse recent entries from a public RSS or Atom feed.",
        _FetchRssFeedArgs,
    ),
    (
        "fetch_telegram_public_channel",
        "Fetch recent public posts from a non-admin public Telegram channel.",
        _FetchTelegramPublicChannelArgs,
    ),
    (
        "gmail_search",
        "Search messages inside a linked Google account's Gmail inbox.",
        _GmailSearchArgs,
    ),
    (
        "gdrive_search",
        "Search files and folders inside a linked Google Drive account.",
        _GdriveSearchArgs,
    ),
    (
        "gdrive_read_file",
        "Read text excerpts from a Google Drive file by ID.",
        _GdriveReadFileArgs,
    ),
    (
        "gcal_events",
        "List upcoming or filtered events from a linked Google Calendar.",
        _GcalEventsArgs,
    ),
    (
        "send_email",
        "Send (or queue for human approval under draft RBAC) an email via a linked Google account.",
        _EmailOutboundArgs,
    ),
    (
        "gmail_draft",
        "Create a Gmail draft (or queue in Approvals under draft RBAC) via a linked Google account.",
        _EmailOutboundArgs,
    ),
    (
        "reply_email",
        "Reply in an existing email thread via a linked Google account.",
        _EmailOutboundArgs,
    ),
    (
        "publish_telegram",
        "Publish (or queue for approval under draft RBAC) a formatted Markdown message to a linked Telegram integration.",
        _PublishTelegramArgs,
    ),
    (
        "publish_linkedin",
        "Publish (or queue for approval under draft RBAC) a post to a linked LinkedIn integration.",
        _PublishLinkedinArgs,
    ),
    (
        "connector_publish",
        "Send an outbound payload (or queue for approval under draft RBAC) through a specified linked integration.",
        _ConnectorPublishArgs,
    ),
    (
        "notify_approval",
        "Deliver a notification about a queued approval card to a linked Telegram, webhook, or Google integration.",
        _NotifyApprovalArgs,
    ),
    (
        "request_human_approval",
        "Explicitly submit a draft or sensitive action to the Web UI Approvals queue.",
        _RequestHumanApprovalArgs,
    ),
    (
        "emit_event",
        "Publish a domain event onto Argo's Valkey event bus for downstream subscribed bots.",
        _EmitEventArgs,
    ),
    (
        "upsert_page",
        "Create or update an interactive Living Page (sandboxed HTML, ECharts dashboard, or declarative JSON) bound to permitted datasets.",
        _UpsertPageArgs,
    ),
    (
        "open_page",
        "Open or dock an existing workspace Page beside the active chat thread.",
        _OpenPageArgs,
    ),
    (
        "list_workspace_files",
        "List uploaded and generated workspace files accessible in the current scope.",
        _ListWorkspaceFilesArgs,
    ),
    (
        "read_workspace_file",
        "Read content or paginated PDF pages from an uploaded workspace file.",
        _ReadWorkspaceFileArgs,
    ),
    (
        "write_workspace_file",
        "Write a downloadable file (Markdown, CSV, JSON, HTML, SVG, text) to the workspace.",
        _WriteWorkspaceFileArgs,
    ),
    (
        "remember_rule",
        "Store a persistent editorial tone or preference rule in style_memory.",
        _RememberRuleArgs,
    ),
    (
        "save_skill",
        "Save or update a reusable markdown Skill playbook for this bot or workspace.",
        _SaveSkillArgs,
    ),
    (
        "ask_operator",
        "Pause execution immediately and ask the operator a clarifying question with clickable decision buttons.",
        _AskOperatorArgs,
    ),
    (
        "delegate_to_bot",
        "Delegate a sub-task to another enabled workspace teammate bot (optionally awaiting its result).",
        _DelegateToBotArgs,
    ),
    (
        "propose_delegation_plan",
        "Propose a structured multi-bot coordination plan for operator confirmation.",
        _ProposeDelegationPlanArgs,
    ),
    (
        "update_self_config",
        "Update safe self-configuration fields or queue an approval card for privileged access changes.",
        _UpdateSelfConfigArgs,
    ),
    (
        "configure_routine",
        "Create, update, or delete a scheduled or manual routine on this bot (including one-shot schedules).",
        _ConfigureRoutineArgs,
    ),
    (
        "run_routine",
        "Load a saved routine's prompt and attached skills to run immediately in chat.",
        _RunRoutineArgs,
    ),
    (
        "propose_specialist_bot",
        "Queue an approval card to create a new specialist bot in the workspace.",
        _ProposeSpecialistBotArgs,
    ),
    (
        "propose_fleet_cleanup",
        "Queue an approval card proposing batch pause/hide/move/delete cleanup across existing bots.",
        _ProposeFleetCleanupArgs,
    ),
    (
        "desktop_browse",
        "Open a public URL in this bot's Virtual Desktop Chromium browser and return text + indexed interactive DOM elements.",
        _DesktopBrowseArgs,
    ),
    (
        "desktop_browser_action",
        "Interact with the current Chromium page in Virtual Desktop (click, fill, select, scroll, key, wait, snapshot, tabs).",
        _DesktopBrowserActionArgs,
    ),
    (
        "desktop_exec",
        "Run shell commands locally inside this bot's own Virtual Desktop XFCE container.",
        _DesktopExecArgs,
    ),
    (
        "desktop_inspect",
        "Inspect Virtual Desktop provisioning state, display, open windows, and Chromium status.",
        _DesktopInspectArgs,
    ),
    (
        "desktop_screenshot",
        "Capture a PNG screenshot of the Virtual Desktop screen for visual inspection.",
        _DesktopScreenshotArgs,
    ),
    (
        "desktop_check_app",
        "Check whether an application is installed or running inside the Virtual Desktop container.",
        _DesktopCheckAppArgs,
    ),
    (
        "desktop_launch",
        "Launch a GUI application inside the Virtual Desktop container.",
        _DesktopLaunchArgs,
    ),
    (
        "desktop_focus_window",
        "Bring a Virtual Desktop application window to the foreground.",
        _DesktopFocusWindowArgs,
    ),
    (
        "desktop_click",
        "Click at explicit X/Y pixel coordinates inside the Virtual Desktop.",
        _DesktopClickArgs,
    ),
    (
        "desktop_type",
        "Type text (supporting {{vault:slug.field}} placeholders) into the focused Virtual Desktop window.",
        _DesktopTypeArgs,
    ),
    (
        "desktop_key",
        "Send an X11 key press or shortcut (e.g. Return, ctrl+l) to the Virtual Desktop.",
        _DesktopKeyArgs,
    ),
    (
        "desktop_scroll",
        "Scroll the mouse wheel inside the Virtual Desktop.",
        _DesktopScrollArgs,
    ),
    (
        "ssh_exec",
        "Execute a remote SSH command using a permitted SSH Vault credential on one or more authorized hosts.",
        _SshExecArgs,
    ),
    (
        "ssh_wait",
        "Wait for additional terminal output or completion on an active in-flight SSH session.",
        _SshWaitArgs,
    ),
    (
        "ssh_input",
        "Send interactive prompt input to a waiting SSH terminal session (or queue approval under draft RBAC).",
        _SshInputArgs,
    ),
    (
        "ssh_close",
        "Close an open persistent SSH terminal session cleanly.",
        _SshCloseArgs,
    ),
    (
        "ssh_session_control",
        "Pause, terminate, or pin the audit record of a monitored SSH session.",
        _SshSessionControlArgs,
    ),
    (
        "sandbox_exec",
        "Write or execute bash/python scripts and CLI tools inside this bot's isolated Fedora 45 /workspace sandbox container.",
        _SandboxExecArgs,
    ),
)


def _build_registry() -> dict[str, ToolSpec]:
    specs: dict[str, ToolSpec] = {}
    for name, description, model_cls in _TOOL_SCHEMA_DEFS:
        clean_schema = sanitize_tool_json_schema(model_cls.model_json_schema())
        specs[name] = ToolSpec(
            name=name,
            description=description,
            parameters_json_schema=clean_schema,
        )
    return specs


_ALL_TOOL_SPECS: dict[str, ToolSpec] = _build_registry()

_GOOGLE_TOOL_NAMES = (
    "gmail_search",
    "gdrive_search",
    "gdrive_read_file",
    "gcal_events",
    "send_email",
    "gmail_draft",
    "reply_email",
)
_DESKTOP_TOOL_NAMES = (
    "desktop_browse",
    "desktop_browser_action",
    "desktop_exec",
    "desktop_inspect",
    "desktop_screenshot",
    "desktop_check_app",
    "desktop_launch",
    "desktop_focus_window",
    "desktop_click",
    "desktop_type",
    "desktop_key",
    "desktop_scroll",
)
_SSH_TOOL_NAMES = (
    "ssh_exec",
    "ssh_wait",
    "ssh_input",
    "ssh_close",
)


def all_tool_specs() -> list[ToolSpec]:
    """Return every registered ToolSpec in declaration order."""
    return list(_ALL_TOOL_SPECS.values())


def get_tool_spec(name: str) -> ToolSpec | None:
    """Return a single registered ToolSpec by exact tool name."""
    return _ALL_TOOL_SPECS.get(name)


def _bot_tool_hints(bot: dict[str, Any]) -> set[str]:
    hints: set[str] = set()
    for item in bot.get("tools") or []:
        if isinstance(item, dict):
            for key in ("name", "slug", "account", "capability", "type"):
                val = str(item.get(key) or "").strip().lower()
                if val:
                    hints.add(val)
        elif item is not None:
            val = str(item).strip().lower()
            if val:
                hints.add(val)
    return hints


def build_bot_tool_specs(
    *,
    bot: dict[str, Any],
    read_cols: Sequence[str],
    data_write_cols: Sequence[str],
    permitted_integrations: Sequence[dict[str, Any]],
    has_ssh_vault: bool,
    can_control_ssh: bool,
    teammate_bots: Sequence[dict[str, Any]],
    trigger_type: str,
    trigger_payload: dict[str, Any],
    is_background_poll: bool,
    needs_platform_status: bool,
    extra_tool_specs: Sequence[ToolSpec] = (),
) -> list[ToolSpec]:
    """Dynamically assemble the exact Gemini-safe ToolSpec subset allowed for this bot and turn."""
    selected: list[str] = []
    hints = _bot_tool_hints(bot)

    # Strict opt-in scoping for built-in public web tools (no static monolith forced onto every bot).
    if (
        hints & {"fetch_public_webpage", "web"}
        or trigger_payload.get("webpage_url")
        or trigger_payload.get("webpage_urls")
    ):
        selected.append("fetch_public_webpage")
    if (
        hints & {"extract_web_data", "web"}
        or trigger_payload.get("webpage_url")
        or trigger_payload.get("webpage_urls")
    ):
        selected.append("extract_web_data")
    if (
        hints & {"fetch_rss_feed", "rss", "feed"}
        or trigger_payload.get("feed_url")
        or trigger_payload.get("feed_urls")
    ):
        selected.append("fetch_rss_feed")
    if (
        hints & {"fetch_telegram_public_channel", "public_channel", "telegram_channel"}
        or trigger_payload.get("public_channel")
        or trigger_payload.get("public_channels")
    ):
        selected.append("fetch_telegram_public_channel")

    write_cols = [str(c).strip() for c in ((bot.get("collections") or {}).get("write") or []) if str(c).strip()]
    if write_cols or data_write_cols:
        selected.append("upsert_document")

    has_analytics_hint = any(
        h in {"data_describe", "data_query", "upsert_page", "extract_web_data"} for h in hints
    )
    if read_cols or trigger_payload.get("attached_files") or has_analytics_hint:
        selected.extend(("data_describe", "data_query"))

    if not is_background_poll or "upsert_page" in hints:
        selected.extend(("upsert_page", "open_page"))

    if not is_background_poll or trigger_payload.get("attached_files"):
        selected.extend(("list_workspace_files", "read_workspace_file", "write_workspace_file"))

    selected.extend(("emit_event", "remember_rule", "save_skill"))

    if not is_background_poll:
        selected.extend(("ask_operator", "update_self_config", "configure_routine", "run_routine"))

    if teammate_bots:
        selected.append("delegate_to_bot")
        if not is_background_poll:
            selected.append("propose_delegation_plan")

    # Strict opt-in scoping for supervisor / fleet-architecture proposals.
    if needs_platform_status or bool(
        hints
        & {
            "platform_status",
            "propose_specialist_bot",
            "propose_fleet_cleanup",
            "supervisor",
            "fleet",
        }
    ):
        selected.extend(("propose_specialist_bot", "propose_fleet_cleanup"))

    # Provider-hint fallback when callers invoke build_bot_tool_specs directly without ConnectorGateway extra_tool_specs.
    extra_names = {s.name for s in extra_tool_specs}
    providers = {str(acc.get("provider") or "").strip().lower() for acc in permitted_integrations}
    if ("google" in providers or any(
        tok in hint for hint in hints for tok in ("google", "gmail", "gdrive", "gcal", "email")
    )) and not any(name in extra_names for name in _GOOGLE_TOOL_NAMES):
        selected.extend(_GOOGLE_TOOL_NAMES)

    if (
        "telegram" in providers
        or trigger_type == "on_event:telegram.message"
        or any("telegram" in hint for hint in hints)
    ) and "publish_telegram" not in extra_names:
        selected.append("publish_telegram")

    if ("linkedin" in providers or any("linkedin" in hint for hint in hints)) and (
        "publish_linkedin" not in extra_names
    ):
        selected.append("publish_linkedin")

    if permitted_integrations or str(bot.get("outbound_rbac") or "").lower() in {"draft", "execute"}:
        selected.extend(("connector_publish", "request_human_approval"))

    if (
        trigger_type == "on_event:approval.queued"
        or permitted_integrations
        or "notify_approval" in hints
    ):
        selected.append("notify_approval")

    if bot.get("runtime") == "sandbox" or "sandbox_exec" in hints:
        selected.append("sandbox_exec")

    if bot.get("runtime") == "desktop":
        selected.extend(_DESKTOP_TOOL_NAMES)

    if has_ssh_vault:
        selected.extend(_SSH_TOOL_NAMES)
    if can_control_ssh:
        selected.append("ssh_session_control")

    deduped: list[ToolSpec] = []
    seen: set[str] = set()
    for name in selected:
        if name in seen:
            continue
        spec = _ALL_TOOL_SPECS.get(name)
        if spec is not None:
            deduped.append(spec)
            seen.add(name)
    for spec in extra_tool_specs:
        if spec.name in seen:
            continue
        deduped.append(spec)
        seen.add(spec.name)
    return deduped


def _strip_none_recursive(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_none_recursive(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none_recursive(item) for item in value if item is not None]
    return value


def _try_parse_json_dict(raw_json: Any) -> dict[str, Any] | None:
    if isinstance(raw_json, dict):
        return dict(raw_json)
    if not isinstance(raw_json, str) or not raw_json.strip():
        return None
    try:
        parsed = json.loads(raw_json)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def normalize_native_tool_call(
    tool_name: str,
    raw_args: dict[str, Any] | None,
    *,
    tool_call_id: str = "",
) -> dict[str, Any]:
    """Convert a native PydanticAI ToolCallPart payload into an executor-ready action dict."""
    action: dict[str, Any] = {"type": str(tool_name or "").strip()}
    src = raw_args if isinstance(raw_args, dict) else {}

    for key, val in src.items():
        if val is None or key == "type":
            continue
        action[key] = _strip_none_recursive(val)

    if action["type"] == "desktop_browser_action":
        for idx_key in ("index", "tab_index"):
            if isinstance(action.get(idx_key), int) and action[idx_key] < 0:
                action.pop(idx_key, None)

    if action["type"] == "upsert_document":
        doc_obj = _try_parse_json_dict(action.pop("doc_json", None)) or {}
        for fld in ("title", "url", "summary"):
            if fld in action and fld not in doc_obj:
                doc_obj[fld] = action[fld]
        if doc_obj:
            action["doc"] = doc_obj

    if action["type"] == "emit_event":
        payload_obj = _try_parse_json_dict(action.pop("payload_json", None))
        if payload_obj is not None:
            action["payload"] = payload_obj

    if action["type"] == "upsert_page":
        spec_obj = _try_parse_json_dict(action.pop("dashboard_spec_json", None))
        if spec_obj is not None:
            action["dashboard_spec"] = spec_obj

    if action["type"] == "request_human_approval":
        extra_obj = _try_parse_json_dict(action.pop("payload_json", None))
        if extra_obj is not None:
            action["payload"] = extra_obj

    if action["type"] == "configure_routine":
        action_obj = _try_parse_json_dict(action.pop("action_json", None))
        if action_obj is not None:
            action["action"] = action_obj

    if tool_call_id:
        action["_tool_call_id"] = tool_call_id
    return action


def build_pydantic_ai_tool_definitions(tool_specs: Sequence[ToolSpec]) -> list[Any]:
    """Construct PydanticAI ExternalToolset ToolDefinition objects from ToolSpecs."""
    from pydantic_ai import ToolDefinition

    return [
        ToolDefinition(
            name=spec.name,
            description=spec.description,
            parameters_json_schema=copy.deepcopy(spec.parameters_json_schema),
            kind="external",
        )
        for spec in tool_specs
    ]


def build_pydantic_ai_external_toolset(tool_specs: Sequence[ToolSpec]) -> Any:
    """Construct a PydanticAI ExternalToolset wrapping all given ToolSpecs."""
    from pydantic_ai import ExternalToolset

    return ExternalToolset(build_pydantic_ai_tool_definitions(tool_specs))


def verify_native_tool_calling_runtime() -> None:
    """Run build-time validation of Gemini schemas, GoogleModel transformation, and agent.iter."""
    from pydantic_ai import (
        Agent,
        BinaryContent,
        DeferredToolRequests,
        DeferredToolResults,
        ToolReturn,
    )
    from pydantic_ai.messages import (
        PartDeltaEvent,
        PartStartEvent,
        TextPart,
        TextPartDelta,
        ToolCallPart,
    )
    from pydantic_ai.models import ModelRequestParameters
    from pydantic_ai.models.function import AgentInfo, DeltaToolCall, FunctionModel
    from pydantic_ai.models.google import GoogleModel
    from pydantic_ai.providers.google import GoogleProvider
    from pydantic_ai.settings import ModelSettings

    specs = all_tool_specs()
    assert len(specs) >= 40, f"Expected full action registry, found only {len(specs)} tools"
    for spec in specs:
        errs = validate_gemini_safe_schema(spec.parameters_json_schema, tool_name=spec.name)
        assert not errs, f"Gemini schema check failed: {errs}"

    tool_defs = build_pydantic_ai_tool_definitions(specs)
    google_model = GoogleModel("gemini-3.8-flash", provider=GoogleProvider(api_key="smoke"))
    customized = google_model.customize_request_parameters(
        ModelRequestParameters(function_tools=tool_defs, allow_text_output=True)
    )
    assert len(customized.function_tools) == len(tool_defs)

    async def _smoke() -> None:
        async def _turn_stream(messages: list[Any], info: AgentInfo) -> Any:
            has_tool_return = any(
                getattr(part, "part_kind", "") == "tool-return"
                for msg in messages
                for part in getattr(msg, "parts", ())
            )
            if has_tool_return:
                yield "Verified OK"
            else:
                yield {
                    0: DeltaToolCall(
                        name="fetch_public_webpage",
                        json_args='{"url": "https://example.com"}',
                        tool_call_id="smoke_c1",
                    )
                }

        agent = Agent(
            model=FunctionModel(stream_function=_turn_stream),
            output_type=[str, DeferredToolRequests],
            toolsets=[build_pydantic_ai_external_toolset(specs)],
        )

        saw_tool_start = False
        async with agent.iter("Check https://example.com") as run1:
            async for node in run1:
                if Agent.is_model_request_node(node):
                    async with node.stream(run1.ctx) as req_stream:
                        async for event in req_stream:
                            if isinstance(event, PartStartEvent) and isinstance(event.part, ToolCallPart):
                                if event.part.tool_name == "fetch_public_webpage":
                                    saw_tool_start = True

        assert saw_tool_start, "Expected PartStartEvent(ToolCallPart) for fetch_public_webpage"
        r1 = run1.result
        assert r1 is not None and isinstance(r1.output, DeferredToolRequests)
        assert len(r1.output.calls) == 1
        assert r1.output.calls[0].tool_name == "fetch_public_webpage"

        deferred_results = DeferredToolResults(
            calls={
                "smoke_c1": ToolReturn(
                    return_value={"status": "ok"},
                    content=[BinaryContent(data=b"\x89PNG\r\n\x1a\n", media_type="image/png")],
                )
            }
        )
        streamed_chunks: list[str] = []
        async with agent.iter(
            None,
            message_history=r1.all_messages(),
            deferred_tool_results=deferred_results,
            model_settings=ModelSettings(tool_choice="none"),
        ) as run2:
            async for node in run2:
                if Agent.is_model_request_node(node):
                    async with node.stream(run2.ctx) as req_stream:
                        async for event in req_stream:
                            if isinstance(event, PartStartEvent) and isinstance(event.part, TextPart):
                                if event.part.content:
                                    streamed_chunks.append(event.part.content)
                            elif isinstance(event, PartDeltaEvent) and isinstance(event.delta, TextPartDelta):
                                if event.delta.content_delta:
                                    streamed_chunks.append(event.delta.content_delta)
        r2 = run2.result
        assert r2 is not None and r2.output == "Verified OK"
        assert "Verified OK" in "".join(streamed_chunks) or r2.output == "Verified OK"

    asyncio.run(_smoke())
