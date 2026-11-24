export type ViewId =
  | "activity"
  | "approvals"
  | "page"
  | "bot"
  | "desktops"
  | "integrations"
  | "models";

export type ResourceVisibility = "private" | "team" | "shared";

export type SettingsTab =
  | "integrations"
  | "vault"
  | "models"
  | "desktops"
  | "memory"
  | "users"
  | "diagnostics";

export interface HostTelemetry {
  cpu_percent: number;
  ram_percent: number;
  ram_total_gb: number;
  disk_percent: number;
  ram_startup_gate_blocked: boolean;
  ram_critical: boolean;
  disk_warning: boolean;
}

export interface WorkspaceSummary {
  version: string;
  commit_sha?: string;
  sqlite_wal: boolean;
  valkey_connected: boolean;
  vault_configured: boolean;
  counts: {
    pending_approvals: number;
    bots: number;
    pages: number;
    active_integrations: number;
    models: number;
    desktops_running: number;
    desktops_total: number;
    sandboxes_running?: number;
    sandboxes_total?: number;
  };
  host: HostTelemetry;
}

export interface SsoPrincipal {
  authenticated: boolean;
  email: string;
  actor: string;
  display_name?: string;
  must_change_password?: boolean;
  auth_method?: string;
  auth_mode?: "sso" | "local" | "hybrid" | string;
  google_auth_enabled?: boolean;
  is_admin?: boolean;
  multi_user?: boolean;
  groups?: Array<{ slug: string; name: string }>;
  max_active_desktops_per_user?: number;
  max_active_sandboxes_per_user?: number;
}

export interface AuthConfigResponse {
  auth_mode: "sso" | "local" | "hybrid";
  multi_user: boolean;
  google_auth_enabled: boolean;
  needs_setup: boolean;
  public_base_url: string;
}

export interface TeamGroupRecord {
  id: string;
  slug: string;
  name: string;
  description: string;
  member_emails: string[];
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface AdminUserRecord {
  email: string;
  display_name: string;
  role: "admin" | "member";
  active: boolean;
  auth_methods: Array<"password" | "google">;
  has_password: boolean;
  must_change_password: boolean;
  max_active_desktops: number | null;
  max_active_sandboxes: number | null;
  groups: Array<{ slug: string; name: string }>;
  last_login_at?: string | null;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ActivityEvent {
  id: string;
  correlation_id: string;
  source_slug: string;
  target_slug: string | null;
  event_type: string;
  payload: {
    category?: string;
    title?: string;
    badge?: string;
    badge_tone?: string;
    summary?: string;
    meta?: string;
    hop_count?: number;
    [key: string]: unknown;
  };
  created_at: string;
}

export interface BotRoutine {
  id: string;
  type?: string;
  event?: string;
  label: string;
  schedule: string;
  enabled: boolean;
  delivery_mode?: "silent" | "chat_and_activity" | "telegram";
  quiet_hours?: string;
  inbox_query?: string;
  prompt?: string;
  skill_slugs?: string[];
  timezone?: string;
  stale_data_policy?: "skip_quietly" | "notify_missing" | "always_run" | string;
  one_shot?: boolean;
  completed_at?: string;
}

export interface BotTriggerResult {
  status: string;
  bot_slug: string;
  correlation_id: string;
  hop_count?: number;
  model_used?: string;
  tokens_used?: number;
  summary?: string;
  actions?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
}

export interface BotRecord {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  id: string;
  slug: string;
  name: string;
  initials: string;
  avatar_color?: string;
  avatar_icon?: string;
  pinned?: boolean;
  section?: string;
  hidden_in_sidebar?: boolean;
  boundaries?: string[];
  goal_metric?: string;
  handoff_bot_slug?: string;
  onboarding_pending?: boolean;
  role: string;
  enabled: boolean;
  runtime: "api" | "sandbox" | "desktop";
  desktop_policy: string;
  desktop_state: "none" | "running" | "hibernated";
  sandbox_policy?: string;
  sandbox_state?: "none" | "running" | "hibernated";
  ram_mb: number;
  ram_limit_mb: number;
  outbound_rbac: "internal" | "draft" | "execute";
  daily_cap: number;
  max_steps_per_run?: number;
  model: string;
  role_prompt: string;
  routines: BotRoutine[];
  permissions: string[];
  tools?: Array<Record<string, unknown> | string>;
  linked_accounts?: string[];
  linked_accounts_restricted?: boolean;
  collections?: {
    read: string[];
    write: string[];
  };
  created_at: string;
  updated_at: string;
}

export interface BotDraftSpec {
  name: string;
  slug: string;
  avatar_color?: string;
  avatar_icon?: string;
  boundaries?: string[];
  role: string;
  role_prompt: string;
  runtime: "api" | "sandbox" | "desktop";
  desktop_policy: string;
  sandbox_policy?: string;
  outbound_rbac: "internal" | "draft" | "execute";
  daily_cap: number;
  max_steps_per_run?: number;
  model: string;
  routines: BotRoutine[];
  tools: Array<Record<string, unknown> | string>;
  linked_accounts?: string[];
  collections: {
    read: string[];
    write: string[];
  };
}

export interface BotDraftResponse {
  draft: BotDraftSpec;
  restated_summary?: {
    job: string;
    schedule: string;
    autonomy: string;
    boundaries: string[];
  };
  warnings: string[];
  used_llm: boolean;
}

export interface MessageQuote {
  id: string;
  sender: string;
  sender_slug?: string;
  sender_name: string;
  excerpt: string;
}

export interface WorkspaceFileAttachment {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  is_image: boolean;
}

export interface WorkspaceFileRecord extends WorkspaceFileAttachment {
  original_filename?: string;
  sha256?: string;
  owner_email: string;
  uploaded_by?: string;
  has_text_preview?: boolean;
  created_at: string;
  updated_at: string;
}

export interface HabitProposal {
  suggested_skill_name: string;
  suggested_routine_label: string;
  suggested_schedule: string;
  suggested_instructions: string;
}

export interface DelegationPlanStep {
  id: string;
  bot_slug: string;
  bot_name: string;
  task: string;
  parallel_group: number;
}

export interface DelegationPlan {
  id: string;
  coordinator_slug: string;
  coordinator_name: string;
  correlation_id?: string;
  room_slug?: string | null;
  goal: string;
  status: "proposed" | "running" | "completed" | string;
  steps: DelegationPlanStep[];
  results?: Array<{
    step_id: string;
    bot_slug: string;
    bot_name: string;
    task: string;
    status: string;
    summary: string;
    tokens_used?: number;
  }>;
  synthesis?: string;
}

export interface PendingRoomHandoff {
  target_bot_slug: string;
  target_bot_name: string;
  instruction: string;
}

export interface LiveTurnChip {
  chip_id: string;
  action_type: string;
  label: string;
  status: "running" | "done" | "warning" | "stopped" | string;
  elapsed_ms?: number;
  detail?: string;
}

export interface ActiveThreadStream {
  runId: string;
  threadKey: string;
  targetType: "bot" | "room";
  targetSlug: string;
  botSlug: string;
  botName: string;
  text: string;
  chips: LiveTurnChip[];
  routedReason?: string;
  routingSource?: string;
  startedAt: number;
  finishing?: boolean;
}

export interface QueuedMessageAck {
  status: "queued";
  run_id: string;
  user_message: BotMessage | RoomMessage | null;
  queued_behind: number;
  removed_message_ids?: string[];
}

export interface RunCheckpoint {
  steps_completed: number;
  max_steps: number;
  next_batch_steps: number;
  continue_prompt: string;
}

export interface OperatorQuestionOption {
  id: string;
  label: string;
  reply: string;
  tone?: "primary" | "secondary" | "danger";
}

export interface OperatorQuestion {
  id: string;
  question: string;
  context?: string;
  options: OperatorQuestionOption[];
  allow_custom_reply?: boolean;
}

export interface BotMessage {
  id: string;
  bot_slug: string;
  sender: "user" | "bot";
  text: string;
  metadata?: {
    correlation_id?: string;
    run_id?: string;
    stopped_by_user?: boolean;
    chips?: LiveTurnChip[];
    trigger_type?: string;
    model_used?: string;
    tokens_used?: number;
    actions?: Array<{ screenshot_url?: string; slug?: string; page_slug?: string; title?: string; [key: string]: unknown }>;
    delegated_by?: string;
    mentioned_bots?: string[];
    mentioned_integrations?: string[];
    skill_slugs?: string[];
    target_page_slug?: string;
    onboarding_interview?: boolean;
    quick_replies?: string[];
    applied_changes?: Record<string, unknown>;
    habit_proposal?: HabitProposal;
    delegation_plan?: DelegationPlan;
    operator_question?: OperatorQuestion;
    run_checkpoint?: RunCheckpoint;
    attachments?: WorkspaceFileAttachment[];
    reply_to?: MessageQuote;
    reactions?: Record<string, string[]>;
  };
  created_at: string;
}

export interface RoomRecord {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  id: string;
  slug: string;
  title: string;
  member_bot_slugs: string[];
  coordinator_bot_slug: string | null;
  stage_order: string[];
  routing_mode?: "auto" | "lead" | "stage";
  ask_before_bot_handoff: boolean;
  max_bot_turns_per_message: number;
  pinned_page_slug: string | null;
  pinned: boolean;
  section: string;
  created_at: string;
  updated_at: string;
}

export interface RoomMessage {
  id: string;
  room_slug: string;
  sender: "user" | "bot";
  sender_slug: string;
  sender_name: string;
  text: string;
  metadata?: {
    correlation_id?: string;
    run_id?: string;
    stopped_by_user?: boolean;
    chips?: LiveTurnChip[];
    routing_source?: string;
    routed_reason?: string;
    room_slug?: string;
    plan_id?: string;
    step_id?: string;
    delegated_by?: string;
    model_used?: string;
    tokens_used?: number;
    actions?: Array<{ screenshot_url?: string; slug?: string; page_slug?: string; title?: string; [key: string]: unknown }>;
    applied_changes?: Record<string, unknown>;
    delegation_plan?: DelegationPlan;
    operator_question?: OperatorQuestion;
    pending_room_handoff?: PendingRoomHandoff;
    run_checkpoint?: RunCheckpoint;
    attachments?: WorkspaceFileAttachment[];
    reply_to?: MessageQuote;
    reactions?: Record<string, string[]>;
    room_welcome?: boolean;
    skill_slugs?: string[];
    target_page_slug?: string;
  };
  created_at: string;
}

export interface LiveRoomStation {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  slug: string;
  title: string;
  member_bot_slugs: string[];
  last_sender_name: string | null;
  last_message_preview: string;
  last_activity_at: string | null;
  unread: boolean;
}

export interface TeamPackRecord {
  id?: string;
  schema_version: string;
  title: string;
  description?: string;
  section?: string;
  required_providers?: string[];
  bots: Array<Record<string, unknown>>;
  rooms?: Array<Record<string, unknown>>;
  pages?: Array<Record<string, unknown>>;
}

export interface SkillRecord {
  id: string;
  slug: string;
  name: string;
  description: string;
  instructions: string;
  scope_slug: string;
  created_at: string;
  updated_at: string;
}

export interface LiveBotStation {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  slug: string;
  name: string;
  initials: string;
  avatar_color: string;
  avatar_icon?: string;
  pinned?: boolean;
  section: string;
  goal_metric: string;
  role: string;
  enabled: boolean;
  runtime: "api" | "sandbox" | "desktop";
  desktop_state: string;
  sandbox_state?: string;
  state: "running" | "waiting_approval" | "takeover_needed" | "paused" | "idle";
  active_step?: string;
  pending_approvals_count: number;
  schedule_label: string;
  last_run_at: string | null;
  last_summary: string;
  last_action_subtitle?: string;
  last_activity_at?: string | null;
  unread?: boolean;
}

export interface BotRunActivity {
  step: string;
  startedAt: number;
}

export interface DesktopBootProgress {
  state: "booting" | "ready" | "error";
  step: string;
  updatedAt: number;
}

export interface LiveWorkspaceStatusResponse {
  generated_at: string;
  counts: WorkspaceSummary["counts"];
  bots: LiveBotStation[];
  rooms?: LiveRoomStation[];
}

export interface ApprovalExecutionResult {
  action_type?: string;
  session_id?: string | null;
  vault_slug?: string;
  host?: string | null;
  port?: number | null;
  command?: string;
  status?: string;
  exit_code?: number | null;
  prompt_line?: string;
  screen_text?: string;
  trusted_prefixes_added?: string[];
}

export interface ApprovalItem {
  id: string;
  correlation_id: string;
  bot_slug: string;
  target_account_slug: string;
  action_type: string;
  status: "pending" | "approved" | "executed" | "rejected" | "superseded";
  trusted_prefixes_added?: string[];
  payload: {
    title?: string;
    text?: string;
    batch_id?: string;
    suggested_trust_prefixes?: string[];
    execution_result?: ApprovalExecutionResult;
    [key: string]: unknown;
  };
  edited_payload: {
    title?: string;
    text?: string;
    [key: string]: unknown;
  } | null;
  source_url: string | null;
  source_excerpt: string | null;
  escalation_note: string | null;
  approved_by: string | null;
  telegram_chat_id: string | null;
  telegram_message_id: number | null;
  error_message: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface StyleRule {
  id: string;
  scope_slug: string;
  rule_text: string;
  active: boolean;
  created_at: string;
}

export interface PageRecord {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  id: string;
  slug: string;
  title: string;
  icon: string;
  render_mode: "declarative_json" | "sandboxed_html";
  content_payload: string;
  allowed_collections: string[];
  owner_bot_slug: string;
  pinned: boolean;
  updated_at: string;
}

export interface CollectionRecord {
  slug: string;
  label?: string;
  description: string;
  doc_count: number;
  owner_bot_slug?: string | null;
  owner_bot_name?: string | null;
  is_internal?: boolean;
  created_at?: string;
}

export interface CollectionDocument {
  id: string;
  collection: string;
  external_key: string | null;
  search_text: string;
  doc: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface PageDataResponse {
  page: PageRecord;
  parsed_payload: {
    description?: string;
    blocks?: Array<{ label: string; value: string; hint?: string }>;
    rows?: Array<Record<string, string>>;
    [key: string]: unknown;
  };
  collections: Record<string, CollectionDocument[]>;
  collection_counts?: Record<string, number>;
  datasets?: Record<string, Array<Record<string, unknown>>>;
  dataset_profiles?: Record<string, unknown>;
  records: CollectionDocument[];
  total_records: number;
}

export interface PageSqlQueryResult {
  page_slug: string;
  columns: string[];
  rows: Array<Record<string, unknown>>;
  row_count: number;
  truncated: boolean;
  collection_counts: Record<string, number>;
  engine?: "duckdb" | "sqlite";
}

export interface DesktopInfo {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  bot_slug: string;
  bot_name: string;
  role: string;
  container_name: string;
  desktop_state: "running" | "hibernated";
  ram_mb: number;
  ram_limit_mb: number;
  cdp_port: number;
  selkies_port: number;
  mcp_port?: number;
  mcp_url?: string;
  screenshot_url?: string;
  has_screenshot?: boolean;
  last_screenshot_at?: string | null;
  image?: string;
  volume_path?: string;
  selkies_url?: string;
  idle_seconds?: number;
  idle_timeout_seconds?: number;
  takeover_active?: boolean;
  awaiting_takeover?: boolean;
  takeover_reason?: string | null;
}

export interface DesktopLaunchQueueItem {
  bot_slug: string;
  reason: string;
  ram_percent: number;
  queued_at: string;
}

export interface SandboxInfo {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  bot_slug: string;
  bot_name: string;
  role: string;
  container_name: string;
  sandbox_state: "running" | "hibernated";
  ram_mb: number;
  ram_limit_mb: number;
  image?: string;
  volume_path?: string;
  idle_seconds?: number;
  idle_timeout_seconds?: number;
}

export interface DesktopsResponse {
  host: HostTelemetry;
  desktops: DesktopInfo[];
  queued_launches: DesktopLaunchQueueItem[];
  sandboxes?: SandboxInfo[];
}

export interface IntegrationAccount {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  id: string;
  slug: string;
  provider: "google" | "telegram" | "linkedin" | "webhook" | "mcp";
  display_name: string;
  account_identifier: string | null;
  scopes: string[];
  status: string;
  has_secrets: boolean;
  last_checked_at: string | null;
  last_error: string | null;
  created_at: string;
}

export interface ModelProvider {
  id: string;
  slug: string;
  provider_type: "google" | "anthropic" | "openai" | "xai" | "openrouter" | "ollama";
  model_id: string;
  api_base: string | null;
  has_api_key: boolean;
  is_default: boolean;
  daily_token_limit: number | null;
  monthly_budget_usd: number | null;
  input_price_per_million?: number | null;
  output_price_per_million?: number | null;
  effective_input_price_per_million?: number;
  effective_output_price_per_million?: number;
  pricing_source?: "custom" | "live" | "catalog" | "provider_default" | "local";
  today_tokens?: number;
  today_cost_usd?: number;
  month_tokens?: number;
  month_cost_usd?: number;
  created_at: string;
}

export interface DiscoveredProviderModel {
  model_id: string;
  display_name: string;
  context_window?: number | null;
  input_price_per_million: number;
  output_price_per_million: number;
  pricing_source: "live" | "catalog" | "provider_default" | "local";
}

export interface DiscoverModelsResponse {
  provider_type: ModelProvider["provider_type"];
  models: DiscoveredProviderModel[];
  pricing_mode: "live" | "local" | "estimated";
  source_note: string;
}

export interface BotRunRecord {
  triggered_by_email?: string;
  id: string;
  correlation_id: string;
  bot_slug: string;
  trigger_type: string;
  hop_count: number;
  llm_model_used: string | null;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number;
  status: string;
  summary: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface BotModelUsageSlice {
  model_id: string;
  runs_count: number;
  today_tokens: number;
  month_tokens: number;
  month_cost_usd: number;
}

export interface BotUsageItem {
  bot_slug: string;
  bot_name: string;
  model: string;
  enabled: boolean;
  exists?: boolean;
  runs_count: number;
  today_tokens: number;
  month_tokens: number;
  month_cost_usd: number;
  top_trigger_type: string;
  models_used?: BotModelUsageSlice[];
}

export interface UserUsageItem {
  email: string;
  runs_count: number;
  today_tokens: number;
  month_tokens: number;
  month_cost_usd: number;
}

export interface ModelsResponse {
  usage_by_user?: UserUsageItem[];
  providers: ModelProvider[];
  today_tokens: number;
  today_cost_usd: number;
  month_tokens?: number;
  month_cost_usd?: number;
  deduplicated_runs_today?: number;
  deduplicated_runs_month?: number;
  recent_runs?: BotRunRecord[];
  usage_by_bot?: BotUsageItem[];
}

export interface GoogleScopeGroup {
  key: string;
  label: string;
  description: string;
  scopes: string[];
}

export interface GoogleWizardConfig {
  redirect_uri: string;
  has_saved_client: boolean;
  saved_client_id_hint: string | null;
  has_server_client?: boolean;
  server_client_id_hint?: string | null;
  has_personal_gmail_client?: boolean;
  personal_client_id_hint?: string | null;
  workspace_client_id_hint?: string | null;
  saved_accounts?: Array<{
    slug: string;
    display_name: string;
    account_identifier: string | null;
    client_id_hint: string | null;
  }>;
  required_oauth_params: {
    access_type: string;
    include_granted_scopes: string;
    prompt: string;
    pkce: string;
  };
  steps: Array<{
    step: number;
    title: string;
    summary: string;
  }>;
  scope_catalog: GoogleScopeGroup[];
}

export interface GoogleAuthorizeResponse {
  authorization_url: string;
  state: string;
  redirect_uri: string;
  scope_groups: string[];
  scopes: string[];
  expires_in_seconds: number;
}

export interface WebhookOnboardResponse extends IntegrationAccount {
  webhook_path: string;
  event_type: string;
  target_collection: string | null;
  signing_secret_once: string | null;
}

export interface TelegramSyncSummary {
  slug: string;
  channels: string[];
  fetched_count: number;
  new_count: number;
  updated_count: number;
  collection: string;
}

export interface ProbeAllResponse {
  total: number;
  ok: number;
  degraded: number;
  expired: number;
  results: Array<{
    slug: string;
    provider: string;
    status: string;
    last_error: string | null;
  }>;
}

export interface DebugTraceTurn {
  turn: number;
  prompt_preview?: string;
  response_preview?: string;
  actions?: Array<Record<string, unknown>>;
  action_results?: Array<Record<string, unknown>>;
  sources?: Record<string, string[]>;
  deduplicated_count?: number;
}

export interface DebugRunTrace {
  id: string;
  bot_slug: string;
  bot_name: string;
  correlation_id: string;
  trigger_type: string;
  status: string;
  model_used: string;
  tokens_used: number;
  summary: string;
  error: string | null;
  turns: DebugTraceTurn[];
  started_at: string;
  finished_at: string;
}

export interface DebugLogEntry {
  seq: number;
  ts: string;
  level: string;
  logger: string;
  message: string;
}

export interface DebugOverviewResponse {
  traces: DebugRunTrace[];
  logs: DebugLogEntry[];
  integrations: IntegrationAccount[];
  counts: WorkspaceSummary["counts"];
}

export interface VaultSecretRecord {
  owner_email?: string;
  visibility?: ResourceVisibility;
  allowed_groups?: string[];
  id: string;
  slug: string;
  name: string;
  secret_type: "ssh" | "login" | "api_token" | "custom" | string;
  host: string;
  port: string;
  url: string;
  secret_keys: string[];
  allowed_bots: string[];
  trusted_command_prefixes?: string[];
  host_key_fingerprints?: Record<string, string>;
  env_placeholders: string[];
  created_at: string;
  updated_at: string;
}

export interface SSHSessionRecord {
  session_id: string;
  bot_slug: string;
  vault_slug: string;
  host: string;
  port: number;
  correlation_id: string;
  status: "active" | "awaiting_input" | "taken_over" | "paused" | "closed" | string;
  operator_takeover: boolean;
  paused: boolean;
  pinned: boolean;
  last_command: string;
  screen_text: string;
  cast_relpath?: string;
  cast_sha256?: string;
  created_at: string;
  expires_at: string;
  live?: boolean;
}

export interface SSHAuditSettings {
  retention_hours: number;
  total_recordings: number;
  pinned_recordings: number;
}

export interface ChatRetentionSettings {
  retention_days: number;
  bot_messages_count: number;
  room_messages_count: number;
  updated_at?: string | null;
  pruned_bot_messages?: number;
  pruned_room_messages?: number;
  pruned_total?: number;
}

export interface ClearMessagesResponse<T> {
  status: string;
  target_type: "bot" | "room";
  slug: string;
  deleted_count: number;
  remaining_count: number;
  messages: T[];
  has_more: boolean;
  total_count: number;
}

export interface DesktopRecordingStatus {
  status: string;
  recording: boolean;
  started_at?: string;
  elapsed_seconds?: number;
  command_count?: number;
  event_count?: number;
}

export interface DesktopRecordingStopResponse {
  status: string;
  discarded?: boolean;
  recording: {
    duration_seconds?: number;
    commands?: Array<Record<string, unknown>>;
    visited_urls?: Array<Record<string, unknown>>;
    window_events?: Array<Record<string, unknown>>;
    clicks?: Array<Record<string, unknown>>;
    dom_events?: Array<Record<string, unknown>>;
    typed_inputs?: Array<Record<string, unknown>>;
  };
  skill: SkillRecord | null;
}
