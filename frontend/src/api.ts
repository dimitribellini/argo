import type {
  ActivityEvent,
  AdminUserRecord,
  ApprovalItem,
  AuthConfigResponse,
  BotDraftResponse,
  BotMessage,
  BotRecord,
  BotRunRecord,
  BotTriggerResult,
  ChatRetentionSettings,
  ClearMessagesResponse,
  CollectionDocument,
  CollectionRecord,
  DebugOverviewResponse,
  DelegationPlan,
  DelegationPlanStep,
  DesktopInfo,
  DesktopRecordingStatus,
  DesktopRecordingStopResponse,
  DesktopsResponse,
  DiscoverModelsResponse,
  GoogleAuthorizeResponse,
  GoogleWizardConfig,
  HostTelemetry,
  IntegrationAccount,
  LiveWorkspaceStatusResponse,
  ModelsResponse,
  ModelProvider,
  PageDataResponse,
  PageRecord,
  PageSqlQueryResult,
  ProbeAllResponse,
  QueuedMessageAck,
  ResourceVisibility,
  RoomMessage,
  RoomRecord,
  SandboxInfo,
  SSHAuditSettings,
  SSHSessionRecord,
  SkillRecord,
  SsoPrincipal,
  StyleRule,
  TeamGroupRecord,
  TeamPackRecord,
  TelegramSyncSummary,
  VaultSecretRecord,
  WebhookOnboardResponse,
  WorkspaceFileRecord,
  WorkspaceSummary,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export const MAX_WORKSPACE_FILE_BYTES = 10 * 1024 * 1024;
export const MAX_ANALYTICS_UPLOAD_BYTES = 100 * 1024 * 1024;

const ANALYTICS_DOCUMENT_EXTS = new Set([
  ".csv",
  ".tsv",
  ".parquet",
  ".json",
  ".ndjson",
  ".jsonl",
  ".xlsx",
  ".xlsm",
  ".xlsb",
  ".xls",
  ".ods",
  ".pdf",
  ".docx",
]);

const ANALYTICS_DOCUMENT_MIMES = new Set([
  "text/csv",
  "text/tab-separated-values",
  "application/csv",
  "application/parquet",
  "application/vnd.apache.parquet",
  "application/x-parquet",
  "application/json",
  "application/x-ndjson",
  "application/ndjson",
  "application/jsonl",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-excel.sheet.macroenabled.12",
  "application/vnd.ms-excel.sheet.binary.macroenabled.12",
  "application/vnd.ms-excel",
  "application/vnd.oasis.opendocument.spreadsheet",
  "application/pdf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]);

export function maxWorkspaceFileBytesForName(filename: string, mimeType = ""): number {
  const cleanName = String(filename || "").trim().toLowerCase();
  const dotIdx = cleanName.lastIndexOf(".");
  const ext = dotIdx >= 0 ? cleanName.slice(dotIdx) : "";
  const cleanMime = String(mimeType || "").split(";")[0].trim().toLowerCase();
  if (ANALYTICS_DOCUMENT_EXTS.has(ext) || ANALYTICS_DOCUMENT_MIMES.has(cleanMime)) {
    return MAX_ANALYTICS_UPLOAD_BYTES;
  }
  return MAX_WORKSPACE_FILE_BYTES;
}

function clearMessagesSuffix(opts?: { keep_last?: number; older_than_days?: number }): string {
  const qs = new URLSearchParams();
  if (opts?.keep_last !== undefined) qs.set("keep_last", String(opts.keep_last));
  if (opts?.older_than_days !== undefined) {
    qs.set("older_than_days", String(opts.older_than_days));
  }
  return qs.toString() ? `?${qs.toString()}` : "";
}

async function downloadTranscriptMarkdown(url: string, filename: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) {
    let detail = `Export failed (${response.status})`;
    try {
      const data = (await response.json()) as { detail?: string };
      if (data.detail) detail = data.detail;
    } catch {
      // Ignore parse errors for non-JSON responses.
    }
    throw new Error(detail);
  }
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  return filename;
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const data = (await response.json()) as { detail?: string };
      if (data.detail) {
        detail = data.detail;
      }
    } catch {
      // Ignore parse errors for non-JSON error responses.
    }
    throw new ApiError(detail, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  getAuthConfig: () => requestJson<AuthConfigResponse>("/api/auth/config"),
  bootstrapAdmin: (payload: { email: string; display_name?: string; password: string }) =>
    requestJson<{ status: string; user: AdminUserRecord }>("/api/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  loginWithPassword: (email: string, password: string) =>
    requestJson<{ status: string; user: AdminUserRecord }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () =>
    requestJson<{ status: string }>("/api/auth/logout", {
      method: "POST",
      body: JSON.stringify({}),
    }),
  changePassword: (payload: { current_password?: string; new_password: string }) =>
    requestJson<{ status: string; user: AdminUserRecord }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listMyTeams: () => requestJson<TeamGroupRecord[]>("/api/teams"),
  listAdminUsers: () => requestJson<AdminUserRecord[]>("/api/admin/users"),
  createAdminUser: (payload: {
    email: string;
    display_name?: string;
    role: "admin" | "member";
    auth_methods: Array<"password" | "google">;
    password?: string;
    must_change_password?: boolean;
    group_slugs?: string[];
    max_active_desktops?: number | null;
    max_active_sandboxes?: number | null;
  }) =>
    requestJson<AdminUserRecord>("/api/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateAdminUser: (
    email: string,
    payload: {
      display_name?: string;
      role?: "admin" | "member";
      active?: boolean;
      auth_methods?: Array<"password" | "google">;
      group_slugs?: string[];
      max_active_desktops?: number | null;
      max_active_sandboxes?: number | null;
      clear_quota_overrides?: boolean;
    },
  ) =>
    requestJson<AdminUserRecord>(`/api/admin/users/${encodeURIComponent(email)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  resetAdminUserPassword: (
    email: string,
    newPassword: string,
    mustChangePassword = true,
  ) =>
    requestJson<AdminUserRecord>(
      `/api/admin/users/${encodeURIComponent(email)}/reset-password`,
      {
        method: "POST",
        body: JSON.stringify({
          new_password: newPassword,
          must_change_password: mustChangePassword,
        }),
      },
    ),
  deleteAdminUser: (email: string) =>
    requestJson<{ status: string; email: string }>(
      `/api/admin/users/${encodeURIComponent(email)}`,
      { method: "DELETE" },
    ),
  createAdminTeam: (payload: {
    name: string;
    slug?: string;
    description?: string;
    member_emails?: string[];
  }) =>
    requestJson<TeamGroupRecord>("/api/admin/teams", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateAdminTeam: (
    slug: string,
    payload: { name?: string; description?: string; member_emails?: string[] },
  ) =>
    requestJson<TeamGroupRecord>(`/api/admin/teams/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteAdminTeam: (slug: string) =>
    requestJson<{ status: string; slug: string }>(
      `/api/admin/teams/${encodeURIComponent(slug)}`,
      { method: "DELETE" },
    ),

  getMe: () => requestJson<SsoPrincipal>("/api/me"),
  getSummary: () => requestJson<WorkspaceSummary>("/api/workspace/summary"),
  getLiveStatus: () => requestJson<LiveWorkspaceStatusResponse>("/api/workspace/live-status"),

  listActivity: (category = "all") =>
    requestJson<ActivityEvent[]>(`/api/activity?category=${encodeURIComponent(category)}`),
  dispatchActivity: (instruction: string, target_slug?: string) =>
    requestJson<ActivityEvent>("/api/activity/dispatch", {
      method: "POST",
      body: JSON.stringify(target_slug ? { instruction, target_slug } : { instruction }),
    }),

  listBots: () => requestJson<BotRecord[]>("/api/bots"),
  draftBotSpec: (payload: {
    prompt: string;
    preferred_runtime?: "auto" | "api" | "sandbox" | "desktop";
    preferred_rbac?: "auto" | "internal" | "draft" | "execute";
    preferred_model?: string;
    linked_accounts?: string[];
  }) =>
    requestJson<BotDraftResponse>("/api/bots/builder/draft", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createBot: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    name: string;
    role?: string;
    role_prompt?: string;
    runtime: "api" | "sandbox" | "desktop";
    outbound_rbac: "internal" | "draft" | "execute";
    model: string;
    daily_cap: number;
    routines?: Array<Record<string, unknown>>;
    tools?: Array<Record<string, unknown> | string>;
    collections?: { read: string[]; write: string[] };
    linked_accounts?: string[];
    avatar_color?: string;
    avatar_icon?: string;
    pinned?: boolean;
    section?: string;
    hidden_in_sidebar?: boolean;
    boundaries?: string[];
    goal_metric?: string;
    handoff_bot_slug?: string;
    onboarding_mode?: "configured" | "interview";
  }) =>
    requestJson<BotRecord>("/api/bots", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  exportBotBlueprint: (slug: string) =>
    requestJson<Record<string, unknown>>(`/api/bots/${encodeURIComponent(slug)}/blueprint`),
  importBotBlueprint: (payload: {
    blueprint: Record<string, unknown>;
    linked_accounts?: string[];
  }) =>
    requestJson<BotRecord>("/api/bots/import-blueprint", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteBot: (slug: string) =>
    requestJson<{ status: string; slug: string }>(`/api/bots/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  triggerBot: (
    slug: string,
    payload?: {
      routine_id?: string;
      input_text?: string;
      payload?: Record<string, unknown>;
      wait_for_chain?: boolean;
    },
  ) =>
    requestJson<BotTriggerResult>(`/api/bots/${encodeURIComponent(slug)}/trigger`, {
      method: "POST",
      body: JSON.stringify(payload ?? { wait_for_chain: true }),
    }),
  updateBot: (
    slug: string,
    updates: {
      visibility?: ResourceVisibility;
    allowed_groups?: string[];
      name?: string;
      enabled?: boolean;
      runtime?: "api" | "sandbox" | "desktop";
      role?: string;
      role_prompt?: string;
      model?: string;
      outbound_rbac?: "internal" | "draft" | "execute";
      daily_cap?: number;
      max_steps_per_run?: number;
      toggle_routine_id?: string;
      routines?: Array<Record<string, unknown>>;
      collections?: { read: string[]; write: string[] };
      linked_accounts?: string[];
      avatar_color?: string;
      avatar_icon?: string;
      pinned?: boolean;
      section?: string;
      hidden_in_sidebar?: boolean;
      boundaries?: string[];
      goal_metric?: string;
      handoff_bot_slug?: string;
      onboarding_pending?: boolean;
    },
  ) =>
    requestJson<BotRecord>(`/api/bots/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),
  listBotMessages: (slug: string) =>
    requestJson<BotMessage[]>(`/api/bots/${encodeURIComponent(slug)}/messages`),
  clearBotMessages: (
    slug: string,
    opts?: { keep_last?: number; older_than_days?: number },
  ) =>
    requestJson<ClearMessagesResponse<BotMessage>>(
      `/api/bots/${encodeURIComponent(slug)}/messages${clearMessagesSuffix(opts)}`,
      { method: "DELETE" },
    ),
  exportBotMessagesMarkdown: (slug: string) =>
    downloadTranscriptMarkdown(
      `/api/bots/${encodeURIComponent(slug)}/messages/export`,
      `${slug}-chat.md`,
    ),
  listBotMessagesPage: async (
    slug: string,
    opts?: { limit?: number; beforeId?: string },
  ): Promise<{ messages: BotMessage[]; hasMore: boolean; totalCount: number }> => {
    const qs = new URLSearchParams();
    qs.set("limit", String(opts?.limit ?? 40));
    if (opts?.beforeId) qs.set("before_id", opts.beforeId);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 15_000);
    let response: Response;
    try {
      response = await fetch(`/api/bots/${encodeURIComponent(slug)}/messages?${qs.toString()}`, {
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error("Timed out loading bot messages.");
      }
      throw err;
    } finally {
      window.clearTimeout(timer);
    }
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const data = (await response.json()) as { detail?: string };
        if (data.detail) detail = data.detail;
      } catch {
        // Ignore parse errors for non-JSON responses.
      }
      throw new Error(detail);
    }
    const messages = (await response.json()) as BotMessage[];
    const hasMore = response.headers.get("X-Has-More") === "true";
    const parsedTotal = Number(response.headers.get("X-Total-Count") ?? messages.length);
    return {
      messages,
      hasMore,
      totalCount: Number.isFinite(parsedTotal) ? parsedTotal : messages.length,
    };
  },
  sendBotMessage: (
    slug: string,
    text: string,
    options?: {
      skill_slugs?: string[];
      context_correlation_id?: string;
      target_page_slug?: string;
      reply_to_id?: string;
      attachment_ids?: string[];
    },
  ) =>
    requestJson<{
      messages: BotMessage[];
      has_more?: boolean;
      total_count?: number;
      run?: BotRunRecord;
      result?: BotTriggerResult;
    }>(`/api/bots/${encodeURIComponent(slug)}/messages`, {
      method: "POST",
      body: JSON.stringify({
        text,
        ...(options ?? {}),
      }),
    }),
  sendBotMessageAsync: (
    slug: string,
    text: string,
    options?: {
      skill_slugs?: string[];
      context_correlation_id?: string;
      target_page_slug?: string;
      reply_to_id?: string;
      attachment_ids?: string[];
    },
  ) =>
    requestJson<QueuedMessageAck>(`/api/bots/${encodeURIComponent(slug)}/messages`, {
      method: "POST",
      body: JSON.stringify({
        text,
        async_mode: true,
        ...(options ?? {}),
      }),
    }),
  editLastBotMessage: (slug: string, messageId: string, text: string) =>
    requestJson<QueuedMessageAck>(
      `/api/bots/${encodeURIComponent(slug)}/messages/${encodeURIComponent(messageId)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ text, async_mode: true }),
      },
    ),
  cancelRun: (runId: string) =>
    requestJson<{ status: string; run_id: string; message_id?: string | null }>(
      `/api/runs/${encodeURIComponent(runId)}/cancel`,
      { method: "POST" },
    ),

  markThreadRead: (target_type: "bot" | "room", slug: string) =>
    requestJson<{ user_email: string; target_type: string; slug: string; last_read_at: string }>(
      "/api/threads/read",
      {
        method: "POST",
        body: JSON.stringify({ target_type, slug }),
      },
    ),
  toggleMessageReaction: (
    messageId: string,
    payload: { collection: "bot_threads" | "room_threads"; emoji: string },
  ) =>
    requestJson<{ id: string; reactions: Record<string, string[]> }>(
      `/api/messages/${encodeURIComponent(messageId)}/reactions`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
  executeBotPlan: (slug: string, planId: string, editedSteps?: DelegationPlanStep[]) =>
    requestJson<{
      status: string;
      plan: DelegationPlan;
      synthesis: string;
      results: Array<Record<string, unknown>>;
    }>(`/api/bots/${encodeURIComponent(slug)}/plans/${encodeURIComponent(planId)}/execute`, {
      method: "POST",
      body: JSON.stringify({ edited_steps: editedSteps ?? null }),
    }),

  listRooms: () => requestJson<RoomRecord[]>("/api/rooms"),
  createRoom: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    title: string;
    member_bot_slugs: string[];
    coordinator_bot_slug?: string | null;
    stage_order?: string[];
    routing_mode?: "auto" | "lead" | "stage";
    ask_before_bot_handoff?: boolean;
    max_bot_turns_per_message?: number;
    pinned_page_slug?: string | null;
    pinned?: boolean;
    section?: string;
  }) =>
    requestJson<RoomRecord>("/api/rooms", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getRoom: (slug: string) => requestJson<RoomRecord>(`/api/rooms/${encodeURIComponent(slug)}`),
  updateRoom: (
    slug: string,
    updates: {
      visibility?: ResourceVisibility;
    allowed_groups?: string[];
      title?: string;
      member_bot_slugs?: string[];
      coordinator_bot_slug?: string | null;
      stage_order?: string[];
      routing_mode?: "auto" | "lead" | "stage";
      ask_before_bot_handoff?: boolean;
      max_bot_turns_per_message?: number;
      pinned_page_slug?: string | null;
      pinned?: boolean;
      section?: string;
    },
  ) =>
    requestJson<RoomRecord>(`/api/rooms/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),
  deleteRoom: (slug: string) =>
    requestJson<{ status: string; slug: string }>(`/api/rooms/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  clearRoomMessages: (
    slug: string,
    opts?: { keep_last?: number; older_than_days?: number },
  ) =>
    requestJson<ClearMessagesResponse<RoomMessage>>(
      `/api/rooms/${encodeURIComponent(slug)}/messages${clearMessagesSuffix(opts)}`,
      { method: "DELETE" },
    ),
  exportRoomMessagesMarkdown: (slug: string) =>
    downloadTranscriptMarkdown(
      `/api/rooms/${encodeURIComponent(slug)}/messages/export`,
      `${slug}-room-chat.md`,
    ),
  listRoomMessagesPage: async (
    slug: string,
    opts?: { limit?: number; beforeId?: string },
  ): Promise<{ messages: RoomMessage[]; hasMore: boolean; totalCount: number }> => {
    const qs = new URLSearchParams();
    qs.set("limit", String(opts?.limit ?? 40));
    if (opts?.beforeId) qs.set("before_id", opts.beforeId);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 15_000);
    let response: Response;
    try {
      response = await fetch(`/api/rooms/${encodeURIComponent(slug)}/messages?${qs.toString()}`, {
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error("Timed out loading room messages.");
      }
      throw err;
    } finally {
      window.clearTimeout(timer);
    }
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const data = (await response.json()) as { detail?: string };
        if (data.detail) detail = data.detail;
      } catch {
        // Ignore parse errors for non-JSON responses.
      }
      throw new Error(detail);
    }
    const messages = (await response.json()) as RoomMessage[];
    const hasMore = response.headers.get("X-Has-More") === "true";
    const parsedTotal = Number(response.headers.get("X-Total-Count") ?? messages.length);
    return {
      messages,
      hasMore,
      totalCount: Number.isFinite(parsedTotal) ? parsedTotal : messages.length,
    };
  },
  sendRoomMessage: (
    slug: string,
    payload: {
      text: string;
      reply_to_id?: string;
      attachment_ids?: string[];
      skill_slugs?: string[];
      target_page_slug?: string;
      approved_handoff_bot_slug?: string;
    },
  ) =>
    requestJson<{
      room_slug: string;
      messages: RoomMessage[];
      has_more: boolean;
      total_count: number;
      results?: BotTriggerResult[];
      actions?: Array<Record<string, unknown>>;
    }>(`/api/rooms/${encodeURIComponent(slug)}/messages`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  sendRoomMessageAsync: (
    slug: string,
    payload: {
      text: string;
      reply_to_id?: string;
      attachment_ids?: string[];
      skill_slugs?: string[];
      target_page_slug?: string;
      approved_handoff_bot_slug?: string;
    },
  ) =>
    requestJson<QueuedMessageAck>(`/api/rooms/${encodeURIComponent(slug)}/messages`, {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        async_mode: true,
      }),
    }),
  editLastRoomMessage: (slug: string, messageId: string, text: string) =>
    requestJson<QueuedMessageAck>(
      `/api/rooms/${encodeURIComponent(slug)}/messages/${encodeURIComponent(messageId)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ text, async_mode: true }),
      },
    ),
  executeRoomPlan: (slug: string, planId: string, editedSteps?: DelegationPlanStep[]) =>
    requestJson<{
      status: string;
      plan: DelegationPlan;
      synthesis: string;
      results: Array<Record<string, unknown>>;
    }>(`/api/rooms/${encodeURIComponent(slug)}/plans/${encodeURIComponent(planId)}/execute`, {
      method: "POST",
      body: JSON.stringify({ edited_steps: editedSteps ?? null }),
    }),

  listWorkspaceFiles: () => requestJson<WorkspaceFileRecord[]>("/api/files"),
  uploadWorkspaceFile: async (file: File): Promise<WorkspaceFileRecord> => {
    const byteLimit = maxWorkspaceFileBytesForName(file.name, file.type);
    if (file.size > byteLimit) {
      const limitMb = Math.round(byteLimit / (1024 * 1024));
      throw new Error(`File exceeds the ${limitMb} MB per-file upload limit.`);
    }
    const response = await fetch("/api/files", {
      method: "POST",
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        "X-File-Name": encodeURIComponent(file.name),
      },
      body: file,
    });
    if (!response.ok) {
      let detail = `Upload failed (${response.status})`;
      try {
        const data = (await response.json()) as { detail?: string };
        if (data.detail) detail = data.detail;
      } catch {
        // Ignore parse errors.
      }
      throw new Error(detail);
    }
    return (await response.json()) as WorkspaceFileRecord;
  },
  uploadWorkspaceFileText: (filename: string, text: string, mime_type = "text/markdown") =>
    requestJson<WorkspaceFileRecord>("/api/files", {
      method: "POST",
      body: JSON.stringify({ filename, mime_type, text }),
    }),
  workspaceFileContentUrl: (fileId: string, opts?: { download?: boolean }) =>
    `/api/files/${encodeURIComponent(fileId)}/content${opts?.download ? "?download=true" : ""}`,
  deleteWorkspaceFile: (fileId: string) =>
    requestJson<{ status: string; id: string }>(`/api/files/${encodeURIComponent(fileId)}`, {
      method: "DELETE",
    }),

  listStarterTeamPacks: () => requestJson<TeamPackRecord[]>("/api/team-packs/starters"),
  exportTeamPack: (opts?: {
    section?: string;
    room_slug?: string;
    bot_slugs?: string[];
    title?: string;
  }) => {
    const qs = new URLSearchParams();
    if (opts?.section) qs.set("section", opts.section);
    if (opts?.room_slug) qs.set("room_slug", opts.room_slug);
    if (opts?.bot_slugs?.length) qs.set("bot_slugs", opts.bot_slugs.join(","));
    if (opts?.title) qs.set("title", opts.title);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return requestJson<TeamPackRecord>(`/api/team-packs/export${suffix}`);
  },
  importTeamPack: (payload: {
    pack: Record<string, unknown>;
    linked_accounts?: string[];
    section_override?: string;
  }) =>
    requestJson<{
      bots: BotRecord[];
      rooms: RoomRecord[];
      pages: PageRecord[];
      slug_map: Record<string, string>;
    }>("/api/team-packs/import", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listApprovals: (tab: "pending" | "history" | "all" = "pending") =>
    requestJson<ApprovalItem[]>(`/api/approvals?tab=${tab}`),
  resolveApproval: (
    approvalId: string,
    payload: {
      action: "approve" | "reject" | "edit_approve";
      edited_text?: string;
      style_rule?: string;
      trust_command?: boolean;
      trust_prefixes?: string[];
    },
  ) =>
    requestJson<ApprovalItem>(`/api/approvals/${encodeURIComponent(approvalId)}/resolve`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  batchResolveApprovals: (payload: {
    approval_ids: string[];
    action: "approve" | "reject";
    trust_command?: boolean;
  }) =>
    requestJson<{
      items: ApprovalItem[];
      resolved_count: number;
      errors: Array<{ approval_id: string; detail: string }>;
      trusted_prefixes_added?: string[];
    }>("/api/approvals/batch-resolve", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listStyleRules: () => requestJson<StyleRule[]>("/api/style-rules"),
  addStyleRule: (rule_text: string, scope_slug = "*") =>
    requestJson<StyleRule>("/api/style-rules", {
      method: "POST",
      body: JSON.stringify({ rule_text, scope_slug }),
    }),
  deleteStyleRule: (ruleId: string) =>
    requestJson<{ status: string }>(`/api/style-rules/${encodeURIComponent(ruleId)}`, {
      method: "DELETE",
    }),
  importStyleRules: (raw_text: string, scope_slug = "*") =>
    requestJson<{ imported_count: number; rules: StyleRule[] }>("/api/style-rules/import", {
      method: "POST",
      body: JSON.stringify({ raw_text, scope_slug }),
    }),

  listSkills: (scopeSlug?: string) => {
    const qs = scopeSlug ? `?scope_slug=${encodeURIComponent(scopeSlug)}` : "";
    return requestJson<SkillRecord[]>(`/api/skills${qs}`);
  },
  upsertSkill: (payload: {
    name: string;
    description?: string;
    instructions: string;
    scope_slug?: string;
  }) =>
    requestJson<SkillRecord>("/api/skills", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteSkill: (skillId: string) =>
    requestJson<{ status: string }>(`/api/skills/${encodeURIComponent(skillId)}`, {
      method: "DELETE",
    }),

  listCollections: () =>
    requestJson<CollectionRecord[]>("/api/collections"),
  listPages: () => requestJson<PageRecord[]>("/api/pages"),
  generatePage: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    prompt: string;
    title?: string;
    owner_bot_slug?: string;
    allowed_collections?: string[];
    existing_page_slug?: string;
    template_key?:
      | "auto"
      | "live_operations_map"
      | "bot_hub_board"
      | "collection_analytics"
      | "interactive_playground"
      | "data_dashboard";
  }) =>
    requestJson<PageRecord>("/api/pages/generate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createPage: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    title: string;
    description: string;
    render_mode: "declarative_json" | "sandboxed_html";
    content_payload?: string;
    allowed_collections?: string[];
  }) =>
    requestJson<PageRecord>("/api/pages", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updatePage: (
    slug: string,
    payload: {
      visibility?: ResourceVisibility;
    allowed_groups?: string[];
      title?: string;
      description?: string;
      render_mode?: "declarative_json" | "sandboxed_html";
      content_payload?: string;
      allowed_collections?: string[];
      pinned?: boolean;
    },
  ) =>
    requestJson<PageRecord>(`/api/pages/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deletePage: (slug: string) =>
    requestJson<{ status: string; slug: string }>(`/api/pages/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  getPageData: (slug: string, qOrOpts?: string | { q?: string; limit?: number }) => {
    const params = new URLSearchParams();
    if (typeof qOrOpts === "string") {
      if (qOrOpts.trim()) params.set("q", qOrOpts.trim());
    } else if (qOrOpts && typeof qOrOpts === "object") {
      if (qOrOpts.q?.trim()) params.set("q", qOrOpts.q.trim());
      if (typeof qOrOpts.limit === "number") params.set("limit", String(qOrOpts.limit));
    }
    const qs = params.toString() ? `?${params.toString()}` : "";
    return requestJson<PageDataResponse>(`/api/pages/${encodeURIComponent(slug)}/data${qs}`);
  },
  queryPageCollection: (
    slug: string,
    payload: { collection: string; query?: string; limit?: number },
  ) =>
    requestJson<{ page_slug: string; collection: string; records: CollectionDocument[] }>(
      `/api/pages/${encodeURIComponent(slug)}/query`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
  queryPageSql: (
    slug: string,
    payload: { sql: string; params?: unknown[]; row_cap?: number; engine?: "auto" | "duckdb" | "sqlite" },
  ) =>
    requestJson<PageSqlQueryResult>(
      `/api/pages/${encodeURIComponent(slug)}/sql`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),

  listDesktops: () => requestJson<DesktopsResponse>("/api/desktops"),
  toggleDesktop: (slug: string) =>
    requestJson<BotRecord>(`/api/desktops/${encodeURIComponent(slug)}/toggle`, {
      method: "POST",
    }),
  stopAllDesktops: () =>
    requestJson<{ stopped_desktops: string[] }>("/api/desktops/stop-all", {
      method: "POST",
    }),
  sweepIdleDesktops: () =>
    requestJson<{ hibernated_desktops: string[] }>("/api/desktops/sweep-idle", {
      method: "POST",
    }),
  listSandboxes: () =>
    requestJson<{ host: HostTelemetry; sandboxes: SandboxInfo[] }>("/api/sandboxes"),
  toggleSandbox: (slug: string) =>
    requestJson<BotRecord>(`/api/sandboxes/${encodeURIComponent(slug)}/toggle`, {
      method: "POST",
    }),
  startSandbox: (slug: string) =>
    requestJson<BotRecord>(`/api/sandboxes/${encodeURIComponent(slug)}/start`, {
      method: "POST",
    }),
  stopSandbox: (slug: string) =>
    requestJson<BotRecord>(`/api/sandboxes/${encodeURIComponent(slug)}/stop`, {
      method: "POST",
    }),
  stopAllSandboxes: () =>
    requestJson<{ stopped_sandboxes: string[] }>("/api/sandboxes/stop-all", {
      method: "POST",
    }),
  sweepIdleSandboxes: () =>
    requestJson<{ hibernated_sandboxes: string[] }>("/api/sandboxes/sweep-idle", {
      method: "POST",
    }),
  startDesktopTakeover: (slug: string) =>
    requestJson<{ status: string; desktop: DesktopInfo }>(
      `/api/desktops/${encodeURIComponent(slug)}/takeover/start`,
      { method: "POST" },
    ),
  releaseDesktopTakeover: (slug: string) =>
    requestJson<{ status: string; desktop: DesktopInfo }>(
      `/api/desktops/${encodeURIComponent(slug)}/takeover/release`,
      { method: "POST" },
    ),
  desktopScreenshotUrl: (
    slug: string,
    opts?: {
      refresh?: boolean;
      download?: boolean;
      passive?: boolean;
      maxWidth?: number;
      cacheBust?: number;
    },
  ) => {
    const qs = new URLSearchParams();
    if (opts?.refresh) qs.set("refresh", "true");
    if (opts?.download) qs.set("download", "true");
    if (opts?.passive) qs.set("passive", "true");
    if (typeof opts?.maxWidth === "number") qs.set("max_width", String(opts.maxWidth));
    if (typeof opts?.cacheBust === "number") qs.set("t", String(opts.cacheBust));
    const suffix = qs.toString();
    return `/api/desktops/${encodeURIComponent(slug)}/screenshot${suffix ? `?${suffix}` : ""}`;
  },
  inspectDesktop: (slug: string) =>
    requestJson<Record<string, unknown>>(`/api/desktops/${encodeURIComponent(slug)}/inspect`),
  desktopAction: (slug: string, payload: Record<string, unknown>) =>
    requestJson<Record<string, unknown>>(`/api/desktops/${encodeURIComponent(slug)}/action`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  startDesktopRecording: (slug: string) =>
    requestJson<DesktopRecordingStatus>(
      `/api/desktops/${encodeURIComponent(slug)}/recording/start`,
      { method: "POST" },
    ),
  getDesktopRecordingStatus: (slug: string) =>
    requestJson<DesktopRecordingStatus>(
      `/api/desktops/${encodeURIComponent(slug)}/recording/status`,
    ),
  stopDesktopRecording: (
    slug: string,
    payload?: { skill_name?: string; save_skill?: boolean; notes?: string },
  ) =>
    requestJson<DesktopRecordingStopResponse>(
      `/api/desktops/${encodeURIComponent(slug)}/recording/stop`,
      {
        method: "POST",
        body: JSON.stringify(payload ?? { save_skill: true }),
      },
    ),
  saveDesktopRecording: (
    slug: string,
    payload: { skill_name?: string; notes?: string; recording: Record<string, unknown> },
  ) =>
    requestJson<DesktopRecordingStopResponse>(
      `/api/desktops/${encodeURIComponent(slug)}/recording/save`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),

  listVaultSecrets: () => requestJson<VaultSecretRecord[]>("/api/vault"),
  createVaultSecret: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    name: string;
    slug?: string;
    secret_type: "ssh" | "login" | "api_token" | "custom";
    host?: string;
    port?: string;
    url?: string;
    secrets: Record<string, string>;
    allowed_bots?: string[];
    trusted_command_prefixes?: string[];
  }) =>
    requestJson<VaultSecretRecord>("/api/vault", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateVaultSecret: (
    slug: string,
    payload: {
      visibility?: ResourceVisibility;
    allowed_groups?: string[];
      name?: string;
      secret_type?: "ssh" | "login" | "api_token" | "custom";
      host?: string;
      port?: string;
      url?: string;
      secrets?: Record<string, string>;
      allowed_bots?: string[];
      trusted_command_prefixes?: string[];
    },
  ) =>
    requestJson<VaultSecretRecord>(`/api/vault/${encodeURIComponent(slug)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  deleteVaultSecret: (slug: string) =>
    requestJson<{ status: string; slug: string }>(`/api/vault/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  bulkCreateSSHVaultSecrets: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    name_prefix: string;
    hosts_text: string;
    port?: string;
    secrets: Record<string, string>;
    allowed_bots?: string[];
  }) =>
    requestJson<{ created: VaultSecretRecord[]; count: number }>("/api/vault/bulk-ssh", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  resetVaultHostKey: (slug: string, hostPort?: string) =>
    requestJson<VaultSecretRecord>(`/api/vault/${encodeURIComponent(slug)}/reset-host-key`, {
      method: "POST",
      body: JSON.stringify({ host_port: hostPort ?? null }),
    }),
  getSSHAuditSettings: () => requestJson<SSHAuditSettings>("/api/settings/ssh-audit"),
  updateSSHAuditSettings: (retentionHours: number) =>
    requestJson<SSHAuditSettings>("/api/settings/ssh-audit", {
      method: "PATCH",
      body: JSON.stringify({ retention_hours: retentionHours }),
    }),
  getChatRetentionSettings: () =>
    requestJson<ChatRetentionSettings>("/api/settings/chat-retention"),
  updateChatRetentionSettings: (retentionDays: number, pruneNow = false) =>
    requestJson<ChatRetentionSettings>("/api/settings/chat-retention", {
      method: "PATCH",
      body: JSON.stringify({ retention_days: retentionDays, prune_now: pruneNow }),
    }),
  listSSHSessions: (params?: { bot_slug?: string; include_closed?: boolean }) => {
    const qs = new URLSearchParams();
    if (params?.bot_slug) qs.set("bot_slug", params.bot_slug);
    if (params?.include_closed !== undefined) {
      qs.set("include_closed", String(params.include_closed));
    }
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return requestJson<SSHSessionRecord[]>(`/api/ssh/sessions${suffix}`);
  },
  getSSHCast: async (sessionId: string): Promise<{ ndjson: string; sha256: string | null }> => {
    const response = await fetch(`/api/ssh/sessions/${encodeURIComponent(sessionId)}/cast?format=ndjson`);
    if (!response.ok) {
      throw new Error(`Unable to load terminal recording (${response.status})`);
    }
    return {
      ndjson: await response.text(),
      sha256: response.headers.get("X-Cast-Sha256"),
    };
  },
  takeoverSSHSession: (sessionId: string) =>
    requestJson<SSHSessionRecord>(`/api/ssh/sessions/${encodeURIComponent(sessionId)}/takeover`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  handbackSSHSession: (sessionId: string) =>
    requestJson<SSHSessionRecord>(`/api/ssh/sessions/${encodeURIComponent(sessionId)}/handback`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  controlSSHSession: (
    sessionId: string,
    operation: "pause" | "resume" | "terminate" | "pin" | "unpin",
    reason?: string,
  ) =>
    requestJson<SSHSessionRecord>(`/api/ssh/sessions/${encodeURIComponent(sessionId)}/control`, {
      method: "POST",
      body: JSON.stringify({ operation, reason: reason ?? "" }),
    }),

  listIntegrations: () => requestJson<IntegrationAccount[]>("/api/integrations"),
  upsertIntegration: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    slug: string;
    provider: "google" | "telegram" | "linkedin" | "webhook" | "mcp";
    display_name: string;
    account_identifier?: string;
    scopes?: string[];
    secrets?: Record<string, unknown>;
  }) =>
    requestJson<IntegrationAccount>("/api/integrations", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteIntegration: (slug: string) =>
    requestJson<{ status: string }>(`/api/integrations/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  onboardTelegram: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    bot_token: string;
    slug?: string;
    display_name?: string;
    operator_chat_id?: string;
    admin_channels?: string[];
    public_channels?: string[];
    register_webhook?: boolean;
  }) =>
    requestJson<IntegrationAccount>("/api/integrations/telegram/onboard", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  testIntegration: (slug: string, sendTestMessage = false) =>
    requestJson<IntegrationAccount>(`/api/integrations/${encodeURIComponent(slug)}/test`, {
      method: "POST",
      body: JSON.stringify({ send_test_message: sendTestMessage }),
    }),
  probeAllIntegrations: () =>
    requestJson<ProbeAllResponse>("/api/integrations/probe-all", {
      method: "POST",
    }),
  getGoogleWizardConfig: () =>
    requestJson<GoogleWizardConfig>("/api/integrations/google/wizard-config"),
  startGoogleOAuth: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    in_production_confirmed: boolean;
    client_id?: string;
    client_secret?: string;
    reuse_saved_client?: boolean;
    slug?: string;
    display_name?: string;
    login_hint?: string;
    scope_groups?: string[];
  }) =>
    requestJson<GoogleAuthorizeResponse>("/api/integrations/google/authorize", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  completeGoogleOAuth: (payload: { code: string; state: string }) =>
    requestJson<IntegrationAccount>("/api/integrations/google/callback", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  onboardLinkedIn: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    access_token: string;
    author_urn?: string;
    linkedin_version?: string;
    slug?: string;
    display_name?: string;
  }) =>
    requestJson<IntegrationAccount>("/api/integrations/linkedin/onboard", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  onboardWebhook: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    display_name: string;
    slug?: string;
    signing_secret?: string;
    event_type?: string;
    target_collection?: string | null;
  }) =>
    requestJson<WebhookOnboardResponse>("/api/integrations/webhook/onboard", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  addTelegramPublicMonitor: (payload: {
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    channel_handle: string;
    slug?: string;
    display_name?: string;
    sync_immediately?: boolean;
  }) =>
    requestJson<IntegrationAccount & { sync_summary?: TelegramSyncSummary | null }>(
      "/api/integrations/telegram/public-monitor",
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
  syncIntegration: (slug: string, limitPerChannel = 20) =>
    requestJson<TelegramSyncSummary>(`/api/integrations/${encodeURIComponent(slug)}/sync`, {
      method: "POST",
      body: JSON.stringify({ limit_per_channel: limitPerChannel }),
    }),

  listModels: (modelId?: string) =>
    requestJson<ModelsResponse>(
      modelId ? `/api/models?model_id=${encodeURIComponent(modelId)}` : "/api/models",
    ),
  discoverModels: (payload: {
    provider_type: "google" | "anthropic" | "openai" | "xai" | "openrouter" | "ollama";
    provider_slug?: string;
    api_key?: string;
    api_base?: string;
  }) =>
    requestJson<DiscoverModelsResponse>("/api/models/discover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  upsertModel: (payload: {
    slug: string;
    provider_type: "google" | "anthropic" | "openai" | "xai" | "openrouter" | "ollama";
    model_id: string;
    api_base?: string;
    api_key?: string;
    is_default?: boolean;
    daily_token_limit?: number;
    monthly_budget_usd?: number;
    input_price_per_million?: number;
    output_price_per_million?: number;
  }) =>
    requestJson<ModelProvider>("/api/models", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  setDefaultModel: (slug: string) =>
    requestJson<ModelProvider>(`/api/models/${encodeURIComponent(slug)}/default`, {
      method: "POST",
    }),
  testModel: (slug: string) =>
    requestJson<{
      status: string;
      model_id: string;
      latency_ms: number;
      output_text: string;
      input_tokens: number;
      output_tokens: number;
      estimated_cost_usd: number;
    }>(`/api/models/${encodeURIComponent(slug)}/test`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  deleteModel: (slug: string) =>
    requestJson<{ status: string }>(`/api/models/${encodeURIComponent(slug)}`, {
      method: "DELETE",
    }),
  evaluateWatchdog: () =>
    requestJson<{
      telemetry: HostTelemetry;
      actions: string[];
      stopped_desktops: string[];
    }>("/api/watchdog/evaluate", {
      method: "POST",
    }),
  getDebugOverview: (params?: {
    bot_slug?: string;
    level?: string;
    contains?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.bot_slug) qs.set("bot_slug", params.bot_slug);
    if (params?.level && params.level !== "ALL") qs.set("level", params.level);
    if (params?.contains) qs.set("contains", params.contains);
    if (params?.limit) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return requestJson<DebugOverviewResponse>(`/api/debug/overview${suffix}`);
  },
  clearDebugData: () =>
    requestJson<{ cleared_logs: number; cleared_traces: number }>("/api/debug/clear", {
      method: "POST",
    }),
};
