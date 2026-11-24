import { useEffect, useState, type FormEvent } from "react";
import {
  ChevronDown,
  ChevronRight,
  Cloud,
  Columns2,
  Cpu,
  Database,
  Download,
  FileText,
  Loader2,
  Monitor,
  Package,
  Paperclip,
  Pin,
  Play,
  Plus,
  Sparkles,
  Terminal,
  Trash2,
  Upload,
  Users,
  X,
} from "lucide-react";
import { api, maxWorkspaceFileBytesForName } from "../api";
import { integrationIconComponent, vaultSecretIconComponent } from "./MentionText";
import type {
  BotRecord,
  CollectionRecord,
  DesktopBootProgress,
  DesktopInfo,
  IntegrationAccount,
  ModelProvider,
  PageRecord,
  ResourceVisibility,
  RoomRecord,
  SkillRecord,
  SsoPrincipal,
  StyleRule,
  TeamGroupRecord,
  VaultSecretRecord,
  WorkspaceFileRecord,
} from "../types";
import { friendlyModelName } from "../utils/format";
import { BOT_ICON_OPTIONS, BotAvatar } from "./BotAvatar";
import { DesktopScreenPreview } from "./DesktopScreenPreview";
import { SSHTerminalPanel } from "./SSHTerminalPanel";
import { VisibilityPicker, formatVisibilityLabel, visibilityBadgeClasses } from "./VisibilityPicker";

export type InspectorTab = "details" | "library" | "computer";

interface InspectorProps {
  bot: BotRecord | null;
  room?: RoomRecord | null;
  bots?: BotRecord[];
  pages?: PageRecord[];
  collections?: CollectionRecord[];
  skills?: SkillRecord[];
  workspaceFiles?: WorkspaceFileRecord[];
  activePageSlug?: string | null;
  initialTab?: InspectorTab;
  theme?: "light" | "dark";
  models: ModelProvider[];
  integrations: IntegrationAccount[];
  vaultSecrets?: VaultSecretRecord[];
  styleRules: StyleRule[];
  onHide: () => void;
  onInspectDebug: (botSlug: string) => void;
  onUpdateBot: (
    slug: string,
    updates: {
      name?: string;
      enabled?: boolean;
      runtime?: "api" | "sandbox" | "desktop";
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
      visibility?: ResourceVisibility;
      allowed_groups?: string[];
    },
  ) => Promise<void> | void;
  teams?: TeamGroupRecord[];
  onUpdateRoom?: (slug: string, updates: Partial<RoomRecord>) => Promise<void>;
  onDeleteRoom?: (slug: string) => Promise<void>;
  onUploadFile?: (file: File) => Promise<WorkspaceFileRecord>;
  onDeleteFile?: (fileId: string) => Promise<void>;
  onDeleteSkill?: (skillId: string) => Promise<void>;
  onExportTeamPack?: (opts?: {
    room_slug?: string;
    bot_slugs?: string[];
    section?: string;
    title?: string;
  }) => Promise<void>;
  onDockPage?: (pageSlug: string) => void;
  onAddStyleRule: (ruleText: string, scopeSlug: string) => Promise<void>;
  onDeleteStyleRule: (ruleId: string) => Promise<void>;
  onTriggerBot: (slug: string, routineId?: string) => Promise<void>;
  togglingDesktop?: boolean;
  togglingSandbox?: boolean;
  desktopInfo?: DesktopInfo | null;
  desktopBootProgress?: DesktopBootProgress | null;
  sshRefreshTick?: number;
  onExpandTerminal?: (botSlug: string) => void;
  onToggleDesktop: (slug: string) => void;
  onToggleSandbox?: (slug: string) => void;
  onOpenSelkies: (bot: BotRecord) => void;
  onExportBlueprint?: (slug: string) => Promise<void>;
  onDeleteBot?: (slug: string) => Promise<void>;
  messageCount?: number;
  onClearBotMessages?: (slug: string, opts?: { keep_last?: number }) => Promise<void>;
  onExportBotMessages?: (slug: string) => Promise<void>;
  onClearRoomMessages?: (slug: string, opts?: { keep_last?: number }) => Promise<void>;
  onExportRoomMessages?: (slug: string) => Promise<void>;
  onOpenIntegrations?: () => void;
  onOpenVault?: () => void;
  onToggleVaultSecret?: (secret: VaultSecretRecord, botSlug: string) => Promise<void> | void;
  onCreateCompanionWriter?: (sourceBot: BotRecord) => Promise<void>;
  onOpenPage?: (pageSlug: string) => void;
  onOpenNewPage?: () => void;
  onTogglePagePin?: (pageSlug: string, nextPinned: boolean) => void;
  principal?: SsoPrincipal | null;
}

const RBAC_MODES: Array<{
  key: "internal" | "draft" | "execute";
  shortTitle: string;
  desc: string;
}> = [
  {
    key: "internal",
    shortTitle: "Read Only",
    desc: "Saves notes internally; never sends external messages.",
  },
  {
    key: "draft",
    shortTitle: "Ask First",
    desc: "Queues outgoing drafts in Approvals for human review before anything sends.",
  },
  {
    key: "execute",
    shortTitle: "Auto-Send",
    desc: "Sends directly within your daily limit; queues uncertain items in Approvals.",
  },
];

const SCHEDULE_OPTIONS = ["Every 15m", "Every 1h", "Every 24h", "Manual"];

function isOneShotRoutineSchedule(
  schedule: string | undefined,
  type?: string,
  oneShotFlag?: boolean,
): boolean {
  if (oneShotFlag || String(type || "").toLowerCase() === "once") {
    return true;
  }
  const s = String(schedule || "").trim();
  return /^(?:once\b|one[\s-]*shot\b|one[\s-]*time\b|\d{4}-\d{2}-\d{2}|at\s+\d{4}-\d{2}-\d{2}|in\s+\d+\s*(?:s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours))/i.test(
    s,
  );
}

const AVATAR_COLORS = [
  { key: "slate", bg: "bg-slate-700" },
  { key: "blue", bg: "bg-[#2b5278]" },
  { key: "emerald", bg: "bg-[#2f6b52]" },
  { key: "indigo", bg: "bg-[#43536b]" },
  { key: "amber", bg: "bg-[#84592b]" },
  { key: "rose", bg: "bg-[#7d3c45]" },
];

const HIDDEN_INTERNAL_COLLECTIONS = new Set([
  "oauth_pending_states",
  "http_feed_cache",
  "debug_run_traces",
  "bot_threads",
  "desktop_snapshots",
  "bot_skills",
  "ingestion_seen_keys",
  "vault_secrets",
  "bot_rooms",
  "room_threads",
  "workspace_files",
  "thread_read_cursors",
  "delegation_plans",
  "ssh_settings",
  "chat_settings",
]);

const BOUNDARY_PREFIX_RE = /^(?:never|do\s+not|don't|skip|discard|ignore)\b/i;

function ToggleSwitch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        onChange();
      }}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors cursor-pointer ${
        checked
          ? "border-[#3b72b2] bg-[#3b72b2]"
          : "border-slate-300 bg-slate-200"
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-xs transition-transform ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

export function Inspector({
  bot,
  room = null,
  bots = [],
  pages = [],
  collections = [],
  skills = [],
  workspaceFiles = [],
  activePageSlug = null,
  initialTab = "details",
  theme = "light",
  models,
  integrations,
  vaultSecrets = [],
  styleRules,
  onHide,
  onInspectDebug,
  onUpdateBot,
  onUpdateRoom,
  onDeleteRoom,
  onUploadFile,
  onDeleteFile,
  onDeleteSkill,
  onExportTeamPack,
  onDockPage,
  onAddStyleRule,
  onDeleteStyleRule,
  onTriggerBot,
  togglingDesktop = false,
  togglingSandbox = false,
  desktopInfo = null,
  desktopBootProgress = null,
  sshRefreshTick = 0,
  onExpandTerminal,
  onToggleDesktop,
  onToggleSandbox,
  onOpenSelkies,
  onExportBlueprint,
  onDeleteBot,
  messageCount,
  onClearBotMessages,
  onExportBotMessages,
  onClearRoomMessages,
  onExportRoomMessages,
  onOpenIntegrations,
  onOpenVault,
  onToggleVaultSecret,
  onCreateCompanionWriter,
  onOpenPage,
  onOpenNewPage,
  onTogglePagePin,
  teams = [],
  principal = null,
}: InspectorProps) {
  const isMultiUser = Boolean(principal?.multi_user);
  const isAdmin = Boolean(principal?.is_admin);
  const callerEmail = (principal?.email || "").toLowerCase();
  const canManageResource = (owner?: string) =>
    !isMultiUser || isAdmin || !owner || owner.toLowerCase() === callerEmail;
  const canManageRoom = canManageResource(room?.owner_email);
  const canManageBot = canManageResource(bot?.owner_email);
  const [roomVisDraft, setRoomVisDraft] = useState<{
    visibility: ResourceVisibility;
    allowed_groups: string[];
  } | null>(null);
  const [botVisDraft, setBotVisDraft] = useState<{
    visibility: ResourceVisibility;
    allowed_groups: string[];
  } | null>(null);
  useEffect(() => {
    setRoomVisDraft(null);
  }, [room?.slug]);
  useEffect(() => {
    setBotVisDraft(null);
  }, [bot?.slug]);
  const browserTz = (() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
    } catch {
      return "UTC";
    }
  })();
  const [activeTab, setActiveTab] = useState<InspectorTab>(initialTab);
  const [triggeringId, setTriggeringId] = useState<string | null>(null);
  const [nameInput, setNameInput] = useState(bot?.name ?? "");
  const [promptInput, setPromptInput] = useState(bot?.role_prompt || bot?.role || "");
  const [sectionInput, setSectionInput] = useState(bot?.section ?? "");
  const [newRuleInput, setNewRuleInput] = useState("");
  const [savingRule, setSavingRule] = useState(false);
  const [savingIdentity, setSavingIdentity] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [addingRoutine, setAddingRoutine] = useState(false);
  const [newRoutineLabel, setNewRoutineLabel] = useState("");
  const [newRoutineSchedule, setNewRoutineSchedule] = useState("Every weekday at 09:00");
  const [newRoutineTimezone, setNewRoutineTimezone] = useState(browserTz);
  const [newRoutinePrompt, setNewRoutinePrompt] = useState("");
  const [newRoutineStale, setNewRoutineStale] = useState<"skip_quietly" | "notify_missing" | "always_run">("skip_quietly");
  const [editingRoutineId, setEditingRoutineId] = useState<string | null>(null);
  const [editRoutineDraft, setEditRoutineDraft] = useState<{
    label: string;
    schedule: string;
    timezone: string;
    prompt: string;
    stale_data_policy: "skip_quietly" | "notify_missing" | "always_run";
  } | null>(null);
  const [addingApp, setAddingApp] = useState(false);
  const [addingSecret, setAddingSecret] = useState(false);
  const [addingSourceBot, setAddingSourceBot] = useState(false);
  const [expandedSkillId, setExpandedSkillId] = useState<string | null>(null);
  const [fileUploadError, setFileUploadError] = useState<string | null>(null);
  const [uploadingFile, setUploadingFile] = useState(false);
  const [confirmDeleteBot, setConfirmDeleteBot] = useState(false);
  const [deletingBot, setDeletingBot] = useState(false);
  const [confirmClearChat, setConfirmClearChat] = useState(false);
  const [clearingChat, setClearingChat] = useState(false);
  const [exportingChat, setExportingChat] = useState(false);
  const [clearChatError, setClearChatError] = useState<string | null>(null);
  const [roomTitleInput, setRoomTitleInput] = useState(room?.title ?? "");

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  useEffect(() => {
    setNameInput(bot?.name ?? "");
    setPromptInput(bot?.role_prompt || bot?.role || "");
    setSectionInput(bot?.section ?? "");
    setMoreOpen(false);
    setAddingRoutine(false);
    setEditingRoutineId(null);
    setEditRoutineDraft(null);
    setAddingApp(false);
    setAddingSecret(false);
    setAddingSourceBot(false);
    setConfirmDeleteBot(false);
    setDeletingBot(false);
    setConfirmClearChat(false);
    setClearingChat(false);
    setExportingChat(false);
    setClearChatError(null);
  }, [bot?.slug, bot?.name, bot?.role_prompt, bot?.role, bot?.section]);

  useEffect(() => {
    setRoomTitleInput(room?.title ?? "");
    setConfirmClearChat(false);
    setClearingChat(false);
    setExportingChat(false);
    setClearChatError(null);
  }, [room?.slug, room?.title]);

  function renderClearChatConfirmation(opts: {
    slug: string;
    onClear?: (slug: string, clearOpts?: { keep_last?: number }) => Promise<void>;
    onExport?: (slug: string) => Promise<void>;
  }) {
    const canKeepLast10 = typeof messageCount !== "number" || messageCount > 10;
    const isEmpty = typeof messageCount === "number" && messageCount === 0;
    const runClear = async (clearOpts?: { keep_last?: number }) => {
      if (!opts.onClear) return;
      setClearingChat(true);
      setClearChatError(null);
      try {
        await opts.onClear(opts.slug, clearOpts);
        setConfirmClearChat(false);
      } catch (err) {
        setClearChatError(err instanceof Error ? err.message : "Failed to clear chat history.");
      } finally {
        setClearingChat(false);
      }
    };
    const runExport = async () => {
      if (!opts.onExport) return;
      setExportingChat(true);
      setClearChatError(null);
      try {
        await opts.onExport(opts.slug);
      } catch (err) {
        setClearChatError(err instanceof Error ? err.message : "Failed to export transcript.");
      } finally {
        setExportingChat(false);
      }
    };

    return (
      <div className="w-full rounded-xl border border-slate-200 bg-white p-3 space-y-2.5">
        <div className="space-y-1">
          <div className="text-xs font-semibold text-slate-900">Clear chat history?</div>
          <p className="text-[11px] leading-relaxed text-slate-500">
            Removes messages from this thread only. Keeps Skills, Rules, Routines, Data Lists, Pages, Files, Approvals &amp; SSH recordings.
          </p>
        </div>
        {clearChatError && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] text-rose-700">
            {clearChatError}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-1.5">
          {opts.onExport && (
            <button
              type="button"
              disabled={clearingChat || exportingChat || isEmpty}
              onClick={() => void runExport()}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-[11px] font-medium text-slate-700 disabled:opacity-50 cursor-pointer"
            >
              {exportingChat ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Download className="w-3 h-3" />
              )}
              <span>Export .md</span>
            </button>
          )}
          <button
            type="button"
            disabled={clearingChat || exportingChat || !canKeepLast10}
            onClick={() => void runClear({ keep_last: 10 })}
            title={canKeepLast10 ? "Delete older messages and keep the newest 10" : "10 or fewer messages in thread"}
            className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-800 disabled:opacity-50 cursor-pointer"
          >
            Keep Last 10
          </button>
          <button
            type="button"
            disabled={clearingChat || exportingChat || isEmpty}
            onClick={() => void runClear()}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-[11px] font-medium disabled:opacity-50 cursor-pointer"
          >
            {clearingChat && <Loader2 className="w-3 h-3 animate-spin" />}
            <span>{clearingChat ? "Clearing..." : "Clear All"}</span>
          </button>
          <button
            type="button"
            disabled={clearingChat || exportingChat}
            onClick={() => {
              setConfirmClearChat(false);
              setClearChatError(null);
            }}
            className="px-2 py-1 rounded-lg text-[11px] text-slate-500 hover:text-slate-900 disabled:opacity-50 cursor-pointer ml-auto"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  function renderWorkspaceFilesSection() {
    return (
      <div className="space-y-2 pt-2 border-t border-slate-200">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            My Workspace Files ({workspaceFiles.length})
          </span>
          <label className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer">
            <Upload className="w-2.5 h-2.5" />
            <span>{uploadingFile ? "Uploading..." : "Upload (<=100 MB docs)"}</span>
            <input
              type="file"
              className="hidden"
              disabled={uploadingFile}
              onChange={async (e) => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (!file) return;
                setFileUploadError(null);
                const limitBytes = maxWorkspaceFileBytesForName(file.name, file.type);
                if (file.size > limitBytes) {
                  const limitMb = Math.round(limitBytes / (1024 * 1024));
                  setFileUploadError(`File exceeds the ${limitMb} MB per-file upload limit.`);
                  return;
                }
                setUploadingFile(true);
                try {
                  if (onUploadFile) await onUploadFile(file);
                  else await api.uploadWorkspaceFile(file);
                } catch (err) {
                  setFileUploadError(err instanceof Error ? err.message : "Upload failed.");
                } finally {
                  setUploadingFile(false);
                }
              }}
            />
          </label>
        </div>
        {fileUploadError && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1 text-[11px] text-rose-700">
            {fileUploadError}
          </div>
        )}
        {workspaceFiles.length === 0 ? (
          <div className="text-[11px] text-slate-400">
            Files attached here stay in your private workspace directory for bots to read.
          </div>
        ) : (
          <div className="space-y-1">
            {workspaceFiles.map((wf) => (
              <div
                key={wf.id}
                className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-xl border border-slate-200 bg-slate-50 text-[11px]"
              >
                <a
                  href={api.workspaceFileContentUrl(wf.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 min-w-0 text-slate-800 hover:underline"
                >
                  <Paperclip className="w-3 h-3 text-slate-500 shrink-0" />
                  <span className="truncate font-medium">{wf.filename}</span>
                </a>
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="text-[11px] text-slate-400">
                    {Math.max(1, Math.round(wf.size_bytes / 1024))} KB
                  </span>
                  <a
                    href={api.workspaceFileContentUrl(wf.id, { download: true })}
                    download={wf.filename}
                    title={`Download ${wf.filename}`}
                    aria-label={`Download ${wf.filename}`}
                    className="p-0.5 text-slate-500 hover:text-slate-900"
                  >
                    <Download className="w-3 h-3" />
                  </a>
                  {onDeleteFile && (
                    <button
                      type="button"
                      title="Delete file"
                      onClick={() => void onDeleteFile(wf.id)}
                      className="p-0.5 text-slate-400 hover:text-rose-600 cursor-pointer"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (room) {
    return (
      <aside className="w-full md:w-[332px] shrink-0 h-full md:border-l border-slate-200 bg-white flex flex-col">
        <div className="h-14 shrink-0 px-4 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
            <Users className="w-4 h-4 text-slate-600" />
            <span>Room Details</span>
          </div>
          <button
            type="button"
            onClick={onHide}
            className="p-1.5 rounded-full border border-slate-200 text-slate-500 hover:text-slate-900 cursor-pointer"
            aria-label="Close Inspector"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto custom-scroll p-4 space-y-5">
          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Room Title
            </label>
            <input
              type="text"
              value={roomTitleInput}
              onChange={(e) => setRoomTitleInput(e.target.value)}
              onBlur={() => {
                if (roomTitleInput.trim() && roomTitleInput.trim() !== room.title) {
                  void onUpdateRoom?.(room.slug, { title: roomTitleInput.trim() });
                }
              }}
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900"
            />
          </div>

          <div className="space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Member Bots ({room.member_bot_slugs.length} of 2–6)
            </div>
            <div className="flex flex-wrap gap-1.5">
              {bots.map((b) => {
                const isMember = room.member_bot_slugs.includes(b.slug);
                return (
                  <button
                    key={b.slug}
                    type="button"
                    onClick={() => {
                      if (!onUpdateRoom) return;
                      if (isMember && room.member_bot_slugs.length <= 2) return;
                      if (!isMember && room.member_bot_slugs.length >= 6) return;
                      const next = isMember
                        ? room.member_bot_slugs.filter((s) => s !== b.slug)
                        : [...room.member_bot_slugs, b.slug];
                      void onUpdateRoom(room.slug, { member_bot_slugs: next });
                    }}
                    className={`inline-flex items-center gap-1.5 pl-1 pr-2.5 py-0.5 rounded-full border text-[11px] cursor-pointer ${
                      isMember
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                    }`}
                  >
                    <BotAvatar
                      icon={b.avatar_icon}
                      color={b.avatar_color}
                      initials={b.initials}
                      size="xs"
                    />
                    <span>{b.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Speaker Routing
            </label>
            <select
              value={room.routing_mode ?? "auto"}
              onChange={(e) =>
                void onUpdateRoom?.(room.slug, {
                  routing_mode: e.target.value as "auto" | "lead" | "stage",
                })
              }
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900"
            >
              <option value="auto">Auto-Pick Best Bot</option>
              <option value="lead">Lead / Coordinator First</option>
              <option value="stage">Fixed Stage Order</option>
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Lead Coordinator
            </label>
            <select
              value={room.coordinator_bot_slug ?? room.member_bot_slugs[0] ?? ""}
              onChange={(e) =>
                void onUpdateRoom?.(room.slug, { coordinator_bot_slug: e.target.value })
              }
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900"
            >
              {room.member_bot_slugs.map((mSlug) => {
                const mb = bots.find((b) => b.slug === mSlug);
                return (
                  <option key={mSlug} value={mSlug}>
                    {mb ? mb.name : mSlug}
                  </option>
                );
              })}
            </select>
          </div>

          <div className="flex items-center justify-between gap-2 rounded-xl border border-slate-200 bg-slate-50 p-3">
            <div>
              <div className="text-xs font-medium text-slate-900">Ask before bot handoff</div>
              <div className="text-[10.5px] text-slate-500">
                Require 1 click before `@mention` triggers the next teammate
              </div>
            </div>
            <ToggleSwitch
              checked={room.ask_before_bot_handoff}
              onChange={() =>
                void onUpdateRoom?.(room.slug, {
                  ask_before_bot_handoff: !room.ask_before_bot_handoff,
                })
              }
              label="Toggle ask before handoff"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Docked Living Page
            </label>
            <select
              value={room.pinned_page_slug ?? ""}
              onChange={(e) =>
                void onUpdateRoom?.(room.slug, { pinned_page_slug: e.target.value || null })
              }
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900"
            >
              <option value="">None</option>
              {pages.map((p) => (
                <option key={p.slug} value={p.slug}>
                  {p.title}
                </option>
              ))}
            </select>
            {room.pinned_page_slug && onDockPage && (
              <button
                type="button"
                onClick={() => onDockPage(room.pinned_page_slug!)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-800 cursor-pointer"
              >
                <Columns2 className="w-3.5 h-3.5" />
                <span>Open Board Beside Chat</span>
              </button>
            )}
          </div>

          {renderWorkspaceFilesSection()}

          {isMultiUser && (
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2">
              <div className="flex items-center justify-between gap-2 text-[11px]">
                <span className="font-semibold uppercase tracking-wider text-slate-500">
                  Access &amp; Owner
                </span>
                <span className="text-slate-600 truncate">
                  {room.owner_email || "workspace"}
                </span>
              </div>
              {canManageRoom ? (
                <VisibilityPicker
                  value={roomVisDraft?.visibility ?? room.visibility ?? "shared"}
                  allowedGroups={roomVisDraft?.allowed_groups ?? room.allowed_groups ?? []}
                  teams={teams}
                  label=""
                  compact
                  onChange={(vis, groups) => {
                    if (vis === "team" && groups.length === 0) {
                      setRoomVisDraft({ visibility: vis, allowed_groups: groups });
                      return;
                    }
                    setRoomVisDraft(null);
                    void onUpdateRoom?.(room.slug, {
                      visibility: vis,
                      allowed_groups: vis === "team" ? groups : [],
                    });
                  }}
                />
              ) : (
                <span
                  className={`inline-flex px-2 py-0.5 rounded-full border text-[11px] font-medium ${visibilityBadgeClasses(
                    room.visibility,
                  )}`}
                >
                  {formatVisibilityLabel(room.visibility, room.allowed_groups)}
                </span>
              )}
            </div>
          )}

          <div className="pt-2 border-t border-slate-200 space-y-2">
            {confirmClearChat && canManageRoom && onClearRoomMessages && renderClearChatConfirmation({
              slug: room.slug,
              onClear: onClearRoomMessages,
              onExport: onExportRoomMessages,
            })}
            <div className="flex flex-wrap gap-2">
              {onExportTeamPack && (
                <button
                  type="button"
                  onClick={() =>
                    void onExportTeamPack({ room_slug: room.slug, title: room.title })
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-800 cursor-pointer"
                >
                  <Package className="w-3.5 h-3.5" />
                  <span>Export Team Pack</span>
                </button>
              )}
              {onClearRoomMessages && canManageRoom && !confirmClearChat && (
                <button
                  type="button"
                  disabled={typeof messageCount === "number" && messageCount === 0}
                  onClick={() => {
                    setClearChatError(null);
                    setConfirmClearChat(true);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-700 disabled:opacity-50 cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Clear Chat</span>
                </button>
              )}
              {onDeleteRoom && canManageRoom && (
                <button
                  type="button"
                  onClick={() => void onDeleteRoom(room.slug)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-200 text-rose-700 hover:bg-rose-50 text-xs font-medium cursor-pointer ml-auto"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete Room</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </aside>
    );
  }

  if (!bot) {
    return (
      <aside className="w-full md:w-[332px] shrink-0 h-full md:border-l border-slate-200 bg-white flex flex-col">
        <div className="h-14 shrink-0 px-4 border-b border-slate-200 flex items-center justify-between">
          <div className="text-xs font-semibold text-slate-900">Workspace Inspector</div>
          <button
            type="button"
            onClick={onHide}
            className="p-1.5 rounded-full border border-slate-200 text-slate-500 hover:text-slate-900 cursor-pointer"
            aria-label="Close Inspector"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="p-4 text-xs text-slate-500">
          Select a bot or page to inspect its instructions, library assets, or computer runtime.
        </div>
      </aside>
    );
  }

  const botLinkedAccounts = bot.linked_accounts ?? [];
  const boundaries = bot.boundaries ?? [];
  const scopedRules = styleRules.filter((r) => r.scope_slug === bot.slug);
  const globalRulesCount = styleRules.filter((r) => r.scope_slug === "*").length;

  const currentPrompt = bot.role_prompt || bot.role || "";
  const identityDirty =
    nameInput.trim() !== bot.name || promptInput.trim() !== currentPrompt.trim();

  async function saveIdentity(e?: FormEvent) {
    if (e) e.preventDefault();
    if (!bot || !identityDirty || savingIdentity || !nameInput.trim()) return;
    setSavingIdentity(true);
    try {
      await onUpdateBot(bot.slug, {
        name: nameInput.trim(),
        role_prompt: promptInput.trim(),
      });
    } finally {
      setSavingIdentity(false);
    }
  }

  async function addUnifiedRule(e: FormEvent) {
    e.preventDefault();
    const cleaned = newRuleInput.trim();
    if (!bot || !cleaned || savingRule) return;
    setSavingRule(true);
    try {
      if (BOUNDARY_PREFIX_RE.test(cleaned)) {
        await onUpdateBot(bot.slug, { boundaries: [...boundaries, cleaned] });
      } else {
        await onAddStyleRule(cleaned, bot.slug);
      }
      setNewRuleInput("");
    } finally {
      setSavingRule(false);
    }
  }

  function toggleLinkedAccount(accSlug: string) {
    if (!bot) return;
    const exists = botLinkedAccounts.includes(accSlug);
    const next = exists
      ? botLinkedAccounts.filter((item) => item !== accSlug)
      : [...botLinkedAccounts, accSlug];
    void onUpdateBot(bot.slug, { linked_accounts: next });
  }

  async function updateRoutineSchedule(routineId: string, schedule: string) {
    if (!bot) return;
    const updated: Array<Record<string, unknown>> = bot.routines.map((r) => {
      if (r.id !== routineId) {
        return r as unknown as Record<string, unknown>;
      }
      const trimmed = schedule.trim();
      const oneShot = isOneShotRoutineSchedule(trimmed);
      const next: Record<string, unknown> = {
        ...(r as unknown as Record<string, unknown>),
        schedule: trimmed || "Manual",
        type:
          trimmed.toLowerCase() === "manual"
            ? "manual_trigger"
            : oneShot
              ? "once"
              : "cron",
        one_shot: oneShot,
        enabled: true,
      };
      delete next.completed_at;
      return next;
    });
    await onUpdateBot(bot.slug, { routines: updated });
  }

  const activeRbacMeta = RBAC_MODES.find((m) => m.key === bot.outbound_rbac) ?? RBAC_MODES[1];
  const primaryRoutine = bot.routines[0];
  const scheduleSummary = primaryRoutine?.schedule || "Manual";
  const modelChoices = Array.from(
    new Set([
      "google:gemini-3.8-flash",
      "google:gemini-4-argon",
      ...models.map((m) => m.model_id),
      bot.model,
    ]),
  );

  const botCollectionsSet = new Set([
    ...(bot.collections?.read ?? []),
    ...(bot.collections?.write ?? []),
  ]);
  const ownedPages = pages.filter(
    (p) =>
      p.owner_bot_slug === bot.slug ||
      p.allowed_collections.some((col) => botCollectionsSet.has(col)),
  );
  const pinnedPages = ownedPages.filter((p) => p.pinned);
  const recentPages = ownedPages.filter((p) => !p.pinned);
  const visibleCollections = collections.filter(
    (c) => !c.is_internal && !HIDDEN_INTERNAL_COLLECTIONS.has(c.slug),
  );
  const botCollections = visibleCollections.filter(
    (c) => c.owner_bot_slug === bot.slug || botCollectionsSet.has(c.slug),
  );
  const displayCollections = botCollections;

  const botSkills = skills.filter((s) => s.scope_slug === bot.slug || s.scope_slug === "*");

  return (
    <aside className="w-full md:w-[332px] shrink-0 h-full md:border-l border-slate-200 bg-white flex flex-col">
      {/* Top Status & Close Strip */}
      <div className="shrink-0 px-4 pt-3 pb-2 flex items-center justify-between gap-2">
        <button
          type="button"
          role="switch"
          aria-checked={bot.enabled}
          aria-label={bot.enabled ? "Pause bot" : "Activate bot"}
          title={
            bot.enabled
              ? "Bot is Active — click to pause (paused bots are skipped in Rooms and schedules)"
              : "Bot is Paused — click to activate"
          }
          onClick={() => void onUpdateBot(bot.slug, { enabled: !bot.enabled })}
          className={`inline-flex items-center gap-2 pl-2.5 pr-1.5 py-1 rounded-full border text-[11px] font-medium transition-colors cursor-pointer ${
            bot.enabled
              ? "border-emerald-200 bg-emerald-50/70 text-emerald-800 hover:bg-emerald-100/80"
              : "border-slate-200 bg-slate-100 text-slate-600 hover:bg-slate-200/80"
          }`}
        >
          <span>{bot.enabled ? "Active" : "Paused"}</span>
          <span
            className={`w-6 h-3.5 rounded-full p-0.5 flex items-center transition-colors ${
              bot.enabled ? "bg-[#3b8c62] justify-end" : "bg-slate-300 justify-start"
            }`}
          >
            <span className="w-2.5 h-2.5 rounded-full bg-white shadow-xs" />
          </span>
        </button>
        <button
          type="button"
          onClick={onHide}
          className="p-1.5 rounded-full border border-slate-200 text-slate-500 hover:text-slate-900 hover:bg-slate-50 cursor-pointer"
          title="Close Panel"
          aria-label="Close Panel"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Centered Grok-Style Bot Identity */}
      <div className="shrink-0 px-5 pb-3 text-center border-b border-slate-200 space-y-2">
        <div className="flex justify-center">
          <BotAvatar
            icon={bot.avatar_icon}
            color={bot.avatar_color}
            initials={bot.initials}
            size="lg"
            statusDot={
              !bot.enabled
                ? "paused"
                : (bot.runtime === "desktop" && bot.desktop_state === "running") ||
                    (bot.runtime === "sandbox" && bot.sandbox_state === "running")
                  ? "desktop"
                  : "active"
            }
          />
        </div>
        <div>
          <input
            type="text"
            value={nameInput}
            onChange={(e) => setNameInput(e.target.value)}
            onBlur={() => void saveIdentity()}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                void saveIdentity();
              }
            }}
            aria-label="Bot Name"
            className="w-full text-center text-sm font-semibold text-slate-900 bg-transparent border border-transparent hover:border-slate-200 focus:border-slate-300 rounded-lg px-2 py-0.5 focus:outline-none"
          />
          <div className="text-[11px] text-slate-500 mt-0.5 truncate">
            {scheduleSummary} · {friendlyModelName(bot.model)}
          </div>
        </div>

        {/* 3-Tab Segmented Switch: Details | Library | Computer */}
        <div className="grid grid-cols-3 gap-1 p-1 rounded-xl border border-slate-200 bg-slate-50">
          {(
            [
              { key: "details", label: "Details" },
              { key: "library", label: "Library", badge: ownedPages.length || undefined },
              {
                key: "computer",
                label: "Computer",
                dot: bot.runtime === "desktop" || bot.runtime === "sandbox",
              },
            ] as const
          ).map((item) => {
            const active = activeTab === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setActiveTab(item.key)}
                className={`py-1.5 px-2 rounded-lg text-[11px] font-medium inline-flex items-center justify-center gap-1.5 cursor-pointer transition-colors ${
                  active
                    ? "bg-slate-900 text-white shadow-xs"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                <span>{item.label}</span>
                {"badge" in item && item.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.2 rounded-full text-[9.5px] font-semibold ${
                      active ? "bg-slate-700 text-white" : "bg-slate-200 text-slate-700"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
                {"dot" in item && item.dot && (
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      (bot.runtime === "desktop" && bot.desktop_state === "running") ||
                      (bot.runtime === "sandbox" && bot.sandbox_state === "running")
                        ? "bg-[#3b8c62]"
                        : "bg-slate-400"
                    }`}
                  />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Scrollable Tab Body */}
      <div className="flex-1 overflow-y-auto custom-scroll p-4 space-y-5">
        {activeTab === "details" && (
          <>
            {isMultiUser && (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2">
                <div className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="font-semibold uppercase tracking-wider text-slate-500">
                    Access &amp; Owner
                  </span>
                  <span className="text-slate-600 truncate">
                    {bot.owner_email || "workspace"}
                  </span>
                </div>
                {canManageBot ? (
                  <VisibilityPicker
                    value={botVisDraft?.visibility ?? bot.visibility ?? "shared"}
                    allowedGroups={botVisDraft?.allowed_groups ?? bot.allowed_groups ?? []}
                    teams={teams}
                    label=""
                    compact
                    onChange={(vis, groups) => {
                      if (vis === "team" && groups.length === 0) {
                        setBotVisDraft({ visibility: vis, allowed_groups: groups });
                        return;
                      }
                      setBotVisDraft(null);
                      void onUpdateBot(bot.slug, {
                        visibility: vis,
                        allowed_groups: vis === "team" ? groups : [],
                      });
                    }}
                  />
                ) : (
                  <span
                    className={`inline-flex px-2 py-0.5 rounded-full border text-[11px] font-medium ${visibilityBadgeClasses(
                      bot.visibility,
                    )}`}
                  >
                    {formatVisibilityLabel(bot.visibility, bot.allowed_groups)}
                  </span>
                )}
              </div>
            )}

            {/* 1. Instructions */}
            <form onSubmit={saveIdentity} className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Instructions
                </label>
                {identityDirty && (
                  <button
                    type="submit"
                    disabled={savingIdentity || !nameInput.trim()}
                    className="px-2.5 py-1 rounded-full bg-slate-900 text-white text-[11px] font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {savingIdentity ? "Saving..." : "Save Changes"}
                  </button>
                )}
              </div>
              <textarea
                rows={4}
                value={promptInput}
                onChange={(e) => setPromptInput(e.target.value)}
                placeholder="Describe what this bot should check, organize, or draft..."
                className="w-full rounded-xl border border-slate-200 bg-slate-50 p-2.5 text-xs text-slate-900 leading-relaxed"
              />
            </form>

            {/* 2. Connected Apps (Linked to this bot only +Add picker) */}
            {(() => {
              const linkedIntegrationItems = integrations.filter((acc) =>
                botLinkedAccounts.includes(acc.slug),
              );
              const unlinkedIntegrationItems = integrations.filter(
                (acc) => !botLinkedAccounts.includes(acc.slug),
              );
              return (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                      Connected Apps
                    </div>
                    <div className="flex items-center gap-2">
                      {unlinkedIntegrationItems.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setAddingApp((v) => !v)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[10.5px] font-medium text-slate-700 cursor-pointer"
                        >
                          <Plus className="w-3 h-3" />
                          <span>{addingApp ? "Done" : "Add"}</span>
                        </button>
                      )}
                      {onOpenIntegrations && (
                        <button
                          type="button"
                          onClick={onOpenIntegrations}
                          className="text-[11px] text-slate-500 hover:text-slate-900 hover:underline cursor-pointer"
                        >
                          {integrations.length === 0 ? "Connect" : "Manage"}
                        </button>
                      )}
                    </div>
                  </div>

                  {addingApp && unlinkedIntegrationItems.length > 0 && (
                    <div className="rounded-xl border border-slate-200 bg-white p-1.5 space-y-0.5">
                      {unlinkedIntegrationItems.map((acc) => {
                        const ProviderIcon = integrationIconComponent(acc.provider);
                        return (
                          <button
                            key={acc.slug}
                            type="button"
                            onClick={() => {
                              toggleLinkedAccount(acc.slug);
                              setAddingApp(false);
                            }}
                            className="w-full text-left px-2 py-1.5 rounded-lg hover:bg-slate-100 flex items-center gap-2 text-xs text-slate-800 cursor-pointer"
                          >
                            <ProviderIcon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                            <span className="truncate font-medium">{acc.display_name}</span>
                            {acc.account_identifier && (
                              <span className="text-[10.5px] text-slate-400 truncate ml-auto">
                                {acc.account_identifier}
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {linkedIntegrationItems.length === 0 ? (
                    <div className="text-[11px] text-slate-400">No external accounts linked.</div>
                  ) : (
                    <div className="space-y-1.5">
                      {linkedIntegrationItems.map((acc) => {
                        const ProviderIcon = integrationIconComponent(acc.provider);
                        return (
                          <div
                            key={acc.slug}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="w-6 h-6 rounded-md border border-slate-200 bg-white flex items-center justify-center shrink-0 text-slate-600">
                                <ProviderIcon className="w-3.5 h-3.5" />
                              </span>
                              <div className="min-w-0">
                                <div className="text-xs font-medium text-slate-900 truncate">
                                  {acc.display_name}
                                </div>
                                {acc.account_identifier && (
                                  <div className="text-[10.5px] text-slate-500 truncate">
                                    {acc.account_identifier}
                                  </div>
                                )}
                              </div>
                            </div>
                            <button
                              type="button"
                              title={`Unlink ${acc.display_name}`}
                              onClick={() => toggleLinkedAccount(acc.slug)}
                              className="p-1 text-slate-400 hover:text-rose-600 cursor-pointer shrink-0"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* 2B. Vault Secrets (Assigned to this bot only + Add picker) */}
            {(() => {
              const grantedSecrets = vaultSecrets.filter(
                (sec) => sec.allowed_bots.includes("*") || sec.allowed_bots.includes(bot.slug),
              );
              const availableSecrets = vaultSecrets.filter(
                (sec) => !sec.allowed_bots.includes("*") && !sec.allowed_bots.includes(bot.slug),
              );
              return (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                      Vault Secrets
                    </div>
                    <div className="flex items-center gap-2">
                      {availableSecrets.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setAddingSecret((v) => !v)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[10.5px] font-medium text-slate-700 cursor-pointer"
                        >
                          <Plus className="w-3 h-3" />
                          <span>{addingSecret ? "Done" : "Add"}</span>
                        </button>
                      )}
                      {onOpenVault && (
                        <button
                          type="button"
                          onClick={onOpenVault}
                          className="text-[11px] text-slate-500 hover:text-slate-900 hover:underline cursor-pointer"
                        >
                          Manage
                        </button>
                      )}
                    </div>
                  </div>

                  {addingSecret && availableSecrets.length > 0 && (
                    <div className="rounded-xl border border-slate-200 bg-white p-1.5 space-y-0.5">
                      {availableSecrets.map((sec) => {
                        const VaultIcon = vaultSecretIconComponent(sec.secret_type);
                        return (
                          <button
                            key={sec.slug}
                            type="button"
                            onClick={() => {
                              void onToggleVaultSecret?.(sec, bot.slug);
                              setAddingSecret(false);
                            }}
                            className="w-full text-left px-2 py-1.5 rounded-lg hover:bg-slate-100 flex items-center gap-2 text-xs text-slate-800 cursor-pointer"
                          >
                            <VaultIcon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                            <span className="truncate font-medium">{sec.name}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {grantedSecrets.length === 0 ? (
                    <div className="text-[11px] text-slate-400">
                      No secrets assigned to this bot.
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {grantedSecrets.map((sec) => {
                        const VaultIcon = vaultSecretIconComponent(sec.secret_type);
                        const endpoint = sec.host || sec.url || "";
                        return (
                          <div
                            key={sec.slug}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="w-6 h-6 rounded-md border border-slate-200 bg-white flex items-center justify-center shrink-0 text-slate-600">
                                <VaultIcon className="w-3.5 h-3.5" />
                              </span>
                              <div className="min-w-0">
                                <div className="text-xs font-medium text-slate-900 truncate">
                                  {sec.name}
                                </div>
                                {(endpoint || sec.allowed_bots.includes("*")) && (
                                  <div className="text-[10.5px] text-slate-500 truncate">
                                    {endpoint}
                                    {endpoint && sec.allowed_bots.includes("*") ? " · " : ""}
                                    {sec.allowed_bots.includes("*") ? "All bots" : ""}
                                  </div>
                                )}
                              </div>
                            </div>
                            <button
                              type="button"
                              title={`Remove access to ${sec.name}`}
                              onClick={() => void onToggleVaultSecret?.(sec, bot.slug)}
                              className="p-1 text-slate-400 hover:text-rose-600 cursor-pointer shrink-0"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* 2C. Source Bots (Scoped Cross-Bot Data Read Grants) */}
            {(() => {
              const sourceColsFor = (other: BotRecord): string[] => {
                const writeCols = (other.collections?.write ?? []).filter(
                  (c) => c && !HIDDEN_INTERNAL_COLLECTIONS.has(c),
                );
                return writeCols.length > 0 ? writeCols : [`bot_${other.slug}_items`];
              };
              const curRead = bot.collections?.read ?? [];
              const curWrite = bot.collections?.write ?? [];
              const otherBots = bots.filter((b) => b.slug !== bot.slug);
              const linkedSourceBots = otherBots.filter((other) =>
                sourceColsFor(other).some((col) => curRead.includes(col)),
              );
              const availableSourceBots = otherBots.filter(
                (other) => !sourceColsFor(other).some((col) => curRead.includes(col)),
              );
              const addSourceBot = (other: BotRecord) => {
                const nextRead = Array.from(new Set([...curRead, ...sourceColsFor(other)]));
                void onUpdateBot(bot.slug, {
                  collections: { read: nextRead, write: curWrite },
                });
                setAddingSourceBot(false);
              };
              const removeSourceBot = (other: BotRecord) => {
                const removeSet = new Set(sourceColsFor(other));
                const nextRead = curRead.filter((col) => !removeSet.has(col));
                void onUpdateBot(bot.slug, {
                  collections: { read: nextRead, write: curWrite },
                });
              };
              return (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                      Source Bots
                    </div>
                    {availableSourceBots.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setAddingSourceBot((v) => !v)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[10.5px] font-medium text-slate-700 cursor-pointer"
                      >
                        <Plus className="w-3 h-3" />
                        <span>{addingSourceBot ? "Done" : "Add"}</span>
                      </button>
                    )}
                  </div>

                  {addingSourceBot && availableSourceBots.length > 0 && (
                    <div className="rounded-xl border border-slate-200 bg-white p-1.5 space-y-0.5">
                      {availableSourceBots.map((other) => (
                        <button
                          key={other.slug}
                          type="button"
                          onClick={() => addSourceBot(other)}
                          className="w-full text-left px-2 py-1.5 rounded-lg hover:bg-slate-100 flex items-center gap-2 text-xs text-slate-800 cursor-pointer"
                        >
                          <BotAvatar
                            icon={other.avatar_icon}
                            color={other.avatar_color}
                            initials={other.initials}
                            size="xs"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-medium">{other.name}</div>
                            <div className="text-[10px] text-slate-400 truncate">{other.role}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}

                  {linkedSourceBots.length === 0 ? (
                    <div className="text-[11px] text-slate-400">
                      Isolated — reads only its own data unless linked or mentioned with @Bot.
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {linkedSourceBots.map((other) => (
                        <div
                          key={other.slug}
                          className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <BotAvatar
                              icon={other.avatar_icon}
                              color={other.avatar_color}
                              initials={other.initials}
                              size="xs"
                            />
                            <div className="min-w-0">
                              <div className="text-xs font-medium text-slate-900 truncate">
                                {other.name}
                              </div>
                              <div className="text-[10.5px] text-slate-500 truncate">
                                {other.role}
                              </div>
                            </div>
                          </div>
                          <button
                            type="button"
                            title={`Revoke access to ${other.name}`}
                            onClick={() => removeSourceBot(other)}
                            className="p-1 text-slate-400 hover:text-rose-600 cursor-pointer shrink-0"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* 3. When Sending */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                When Sending
              </div>
              <div className="grid grid-cols-3 gap-1 p-1 rounded-xl border border-slate-200 bg-slate-50">
                {RBAC_MODES.map((mode) => {
                  const active = bot.outbound_rbac === mode.key;
                  return (
                    <button
                      key={mode.key}
                      type="button"
                      onClick={() => void onUpdateBot(bot.slug, { outbound_rbac: mode.key })}
                      className={`py-1.5 px-2 rounded-lg text-[11px] font-medium cursor-pointer transition ${
                        active
                          ? "bg-slate-900 text-white shadow-xs"
                          : "text-slate-600 hover:text-slate-900"
                      }`}
                    >
                      {mode.shortTitle}
                    </button>
                  );
                })}
              </div>
              <p className="text-[11px] text-slate-500 leading-snug">{activeRbacMeta.desc}</p>

              {bot.outbound_rbac === "execute" && (
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 space-y-1.5 text-[11px]">
                  <div className="flex justify-between text-slate-700 font-medium">
                    <span>Daily Send Limit</span>
                    <span className="font-semibold text-slate-900">{bot.daily_cap}/day</span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={50}
                    step={1}
                    value={bot.daily_cap}
                    onChange={(e) =>
                      void onUpdateBot(bot.slug, { daily_cap: Number(e.target.value) })
                    }
                    className="w-full accent-[#3b72b2] cursor-pointer"
                  />
                </div>
              )}

              {/* Generic Turn Governance Step Budget */}
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 space-y-1.5 text-[11px]">
                <div className="flex justify-between text-slate-700 font-medium">
                  <span>Step Limit Before Check-In</span>
                  <span className="font-semibold text-slate-900">
                    {bot.max_steps_per_run ?? 10} steps
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-1 p-0.5 rounded-lg border border-slate-200 bg-white">
                  {(
                    [
                      [5, "Short (5)"],
                      [10, "Standard (10)"],
                      [25, "Extended (25)"],
                    ] as const
                  ).map(([val, lbl]) => {
                    const active = (bot.max_steps_per_run ?? 10) === val;
                    return (
                      <button
                        key={val}
                        type="button"
                        onClick={() => void onUpdateBot(bot.slug, { max_steps_per_run: val })}
                        className={`py-1 px-1.5 rounded-md text-[10.5px] font-medium cursor-pointer transition ${
                          active
                            ? "bg-slate-900 text-white shadow-xs"
                            : "text-slate-600 hover:text-slate-900"
                        }`}
                      >
                        {lbl}
                      </button>
                    );
                  })}
                </div>
                <p className="text-[10.5px] text-slate-500 leading-snug">
                  Repeated stuck loops stop automatically. Longer workflows pause with a 1-click Continue button.
                </p>
              </div>
            </div>

            {/* 4. Routines & Schedules */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Routines ({bot.routines.length})
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setAddingRoutine((v) => !v);
                    setNewRoutineLabel("");
                    setNewRoutinePrompt("");
                    setNewRoutineTimezone(browserTz);
                  }}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[10.5px] font-medium text-slate-700 cursor-pointer"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add Routine</span>
                </button>
              </div>

              {addingRoutine && (
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 space-y-2 text-xs">
                  <input
                    type="text"
                    value={newRoutineLabel}
                    onChange={(e) => setNewRoutineLabel(e.target.value)}
                    placeholder="Routine name (e.g. Morning Digest)"
                    className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px]"
                  />
                  <div className="grid grid-cols-2 gap-1.5">
                    <input
                      type="text"
                      value={newRoutineSchedule}
                      onChange={(e) => setNewRoutineSchedule(e.target.value)}
                      placeholder="Every weekday at 09:00 or Once at 2026-11-20 21:00"
                      className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                    />
                    <input
                      type="text"
                      value={newRoutineTimezone}
                      onChange={(e) => setNewRoutineTimezone(e.target.value)}
                      placeholder="UTC / America/New_York"
                      className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                    />
                  </div>
                  <textarea
                    rows={2}
                    value={newRoutinePrompt}
                    onChange={(e) => setNewRoutinePrompt(e.target.value)}
                    placeholder="Task prompt for this routine..."
                    className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px]"
                  />
                  <div className="flex items-center justify-between gap-2">
                    <select
                      value={newRoutineStale}
                      onChange={(e) =>
                        setNewRoutineStale(
                          e.target.value as "skip_quietly" | "notify_missing" | "always_run",
                        )
                      }
                      className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10.5px]"
                    >
                      <option value="skip_quietly">Skip quietly if no new items</option>
                      <option value="notify_missing">Notify if no new items</option>
                      <option value="always_run">Always summarize</option>
                    </select>
                    <button
                      type="button"
                      disabled={!newRoutineLabel.trim()}
                      onClick={() => {
                        const schedVal = newRoutineSchedule.trim() || "Manual";
                        const oneShot = isOneShotRoutineSchedule(schedVal);
                        const next = [
                          ...(bot.routines ?? []).map((r) => ({ ...r })),
                          {
                            id: `rtn-${Date.now()}`,
                            type:
                              schedVal.toLowerCase() === "manual"
                                ? "manual_trigger"
                                : oneShot
                                  ? "once"
                                  : "cron",
                            one_shot: oneShot,
                            label: newRoutineLabel.trim(),
                            schedule: schedVal,
                            timezone: newRoutineTimezone.trim() || browserTz,
                            prompt: newRoutinePrompt.trim(),
                            stale_data_policy: newRoutineStale,
                            enabled: true,
                          },
                        ];
                        void onUpdateBot(bot.slug, { routines: next });
                        setAddingRoutine(false);
                      }}
                      className="px-2.5 py-1 rounded-lg bg-slate-900 text-white text-[11px] font-medium disabled:opacity-40 cursor-pointer"
                    >
                      Save
                    </button>
                  </div>
                </div>
              )}

              <div className="space-y-1.5">
                {bot.routines.map((routine) => {
                  const isEvent = routine.type === "on_event" || Boolean(routine.event);
                  const isOneShot =
                    !isEvent &&
                    isOneShotRoutineSchedule(
                      routine.schedule,
                      routine.type,
                      routine.one_shot,
                    );
                  const isCompletedOneShot = isOneShot && !routine.enabled && Boolean(routine.completed_at);
                  const scheduleChoices = SCHEDULE_OPTIONS.includes(routine.schedule)
                    ? SCHEDULE_OPTIONS
                    : [routine.schedule, ...SCHEDULE_OPTIONS];
                  const isExpanded = editingRoutineId === routine.id;
                  return (
                    <div
                      key={routine.id}
                      className="rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-2 space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <button
                              type="button"
                              onClick={() => {
                                if (isExpanded) {
                                  setEditingRoutineId(null);
                                  setEditRoutineDraft(null);
                                } else {
                                  setEditingRoutineId(routine.id);
                                  setEditRoutineDraft({
                                    label: routine.label || "Routine",
                                    schedule: routine.schedule || "Manual",
                                    timezone: routine.timezone || browserTz,
                                    prompt: routine.prompt || "",
                                    stale_data_policy:
                                      (routine.stale_data_policy as
                                        | "skip_quietly"
                                        | "notify_missing"
                                        | "always_run") || "skip_quietly",
                                  });
                                }
                              }}
                              className="text-left text-[11.5px] font-semibold text-slate-900 truncate hover:underline cursor-pointer"
                            >
                              {routine.label || "Routine"}
                              {routine.timezone && routine.timezone !== "UTC"
                                ? ` (${routine.timezone})`
                                : ""}
                            </button>
                            {isOneShot && (
                              <span
                                className={`px-1.5 py-0.5 rounded-full text-[9.5px] font-medium shrink-0 border ${
                                  isCompletedOneShot
                                    ? "bg-slate-100 border-slate-200 text-slate-600"
                                    : "bg-indigo-50 border-indigo-200 text-indigo-700"
                                }`}
                              >
                                {isCompletedOneShot ? "Ran once" : "One-time"}
                              </span>
                            )}
                          </div>
                          {isEvent ? (
                            <div className="text-[10.5px] text-slate-600 truncate">
                              On event: {routine.event || routine.schedule}
                            </div>
                          ) : (
                            <select
                              value={routine.schedule}
                              onChange={(e) => void updateRoutineSchedule(routine.id, e.target.value)}
                              className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px] text-slate-900 cursor-pointer"
                            >
                              {scheduleChoices.map((opt) => (
                                <option key={opt} value={opt}>
                                  {opt}
                                </option>
                              ))}
                            </select>
                          )}
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            type="button"
                            title="Test routine now"
                            disabled={triggeringId !== null || !bot.enabled}
                            onClick={async () => {
                              setTriggeringId(routine.id);
                              try {
                                await onTriggerBot(bot.slug, routine.id);
                              } finally {
                                setTriggeringId(null);
                              }
                            }}
                            className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-40 cursor-pointer"
                          >
                            <Play className="w-3 h-3" />
                          </button>
                          <ToggleSwitch
                            checked={routine.enabled}
                            onChange={() =>
                              void onUpdateBot(bot.slug, { toggle_routine_id: routine.id })
                            }
                            label="Toggle routine schedule"
                          />
                          {bot.routines.length > 1 && (
                            <button
                              type="button"
                              title="Delete routine"
                              onClick={() =>
                                void onUpdateBot(bot.slug, {
                                  routines: bot.routines
                                    .filter((r) => r.id !== routine.id)
                                    .map((r) => ({ ...r })),
                                })
                              }
                              className="p-1 text-slate-400 hover:text-rose-600 cursor-pointer"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                      </div>
                      {isExpanded && !isEvent && editRoutineDraft && (
                        <div className="pt-2 border-t border-slate-200 space-y-1.5 text-[11px]">
                          <div className="grid grid-cols-2 gap-1.5">
                            <input
                              type="text"
                              value={editRoutineDraft.label}
                              onChange={(e) =>
                                setEditRoutineDraft((prev) =>
                                  prev ? { ...prev, label: e.target.value } : prev,
                                )
                              }
                              placeholder="Routine name"
                              className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                            />
                            <input
                              type="text"
                              value={editRoutineDraft.timezone}
                              onChange={(e) =>
                                setEditRoutineDraft((prev) =>
                                  prev ? { ...prev, timezone: e.target.value } : prev,
                                )
                              }
                              placeholder="Timezone"
                              className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                            />
                          </div>
                          <input
                            type="text"
                            value={editRoutineDraft.schedule}
                            onChange={(e) =>
                              setEditRoutineDraft((prev) =>
                                prev ? { ...prev, schedule: e.target.value } : prev,
                              )
                            }
                            placeholder="Every weekday at 09:00 or Once at 2026-11-20 21:00"
                            className="w-full rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                          />
                          <textarea
                            rows={2}
                            value={editRoutineDraft.prompt}
                            onChange={(e) =>
                              setEditRoutineDraft((prev) =>
                                prev ? { ...prev, prompt: e.target.value } : prev,
                              )
                            }
                            placeholder="Task prompt (leave blank to use bot instructions)"
                            className="w-full rounded-lg border border-slate-200 bg-white px-2 py-1 text-[11px]"
                          />
                          <div className="flex items-center justify-between gap-1.5">
                            <select
                              value={editRoutineDraft.stale_data_policy}
                              onChange={(e) =>
                                setEditRoutineDraft((prev) =>
                                  prev
                                    ? {
                                        ...prev,
                                        stale_data_policy: e.target.value as
                                          | "skip_quietly"
                                          | "notify_missing"
                                          | "always_run",
                                      }
                                    : prev,
                                )
                              }
                              className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-[10.5px]"
                            >
                              <option value="skip_quietly">Skip quietly if no new items</option>
                              <option value="notify_missing">Notify if no new items</option>
                              <option value="always_run">Always summarize</option>
                            </select>
                            <button
                              type="button"
                              onClick={() => {
                                const updated = bot.routines.map((r) => {
                                  if (r.id !== routine.id) {
                                    return r as unknown as Record<string, unknown>;
                                  }
                                  const nextSched =
                                    editRoutineDraft.schedule.trim() || r.schedule || "Manual";
                                  const nextOneShot = isOneShotRoutineSchedule(nextSched);
                                  const nextObj: Record<string, unknown> = {
                                    ...(r as unknown as Record<string, unknown>),
                                    label: editRoutineDraft.label.trim() || r.label,
                                    schedule: nextSched,
                                    type:
                                      nextSched.toLowerCase() === "manual"
                                        ? "manual_trigger"
                                        : nextOneShot
                                          ? "once"
                                          : "cron",
                                    one_shot: nextOneShot,
                                    timezone: editRoutineDraft.timezone.trim() || browserTz,
                                    prompt: editRoutineDraft.prompt.trim(),
                                    stale_data_policy: editRoutineDraft.stale_data_policy,
                                  };
                                  if (nextSched !== r.schedule) {
                                    nextObj.enabled = true;
                                    delete nextObj.completed_at;
                                  }
                                  return nextObj;
                                });
                                void onUpdateBot(bot.slug, { routines: updated });
                                setEditingRoutineId(null);
                                setEditRoutineDraft(null);
                              }}
                              className="px-2.5 py-1 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer"
                            >
                              Save
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 5. Hand Off Findings To */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Hand Off Findings To
              </div>
              <select
                value={bot.handoff_bot_slug || ""}
                onChange={(e) => void onUpdateBot(bot.slug, { handoff_bot_slug: e.target.value })}
                className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-900 cursor-pointer"
              >
                <option value="">None (handle on its own)</option>
                {bots
                  .filter((other) => other.slug !== bot.slug)
                  .map((other) => (
                    <option key={other.slug} value={other.slug}>
                      {other.name}
                    </option>
                  ))}
              </select>
              <p className="text-[11px] text-slate-500 leading-snug">
                When this bot saves useful findings, it automatically sends them to the chosen bot.
              </p>
              {!bot.handoff_bot_slug && onCreateCompanionWriter && (
                <button
                  type="button"
                  onClick={() => void onCreateCompanionWriter(bot)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                >
                  <Plus className="w-3 h-3" />
                  Create a Writer Bot &amp; Link
                </button>
              )}
            </div>

            {/* 6. Rules for This Bot */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Rules for This Bot
              </div>
              <div className="space-y-1.5">
                {boundaries.length === 0 && scopedRules.length === 0 ? (
                  <div className="text-[11px] text-slate-400">
                    No bot-specific rules yet. Add rules like &ldquo;Never delete emails&rdquo; or &ldquo;Keep replies brief&rdquo;.
                  </div>
                ) : (
                  <>
                    {boundaries.map((b, idx) => (
                      <div
                        key={`b-${idx}`}
                        className="flex items-start justify-between gap-2 px-2.5 py-2 rounded-lg border border-slate-200 bg-slate-50 text-[11px]"
                      >
                        <span className="text-slate-800">{b}</span>
                        <button
                          type="button"
                          onClick={() =>
                            void onUpdateBot(bot.slug, {
                              boundaries: boundaries.filter((_, i) => i !== idx),
                            })
                          }
                          className="text-[10px] text-rose-600 hover:underline shrink-0 cursor-pointer"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                    {scopedRules.map((rule) => (
                      <div
                        key={rule.id}
                        className="flex items-start justify-between gap-2 px-2.5 py-2 rounded-lg border border-slate-200 bg-slate-50 text-[11px]"
                      >
                        <span className="text-slate-800">{rule.rule_text}</span>
                        <button
                          type="button"
                          onClick={() => void onDeleteStyleRule(rule.id)}
                          className="text-[10px] text-rose-600 hover:underline shrink-0 cursor-pointer"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </>
                )}
              </div>
              <form onSubmit={addUnifiedRule} className="flex gap-1.5">
                <input
                  type="text"
                  value={newRuleInput}
                  onChange={(e) => setNewRuleInput(e.target.value)}
                  placeholder="Add a rule or boundary..."
                  className="flex-1 min-w-0 rounded-lg border border-slate-200 px-2.5 py-1.5 text-[11px]"
                />
                <button
                  type="submit"
                  disabled={savingRule || !newRuleInput.trim()}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 disabled:opacity-40 text-white text-[11px] font-medium cursor-pointer"
                >
                  Add
                </button>
              </form>
              {globalRulesCount > 0 && (
                <div className="text-[10px] text-slate-400">
                  + {globalRulesCount} workspace rule{globalRulesCount === 1 ? "" : "s"} managed in Settings
                </div>
              )}
            </div>

            {/* 7. More Options */}
            <div className="pt-2 border-t border-slate-200">
              <button
                type="button"
                onClick={() => setMoreOpen((v) => !v)}
                className="w-full flex items-center justify-between py-1 text-xs font-medium text-slate-700 hover:text-slate-900 cursor-pointer"
              >
                <span>More Options</span>
                {moreOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              </button>

              {moreOpen && (
                <div className="mt-3 space-y-3">
                  <div>
                    <label className="block text-[11px] text-slate-500 mb-1">Badge Color &amp; Icon</label>
                    <div className="flex items-center gap-1.5 mb-2">
                      {AVATAR_COLORS.map((c) => (
                        <button
                          key={c.key}
                          type="button"
                          onClick={() => void onUpdateBot(bot.slug, { avatar_color: c.key })}
                          className={`w-5 h-5 rounded-full ${c.bg} cursor-pointer ${
                            (bot.avatar_color ?? "slate") === c.key
                              ? "ring-2 ring-offset-2 ring-slate-900"
                              : "opacity-75 hover:opacity-100"
                          }`}
                        />
                      ))}
                    </div>
                    <div className="flex items-center gap-1 flex-wrap">
                      {BOT_ICON_OPTIONS.map(({ key, label, Icon }) => (
                        <button
                          key={key}
                          type="button"
                          title={label}
                          onClick={() => void onUpdateBot(bot.slug, { avatar_icon: key })}
                          className={`p-1.5 rounded-lg border cursor-pointer ${
                            (bot.avatar_icon ?? "bot") === key
                              ? "border-slate-900 bg-slate-900 text-white"
                              : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-500 mb-1">Sidebar Group</label>
                    <input
                      type="text"
                      value={sectionInput}
                      onChange={(e) => setSectionInput(e.target.value)}
                      onBlur={() => {
                        if (sectionInput.trim() !== (bot.section ?? "")) {
                          void onUpdateBot(bot.slug, { section: sectionInput.trim() });
                        }
                      }}
                      placeholder="e.g. Content, Ops"
                      className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] text-slate-500 mb-1">AI Model</label>
                    <select
                      value={bot.model}
                      onChange={(e) => void onUpdateBot(bot.slug, { model: e.target.value })}
                      className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-900"
                    >
                      {modelChoices.map((modelId) => (
                        <option key={modelId} value={modelId}>
                          {friendlyModelName(modelId)}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => onInspectDebug(bot.slug)}
                      className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-[11px] font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                    >
                      View Run Logs
                    </button>
                    {onExportBlueprint && (
                      <button
                        type="button"
                        onClick={() => void onExportBlueprint(bot.slug)}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        Export Blueprint
                      </button>
                    )}
                    {onExportTeamPack && (
                      <button
                        type="button"
                        onClick={() =>
                          void onExportTeamPack(
                            bot.section?.trim()
                              ? { section: bot.section.trim(), title: `${bot.section.trim()} Crew` }
                              : { bot_slugs: [bot.slug], title: `${bot.name} Pack` },
                          )
                        }
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                      >
                        <Package className="w-3 h-3" />
                        Export Team Pack
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          </>
        )}

        {activeTab === "library" && (
          <>
            {/* Interactive Pages owned by / linked to this bot */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Interactive Pages
                </span>
                {onOpenNewPage && (
                  <button
                    type="button"
                    onClick={onOpenNewPage}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                  >
                    <Plus className="w-3 h-3" />
                    <span>New Page</span>
                  </button>
                )}
              </div>

              {ownedPages.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-200 p-3 text-[11px] text-slate-500">
                  No pages linked to {bot.name} yet.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {pinnedPages.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                        Pinned
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {pinnedPages.map((pg) => {
                          const isCurrent = activePageSlug === pg.slug;
                          return (
                            <div
                              key={pg.id}
                              className={`inline-flex items-center gap-1.5 pl-3 pr-1.5 py-1 rounded-full border text-xs font-medium transition-colors ${
                                isCurrent
                                  ? "border-slate-900 bg-slate-900 text-white"
                                  : "border-slate-200 bg-slate-50 text-slate-800 hover:bg-slate-100"
                              }`}
                            >
                              <button
                                type="button"
                                onClick={() => onOpenPage?.(pg.slug)}
                                className="inline-flex items-center gap-1.5 cursor-pointer"
                              >
                                <FileText className="w-3 h-3 shrink-0" />
                                <span className="truncate max-w-[190px]">{pg.title}</span>
                              </button>
                              {onDockPage && (
                                <button
                                  type="button"
                                  title="Dock beside chat"
                                  onClick={() => onDockPage(pg.slug)}
                                  className="p-1 rounded-full opacity-70 hover:opacity-100 cursor-pointer"
                                >
                                  <Columns2 className="w-2.5 h-2.5" />
                                </button>
                              )}
                              {onTogglePagePin && (
                                <button
                                  type="button"
                                  title="Unpin Page"
                                  onClick={() => onTogglePagePin(pg.slug, false)}
                                  className="p-1 rounded-full hover:bg-slate-700 cursor-pointer"
                                >
                                  <Pin className="w-2.5 h-2.5 text-amber-400 fill-amber-400" />
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {recentPages.length > 0 && (
                    <div className="space-y-1.5">
                      {pinnedPages.length > 0 && (
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                          Recent
                        </div>
                      )}
                      <div className="flex flex-wrap gap-1.5">
                        {recentPages.map((pg) => {
                          const isCurrent = activePageSlug === pg.slug;
                          return (
                            <div
                              key={pg.id}
                              className={`inline-flex items-center gap-1.5 pl-3 pr-1.5 py-1 rounded-full border text-xs font-medium transition-colors ${
                                isCurrent
                                  ? "border-slate-900 bg-slate-900 text-white"
                                  : "border-slate-200 bg-slate-50 text-slate-800 hover:bg-slate-100"
                              }`}
                            >
                              <button
                                type="button"
                                onClick={() => onOpenPage?.(pg.slug)}
                                className="inline-flex items-center gap-1.5 cursor-pointer"
                              >
                                <FileText className="w-3 h-3 shrink-0" />
                                <span className="truncate max-w-[190px]">{pg.title}</span>
                              </button>
                              {onDockPage && (
                                <button
                                  type="button"
                                  title="Dock beside chat"
                                  onClick={() => onDockPage(pg.slug)}
                                  className="p-1 rounded-full opacity-60 hover:opacity-100 cursor-pointer"
                                >
                                  <Columns2 className="w-2.5 h-2.5" />
                                </button>
                              )}
                              {onTogglePagePin && (
                                <button
                                  type="button"
                                  title="Pin Page"
                                  onClick={() => onTogglePagePin(pg.slug, true)}
                                  className="p-1 rounded-full opacity-50 hover:opacity-100 cursor-pointer"
                                >
                                  <Pin className="w-2.5 h-2.5" />
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Data Collections */}
            <div className="space-y-2 pt-2 border-t border-slate-200">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Data Lists
              </div>
              {displayCollections.length === 0 ? (
                <div className="text-[11px] text-slate-400">No data lists registered yet.</div>
              ) : (
                <div className="space-y-1.5">
                  {displayCollections.map((col) => (
                    <div
                      key={col.slug}
                      className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50"
                    >
                      <div className="min-w-0 flex items-center gap-2">
                        <Database className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                        <div className="text-xs font-medium text-slate-900 truncate">
                          {col.label || col.slug}
                        </div>
                      </div>
                      <span className="px-2 py-0.5 rounded-full bg-white border border-slate-200 text-[10px] font-semibold text-slate-700 shrink-0">
                        {col.doc_count}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Skills */}
            <div className="space-y-2 pt-2 border-t border-slate-200">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Saved Skills ({botSkills.length})
              </div>
              {botSkills.length === 0 ? (
                <div className="text-[11px] text-slate-400">
                  Save reusable instructions from any chat reply via &ldquo;Save as Skill&rdquo;.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {botSkills.map((sk) => {
                    const expanded = expandedSkillId === sk.id;
                    return (
                      <div
                        key={sk.id}
                        className="rounded-xl border border-slate-200 bg-slate-50 p-2 space-y-1.5"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedSkillId((prev) => (prev === sk.id ? null : sk.id))
                            }
                            className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-800 hover:underline min-w-0 cursor-pointer"
                          >
                            <Sparkles className="w-3 h-3 text-slate-500 shrink-0" />
                            <span className="truncate">{sk.name}</span>
                          </button>
                          {onDeleteSkill && (
                            <button
                              type="button"
                              title="Delete skill"
                              onClick={() => void onDeleteSkill(sk.id)}
                              className="p-0.5 text-slate-400 hover:text-rose-600 cursor-pointer"
                            >
                              <Trash2 className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                        {expanded && (
                          <div className="text-[11px] text-slate-600 bg-white border border-slate-200 rounded-lg p-2 whitespace-pre-wrap max-h-32 overflow-y-auto">
                            {sk.instructions}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Per-User Workspace Files (<= 10 MB) */}
            {renderWorkspaceFilesSection()}
          </>
        )}

        {activeTab === "computer" && (
          <div className="space-y-4">
            <SSHTerminalPanel
              botSlug={bot.slug}
              theme={theme}
              variant="sidebar"
              refreshTick={sshRefreshTick}
              onExpandModal={onExpandTerminal ? () => onExpandTerminal(bot.slug) : undefined}
              hasPermittedSSH={vaultSecrets.some(
                (v) =>
                  v.secret_type === "ssh" &&
                  (v.allowed_bots.includes("*") || v.allowed_bots.includes(bot.slug)),
              )}
            />
            {bot.runtime === "desktop" ? (
              <>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="inline-flex items-center gap-1.5 font-semibold text-slate-900">
                      <Cpu className="w-3.5 h-3.5 text-sky-600" />
                      <span>Virtual Desktop</span>
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${
                        bot.desktop_state === "running"
                          ? "bg-emerald-50 border border-emerald-200 text-emerald-700"
                          : "bg-slate-200 text-slate-700"
                      }`}
                    >
                      {bot.desktop_state === "running" ? "Running" : "Sleeping"}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Isolated Fedora XFCE · Chromium CDP :9222 · Desktop MCP :9223
                  </div>
                  <DesktopScreenPreview
                    botSlug={bot.slug}
                    running={bot.desktop_state === "running"}
                    hasScreenshot={desktopInfo?.has_screenshot}
                    toggling={togglingDesktop}
                    bootProgress={desktopBootProgress}
                    onOpenScreen={() => onOpenSelkies(bot)}
                    compact
                  />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={togglingDesktop}
                      onClick={() => onOpenSelkies(bot)}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 bg-slate-900 text-white py-1.5 px-2.5 rounded-lg text-[11px] font-medium disabled:opacity-50 cursor-pointer"
                    >
                      <Monitor className="w-3 h-3 shrink-0" />
                      <span>{bot.desktop_state === "running" ? "Open Screen" : "Start & Open"}</span>
                    </button>
                    <button
                      type="button"
                      disabled={togglingDesktop}
                      onClick={() => onToggleDesktop(bot.slug)}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 border border-slate-200 bg-white py-1.5 px-2.5 rounded-lg text-[11px] font-medium text-slate-900 cursor-pointer hover:bg-slate-50 disabled:opacity-50"
                    >
                      {togglingDesktop && <Loader2 className="w-3 h-3 animate-spin shrink-0" />}
                      <span>
                        {togglingDesktop
                          ? bot.desktop_state === "running"
                            ? "Stopping..."
                            : "Starting..."
                          : bot.desktop_state === "running"
                            ? "Put to Sleep"
                            : "Start Desktop"}
                      </span>
                    </button>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-200 p-3 space-y-2">
                  <div className="text-xs font-medium text-slate-900">Runtime Mode</div>
                  <p className="text-[11px] text-slate-500 leading-snug">
                    Switch to Script Sandbox (512 MB CLI) for bash/Python scripts, or 0 MB Cloud API for direct connectors.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => void onUpdateBot(bot.slug, { runtime: "sandbox" })}
                      className="px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                    >
                      Switch to Script Sandbox (512 MB)
                    </button>
                    <button
                      type="button"
                      onClick={() => void onUpdateBot(bot.slug, { runtime: "api" })}
                      className="px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                    >
                      Switch to Cloud API (0 MB)
                    </button>
                  </div>
                </div>
              </>
            ) : bot.runtime === "sandbox" ? (
              <>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="inline-flex items-center gap-1.5 font-semibold text-slate-900">
                      <Terminal className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Script Sandbox</span>
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${
                        bot.sandbox_state === "running"
                          ? "bg-emerald-50 border border-emerald-200 text-emerald-700"
                          : "bg-slate-200 text-slate-700"
                      }`}
                    >
                      {bot.sandbox_state === "running" ? "Running" : "Sleeping"}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Headless Fedora 45 CLI · {bot.ram_limit_mb} MB cap · Persistent /workspace
                  </div>
                  <div className="rounded-lg bg-white border border-slate-200 px-2.5 py-1.5 text-[11px] text-slate-600 flex justify-between gap-2">
                    <span>
                      Memory:{" "}
                      {bot.sandbox_state === "running"
                        ? `${bot.ram_mb} MB / ${bot.ram_limit_mb} MB`
                        : "0 MB (/workspace saved)"}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400">bash · python3</span>
                  </div>
                  {onToggleSandbox && (
                    <button
                      type="button"
                      disabled={togglingSandbox}
                      onClick={() => onToggleSandbox(bot.slug)}
                      className="w-full inline-flex items-center justify-center gap-1.5 border border-slate-200 bg-white py-1.5 px-2.5 rounded-lg text-[11px] font-medium text-slate-900 cursor-pointer hover:bg-slate-50 disabled:opacity-50"
                    >
                      {togglingSandbox && <Loader2 className="w-3 h-3 animate-spin shrink-0" />}
                      <span>
                        {togglingSandbox
                          ? bot.sandbox_state === "running"
                            ? "Stopping..."
                            : "Starting..."
                          : bot.sandbox_state === "running"
                            ? "Put to Sleep"
                            : "Start Sandbox"}
                      </span>
                    </button>
                  )}
                </div>

                <div className="rounded-xl border border-slate-200 p-3 space-y-2">
                  <div className="text-xs font-medium text-slate-900">Runtime Mode</div>
                  <p className="text-[11px] text-slate-500 leading-snug">
                    Switch to 0 MB Cloud API when scripts are no longer needed, or upgrade to Virtual Desktop for GUI browser automation.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => void onUpdateBot(bot.slug, { runtime: "api" })}
                      className="px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                    >
                      Switch to Cloud API (0 MB)
                    </button>
                    <button
                      type="button"
                      onClick={() => void onUpdateBot(bot.slug, { runtime: "desktop" })}
                      className="px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                    >
                      Upgrade to Virtual Desktop
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-xl bg-sky-50 border border-sky-200 flex items-center justify-center">
                    <Cloud className="w-4 h-4 text-sky-600" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-900">Cloud API Mode (0 MB)</div>
                    <div className="text-[11px] text-slate-500">
                      Fast native Gmail, Telegram, LinkedIn, MCP &amp; RSS tools
                    </div>
                  </div>
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  No container is attached. Attach Script Sandbox (512 MB CLI) for custom bash/Python scripts, or Virtual Desktop (2 GB) for GUI browser apps.
                </p>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void onUpdateBot(bot.slug, { runtime: "sandbox" })}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-slate-900 text-[11px] font-medium cursor-pointer"
                  >
                    <Terminal className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Attach Script Sandbox</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => void onUpdateBot(bot.slug, { runtime: "desktop" })}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900 text-white text-[11px] font-medium cursor-pointer"
                  >
                    <Monitor className="w-3.5 h-3.5" />
                    <span>Attach Virtual Desktop</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {(onDeleteBot || onClearBotMessages) && (activeTab === "details" || activeTab === "computer") && (
        <div className="shrink-0 px-4 py-2.5 border-t border-slate-200 bg-slate-50 flex items-center justify-between gap-2">
          {confirmClearChat && onClearBotMessages ? (
            renderClearChatConfirmation({
              slug: bot.slug,
              onClear: onClearBotMessages,
              onExport: onExportBotMessages,
            })
          ) : confirmDeleteBot && onDeleteBot ? (
            <div className="flex items-center justify-between gap-2 w-full">
              <span className="text-[11px] font-medium text-rose-700 truncate">
                Delete {bot.name}?
              </span>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  type="button"
                  disabled={deletingBot}
                  onClick={() => setConfirmDeleteBot(false)}
                  className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] text-slate-600 hover:bg-slate-100 disabled:opacity-50 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={deletingBot}
                  onClick={async () => {
                    setDeletingBot(true);
                    try {
                      await onDeleteBot(bot.slug);
                      setConfirmDeleteBot(false);
                    } finally {
                      setDeletingBot(false);
                    }
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-[11px] font-medium disabled:opacity-50 cursor-pointer"
                >
                  {deletingBot && <Loader2 className="w-3 h-3 animate-spin" />}
                  <span>{deletingBot ? "Deleting..." : "Confirm Delete"}</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              <button
                type="button"
                onClick={() => onInspectDebug(bot.slug)}
                className="text-[11px] text-slate-500 hover:text-slate-900 cursor-pointer"
              >
                Run Logs
              </button>
              <div className="flex items-center gap-1.5">
                {onClearBotMessages && canManageBot && (
                  <button
                    type="button"
                    disabled={deletingBot || (typeof messageCount === "number" && messageCount === 0)}
                    onClick={() => {
                      setConfirmDeleteBot(false);
                      setClearChatError(null);
                      setConfirmClearChat(true);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>Clear Chat</span>
                  </button>
                )}
                {onDeleteBot && canManageBot && (
                  <button
                    type="button"
                    disabled={deletingBot}
                    onClick={() => {
                      setConfirmClearChat(false);
                      setConfirmDeleteBot(true);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-rose-200 bg-white text-[11px] font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                  >
                    <Trash2 className="w-3 h-3" />
                    <span>Delete Bot</span>
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </aside>
  );
}
