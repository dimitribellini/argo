import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import {
  ArrowRight,
  ArrowUp,
  AtSign,
  BookmarkPlus,
  Camera,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  CornerUpLeft,
  Download,
  FileText,
  FileUp,
  Image as ImageIcon,
  ListChecks,
  Loader2,
  Monitor,
  MoreHorizontal,
  Paperclip,
  Pencil,
  Plus,
  ShieldCheck,
  SmilePlus,
  Sparkles,
  Square,
  Terminal,
  X,
} from "lucide-react";
import { api, maxWorkspaceFileBytesForName } from "../../api";
import { useIsMobile } from "../../hooks/useIsMobile";
import type {
  ActiveThreadStream,
  ApprovalItem,
  BotMessage,
  BotRecord,
  BotRunActivity,
  DelegationPlan,
  DesktopBootProgress,
  HabitProposal,
  IntegrationAccount,
  LiveTurnChip,
  MessageQuote,
  ModelProvider,
  OperatorQuestion,
  PageRecord,
  PendingRoomHandoff,
  RoomMessage,
  RoomRecord,
  RunCheckpoint,
  SkillRecord,
  VaultSecretRecord,
  WorkspaceFileAttachment,
  WorkspaceFileRecord,
} from "../../types";
import {
  computeWordDiff,
  extractApprovalHost,
  extractSuggestedTrustPrefixes,
  formatBotSystemText,
  formatFriendlyTime,
  formatShellCommandForDisplay,
  friendlyActionStepLabel,
  friendlyAutonomyLabel,
  partitionSSHApprovalBatches,
} from "../../utils/format";
import { BotAvatar } from "../BotAvatar";
import {
  HighlightedMessageText,
  InlineMentionBadge,
  integrationIconComponent,
  renderComposerBackdropNodes,
  skillIconComponent,
  vaultSecretIconComponent,
  type MentionCatalog,
  type ResolvedMentionEntity,
} from "../MentionText";
import { RichMarkdown } from "../RichMarkdown";

interface BotThreadViewProps {
  bot: BotRecord | null;
  room?: RoomRecord | null;
  bots?: BotRecord[];
  messages: BotMessage[];
  roomMessages?: RoomMessage[];
  approvals?: ApprovalItem[];
  integrations?: IntegrationAccount[];
  models?: ModelProvider[];
  pages?: PageRecord[];
  skills?: SkillRecord[];
  vaultSecrets?: VaultSecretRecord[];
  workspaceFiles?: WorkspaceFileRecord[];
  activeRun?: BotRunActivity | null;
  activeStream?: ActiveThreadStream | null;
  queuedCount?: number;
  desktopBootProgress?: DesktopBootProgress | null;
  contextCorrelationId?: string | null;
  targetPageSlug?: string | null;
  onClearContextCorrelation?: () => void;
  onSendMessage: (
    slug: string,
    text: string,
    options?: {
      skill_slugs?: string[];
      context_correlation_id?: string;
      target_page_slug?: string;
      reply_to_id?: string;
      attachment_ids?: string[];
    },
  ) => Promise<void>;
  onSendRoomMessage?: (
    roomSlug: string,
    payload: {
      text: string;
      reply_to_id?: string;
      attachment_ids?: string[];
      skill_slugs?: string[];
      target_page_slug?: string;
      approved_handoff_bot_slug?: string;
    },
  ) => Promise<void>;
  onEditLastMessage?: (messageId: string, newText: string) => Promise<void>;
  onCancelRun?: (runId: string) => Promise<void>;
  onUploadFile?: (file: File) => Promise<WorkspaceFileRecord>;
  onExecutePlan?: (plan: DelegationPlan) => Promise<void>;
  onToggleReaction?: (
    messageId: string,
    emoji: string,
    collection: "bot_threads" | "room_threads",
  ) => Promise<void>;
  onOpenNewBot: () => void;
  onTriggerBot?: (slug: string) => Promise<void>;
  onUpdateBot?: (
    slug: string,
    updates: {
      model?: string;
      outbound_rbac?: "internal" | "draft" | "execute";
      routines?: Array<Record<string, unknown>>;
    },
  ) => Promise<void> | void;
  onApproveItem?: (id: string, opts?: { trust_command?: boolean }) => Promise<void>;
  onBatchResolveApprovals?: (
    ids: string[],
    action: "approve" | "reject",
    opts?: { trust_command?: boolean },
  ) => Promise<void>;
  onRejectItem?: (id: string) => Promise<void>;
  onEditApprovalItem?: (item: ApprovalItem) => void;
  onOpenPage?: (pageSlug: string, sideBySide?: boolean) => void;
  onOpenSelkies?: (bot: BotRecord) => void;
  onOpenTerminal?: (botSlug: string, sessionId?: string | null) => void;
  onSaveSkill?: (payload: {
    name: string;
    description?: string;
    instructions: string;
    scope_slug?: string;
  }) => Promise<void>;
  hasMoreMessages?: boolean;
  totalMessagesCount?: number;
  loadingMessages?: boolean;
  loadingOlderMessages?: boolean;
  onLoadOlderMessages?: () => Promise<void> | void;
  prefillDraft?: { id: number; text: string } | null;
  onConsumePrefillDraft?: () => void;
  compact?: boolean;
  placeholder?: string;
}

interface NormalizedThreadMessage {
  id: string;
  sender: "user" | "bot";
  senderSlug: string;
  senderName: string;
  text: string;
  createdAt: string;
  metadata?: {
    correlation_id?: string;
    run_id?: string;
    stopped_by_user?: boolean;
    chips?: LiveTurnChip[];
    routing_source?: string;
    routed_reason?: string;
    trigger_type?: string;
    actions?: Array<{ screenshot_url?: string; slug?: string; page_slug?: string; title?: string; [key: string]: unknown }>;
    delegated_by?: string;
    skill_slugs?: string[];
    target_page_slug?: string;
    onboarding_interview?: boolean;
    quick_replies?: string[];
    applied_changes?: Record<string, unknown>;
    habit_proposal?: HabitProposal;
    delegation_plan?: DelegationPlan;
    operator_question?: OperatorQuestion;
    pending_room_handoff?: PendingRoomHandoff;
    run_checkpoint?: RunCheckpoint;
    attachments?: WorkspaceFileAttachment[];
    reply_to?: MessageQuote;
    reactions?: Record<string, string[]>;
  };
}

type MentionCategory = "Bots" | "Connected Apps" | "Secrets" | "Skills" | "Pages" | "Files";

interface MentionCandidate {
  kind: "vault" | "integration" | "bot" | "page" | "file" | "skill";
  category: MentionCategory;
  token: string;
  label: string;
  bot?: BotRecord;
  provider?: string;
  secretType?: string;
  isRecorded?: boolean;
}

const QUICK_REACTIONS = ["👍", "✅", "👀"];

const SCHEDULE_PRESETS = ["Every 15m", "Every 1h", "Every 24h", "Manual"];

function botHasTool(bot: BotRecord, toolName: string): boolean {
  return (bot.tools ?? []).some(
    (t) =>
      (typeof t === "string" && t === toolName) ||
      (typeof t === "object" && t !== null && String(t.name ?? "") === toolName),
  );
}

function getRoleType(
  bot: BotRecord,
): "supervisor" | "sandbox" | "desktop" | "email" | "web" | "writer" | "general" {
  const combined = `${bot.name} ${bot.role} ${bot.role_prompt}`.toLowerCase();
  if (
    botHasTool(bot, "platform_status") ||
    bot.avatar_icon === "shield" ||
    /\b(supervisor|coordinator|oversee|all bots|fleet|manage bots)\b/.test(combined)
  ) {
    return "supervisor";
  }
  if (bot.runtime === "desktop") {
    return "desktop";
  }
  if (bot.runtime === "sandbox") {
    return "sandbox";
  }
  if (
    botHasTool(bot, "gmail_search") ||
    bot.avatar_icon === "mail" ||
    /\b(gmail|email|inbox|mailbox)\b/.test(combined)
  ) {
    return "email";
  }
  if (
    botHasTool(bot, "fetch_rss_feed") ||
    botHasTool(bot, "fetch_public_webpage") ||
    bot.avatar_icon === "rss" ||
    /\b(rss|feed|blog|article|news|http)\b/.test(combined)
  ) {
    return "web";
  }
  if (
    bot.avatar_icon === "pen" ||
    /\b(writer|story|copywriter|editorial|draft posts)\b/.test(combined)
  ) {
    return "writer";
  }
  return "general";
}

function getStarterPrompts(bot: BotRecord): Array<{ title: string; prompt: string }> {
  const roleType = getRoleType(bot);
  if (roleType === "supervisor") {
    return [
      {
        title: "Check all bots & recent runs",
        prompt: "Check the status, schedules, and recent runs of all my bots.",
      },
      {
        title: "Build a live Bot Operations Map",
        prompt: "Build a Live Operations Map Page showing all my bots, their states, and pending approvals.",
      },
      {
        title: "Audit token usage & costs",
        prompt: "Audit which bots used the most tokens recently and suggest optimizations.",
      },
      {
        title: "Propose a new specialist bot",
        prompt: "Based on my current bots, propose a helpful new specialist bot to fill any gap.",
      },
    ];
  }
  if (roleType === "sandbox") {
    return [
      {
        title: "Write & run a Python script",
        prompt:
          "Write a Python script to /workspace/check_versions.py that fetches JSON API metadata and prints a clean summary.",
      },
      {
        title: "Inspect /workspace scripts",
        prompt: "List files in /workspace and inspect any saved scripts and recent outputs.",
      },
      {
        title: "Check HTTPS endpoint via curl",
        prompt:
          "Use curl or Python in your Script Sandbox to inspect response status, headers, and release info from a public API endpoint.",
      },
      {
        title: "Create a live status Page",
        prompt: "Collect CLI script findings and publish an interactive Page summarizing the results.",
      },
    ];
  }
  if (roleType === "desktop") {
    return [
      {
        title: "Open a website in Virtual Desktop",
        prompt: "Open https://example.com in your virtual desktop and capture a screenshot with a summary.",
      },
      {
        title: "Inspect desktop & running apps",
        prompt: "Inspect your Virtual Desktop screen, check which applications are running, and take a screenshot.",
      },
      {
        title: "Create a digest Page",
        prompt: "Build an interactive Page summarizing the findings captured in your Virtual Desktop.",
      },
      {
        title: "Inspect desktop mode & takeover",
        prompt: "Explain how your Virtual Desktop (Selkies + MCP + Chromium) works and when you ask me to take over.",
      },
    ];
  }
  if (roleType === "email") {
    return [
      {
        title: "Screen unread emails now",
        prompt: "Check my unread emails now and summarize only messages from real people.",
      },
      {
        title: "Draft a reply to latest email",
        prompt: "Draft a polite, concise reply to the most recent personal email and queue it for my approval.",
      },
      {
        title: "Add a noise filter rule",
        prompt: "Remember to never disturb me for newsletters, receipts, or automated alerts.",
      },
      {
        title: "Build an inbox digest Page",
        prompt: "Build an interactive Page summarizing important emails you have found.",
      },
    ];
  }
  if (roleType === "web") {
    return [
      {
        title: "Fetch latest updates now",
        prompt: "Check your configured websites or feeds now and summarize any unseen articles.",
      },
      {
        title: "Build a Data Explorer Page",
        prompt: "Build an interactive Data Explorer Page visualizing the articles you have saved.",
      },
      {
        title: "Set content exclusions",
        prompt: "Remember to skip marketing case studies and only keep technical release updates.",
      },
      {
        title: "Adjust check frequency",
        prompt: "Switch your check schedule to run every 1 hour instead.",
      },
    ];
  }
  if (roleType === "writer") {
    return [
      {
        title: "Craft a story from saved leads",
        prompt: "Review the latest collected items and draft an engaging summary or post for my approval.",
      },
      {
        title: "Save my preferred structure",
        prompt: "Remember to lead with one key takeaway, keep paragraphs short, and include source links.",
      },
      {
        title: "Prepare a draft Page preview",
        prompt: "Build a clean interactive Page displaying your recent drafts and source items.",
      },
      {
        title: "Run using reusable @skills",
        prompt: "What writing rules and reusable skills are you currently following?",
      },
    ];
  }
  return [
    {
      title: "Run a check now",
      prompt: "Run a check now and summarize anything important you find.",
    },
    {
      title: "Build an interactive Page",
      prompt: "Build an interactive Page visualizing what you have collected.",
    },
    {
      title: "Inspect rules & connected apps",
      prompt: "What rules, schedules, and connected apps are you currently using?",
    },
    {
      title: "Suggest next automations",
      prompt: "Explain what recurring automations or handoffs we can set up for this role.",
    },
  ];
}

export function BotThreadView({
  bot,
  room = null,
  bots = [],
  messages,
  roomMessages = [],
  approvals = [],
  integrations = [],
  pages = [],
  skills = [],
  vaultSecrets = [],
  workspaceFiles = [],
  activeRun = null,
  activeStream = null,
  queuedCount = 0,
  desktopBootProgress = null,
  contextCorrelationId = null,
  targetPageSlug = null,
  onClearContextCorrelation,
  onSendMessage,
  onSendRoomMessage,
  onEditLastMessage,
  onCancelRun,
  onUploadFile,
  onExecutePlan,
  onToggleReaction,
  onOpenNewBot,
  onUpdateBot,
  onApproveItem,
  onBatchResolveApprovals,
  onRejectItem,
  onEditApprovalItem,
  onOpenPage,
  onOpenSelkies,
  onOpenTerminal,
  onSaveSkill,
  hasMoreMessages = false,
  totalMessagesCount = 0,
  loadingMessages = false,
  loadingOlderMessages = false,
  onLoadOlderMessages,
  prefillDraft = null,
  onConsumePrefillDraft,
  compact = false,
  placeholder,
}: BotThreadViewProps) {
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [pendingUserMsg, setPendingUserMsg] = useState<{
    text: string;
    replyTo?: MessageQuote | null;
    attachments?: WorkspaceFileRecord[];
  } | null>(null);
  const isMobile = useIsMobile();
  const [elapsedSec, setElapsedSec] = useState(0);
  const [mentionOpen, setMentionOpen] = useState(false);
  const [attachMenuOpen, setAttachMenuOpen] = useState(false);
  const [mentionQuery, setMentionQuery] = useState("");
  const [mentionSelectedIndex, setMentionSelectedIndex] = useState(0);
  const [expandedSteps, setExpandedSteps] = useState<Record<string, boolean>>({});
  const [skillDraftMsgId, setSkillDraftMsgId] = useState<string | null>(null);
  const [skillNameInput, setSkillNameInput] = useState("");
  const [automateMsgId, setAutomateMsgId] = useState<string | null>(null);
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null);
  const [reactMenuMsgId, setReactMenuMsgId] = useState<string | null>(null);
  const [moreMenuMsgId, setMoreMenuMsgId] = useState<string | null>(null);
  const [failedShotKeys, setFailedShotKeys] = useState<Record<string, boolean>>({});
  const [replyTo, setReplyTo] = useState<MessageQuote | null>(null);
  const [draftAttachments, setDraftAttachments] = useState<WorkspaceFileRecord[]>([]);
  const [uploadingFile, setUploadingFile] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [executingPlanId, setExecutingPlanId] = useState<string | null>(null);
  const [approvingHandoffKey, setApprovingHandoffKey] = useState<string | null>(null);
  const [habitDrafts, setHabitDrafts] = useState<
    Record<string, { label: string; schedule: string; timezone: string }>
  >({});
  const [activatedHabits, setActivatedHabits] = useState<Record<string, boolean>>({});
  const [savingHabitId, setSavingHabitId] = useState<string | null>(null);
  const [answeredQuestions, setAnsweredQuestions] = useState<Record<string, string>>({});
  const [busyApprovalId, setBusyApprovalId] = useState<string | null>(null);
  const [busyBatchMsgId, setBusyBatchMsgId] = useState<string | null>(null);
  const [expandedBatchKeys, setExpandedBatchKeys] = useState<Record<string, boolean>>({});
  const [copiedApprovalKey, setCopiedApprovalKey] = useState<string | null>(null);
  const [editingMsgId, setEditingMsgId] = useState<string | null>(null);
  const [editingText, setEditingText] = useState("");
  const [submittingEdit, setSubmittingEdit] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  function compactStepUrl(rawUrl: string): string {
    const clean = rawUrl.trim();
    if (!clean) return "";
    try {
      const u = new URL(clean);
      const host = u.hostname.replace(/^www\./, "");
      const path = u.pathname.replace(/\/+$/, "");
      const joined = path ? `${host}${path}` : host;
      return joined.length <= 44 ? joined : `${joined.slice(0, 41)}...`;
    } catch {
      return clean.length <= 44 ? clean : `${clean.slice(0, 41)}...`;
    }
  }

  function copyApprovalCommand(copyKey: string, commandText: string) {
    if (!commandText) return;
    void navigator.clipboard?.writeText(commandText);
    setCopiedApprovalKey(copyKey);
    window.setTimeout(() => {
      setCopiedApprovalKey((prev) => (prev === copyKey ? null : prev));
    }, 1600);
  }

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const docFileInputRef = useRef<HTMLInputElement | null>(null);
  const photoFileInputRef = useRef<HTMLInputElement | null>(null);
  const composerBackdropRef = useRef<HTMLDivElement | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const anchoredThreadKeyRef = useRef<string | null>(null);
  const pendingPrependHeightRef = useRef<number | null>(null);
  const prevLastMsgIdRef = useRef<string | null>(null);
  const wasNearBottomRef = useRef<boolean>(true);
  const mentionRangeRef = useRef<{ start: number; end: number } | null>(null);

  const isRoomMode = Boolean(room);
  const threadKey = room ? `room:${room.slug}` : bot ? `bot:${bot.slug}` : null;
  const activeBotSlug =
    bot?.slug ??
    room?.coordinator_bot_slug ??
    room?.member_bot_slugs[0] ??
    "";
  const subjectBot =
    bot ??
    (room
      ? bots.find((b) => b.slug === (room.coordinator_bot_slug || room.member_bot_slugs[0])) ??
        null
      : null);

  const visibleMessages: NormalizedThreadMessage[] = useMemo(() => {
    if (room) {
      return roomMessages
        .filter((m) => m.room_slug === room.slug)
        .map((m) => ({
          id: m.id,
          sender: m.sender,
          senderSlug: m.sender_slug,
          senderName: m.sender_name,
          text: m.text,
          createdAt: m.created_at,
          metadata: m.metadata,
        }));
    }
    if (!bot) return [];
    return messages
      .filter((m) => m.bot_slug === bot.slug)
      .map((m) => ({
        id: m.id,
        sender: m.sender,
        senderSlug: m.sender === "user" ? "user" : bot.slug,
        senderName: m.sender === "user" ? "You" : bot.name,
        text: m.text,
        createdAt: m.created_at,
        metadata: m.metadata,
      }));
  }, [room, roomMessages, bot, messages]);

  const { claimedApprovalIds, latestFallbackMsgIdByCorr } = useMemo(() => {
    const claimed = new Set<string>();
    const latestByCorr = new Map<string, string>();
    for (const m of visibleMessages) {
      if (m.sender === "user") continue;
      const mActions = m.metadata?.actions ?? [];
      let hasExplicitApproval = false;
      for (const a of mActions) {
        const aid = String(
          a.approval_id ?? (a.approval as { id?: string } | undefined)?.id ?? "",
        ).trim();
        if (aid) {
          claimed.add(aid);
          hasExplicitApproval = true;
        }
      }
      const corr = m.metadata?.correlation_id;
      if (!hasExplicitApproval && corr) {
        latestByCorr.set(corr, m.id);
      }
    }
    return { claimedApprovalIds: claimed, latestFallbackMsgIdByCorr: latestByCorr };
  }, [visibleMessages]);

  const showLiveStream = Boolean(
    activeStream &&
      !visibleMessages.some(
        (m) =>
          m.metadata?.run_id === activeStream.runId &&
          (!activeStream.botSlug || m.senderSlug === activeStream.botSlug),
      ),
  );
  const isWorking = sending || Boolean(activeRun) || showLiveStream;
  const [cancellingRunId, setCancellingRunId] = useState<string | null>(null);

  const lastUserMessageId = useMemo(() => {
    for (let i = visibleMessages.length - 1; i >= 0; i -= 1) {
      if (visibleMessages[i].sender === "user") {
        return visibleMessages[i].id;
      }
    }
    return null;
  }, [visibleMessages]);

  async function handleSubmitEditLastMessage(messageId: string) {
    if (!onEditLastMessage || submittingEdit) return;
    const trimmed = editingText.trim();
    if (!trimmed) {
      setEditError("Message cannot be empty.");
      return;
    }
    setSubmittingEdit(true);
    setEditError(null);
    try {
      await onEditLastMessage(messageId, trimmed);
      setEditingMsgId(null);
      setEditingText("");
    } catch (err) {
      setEditError(err instanceof Error ? err.message : "Failed to re-submit edited message.");
    } finally {
      setSubmittingEdit(false);
    }
  }

  useEffect(() => {
    setReplyTo(null);
    setDraftAttachments([]);
    setFileError(null);
    setMentionOpen(false);
    setAttachMenuOpen(false);
    setReactMenuMsgId(null);
    setMoreMenuMsgId(null);
    setEditingMsgId(null);
    setEditingText("");
    setSubmittingEdit(false);
    setEditError(null);
  }, [threadKey]);

  useEffect(() => {
    if (!mentionOpen && !attachMenuOpen && !reactMenuMsgId && !moreMenuMsgId) return;
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as HTMLElement | null;
      if (reactMenuMsgId && !target?.closest('[data-argo-popover="react"]')) {
        setReactMenuMsgId(null);
      }
      if (moreMenuMsgId && !target?.closest('[data-argo-popover="more"]')) {
        setMoreMenuMsgId(null);
      }
      if (mentionOpen && !target?.closest('[data-argo-popover="mention"]')) {
        setMentionOpen(false);
      }
      if (attachMenuOpen && !target?.closest('[data-argo-popover="attach"]')) {
        setAttachMenuOpen(false);
      }
    };
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setMentionOpen(false);
        setAttachMenuOpen(false);
        setReactMenuMsgId(null);
        setMoreMenuMsgId(null);
      }
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [mentionOpen, attachMenuOpen, reactMenuMsgId, moreMenuMsgId]);

  useEffect(() => {
    if (!prefillDraft) return;
    setText(prefillDraft.text);
    onConsumePrefillDraft?.();
    window.requestAnimationFrame(() => {
      const area = textareaRef.current;
      if (!area) return;
      area.focus();
      const len = prefillDraft.text.length;
      area.setSelectionRange(len, len);
    });
  }, [prefillDraft, onConsumePrefillDraft]);

  useLayoutEffect(() => {
    const area = textareaRef.current;
    if (!area) return;
    const MAX_COMPOSER_HEIGHT = 200;
    const syncHeight = () => {
      area.style.height = "auto";
      const nextHeight = Math.min(area.scrollHeight, MAX_COMPOSER_HEIGHT);
      area.style.height = `${nextHeight}px`;
      area.style.overflowY = area.scrollHeight > MAX_COMPOSER_HEIGHT ? "auto" : "hidden";
      if (composerBackdropRef.current) {
        composerBackdropRef.current.style.transform = `translateY(-${area.scrollTop}px)`;
      }
    };
    syncHeight();
    if (typeof ResizeObserver === "undefined") return;
    let lastWidth = area.clientWidth;
    const ro = new ResizeObserver(() => {
      if (area.clientWidth === lastWidth) return;
      lastWidth = area.clientWidth;
      syncHeight();
    });
    ro.observe(area);
    return () => ro.disconnect();
  }, [text, threadKey]);

  useEffect(() => {
    if (!isWorking) {
      setElapsedSec(0);
      setCancellingRunId(null);
      return;
    }
    const startMs = activeStream?.startedAt ?? activeRun?.startedAt ?? Date.now();
    const tick = () => {
      setElapsedSec(Math.max(0, Math.floor((Date.now() - startMs) / 1000)));
    };
    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [isWorking, activeRun?.startedAt, activeStream?.startedAt]);

  useLayoutEffect(() => {
    const el = scrollContainerRef.current;
    if (!el || !threadKey) return;

    if (pendingPrependHeightRef.current !== null && !loadingOlderMessages) {
      const delta = el.scrollHeight - pendingPrependHeightRef.current;
      el.scrollTop = Math.max(0, delta);
      pendingPrependHeightRef.current = null;
      return;
    }

    const lastId = visibleMessages[visibleMessages.length - 1]?.id ?? null;
    if (anchoredThreadKeyRef.current !== threadKey) {
      if (!loadingMessages || visibleMessages.length > 0) {
        el.scrollTop = el.scrollHeight;
        anchoredThreadKeyRef.current = threadKey;
        prevLastMsgIdRef.current = lastId;
        wasNearBottomRef.current = true;
      }
      return;
    }

    if (lastId && lastId !== prevLastMsgIdRef.current) {
      prevLastMsgIdRef.current = lastId;
      if (wasNearBottomRef.current) {
        el.scrollTop = el.scrollHeight;
      }
    }
  }, [threadKey, visibleMessages, loadingMessages, loadingOlderMessages]);

  useEffect(() => {
    if (
      pendingUserMsg ||
      ((isWorking || Boolean(activeStream?.text) || (activeStream?.chips.length ?? 0) > 0) &&
        wasNearBottomRef.current)
    ) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [pendingUserMsg, isWorking, activeStream?.text, activeStream?.chips.length]);

  function triggerLoadOlder() {
    if (!hasMoreMessages || loadingOlderMessages || !onLoadOlderMessages) return;
    const el = scrollContainerRef.current;
    if (el) {
      pendingPrependHeightRef.current = el.scrollHeight;
    }
    void onLoadOlderMessages();
  }

  function handleThreadScroll() {
    const el = scrollContainerRef.current;
    if (!el) return;
    wasNearBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120;
    if (el.scrollTop <= 32 && hasMoreMessages && !loadingOlderMessages && onLoadOlderMessages) {
      triggerLoadOlder();
    }
  }

  const primaryRoutine = useMemo(() => {
    if (!subjectBot) return null;
    const list = subjectBot.routines ?? [];
    return list.find((r) => r.type !== "on_event") ?? list[0] ?? null;
  }, [subjectBot]);

  if (!room && !bot) {
    return (
      <div className="p-8 flex items-center justify-center h-full">
        <div className="max-w-md rounded-2xl border border-slate-200 bg-white p-7 text-center space-y-3 shadow-xs">
          <div className="text-sm font-semibold text-slate-900">Create your first automation bot</div>
          <p className="text-xs text-slate-500 leading-relaxed">
            Start a conversational Quick Setup or assemble a multi-bot Room in seconds.
          </p>
          <button
            type="button"
            onClick={onOpenNewBot}
            className="bg-slate-900 text-white px-4 py-2 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
          >
            + New Bot
          </button>
        </div>
      </div>
    );
  }

  const browserTz =
    (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
      } catch {
        return "UTC";
      }
    })();

  const botNameBySlug = new Map(bots.map((b) => [b.slug, b.name]));
  const botBySlug = new Map(bots.map((b) => [b.slug, b]));
  const botSkills = skills.filter(
    (s) => s.scope_slug === "*" || s.scope_slug === activeBotSlug,
  );
  const mentionCatalog: MentionCatalog = {
    bots,
    integrations,
    vaultSecrets,
    skills: botSkills,
    rooms: room ? [room] : [],
    pages,
    files: workspaceFiles,
  };
  const needle = mentionQuery.trim().toLowerCase();
  const filteredBots = bots.filter(
    (b) =>
      (isRoomMode || b.slug !== activeBotSlug) &&
      (!needle || b.name.toLowerCase().includes(needle) || b.slug.includes(needle)),
  );
  const filteredApps = integrations.filter(
    (acc) =>
      !needle ||
      acc.display_name.toLowerCase().includes(needle) ||
      acc.slug.includes(needle),
  );
  const filteredSkills = botSkills.filter(
    (s) => !needle || s.name.toLowerCase().includes(needle) || s.slug.includes(needle),
  );
  const permittedVault = vaultSecrets.filter(
    (v) => v.allowed_bots.includes("*") || v.allowed_bots.includes(activeBotSlug),
  );
  const filteredVault = permittedVault.filter(
    (v) =>
      !needle ||
      v.name.toLowerCase().includes(needle) ||
      v.slug.includes(needle) ||
      v.host.toLowerCase().includes(needle),
  );
  const filteredPages = pages.filter(
    (p) => !needle || p.title.toLowerCase().includes(needle) || p.slug.includes(needle),
  );
  const filteredFiles = workspaceFiles.filter(
    (f) => !needle || f.filename.toLowerCase().includes(needle),
  );

  const mentionCandidates: MentionCandidate[] = [
    ...filteredBots.map((b) => ({
      kind: "bot" as const,
      category: "Bots" as const,
      token: b.slug,
      label: b.name,
      bot: b,
    })),
    ...filteredApps.map((acc) => ({
      kind: "integration" as const,
      category: "Connected Apps" as const,
      token: acc.slug,
      label: acc.display_name,
      provider: acc.provider,
    })),
    ...filteredVault.map((sec) => ({
      kind: "vault" as const,
      category: "Secrets" as const,
      token: sec.slug,
      label: sec.name,
      secretType: sec.secret_type,
    })),
    ...filteredSkills.map((sk) => ({
      kind: "skill" as const,
      category: "Skills" as const,
      token: sk.slug,
      label: sk.name,
      isRecorded: (sk.description ?? "").toLowerCase().includes("recorded"),
    })),
    ...filteredPages.map((pg) => ({
      kind: "page" as const,
      category: "Pages" as const,
      token: pg.slug,
      label: pg.title,
    })),
    ...filteredFiles.map((wf) => ({
      kind: "file" as const,
      category: "Files" as const,
      token: wf.filename,
      label: wf.filename,
    })),
  ];

  function handleMentionClick(entity: ResolvedMentionEntity) {
    if (entity.kind === "page") {
      onOpenPage?.(entity.slug, true);
    }
  }

  function handleTextChange(val: string, caretPosition?: number | null) {
    setText(val);
    const pos =
      typeof caretPosition === "number"
        ? caretPosition
        : textareaRef.current?.selectionStart ?? val.length;
    const beforeCaret = val.slice(0, pos);
    const match = /(?:^|\s)(@([a-zA-Z0-9._-]*))$/.exec(beforeCaret);
    if (match) {
      const tokenWithAt = match[1];
      const startIdx = beforeCaret.length - tokenWithAt.length;
      mentionRangeRef.current = { start: startIdx, end: pos };
      setMentionOpen(true);
      setMentionQuery(match[2] ?? "");
      setMentionSelectedIndex(0);
    } else if (mentionOpen) {
      mentionRangeRef.current = null;
      setMentionOpen(false);
      setMentionQuery("");
    }
  }

  function insertMentionToken(token: string) {
    const range = mentionRangeRef.current;
    const el = textareaRef.current;
    let nextText = "";
    let nextCaret = 0;

    if (range && range.start >= 0 && range.end <= text.length) {
      const insertStr = `@${token} `;
      nextText = `${text.slice(0, range.start)}${insertStr}${text.slice(range.end)}`;
      nextCaret = range.start + insertStr.length;
    } else if (el && typeof el.selectionStart === "number") {
      const pos = el.selectionStart;
      const before = text.slice(0, pos);
      const needsSpace = before.length > 0 && !/\s$/.test(before);
      const insertStr = `${needsSpace ? " " : ""}@${token} `;
      nextText = `${before}${insertStr}${text.slice(pos)}`;
      nextCaret = pos + insertStr.length;
    } else {
      const insertStr = `${text && !text.endsWith(" ") ? " " : ""}@${token} `;
      nextText = `${text}${insertStr}`;
      nextCaret = nextText.length;
    }

    mentionRangeRef.current = null;
    setText(nextText);
    setMentionOpen(false);
    setMentionQuery("");
    setMentionSelectedIndex(0);
    window.requestAnimationFrame(() => {
      const area = textareaRef.current;
      if (!area) return;
      area.focus();
      area.setSelectionRange(nextCaret, nextCaret);
    });
  }

  async function handleFileSelection(files: FileList | File[]) {
    const list = Array.from(files);
    if (list.length === 0) return;
    setFileError(null);
    setUploadingFile(true);
    try {
      for (const file of list) {
        const limitBytes = maxWorkspaceFileBytesForName(file.name, file.type);
        if (file.size > limitBytes) {
          const limitMb = Math.round(limitBytes / (1024 * 1024));
          setFileError(`"${file.name}" exceeds the ${limitMb} MB per-file upload limit.`);
          continue;
        }
        const uploaded = onUploadFile
          ? await onUploadFile(file)
          : await api.uploadWorkspaceFile(file);
        setDraftAttachments((prev) =>
          prev.some((f) => f.id === uploaded.id) ? prev : [...prev, uploaded],
        );
      }
    } catch (err) {
      setFileError(err instanceof Error ? err.message : "File upload failed.");
    } finally {
      setUploadingFile(false);
    }
  }

  function handleComposerPaste(e: ClipboardEvent<HTMLTextAreaElement>) {
    const dt = e.clipboardData;
    if (!dt) return;
    const rawFiles: File[] = [];
    if (dt.items && dt.items.length > 0) {
      for (const item of Array.from(dt.items)) {
        if (item.kind === "file") {
          const f = item.getAsFile();
          if (f) rawFiles.push(f);
        }
      }
    } else if (dt.files && dt.files.length > 0) {
      rawFiles.push(...Array.from(dt.files));
    }
    if (rawFiles.length === 0) return;

    const plainText = dt.getData("text/plain");
    if (!plainText) {
      e.preventDefault();
    }

    const stamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
    const normalizedFiles = rawFiles.map((file, idx) => {
      const hasCustomName = Boolean(file.name && file.name !== "image.png" && file.name !== "blob");
      if (hasCustomName) return file;
      const mime = (file.type || "image/png").toLowerCase();
      const ext =
        mime.includes("jpeg") || mime.includes("jpg")
          ? "jpg"
          : mime.includes("webp")
            ? "webp"
            : mime.includes("gif")
              ? "gif"
              : mime.includes("pdf")
                ? "pdf"
                : "png";
      const suffix = rawFiles.length > 1 ? `-${idx + 1}` : "";
      return new File([file], `pasted-${stamp}${suffix}.${ext}`, {
        type: file.type || "image/png",
        lastModified: Date.now(),
      });
    });

    void handleFileSelection(normalizedFiles);
  }

  function handleDropFile(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDraggingFile(false);
    if (e.dataTransfer.files?.length) {
      void handleFileSelection(e.dataTransfer.files);
    }
  }

  async function submitText(rawText: string) {
    const trimmed = rawText.trim();
    if ((!trimmed && draftAttachments.length === 0) || sending || (!bot && !room)) return;
    const attachedFilesSnapshot = [...draftAttachments];
    const replySnapshot = replyTo;
    const attachmentIds = attachedFilesSnapshot.map((f) => f.id);
    const skillSlugs = botSkills
      .filter((sk) => {
        const escaped = sk.slug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        return new RegExp(
          `(?:^|[\\s([{"'\`:;,])${"@"}${escaped}(?=$|[\\s.,;:!?)'"\`\\]])`,
          "i",
        ).test(trimmed);
      })
      .map((sk) => sk.slug);
    setPendingUserMsg({
      text: trimmed || "(Attached workspace file)",
      replyTo: replySnapshot,
      attachments: attachedFilesSnapshot,
    });
    setText("");
    setDraftAttachments([]);
    setReplyTo(null);
    setFileError(null);
    if (composerBackdropRef.current) {
      composerBackdropRef.current.style.transform = "translateY(0px)";
    }
    setMentionOpen(false);
    setSending(true);
    try {
      if (room && onSendRoomMessage) {
        await onSendRoomMessage(room.slug, {
          text: trimmed,
          reply_to_id: replySnapshot?.id,
          attachment_ids: attachmentIds,
          skill_slugs: skillSlugs,
          target_page_slug: targetPageSlug ?? undefined,
        });
      } else if (bot) {
        await onSendMessage(bot.slug, trimmed, {
          skill_slugs: skillSlugs,
          context_correlation_id: contextCorrelationId ?? undefined,
          target_page_slug: targetPageSlug ?? undefined,
          reply_to_id: replySnapshot?.id,
          attachment_ids: attachmentIds,
        });
        onClearContextCorrelation?.();
      }
    } catch {
      setText(trimmed);
      setDraftAttachments(attachedFilesSnapshot);
      setReplyTo(replySnapshot);
    } finally {
      setPendingUserMsg(null);
      setSending(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await submitText(text);
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (mentionOpen && mentionCandidates.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setMentionSelectedIndex((i) => (i + 1) % mentionCandidates.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setMentionSelectedIndex(
          (i) => (i - 1 + mentionCandidates.length) % mentionCandidates.length,
        );
        return;
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        const chosen = mentionCandidates[mentionSelectedIndex] ?? mentionCandidates[0];
        if (chosen) insertMentionToken(chosen.token);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setMentionOpen(false);
        return;
      }
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void submitText(text);
    }
  }

  async function appendRoutineFromMessage(msg: NormalizedThreadMessage, schedule: string) {
    const targetBot = botBySlug.get(msg.senderSlug) ?? subjectBot;
    if (!targetBot || !onUpdateBot) return;
    const idx = visibleMessages.findIndex((m) => m.id === msg.id);
    const prevUserMsg =
      idx > 0 ? [...visibleMessages.slice(0, idx)].reverse().find((m) => m.sender === "user") : null;
    const taskPrompt = prevUserMsg?.text?.trim() || msg.text.slice(0, 400);
    const cleanLabel = (prevUserMsg?.text?.trim().slice(0, 40) || `${targetBot.name} Routine`).replace(
      /[?!.]+$/,
      "",
    );
    const existing = (targetBot.routines ?? []).map((r) => ({ ...r }));
    existing.push({
      id: `rtn-${Date.now()}`,
      type: schedule.toLowerCase() === "manual" ? "manual_trigger" : "cron",
      label: cleanLabel || "Scheduled Task",
      schedule,
      timezone: browserTz,
      prompt: taskPrompt,
      stale_data_policy: "skip_quietly",
      enabled: true,
    });
    await onUpdateBot(targetBot.slug, { routines: existing });
    setAutomateMsgId(null);
  }

  async function activateHabitProposal(
    msg: NormalizedThreadMessage,
    proposal: HabitProposal,
  ) {
    const targetBot = botBySlug.get(msg.senderSlug) ?? subjectBot;
    if (!targetBot || !onUpdateBot) return;
    const draft = habitDrafts[msg.id] ?? {
      label: proposal.suggested_routine_label,
      schedule: proposal.suggested_schedule,
      timezone: browserTz,
    };
    setSavingHabitId(msg.id);
    try {
      let skillSlug: string | undefined;
      if (onSaveSkill && proposal.suggested_skill_name.trim()) {
        await onSaveSkill({
          name: proposal.suggested_skill_name.trim(),
          description: `Saved habit for ${draft.label}`,
          instructions: proposal.suggested_instructions,
          scope_slug: targetBot.slug,
        });
        skillSlug = proposal.suggested_skill_name
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "");
      }
      const existing = (targetBot.routines ?? []).map((r) => ({ ...r }));
      existing.push({
        id: `rtn-${Date.now()}`,
        type: draft.schedule.toLowerCase() === "manual" ? "manual_trigger" : "cron",
        label: draft.label.trim() || proposal.suggested_routine_label,
        schedule: draft.schedule.trim() || proposal.suggested_schedule,
        timezone: draft.timezone.trim() || browserTz,
        prompt: proposal.suggested_instructions,
        skill_slugs: skillSlug ? [skillSlug] : [],
        stale_data_policy: "skip_quietly",
        enabled: true,
      });
      await onUpdateBot(targetBot.slug, { routines: existing });
      setActivatedHabits((prev) => ({ ...prev, [msg.id]: true }));
    } finally {
      setSavingHabitId(null);
    }
  }

  async function handleSaveReplyAsSkill(msg: NormalizedThreadMessage) {
    if (!onSaveSkill || !skillNameInput.trim() || !subjectBot) return;
    const targetBot = botBySlug.get(msg.senderSlug) ?? subjectBot;
    const idx = visibleMessages.findIndex((m) => m.id === msg.id);
    const prevUserMsg =
      idx > 0 ? [...visibleMessages.slice(0, idx)].reverse().find((m) => m.sender === "user") : null;
    const instructions = prevUserMsg
      ? `Task: ${prevUserMsg.text}\n\nExpected Output Style:\n${msg.text.slice(0, 1200)}`
      : msg.text.slice(0, 1500);
    await onSaveSkill({
      name: skillNameInput.trim(),
      description: `Saved from ${targetBot.name} thread`,
      instructions,
      scope_slug: targetBot.slug,
    });
    setSkillDraftMsgId(null);
    setSkillNameInput("");
  }

  function copyMessage(msg: NormalizedThreadMessage) {
    if (navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(msg.text);
    }
    setCopiedMsgId(msg.id);
    window.setTimeout(() => setCopiedMsgId((prev) => (prev === msg.id ? null : prev)), 1500);
  }

  const isInterviewIntro = Boolean(visibleMessages[0]?.metadata?.onboarding_interview);
  const starterCards = subjectBot ? getStarterPrompts(subjectBot) : [];
  const showOnboardingHero =
    !isRoomMode &&
    !loadingMessages &&
    !visibleMessages.some((m) => m.sender === "user") &&
    visibleMessages.length <= 1 &&
    !isInterviewIntro;
  const handoffTarget = subjectBot?.handoff_bot_slug
    ? bots.find((b) => b.slug === subjectBot.handoff_bot_slug)
    : undefined;

  const scheduleLabel = primaryRoutine
    ? primaryRoutine.enabled
      ? primaryRoutine.schedule
      : "Paused"
    : "Manual";

  const linkedAppNames = subjectBot
    ? integrations
        .filter((acc) => (subjectBot.linked_accounts ?? []).includes(acc.slug))
        .map((acc) => acc.display_name)
    : [];

  return (
    <div className="flex flex-col h-full bg-slate-50">
      <div
        ref={scrollContainerRef}
        onScroll={handleThreadScroll}
        className={`flex-1 overflow-y-auto custom-scroll ${compact ? "p-3.5" : "px-5 py-6"}`}
      >
        <div className={`${compact ? "space-y-4" : "max-w-3xl mx-auto space-y-6"}`}>

          {loadingMessages && visibleMessages.length === 0 ? (
            <div className="py-12 flex items-center justify-center gap-2 text-xs text-slate-500">
              <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
              <span>Loading latest messages...</span>
            </div>
          ) : showOnboardingHero && subjectBot && !pendingUserMsg ? (
            <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-5 shadow-xs mt-2">
              <div className="flex items-start gap-4 flex-wrap">
                <BotAvatar
                  icon={subjectBot.avatar_icon}
                  color={subjectBot.avatar_color}
                  initials={subjectBot.initials}
                  size="lg"
                />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="text-base font-semibold text-slate-900">{subjectBot.name}</h2>
                    <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-600">
                      {scheduleLabel}
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-600">
                      {friendlyAutonomyLabel(subjectBot.outbound_rbac)}
                    </span>
                    {handoffTarget && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-indigo-200 bg-indigo-50 text-[11px] text-indigo-700">
                        <ArrowRight className="w-3 h-3" />
                        Hands off to {handoffTarget.name}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-600 leading-relaxed">{subjectBot.role}</p>
                  {linkedAppNames.length > 0 && (
                    <div className="text-[11px] text-slate-500">
                      Connected apps: <span className="font-medium text-slate-700">{linkedAppNames.join(", ")}</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Suggested Next Steps
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {starterCards.map((card) => (
                    <button
                      key={card.title}
                      type="button"
                      onClick={() => void submitText(card.prompt)}
                      className="text-left rounded-xl border border-slate-200 bg-slate-50 hover:bg-slate-100 p-3 transition cursor-pointer group"
                    >
                      <div className="text-xs font-semibold text-slate-900 flex items-center justify-between gap-2">
                        <span>{card.title}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-700 shrink-0" />
                      </div>
                      <div className="text-[11px] text-slate-500 mt-1 line-clamp-2">
                        {card.prompt}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              {hasMoreMessages && (
                <div className="flex justify-center pt-1">
                  <button
                    type="button"
                    disabled={loadingOlderMessages}
                    onClick={triggerLoadOlder}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-600 shadow-xs cursor-pointer disabled:opacity-60"
                  >
                    {loadingOlderMessages && <Loader2 className="w-3 h-3 animate-spin" />}
                    <span>
                      {loadingOlderMessages
                        ? "Loading earlier messages..."
                        : `Load earlier messages${
                            totalMessagesCount > visibleMessages.length
                              ? ` (${totalMessagesCount - visibleMessages.length} older)`
                              : ""
                          }`}
                    </span>
                  </button>
                </div>
              )}
              {visibleMessages.map((msg, msgIdx) => {
                const actions = msg.metadata?.actions ?? [];
                const msgApprovalIds = new Set(
                  actions
                    .map((a) =>
                      String(a.approval_id ?? (a.approval as { id?: string } | undefined)?.id ?? ""),
                    )
                    .filter(Boolean),
                );
                const msgCorr = msg.metadata?.correlation_id;
                const linkedApprovals = approvals.filter((apr) => {
                  if (msgApprovalIds.size > 0) {
                    return msgApprovalIds.has(apr.id);
                  }
                  if (!msgCorr || apr.correlation_id !== msgCorr) return false;
                  if (apr.status !== "pending") return false;
                  if (claimedApprovalIds.has(apr.id)) return false;
                  return latestFallbackMsgIdByCorr.get(msgCorr) === msg.id;
                });
                const linkedPagesMap = new Map<string, string>();
                for (const a of actions) {
                  if (
                    (a.type === "upsert_page" || a.type === "open_page") &&
                    a.status === "ok"
                  ) {
                    const pSlug = String(a.slug ?? a.page_slug ?? "").trim();
                    if (pSlug) {
                      const pTitle =
                        (typeof a.title === "string" && a.title.trim()) ||
                        pages.find((p) => p.slug === pSlug)?.title ||
                        pSlug;
                      linkedPagesMap.set(pSlug, pTitle);
                    }
                  }
                }
                const linkedPages = Array.from(linkedPagesMap.entries()).map(([slug, title]) => ({
                  slug,
                  title,
                }));
                const takeoverAlerts = actions.filter(
                  (a) => a.status === "halted_takeover_required",
                );
                const screenshotUrls = Array.from(
                  new Set(
                    actions
                      .map((a) => (typeof a.screenshot_url === "string" ? a.screenshot_url : ""))
                      .filter(Boolean),
                  ),
                );
                const msgAttachments = (() => {
                  const combined = [...(msg.metadata?.attachments ?? [])];
                  const seenAttIds = new Set(combined.map((item) => item.id));
                  for (const act of actions) {
                    if (
                      act.type === "write_workspace_file" &&
                      act.status === "ok" &&
                      act.file &&
                      typeof act.file === "object"
                    ) {
                      const fobj = act.file as Record<string, unknown>;
                      const fid = String(fobj.id ?? "").trim();
                      if (fid && !seenAttIds.has(fid)) {
                        seenAttIds.add(fid);
                        combined.push({
                          id: fid,
                          filename: String(fobj.filename ?? "file"),
                          mime_type: String(fobj.mime_type ?? "text/plain"),
                          size_bytes: Number(fobj.size_bytes ?? 0),
                          is_image: Boolean(fobj.is_image),
                        });
                      }
                    }
                  }
                  return combined;
                })();
                const msgReactions = msg.metadata?.reactions ?? {};
                const reactionEntries = Object.entries(msgReactions).filter(
                  ([, actors]) => Array.isArray(actors) && actors.length > 0,
                );
                const stepsOpen = Boolean(expandedSteps[msg.id]);
                const targetCollection = isRoomMode ? "room_threads" : "bot_threads";

                if (msg.sender === "user") {
                  const targetSlug = msg.metadata?.target_page_slug;
                  const matchedTargetPage = targetSlug
                    ? pages.find((p) => p.slug === targetSlug) ?? null
                    : null;
                  return (
                    <div key={msg.id} className="flex justify-end group">
                      <div className="max-w-[78%] space-y-1">
                        <div className="rounded-2xl rounded-tr-sm px-4 py-2.5 text-[13px] leading-relaxed shadow-xs argo-user-bubble space-y-1.5">
                          {msg.metadata?.reply_to && (
                            <div className="rounded-lg border border-[#35547a] bg-[#16273f] px-2.5 py-1 text-[11px] text-[#dbeafe]">
                              <div className="font-semibold">
                                Replying to {msg.metadata.reply_to.sender_name}
                              </div>
                              <div className="truncate opacity-85">
                                {msg.metadata.reply_to.excerpt}
                              </div>
                            </div>
                          )}
                          {targetSlug && (
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <button
                                type="button"
                                onClick={() => onOpenPage?.(targetSlug, true)}
                                className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-[#35547a] bg-[#1d3554] hover:bg-[#244166] text-[11px] font-medium text-white cursor-pointer transition-colors"
                              >
                                <FileText className="w-3 h-3 shrink-0" />
                                <span>{matchedTargetPage?.title ?? targetSlug}</span>
                              </button>
                            </div>
                          )}
                          {editingMsgId === msg.id ? (
                            <div className="space-y-2 min-w-[240px]">
                              <textarea
                                rows={3}
                                autoFocus
                                value={editingText}
                                disabled={submittingEdit}
                                onChange={(e) => setEditingText(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === "Escape") {
                                    e.preventDefault();
                                    setEditingMsgId(null);
                                    setEditingText("");
                                    setEditError(null);
                                  } else if (e.key === "Enter" && !e.shiftKey) {
                                    e.preventDefault();
                                    void handleSubmitEditLastMessage(msg.id);
                                  }
                                }}
                                className="w-full rounded-xl border border-[#35547a] bg-[#16273f] px-3 py-2 text-[13px] text-white placeholder-[#94a3b8] focus:outline-none focus:border-white"
                              />
                              {editError && (
                                <div className="rounded-lg border border-rose-300 bg-rose-900 px-2.5 py-1 text-[11px] text-white">
                                  {editError}
                                </div>
                              )}
                              <div className="flex items-center justify-between gap-2 flex-wrap">
                                <span className="text-[10px] text-[#cbd5e1]">
                                  Replaces reply below with a new answer
                                </span>
                                <div className="flex items-center gap-1.5 ml-auto">
                                  <button
                                    type="button"
                                    disabled={submittingEdit}
                                    onClick={() => {
                                      setEditingMsgId(null);
                                      setEditingText("");
                                      setEditError(null);
                                    }}
                                    className="px-2.5 py-1 rounded-lg border border-[#35547a] bg-[#1d3554] text-[11px] text-[#dbeafe] hover:bg-[#244166] disabled:opacity-50 cursor-pointer"
                                  >
                                    Cancel
                                  </button>
                                  <button
                                    type="button"
                                    disabled={submittingEdit || !editingText.trim()}
                                    onClick={() => void handleSubmitEditLastMessage(msg.id)}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white text-slate-900 hover:bg-slate-100 text-[11px] font-semibold disabled:opacity-50 cursor-pointer"
                                  >
                                    {submittingEdit && <Loader2 className="w-3 h-3 animate-spin" />}
                                    <span>{submittingEdit ? "Sending..." : "Save & Resend"}</span>
                                  </button>
                                </div>
                              </div>
                            </div>
                          ) : (
                            msg.text && (
                              <HighlightedMessageText
                                text={msg.text}
                                catalog={mentionCatalog}
                                inverted
                                onMentionClick={handleMentionClick}
                              />
                            )
                          )}
                          {msgAttachments.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 pt-1">
                              {msgAttachments.map((att) => (
                                <span
                                  key={att.id}
                                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-[#35547a] bg-[#1d3554] text-[11px] text-[#dbeafe]"
                                >
                                  <a
                                    href={api.workspaceFileContentUrl(att.id)}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="inline-flex items-center gap-1.5 min-w-0 hover:underline"
                                  >
                                    <Paperclip className="w-3 h-3 shrink-0" />
                                    <span className="truncate max-w-[160px]">{att.filename}</span>
                                  </a>
                                  <a
                                    href={api.workspaceFileContentUrl(att.id, { download: true })}
                                    download={att.filename}
                                    title={`Download ${att.filename}`}
                                    aria-label={`Download ${att.filename}`}
                                    className="p-0.5 rounded text-[#cbd5e1] hover:text-white shrink-0"
                                  >
                                    <Download className="w-3 h-3" />
                                  </a>
                                </span>
                              ))}
                            </div>
                          )}
                          {(() => {
                            const extraSlugs = (msg.metadata?.skill_slugs ?? []).filter(
                              (sk) => !msg.text.toLowerCase().includes(`@${sk.toLowerCase()}`),
                            );
                            if (extraSlugs.length === 0) return null;
                            return (
                              <div className="mt-1.5 flex flex-wrap gap-1">
                                {extraSlugs.map((sk) => (
                                  <InlineMentionBadge
                                    key={sk}
                                    token={sk}
                                    catalog={mentionCatalog}
                                    inverted
                                  />
                                ))}
                              </div>
                            );
                          })()}
                          <div className="mt-1 text-[10px] text-[#cbd5e1] flex items-center justify-between gap-2">
                            <span>{formatFriendlyTime(msg.createdAt)}</span>
                            <div className="flex items-center gap-2.5">
                              {editingMsgId !== msg.id &&
                                msg.id === lastUserMessageId &&
                                onEditLastMessage &&
                                !isWorking &&
                                queuedCount === 0 && (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setEditingMsgId(msg.id);
                                      setEditingText(msg.text);
                                      setEditError(null);
                                    }}
                                    className="opacity-85 md:opacity-0 md:group-hover:opacity-100 inline-flex items-center gap-0.5 text-[#dbeafe] hover:underline cursor-pointer"
                                  >
                                    <Pencil className="w-2.5 h-2.5" />
                                    Edit
                                  </button>
                                )}
                              <button
                                type="button"
                                onClick={() =>
                                  setReplyTo({
                                    id: msg.id,
                                    sender: "user",
                                    sender_slug: "user",
                                    sender_name: "You",
                                    excerpt: msg.text.slice(0, 140),
                                  })
                                }
                                className="opacity-85 md:opacity-0 md:group-hover:opacity-100 inline-flex items-center gap-0.5 text-[#dbeafe] hover:underline cursor-pointer"
                              >
                                <CornerUpLeft className="w-2.5 h-2.5" />
                                Reply
                              </button>
                            </div>
                          </div>
                        </div>
                        {reactionEntries.length > 0 && (
                          <div className="flex items-center justify-end gap-1 flex-wrap">
                            {reactionEntries.map(([emoji, actors]) => (
                              <button
                                key={emoji}
                                type="button"
                                onClick={() =>
                                  void onToggleReaction?.(msg.id, emoji, targetCollection)
                                }
                                className="px-1.5 py-0.5 rounded-full border border-slate-200 bg-white text-[11px] text-slate-700 cursor-pointer"
                              >
                                {emoji} {actors.length}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }

                const speakerBot = botBySlug.get(msg.senderSlug) ?? subjectBot;
                const speakerName = msg.senderName || speakerBot?.name || "Bot";
                const delegatedFromSlug = msg.metadata?.delegated_by;
                const delegatedFromName = delegatedFromSlug
                  ? (botNameBySlug.get(delegatedFromSlug) ?? delegatedFromSlug)
                  : null;
                const isScheduledReply =
                  msg.metadata?.trigger_type?.startsWith("cron") ||
                  msg.metadata?.trigger_type === "scheduled";
                const quickReplies = Array.isArray(msg.metadata?.quick_replies)
                  ? msg.metadata.quick_replies
                  : [];
                const appliedChanges = msg.metadata?.applied_changes;
                const appliedEntries = appliedChanges
                  ? Object.entries(appliedChanges).filter(([, v]) => v !== null && v !== undefined && v !== "")
                  : [];
                const delegationPlan = msg.metadata?.delegation_plan;
                const operatorQuestion = msg.metadata?.operator_question;
                const answeredChoiceLabel = answeredQuestions[msg.id] ?? null;
                const hasLaterUserReply =
                  Boolean(operatorQuestion) &&
                  visibleMessages.slice(msgIdx + 1).some((m) => m.sender === "user");
                const questionResolved = Boolean(answeredChoiceLabel) || hasLaterUserReply;
                const habitProposal = msg.metadata?.habit_proposal;
                const pendingHandoff = msg.metadata?.pending_room_handoff;
                const footerVisible =
                  reactMenuMsgId === msg.id ||
                  moreMenuMsgId === msg.id ||
                  skillDraftMsgId === msg.id ||
                  automateMsgId === msg.id ||
                  copiedMsgId === msg.id;

                return (
                  <div key={msg.id} className="flex items-start gap-3 group">
                    {!compact && speakerBot && (
                      <BotAvatar
                        icon={speakerBot.avatar_icon}
                        color={speakerBot.avatar_color}
                        initials={speakerBot.initials}
                        size="sm"
                      />
                    )}
                    <div className="min-w-0 flex-1 space-y-2.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-semibold text-slate-900">{speakerName}</span>
                        <span className="text-[11px] text-slate-400">
                          {formatFriendlyTime(msg.createdAt)}
                        </span>
                        {isRoomMode &&
                          (msg.metadata?.routing_source === "capability" ||
                            msg.metadata?.routing_source === "auto_picker") && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-slate-100 text-[11px] font-medium text-slate-600">
                              Auto-picked {speakerName}
                              {msg.metadata?.routed_reason ? ` · ${msg.metadata.routed_reason}` : ""}
                            </span>
                          )}
                        {msg.metadata?.stopped_by_user && (
                          <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-100 text-[11px] font-medium text-slate-600">
                            Stopped
                          </span>
                        )}
                        {isScheduledReply && (
                          <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-white text-[10px] text-slate-500">
                            Scheduled
                          </span>
                        )}
                        {delegatedFromName && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-indigo-200 bg-indigo-50 text-[10px] font-medium text-indigo-700">
                            <ArrowRight className="w-2.5 h-2.5" />
                            Handoff from {delegatedFromName}
                          </span>
                        )}
                        {actions.length > 0 && (
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedSteps((prev) => ({ ...prev, [msg.id]: !prev[msg.id] }))
                            }
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white text-[10px] font-medium text-slate-600 hover:bg-slate-100 cursor-pointer"
                          >
                            {stepsOpen ? (
                              <ChevronDown className="w-3 h-3" />
                            ) : (
                              <ChevronRight className="w-3 h-3" />
                            )}
                            <span>
                              {actions.length} step{actions.length === 1 ? "" : "s"}
                            </span>
                          </button>
                        )}
                      </div>

                      {Array.isArray(msg.metadata?.chips) && msg.metadata.chips.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          {msg.metadata.chips.map((chip) => {
                            const st = String(chip.status || "done");
                            const secStr =
                              typeof chip.elapsed_ms === "number" && chip.elapsed_ms >= 50
                                ? ` · ${(chip.elapsed_ms / 1000).toFixed(1)}s`
                                : "";
                            return (
                              <span
                                key={chip.chip_id}
                                title={chip.detail || chip.label}
                                className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-slate-200 bg-white text-[11px] font-medium text-slate-700"
                              >
                                <span
                                  className="w-1.5 h-1.5 rounded-full shrink-0"
                                  style={{
                                    backgroundColor:
                                      st === "done"
                                        ? "#2f6b52"
                                        : st === "warning"
                                          ? "#c98a2c"
                                          : "#64748b",
                                  }}
                                />
                                <span>{chip.label}</span>
                                <span className="text-slate-400">
                                  {st === "stopped" ? "Stopped" : st === "warning" ? "Note" : `Done${secStr}`}
                                </span>
                              </span>
                            );
                          })}
                        </div>
                      )}

                      {msg.metadata?.reply_to && (
                        <div className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-[11px] text-slate-600 max-w-lg">
                          <span className="font-semibold text-slate-800">
                            Replying to {msg.metadata.reply_to.sender_name}:{" "}
                          </span>
                          <span className="truncate">{msg.metadata.reply_to.excerpt}</span>
                        </div>
                      )}

                      {stepsOpen && actions.length > 0 && (
                        <div className="rounded-xl border border-slate-200 bg-white p-2.5 space-y-1.5 text-[11px] max-w-lg">
                          {actions.map((act, idx) => {
                            const actType = String(act.type ?? "action");
                            const actStatus = String(act.status ?? act.outcome ?? "ok");
                            const friendly = friendlyActionStepLabel(actType, actStatus);
                            const hostLabel =
                              typeof act.host === "string" && act.host.trim() ? act.host.trim() : null;
                            const urlLabel =
                              typeof act.url === "string" && act.url.trim() ? act.url.trim() : null;
                            const handleLabel =
                              typeof act.channel_handle === "string" && act.channel_handle.trim()
                                ? `@${act.channel_handle.trim().replace(/^@/, "")}`
                                : null;
                            const fileLabel =
                              typeof act.filename === "string" && act.filename.trim()
                                ? act.filename.trim()
                                : null;
                            const colLabel =
                              !fileLabel && !urlLabel && typeof act.collection === "string" && act.collection.trim()
                                ? act.collection.trim()
                                : null;
                            const targetSuffix = hostLabel
                              ? hostLabel
                              : urlLabel
                                ? compactStepUrl(urlLabel)
                                : handleLabel ?? fileLabel ?? colLabel ?? null;
                            const detailText =
                              typeof act.detail === "string" && act.detail.trim() ? act.detail.trim() : null;
                            const sessionId =
                              typeof act.session_id === "string" && act.session_id.trim()
                                ? act.session_id.trim()
                                : null;
                            const isErrorStep =
                              actStatus !== "ok" &&
                              actStatus !== "completed" &&
                              actStatus !== "queued_approval";
                            return (
                              <div key={idx} className="space-y-0.5">
                                <div className="flex items-center justify-between gap-2">
                                  <span
                                    title={urlLabel || undefined}
                                    className="font-medium text-slate-800 truncate"
                                  >
                                    {friendly.label}
                                    {targetSuffix ? ` · ${targetSuffix}` : ""}
                                  </span>
                                  <div className="flex items-center gap-2 shrink-0">
                                    {sessionId && onOpenTerminal && (
                                      <button
                                        type="button"
                                        onClick={() => onOpenTerminal(msg.senderSlug, sessionId)}
                                        className="inline-flex items-center gap-1 text-sky-700 hover:underline font-medium cursor-pointer"
                                      >
                                        <Terminal className="w-3 h-3" />
                                        <span>View Terminal</span>
                                      </button>
                                    )}
                                    <span
                                      className={
                                        isErrorStep
                                          ? "text-rose-700 font-medium"
                                          : "text-slate-500"
                                      }
                                    >
                                      {friendly.outcome}
                                    </span>
                                  </div>
                                </div>
                                {detailText && isErrorStep && (
                                  <div className="text-[10.5px] text-rose-700 bg-rose-50 border border-rose-200 rounded-md px-2 py-1 break-words">
                                    {detailText}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}

                      <div className="text-[13.5px] text-slate-900 leading-relaxed">
                        <RichMarkdown
                          text={formatBotSystemText(
                            msg.metadata?.stopped_by_user
                              ? msg.text.replace(/\n*\*\(Stopped\)\*$/i, "").trim() || "(Stopped)"
                              : msg.text,
                          )}
                          catalog={mentionCatalog}
                        />
                      </div>

                      {/* Applied Self-Config Confirmation Pills */}
                      {appliedEntries.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {appliedEntries.map(([key]) => (
                            <span
                              key={key}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[10.5px] font-medium text-slate-700"
                            >
                              <Check className="w-3 h-3" />
                              Updated {key.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Quick Replies for Conversational Onboarding */}
                      {quickReplies.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {quickReplies.map((qr) => (
                            <button
                              key={qr}
                              type="button"
                              disabled={isWorking}
                              onClick={() => void submitText(qr)}
                              className="px-2.5 py-1 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 disabled:opacity-50 cursor-pointer"
                            >
                              {qr}
                            </button>
                          ))}
                        </div>
                      )}

                      {/* Pending Room Handoff Approval Gate */}
                      {pendingHandoff && room && onSendRoomMessage && (
                        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 flex items-center justify-between gap-2 flex-wrap max-w-lg">
                          <span className="text-xs text-slate-800">
                            Allow <strong>@{pendingHandoff.target_bot_name}</strong> to reply next in this Room?
                          </span>
                          <button
                            type="button"
                            disabled={approvingHandoffKey === msg.id || isWorking}
                            onClick={async () => {
                              setApprovingHandoffKey(msg.id);
                              try {
                                await onSendRoomMessage(room.slug, {
                                  text: "",
                                  approved_handoff_bot_slug: pendingHandoff.target_bot_slug,
                                });
                              } finally {
                                setApprovingHandoffKey(null);
                              }
                            }}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-slate-900 text-white text-[11px] font-medium hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                          >
                            {approvingHandoffKey === msg.id && (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            )}
                            <span>Let @{pendingHandoff.target_bot_name} reply</span>
                          </button>
                        </div>
                      )}

                      {/* Round-Trip Delegation Plan Card */}
                      {delegationPlan && (
                        <div className="rounded-2xl border border-slate-200 bg-white p-3.5 space-y-2.5 max-w-xl shadow-xs">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                              <ListChecks className="w-3.5 h-3.5 text-sky-600" />
                              <span>Delegation Plan: {delegationPlan.goal}</span>
                            </div>
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                                delegationPlan.status === "completed"
                                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                                  : "border-slate-200 bg-slate-50 text-slate-700"
                              }`}
                            >
                              {delegationPlan.status}
                            </span>
                          </div>
                          <div className="space-y-1.5">
                            {delegationPlan.steps.map((st, idx) => {
                              const stepBot = botBySlug.get(st.bot_slug);
                              return (
                                <div
                                  key={st.id || idx}
                                  className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs flex items-center justify-between gap-2"
                                >
                                  <div className="min-w-0 flex items-center gap-2">
                                    {stepBot && (
                                      <BotAvatar
                                        icon={stepBot.avatar_icon}
                                        color={stepBot.avatar_color}
                                        initials={stepBot.initials}
                                        size="xs"
                                      />
                                    )}
                                    <div className="min-w-0">
                                      <span className="font-semibold text-slate-900">
                                        {idx + 1}. {stepBot?.name ?? st.bot_slug}
                                      </span>{" "}
                                      <span className="text-slate-700">{st.task}</span>
                                    </div>
                                  </div>
                                  <span className="text-[10px] text-slate-500 shrink-0">
                                    Stage {st.parallel_group}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                          {delegationPlan.status === "proposed" && onExecutePlan && (
                            <div className="flex items-center justify-end">
                              <button
                                type="button"
                                disabled={executingPlanId === delegationPlan.id || isWorking}
                                onClick={async () => {
                                  setExecutingPlanId(delegationPlan.id);
                                  try {
                                    await onExecutePlan(delegationPlan);
                                  } finally {
                                    setExecutingPlanId(null);
                                  }
                                }}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                              >
                                {executingPlanId === delegationPlan.id && (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                )}
                                <span>Approve &amp; Run Plan</span>
                              </button>
                            </div>
                          )}
                        </div>
                      )}

                      {operatorQuestion && (
                        <div className="rounded-2xl border border-slate-200 bg-white p-3.5 space-y-2.5 max-w-xl shadow-xs">
                          <div className="flex items-center justify-between gap-2 flex-wrap">
                            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                              <ListChecks className="w-3.5 h-3.5 text-amber-600" />
                              <span>Decision Required</span>
                            </span>
                            {questionResolved ? (
                              <span className="px-2 py-0.5 rounded-full border border-emerald-200 bg-emerald-50 text-[10px] font-medium text-emerald-700">
                                {answeredChoiceLabel ? `Selected: ${answeredChoiceLabel}` : "Answered"}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-full border border-amber-200 bg-amber-50 text-[10px] font-medium text-amber-800">
                                Waiting for your choice
                              </span>
                            )}
                          </div>
                          {operatorQuestion.question.trim() !== msg.text.trim() && (
                            <p className="text-xs font-medium text-slate-900">
                              {operatorQuestion.question}
                            </p>
                          )}
                          {operatorQuestion.context &&
                            !msg.text.includes(operatorQuestion.context) && (
                              <p className="text-[11px] text-slate-600 leading-relaxed">
                                {operatorQuestion.context}
                              </p>
                            )}
                          {!questionResolved && operatorQuestion.options.length > 0 && (
                            <div className="flex items-center gap-2 flex-wrap pt-0.5">
                              {operatorQuestion.options.map((opt) => {
                                const btnToneClass =
                                  opt.tone === "primary"
                                    ? "bg-slate-900 text-white hover:bg-slate-800"
                                    : opt.tone === "danger"
                                      ? "border border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100"
                                      : "border border-slate-200 bg-slate-50 text-slate-800 hover:bg-slate-100";
                                return (
                                  <button
                                    key={opt.id}
                                    type="button"
                                    disabled={isWorking}
                                    onClick={() => {
                                      setAnsweredQuestions((prev) => ({
                                        ...prev,
                                        [msg.id]: opt.label,
                                      }));
                                      void submitText(opt.reply);
                                    }}
                                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium disabled:opacity-50 cursor-pointer transition-colors ${btnToneClass}`}
                                  >
                                    <span>{opt.label}</span>
                                  </button>
                                );
                              })}
                            </div>
                          )}
                          {!questionResolved && operatorQuestion.allow_custom_reply !== false && (
                            <p className="text-[11px] text-slate-500">
                              Or reply below with custom instructions.
                            </p>
                          )}
                        </div>
                      )}

                      {msg.metadata?.run_checkpoint && (
                        <div className="rounded-xl border border-sky-200 bg-sky-50 px-3.5 py-2.5 flex items-center justify-between gap-3 flex-wrap max-w-xl">
                          <span className="text-xs text-slate-800">
                            Paused after <strong>{msg.metadata.run_checkpoint.steps_completed}</strong>{" "}
                            step{msg.metadata.run_checkpoint.steps_completed === 1 ? "" : "s"} so you can review progress.
                          </span>
                          <button
                            type="button"
                            disabled={isWorking}
                            onClick={() =>
                              void submitText(
                                msg.metadata?.run_checkpoint?.continue_prompt ||
                                  "Continue from where you left off and complete the remaining steps.",
                              )
                            }
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium hover:bg-slate-800 disabled:opacity-50 cursor-pointer shrink-0"
                          >
                            <ArrowRight className="w-3 h-3" />
                            <span>
                              Continue (+{msg.metadata.run_checkpoint.next_batch_steps} steps)
                            </span>
                          </button>
                        </div>
                      )}

                      {/* Proactive Skill + Routine Habit Proposal Card */}
                      {habitProposal && onUpdateBot && (
                        <div className="rounded-2xl border border-slate-200 bg-white p-3.5 space-y-2.5 max-w-xl shadow-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
                              <Sparkles className="w-3.5 h-3.5 text-amber-600" />
                              Save as Skill &amp; Named Routine?
                            </span>
                            {activatedHabits[msg.id] && (
                              <span className="px-2 py-0.5 rounded-full border border-emerald-200 bg-emerald-50 text-[10px] font-medium text-emerald-700">
                                Activated
                              </span>
                            )}
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                            <input
                              type="text"
                              value={
                                habitDrafts[msg.id]?.label ?? habitProposal.suggested_routine_label
                              }
                              onChange={(e) =>
                                setHabitDrafts((prev) => ({
                                  ...prev,
                                  [msg.id]: {
                                    label: e.target.value,
                                    schedule:
                                      prev[msg.id]?.schedule ?? habitProposal.suggested_schedule,
                                    timezone: prev[msg.id]?.timezone ?? browserTz,
                                  },
                                }))
                              }
                              placeholder="Routine name"
                              className="rounded-lg border border-slate-200 px-2.5 py-1.5 text-[11px]"
                            />
                            <input
                              type="text"
                              value={
                                habitDrafts[msg.id]?.schedule ?? habitProposal.suggested_schedule
                              }
                              onChange={(e) =>
                                setHabitDrafts((prev) => ({
                                  ...prev,
                                  [msg.id]: {
                                    label:
                                      prev[msg.id]?.label ??
                                      habitProposal.suggested_routine_label,
                                    schedule: e.target.value,
                                    timezone: prev[msg.id]?.timezone ?? browserTz,
                                  },
                                }))
                              }
                              placeholder="Every weekday at 09:00"
                              className="rounded-lg border border-slate-200 px-2.5 py-1.5 text-[11px]"
                            />
                            <input
                              type="text"
                              value={habitDrafts[msg.id]?.timezone ?? browserTz}
                              onChange={(e) =>
                                setHabitDrafts((prev) => ({
                                  ...prev,
                                  [msg.id]: {
                                    label:
                                      prev[msg.id]?.label ??
                                      habitProposal.suggested_routine_label,
                                    schedule:
                                      prev[msg.id]?.schedule ?? habitProposal.suggested_schedule,
                                    timezone: e.target.value,
                                  },
                                }))
                              }
                              placeholder="Timezone (e.g. America/New_York)"
                              className="rounded-lg border border-slate-200 px-2.5 py-1.5 text-[11px]"
                            />
                          </div>
                          {!activatedHabits[msg.id] && (
                            <div className="flex justify-end">
                              <button
                                type="button"
                                disabled={savingHabitId === msg.id}
                                onClick={() => void activateHabitProposal(msg, habitProposal)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
                              >
                                {savingHabitId === msg.id && (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                )}
                                <span>Save Skill &amp; Activate Routine</span>
                              </button>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Workspace Attachments on Bot Reply */}
                      {msgAttachments.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          {msgAttachments.map((att) =>
                            att.is_image ? (
                              <div
                                key={att.id}
                                className="block rounded-xl border border-slate-200 bg-white overflow-hidden max-w-xs shadow-xs"
                              >
                                <a
                                  href={api.workspaceFileContentUrl(att.id)}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="block"
                                >
                                  <img
                                    src={api.workspaceFileContentUrl(att.id)}
                                    alt={att.filename}
                                    className="max-h-40 object-cover"
                                  />
                                </a>
                                <div className="px-2.5 py-1 flex items-center justify-between gap-2 text-[11px] text-slate-600 border-t border-slate-200">
                                  <span className="truncate">{att.filename}</span>
                                  <a
                                    href={api.workspaceFileContentUrl(att.id, { download: true })}
                                    download={att.filename}
                                    title={`Download ${att.filename}`}
                                    aria-label={`Download ${att.filename}`}
                                    className="p-0.5 text-slate-500 hover:text-slate-900 shrink-0"
                                  >
                                    <Download className="w-3 h-3" />
                                  </a>
                                </div>
                              </div>
                            ) : (
                              <span
                                key={att.id}
                                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] text-slate-700"
                              >
                                <a
                                  href={api.workspaceFileContentUrl(att.id)}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center gap-1.5 min-w-0 hover:underline"
                                >
                                  <Paperclip className="w-3 h-3 shrink-0" />
                                  <span className="truncate max-w-[200px]">{att.filename}</span>
                                </a>
                                <a
                                  href={api.workspaceFileContentUrl(att.id, { download: true })}
                                  download={att.filename}
                                  title={`Download ${att.filename}`}
                                  aria-label={`Download ${att.filename}`}
                                  className="p-0.5 text-slate-500 hover:text-slate-900 shrink-0"
                                >
                                  <Download className="w-3 h-3" />
                                </a>
                              </span>
                            ),
                          )}
                        </div>
                      )}

                      {/* Inline Approval Cards (Unified SSH Batch Cards + Individual Cards) */}
                      {(() => {
                        const { batches, singles } = partitionSSHApprovalBatches(linkedApprovals, {
                          scopeByBot: false,
                        });
                        const remainingPending = singles.filter((a) => a.status === "pending");
                        const pendingBatchCount = batches.filter((b) =>
                          b.items.some((a) => a.status === "pending"),
                        ).length;
                        const allPendingApprovals = linkedApprovals.filter(
                          (a) => a.status === "pending",
                        );
                        const allTrustableApprovals = allPendingApprovals.filter(
                          (a) =>
                            a.action_type === "ssh_exec" &&
                            extractSuggestedTrustPrefixes(a).length > 0,
                        );
                        const showMessageBatchBar =
                          Boolean(onBatchResolveApprovals) &&
                          allPendingApprovals.length >= 2 &&
                          (pendingBatchCount > 1 ||
                            (pendingBatchCount === 1 && remainingPending.length > 0) ||
                            (pendingBatchCount === 0 && remainingPending.length >= 2));
                        const batchBusy = busyBatchMsgId === msg.id;

                        return (
                          <>
                            {showMessageBatchBar && onBatchResolveApprovals && (
                              <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 flex items-center justify-between gap-2 flex-wrap">
                                <span className="text-[11px] font-medium text-amber-900">
                                  {allPendingApprovals.length} actions awaiting approval together
                                </span>
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <button
                                    type="button"
                                    disabled={batchBusy || busyApprovalId !== null}
                                    onClick={async () => {
                                      setBusyBatchMsgId(msg.id);
                                      try {
                                        await onBatchResolveApprovals(
                                          allPendingApprovals.map((a) => a.id),
                                          "approve",
                                        );
                                      } finally {
                                        setBusyBatchMsgId(null);
                                      }
                                    }}
                                    className="inline-flex items-center gap-1 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-2.5 py-1 rounded-lg text-[11px] font-medium cursor-pointer"
                                  >
                                    <Check className="w-3 h-3" />
                                    <span>
                                      {batchBusy
                                        ? "Running..."
                                        : `Approve All (${allPendingApprovals.length})`}
                                    </span>
                                  </button>
                                  {allTrustableApprovals.length > 0 && (
                                    <button
                                      type="button"
                                      disabled={batchBusy || busyApprovalId !== null}
                                      onClick={async () => {
                                        setBusyBatchMsgId(msg.id);
                                        try {
                                          await onBatchResolveApprovals(
                                            allPendingApprovals.map((a) => a.id),
                                            "approve",
                                            { trust_command: true },
                                          );
                                        } finally {
                                          setBusyBatchMsgId(null);
                                        }
                                      }}
                                      className="inline-flex items-center gap-1 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 px-2.5 py-1 rounded-lg text-[11px] font-medium cursor-pointer"
                                    >
                                      <ShieldCheck className="w-3 h-3" />
                                      <span>Approve All &amp; Always Allow</span>
                                    </button>
                                  )}
                                  <button
                                    type="button"
                                    disabled={batchBusy || busyApprovalId !== null}
                                    onClick={async () => {
                                      setBusyBatchMsgId(msg.id);
                                      try {
                                        await onBatchResolveApprovals(
                                          allPendingApprovals.map((a) => a.id),
                                          "reject",
                                        );
                                      } finally {
                                        setBusyBatchMsgId(null);
                                      }
                                    }}
                                    className="px-2.5 py-1 rounded-lg border border-rose-200 text-rose-700 bg-white text-[11px] font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                                  >
                                    Reject All
                                  </button>
                                </div>
                              </div>
                            )}

                            {batches.map((batch) => {
                              const batchKey = `${msg.id}:${batch.key}`;
                              const batchIds = batch.items.map((a) => a.id);
                              const isExpanded = Boolean(expandedBatchKeys[batchKey]);
                              const formattedCmd = formatShellCommandForDisplay(batch.command);
                              const copyKey = `batch-${batchKey}`;
                              const isCopied = copiedApprovalKey === copyKey;
                              const visiblePrefixes = batch.trustPrefixes.slice(0, 6);
                              const extraPrefixCount = Math.max(
                                0,
                                batch.trustPrefixes.length - visiblePrefixes.length,
                              );

                              return (
                                <div
                                  key={batchKey}
                                  className="rounded-2xl border border-amber-200 bg-amber-50 p-3.5 space-y-3"
                                >
                                  <div className="flex items-center justify-between gap-2 flex-wrap">
                                    <div className="flex items-center gap-2 flex-wrap min-w-0">
                                      <Terminal className="w-3.5 h-3.5 text-slate-700 shrink-0" />
                                      <span className="text-xs font-semibold text-slate-900">
                                        Run SSH command across {batch.items.length} hosts
                                      </span>
                                      <span className="px-2 py-0.5 rounded-md border border-slate-200 bg-white text-[10.5px] font-mono text-slate-700">
                                        @{batch.vaultSlug}
                                      </span>
                                    </div>
                                    <span className="px-2 py-0.5 rounded-full text-[10px] font-medium border bg-amber-100 border-amber-300 text-amber-900 shrink-0">
                                      Waiting for review
                                    </span>
                                  </div>

                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    {batch.items.map((it) => {
                                      const hostLabel = extractApprovalHost(it) || "target host";
                                      return (
                                        <span
                                          key={it.id}
                                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-slate-200 bg-white text-[11px] font-mono text-slate-800"
                                        >
                                          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                                          <span>{hostLabel}</span>
                                        </span>
                                      );
                                    })}
                                  </div>

                                  <div className="argo-code-block rounded-xl border overflow-hidden">
                                    <div className="argo-code-block-bar px-3 py-1.5 border-b flex items-center justify-between gap-2 text-[10.5px]">
                                      <span className="font-medium">Shell command</span>
                                      <button
                                        type="button"
                                        onClick={() => copyApprovalCommand(copyKey, batch.command)}
                                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-700 transition-colors cursor-pointer"
                                      >
                                        {isCopied ? (
                                          <>
                                            <Check className="w-3 h-3" />
                                            <span>Copied</span>
                                          </>
                                        ) : (
                                          <>
                                            <Copy className="w-3 h-3" />
                                            <span>Copy</span>
                                          </>
                                        )}
                                      </button>
                                    </div>
                                    <pre className="p-3 text-[11.5px] leading-relaxed font-mono whitespace-pre-wrap break-words max-h-56 overflow-y-auto custom-scroll m-0">
                                      {formattedCmd}
                                    </pre>
                                  </div>

                                  {batch.trustPrefixes.length > 0 && (
                                    <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-slate-600">
                                      <span className="font-medium text-slate-700">
                                        Always Allow will trust on @{batch.vaultSlug}:
                                      </span>
                                      {visiblePrefixes.map((pref) => (
                                        <code
                                          key={pref}
                                          className="px-1.5 py-0.5 rounded border border-slate-300 bg-slate-100 text-[10.5px] font-mono text-slate-800"
                                        >
                                          {pref}
                                        </code>
                                      ))}
                                      {extraPrefixCount > 0 && (
                                        <span className="text-[10.5px] text-slate-500">
                                          +{extraPrefixCount} more
                                        </span>
                                      )}
                                    </div>
                                  )}

                                  {(onApproveItem || onBatchResolveApprovals || onRejectItem) && (
                                    <div className="flex items-center justify-between gap-2 flex-wrap">
                                      <div className="flex items-center gap-2 flex-wrap">
                                        {onBatchResolveApprovals && (
                                          <>
                                            <button
                                              type="button"
                                              disabled={batchBusy || busyApprovalId !== null}
                                              onClick={async () => {
                                                setBusyBatchMsgId(msg.id);
                                                try {
                                                  await onBatchResolveApprovals(batchIds, "approve");
                                                } finally {
                                                  setBusyBatchMsgId(null);
                                                }
                                              }}
                                              className="inline-flex items-center gap-1 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-[11px] font-medium cursor-pointer"
                                            >
                                              <Check className="w-3 h-3" />
                                              <span>
                                                {batchBusy
                                                  ? "Running..."
                                                  : `Approve All (${batch.items.length})`}
                                              </span>
                                            </button>
                                            {batch.trustPrefixes.length > 0 && (
                                              <button
                                                type="button"
                                                disabled={batchBusy || busyApprovalId !== null}
                                                title={`Approve, run now, and always allow on @${batch.vaultSlug}: ${batch.trustPrefixes.join(", ")}`}
                                                onClick={async () => {
                                                  setBusyBatchMsgId(msg.id);
                                                  try {
                                                    await onBatchResolveApprovals(
                                                      batchIds,
                                                      "approve",
                                                      { trust_command: true },
                                                    );
                                                  } finally {
                                                    setBusyBatchMsgId(null);
                                                  }
                                                }}
                                                className="inline-flex items-center gap-1 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 px-3 py-1.5 rounded-lg text-[11px] font-medium cursor-pointer"
                                              >
                                                <ShieldCheck className="w-3 h-3" />
                                                <span>Approve All &amp; Always Allow</span>
                                              </button>
                                            )}
                                            <button
                                              type="button"
                                              disabled={batchBusy || busyApprovalId !== null}
                                              onClick={async () => {
                                                setBusyBatchMsgId(msg.id);
                                                try {
                                                  await onBatchResolveApprovals(batchIds, "reject");
                                                } finally {
                                                  setBusyBatchMsgId(null);
                                                }
                                              }}
                                              className="px-3 py-1.5 rounded-lg border border-rose-200 text-rose-700 bg-white text-[11px] font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                                            >
                                              Reject All
                                            </button>
                                          </>
                                        )}
                                      </div>

                                      <button
                                        type="button"
                                        onClick={() =>
                                          setExpandedBatchKeys((prev) => ({
                                            ...prev,
                                            [batchKey]: !prev[batchKey],
                                          }))
                                        }
                                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                                      >
                                        {isExpanded ? (
                                          <ChevronDown className="w-3.5 h-3.5" />
                                        ) : (
                                          <ChevronRight className="w-3.5 h-3.5" />
                                        )}
                                        <span>Per-host controls ({batch.items.length})</span>
                                      </button>
                                    </div>
                                  )}

                                  {isExpanded && (
                                    <div className="rounded-xl border border-slate-200 bg-white divide-y divide-slate-100">
                                      {batch.items.map((it) => {
                                        const hostLabel = extractApprovalHost(it) || "target host";
                                        const rowBusy =
                                          busyApprovalId === it.id || busyBatchMsgId === msg.id;
                                        const itTrust = extractSuggestedTrustPrefixes(it);
                                        return (
                                          <div
                                            key={it.id}
                                            className="px-3 py-2 flex items-center justify-between gap-2 flex-wrap"
                                          >
                                            <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-semibold text-slate-800">
                                              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                                              <span>{hostLabel}</span>
                                            </span>
                                            <div className="flex items-center gap-1.5 flex-wrap">
                                              {onApproveItem && (
                                                <button
                                                  type="button"
                                                  disabled={rowBusy}
                                                  onClick={async () => {
                                                    setBusyApprovalId(it.id);
                                                    try {
                                                      await onApproveItem(it.id);
                                                    } finally {
                                                      setBusyApprovalId(null);
                                                    }
                                                  }}
                                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-[10.5px] font-medium cursor-pointer"
                                                >
                                                  <Check className="w-3 h-3" />
                                                  <span>Approve</span>
                                                </button>
                                              )}
                                              {onApproveItem && itTrust.length > 0 && (
                                                <button
                                                  type="button"
                                                  disabled={rowBusy}
                                                  onClick={async () => {
                                                    setBusyApprovalId(it.id);
                                                    try {
                                                      await onApproveItem(it.id, {
                                                        trust_command: true,
                                                      });
                                                    } finally {
                                                      setBusyApprovalId(null);
                                                    }
                                                  }}
                                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 text-[10.5px] font-medium cursor-pointer"
                                                >
                                                  <ShieldCheck className="w-3 h-3" />
                                                  <span>Always Allow</span>
                                                </button>
                                              )}
                                              {onEditApprovalItem && (
                                                <button
                                                  type="button"
                                                  disabled={rowBusy}
                                                  onClick={() => onEditApprovalItem(it)}
                                                  className="px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 text-[10.5px] font-medium disabled:opacity-50 cursor-pointer"
                                                >
                                                  Edit
                                                </button>
                                              )}
                                              {onRejectItem && (
                                                <button
                                                  type="button"
                                                  disabled={rowBusy}
                                                  onClick={async () => {
                                                    setBusyApprovalId(it.id);
                                                    try {
                                                      await onRejectItem(it.id);
                                                    } finally {
                                                      setBusyApprovalId(null);
                                                    }
                                                  }}
                                                  className="px-2.5 py-1 rounded-md border border-rose-200 text-rose-700 bg-white hover:bg-rose-50 text-[10.5px] font-medium disabled:opacity-50 cursor-pointer"
                                                >
                                                  Reject
                                                </button>
                                              )}
                                            </div>
                                          </div>
                                        );
                                      })}
                                    </div>
                                  )}
                                </div>
                              );
                            })}

                            {singles.map((item) => {
                              const isWorkspaceAction = item.target_account_slug === "argo_workspace";
                              const isSshAction =
                                item.action_type === "ssh_exec" || item.action_type === "ssh_input";
                              const origText = String(item.payload.text ?? "");
                              const editedText = item.edited_payload?.text
                                ? String(item.edited_payload.text)
                                : null;
                              const hasDiff = Boolean(
                                editedText && origText && editedText !== origText,
                              );
                              const suggestedTrust = extractSuggestedTrustPrefixes(item);
                              const visiblePrefixes = suggestedTrust.slice(0, 6);
                              const extraPrefixCount = Math.max(
                                0,
                                suggestedTrust.length - visiblePrefixes.length,
                              );
                              const cardBusy =
                                busyApprovalId === item.id || busyBatchMsgId === msg.id;
                              const copyKey = `single-${item.id}`;
                              const isCopied = copiedApprovalKey === copyKey;

                              return (
                                <div
                                  key={item.id}
                                  className="rounded-2xl border border-amber-200 bg-amber-50 p-3.5 space-y-2.5"
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 min-w-0">
                                      {isSshAction && (
                                        <Terminal className="w-3.5 h-3.5 text-slate-700 shrink-0" />
                                      )}
                                      <span className="text-xs font-semibold text-slate-900 truncate">
                                        {item.payload.title ??
                                          (isWorkspaceAction
                                            ? "Configuration update awaiting approval"
                                            : "Draft ready for review")}
                                      </span>
                                    </div>
                                    <span
                                      className={`px-2 py-0.5 rounded-full text-[10px] font-medium border shrink-0 ${
                                        item.status === "pending"
                                          ? "bg-amber-100 border-amber-300 text-amber-900"
                                          : "bg-emerald-50 border-emerald-200 text-emerald-700"
                                      }`}
                                    >
                                      {item.status === "pending" ? "Waiting for review" : item.status}
                                    </span>
                                  </div>

                                  {hasDiff && editedText ? (
                                    <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs text-slate-800 whitespace-pre-wrap">
                                      {computeWordDiff(origText, editedText).map((tok, i) =>
                                        tok.type === "same" ? (
                                          <span key={i}>{tok.text}</span>
                                        ) : tok.type === "add" ? (
                                          <span
                                            key={i}
                                            className="bg-emerald-100 text-emerald-900 px-0.5 rounded"
                                          >
                                            {tok.text}
                                          </span>
                                        ) : (
                                          <span
                                            key={i}
                                            className="bg-rose-100 text-rose-800 line-through px-0.5 rounded"
                                          >
                                            {tok.text}
                                          </span>
                                        ),
                                      )}
                                    </div>
                                  ) : isSshAction ? (
                                    (() => {
                                      const sshCmdText =
                                        origText ||
                                        (item.action_type === "ssh_exec" &&
                                        typeof item.payload.command === "string"
                                          ? item.payload.command.trim()
                                          : "");
                                      const sshPromptLine =
                                        typeof item.payload.prompt_line === "string"
                                          ? item.payload.prompt_line.trim()
                                          : "";
                                      const sshExcerpt =
                                        typeof item.payload.screen_excerpt === "string"
                                          ? item.payload.screen_excerpt.trim()
                                          : "";
                                      return (
                                        <div className="space-y-2">
                                          {sshExcerpt && (
                                            <pre className="argo-ssh-terminal rounded-lg border border-slate-800 bg-slate-900 text-slate-100 p-2.5 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap max-h-44 overflow-y-auto custom-scroll m-0">
                                              {sshExcerpt}
                                            </pre>
                                          )}
                                          {sshPromptLine && item.action_type === "ssh_input" && (
                                            <div className="rounded-lg border border-amber-200 bg-white px-2.5 py-1.5 text-[11px] font-mono text-slate-800 break-words">
                                              Prompt: {sshPromptLine}
                                            </div>
                                          )}
                                          <div className="argo-code-block rounded-xl border overflow-hidden">
                                            <div className="argo-code-block-bar px-3 py-1.5 border-b flex items-center justify-between gap-2 text-[10.5px]">
                                              <span className="font-medium">
                                                {item.action_type === "ssh_input"
                                                  ? "Terminal input"
                                                  : "Shell command"}
                                              </span>
                                              {sshCmdText && (
                                                <button
                                                  type="button"
                                                  onClick={() =>
                                                    copyApprovalCommand(copyKey, sshCmdText)
                                                  }
                                                  className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded hover:bg-slate-700 transition-colors cursor-pointer"
                                                >
                                                  {isCopied ? (
                                                    <>
                                                      <Check className="w-3 h-3" />
                                                      <span>Copied</span>
                                                    </>
                                                  ) : (
                                                    <>
                                                      <Copy className="w-3 h-3" />
                                                      <span>Copy</span>
                                                    </>
                                                  )}
                                                </button>
                                              )}
                                            </div>
                                            <pre className="p-3 text-[11.5px] leading-relaxed font-mono whitespace-pre-wrap break-words max-h-56 overflow-y-auto custom-scroll m-0">
                                              {sshCmdText
                                                ? formatShellCommandForDisplay(sshCmdText)
                                                : "(Empty input / Enter)"}
                                            </pre>
                                          </div>
                                        </div>
                                      );
                                    })()
                                  ) : (
                                    <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs text-slate-800 space-y-2">
                                      <RichMarkdown
                                        text={origText || JSON.stringify(item.payload)}
                                        catalog={mentionCatalog}
                                      />
                                    </div>
                                  )}

                                  {item.payload.execution_result?.screen_text && (
                                    <pre className="argo-ssh-terminal rounded-lg border border-slate-800 bg-slate-900 text-slate-100 p-2.5 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap max-h-52 overflow-y-auto custom-scroll">
                                      {item.payload.execution_result.screen_text}
                                    </pre>
                                  )}

                                  {item.status === "pending" &&
                                    item.action_type === "ssh_exec" &&
                                    suggestedTrust.length > 0 && (
                                      <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-slate-600">
                                        <span className="font-medium text-slate-700">
                                          Always Allow will trust on @{item.target_account_slug}:
                                        </span>
                                        {visiblePrefixes.map((pref) => (
                                          <code
                                            key={pref}
                                            className="px-1.5 py-0.5 rounded border border-slate-300 bg-slate-100 text-[10.5px] font-mono text-slate-800"
                                          >
                                            {pref}
                                          </code>
                                        ))}
                                        {extraPrefixCount > 0 && (
                                          <span className="text-[10.5px] text-slate-500">
                                            +{extraPrefixCount} more
                                          </span>
                                        )}
                                      </div>
                                    )}

                                  {item.status === "pending" && (onApproveItem || onRejectItem) && (
                                    <div className="flex items-center gap-2 flex-wrap">
                                      {onApproveItem && (
                                        <button
                                          type="button"
                                          disabled={cardBusy}
                                          onClick={async () => {
                                            setBusyApprovalId(item.id);
                                            try {
                                              await onApproveItem(item.id);
                                            } finally {
                                              setBusyApprovalId(null);
                                            }
                                          }}
                                          className="inline-flex items-center justify-center gap-1.5 flex-1 md:flex-none min-h-[42px] md:min-h-0 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3.5 md:px-3 py-2 md:py-1.5 rounded-xl md:rounded-lg text-xs md:text-[11px] font-medium cursor-pointer"
                                        >
                                          <Check className="w-3.5 h-3.5 md:w-3 md:h-3" />
                                          {isWorkspaceAction
                                            ? "Approve & Apply"
                                            : isSshAction
                                              ? "Approve & Run"
                                              : "Approve & Send"}
                                        </button>
                                      )}
                                      {onApproveItem &&
                                        item.action_type === "ssh_exec" &&
                                        suggestedTrust.length > 0 && (
                                          <button
                                            type="button"
                                            disabled={cardBusy}
                                            title={`Approve, run now, and always allow on @${item.target_account_slug}: ${suggestedTrust.join(", ")}`}
                                            onClick={async () => {
                                              setBusyApprovalId(item.id);
                                              try {
                                                await onApproveItem(item.id, {
                                                  trust_command: true,
                                                });
                                              } finally {
                                                setBusyApprovalId(null);
                                              }
                                            }}
                                            className="inline-flex items-center justify-center gap-1.5 min-h-[42px] md:min-h-0 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 px-3.5 md:px-3 py-2 md:py-1.5 rounded-xl md:rounded-lg text-xs md:text-[11px] font-medium cursor-pointer"
                                          >
                                            <ShieldCheck className="w-3.5 h-3.5 md:w-3 md:h-3" />
                                            <span>
                                              Always Allow on @{item.target_account_slug}
                                            </span>
                                          </button>
                                        )}
                                      {onEditApprovalItem && !isWorkspaceAction && (
                                        <button
                                          type="button"
                                          disabled={cardBusy}
                                          onClick={() => onEditApprovalItem(item)}
                                          className="min-h-[42px] md:min-h-0 px-3.5 md:px-3 py-2 md:py-1.5 rounded-xl md:rounded-lg border border-slate-200 bg-white text-xs md:text-[11px] font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                                        >
                                          Edit
                                        </button>
                                      )}
                                      {onRejectItem && (
                                        <button
                                          type="button"
                                          disabled={cardBusy}
                                          onClick={async () => {
                                            setBusyApprovalId(item.id);
                                            try {
                                              await onRejectItem(item.id);
                                            } finally {
                                              setBusyApprovalId(null);
                                            }
                                          }}
                                          className="flex-1 md:flex-none min-h-[42px] md:min-h-0 px-3.5 md:px-3 py-2 md:py-1.5 rounded-xl md:rounded-lg border border-rose-200 text-rose-700 bg-white text-xs md:text-[11px] font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                                        >
                                          Reject
                                        </button>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </>
                        );
                      })()}

                      {/* Inline Page Pills -> Dock beside chat */}
                      {linkedPages.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2">
                          {linkedPages.map((pg, i) => (
                            <div
                              key={`${pg.slug}-${i}`}
                              className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 pl-3 pr-2 py-1 shadow-xs"
                            >
                              <button
                                type="button"
                                onClick={() => onOpenPage?.(pg.slug, true)}
                                className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900 hover:text-indigo-700 cursor-pointer"
                              >
                                <FileText className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                                <span>{pg.title}</span>
                              </button>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Inline Desktop Screenshot Cards */}
                      {speakerBot &&
                        screenshotUrls.map((rawShotUrl, idx) => {
                          const shotKey = `${msg.id}-${idx}`;
                          if (failedShotKeys[shotKey]) {
                            return null;
                          }
                          const isImmutableSnapshot = rawShotUrl.includes("/snapshots/");
                          const thumbUrl = isImmutableSnapshot
                            ? rawShotUrl
                            : `${rawShotUrl}${rawShotUrl.includes("?") ? "&" : "?"}t=${encodeURIComponent(msg.createdAt)}`;
                          const downloadUrl = isImmutableSnapshot
                            ? `${rawShotUrl}${rawShotUrl.includes("?") ? "&" : "?"}download=true`
                            : api.desktopScreenshotUrl(speakerBot.slug, {
                                refresh: false,
                                download: true,
                              });
                          return (
                            <div
                              key={shotKey}
                              className="rounded-2xl border border-slate-200 bg-white overflow-hidden max-w-md shadow-xs"
                            >
                              <div className="px-3 py-1.5 border-b border-slate-100 flex items-center justify-between gap-2 text-[11px]">
                                <span className="inline-flex items-center gap-1.5 font-medium text-slate-700">
                                  <Camera className="w-3.5 h-3.5 text-sky-600" />
                                  Virtual Desktop Snapshot
                                </span>
                                <div className="flex items-center gap-2">
                                  <a
                                    href={downloadUrl}
                                    download={`${speakerBot.slug}-desktop.png`}
                                    className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-900"
                                  >
                                    <Download className="w-3 h-3" />
                                    <span>Save</span>
                                  </a>
                                  {onOpenSelkies && (
                                    <button
                                      type="button"
                                      onClick={() => onOpenSelkies(speakerBot)}
                                      className="text-sky-700 hover:text-sky-900 font-medium cursor-pointer"
                                    >
                                      Open Desktop
                                    </button>
                                  )}
                                </div>
                              </div>
                              <img
                                src={thumbUrl}
                                alt={`Virtual Desktop snapshot for ${speakerBot.name}`}
                                onError={() =>
                                  setFailedShotKeys((prev) => ({ ...prev, [shotKey]: true }))
                                }
                                onClick={() => onOpenSelkies?.(speakerBot)}
                                className={`w-full aspect-video object-cover bg-slate-950 ${onOpenSelkies ? "cursor-pointer" : ""}`}
                              />
                            </div>
                          );
                        })}

                      {/* Inline Desktop Takeover Cards */}
                      {speakerBot &&
                        takeoverAlerts.map((tk, i) => (
                          <div
                            key={i}
                            className="rounded-2xl border border-rose-200 bg-rose-50 p-3 flex items-center justify-between gap-2 flex-wrap"
                          >
                            <div className="flex items-center gap-2">
                              <Monitor className="w-4 h-4 text-rose-600" />
                              <div className="text-xs text-rose-900">
                                <span className="font-semibold">Sign-in or security check needed:</span>{" "}
                                {String(tk.detail ?? "Open the virtual desktop to continue.")}
                              </div>
                            </div>
                            {onOpenSelkies && (
                              <button
                                type="button"
                                onClick={() => onOpenSelkies(speakerBot)}
                                className="px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer"
                              >
                                Open Live Desktop
                              </button>
                            )}
                          </div>
                        ))}

                      {/* Reaction Pills */}
                      {reactionEntries.length > 0 && (
                        <div className="flex items-center gap-1 flex-wrap">
                          {reactionEntries.map(([emoji, actors]) => (
                            <button
                              key={emoji}
                              type="button"
                              onClick={() =>
                                void onToggleReaction?.(msg.id, emoji, targetCollection)
                              }
                              className="px-2 py-0.5 rounded-full border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-100 cursor-pointer"
                            >
                              {emoji} {actors.length}
                            </button>
                          ))}
                        </div>
                      )}

                      <div
                        className={`relative flex items-center gap-1 md:gap-0.5 text-slate-400 transition-opacity ${
                          footerVisible
                            ? "opacity-100"
                            : "opacity-100 md:opacity-0 md:group-hover:opacity-100 md:focus-within:opacity-100"
                        }`}
                      >
                        {onToggleReaction && (
                          <div className="relative" data-argo-popover="react">
                            <button
                              type="button"
                              title="Add reaction"
                              onClick={() => {
                                setMoreMenuMsgId(null);
                                setReactMenuMsgId((prev) => (prev === msg.id ? null : msg.id));
                              }}
                              className="p-1 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200 cursor-pointer"
                            >
                              <SmilePlus className="w-3.5 h-3.5" />
                            </button>
                            {reactMenuMsgId === msg.id && (
                              <div className="absolute bottom-full left-0 mb-1 flex items-center gap-0.5 rounded-full border border-slate-200 bg-white shadow-md px-1.5 py-0.5 z-20">
                                {QUICK_REACTIONS.map((emoji) => (
                                  <button
                                    key={emoji}
                                    type="button"
                                    onClick={() => {
                                      setReactMenuMsgId(null);
                                      void onToggleReaction(msg.id, emoji, targetCollection);
                                    }}
                                    className="px-1.5 py-0.5 rounded-full hover:bg-slate-100 cursor-pointer text-xs"
                                    title={`React ${emoji}`}
                                  >
                                    {emoji}
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                        <button
                          type="button"
                          title="Reply"
                          onClick={() => {
                            setReplyTo({
                              id: msg.id,
                              sender: "bot",
                              sender_slug: msg.senderSlug,
                              sender_name: speakerName,
                              excerpt: msg.text.slice(0, 140),
                            });
                            textareaRef.current?.focus();
                          }}
                          className="p-1 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200 cursor-pointer"
                        >
                          <CornerUpLeft className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          title={copiedMsgId === msg.id ? "Copied" : "Copy"}
                          onClick={() => copyMessage(msg)}
                          className="p-1 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200 cursor-pointer"
                        >
                          {copiedMsgId === msg.id ? (
                            <Check className="w-3.5 h-3.5 text-slate-800" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        {(onSaveSkill || onUpdateBot) && (
                          <div className="relative" data-argo-popover="more">
                            <button
                              type="button"
                              title="More actions"
                              onClick={() => {
                                setReactMenuMsgId(null);
                                setMoreMenuMsgId((prev) => (prev === msg.id ? null : msg.id));
                              }}
                              className="p-1 rounded-md text-slate-400 hover:text-slate-800 hover:bg-slate-200 cursor-pointer"
                            >
                              <MoreHorizontal className="w-3.5 h-3.5" />
                            </button>
                            {moreMenuMsgId === msg.id && (
                              <div className="absolute bottom-full left-0 mb-1 w-44 rounded-xl border border-slate-200 bg-white shadow-lg p-1 z-20 text-[11.5px]">
                                {onSaveSkill && (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setMoreMenuMsgId(null);
                                      setSkillDraftMsgId((prev) =>
                                        prev === msg.id ? null : msg.id,
                                      );
                                      setSkillNameInput("");
                                    }}
                                    className="w-full text-left px-2.5 py-1.5 rounded-lg text-slate-700 hover:bg-slate-100 flex items-center gap-2 cursor-pointer"
                                  >
                                    <BookmarkPlus className="w-3.5 h-3.5 text-slate-500" />
                                    <span>Save as Skill</span>
                                  </button>
                                )}
                                {onUpdateBot && (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setMoreMenuMsgId(null);
                                      setAutomateMsgId((prev) =>
                                        prev === msg.id ? null : msg.id,
                                      );
                                    }}
                                    className="w-full text-left px-2.5 py-1.5 rounded-lg text-slate-700 hover:bg-slate-100 flex items-center gap-2 cursor-pointer"
                                  >
                                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                                    <span>Automate as Routine</span>
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>

                      {skillDraftMsgId === msg.id && (
                        <div className="flex items-center gap-2 pt-1 max-w-md">
                          <input
                            type="text"
                            value={skillNameInput}
                            onChange={(e) => setSkillNameInput(e.target.value)}
                            placeholder="Skill name (e.g. Morning Release Check)..."
                            className="flex-1 rounded-lg border border-slate-200 px-2.5 py-1 text-[11px]"
                          />
                          <button
                            type="button"
                            disabled={!skillNameInput.trim()}
                            onClick={() => void handleSaveReplyAsSkill(msg)}
                            className="px-2.5 py-1 rounded-lg bg-slate-900 text-white text-[11px] font-medium disabled:opacity-40 cursor-pointer"
                          >
                            Save
                          </button>
                        </div>
                      )}

                      {automateMsgId === msg.id && (
                        <div className="flex items-center gap-1.5 flex-wrap pt-1">
                          <span className="text-[11px] text-slate-500 mr-1">
                            Add new named routine:
                          </span>
                          {SCHEDULE_PRESETS.map((preset) => (
                            <button
                              key={preset}
                              type="button"
                              onClick={() => {
                                void appendRoutineFromMessage(msg, preset);
                              }}
                              className="px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-[11px] text-slate-700 cursor-pointer"
                            >
                              {preset}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </>
          )}

          {pendingUserMsg && (
            <div className="flex justify-end">
              <div className="max-w-[78%] rounded-2xl rounded-tr-sm px-4 py-2.5 text-[13px] leading-relaxed shadow-xs argo-user-bubble space-y-1.5">
                {pendingUserMsg.replyTo && (
                  <div className="rounded-lg border border-[#35547a] bg-[#16273f] px-2.5 py-1 text-[11px] text-[#dbeafe]">
                    <div className="font-semibold">
                      Replying to {pendingUserMsg.replyTo.sender_name}
                    </div>
                    <div className="truncate opacity-85">{pendingUserMsg.replyTo.excerpt}</div>
                  </div>
                )}
                <HighlightedMessageText
                  text={pendingUserMsg.text}
                  catalog={mentionCatalog}
                  inverted
                />
                {pendingUserMsg.attachments && pendingUserMsg.attachments.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {pendingUserMsg.attachments.map((att) => (
                      <span
                        key={att.id}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#1d3554] text-[10.5px] text-[#dbeafe]"
                      >
                        <Paperclip className="w-3 h-3" />
                        {att.filename}
                      </span>
                    ))}
                  </div>
                )}
                <div className="mt-1 text-[10px] text-[#cbd5e1]">Sending...</div>
              </div>
            </div>
          )}

          {showLiveStream && activeStream && (() => {
            const streamBot = botBySlug.get(activeStream.botSlug) ?? subjectBot;
            const streamBotName = activeStream.botName || streamBot?.name || "Bot";
            const isAutoPicked =
              isRoomMode &&
              (activeStream.routingSource === "capability" ||
                activeStream.routingSource === "auto_picker");
            return (
              <div className="flex items-start gap-3">
                {!compact && streamBot && (
                  <BotAvatar
                    icon={streamBot.avatar_icon}
                    color={streamBot.avatar_color}
                    initials={streamBot.initials}
                    size="sm"
                    statusDot="running"
                  />
                )}
                <div className="min-w-0 flex-1 space-y-2.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-slate-900">
                        {streamBotName}
                      </span>
                      {isAutoPicked && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-slate-100 text-[11px] font-medium text-slate-600">
                          Auto-picked {streamBotName}
                          {activeStream.routedReason ? ` · ${activeStream.routedReason}` : ""}
                        </span>
                      )}
                      <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                        <Loader2 className="w-3 h-3 animate-spin text-[#3b72b2]" />
                        <span>
                          {elapsedSec > 0 ? `${elapsedSec}s` : "Streaming"}
                        </span>
                      </span>
                      {queuedCount > 0 && (
                        <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-white text-[11px] text-slate-600">
                          {queuedCount} queued
                        </span>
                      )}
                    </div>
                    {onCancelRun && (
                      <button
                        type="button"
                        disabled={cancellingRunId === activeStream.runId}
                        onClick={() => {
                          setCancellingRunId(activeStream.runId);
                          void onCancelRun(activeStream.runId);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                      >
                        <Square className="w-2.5 h-2.5 fill-current" />
                        <span>
                          {cancellingRunId === activeStream.runId ? "Stopping..." : "Stop"}
                        </span>
                      </button>
                    )}
                  </div>

                  {activeStream.chips.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      {activeStream.chips.map((chip) => {
                        const st = String(chip.status || "running");
                        const secStr =
                          typeof chip.elapsed_ms === "number" && chip.elapsed_ms >= 50
                            ? ` · ${(chip.elapsed_ms / 1000).toFixed(1)}s`
                            : "";
                        return (
                          <span
                            key={chip.chip_id}
                            title={chip.detail || chip.label}
                            className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-slate-200 bg-white text-[11px] font-medium text-slate-700"
                          >
                            {st === "running" ? (
                              <Loader2 className="w-3 h-3 animate-spin text-[#3b72b2] shrink-0" />
                            ) : st === "done" ? (
                              <Check className="w-3 h-3 text-[#2f6b52] shrink-0" />
                            ) : (
                              <span
                                className="w-1.5 h-1.5 rounded-full shrink-0"
                                style={{
                                  backgroundColor: st === "warning" ? "#c98a2c" : "#64748b",
                                }}
                              />
                            )}
                            <span>{chip.label}</span>
                            <span className="text-slate-400">
                              {st === "running"
                                ? "Running"
                                : st === "stopped"
                                  ? "Stopped"
                                  : st === "warning"
                                    ? "Note"
                                    : `Done${secStr}`}
                            </span>
                          </span>
                        );
                      })}
                    </div>
                  )}

                  {activeStream.text ? (
                    <div className="text-[13.5px] text-slate-900 leading-relaxed">
                      <RichMarkdown text={activeStream.text} catalog={mentionCatalog} />
                    </div>
                  ) : (
                    <div className="rounded-2xl px-4 py-2.5 text-xs bg-white border border-slate-200 text-slate-500 inline-flex items-center gap-2">
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-[#3b72b2] shrink-0" />
                      <span>
                        {activeRun?.step ||
                          (desktopBootProgress?.state === "booting"
                            ? desktopBootProgress.step
                            : isRoomMode
                              ? "Selecting best teammate..."
                              : "Thinking...")}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {!showLiveStream && (isWorking || desktopBootProgress?.state === "booting") && subjectBot && (
            <div className="flex items-start gap-3">
              {!compact && (
                <BotAvatar
                  icon={subjectBot.avatar_icon}
                  color={subjectBot.avatar_color}
                  initials={subjectBot.initials}
                  size="sm"
                  statusDot="running"
                />
              )}
              <div className="rounded-2xl px-4 py-3 text-xs shadow-xs bg-white border border-slate-200 text-slate-900 flex items-center gap-2.5">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#3b72b2] shrink-0" />
                <div>
                  <div className="font-medium text-slate-900">
                    {activeRun?.step ||
                      (desktopBootProgress?.state === "booting"
                        ? desktopBootProgress.step
                        : sending
                          ? isRoomMode
                            ? "Coordinating Room reply..."
                            : "Working on your request..."
                          : "Running check...")}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {isRoomMode && room ? room.title : subjectBot.name}
                    {desktopBootProgress?.state === "booting" && !activeRun
                      ? " · Preparing Virtual Desktop, please wait"
                      : ` · ${elapsedSec > 0 ? `${elapsedSec}s elapsed` : "Just started"}`}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      </div>

      {/* Clean Single-Row Grok-Style Composer Bar */}
      <footer className={`shrink-0 ${compact ? "p-3" : "px-3 pb-3 pt-2 md:px-5 md:pb-5 md:pt-2"} bg-slate-50 argo-safe-bottom`}>
        <form onSubmit={handleSubmit} className={compact ? "relative" : "max-w-3xl mx-auto relative"}>
          {mentionOpen && (
            <div
              data-argo-popover="mention"
              className="absolute bottom-full left-0 mb-2 w-72 max-w-[calc(100vw-2rem)] max-h-72 overflow-y-auto custom-scroll rounded-xl border border-slate-200 bg-white shadow-lg p-1.5 space-y-0.5 z-30 text-xs"
            >
              {mentionCandidates.length === 0 ? (
                <div className="px-2.5 py-2 text-[11px] text-slate-400">No matches found.</div>
              ) : (
                mentionCandidates.map((cand, idx) => {
                  const selected = idx === mentionSelectedIndex;
                  const showCat =
                    idx === 0 || cand.category !== mentionCandidates[idx - 1].category;
                  let iconEl = null;
                  if (cand.kind === "bot" && cand.bot) {
                    iconEl = (
                      <BotAvatar
                        icon={cand.bot.avatar_icon}
                        color={cand.bot.avatar_color}
                        initials={cand.bot.initials}
                        size="xs"
                      />
                    );
                  } else {
                    const IconComp =
                      cand.kind === "integration"
                        ? integrationIconComponent(cand.provider)
                        : cand.kind === "vault"
                          ? vaultSecretIconComponent(cand.secretType)
                          : cand.kind === "skill"
                            ? skillIconComponent(cand.isRecorded)
                            : cand.kind === "page"
                              ? FileText
                              : Paperclip;
                    iconEl = (
                      <span className="w-5 h-5 rounded-md border border-slate-200 bg-slate-50 text-slate-600 flex items-center justify-center shrink-0">
                        <IconComp className="w-3 h-3" />
                      </span>
                    );
                  }
                  return (
                    <div key={`${cand.kind}:${cand.token}`}>
                      {showCat && (
                        <div className="px-2 pt-1.5 pb-0.5 text-[10.5px] font-medium text-slate-400">
                          {cand.category}
                        </div>
                      )}
                      <button
                        type="button"
                        onClick={() => insertMentionToken(cand.token)}
                        className={`w-full text-left px-2 py-1.5 rounded-lg flex items-center gap-2.5 cursor-pointer ${
                          selected ? "bg-slate-100" : "hover:bg-slate-50"
                        }`}
                      >
                        {iconEl}
                        <span className="text-xs font-medium text-slate-900 truncate">
                          {cand.label}
                        </span>
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          )}

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDraggingFile(true);
            }}
            onDragLeave={() => setIsDraggingFile(false)}
            onDrop={handleDropFile}
            className={`rounded-3xl border bg-white shadow-sm px-3 py-2 space-y-2 focus-within:ring-2 focus-within:ring-slate-300 ${
              isDraggingFile ? "border-[#3b72b2] ring-2 ring-[#3b72b2]" : "border-slate-200"
            }`}
          >
            {contextCorrelationId && (
              <div className="flex items-center gap-1.5 flex-wrap px-1">
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100 border border-slate-200 text-[11px] text-slate-700">
                  Continuing prior run
                  {onClearContextCorrelation && (
                    <button
                      type="button"
                      onClick={onClearContextCorrelation}
                      className="hover:text-slate-900 cursor-pointer"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </span>
              </div>
            )}

            {replyTo && (
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 flex items-center justify-between gap-2 text-[11px]">
                <div className="min-w-0">
                  <span className="font-semibold text-slate-800">
                    Replying to {replyTo.sender_name}:{" "}
                  </span>
                  <span className="text-slate-600 truncate">{replyTo.excerpt}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setReplyTo(null)}
                  className="text-slate-400 hover:text-slate-800 cursor-pointer shrink-0"
                  aria-label="Cancel reply"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {draftAttachments.length > 0 && (
              <div className="flex flex-wrap gap-1.5 px-1">
                {draftAttachments.map((f) => (
                  <span
                    key={f.id}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-700"
                  >
                    <Paperclip className="w-3 h-3 text-slate-500" />
                    <span className="truncate max-w-[160px]">{f.filename}</span>
                    <button
                      type="button"
                      onClick={() =>
                        setDraftAttachments((prev) => prev.filter((item) => item.id !== f.id))
                      }
                      className="text-slate-400 hover:text-slate-800 cursor-pointer"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}

            {fileError && (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1 text-[11px] text-rose-700">
                {fileError}
              </div>
            )}

            <div className="flex items-end gap-1.5">
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => {
                  if (e.target.files?.length) {
                    void handleFileSelection(e.target.files);
                    e.target.value = "";
                  }
                }}
              />
              <input
                ref={docFileInputRef}
                type="file"
                multiple
                accept="application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.oasis.opendocument.spreadsheet,text/csv,text/tab-separated-values,text/plain,text/markdown,application/json,application/x-ndjson,application/octet-stream,.pdf,.docx,.xlsx,.xlsm,.xlsb,.xls,.ods,.csv,.tsv,.parquet,.json,.ndjson,.jsonl,.txt,.md,.log,.sh,.yaml,.yml,.zip"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files?.length) {
                    void handleFileSelection(e.target.files);
                    e.target.value = "";
                  }
                }}
              />
              <input
                ref={photoFileInputRef}
                type="file"
                multiple
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  if (e.target.files?.length) {
                    void handleFileSelection(e.target.files);
                    e.target.value = "";
                  }
                }}
              />
              <div className="relative shrink-0" data-argo-popover="attach">
                {attachMenuOpen && (
                  <div className="absolute bottom-full left-0 mb-2 w-52 rounded-xl border border-slate-200 bg-white shadow-lg p-1.5 space-y-0.5 z-30 text-xs">
                    <button
                      type="button"
                      onClick={() => {
                        setAttachMenuOpen(false);
                        docFileInputRef.current?.click();
                      }}
                      className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left font-medium text-slate-800 hover:bg-slate-100 cursor-pointer"
                    >
                      <FileUp className="w-4 h-4 text-slate-500 shrink-0" />
                      <span>Document or File</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAttachMenuOpen(false);
                        photoFileInputRef.current?.click();
                      }}
                      className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left font-medium text-slate-800 hover:bg-slate-100 cursor-pointer"
                    >
                      <ImageIcon className="w-4 h-4 text-slate-500 shrink-0" />
                      <span>Photo or Camera</span>
                    </button>
                  </div>
                )}
                <button
                  type="button"
                  disabled={uploadingFile}
                  title="Attach workspace file (max 100 MB docs/data, 10 MB misc)"
                  aria-label="Attach workspace file"
                  onClick={() => {
                    if (isMobile) {
                      setMentionOpen(false);
                      setAttachMenuOpen((v) => !v);
                    } else {
                      fileInputRef.current?.click();
                    }
                  }}
                  className="w-9 h-9 md:w-8 md:h-8 rounded-full border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 flex items-center justify-center disabled:opacity-50 cursor-pointer shrink-0"
                >
                  {uploadingFile ? (
                    <Loader2 className="w-4 h-4 md:w-3.5 md:h-3.5 animate-spin" />
                  ) : (
                    <Plus className="w-4 h-4 md:w-3.5 md:h-3.5" />
                  )}
                </button>
              </div>

              <button
                type="button"
                data-argo-popover="mention"
                title="Mention"
                aria-label="Mention"
                onClick={() => {
                  mentionRangeRef.current = null;
                  setMentionOpen((v) => !v);
                  setMentionQuery("");
                  setMentionSelectedIndex(0);
                }}
                className="w-9 h-9 md:w-8 md:h-8 rounded-full hover:bg-slate-100 text-slate-500 flex items-center justify-center cursor-pointer shrink-0"
              >
                <AtSign className="w-4 h-4 md:w-3.5 md:h-3.5" />
              </button>

              <div className="relative flex-1 min-w-0 my-1" data-argo-popover="mention">
                <div
                  aria-hidden="true"
                  className="argo-composer-backdrop pointer-events-none absolute inset-0 overflow-hidden"
                >
                  <div
                    ref={composerBackdropRef}
                    className="whitespace-pre-wrap break-words text-[16px] md:text-[13px] leading-relaxed select-none m-0 p-0 border-0 will-change-transform"
                  >
                    {renderComposerBackdropNodes(text, mentionCatalog)}
                  </div>
                </div>
                <textarea
                  ref={textareaRef}
                  rows={1}
                  value={text}
                  onChange={(e) => handleTextChange(e.target.value, e.target.selectionStart)}
                  onScroll={(e) => {
                    if (composerBackdropRef.current) {
                      composerBackdropRef.current.style.transform = `translateY(-${e.currentTarget.scrollTop}px)`;
                    }
                  }}
                  onKeyDown={handleKeyDown}
                  onPaste={handleComposerPaste}
                  placeholder={
                    placeholder ??
                    (isRoomMode && room
                      ? `Message ${room.title}...`
                      : `Message ${subjectBot?.name ?? "Bot"}...`)
                  }
                  className="argo-composer-input relative z-10 w-full resize-none border-0 bg-transparent text-[16px] md:text-[13px] leading-relaxed focus:outline-none m-0 p-0 block max-h-[200px] overflow-y-hidden custom-scroll"
                />
              </div>

              {showLiveStream && activeStream && onCancelRun && (
                <button
                  type="button"
                  disabled={cancellingRunId === activeStream.runId}
                  onClick={() => {
                    setCancellingRunId(activeStream.runId);
                    void onCancelRun(activeStream.runId);
                  }}
                  title="Stop current reply"
                  aria-label="Stop current reply"
                  className="w-9 h-9 md:w-8 md:h-8 rounded-full border border-slate-200 bg-slate-100 hover:bg-slate-200 text-slate-800 flex items-center justify-center cursor-pointer disabled:opacity-50 shrink-0"
                >
                  <Square className="w-3.5 h-3.5 md:w-3 md:h-3 fill-current" />
                </button>
              )}

              <button
                type="submit"
                disabled={sending || (!text.trim() && draftAttachments.length === 0)}
                title={showLiveStream ? "Queue follow-up message" : "Send message"}
                aria-label="Send message"
                className="w-9 h-9 md:w-8 md:h-8 rounded-full bg-slate-900 text-white flex items-center justify-center cursor-pointer hover:bg-slate-800 disabled:opacity-35 shrink-0"
              >
                <ArrowUp className="w-4 h-4" />
              </button>
            </div>
          </div>
        </form>
      </footer>
    </div>
  );
}
