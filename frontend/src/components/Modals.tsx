import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Download,
  ExternalLink,
  Loader2,
  Maximize2,
  Minimize2,
  RefreshCw,
  Square,
  Video,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { api } from "../api";
import { useIsMobile } from "../hooks/useIsMobile";
import type {
  ApprovalItem,
  BotDraftResponse,
  SsoPrincipal,
  BotRecord,
  CollectionRecord,
  DebugOverviewResponse,
  DesktopBootProgress,
  DesktopInfo,
  DesktopRecordingStatus,
  DesktopRecordingStopResponse,
  DiscoveredProviderModel,
  GoogleAuthorizeResponse,
  GoogleWizardConfig,
  IntegrationAccount,
  ModelProvider,
  ResourceVisibility,
  TeamGroupRecord,
  WebhookOnboardResponse,
} from "../types";
import { computeWordDiff, friendlyModelName } from "../utils/format";
import { BOT_ICON_OPTIONS, BotAvatar } from "./BotAvatar";
import { VisibilityPicker } from "./VisibilityPicker";

export type NewBotModalTab = "quick" | "builder" | "room" | "packs";

export type ActiveModal =
  | { type: "new-bot"; initialTab?: NewBotModalTab }
  | { type: "new-page" }
  | { type: "edit-approval"; item: ApprovalItem }
  | { type: "new-integration"; defaultProvider?: IntegrationAccount["provider"] }
  | { type: "google-wizard"; reauthAccount?: IntegrationAccount }
  | { type: "telegram-onboard" }
  | { type: "linkedin-onboard" }
  | { type: "webhook-onboard" }
  | { type: "new-model"; initial?: ModelProvider }
  | { type: "selkies"; desktop: DesktopInfo }
  | { type: "debug"; botSlug?: string }
  | null;

const SUGGESTED_MODELS: Record<ModelProvider["provider_type"], string> = {
  google: "google:gemini-3.8-flash",
  anthropic: "anthropic:claude-4.5-sonnet",
  openai: "openai:gpt-5-mini",
  xai: "xai:grok-4",
  openrouter: "openrouter:anthropic/claude-4.5-sonnet",
  ollama: "ollama:qwen3-32b",
};

interface ModalsProps {
  modal: ActiveModal;
  onClose: () => void;
  models: ModelProvider[];
  integrations: IntegrationAccount[];
  bots: BotRecord[];
  collections?: CollectionRecord[];
  desktopBootBySlug?: Record<string, DesktopBootProgress>;
  onLoadDebugOverview: (params?: {
    bot_slug?: string;
    level?: string;
    contains?: string;
    limit?: number;
  }) => Promise<DebugOverviewResponse>;
  onClearDebug: () => Promise<unknown>;
  onDraftBotSpec: (payload: {
    prompt: string;
    preferred_runtime?: "auto" | "api" | "sandbox" | "desktop";
    preferred_rbac?: "auto" | "internal" | "draft" | "execute";
    preferred_model?: string;
    linked_accounts?: string[];
  }) => Promise<BotDraftResponse>;
  onCreateBot: (payload: {
    name: string;
    role?: string;
    role_prompt?: string;
    runtime: "api" | "sandbox" | "desktop";
    outbound_rbac: "internal" | "draft" | "execute";
    model: string;
    daily_cap: number;
    routines?: Array<Record<string, unknown>>;
    tools?: Array<string | Record<string, unknown>>;
    collections?: { read: string[]; write: string[] };
    linked_accounts?: string[];
    avatar_color?: string;
    avatar_icon?: string;
    boundaries?: string[];
    section?: string;
    handoff_bot_slug?: string;
    onboarding_mode?: "configured" | "interview";
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onCreateRoom?: (payload: {
    title: string;
    member_bot_slugs: string[];
    coordinator_bot_slug?: string | null;
    routing_mode?: "auto" | "lead" | "stage";
    ask_before_bot_handoff?: boolean;
    max_bot_turns_per_message?: number;
    section?: string;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onImportTeamPack?: (payload: {
    pack: Record<string, unknown>;
    linked_accounts?: string[];
    section_override?: string;
  }) => Promise<void>;
  onCreatePipeline?: (payload: {
    scoutName: string;
    scoutSource: string;
    scoutSchedule: string;
    scoutAccounts: string[];
    writerName: string;
    writerStyle: string;
    writerAccounts: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onImportBlueprint?: (payload: {
    blueprint: Record<string, unknown>;
    linked_accounts?: string[];
  }) => Promise<void>;
  onCreatePage: (payload: {
    title: string;
    description: string;
    render_mode: "declarative_json" | "sandboxed_html";
    content_payload?: string;
    allowed_collections?: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onGeneratePage?: (payload: {
    prompt: string;
    title?: string;
    owner_bot_slug?: string;
    allowed_collections?: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
    template_key?:
      | "auto"
      | "live_operations_map"
      | "bot_hub_board"
      | "collection_analytics"
      | "interactive_playground"
      | "data_dashboard";
  }) => Promise<void>;
  onStartTakeover: (slug: string) => Promise<DesktopInfo>;
  onReleaseTakeover: (slug: string) => Promise<DesktopInfo>;
  onSkillSaved?: () => Promise<void> | void;
  onResolveEditedApproval: (
    id: string,
    editedText: string,
    styleRule: string,
  ) => Promise<void>;
  onUpsertIntegration: (payload: {
    slug: string;
    provider: "google" | "telegram" | "linkedin" | "webhook" | "mcp";
    display_name: string;
    account_identifier?: string;
    scopes?: string[];
    secrets?: Record<string, unknown>;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onOnboardTelegram: (payload: {
    bot_token: string;
    slug?: string;
    display_name?: string;
    operator_chat_id?: string;
    admin_channels?: string[];
    public_channels?: string[];
    register_webhook?: boolean;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onLoadGoogleWizardConfig: () => Promise<GoogleWizardConfig>;
  onStartGoogleOAuth: (payload: {
    in_production_confirmed: boolean;
    client_id?: string;
    client_secret?: string;
    reuse_saved_client?: boolean;
    slug?: string;
    display_name?: string;
    login_hint?: string;
    scope_groups?: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<GoogleAuthorizeResponse>;
  onCompleteGoogleOAuth: (payload: { code: string; state: string }) => Promise<IntegrationAccount>;
  onOnboardLinkedIn: (payload: {
    access_token: string;
    author_urn?: string;
    linkedin_version?: string;
    slug?: string;
    display_name?: string;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
  onOnboardWebhook: (payload: {
    display_name: string;
    slug?: string;
    signing_secret?: string;
    event_type?: string;
    target_collection?: string | null;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<WebhookOnboardResponse>;
  onUpsertModel: (payload: {
    slug: string;
    provider_type: "google" | "anthropic" | "openai" | "xai" | "openrouter" | "ollama";
    model_id: string;
    api_base?: string;
    api_key?: string;
    is_default: boolean;
    daily_token_limit?: number;
    monthly_budget_usd?: number;
    input_price_per_million?: number;
    output_price_per_million?: number;
  }) => Promise<void>;
  teams?: TeamGroupRecord[];
  principal?: SsoPrincipal | null;
}

export function Modals({
  modal,
  onClose,
  models,
  integrations,
  bots,
  collections = [],
  desktopBootBySlug = {},
  onLoadDebugOverview,
  onClearDebug,
  onDraftBotSpec,
  onCreateBot,
  onCreateRoom,
  onImportTeamPack,
  onCreatePipeline,
  onImportBlueprint,
  onCreatePage,
  onGeneratePage,
  onStartTakeover,
  onReleaseTakeover,
  onSkillSaved,
  onResolveEditedApproval,
  onUpsertIntegration,
  onOnboardTelegram,
  onLoadGoogleWizardConfig,
  onStartGoogleOAuth,
  onCompleteGoogleOAuth,
  onOnboardLinkedIn,
  onOnboardWebhook,
  onUpsertModel,
  teams = [],
  principal = null,
}: ModalsProps) {
  const isMultiUser = Boolean(principal?.multi_user);
  const [resourceVisibility, setResourceVisibility] = useState<ResourceVisibility>("private");
  const [resourceGroups, setResourceGroups] = useState<string[]>([]);
  const [botBuilderPrompt, setBotBuilderPrompt] = useState("");
  const [botName, setBotName] = useState("");
  const [botRole, setBotRole] = useState("");
  const [botRolePrompt, setBotRolePrompt] = useState("");
  const [botRuntime, setBotRuntime] = useState<"api" | "sandbox" | "desktop">("api");
  const [runtimeTouched, setRuntimeTouched] = useState(false);
  const [botRbac, setBotRbac] = useState<"internal" | "draft" | "execute">("draft");
  const [botModel, setBotModel] = useState("google:gemini-3.8-flash");
  const [botDailyCap, setBotDailyCap] = useState("0");
  const [botTriggerMode, setBotTriggerMode] = useState<"schedule" | "on_event">("schedule");
  const [botEventName, setBotEventName] = useState("");
  const [botCollectionsRead, setBotCollectionsRead] = useState("");
  const [botCollectionsWrite, setBotCollectionsWrite] = useState("");
  const [botDraftedTools, setBotDraftedTools] = useState<Array<string | Record<string, unknown>>>([]);
  const [botDraftedRoutines, setBotDraftedRoutines] = useState<Array<Record<string, unknown>> | null>(
    null,
  );
  const [selectedLinkedAccounts, setSelectedLinkedAccounts] = useState<string[]>([]);
  const [showAdvancedBotOptions, setShowAdvancedBotOptions] = useState(false);
  const [builderWarnings, setBuilderWarnings] = useState<string[]>([]);
  const [builderUsedLlm, setBuilderUsedLlm] = useState(false);
  const [builderError, setBuilderError] = useState<string | null>(null);
  const [synthesizingBot, setSynthesizingBot] = useState(false);
  const [creatingBot, setCreatingBot] = useState(false);
  const [showJsonPreview, setShowJsonPreview] = useState(false);
  const [botBoundaries, setBotBoundaries] = useState<string[]>([]);
  const [botAvatarColor, setBotAvatarColor] = useState("slate");
  const [botAvatarIcon, setBotAvatarIcon] = useState("bot");
  const [botSection, setBotSection] = useState("");
  const [restatedSummary, setRestatedSummary] = useState<BotDraftResponse["restated_summary"] | null>(
    null,
  );
  const [blueprintImportMode, setBlueprintImportMode] = useState(false);
  const [blueprintJson, setBlueprintJson] = useState("");
  const [pipelineMode, setPipelineMode] = useState(false);
  const [pipeScoutName, setPipeScoutName] = useState("Inbox & Web Scout");
  const [pipeScoutSource, setPipeScoutSource] = useState(
    "Check unread emails (or websites) for valuable leads or personal messages, ignoring newsletters and automated receipts.",
  );
  const [pipeScoutSchedule, setPipeScoutSchedule] = useState("Every 15m");
  const [pipeScoutAccounts, setPipeScoutAccounts] = useState<string[]>([]);
  const [pipeWriterName, setPipeWriterName] = useState("Story Writer");
  const [pipeWriterStyle, setPipeWriterStyle] = useState(
    "Read the collected items from the Scout, write a clear engaging story or reply with key facts and source links, and queue it in Approvals.",
  );
  const [pipeWriterAccounts, setPipeWriterAccounts] = useState<string[]>([]);

  const [newBotTab, setNewBotTab] = useState<NewBotModalTab>("quick");
  const [quickBotHint, setQuickBotHint] = useState("");
  useEffect(() => {
    setResourceVisibility("private");
    setResourceGroups([]);
  }, [modal?.type, newBotTab]);
  const [roomTitle, setRoomTitle] = useState("");
  const [roomMembers, setRoomMembers] = useState<string[]>([]);
  const [roomCoordinator, setRoomCoordinator] = useState<string>("");
  const [roomRoutingMode, setRoomRoutingMode] = useState<"auto" | "lead" | "stage">("auto");
  const [roomAskBeforeHandoff, setRoomAskBeforeHandoff] = useState(false);
  const [roomSection, setRoomSection] = useState("");

  const [pagePrompt, setPagePrompt] = useState("");
  const [pageOwnerBot, setPageOwnerBot] = useState("");
  const [pageSelectedCols, setPageSelectedCols] = useState<string[]>([]);
  const [pageColsTouched, setPageColsTouched] = useState(false);
  const [pageManualMode, setPageManualMode] = useState(false);
  const [generatingPage, setGeneratingPage] = useState(false);
  const [pageTitle, setPageTitle] = useState("");
  const [pageDesc, setPageDesc] = useState("");
  const [pageMode, setPageMode] = useState<"declarative_json" | "sandboxed_html">(
    "declarative_json",
  );
  const [pageAllowedCollections, setPageAllowedCollections] = useState("");
  const [pageCustomPayload, setPageCustomPayload] = useState("");

  const [activeDesktop, setActiveDesktop] = useState<DesktopInfo | null>(null);
  const [takeoverLoading, setTakeoverLoading] = useState(false);
  const [takeoverError, setTakeoverError] = useState<string | null>(null);
  const [iframeKey, setIframeKey] = useState(0);
  const isMobile = useIsMobile();
  const [desktopFullscreen, setDesktopFullscreen] = useState(false);
  const [mobileDesktopWide, setMobileDesktopWide] = useState(false);
  const selkiesIframeRef = useRef<HTMLIFrameElement | null>(null);

  useEffect(() => {
    if (modal?.type !== "selkies") {
      setMobileDesktopWide(false);
    }
  }, [modal?.type]);
  const detachSelkiesIframe = () => {
    const frame = selkiesIframeRef.current;
    if (!frame) return;
    try {
      const win = frame.contentWindow as
        | (Window & { peerConnection?: RTCPeerConnection; localStream?: MediaStream })
        | null;
      win?.localStream?.getTracks?.().forEach((t) => t.stop());
      win?.peerConnection?.close?.();
    } catch {
      /* ignore cross-state errors */
    }
    try {
      frame.src = "about:blank";
    } catch {
      /* ignore */
    }
  };
  const [recordingState, setRecordingState] = useState<DesktopRecordingStatus | null>(null);
  const [recordingBusy, setRecordingBusy] = useState(false);
  const [stoppedRecordingTrace, setStoppedRecordingTrace] =
    useState<DesktopRecordingStopResponse["recording"] | null>(null);
  const [recordSkillName, setRecordSkillName] = useState("");
  const [recordedSkillResult, setRecordedSkillResult] =
    useState<DesktopRecordingStopResponse | null>(null);
  const [recordingError, setRecordingError] = useState<string | null>(null);
  const [recordingNotice, setRecordingNotice] = useState<string | null>(null);
  const [recordingElapsedSec, setRecordingElapsedSec] = useState(0);

  const [editText, setEditText] = useState("");
  const [editRule, setEditRule] = useState("");

  const [intSlug, setIntSlug] = useState("");
  const [intProvider, setIntProvider] = useState<
    "google" | "telegram" | "linkedin" | "webhook" | "mcp"
  >("telegram");
  const [intName, setIntName] = useState("");
  const [intIdent, setIntIdent] = useState("");
  const [intToken, setIntToken] = useState("");

  const [tgToken, setTgToken] = useState("");
  const [tgSlug, setTgSlug] = useState("");
  const [tgName, setTgName] = useState("");
  const [tgChatId, setTgChatId] = useState("");
  const [tgChannels, setTgChannels] = useState("");
  const [tgPublicChannels, setTgPublicChannels] = useState("");
  const [tgWebhook, setTgWebhook] = useState(false);

  const [mdlSlug, setMdlSlug] = useState("");
  const [mdlProvider, setMdlProvider] = useState<ModelProvider["provider_type"]>("google");
  const [mdlId, setMdlId] = useState("google:gemini-3.8-flash");
  const [mdlBase, setMdlBase] = useState("");
  const [mdlKey, setMdlKey] = useState("");
  const [mdlDailyLimit, setMdlDailyLimit] = useState("");
  const [mdlMonthlyBudget, setMdlMonthlyBudget] = useState("100");
  const [mdlInputPrice, setMdlInputPrice] = useState("");
  const [mdlOutputPrice, setMdlOutputPrice] = useState("");
  const [mdlDefault, setMdlDefault] = useState(false);
  const [discoveredModels, setDiscoveredModels] = useState<DiscoveredProviderModel[]>([]);
  const [discoveringModels, setDiscoveringModels] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const [discoverNote, setDiscoverNote] = useState<string | null>(null);
  const [discoverFilter, setDiscoverFilter] = useState("");

  useEffect(() => {
    if (modal?.type === "new-integration" && modal.defaultProvider) {
      setIntProvider(modal.defaultProvider);
    }
  }, [modal]);

  useEffect(() => {
    if (modal?.type === "new-bot") {
      setNewBotTab(modal.initialTab ?? "quick");
      setQuickBotHint("");
      setRoomTitle("");
      setRoomMembers(bots.slice(0, 2).map((b) => b.slug));
      setRoomCoordinator(bots[0]?.slug ?? "");
      setRoomRoutingMode("auto");
      setRoomAskBeforeHandoff(false);
      setRoomSection("");
      setSelectedLinkedAccounts([]);
      setShowAdvancedBotOptions(false);
      setBuilderError(null);
      setCreatingBot(false);
      setRestatedSummary(null);
      setBlueprintImportMode(false);
      setBlueprintJson("");
      setPipelineMode(false);
      setPipeScoutName("Source Bot");
      setPipeScoutSource(
        "Check unread emails (or websites) for valuable leads or personal messages, ignoring newsletters and automated receipts.",
      );
      setPipeScoutSchedule("Every 15m");
      setPipeScoutAccounts([]);
      setPipeWriterName("Drafting Bot");
      setPipeWriterStyle(
        "Read the collected items from the Source Bot, write a clear engaging summary or reply with key facts and source links, and queue it in Approvals.",
      );
      setPipeWriterAccounts([]);
      setBotBoundaries([]);
      setBotAvatarColor("slate");
      setBotAvatarIcon("bot");
      setBotSection("");
      setBotRuntime("api");
      setRuntimeTouched(false);
    } else if (modal?.type === "new-page") {
      const initialOwner = bots[0]?.slug ?? "";
      setPagePrompt("");
      setPageTitle("");
      const hiddenCols = new Set([
        "oauth_pending_states",
        "http_feed_cache",
        "debug_run_traces",
        "bot_threads",
        "desktop_snapshots",
        "bot_skills",
        "ingestion_seen_keys",
        "vault_secrets",
      ]);
      const ownerCols = collections
        .filter(
          (c) =>
            !c.is_internal &&
            !hiddenCols.has(c.slug) &&
            c.owner_bot_slug === initialOwner,
        )
        .map((c) => c.slug);
      setPagePrompt("");
      setPageOwnerBot(initialOwner);
      setPageSelectedCols(ownerCols);
      setPageColsTouched(false);
      setPageManualMode(false);
      setGeneratingPage(false);
    } else if (modal?.type === "edit-approval") {
      setEditText(modal.item.payload.text ?? "");
      setEditRule("");
    }
  }, [modal, bots]);

  useEffect(() => {
    if (modal?.type === "new-model") {
      if (modal.initial) {
        setMdlSlug(modal.initial.slug);
        setMdlProvider(modal.initial.provider_type);
        setMdlId(modal.initial.model_id);
        setMdlBase(modal.initial.api_base ?? "");
        setMdlKey("");
        setMdlDailyLimit(
          modal.initial.daily_token_limit != null ? String(modal.initial.daily_token_limit) : "",
        );
        setMdlMonthlyBudget(
          modal.initial.monthly_budget_usd != null ? String(modal.initial.monthly_budget_usd) : "",
        );
        setMdlInputPrice(
          modal.initial.input_price_per_million != null
            ? String(modal.initial.input_price_per_million)
            : "",
        );
        setMdlOutputPrice(
          modal.initial.output_price_per_million != null
            ? String(modal.initial.output_price_per_million)
            : "",
        );
        setMdlDefault(modal.initial.is_default);
      } else {
        setMdlSlug("");
        setMdlProvider("google");
        setMdlId("google:gemini-3.8-flash");
        setMdlBase("");
        setMdlKey("");
        setMdlDailyLimit("");
        setMdlMonthlyBudget("100");
        setMdlInputPrice("");
        setMdlOutputPrice("");
        setMdlDefault(false);
      }
      setDiscoveredModels([]);
      setDiscoveringModels(false);
      setDiscoverError(null);
      setDiscoverNote(null);
      setDiscoverFilter("");
    }
  }, [modal]);

  useEffect(() => {
    if (modal?.type !== "selkies") {
      setActiveDesktop(null);
      setTakeoverLoading(false);
      setTakeoverError(null);
      setDesktopFullscreen(false);
      setRecordingState(null);
      setRecordingBusy(false);
      setStoppedRecordingTrace(null);
      setRecordSkillName("");
      setRecordedSkillResult(null);
      setRecordingError(null);
      setRecordingNotice(null);
      setRecordingElapsedSec(0);
      return;
    }
    let cancelled = false;
    setActiveDesktop(modal.desktop);
    setIframeKey(0);
    setTakeoverLoading(true);
    setTakeoverError(null);
    setRecordingError(null);
    setRecordingNotice(null);
    setRecordedSkillResult(null);
    setStoppedRecordingTrace(null);
    void onStartTakeover(modal.desktop.bot_slug)
      .then((updated) => {
        if (!cancelled) {
          setActiveDesktop(updated);
          void api
            .getDesktopRecordingStatus(modal.desktop.bot_slug)
            .then((rec) => {
              if (!cancelled) {
                setRecordingState(rec);
                if (rec.started_at) {
                  const elapsed = Math.max(
                    0,
                    Math.round((Date.now() - Date.parse(rec.started_at)) / 1000),
                  );
                  if (Number.isFinite(elapsed)) setRecordingElapsedSec(elapsed);
                }
              }
            })
            .catch(() => {
              // Desktop agent might still be booting; ignore initial status probe failure.
            });
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setTakeoverError(
            err instanceof Error ? err.message : "Failed to initialize Selkies takeover session.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setTakeoverLoading(false);
        }
      });
    return () => {
      cancelled = true;
      detachSelkiesIframe();
    };
  }, [modal, onStartTakeover]);

  useEffect(() => {
    if (modal?.type !== "selkies" || !recordingState?.recording) return;
    const slug = modal.desktop.bot_slug;
    let cancelled = false;
    let pollInFlight = false;
    const tick = window.setInterval(() => {
      setRecordingElapsedSec((s) => s + 1);
    }, 1000);
    const poll = window.setInterval(() => {
      if (pollInFlight) return;
      pollInFlight = true;
      void api
        .getDesktopRecordingStatus(slug)
        .then((rec) => {
          if (!cancelled) {
            setRecordingState(rec);
          }
        })
        .catch(() => {
          // Ignore transient poll errors during active session recording.
        })
        .finally(() => {
          pollInFlight = false;
        });
    }, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(tick);
      window.clearInterval(poll);
    };
  }, [modal, recordingState?.recording]);

  if (!modal) return null;

  const parseCsvList = (raw: string): string[] =>
    raw
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

  const computedBotSlug =
    botName
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "new-bot";

  const trimmedEvent = botEventName.trim();
  const effectiveRoutines: Array<Record<string, unknown>> =
    botDraftedRoutines && botDraftedRoutines.length > 0
      ? botDraftedRoutines
      : botTriggerMode === "on_event" && trimmedEvent
        ? [
            {
              type: "on_event",
              event: trimmedEvent,
              label: `Subscribe ${trimmedEvent}`,
              schedule: `on:${trimmedEvent}`,
              enabled: true,
            },
          ]
        : [
            {
              type: "manual_trigger",
              label: "Manual Run",
              schedule: "Manual",
              enabled: true,
            },
          ];

  function toggleLinkedAccount(accountSlug: string) {
    setSelectedLinkedAccounts((prev) =>
      prev.includes(accountSlug)
        ? prev.filter((item) => item !== accountSlug)
        : [...prev, accountSlug],
    );
  }

  const liveBotSpecPreview = {
    name: botName.trim() || "Untitled Bot",
    slug: computedBotSlug,
    avatar_color: botAvatarColor,
    avatar_icon: botAvatarIcon,
    section: botSection.trim() || undefined,
    role: botRole.trim() || "Operational specialist bot",
    role_prompt: botRolePrompt.trim() || botBuilderPrompt.trim() || botRole.trim(),
    boundaries: botBoundaries,
    runtime: botRuntime,
    outbound_rbac: botRbac,
    daily_cap: Number.parseInt(botDailyCap, 10) || 0,
    model: botModel.trim() || "google:gemini-3.8-flash",
    linked_accounts: selectedLinkedAccounts,
    collections: {
      read: parseCsvList(botCollectionsRead),
      write: parseCsvList(botCollectionsWrite),
    },
    routines: effectiveRoutines,
    tools: botDraftedTools,
  };

  async function handleSynthesizeBot() {
    const prompt = (botRolePrompt || botBuilderPrompt).trim();
    if (!prompt) return;
    setSynthesizingBot(true);
    setBuilderError(null);
    try {
      const res = await onDraftBotSpec({
        prompt,
        preferred_runtime: runtimeTouched ? botRuntime : "auto",
        preferred_rbac: botRbac,
        preferred_model: botModel,
        linked_accounts: selectedLinkedAccounts,
      });
      const draft = res.draft;
      if (!botName.trim()) {
        setBotName(draft.name);
      }
      setBotRole(draft.role);
      setBotRolePrompt((prev) => prev.trim() || draft.role_prompt);
      setBotRuntime(draft.runtime);
      setBotRbac(draft.outbound_rbac);
      setBotModel(draft.model);
      setBotDailyCap(String(draft.daily_cap ?? 0));
      setBotCollectionsRead((draft.collections?.read ?? []).join(", "));
      setBotCollectionsWrite((draft.collections?.write ?? []).join(", "));
      setBotDraftedTools(draft.tools ?? []);
      setBotDraftedRoutines((draft.routines ?? []).map((routine) => ({ ...routine })));
      setBotBoundaries(draft.boundaries ?? []);
      if (draft.avatar_color) setBotAvatarColor(draft.avatar_color);
      if (draft.avatar_icon) setBotAvatarIcon(draft.avatar_icon);
      setRestatedSummary(res.restated_summary ?? null);
      setBuilderWarnings(res.warnings ?? []);
      setBuilderUsedLlm(Boolean(res.used_llm));
      const onEventRoutine = (draft.routines ?? []).find(
        (r) => String(r.type ?? "") === "on_event" || Boolean(r.event),
      );
      if (onEventRoutine) {
        setBotTriggerMode("on_event");
        setBotEventName(String(onEventRoutine.event ?? ""));
      } else {
        setBotTriggerMode("schedule");
        setBotEventName("");
      }
    } catch (err) {
      setBuilderError(err instanceof Error ? err.message : "Failed to prepare bot configuration.");
    } finally {
      setSynthesizingBot(false);
    }
  }

  async function submitBot(e: FormEvent) {
    e.preventDefault();
    const instructions = (botRolePrompt || botBuilderPrompt || botRole).trim();
    if (!botName.trim() && !instructions) return;
    if (isMultiUser && resourceVisibility === "team" && resourceGroups.length === 0) {
      setBuilderError("Select at least one Team Group when Visibility is set to Team.");
      return;
    }

    setCreatingBot(true);
    setBuilderError(null);
    try {
      let finalName = botName.trim();
      let finalRole = botRole.trim();
      let finalRolePrompt = instructions;
      let finalRuntime: "api" | "sandbox" | "desktop" = botRuntime;
      let finalRoutines = effectiveRoutines;
      let finalTools = botDraftedTools;
      let finalRead = parseCsvList(botCollectionsRead);
      let finalWrite = parseCsvList(botCollectionsWrite);
      let finalBoundaries = botBoundaries;
      let finalAvatarColor = botAvatarColor;
      let finalAvatarIcon = botAvatarIcon;

      if (botDraftedRoutines === null && botDraftedTools.length === 0 && instructions) {
        try {
          const res = await onDraftBotSpec({
            prompt: instructions,
            preferred_runtime: runtimeTouched ? botRuntime : "auto",
            preferred_rbac: botRbac,
            preferred_model: botModel,
            linked_accounts: selectedLinkedAccounts,
          });
          const draft = res.draft;
          if (!finalName) finalName = draft.name;
          if (!finalRole) finalRole = draft.role;
          if (!finalRolePrompt) finalRolePrompt = draft.role_prompt;
          if (!runtimeTouched && draft.runtime) finalRuntime = draft.runtime;
          if (
            !(botTriggerMode === "on_event" && trimmedEvent) &&
            Array.isArray(draft.routines) &&
            draft.routines.length > 0
          ) {
            finalRoutines = draft.routines.map((routine) => ({ ...routine }));
          }
          if (Array.isArray(draft.tools) && draft.tools.length > 0) {
            finalTools = draft.tools;
          }
          if (finalRead.length === 0 && draft.collections?.read?.length) {
            finalRead = draft.collections.read;
          }
          if (finalWrite.length === 0 && draft.collections?.write?.length) {
            finalWrite = draft.collections.write;
          }
          if (finalBoundaries.length === 0 && Array.isArray(draft.boundaries)) {
            finalBoundaries = draft.boundaries;
          }
          if (finalAvatarColor === "slate" && draft.avatar_color) {
            finalAvatarColor = draft.avatar_color;
          }
          if (finalAvatarIcon === "bot" && draft.avatar_icon) {
            finalAvatarIcon = draft.avatar_icon;
          }
        } catch {
          // Gracefully fall back to direct operator inputs if auto-drafting fails.
        }
      }

      if (!finalName) {
        finalName = instructions.split(/[\n.!?]/)[0]?.trim().slice(0, 48) || "Custom Bot";
      }
      if (!finalRole) {
        finalRole = instructions.split(/[\n.!?]/)[0]?.trim().slice(0, 120) || finalName;
      }

      const parsedCap = Number.parseInt(botDailyCap, 10);
      await onCreateBot({
        name: finalName,
        role: finalRole,
        role_prompt: finalRolePrompt || finalRole,
        runtime: finalRuntime,
        outbound_rbac: botRbac,
        model: botModel.trim() || "google:gemini-3.8-flash",
        daily_cap: Number.isFinite(parsedCap) ? parsedCap : botRbac === "execute" ? 10 : 0,
        routines: finalRoutines,
        tools: finalTools.length > 0 ? finalTools : undefined,
        collections: {
          read: finalRead,
          write: finalWrite,
        },
        linked_accounts: selectedLinkedAccounts,
        avatar_color: finalAvatarColor,
        avatar_icon: finalAvatarIcon,
        boundaries: finalBoundaries,
        section: botSection.trim() || undefined,
        ...(isMultiUser
          ? {
              visibility: resourceVisibility,
              ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
            }
          : {}),
      });

      setBotBuilderPrompt("");
      setBotName("");
      setBotRole("");
      setBotRolePrompt("");
      setBotModel("google:gemini-3.8-flash");
      setBotDailyCap("0");
      setBotCollectionsRead("");
      setBotCollectionsWrite("");
      setBotDraftedTools([]);
      setBotDraftedRoutines(null);
      setSelectedLinkedAccounts([]);
      setShowAdvancedBotOptions(false);
      setBuilderWarnings([]);
      setBuilderUsedLlm(false);
      setBuilderError(null);
      setShowJsonPreview(false);
      setBotTriggerMode("schedule");
      setBotEventName("");
      setBotBoundaries([]);
      setBotAvatarColor("slate");
      setBotAvatarIcon("bot");
      setBotSection("");
      setBotRuntime("api");
      setRuntimeTouched(false);
      setRestatedSummary(null);
      setBlueprintImportMode(false);
      setBlueprintJson("");
      onClose();
    } catch (err) {
      setBuilderError(err instanceof Error ? err.message : "Failed to create bot.");
    } finally {
      setCreatingBot(false);
    }
  }

  async function submitQuickBot(e: FormEvent) {
    e.preventDefault();
    const cleanName = botName.trim();
    if (!cleanName) {
      setBuilderError("Give your bot a short name to start.");
      return;
    }
    if (isMultiUser && resourceVisibility === "team" && resourceGroups.length === 0) {
      setBuilderError("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setCreatingBot(true);
    setBuilderError(null);
    try {
      const hint = quickBotHint.trim();
      const defaultModelId =
        models.find((m) => m.is_default)?.model_id || "google:gemini-3.8-flash";
      await onCreateBot({
        name: cleanName,
        role: hint || "Workspace automation coworker",
        role_prompt: hint || undefined,
        runtime: "api",
        outbound_rbac: "draft",
        model: defaultModelId,
        daily_cap: 10,
        avatar_color: botAvatarColor,
        avatar_icon: botAvatarIcon,
        section: botSection.trim() || undefined,
        onboarding_mode: "interview",
        ...(isMultiUser
          ? {
              visibility: resourceVisibility,
              ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
            }
          : {}),
      });
      setBotName("");
      setQuickBotHint("");
      setBotSection("");
      onClose();
    } catch (err) {
      setBuilderError(err instanceof Error ? err.message : "Failed to create bot.");
    } finally {
      setCreatingBot(false);
    }
  }

  async function submitTeamRoom(e: FormEvent) {
    e.preventDefault();
    if (!onCreateRoom) return;
    if (!roomTitle.trim()) {
      setBuilderError("Provide a Room title.");
      return;
    }
    if (roomMembers.length < 2 || roomMembers.length > 6) {
      setBuilderError("Select between 2 and 6 bots for a shared Room.");
      return;
    }
    if (isMultiUser && resourceVisibility === "team" && resourceGroups.length === 0) {
      setBuilderError("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setCreatingBot(true);
    setBuilderError(null);
    try {
      await onCreateRoom({
        title: roomTitle.trim(),
        member_bot_slugs: roomMembers,
        coordinator_bot_slug:
          roomCoordinator && roomMembers.includes(roomCoordinator)
            ? roomCoordinator
            : roomMembers[0],
        routing_mode: roomRoutingMode,
        ask_before_bot_handoff: roomAskBeforeHandoff,
        max_bot_turns_per_message: 3,
        section: roomSection.trim() || undefined,
        ...(isMultiUser
          ? {
              visibility: resourceVisibility,
              ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
            }
          : {}),
      });
      onClose();
    } catch (err) {
      setBuilderError(err instanceof Error ? err.message : "Failed to create Room.");
    } finally {
      setCreatingBot(false);
    }
  }

  async function submitImportBlueprint(e: FormEvent) {
    e.preventDefault();
    if (!blueprintJson.trim()) return;
    setCreatingBot(true);
    setBuilderError(null);
    try {
      const parsed = JSON.parse(blueprintJson) as Record<string, unknown>;
      if (
        onImportTeamPack &&
        (parsed.schema_version === "argo.team_pack.v1" || Array.isArray(parsed.bots))
      ) {
        await onImportTeamPack({
          pack: parsed,
          linked_accounts: selectedLinkedAccounts,
        });
      } else if (onImportBlueprint) {
        await onImportBlueprint({
          blueprint: parsed,
          linked_accounts: selectedLinkedAccounts,
        });
      }
      setBlueprintImportMode(false);
      setBlueprintJson("");
      onClose();
    } catch (err) {
      setBuilderError(
        err instanceof Error ? err.message : "Invalid blueprint JSON. Please check formatting.",
      );
    } finally {
      setCreatingBot(false);
    }
  }

  async function submitPipeline(e: FormEvent) {
    e.preventDefault();
    if (!onCreatePipeline || !pipeScoutName.trim() || !pipeWriterName.trim()) return;
    setCreatingBot(true);
    setBuilderError(null);
    try {
      await onCreatePipeline({
        scoutName: pipeScoutName.trim(),
        scoutSource: pipeScoutSource.trim(),
        scoutSchedule: pipeScoutSchedule,
        scoutAccounts: pipeScoutAccounts,
        writerName: pipeWriterName.trim(),
        writerStyle: pipeWriterStyle.trim(),
        writerAccounts: pipeWriterAccounts,
        ...(isMultiUser
          ? {
              visibility: resourceVisibility,
              ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
            }
          : {}),
      });
      setPipelineMode(false);
      onClose();
    } catch (err) {
      setBuilderError(err instanceof Error ? err.message : "Failed to create 2-bot pipeline.");
    } finally {
      setCreatingBot(false);
    }
  }

  async function submitPage(e: FormEvent) {
    e.preventDefault();
    if (!pageTitle.trim()) return;
    const allowed =
      pageSelectedCols.length > 0 ? pageSelectedCols : parseCsvList(pageAllowedCollections);
    await onCreatePage({
      title: pageTitle.trim(),
      description: pageDesc.trim(),
      render_mode: pageMode,
      content_payload: pageCustomPayload.trim() || undefined,
      allowed_collections: allowed,
      ...(isMultiUser
        ? {
            visibility: resourceVisibility,
            ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
          }
        : {}),
    });
    setPageTitle("");
    setPageDesc("");
    setPageAllowedCollections("");
    setPageCustomPayload("");
    setPageSelectedCols([]);
    onClose();
  }

  async function submitGeneratePage(e: FormEvent) {
    e.preventDefault();
    if (!pagePrompt.trim()) return;
    if (!onGeneratePage) {
      await submitPage(e);
      return;
    }
    setGeneratingPage(true);
    try {
      const allowed =
        pageSelectedCols.length > 0 ? pageSelectedCols : parseCsvList(pageAllowedCollections);
      await onGeneratePage({
        prompt: pagePrompt.trim(),
        title: pageTitle.trim() || undefined,
        owner_bot_slug: pageOwnerBot || undefined,
        allowed_collections: allowed,
        template_key: "auto",
        ...(isMultiUser
          ? {
              visibility: resourceVisibility,
              ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
            }
          : {}),
      });
      setPagePrompt("");
      setPageTitle("");
      setPageSelectedCols([]);
      onClose();
    } finally {
      setGeneratingPage(false);
    }
  }

  async function submitApprovalEdit(e: FormEvent, approvalId: string, fallbackText: string) {
    e.preventDefault();
    await onResolveEditedApproval(approvalId, (editText || fallbackText).trim(), editRule.trim());
    setEditText("");
    setEditRule("");
    onClose();
  }

  async function submitIntegration(e: FormEvent) {
    e.preventDefault();
    if (!intSlug.trim() || !intName.trim()) return;
    await onUpsertIntegration({
      slug: intSlug.trim(),
      provider: intProvider,
      display_name: intName.trim(),
      account_identifier: intIdent.trim() || undefined,
      scopes: ["default"],
      secrets: intToken.trim() ? { token: intToken.trim() } : {},
      ...(isMultiUser
        ? {
            visibility: resourceVisibility,
            ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
          }
        : {}),
    });
    setIntSlug("");
    setIntName("");
    setIntIdent("");
    setIntToken("");
    onClose();
  }

  async function submitTelegramOnboard(e: FormEvent) {
    e.preventDefault();
    if (!tgToken.trim()) return;
    const channels = tgChannels
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const publicChannels = tgPublicChannels
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    await onOnboardTelegram({
      bot_token: tgToken.trim(),
      slug: tgSlug.trim() || undefined,
      display_name: tgName.trim() || undefined,
      operator_chat_id: tgChatId.trim() || undefined,
      admin_channels: channels,
      public_channels: publicChannels,
      register_webhook: tgWebhook,
      ...(isMultiUser
        ? {
            visibility: resourceVisibility,
            ...(resourceVisibility === "team" ? { allowed_groups: resourceGroups } : {}),
          }
        : {}),
    });
    setTgToken("");
    setTgSlug("");
    setTgName("");
    setTgChatId("");
    setTgChannels("");
    setTgPublicChannels("");
    setTgWebhook(false);
    onClose();
  }

  async function handleDiscoverModels() {
    setDiscoveringModels(true);
    setDiscoverError(null);
    setDiscoverNote(null);
    try {
      const res = await api.discoverModels({
        provider_type: mdlProvider,
        provider_slug: modal?.type === "new-model" ? modal.initial?.slug : undefined,
        api_key: mdlKey.trim() || undefined,
        api_base: mdlBase.trim() || undefined,
      });
      setDiscoveredModels(res.models);
      setDiscoverNote(res.source_note);
      if (res.models.length === 0) {
        setDiscoverError("No compatible models returned by this provider.");
      }
    } catch (err) {
      setDiscoveredModels([]);
      setDiscoverError(err instanceof Error ? err.message : "Failed to fetch provider models.");
    } finally {
      setDiscoveringModels(false);
    }
  }

  function handleSelectDiscoveredModel(modelId: string) {
    setMdlId(modelId);
    const picked = discoveredModels.find((m) => m.model_id === modelId);
    if (!mdlSlug.trim()) {
      const autoSlug = modelId
        .replace(/[^a-zA-Z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "")
        .toLowerCase()
        .slice(0, 48);
      if (autoSlug) setMdlSlug(autoSlug);
    }
    if (picked) {
      if (picked.pricing_source === "live" || picked.pricing_source === "local") {
        setMdlInputPrice(String(picked.input_price_per_million));
        setMdlOutputPrice(String(picked.output_price_per_million));
      } else if (!mdlInputPrice.trim() && !mdlOutputPrice.trim()) {
        setMdlInputPrice("");
        setMdlOutputPrice("");
      }
    }
  }

  async function submitModel(e: FormEvent) {
    e.preventDefault();
    if (!mdlSlug.trim() || !mdlId.trim()) return;
    const dailyCapNum = mdlDailyLimit.trim() ? Number(mdlDailyLimit.trim()) : undefined;
    const monthlyNum = mdlMonthlyBudget.trim() ? Number(mdlMonthlyBudget.trim()) : undefined;
    const inPriceNum = mdlInputPrice.trim() ? Number(mdlInputPrice.trim()) : undefined;
    const outPriceNum = mdlOutputPrice.trim() ? Number(mdlOutputPrice.trim()) : undefined;
    await onUpsertModel({
      slug: mdlSlug.trim(),
      provider_type: mdlProvider,
      model_id: mdlId.trim(),
      api_base: mdlBase.trim() || undefined,
      api_key: mdlKey.trim() || undefined,
      is_default: mdlDefault,
      daily_token_limit: Number.isFinite(dailyCapNum) ? dailyCapNum : undefined,
      monthly_budget_usd: Number.isFinite(monthlyNum) ? monthlyNum : undefined,
      input_price_per_million: Number.isFinite(inPriceNum) ? inPriceNum : undefined,
      output_price_per_million: Number.isFinite(outPriceNum) ? outPriceNum : undefined,
    });
    setMdlSlug("");
    setMdlBase("");
    setMdlKey("");
    setMdlInputPrice("");
    setMdlOutputPrice("");
    onClose();
  }

  const modalWidthClass =
    modal.type === "selkies"
      ? desktopFullscreen
        ? "w-screen h-[100dvh] max-w-none max-h-none rounded-none border-0 argo-desktop-studio"
        : "w-screen h-[100dvh] sm:w-[96vw] sm:max-w-[1680px] sm:h-[93vh] sm:max-h-[93vh] rounded-none sm:rounded-xl border-0 sm:border argo-desktop-studio"
      : modal.type === "debug"
        ? "sm:max-w-4xl h-[100dvh] sm:h-auto max-h-[100dvh] sm:max-h-[92vh] rounded-none sm:rounded-2xl border-0 sm:border argo-modal-panel"
        : modal.type === "new-bot" || modal.type === "new-page"
          ? "sm:max-w-2xl h-[100dvh] sm:h-auto max-h-[100dvh] sm:max-h-[92vh] rounded-none sm:rounded-2xl border-0 sm:border argo-modal-panel"
          : "sm:max-w-lg h-[100dvh] sm:h-auto max-h-[100dvh] sm:max-h-[92vh] rounded-none sm:rounded-2xl border-0 sm:border argo-modal-panel";

  const canDismissBackdrop =
    modal.type !== "selkies" && !creatingBot && !generatingPage;

  const modelChoices = Array.from(
    new Set([
      "google:gemini-3.8-flash",
      "google:gemini-4-argon",
      ...models.map((m) => m.model_id),
      ...(botModel ? [botModel] : []),
    ]),
  );

  return (
    <div
      className={`fixed inset-0 z-[60] argo-modal-backdrop flex items-center justify-center ${
        modal.type === "selkies"
          ? desktopFullscreen
            ? "p-0"
            : "p-0 sm:p-2 md:p-3"
          : "p-0 sm:p-4"
      }`}
      onClick={(e) => {
        if (canDismissBackdrop && e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className={`w-full ${modalWidthClass} flex flex-col overflow-hidden argo-safe-top argo-safe-bottom`}
      >
        {modal.type === "new-bot" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between shrink-0">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  {newBotTab === "room"
                    ? "New Team Room"
                    : newBotTab === "packs"
                      ? "Team Packs & Blueprints"
                      : "Create Bot"}
                </h2>
                <p className="text-xs text-slate-500">
                  {newBotTab === "quick"
                    ? "Name your bot and shape its role, guardrails, and routines together in chat."
                    : newBotTab === "room"
                      ? "Bring 2 to 6 specialist bots into one shared multi-bot chat room."
                      : newBotTab === "packs"
                        ? "Import a portable Bot Blueprint (argo.bot_blueprint.v1) or Team Pack (argo.team_pack.v1) JSON."
                        : "Configure job instructions, pipelines, models, and collections upfront."}
                </p>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>

            <div className="px-5 pt-2.5 pb-2 border-b border-slate-200 bg-slate-50 flex flex-wrap gap-1.5 shrink-0">
              {(
                [
                  { id: "quick", label: "Quick Setup (Chat)" },
                  { id: "builder", label: "Detailed Builder" },
                  { id: "room", label: "Team Room" },
                  { id: "packs", label: "Import JSON" },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => {
                    setNewBotTab(tab.id);
                    setBuilderError(null);
                    setPipelineMode(false);
                    setBlueprintImportMode(false);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                    newBotTab === tab.id
                      ? "bg-slate-900 text-white shadow-xs"
                      : "bg-white border border-slate-200 text-slate-700 hover:bg-slate-100"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {newBotTab === "quick" && (
              <form onSubmit={submitQuickBot} className="p-5 space-y-4 overflow-y-auto custom-scroll">
                <div className="flex items-center gap-3.5 rounded-xl border border-slate-200 bg-slate-50 p-3.5">
                  <BotAvatar
                    icon={botAvatarIcon}
                    color={botAvatarColor}
                    initials={(botName.trim().slice(0, 2) || "NB").toUpperCase()}
                    size="lg"
                  />
                  <div className="flex-1 min-w-0">
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Bot Name
                    </label>
                    <input
                      type="text"
                      autoFocus
                      required
                      value={botName}
                      onChange={(e) => setBotName(e.target.value)}
                      placeholder="e.g. Research Scout, Inbox Helper, Ops Coordinator"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[11px] font-medium text-slate-600">Color:</span>
                    {[
                      { key: "slate", dot: "bg-slate-700" },
                      { key: "blue", dot: "bg-[#2b5278]" },
                      { key: "emerald", dot: "bg-[#2f6b52]" },
                      { key: "indigo", dot: "bg-[#43536b]" },
                      { key: "violet", dot: "bg-[#55506b]" },
                      { key: "amber", dot: "bg-[#84592b]" },
                      { key: "rose", dot: "bg-[#7d3c45]" },
                    ].map((c) => (
                      <button
                        key={c.key}
                        type="button"
                        onClick={() => setBotAvatarColor(c.key)}
                        title={c.key}
                        className={`w-5 h-5 rounded-full ${c.dot} cursor-pointer transition-transform ${
                          botAvatarColor === c.key
                            ? "ring-2 ring-offset-1 ring-slate-900 scale-110"
                            : "opacity-75 hover:opacity-100"
                        }`}
                      />
                    ))}
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[11px] font-medium text-slate-600 mr-1">Shape:</span>
                    {BOT_ICON_OPTIONS.map(({ key, label, Icon }) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => setBotAvatarIcon(key)}
                        className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg border text-[11px] cursor-pointer ${
                          botAvatarIcon === key
                            ? "border-slate-900 bg-slate-900 text-white"
                            : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <Icon className="w-3 h-3" />
                        <span>{label}</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      What should it help with?{" "}
                      <span className="text-slate-400 font-normal">(optional hint)</span>
                    </label>
                    <input
                      type="text"
                      value={quickBotHint}
                      onChange={(e) => setQuickBotHint(e.target.value)}
                      placeholder="e.g. Watch product release notes or triage my inbox"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Sidebar Group
                    </label>
                    <input
                      type="text"
                      value={botSection}
                      onChange={(e) => setBotSection(e.target.value)}
                      placeholder="e.g. Operations"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                    />
                  </div>
                </div>

                {isMultiUser && (
                  <VisibilityPicker
                    value={resourceVisibility}
                    allowedGroups={resourceGroups}
                    teams={teams}
                    onChange={(vis, groups) => {
                      setResourceVisibility(vis);
                      setResourceGroups(groups);
                    }}
                  />
                )}

                {builderError && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                    {builderError}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creatingBot || !botName.trim()}
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {creatingBot ? "Starting..." : "Start Onboarding Chat"}
                  </button>
                </div>
              </form>
            )}

            {newBotTab === "room" && (
              <form onSubmit={submitTeamRoom} className="p-5 space-y-4 overflow-y-auto custom-scroll">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Room Title
                    </label>
                    <input
                      type="text"
                      required
                      value={roomTitle}
                      onChange={(e) => setRoomTitle(e.target.value)}
                      placeholder="e.g. Content × Coordinator"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Sidebar Group
                    </label>
                    <input
                      type="text"
                      value={roomSection}
                      onChange={(e) => setRoomSection(e.target.value)}
                      placeholder="Optional"
                      className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1.5">
                    Select 2–6 Member Bots ({roomMembers.length} selected)
                  </label>
                  {bots.length < 2 ? (
                    <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-800">
                      Create at least 2 bots (or install a Team Pack) before opening a shared Room.
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {bots.map((b) => {
                        const checked = roomMembers.includes(b.slug);
                        return (
                          <button
                            key={b.slug}
                            type="button"
                            onClick={() => {
                              setRoomMembers((prev) => {
                                const next = prev.includes(b.slug)
                                  ? prev.filter((s) => s !== b.slug)
                                  : prev.length < 6
                                    ? [...prev, b.slug]
                                    : prev;
                                if (next.length > 0 && !next.includes(roomCoordinator)) {
                                  setRoomCoordinator(next[0]);
                                }
                                return next;
                              });
                            }}
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-full border text-xs cursor-pointer ${
                              checked
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                            }`}
                          >
                            <span>{b.name}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {roomMembers.length >= 2 && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-slate-900 mb-1">
                        Speaker Routing
                      </label>
                      <select
                        value={roomRoutingMode}
                        onChange={(e) =>
                          setRoomRoutingMode(e.target.value as "auto" | "lead" | "stage")
                        }
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                      >
                        <option value="auto">Auto-Pick Best Bot</option>
                        <option value="lead">Lead / Coordinator First</option>
                        <option value="stage">Fixed Stage Order</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-900 mb-1">
                        Lead Coordinator (fallback when lead speaks first)
                      </label>
                      <select
                        value={roomCoordinator || roomMembers[0]}
                        onChange={(e) => setRoomCoordinator(e.target.value)}
                        className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-slate-900"
                      >
                        {roomMembers.map((mSlug) => {
                          const b = bots.find((item) => item.slug === mSlug);
                          return (
                            <option key={mSlug} value={mSlug}>
                              {b ? b.name : mSlug}
                            </option>
                          );
                        })}
                      </select>
                    </div>
                  </div>
                )}

                <label className="flex items-start gap-2.5 rounded-xl border border-slate-200 bg-slate-50 p-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={roomAskBeforeHandoff}
                    onChange={(e) => setRoomAskBeforeHandoff(e.target.checked)}
                    className="mt-0.5"
                  />
                  <div>
                    <div className="text-xs font-medium text-slate-900">
                      Ask me before one bot triggers another in this Room
                    </div>
                    <div className="text-[11px] text-slate-500">
                      When enabled, bots show a 1-click approval chip before an `@mention` handoff executes automatically.
                    </div>
                  </div>
                </label>

                {isMultiUser && (
                  <VisibilityPicker
                    value={resourceVisibility}
                    allowedGroups={resourceGroups}
                    teams={teams}
                    onChange={(vis, groups) => {
                      setResourceVisibility(vis);
                      setResourceGroups(groups);
                    }}
                  />
                )}

                {builderError && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                    {builderError}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={
                      creatingBot ||
                      !roomTitle.trim() ||
                      roomMembers.length < 2 ||
                      roomMembers.length > 6
                    }
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {creatingBot ? "Creating Room..." : "Create Room"}
                  </button>
                </div>
              </form>
            )}

            {newBotTab === "packs" && (
              <div className="p-5 space-y-4 overflow-y-auto custom-scroll">
                {integrations.length > 0 && (
                  <div className="space-y-1.5 rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <div className="text-[11px] font-semibold text-slate-800">
                      Map Local Integrations (Optional)
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {integrations.map((acc) => {
                        const checked = selectedLinkedAccounts.includes(acc.slug);
                        return (
                          <button
                            key={acc.slug}
                            type="button"
                            onClick={() =>
                              setSelectedLinkedAccounts((prev) =>
                                prev.includes(acc.slug)
                                  ? prev.filter((s) => s !== acc.slug)
                                  : [...prev, acc.slug],
                              )
                            }
                            className={`px-2.5 py-1 rounded-full border text-[11px] cursor-pointer ${
                              checked
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-700"
                            }`}
                          >
                            {acc.display_name} ({acc.provider})
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                <form onSubmit={submitImportBlueprint} className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <label className="text-xs font-semibold text-slate-900">
                      Import Team Pack or Bot Blueprint (.json)
                    </label>
                    <label className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] font-medium text-slate-700 hover:bg-slate-50 cursor-pointer">
                      Choose .json File
                      <input
                        type="file"
                        accept=".json,application/json"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (!file) return;
                          file.text().then((txt) => setBlueprintJson(txt));
                        }}
                      />
                    </label>
                  </div>
                  <textarea
                    rows={5}
                    value={blueprintJson}
                    onChange={(e) => setBlueprintJson(e.target.value)}
                    placeholder='Paste argo.team_pack.v1 or argo.bot_blueprint.v1 JSON (zero secrets included)...'
                    className="w-full rounded-lg border border-slate-200 bg-white p-2.5 text-xs font-mono"
                  />
                  {builderError && (
                    <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                      {builderError}
                    </div>
                  )}
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={onClose}
                      className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={creatingBot || !blueprintJson.trim()}
                      className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                    >
                      {creatingBot ? "Importing..." : "Import Pack / Blueprint"}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {newBotTab === "builder" && (
              <>
            <div className="px-5 py-2.5 border-b border-slate-100 bg-slate-50 flex flex-wrap items-center justify-between gap-2 shrink-0">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setBlueprintImportMode(false);
                    setPipelineMode(false);
                    setBuilderError(null);
                  }}
                  className={`px-3 py-1 rounded-full border text-[11px] font-medium cursor-pointer ${
                    !pipelineMode
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-200 bg-white text-slate-700 hover:bg-slate-100"
                  }`}
                >
                  Single Bot
                </button>
                {onCreatePipeline && (
                  <button
                    type="button"
                    onClick={() => {
                      setBlueprintImportMode(false);
                      setPipelineMode(true);
                      setBuilderError(null);
                    }}
                    className={`px-3 py-1 rounded-full border text-[11px] font-medium cursor-pointer ${
                      pipelineMode
                        ? "border-emerald-700 bg-emerald-700 text-white"
                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-100"
                    }`}
                  >
                    2-Bot Pipeline
                  </button>
                )}
              </div>
              {onImportBlueprint && (
                <button
                  type="button"
                  onClick={() => {
                    setNewBotTab("packs");
                    setBuilderError(null);
                  }}
                  className="px-2.5 py-1 rounded-full border border-slate-200 bg-white text-slate-700 hover:bg-slate-100 text-[11px] font-medium cursor-pointer"
                >
                  Import JSON
                </button>
              )}
            </div>

            {pipelineMode ? (
              <form
                onSubmit={submitPipeline}
                className="p-5 space-y-4 overflow-y-auto custom-scroll"
              >
                <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs text-emerald-900">
                  Creates two linked bots in one step: the <strong>Scout</strong> gathers relevant
                  items on schedule and automatically hands them off to the <strong>Writer</strong>{" "}
                  for polished drafts in <strong>Approvals</strong>.
                </div>

                <div className="rounded-xl border border-slate-200 p-3.5 space-y-3">
                  <div className="text-xs font-semibold text-slate-900">
                    1. Scout Bot (Collects &amp; Filters)
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    <input
                      type="text"
                      required
                      value={pipeScoutName}
                      onChange={(e) => setPipeScoutName(e.target.value)}
                      placeholder="Scout name"
                      className="sm:col-span-2 rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                    <select
                      value={pipeScoutSchedule}
                      onChange={(e) => setPipeScoutSchedule(e.target.value)}
                      className="rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs bg-white"
                    >
                      <option value="Every 15m">Every 15m</option>
                      <option value="Every 1h">Every 1h</option>
                      <option value="Every 24h">Every 24h</option>
                      <option value="Manual">Manual</option>
                    </select>
                  </div>
                  <textarea
                    rows={2}
                    value={pipeScoutSource}
                    onChange={(e) => setPipeScoutSource(e.target.value)}
                    placeholder="What emails, websites, or channels should the Scout check?"
                    className="w-full rounded-lg border border-slate-200 p-2.5 text-xs"
                  />
                  {integrations.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {integrations.map((acc) => {
                        const checked = pipeScoutAccounts.includes(acc.slug);
                        return (
                          <button
                            key={acc.slug}
                            type="button"
                            onClick={() =>
                              setPipeScoutAccounts((prev) =>
                                prev.includes(acc.slug)
                                  ? prev.filter((s) => s !== acc.slug)
                                  : [...prev, acc.slug],
                              )
                            }
                            className={`px-2.5 py-1 rounded-full border text-[11px] cursor-pointer ${
                              checked
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-700"
                            }`}
                          >
                            {acc.display_name}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-slate-200 p-3.5 space-y-3">
                  <div className="text-xs font-semibold text-slate-900">
                    2. Writer Bot (Crafts Stories for Approvals)
                  </div>
                  <input
                    type="text"
                    required
                    value={pipeWriterName}
                    onChange={(e) => setPipeWriterName(e.target.value)}
                    placeholder="Writer name (e.g. Story Writer)"
                    className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                  />
                  <textarea
                    rows={2}
                    value={pipeWriterStyle}
                    onChange={(e) => setPipeWriterStyle(e.target.value)}
                    placeholder="How should the Writer craft the story and where should drafts go?"
                    className="w-full rounded-lg border border-slate-200 p-2.5 text-xs"
                  />
                  {integrations.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 items-center">
                      <span className="text-[11px] text-slate-500 mr-1">Draft via:</span>
                      {integrations.map((acc) => {
                        const checked = pipeWriterAccounts.includes(acc.slug);
                        return (
                          <button
                            key={acc.slug}
                            type="button"
                            onClick={() =>
                              setPipeWriterAccounts((prev) =>
                                prev.includes(acc.slug)
                                  ? prev.filter((s) => s !== acc.slug)
                                  : [...prev, acc.slug],
                              )
                            }
                            className={`px-2.5 py-1 rounded-full border text-[11px] cursor-pointer ${
                              checked
                                ? "border-slate-900 bg-slate-900 text-white"
                                : "border-slate-200 bg-white text-slate-700"
                            }`}
                          >
                            {acc.display_name}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {builderError && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                    {builderError}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-1">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creatingBot}
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {creatingBot ? "Creating Pipeline..." : "Create 2-Bot Pipeline"}
                  </button>
                </div>
              </form>
            ) : blueprintImportMode ? (
              <form
                onSubmit={submitImportBlueprint}
                className="p-5 space-y-4 overflow-y-auto custom-scroll"
              >
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Sanitized Bot Blueprint JSON
                  </label>
                  <p className="text-[11px] text-slate-500 mb-2">
                    Paste an exported Argo bot blueprint. Secret credentials are never included in
                    exports — select local integrations below after pasting.
                  </p>
                  <textarea
                    rows={8}
                    value={blueprintJson}
                    onChange={(e) => setBlueprintJson(e.target.value)}
                    placeholder='{"blueprint_version":"1.0","bot":{"name":"...","role_prompt":"..."}}'
                    className="w-full rounded-lg border border-slate-200 bg-white p-2.5 text-xs font-mono"
                  />
                </div>
                {builderError && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                    {builderError}
                  </div>
                )}
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creatingBot || !blueprintJson.trim()}
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {creatingBot ? "Importing..." : "Import Blueprint"}
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={submitBot} className="p-5 space-y-4 overflow-y-auto custom-scroll">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Bot Name{" "}
                      <span className="text-slate-400 font-normal">
                        (optional — smart-named automatically)
                      </span>
                    </label>
                    <input
                      type="text"
                      value={botName}
                      onChange={(e) => setBotName(e.target.value)}
                      placeholder="e.g. Release Notes Monitor"
                      className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Sidebar Group
                    </label>
                    <input
                      type="text"
                      value={botSection}
                      onChange={(e) => setBotSection(e.target.value)}
                      placeholder="e.g. Content, Ops"
                      className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[11px] font-medium text-slate-600">Color:</span>
                    {[
                      { key: "slate", dot: "bg-slate-700" },
                      { key: "blue", dot: "bg-[#2b5278]" },
                      { key: "emerald", dot: "bg-[#2f6b52]" },
                      { key: "indigo", dot: "bg-[#43536b]" },
                      { key: "violet", dot: "bg-[#55506b]" },
                      { key: "amber", dot: "bg-[#84592b]" },
                      { key: "rose", dot: "bg-[#7d3c45]" },
                    ].map((c) => (
                      <button
                        key={c.key}
                        type="button"
                        onClick={() => setBotAvatarColor(c.key)}
                        title={c.key}
                        className={`w-5 h-5 rounded-full ${c.dot} cursor-pointer transition-transform ${
                          botAvatarColor === c.key
                            ? "ring-2 ring-offset-2 ring-slate-900 scale-110"
                            : "opacity-75 hover:opacity-100"
                        }`}
                      />
                    ))}
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[11px] font-medium text-slate-600 mr-0.5">Icon:</span>
                    {BOT_ICON_OPTIONS.map(({ key, label, Icon }) => (
                      <button
                        key={key}
                        type="button"
                        title={label}
                        onClick={() => setBotAvatarIcon(key)}
                        className={`p-1.5 rounded-lg border cursor-pointer ${
                          botAvatarIcon === key
                            ? "border-slate-900 bg-slate-900 text-white"
                            : "border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5" />
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <label className="block text-xs font-medium text-slate-900">
                      What should this bot do?
                    </label>
                    <div className="flex items-center gap-2">
                      {builderUsedLlm && (
                        <span className="px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-[10px] font-medium text-emerald-700">
                          Ready
                        </span>
                      )}
                      <button
                        type="button"
                        disabled={synthesizingBot || !(botRolePrompt.trim() || botBuilderPrompt.trim())}
                        onClick={() => void handleSynthesizeBot()}
                        className="px-2.5 py-1 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-[11px] font-medium text-slate-700 disabled:opacity-50 cursor-pointer"
                      >
                        {synthesizingBot ? "Reading..." : "Preview Understanding"}
                      </button>
                    </div>
                  </div>
                  <textarea
                    rows={4}
                    value={botRolePrompt}
                    onChange={(e) => {
                      setBotRolePrompt(e.target.value);
                      setBotBuilderPrompt(e.target.value);
                    }}
                    placeholder="Ramble naturally in plain English — e.g. Monitor https://news.example.com/feed, ignore case studies, save new articles, and send me a short Telegram digest for approval."
                    className="w-full rounded-lg border border-slate-200 bg-white p-2.5 text-xs"
                  />

                  {restatedSummary && (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-1.5 text-xs">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-700">
                        Bot Understanding Preview
                      </div>
                      <div className="text-slate-800">
                        <span className="font-medium">Job:</span> {restatedSummary.job}
                      </div>
                      <div className="flex flex-wrap gap-3 text-[11px] text-slate-700">
                        <span>
                          <span className="font-medium">Schedule:</span> {restatedSummary.schedule}
                        </span>
                        <span>
                          <span className="font-medium">Autonomy:</span> {restatedSummary.autonomy}
                        </span>
                      </div>
                      {(botBoundaries.length > 0 || restatedSummary.boundaries.length > 0) && (
                        <div className="pt-1">
                          <div className="text-[11px] font-medium text-slate-800 mb-0.5">
                            Boundaries (Never-Do Rules):
                          </div>
                          <ul className="list-disc pl-4 space-y-0.5 text-[11px] text-slate-700">
                            {(botBoundaries.length > 0
                              ? botBoundaries
                              : restatedSummary.boundaries
                            ).map((b, i) => (
                              <li key={i}>{b}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {builderError && (
                    <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                      {builderError}
                    </div>
                  )}
                  {builderWarnings.length > 0 && (
                    <div className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-[11px] text-amber-900 space-y-1">
                      <div className="font-semibold">Notes</div>
                      <ul className="list-disc pl-4 space-y-0.5">
                        {builderWarnings.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <div>
                    <div className="text-xs font-medium text-slate-900">Connected Apps</div>
                    <p className="text-[11px] text-slate-500">
                      Only checked accounts can be read or messaged by this bot.
                    </p>
                  </div>
                  {integrations.length === 0 ? (
                    <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-2.5 text-[11px] text-slate-500">
                      No accounts connected yet. You can connect Google or Telegram anytime in
                      Settings.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-40 overflow-y-auto pr-1">
                      {integrations.map((acc) => {
                        const checked = selectedLinkedAccounts.includes(acc.slug);
                        return (
                          <label
                            key={acc.id}
                            className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs cursor-pointer transition-colors ${
                              checked
                                ? "border-slate-900 bg-slate-50"
                                : "border-slate-200 bg-white hover:bg-slate-50"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggleLinkedAccount(acc.slug)}
                              className="mt-0.5"
                            />
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-1.5">
                                <span
                                  className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                    acc.status === "connected" ? "bg-emerald-500" : "bg-amber-500"
                                  }`}
                                />
                                <span className="font-medium text-slate-900 truncate">
                                  {acc.display_name}
                                </span>
                                <span className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] font-mono text-slate-600 uppercase shrink-0">
                                  {acc.provider}
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-500 truncate mt-0.5">
                                {acc.account_identifier || acc.slug}
                              </div>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-900">
                    Execution Environment:
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {[
                      {
                        value: "api" as const,
                        title: "Cloud API (Fast, 0 MB)",
                        desc: "Direct connected APIs & MCP tools with zero container RAM",
                      },
                      {
                        value: "sandbox" as const,
                        title: "Script Sandbox (512 MB CLI)",
                        desc: "Isolated Fedora 45 CLI container with Python 3, curl, jq & /workspace",
                      },
                      {
                        value: "desktop" as const,
                        title: "Virtual Desktop (2 GB GUI)",
                        desc: "Dedicated Fedora XFCE desktop with Chromium, GUI apps & live screen",
                      },
                    ].map((opt) => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => {
                          setBotRuntime(opt.value);
                          setRuntimeTouched(true);
                          setBotDraftedRoutines(null);
                          if (opt.value === "sandbox" && botAvatarIcon === "bot") {
                            setBotAvatarColor("emerald");
                            setBotAvatarIcon("terminal");
                          } else if (opt.value === "desktop" && botAvatarIcon === "bot") {
                            setBotAvatarColor("amber");
                            setBotAvatarIcon("globe");
                          }
                        }}
                        className={`text-left rounded-lg border px-3 py-2 cursor-pointer transition-colors ${
                          botRuntime === opt.value
                            ? "border-slate-900 bg-slate-900 text-white"
                            : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <div className="text-xs font-medium">{opt.title}</div>
                        <div
                          className={`text-[10px] ${
                            botRuntime === opt.value ? "text-slate-300" : "text-slate-500"
                          }`}
                        >
                          {opt.desc}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-slate-900">
                    When sending messages or taking external actions:
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {[
                      {
                        value: "draft" as const,
                        title: "Ask Before Sending",
                        desc: "Queues drafts in Approvals for human review",
                      },
                      {
                        value: "internal" as const,
                        title: "Read & Organize Only",
                        desc: "Saves notes privately; never sends",
                      },
                      {
                        value: "execute" as const,
                        title: "Send Automatically",
                        desc: "Auto-sends within your daily limit",
                      },
                    ].map((opt) => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => setBotRbac(opt.value)}
                        className={`text-left rounded-lg border px-3 py-2 cursor-pointer transition-colors ${
                          botRbac === opt.value
                            ? "border-slate-900 bg-slate-900 text-white"
                            : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <div className="text-xs font-medium">{opt.title}</div>
                        <div
                          className={`text-[10px] ${
                            botRbac === opt.value ? "text-slate-300" : "text-slate-500"
                          }`}
                        >
                          {opt.desc}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="rounded-lg border border-slate-200 bg-slate-50">
                  <button
                    type="button"
                    onClick={() => setShowAdvancedBotOptions((prev) => !prev)}
                    className="w-full px-3 py-2 text-left text-xs font-medium text-slate-700 flex items-center justify-between cursor-pointer hover:bg-slate-100"
                  >
                    <span>Advanced Options (Model, Schedule, Boundaries, JSON)</span>
                    <span className="text-[11px] text-slate-500">
                      {showAdvancedBotOptions ? "Hide" : "Show"}
                    </span>
                  </button>
                  {showAdvancedBotOptions && (
                    <div className="p-3.5 border-t border-slate-200 space-y-3 bg-white rounded-b-lg">
                      <div>
                        <label className="block text-xs font-medium text-slate-900 mb-1">
                          Short Role Summary (optional)
                        </label>
                        <input
                          type="text"
                          value={botRole}
                          onChange={(e) => setBotRole(e.target.value)}
                          placeholder="Short 1-line role description"
                          className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-medium text-slate-900 mb-1">
                          Never-Do Boundaries (one rule per line)
                        </label>
                        <textarea
                          rows={2}
                          value={botBoundaries.join("\n")}
                          onChange={(e) =>
                            setBotBoundaries(
                              e.target.value
                                .split("\n")
                                .map((s) => s.trim())
                                .filter(Boolean),
                            )
                          }
                          placeholder="Never publish without human approval&#10;Never include private client names"
                          className="w-full rounded-lg border border-slate-200 p-2 text-xs"
                        />
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            AI Model
                          </label>
                          <select
                            value={botModel}
                            onChange={(e) => setBotModel(e.target.value)}
                            className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs bg-white"
                          >
                            {modelChoices.map((m) => (
                              <option key={m} value={m}>
                                {friendlyModelName(m)}
                              </option>
                            ))}
                          </select>
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Where It Runs
                          </label>
                          <select
                            value={botRuntime}
                            onChange={(e) => {
                              setBotRuntime(e.target.value as "api" | "sandbox" | "desktop");
                              setRuntimeTouched(true);
                              setBotDraftedRoutines(null);
                            }}
                            className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs bg-white"
                          >
                            <option value="api">Cloud API (Fast, 0 MB)</option>
                            <option value="sandbox">Script Sandbox (512 MB CLI)</option>
                            <option value="desktop">Dedicated Virtual Desktop</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Daily Send Limit
                          </label>
                          <input
                            type="number"
                            min={0}
                            max={1000}
                            value={botDailyCap}
                            onChange={(e) => setBotDailyCap(e.target.value)}
                            className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-mono"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Trigger
                          </label>
                          <select
                            value={botTriggerMode}
                            onChange={(e) => {
                              setBotTriggerMode(e.target.value as "schedule" | "on_event");
                              setBotDraftedRoutines(null);
                            }}
                            className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs bg-white"
                          >
                            <option value="schedule">Every 15 minutes</option>
                            <option value="on_event">When an event happens</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Event Name
                          </label>
                          <input
                            type="text"
                            disabled={botTriggerMode !== "on_event"}
                            value={botEventName}
                            onChange={(e) => {
                              setBotEventName(e.target.value);
                              setBotDraftedRoutines(null);
                            }}
                            placeholder="e.g. approval.queued, news.collected"
                            className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs disabled:bg-slate-50 disabled:text-slate-400"
                          />
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Read From Lists (comma-separated)
                          </label>
                          <input
                            type="text"
                            value={botCollectionsRead}
                            onChange={(e) => setBotCollectionsRead(e.target.value)}
                            placeholder="e.g. tech_news, releases"
                            className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-mono"
                          />
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-slate-900 mb-1">
                            Save Into Lists (comma-separated)
                          </label>
                          <input
                            type="text"
                            value={botCollectionsWrite}
                            onChange={(e) => setBotCollectionsWrite(e.target.value)}
                            placeholder="e.g. editorial_briefs"
                            className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-mono"
                          />
                        </div>
                      </div>

                      <div className="rounded-lg border border-slate-200 bg-slate-50">
                        <button
                          type="button"
                          onClick={() => setShowJsonPreview((prev) => !prev)}
                          className="w-full px-3 py-1.5 text-left text-[11px] font-medium text-slate-700 flex items-center justify-between cursor-pointer hover:bg-slate-100"
                        >
                          <span>Show Raw JSON</span>
                          <span>{showJsonPreview ? "Hide" : "Show"}</span>
                        </button>
                        {showJsonPreview && (
                          <pre className="p-3 border-t border-slate-200 bg-slate-900 text-slate-100 text-xs font-mono overflow-x-auto max-h-48">
                            {JSON.stringify(liveBotSpecPreview, null, 2)}
                          </pre>
                        )}
                      </div>
                    </div>
                  )}
                </div>

                {isMultiUser && (
                  <VisibilityPicker
                    value={resourceVisibility}
                    allowedGroups={resourceGroups}
                    teams={teams}
                    onChange={(vis, groups) => {
                      setResourceVisibility(vis);
                      setResourceGroups(groups);
                    }}
                  />
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={
                      creatingBot ||
                      (!botName.trim() && !(botRolePrompt.trim() || botBuilderPrompt.trim() || botRole.trim()))
                    }
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {creatingBot ? "Creating Bot..." : "Create Bot"}
                  </button>
                </div>
              </form>
            )}
              </>
            )}
          </>
        )}

        {modal.type === "new-page" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between shrink-0">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">Create Living Page</h2>
                <p className="text-xs text-slate-500">
                  Build an interactive view or simulator from plain English and edit it live with a bot.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPageManualMode((v) => !v)}
                  className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
                >
                  {pageManualMode ? "Prompt & Templates" : "Manual JSON / HTML"}
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
                >
                  <X className="w-3.5 h-3.5" />
                  Close
                </button>
              </div>
            </div>

            {!pageManualMode ? (
              <form
                onSubmit={submitGeneratePage}
                className="p-5 space-y-4 overflow-y-auto custom-scroll"
              >
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    What should this Page show or let users explore?
                  </label>
                  <textarea
                    rows={4}
                    required
                    value={pagePrompt}
                    onChange={(e) => setPagePrompt(e.target.value)}
                    placeholder="e.g. Build a searchable table and chart of saved items, an executive PDF summary, or a live status overview..."
                    className="w-full rounded-lg border border-slate-200 bg-white p-2.5 text-xs"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Title <span className="text-slate-400 font-normal">(optional)</span>
                    </label>
                    <input
                      type="text"
                      value={pageTitle}
                      onChange={(e) => setPageTitle(e.target.value)}
                      placeholder="e.g. Live Fleet Map"
                      className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Owner Bot (conversational editor)
                    </label>
                    <select
                      value={pageOwnerBot}
                      onChange={(e) => {
                        const nextOwner = e.target.value;
                        setPageOwnerBot(nextOwner);
                        if (!pageColsTouched) {
                          const hiddenSet = new Set([
                            "oauth_pending_states",
                            "http_feed_cache",
                            "debug_run_traces",
                            "bot_threads",
                            "desktop_snapshots",
                            "bot_skills",
                            "ingestion_seen_keys",
                            "vault_secrets",
                          ]);
                          const matching = collections
                            .filter(
                              (c) =>
                                !c.is_internal &&
                                !hiddenSet.has(c.slug) &&
                                c.owner_bot_slug === nextOwner,
                            )
                            .map((c) => c.slug);
                          setPageSelectedCols(matching);
                        }
                      }}
                      className="w-full rounded-lg border border-slate-200 px-2.5 py-2 text-xs bg-white"
                    >
                      <option value="">Unassigned (Workspace Page)</option>
                      {bots.map((b) => (
                        <option key={b.slug} value={b.slug}>
                          {b.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Data Lists this Page can read
                  </label>
                  {(() => {
                    const internalCols = new Set([
                      "oauth_pending_states",
                      "http_feed_cache",
                      "debug_run_traces",
                      "bot_threads",
                      "desktop_snapshots",
                      "bot_skills",
                      "ingestion_seen_keys",
                      "vault_secrets",
                    ]);
                    const visibleCols = collections.filter(
                      (c) => !c.is_internal && !internalCols.has(c.slug),
                    );
                    return visibleCols.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {visibleCols.map((c) => {
                          const selected = pageSelectedCols.includes(c.slug);
                          return (
                            <button
                              key={c.slug}
                              type="button"
                              onClick={() => {
                                setPageColsTouched(true);
                                setPageSelectedCols((prev) =>
                                  prev.includes(c.slug)
                                    ? prev.filter((item) => item !== c.slug)
                                    : [...prev, c.slug],
                                );
                              }}
                              title={c.slug}
                              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-[11px] font-medium cursor-pointer transition-colors ${
                                selected
                                  ? "border-slate-900 bg-slate-900 text-white"
                                  : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                              }`}
                            >
                              <span>{c.label || c.slug}</span>
                              {c.owner_bot_name && (
                                <span className={selected ? "text-slate-300" : "text-slate-400"}>
                                  · {c.owner_bot_name}
                                </span>
                              )}
                              <span
                                className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                                  selected
                                    ? "bg-slate-700 text-white"
                                    : "bg-slate-100 text-slate-600"
                                }`}
                              >
                                {c.doc_count}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="rounded-lg border border-dashed border-slate-200 p-2.5 text-[11px] text-slate-500">
                        Your bots haven&apos;t saved custom data lists yet — Pages can still show live bot status or interactive playgrounds.
                      </div>
                    );
                  })()}
                </div>

                {isMultiUser && (
                  <VisibilityPicker
                    value={resourceVisibility}
                    allowedGroups={resourceGroups}
                    teams={teams}
                    onChange={(vis, groups) => {
                      setResourceVisibility(vis);
                      setResourceGroups(groups);
                    }}
                  />
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={generatingPage || !pagePrompt.trim()}
                    className="bg-slate-900 text-white px-4 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                  >
                    {generatingPage ? "Building Page..." : "Build Living Page"}
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={submitPage} className="p-5 space-y-4 overflow-y-auto custom-scroll">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Page Title</label>
                  <input
                    type="text"
                    required
                    value={pageTitle}
                    onChange={(e) => setPageTitle(e.target.value)}
                    placeholder="e.g. Monthly Operations"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Description</label>
                  <input
                    type="text"
                    value={pageDesc}
                    onChange={(e) => setPageDesc(e.target.value)}
                    placeholder="Operational summary view"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Render Mode
                    </label>
                    <select
                      value={pageMode}
                      onChange={(e) =>
                        setPageMode(e.target.value as "declarative_json" | "sandboxed_html")
                      }
                      className="w-full rounded-lg border border-slate-200 px-2.5 py-2 text-xs bg-white"
                    >
                      <option value="declarative_json">Declarative JSON Blocks</option>
                      <option value="sandboxed_html">Interactive Sandboxed HTML</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-900 mb-1">
                      Data Lists (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={pageAllowedCollections}
                      onChange={(e) => setPageAllowedCollections(e.target.value)}
                      placeholder="e.g. tech_news, releases"
                      className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Optional Custom{" "}
                    {pageMode === "sandboxed_html" ? "HTML" : "JSON"} Payload
                  </label>
                  <textarea
                    rows={4}
                    value={pageCustomPayload}
                    onChange={(e) => setPageCustomPayload(e.target.value)}
                    placeholder={
                      pageMode === "sandboxed_html"
                        ? "Leave blank to use default interactive dashboard template..."
                        : '{"description":"...", "blocks":[{"label":"KPI","value":"0"}], "rows":[]}'
                    }
                    className="w-full rounded-lg border border-slate-200 p-2.5 text-xs font-mono"
                  />
                </div>
                {isMultiUser && (
                  <VisibilityPicker
                    value={resourceVisibility}
                    allowedGroups={resourceGroups}
                    teams={teams}
                    onChange={(vis, groups) => {
                      setResourceVisibility(vis);
                      setResourceGroups(groups);
                    }}
                  />
                )}

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={onClose}
                    className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer"
                  >
                    Create Page
                  </button>
                </div>
              </form>
            )}
          </>
        )}

        {modal.type === "edit-approval" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  Edit Draft &amp; Teach Style Preference
                </h2>
                <p className="text-xs text-slate-500">{modal.item.target_account_slug}</p>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>
            <form
              onSubmit={(e) =>
                submitApprovalEdit(e, modal.item.id, modal.item.payload.text ?? "")
              }
              className="p-5 space-y-4 overflow-y-auto custom-scroll"
            >
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">Draft Text</label>
                <textarea
                  rows={4}
                  value={editText}
                  onChange={(e) => setEditText(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 p-2.5 text-xs"
                />
              </div>
              {editText !== (modal.item.payload.text ?? "") && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">
                    Highlighted Changes
                  </div>
                  <div className="text-xs leading-relaxed">
                    {computeWordDiff(modal.item.payload.text ?? "", editText).map((tok, idx) =>
                      tok.type === "same" ? (
                        <span key={idx}>{tok.text}</span>
                      ) : tok.type === "del" ? (
                        <span
                          key={idx}
                          className="bg-rose-100 text-rose-800 line-through px-0.5 rounded"
                        >
                          {tok.text}
                        </span>
                      ) : (
                        <span key={idx} className="bg-emerald-100 text-emerald-800 px-0.5 rounded">
                          {tok.text}
                        </span>
                      ),
                    )}
                  </div>
                </div>
              )}
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  Preference Saved for Future Runs
                </label>
                <input
                  type="text"
                  value={editRule}
                  onChange={(e) => setEditRule(e.target.value)}
                  placeholder="Optional concise rule (auto-learned from your edit if blank)..."
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer"
                >
                  Save Rule &amp; Approve
                </button>
              </div>
            </form>
          </>
        )}

        {modal.type === "new-integration" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">Add Integration Connector</h2>
              <button
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>
            <form onSubmit={submitIntegration} className="p-5 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Slug</label>
                  <input
                    type="text"
                    required
                    value={intSlug}
                    onChange={(e) => setIntSlug(e.target.value)}
                    placeholder={intProvider === "mcp" ? "mcp_github" : "tg_main"}
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Provider</label>
                  <select
                    value={intProvider}
                    onChange={(e) =>
                      setIntProvider(
                        e.target.value as "google" | "telegram" | "linkedin" | "webhook" | "mcp",
                      )
                    }
                    className="w-full rounded-lg border border-slate-200 px-2.5 py-2 text-xs bg-white"
                  >
                    <option value="telegram">Telegram</option>
                    <option value="google">Google</option>
                    <option value="linkedin">LinkedIn</option>
                    <option value="webhook">Webhook</option>
                    <option value="mcp">MCP</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  Display Name
                </label>
                <input
                  type="text"
                  required
                  value={intName}
                  onChange={(e) => setIntName(e.target.value)}
                  placeholder={intProvider === "mcp" ? "GitHub MCP Server" : "Community Telegram Bot"}
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  {intProvider === "mcp"
                    ? "MCP Endpoint URL (Streamable HTTP JSON-RPC 2.0)"
                    : "Identifier (email, @handle, or URL)"}
                </label>
                <input
                  type="text"
                  required={intProvider === "mcp"}
                  value={intIdent}
                  onChange={(e) => setIntIdent(e.target.value)}
                  placeholder={intProvider === "mcp" ? "https://mcp.example.com/rpc" : "@argo_ops_bot"}
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  {intProvider === "mcp"
                    ? "Bearer Token (optional, encrypted via Fernet)"
                    : "Credential / Token (encrypted via Fernet)"}
                </label>
                <input
                  type="password"
                  value={intToken}
                  onChange={(e) => setIntToken(e.target.value)}
                  placeholder={intProvider === "mcp" ? "Optional Bearer secret" : "Optional token or secret"}
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
              {isMultiUser && (
                <VisibilityPicker
                  value={resourceVisibility}
                  allowedGroups={resourceGroups}
                  teams={teams}
                  onChange={(vis, groups) => {
                    setResourceVisibility(vis);
                    setResourceGroups(groups);
                  }}
                />
              )}
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer"
                >
                  Save Connector
                </button>
              </div>
            </form>
          </>
        )}

        {modal.type === "telegram-onboard" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  Connect Telegram Bot (aiogram v3.31.0)
                </h2>
                <p className="text-xs text-slate-500">
                  Validates via Bot API getMe and encrypts credentials with Fernet
                </p>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>
            <form onSubmit={submitTelegramOnboard} className="p-5 space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  BotFather Token
                </label>
                <input
                  type="password"
                  required
                  value={tgToken}
                  onChange={(e) => setTgToken(e.target.value)}
                  placeholder="123456789:AA..."
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Operator Alert Chat ID
                  </label>
                  <input
                    type="text"
                    value={tgChatId}
                    onChange={(e) => setTgChatId(e.target.value)}
                    placeholder="e.g. 987654321"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Connector Slug (optional)
                  </label>
                  <input
                    type="text"
                    value={tgSlug}
                    onChange={(e) => setTgSlug(e.target.value)}
                    placeholder="tg_main"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Display Name (optional)
                  </label>
                  <input
                    type="text"
                    value={tgName}
                    onChange={(e) => setTgName(e.target.value)}
                    placeholder="Argo Operations Bot"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Admin Channels (optional)
                  </label>
                  <input
                    type="text"
                    value={tgChannels}
                    onChange={(e) => setTgChannels(e.target.value)}
                    placeholder="@community_updates"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-900 mb-1">
                  Public Channels (t.me/s/ preview, optional)
                </label>
                <input
                  type="text"
                  value={tgPublicChannels}
                  onChange={(e) => setTgPublicChannels(e.target.value)}
                  placeholder="@telegram, @durov"
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={tgWebhook}
                  onChange={(e) => setTgWebhook(e.target.checked)}
                />
                Register HTTPS webhook endpoint with Bot API
              </label>
              {isMultiUser && (
                <VisibilityPicker
                  value={resourceVisibility}
                  allowedGroups={resourceGroups}
                  teams={teams}
                  onChange={(vis, groups) => {
                    setResourceVisibility(vis);
                    setResourceGroups(groups);
                  }}
                />
              )}
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer"
                >
                  Verify &amp; Connect
                </button>
              </div>
            </form>
          </>
        )}

        {modal.type === "new-model" && (
          <>
            <div className="px-5 py-4 border-b border-slate-200 argo-modal-header flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900">
                {modal.initial ? "Update LLM Provider" : "Configure LLM Provider"}
              </h2>
              <button
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
              >
                <X className="w-3.5 h-3.5" />
                Close
              </button>
            </div>
            <form onSubmit={submitModel} className="p-5 space-y-3 overflow-y-auto custom-scroll">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Slug</label>
                  <input
                    type="text"
                    required
                    value={mdlSlug}
                    onChange={(e) => setMdlSlug(e.target.value)}
                    placeholder="anthropic_claude"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">Provider</label>
                  <select
                    value={mdlProvider}
                    onChange={(e) => {
                      const nextProvider = e.target.value as ModelProvider["provider_type"];
                      setMdlProvider(nextProvider);
                      setDiscoveredModels([]);
                      setDiscoverError(null);
                      setDiscoverNote(null);
                      setDiscoverFilter("");
                      if (!modal.initial) {
                        setMdlId(SUGGESTED_MODELS[nextProvider]);
                        setMdlInputPrice("");
                        setMdlOutputPrice("");
                      }
                    }}
                    className="w-full rounded-lg border border-slate-200 px-2.5 py-2 text-xs bg-white"
                  >
                    <option value="google">Google</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="openai">OpenAI</option>
                    <option value="xai">xAI</option>
                    <option value="openrouter">OpenRouter</option>
                    <option value="ollama">Ollama</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    API Key (Fernet-encrypted)
                  </label>
                  <input
                    type="password"
                    value={mdlKey}
                    onChange={(e) => setMdlKey(e.target.value)}
                    placeholder={
                      modal.initial?.has_api_key
                        ? "Leave blank to keep stored"
                        : mdlProvider === "ollama"
                          ? "Optional for Ollama"
                          : "Paste provider key or reuse saved"
                    }
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    API Base URL (optional)
                  </label>
                  <input
                    type="text"
                    value={mdlBase}
                    onChange={(e) => setMdlBase(e.target.value)}
                    placeholder="http://localhost:11434/v1"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <label className="block text-xs font-medium text-slate-900">
                    PydanticAI Model ID
                  </label>
                  <button
                    type="button"
                    disabled={discoveringModels}
                    onClick={() => void handleDiscoverModels()}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                  >
                    {discoveringModels ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <RefreshCw className="w-3 h-3" />
                    )}
                    <span>{discoveringModels ? "Fetching..." : "Fetch Available Models"}</span>
                  </button>
                </div>

                {discoveredModels.length > 0 && (
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-2.5 space-y-2">
                    <input
                      type="text"
                      value={discoverFilter}
                      onChange={(e) => setDiscoverFilter(e.target.value)}
                      placeholder={`Filter ${discoveredModels.length} live models...`}
                      className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                    />
                    <select
                      size={Math.min(5, Math.max(2, discoveredModels.length))}
                      value={mdlId}
                      onChange={(e) => handleSelectDiscoveredModel(e.target.value)}
                      className="w-full rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs font-mono"
                    >
                      {discoveredModels
                        .filter((m) => {
                          const q = discoverFilter.trim().toLowerCase();
                          if (!q) return true;
                          return (
                            m.model_id.toLowerCase().includes(q) ||
                            m.display_name.toLowerCase().includes(q)
                          );
                        })
                        .map((m) => {
                          const rateTag =
                            m.pricing_source === "local"
                              ? "Local ($0)"
                              : `$${m.input_price_per_million}/$${m.output_price_per_million} per 1M (${
                                  m.pricing_source === "live" ? "Live" : "Est."
                                })`;
                          return (
                            <option key={m.model_id} value={m.model_id}>
                              {m.model_id} — {rateTag}
                            </option>
                          );
                        })}
                    </select>
                    {discoverNote && (
                      <p className="text-[10.5px] text-slate-500">{discoverNote}</p>
                    )}
                  </div>
                )}

                {discoverError && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] text-rose-700">
                    {discoverError}
                  </div>
                )}

                <input
                  type="text"
                  required
                  value={mdlId}
                  onChange={(e) => setMdlId(e.target.value)}
                  placeholder="google:gemini-3.8-flash"
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Input Price ($ / 1M tokens)
                  </label>
                  <input
                    type="number"
                    min={0}
                    step="0.01"
                    value={mdlInputPrice}
                    onChange={(e) => setMdlInputPrice(e.target.value)}
                    placeholder={
                      modal.initial?.effective_input_price_per_million != null
                        ? `Auto (${modal.initial.effective_input_price_per_million})`
                        : "Auto (catalog / live)"
                    }
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Output Price ($ / 1M tokens)
                  </label>
                  <input
                    type="number"
                    min={0}
                    step="0.01"
                    value={mdlOutputPrice}
                    onChange={(e) => setMdlOutputPrice(e.target.value)}
                    placeholder={
                      modal.initial?.effective_output_price_per_million != null
                        ? `Auto (${modal.initial.effective_output_price_per_million})`
                        : "Auto (catalog / live)"
                    }
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Daily Token Limit
                  </label>
                  <input
                    type="number"
                    min={1}
                    value={mdlDailyLimit}
                    onChange={(e) => setMdlDailyLimit(e.target.value)}
                    placeholder="Unbounded"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-900 mb-1">
                    Monthly Budget (USD)
                  </label>
                  <input
                    type="number"
                    min={0}
                    step="0.5"
                    value={mdlMonthlyBudget}
                    onChange={(e) => setMdlMonthlyBudget(e.target.value)}
                    placeholder="100"
                    className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={mdlDefault}
                  onChange={(e) => setMdlDefault(e.target.checked)}
                />
                Set as default model provider
              </label>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer"
                >
                  Save Provider
                </button>
              </div>
            </form>
          </>
        )}

        {modal.type === "selkies" && (() => {
          const desktop = activeDesktop ?? modal.desktop;
          const selkiesUrl = desktop.selkies_url || `/api/desktops/${desktop.bot_slug}/selkies/`;
          const liveBoot = desktopBootBySlug[desktop.bot_slug];
          const downloadShotUrl = api.desktopScreenshotUrl(desktop.bot_slug, {
            refresh: true,
            download: true,
          });
          const isRecording = Boolean(recordingState?.recording);
          const recMins = String(Math.floor(recordingElapsedSec / 60)).padStart(2, "0");
          const recSecs = String(recordingElapsedSec % 60).padStart(2, "0");
          const recTotalEvents =
            (recordingState?.command_count ?? 0) + (recordingState?.event_count ?? 0);

          const handleStartRecording = async () => {
            if (recordingBusy) return;
            setRecordingBusy(true);
            setRecordingError(null);
            setRecordingNotice(null);
            setRecordedSkillResult(null);
            setStoppedRecordingTrace(null);
            try {
              const status = await api.startDesktopRecording(desktop.bot_slug);
              setRecordingState(status);
              setRecordingElapsedSec(0);
            } catch (err) {
              setRecordingError(
                err instanceof Error ? err.message : "Failed to start desktop session recording.",
              );
            } finally {
              setRecordingBusy(false);
            }
          };

          const handleStopRecording = async () => {
            if (recordingBusy) return;
            setRecordingBusy(true);
            setRecordingError(null);
            setRecordingNotice(null);
            try {
              const res = await api.stopDesktopRecording(desktop.bot_slug, { save_skill: false });
              setRecordingState(null);
              setRecordingElapsedSec(0);
              setRecordSkillName("");
              setStoppedRecordingTrace(res.recording);
            } catch (err) {
              setRecordingError(
                err instanceof Error ? err.message : "Failed to stop desktop session recording.",
              );
            } finally {
              setRecordingBusy(false);
            }
          };

          const handleSaveStoppedRecording = async (e: FormEvent) => {
            e.preventDefault();
            if (recordingBusy || !stoppedRecordingTrace) return;
            setRecordingBusy(true);
            setRecordingError(null);
            setRecordingNotice(null);
            try {
              const saved = await api.saveDesktopRecording(desktop.bot_slug, {
                skill_name: recordSkillName.trim() || undefined,
                recording: stoppedRecordingTrace as unknown as Record<string, unknown>,
              });
              setStoppedRecordingTrace(null);
              setRecordSkillName("");
              setRecordedSkillResult(saved);
              await onSkillSaved?.();
            } catch (err) {
              setRecordingError(
                err instanceof Error ? err.message : "Failed to save recorded session skill.",
              );
            } finally {
              setRecordingBusy(false);
            }
          };

          const handleDiscardStoppedRecording = () => {
            setStoppedRecordingTrace(null);
            setRecordSkillName("");
            setRecordingNotice("Recording discarded.");
          };

          const capturedStepTotal = (rec?: DesktopRecordingStopResponse["recording"] | null) =>
            (rec?.commands?.length ?? 0) +
            (rec?.visited_urls?.length ?? 0) +
            (rec?.dom_events?.length ?? 0) +
            (rec?.typed_inputs?.length ?? 0) +
            (rec?.clicks?.length ?? 0);

          const handleReleaseAndClose = () => {
            detachSelkiesIframe();
            const cleanup = isRecording
              ? api.stopDesktopRecording(desktop.bot_slug, { save_skill: false }).catch(() => {})
              : Promise.resolve();
            void cleanup.finally(() =>
              onReleaseTakeover(desktop.bot_slug).finally(() => window.setTimeout(onClose, 50)),
            );
          };

          return (
            <>
              <div className="min-h-12 sm:h-11 px-3 border-b border-slate-800 flex items-center justify-between gap-2 bg-[#161920] text-slate-100 shrink-0">
                <div className="flex items-center gap-2 min-w-0">
                  <button
                    type="button"
                    onClick={handleReleaseAndClose}
                    aria-label="Back and release desktop"
                    className="sm:hidden w-8 h-8 -ml-1 rounded-full bg-[#222732] border border-[#353d4d] text-slate-100 flex items-center justify-center shrink-0 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      desktop.awaiting_takeover ? "bg-[#c98a2c]" : "bg-[#3b8c62]"
                    }`}
                  />
                  <span className="text-xs font-semibold tracking-tight text-slate-100 truncate">
                    {desktop.bot_name}
                  </span>
                  <span className="hidden md:inline-flex items-center px-2 py-0.5 rounded-md border border-slate-700 bg-[#1e232c] font-mono text-[11px] text-slate-300 truncate max-w-[240px]">
                    {desktop.container_name}
                  </span>
                  {takeoverLoading && (
                    <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800 text-[11px] text-slate-200">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Starting…
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {!takeoverLoading && !takeoverError && (
                    <>
                      {isRecording ? (
                        <button
                          type="button"
                          disabled={recordingBusy}
                          onClick={() => void handleStopRecording()}
                          title="Stop recording desktop actions"
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#991b1b] bg-[#7f1d1d] hover:bg-[#991b1b] text-xs font-medium text-[#fecaca] cursor-pointer disabled:opacity-60"
                        >
                          <span className="w-2 h-2 rounded-full bg-[#f87171]" />
                          <Square className="w-2.5 h-2.5 fill-current" />
                          <span>
                            Stop ({recMins}:{recSecs}
                            {recTotalEvents > 0 ? ` · ${recTotalEvents}` : ""})
                          </span>
                        </button>
                      ) : !stoppedRecordingTrace ? (
                        <button
                          type="button"
                          disabled={recordingBusy}
                          onClick={() => void handleStartRecording()}
                          title="Record manual terminal commands, URLs, clicks & typing into a replayable Bot Skill"
                          className="argo-studio-btn inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium cursor-pointer disabled:opacity-60"
                        >
                          <Video className="w-3.5 h-3.5 text-[#ef4444]" />
                          <span className="hidden sm:inline">Record Session</span>
                        </button>
                      ) : null}

                      <a
                        href={downloadShotUrl}
                        download={`${desktop.bot_slug}-desktop.png`}
                        title="Save Screenshot"
                        className="argo-studio-btn inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span className="hidden lg:inline">Screenshot</span>
                      </a>

                      <button
                        type="button"
                        onClick={() => setIframeKey((k) => k + 1)}
                        title="Reload Desktop Screen"
                        className="argo-studio-btn inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs cursor-pointer"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span className="hidden lg:inline">Reload</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setMobileDesktopWide((prev) => !prev)}
                        title={
                          mobileDesktopWide
                            ? "Fit Virtual Desktop to phone screen"
                            : "Switch to scrollable 1280×720 desktop view"
                        }
                        className="argo-studio-btn inline-flex md:hidden items-center gap-1 px-2 py-1 rounded-md text-xs cursor-pointer"
                      >
                        {mobileDesktopWide ? (
                          <ZoomOut className="w-3.5 h-3.5" />
                        ) : (
                          <ZoomIn className="w-3.5 h-3.5" />
                        )}
                        <span>{mobileDesktopWide ? "Fit" : "Wide"}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setDesktopFullscreen((v) => !v)}
                        title={desktopFullscreen ? "Exit Fullscreen" : "Expand Fullscreen"}
                        className="argo-studio-btn hidden sm:inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs cursor-pointer"
                      >
                        {desktopFullscreen ? (
                          <Minimize2 className="w-3.5 h-3.5" />
                        ) : (
                          <Maximize2 className="w-3.5 h-3.5" />
                        )}
                      </button>

                      <a
                        href={selkiesUrl}
                        target="_blank"
                        rel="noreferrer"
                        title="Open in New Tab"
                        className="argo-studio-btn inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </>
                  )}

                  <button
                    type="button"
                    onClick={handleReleaseAndClose}
                    className="px-2.5 py-1 rounded-md bg-[#2a3140] hover:bg-[#343d50] border border-[#3d475c] text-xs font-medium text-white cursor-pointer"
                  >
                    Release
                  </button>
                </div>
              </div>

              {stoppedRecordingTrace && (
                <form
                  onSubmit={(e) => void handleSaveStoppedRecording(e)}
                  className="px-3 py-2 bg-[#1b2029] border-b border-slate-800 flex items-center justify-between gap-2 flex-wrap text-xs shrink-0"
                >
                  <div className="flex items-center gap-2 flex-1 min-w-[240px]">
                    <span className="text-xs font-medium text-slate-200 shrink-0">
                      Captured {capturedStepTotal(stoppedRecordingTrace)} step
                      {capturedStepTotal(stoppedRecordingTrace) === 1 ? "" : "s"}:
                    </span>
                    <input
                      type="text"
                      value={recordSkillName}
                      onChange={(e) => setRecordSkillName(e.target.value)}
                      placeholder="Optional skill name (e.g. Deploy Service Update via SSH)"
                      className="flex-1 min-w-[180px] rounded-md border border-slate-700 bg-[#141820] px-2.5 py-1 text-xs text-slate-100 placeholder-slate-400"
                    />
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      type="button"
                      disabled={recordingBusy}
                      onClick={handleDiscardStoppedRecording}
                      className="argo-studio-btn px-2.5 py-1 rounded-md text-xs cursor-pointer disabled:opacity-60"
                    >
                      Discard
                    </button>
                    <button
                      type="submit"
                      disabled={recordingBusy}
                      className="px-3 py-1 rounded-md bg-slate-100 hover:bg-white text-slate-900 text-xs font-medium cursor-pointer disabled:opacity-60"
                    >
                      {recordingBusy ? "Compiling Skill..." : "Save Skill"}
                    </button>
                  </div>
                </form>
              )}

              {(recordingError || recordingNotice || takeoverError || desktop.takeover_reason || recordedSkillResult) && (
                <div className="px-3 py-2 bg-[#181c23] border-b border-slate-800 space-y-1 shrink-0">
                  {recordingError && (
                    <div className="flex items-center justify-between gap-2 text-xs text-red-300">
                      <span>Recording error: {recordingError}</span>
                      <button
                        type="button"
                        onClick={() => setRecordingError(null)}
                        className="text-slate-400 hover:text-white cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                  {recordingNotice && (
                    <div className="flex items-center justify-between gap-2 text-xs text-slate-300">
                      <span>{recordingNotice}</span>
                      <button
                        type="button"
                        onClick={() => setRecordingNotice(null)}
                        className="text-slate-400 hover:text-white cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                  {desktop.takeover_reason && (
                    <div className="text-xs text-amber-200">
                      <span className="font-semibold">Takeover Reason:</span>{" "}
                      {desktop.takeover_reason}
                    </div>
                  )}
                  {recordedSkillResult && (
                    <div className="flex items-center justify-between gap-2 text-xs text-slate-200">
                      <span>
                        {recordedSkillResult.skill ? (
                          <>
                            Saved replayable Skill{" "}
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-[#3d4d66] bg-[#292d3e] font-mono font-semibold text-[#cbd5e8]">
                              @{recordedSkillResult.skill.slug}
                            </span>{" "}
                            ({capturedStepTotal(recordedSkillResult.recording)} steps captured) —
                            mention{" "}
                            <code className="font-mono bg-slate-800 px-1 py-0.5 rounded text-slate-100">
                              @{recordedSkillResult.skill.slug}
                            </code>{" "}
                            in {desktop.bot_name}&apos;s chat to replay it.
                          </>
                        ) : (
                          <>
                            Captured session ({capturedStepTotal(recordedSkillResult.recording)}{" "}
                            steps).
                          </>
                        )}
                      </span>
                      <button
                        type="button"
                        onClick={() => setRecordedSkillResult(null)}
                        className="text-slate-400 hover:text-white cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              )}

              <div className="flex-1 min-h-0 flex flex-col bg-[#13161c]">
                {takeoverLoading ? (
                  <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center p-6">
                    <Loader2 className="w-6 h-6 animate-spin text-slate-300" />
                    <div className="text-xs font-medium text-slate-100">
                      Starting Fedora XFCE Virtual Desktop &amp; connecting Selkies stream…
                    </div>
                    <p className="text-xs text-slate-300 max-w-md">
                      {liveBoot?.step ||
                        "First launch may take a moment while Docker initializes the isolated desktop environment."}
                    </p>
                  </div>
                ) : takeoverError ? (
                  <div className="flex-1 flex flex-col items-center justify-center gap-2 text-center p-6">
                    <div className="text-xs font-semibold text-red-300">
                      Virtual Desktop Failed to Start
                    </div>
                    <p className="text-xs text-slate-300 max-w-md">{takeoverError}</p>
                  </div>
                ) : isMobile && mobileDesktopWide ? (
                  <div className="flex-1 min-h-0 overflow-auto bg-[#0b0e14]">
                    <iframe
                      ref={selkiesIframeRef}
                      key={iframeKey}
                      src={selkiesUrl}
                      allow="autoplay; clipboard-read; clipboard-write; fullscreen"
                      title={`Selkies live screen for ${desktop.bot_name}`}
                      style={{ width: "1280px", height: "720px" }}
                      className="block border-0 bg-[#13161c]"
                    />
                  </div>
                ) : (
                  <iframe
                    ref={selkiesIframeRef}
                    key={iframeKey}
                    src={selkiesUrl}
                    allow="autoplay; clipboard-read; clipboard-write; fullscreen"
                    title={`Selkies live screen for ${desktop.bot_name}`}
                    className="flex-1 w-full h-full min-h-0 border-0 bg-[#13161c]"
                  />
                )}
              </div>
            </>
          );
        })()}

        {modal.type === "google-wizard" && (
          <GoogleWizardModal
            isMultiUser={isMultiUser}
            teams={teams}
            reauthAccount={modal.reauthAccount}
            onClose={onClose}
            onLoadConfig={onLoadGoogleWizardConfig}
            onStartOAuth={onStartGoogleOAuth}
            onCompleteOAuth={onCompleteGoogleOAuth}
          />
        )}

        {modal.type === "linkedin-onboard" && (
          <LinkedInOnboardModal
            isMultiUser={isMultiUser}
            teams={teams}
            onClose={onClose}
            onSubmit={onOnboardLinkedIn}
          />
        )}

        {modal.type === "webhook-onboard" && (
          <WebhookOnboardModal
            isMultiUser={isMultiUser}
            teams={teams}
            onClose={onClose}
            onSubmit={onOnboardWebhook}
          />
        )}

        {modal.type === "debug" && (
          <DebugModal
            initialBotSlug={modal.botSlug}
            bots={bots}
            onClose={onClose}
            onLoadOverview={onLoadDebugOverview}
            onClear={onClearDebug}
          />
        )}
      </div>
    </div>
  );
}

function extractOAuthCode(rawInput: string): string {
  const trimmed = rawInput.trim();
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    try {
      const url = new URL(trimmed);
      return url.searchParams.get("code") ?? trimmed;
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

function GoogleWizardModal({
  isMultiUser = false,
  teams = [],
  reauthAccount,
  onClose,
  onLoadConfig,
  onStartOAuth,
  onCompleteOAuth,
}: {
  isMultiUser?: boolean;
  teams?: TeamGroupRecord[];
  reauthAccount?: IntegrationAccount;
  onClose: () => void;
  onLoadConfig: () => Promise<GoogleWizardConfig>;
  onStartOAuth: (payload: {
    in_production_confirmed: boolean;
    client_id?: string;
    client_secret?: string;
    reuse_saved_client?: boolean;
    slug?: string;
    display_name?: string;
    login_hint?: string;
    scope_groups?: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<GoogleAuthorizeResponse>;
  onCompleteOAuth: (payload: { code: string; state: string }) => Promise<IntegrationAccount>;
}) {
  const [config, setConfig] = useState<GoogleWizardConfig | null>(null);
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [copiedUri, setCopiedUri] = useState(false);

  const [inProductionConfirmed, setInProductionConfirmed] = useState(true);
  const [showCustomClient, setShowCustomClient] = useState(false);
  const [forceReuseClient, setForceReuseClient] = useState(false);
  const [showManualFallback, setShowManualFallback] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");

  const [displayName, setDisplayName] = useState(reauthAccount?.display_name ?? "");
  const [slug, setSlug] = useState(reauthAccount?.slug ?? "");
  const [loginHint, setLoginHint] = useState(reauthAccount?.account_identifier ?? "");
  const [visibility, setVisibility] = useState<ResourceVisibility>(
    reauthAccount?.visibility === "shared" || reauthAccount?.visibility === "team"
      ? reauthAccount.visibility
      : "private",
  );
  const [allowedGroups, setAllowedGroups] = useState<string[]>(reauthAccount?.allowed_groups ?? []);
  const [scopeGroups, setScopeGroups] = useState<string[]>([
    "gmail_read",
    "gmail_compose",
    "calendar",
  ]);

  const [authResponse, setAuthResponse] = useState<GoogleAuthorizeResponse | null>(null);
  const [manualCodeInput, setManualCodeInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoadingConfig(true);
    onLoadConfig()
      .then((cfg) => {
        if (!active) return;
        setConfig(cfg);
        if (reauthAccount && reauthAccount.scopes.length > 0 && cfg.scope_catalog.length > 0) {
          const matched = cfg.scope_catalog
            .filter((g) => g.scopes.some((s) => reauthAccount.scopes.includes(s)))
            .map((g) => g.key);
          if (matched.length > 0) {
            setScopeGroups(matched);
          }
        }
      })
      .catch((err) => {
        if (!active) return;
        setErrorMsg(err instanceof Error ? err.message : "Failed to load Google OAuth configuration");
      })
      .finally(() => {
        if (active) setLoadingConfig(false);
      });
    return () => {
      active = false;
    };
  }, [onLoadConfig, reauthAccount]);

  function toggleScopeGroup(key: string) {
    setScopeGroups((prev) =>
      prev.includes(key) ? prev.filter((item) => item !== key) : [...prev, key],
    );
  }

  function applyAccountPreset(presetName: string) {
    setDisplayName(presetName);
    setForceReuseClient(false);
    if (!reauthAccount) {
      setSlug("");
    }
  }

  async function handleCopyRedirectUri() {
    if (!config) return;
    try {
      await navigator.clipboard.writeText(config.redirect_uri);
      setCopiedUri(true);
      window.setTimeout(() => setCopiedUri(false), 1800);
    } catch {
      setErrorMsg("Clipboard write denied; copy the Redirect URI manually.");
    }
  }

  const trimmedHint = loginHint.trim();
  const hasConsumerGmailHint = /@(gmail|googlemail)\.com$/i.test(trimmedHint);
  const hasCustomDomainHint = trimmedHint.includes("@") && !hasConsumerGmailHint;
  const isPersonalGmail =
    hasConsumerGmailHint ||
    (!hasCustomDomainHint &&
      (displayName.toLowerCase().includes("personal") || slug === "personal-gmail"));
  const hasExistingClient = Boolean(config?.has_saved_client || config?.has_server_client);
  const needsExternalClientForPersonal =
    isPersonalGmail &&
    !reauthAccount &&
    Boolean(config?.has_saved_client) &&
    !config?.has_personal_gmail_client &&
    !config?.has_server_client;
  const usingExistingClient =
    hasExistingClient && !showCustomClient && (!needsExternalClientForPersonal || forceReuseClient);
  const activeClientHint = isPersonalGmail
    ? config?.personal_client_id_hint || config?.saved_client_id_hint || config?.server_client_id_hint
    : config?.workspace_client_id_hint || config?.server_client_id_hint || config?.saved_client_id_hint;
  const redirectUri =
    config?.redirect_uri ?? `${window.location.origin}/api/integrations/google/callback`;

  async function handleStartAuthorize(autoRedirect: boolean) {
    if (!usingExistingClient) {
      if (!inProductionConfirmed) {
        setErrorMsg(
          "Confirm your Google OAuth consent screen is set to In Production so refresh tokens stay durable.",
        );
        return;
      }
      if (!clientId.trim() || !clientSecret.trim()) {
        setErrorMsg("Enter your Google OAuth Client ID and Client Secret first.");
        return;
      }
    }
    if (isMultiUser && visibility === "team" && allowedGroups.length === 0) {
      setErrorMsg("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setErrorMsg(null);
    setBusy(true);
    try {
      const res = await onStartOAuth({
        in_production_confirmed: usingExistingClient ? true : inProductionConfirmed,
        reuse_saved_client: usingExistingClient,
        client_id: usingExistingClient ? undefined : clientId.trim() || undefined,
        client_secret: usingExistingClient ? undefined : clientSecret.trim() || undefined,
        slug: slug.trim() || undefined,
        display_name: displayName.trim() || undefined,
        login_hint: loginHint.trim() || undefined,
        scope_groups: scopeGroups,
        ...(isMultiUser
          ? {
              visibility,
              ...(visibility === "team" ? { allowed_groups: allowedGroups } : {}),
            }
          : {}),
      });
      setAuthResponse(res);
      if (autoRedirect) {
        window.location.assign(res.authorization_url);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to initialize Google OAuth URL");
    } finally {
      setBusy(false);
    }
  }

  async function handleManualComplete(e: FormEvent) {
    e.preventDefault();
    if (!authResponse || !manualCodeInput.trim()) return;
    setErrorMsg(null);
    setBusy(true);
    try {
      await onCompleteOAuth({
        code: extractOAuthCode(manualCodeInput),
        state: authResponse.state,
      });
      onClose();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "OAuth code exchange failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="px-5 py-3.5 border-b border-slate-200 argo-modal-header flex items-center justify-between shrink-0">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">
            {reauthAccount
              ? `Re-authorize ${reauthAccount.display_name}`
              : "Connect Gmail & Google Workspace"}
          </h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Connect separate named accounts (e.g. Personal Gmail, Business Gmail) with one-click OAuth 2.0
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
        >
          <X className="w-3.5 h-3.5" />
          Close
        </button>
      </div>

      <div className="p-5 space-y-4 text-xs overflow-y-auto custom-scroll">
        {errorMsg && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-rose-700 text-[11px]">
            {errorMsg}
          </div>
        )}

        {loadingConfig && !config ? (
          <div className="py-6 text-center text-slate-500">Loading OAuth configuration…</div>
        ) : (
          <>
            {!reauthAccount && (
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-slate-600">Quick Label Presets</div>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => applyAccountPreset("Personal Gmail")}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-medium cursor-pointer ${
                      displayName === "Personal Gmail"
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100"
                    }`}
                  >
                    Personal Gmail
                  </button>
                  <button
                    type="button"
                    onClick={() => applyAccountPreset("Business Gmail")}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-medium cursor-pointer ${
                      displayName === "Business Gmail"
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100"
                    }`}
                  >
                    Business Gmail
                  </button>
                  <button
                    type="button"
                    onClick={() => applyAccountPreset("")}
                    className={`px-2.5 py-1 rounded-lg border text-[11px] font-medium cursor-pointer ${
                      displayName !== "Personal Gmail" && displayName !== "Business Gmail"
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100"
                    }`}
                  >
                    Custom
                  </button>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block font-medium text-slate-900 mb-1">Integration Name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Personal Gmail or Business Gmail"
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-900 mb-1">
                  Google Email Hint <span className="text-slate-400 font-normal">(optional)</span>
                </label>
                <input
                  type="email"
                  value={loginHint}
                  onChange={(e) => setLoginHint(e.target.value)}
                  placeholder="name@company.com"
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
                />
              </div>
            </div>

            <div>
              <div className="font-medium text-slate-900 mb-1.5">Permissions</div>
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {(config?.scope_catalog ?? []).map((group) => (
                  <label
                    key={group.key}
                    className="flex items-start gap-2 rounded-lg border border-slate-200 px-2.5 py-2 cursor-pointer hover:bg-slate-50"
                  >
                    <input
                      type="checkbox"
                      checked={scopeGroups.includes(group.key)}
                      onChange={() => toggleScopeGroup(group.key)}
                      className="mt-0.5"
                    />
                    <div className="min-w-0">
                      <div className="font-medium text-slate-900">{group.label}</div>
                      <div className="text-[11px] text-slate-500">{group.description}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {usingExistingClient ? (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 space-y-1.5 text-emerald-950">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-semibold text-[11px]">
                    {isPersonalGmail && config?.has_personal_gmail_client
                      ? "Personal Gmail sign-in is ready — no secrets required"
                      : "Google sign-in is ready — no secrets required"}
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setForceReuseClient(false);
                      setShowCustomClient(true);
                    }}
                    className="text-[11px] font-medium text-emerald-900 underline cursor-pointer shrink-0"
                  >
                    Change OAuth app
                  </button>
                </div>
                <p className="text-[11px] text-emerald-900 leading-relaxed">
                  {isPersonalGmail
                    ? "Argo already has your team's Gmail app credentials saved. Enter a label above (e.g. 'Marco Personal Gmail') and click Authorize with Google. Note: an admin just needs to add new @gmail.com addresses to the Google Cloud Test Users list."
                    : "Google app credentials are already configured. Enter a label above (e.g. 'Business Gmail') and click Authorize with Google."}
                </p>
                {activeClientHint && (
                  <div className="text-[10px] text-emerald-800 font-mono truncate">
                    App ID: {activeClientHint}
                  </div>
                )}
              </div>
            ) : (
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-semibold text-slate-900">
                    {isPersonalGmail
                      ? "One-Time Setup for Personal @gmail.com"
                      : "One-Time Google Sign-In Setup"}
                  </div>
                  {hasExistingClient && (
                    <button
                      type="button"
                      onClick={() => {
                        setForceReuseClient(true);
                        setShowCustomClient(false);
                      }}
                      className="text-[11px] text-slate-600 underline cursor-pointer"
                    >
                      Use saved Google app instead
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-slate-600 leading-relaxed">
                  {isPersonalGmail
                    ? "Company Google Workspace sign-in only accepts company email addresses. Enter the Client ID and Secret from an External Google Cloud app once below — Argo saves them automatically so colleagues won't need to enter any secrets."
                    : "Enter your Google Cloud Web App Client ID and Secret once below — Argo saves them securely so future accounts connect in one click."}
                </p>

                <div className="rounded-lg border border-slate-200 bg-white p-2.5 space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-[11px] text-slate-700">
                      Authorized Redirect URI
                    </span>
                    <button
                      type="button"
                      onClick={() => void handleCopyRedirectUri()}
                      className="px-2 py-0.5 rounded border border-slate-200 bg-slate-50 text-[10px] font-medium hover:bg-slate-100 cursor-pointer"
                    >
                      {copiedUri ? "Copied" : "Copy URI"}
                    </button>
                  </div>
                  <div className="font-mono text-[10px] text-slate-700 break-all select-all">
                    {redirectUri}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  <div>
                    <label className="block font-medium text-slate-900 mb-1">Client ID</label>
                    <input
                      type="text"
                      value={clientId}
                      onChange={(e) => setClientId(e.target.value)}
                      placeholder="12345-abc.apps.googleusercontent.com"
                      className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-900 mb-1">Client Secret</label>
                    <input
                      type="password"
                      value={clientSecret}
                      onChange={(e) => setClientSecret(e.target.value)}
                      placeholder="GOCSPX-..."
                      className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <label className="flex items-start gap-2 rounded-lg border border-slate-200 bg-white p-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={inProductionConfirmed}
                    onChange={(e) => setInProductionConfirmed(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span className="text-[11px] text-slate-700">
                    I added the Redirect URI above in Google Cloud (and listed <code>@gmail.com</code> emails under Test users if the app is in Testing mode).
                  </span>
                </label>
              </div>
            )}

            {isMultiUser && (
              <VisibilityPicker
                value={visibility}
                allowedGroups={allowedGroups}
                teams={teams}
                onChange={(vis, groups) => {
                  setVisibility(vis);
                  setAllowedGroups(groups);
                }}
              />
            )}

            <div className="rounded-lg border border-slate-200 bg-slate-50">
              <button
                type="button"
                onClick={() => setShowManualFallback((prev) => !prev)}
                className="w-full px-3 py-2 text-left text-[11px] font-medium text-slate-700 flex items-center justify-between cursor-pointer hover:bg-slate-100"
              >
                <span>Manual Code Fallback &amp; Custom Connector Slug</span>
                <span>{showManualFallback ? "Hide" : "Show"}</span>
              </button>
              {showManualFallback && (
                <div className="p-3 border-t border-slate-200 bg-white space-y-3 rounded-b-lg">
                  <div>
                    <label className="block font-medium text-slate-900 mb-1">
                      Connector Slug (optional override)
                    </label>
                    <input
                      type="text"
                      value={slug}
                      onChange={(e) => setSlug(e.target.value)}
                      disabled={Boolean(reauthAccount)}
                      placeholder="e.g. personal-gmail or business-gmail"
                      className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-mono disabled:bg-slate-50"
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void handleStartAuthorize(false)}
                      className="px-2.5 py-1 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-[11px] font-medium cursor-pointer"
                    >
                      Generate Link Without Redirect
                    </button>
                    {authResponse && (
                      <a
                        href={authResponse.authorization_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] font-medium text-slate-900 underline"
                      >
                        Open Consent Screen in New Tab
                      </a>
                    )}
                  </div>
                  {authResponse && (
                    <form onSubmit={handleManualComplete} className="flex gap-2">
                      <input
                        type="text"
                        value={manualCodeInput}
                        onChange={(e) => setManualCodeInput(e.target.value)}
                        placeholder="Paste callback URL or code= value..."
                        className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-mono"
                      />
                      <button
                        type="submit"
                        disabled={busy || !manualCodeInput.trim()}
                        className="px-3 py-1.5 rounded-lg bg-slate-900 disabled:opacity-40 text-white font-medium cursor-pointer"
                      >
                        Complete
                      </button>
                    </form>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg border border-slate-200 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={
                  busy ||
                  (!usingExistingClient &&
                    (!inProductionConfirmed || !clientId.trim() || !clientSecret.trim()))
                }
                onClick={() => void handleStartAuthorize(true)}
                className="bg-slate-900 disabled:opacity-40 text-white px-4 py-1.5 rounded-lg font-medium hover:bg-slate-800 cursor-pointer"
              >
                {busy ? "Connecting to Google…" : "Authorize with Google"}
              </button>
            </div>
          </>
        )}
      </div>
    </>
  );
}

function LinkedInOnboardModal({
  isMultiUser = false,
  teams = [],
  onClose,
  onSubmit,
}: {
  isMultiUser?: boolean;
  teams?: TeamGroupRecord[];
  onClose: () => void;
  onSubmit: (payload: {
    access_token: string;
    author_urn?: string;
    linkedin_version?: string;
    slug?: string;
    display_name?: string;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<void>;
}) {
  const [accessToken, setAccessToken] = useState("");
  const [linkedinVersion, setLinkedinVersion] = useState("202611");
  const [authorUrn, setAuthorUrn] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [slug, setSlug] = useState("");
  const [visibility, setVisibility] = useState<ResourceVisibility>("private");
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!accessToken.trim()) return;
    if (isMultiUser && visibility === "team" && allowedGroups.length === 0) {
      setErrorMsg("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setErrorMsg(null);
    setBusy(true);
    try {
      await onSubmit({
        access_token: accessToken.trim(),
        linkedin_version: linkedinVersion.trim() || "202611",
        author_urn: authorUrn.trim() || undefined,
        display_name: displayName.trim() || undefined,
        slug: slug.trim() || undefined,
        ...(isMultiUser
          ? {
              visibility,
              ...(visibility === "team" ? { allowed_groups: allowedGroups } : {}),
            }
          : {}),
      });
      onClose();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "LinkedIn onboarding failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="px-5 py-3.5 border-b border-slate-200 argo-modal-header flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">Connect LinkedIn Posts API</h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Targets official versioned `/rest/posts` (`Linkedin-Version` header; legacy `/v2/ugcPosts` blocked)
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
        >
          <X className="w-3.5 h-3.5" />
          Close
        </button>
      </div>
      <form onSubmit={handleSubmit} className="p-5 space-y-3 text-xs">
        {errorMsg && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-rose-700 text-[11px]">
            {errorMsg}
          </div>
        )}
        <div>
          <label className="block font-medium text-slate-900 mb-1">OAuth Access Token</label>
          <input
            type="password"
            required
            value={accessToken}
            onChange={(e) => setAccessToken(e.target.value)}
            placeholder="AQV..."
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block font-medium text-slate-900 mb-1">Linkedin-Version</label>
            <input
              type="text"
              required
              value={linkedinVersion}
              onChange={(e) => setLinkedinVersion(e.target.value)}
              placeholder="202611"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
            />
          </div>
          <div>
            <label className="block font-medium text-slate-900 mb-1">Author URN (optional)</label>
            <input
              type="text"
              value={authorUrn}
              onChange={(e) => setAuthorUrn(e.target.value)}
              placeholder="urn:li:person:... (auto via userinfo)"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block font-medium text-slate-900 mb-1">Display Name (optional)</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Company LinkedIn Page"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
            />
          </div>
          <div>
            <label className="block font-medium text-slate-900 mb-1">Slug (optional)</label>
            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="linkedin_main"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
            />
          </div>
        </div>
        {isMultiUser && (
          <VisibilityPicker
            value={visibility}
            allowedGroups={allowedGroups}
            teams={teams}
            onChange={(vis, groups) => {
              setVisibility(vis);
              setAllowedGroups(groups);
            }}
          />
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg border border-slate-200 cursor-pointer"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy}
            className="bg-slate-900 disabled:opacity-40 text-white px-3 py-1.5 rounded-lg font-medium cursor-pointer"
          >
            {busy ? "Verifying…" : "Verify & Connect"}
          </button>
        </div>
      </form>
    </>
  );
}

function WebhookOnboardModal({
  isMultiUser = false,
  teams = [],
  onClose,
  onSubmit,
}: {
  isMultiUser?: boolean;
  teams?: TeamGroupRecord[];
  onClose: () => void;
  onSubmit: (payload: {
    display_name: string;
    slug?: string;
    signing_secret?: string;
    event_type?: string;
    target_collection?: string | null;
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
  }) => Promise<WebhookOnboardResponse>;
}) {
  const [displayName, setDisplayName] = useState("");
  const [slug, setSlug] = useState("");
  const [eventType, setEventType] = useState("webhook.received");
  const [targetCollection, setTargetCollection] = useState("webhook_events");
  const [signingSecret, setSigningSecret] = useState("");
  const [visibility, setVisibility] = useState<ResourceVisibility>("private");
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [created, setCreated] = useState<WebhookOnboardResponse | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!displayName.trim()) return;
    if (isMultiUser && visibility === "team" && allowedGroups.length === 0) {
      setErrorMsg("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setErrorMsg(null);
    setBusy(true);
    try {
      const res = await onSubmit({
        display_name: displayName.trim(),
        slug: slug.trim() || undefined,
        event_type: eventType.trim() || "webhook.received",
        target_collection: targetCollection.trim() || null,
        signing_secret: signingSecret.trim() || undefined,
        ...(isMultiUser
          ? {
              visibility,
              ...(visibility === "team" ? { allowed_groups: allowedGroups } : {}),
            }
          : {}),
      });
      setCreated(res);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create webhook endpoint");
    } finally {
      setBusy(false);
    }
  }

  async function handleCopySecret() {
    if (!created?.signing_secret_once) return;
    try {
      await navigator.clipboard.writeText(created.signing_secret_once);
      setCopiedSecret(true);
      window.setTimeout(() => setCopiedSecret(false), 1800);
    } catch {
      setErrorMsg("Clipboard write denied; copy the secret manually before closing.");
    }
  }

  return (
    <>
      <div className="px-5 py-3.5 border-b border-slate-200 argo-modal-header flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">
            {created ? `Webhook Ready · ${created.display_name}` : "Create Signed Inbound Webhook"}
          </h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Verifies `X-Argo-Signature-256` (`sha256=&lt;hex&gt;`) before writing to Collections &amp; Valkey Bus
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
        >
          <X className="w-3.5 h-3.5" />
          Close
        </button>
      </div>

      {created ? (
        <div className="p-5 space-y-3 text-xs">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 space-y-1">
            <div className="font-medium text-slate-900">Endpoint URL</div>
            <div className="font-mono text-[11px] text-slate-700 break-all select-all">
              {`${window.location.origin}${created.webhook_path}`}
            </div>
          </div>

          {created.signing_secret_once && (
            <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 space-y-1.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-amber-900">
                  Signing Secret (shown once only)
                </span>
                <button
                  type="button"
                  onClick={handleCopySecret}
                  className="px-2 py-0.5 rounded border border-amber-300 bg-white text-[11px] font-medium cursor-pointer"
                >
                  {copiedSecret ? "Copied" : "Copy Secret"}
                </button>
              </div>
              <div className="font-mono text-[11px] text-amber-950 break-all select-all">
                {created.signing_secret_once}
              </div>
            </div>
          )}

          <div className="rounded-lg border border-slate-800 bg-slate-950 text-slate-100 p-3 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
            {`BODY='{"event":"ping","source":"ci"}'\nSIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "${created.signing_secret_once ?? "<YOUR_SECRET>"}" | awk '{print $2}')\ncurl -X POST "${window.location.origin}${created.webhook_path}" \\\n  -H "Content-Type: application/json" \\\n  -H "X-Argo-Signature-256: sha256=$SIG" \\\n  -d "$BODY"`}
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="button"
              onClick={onClose}
              className="bg-slate-900 text-white px-3 py-1.5 rounded-lg font-medium cursor-pointer"
            >
              Done
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="p-5 space-y-3 text-xs">
          {errorMsg && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-rose-700 text-[11px]">
              {errorMsg}
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-900 mb-1">Display Name</label>
              <input
                type="text"
                required
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="CRM Lead Webhook"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs"
              />
            </div>
            <div>
              <label className="block font-medium text-slate-900 mb-1">Slug (optional)</label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="crm_leads"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block font-medium text-slate-900 mb-1">Event Type</label>
              <input
                type="text"
                required
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                placeholder="webhook.received"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
              />
            </div>
            <div>
              <label className="block font-medium text-slate-900 mb-1">Target Collection (optional)</label>
              <input
                type="text"
                value={targetCollection}
                onChange={(e) => setTargetCollection(e.target.value)}
                placeholder="webhook_events"
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
              />
            </div>
          </div>
          <div>
            <label className="block font-medium text-slate-900 mb-1">
              Signing Secret (optional, leave blank to auto-generate)
            </label>
            <input
              type="password"
              value={signingSecret}
              onChange={(e) => setSigningSecret(e.target.value)}
              placeholder="Auto-generated 256-bit hex secret if omitted"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-xs font-mono"
            />
          </div>
          {isMultiUser && (
          <VisibilityPicker
            value={visibility}
            allowedGroups={allowedGroups}
            teams={teams}
            onChange={(vis, groups) => {
              setVisibility(vis);
              setAllowedGroups(groups);
            }}
          />
        )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg border border-slate-200 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="bg-slate-900 disabled:opacity-40 text-white px-3 py-1.5 rounded-lg font-medium cursor-pointer"
            >
              {busy ? "Creating…" : "Create Webhook"}
            </button>
          </div>
        </form>
      )}
    </>
  );
}

export function DebugModal({
  initialBotSlug,
  bots,
  onClose,
  onLoadOverview,
  onClear,
}: {
  initialBotSlug?: string;
  bots: BotRecord[];
  onClose?: () => void;
  onLoadOverview: (params?: {
    bot_slug?: string;
    level?: string;
    contains?: string;
    limit?: number;
  }) => Promise<DebugOverviewResponse>;
  onClear: () => Promise<unknown>;
}) {
  const [botFilter, setBotFilter] = useState(initialBotSlug ?? "");
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [searchText, setSearchText] = useState("");
  const [activeTab, setActiveTab] = useState<"traces" | "logs">("traces");
  const [data, setData] = useState<DebugOverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);
  const [expandedTraceIds, setExpandedTraceIds] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let active = true;
    setLoading(true);
    setErrorMsg(null);
    onLoadOverview({
      bot_slug: botFilter || undefined,
      level: levelFilter !== "ALL" ? levelFilter : undefined,
      limit: 100,
    })
      .then((res) => {
        if (active) {
          setData(res);
        }
      })
      .catch((err) => {
        if (active) {
          setErrorMsg(err instanceof Error ? err.message : "Failed to load debug overview");
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [botFilter, levelFilter, onLoadOverview, reloadTick]);

  async function handleClear() {
    setClearing(true);
    setErrorMsg(null);
    try {
      await onClear();
      setReloadTick((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to clear debug buffers");
    } finally {
      setClearing(false);
    }
  }

  function toggleTrace(traceId: string) {
    setExpandedTraceIds((prev) => ({
      ...prev,
      [traceId]: !prev[traceId],
    }));
  }

  const query = searchText.trim().toLowerCase();
  const filteredTraces = (data?.traces ?? []).filter((trace) => {
    if (!query) return true;
    const haystack = [
      trace.bot_name,
      trace.bot_slug,
      trace.trigger_type,
      trace.status,
      trace.model_used,
      trace.summary,
      trace.error ?? "",
      JSON.stringify(trace.turns ?? []),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });

  const filteredLogs = (data?.logs ?? []).filter((entry) => {
    if (!query) return true;
    return `${entry.ts} ${entry.level} ${entry.logger} ${entry.message}`
      .toLowerCase()
      .includes(query);
  });

  return (
    <>
      <div className="px-5 py-3.5 border-b border-slate-200 argo-modal-header flex items-center justify-between shrink-0">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">
            Run Traces &amp; System Logs
          </h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Inspect model runs and scrubbed server logs
          </p>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer shrink-0"
          >
            <X className="w-3.5 h-3.5" />
            Close
          </button>
        )}
      </div>

      <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex flex-wrap items-center gap-2 shrink-0 text-xs">
        <select
          value={botFilter}
          onChange={(e) => setBotFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
        >
          <option value="">All Bots</option>
          {bots.map((b) => (
            <option key={b.slug} value={b.slug}>
              {b.name} ({b.slug})
            </option>
          ))}
        </select>

        <select
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
        >
          <option value="ALL">All Levels</option>
          <option value="ERROR">ERROR</option>
          <option value="WARNING">WARNING</option>
          <option value="INFO">INFO</option>
        </select>

        <input
          type="text"
          value={searchText}
          onChange={(e) => setSearchText(e.target.value)}
          placeholder="Search traces or logs..."
          className="flex-1 min-w-[180px] rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs"
        />

        <button
          type="button"
          disabled={loading}
          onClick={() => setReloadTick((prev) => prev + 1)}
          className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-xs font-medium cursor-pointer disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
        <button
          type="button"
          disabled={clearing}
          onClick={() => void handleClear()}
          className="px-2.5 py-1.5 rounded-lg border border-rose-200 bg-white hover:bg-rose-50 text-xs font-medium text-rose-700 cursor-pointer disabled:opacity-50"
        >
          {clearing ? "Clearing..." : "Clear"}
        </button>
      </div>

      <div className="px-5 pt-2.5 border-b border-slate-200 flex items-center gap-2 shrink-0 text-xs">
        <button
          type="button"
          onClick={() => setActiveTab("traces")}
          className={`px-3 py-1.5 rounded-t-lg font-medium border-b-2 cursor-pointer ${
            activeTab === "traces"
              ? "border-slate-900 text-slate-900"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          Run Traces ({filteredTraces.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("logs")}
          className={`px-3 py-1.5 rounded-t-lg font-medium border-b-2 cursor-pointer ${
            activeTab === "logs"
              ? "border-slate-900 text-slate-900"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          System Logs ({filteredLogs.length})
        </button>
      </div>

      <div className="p-5 overflow-y-auto custom-scroll space-y-3 text-xs flex-1">
        {errorMsg && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-rose-700 text-[11px]">
            {errorMsg}
          </div>
        )}

        {loading && !data ? (
          <div className="py-8 text-center text-slate-500">Loading traces and system logs…</div>
        ) : activeTab === "traces" ? (
          filteredTraces.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
              No matching bot run traces recorded yet.
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredTraces.map((trace) => {
                const expanded = Boolean(expandedTraceIds[trace.id]);
                const statusBadge =
                  trace.status === "completed"
                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                    : trace.status === "error" || trace.status === "failed"
                      ? "bg-rose-50 text-rose-700 border-rose-200"
                      : "bg-slate-100 text-slate-700 border-slate-200";
                return (
                  <div
                    key={trace.id}
                    className="rounded-xl border border-slate-200 bg-white overflow-hidden"
                  >
                    <button
                      type="button"
                      onClick={() => toggleTrace(trace.id)}
                      className="w-full px-3.5 py-2.5 text-left hover:bg-slate-50 flex items-start justify-between gap-3 cursor-pointer"
                    >
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-slate-900">{trace.bot_name}</span>
                          <span className="font-mono text-[10px] text-slate-500">
                            {trace.bot_slug}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${statusBadge}`}
                          >
                            {trace.status}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] font-mono text-slate-600">
                            {trace.trigger_type}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            {trace.model_used} · {trace.tokens_used} tokens
                          </span>
                        </div>
                        <div className="text-slate-700 line-clamp-2">{trace.summary}</div>
                      </div>
                      <div className="text-right shrink-0 space-y-0.5">
                        <div className="text-[10px] font-mono text-slate-400">
                          {trace.started_at}
                        </div>
                        <div className="text-[11px] font-medium text-slate-600">
                          {expanded ? "Hide turns" : `Turns (${trace.turns?.length ?? 0})`}
                        </div>
                      </div>
                    </button>

                    {trace.error && (
                      <div className="mx-3.5 mb-2.5 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700 font-mono whitespace-pre-wrap">
                        {trace.error}
                      </div>
                    )}

                    {expanded && (
                      <div className="border-t border-slate-200 bg-slate-50 p-3.5 space-y-2.5">
                        {(trace.turns ?? []).length === 0 ? (
                          <div className="text-[11px] text-slate-500">
                            No turn details captured for this run.
                          </div>
                        ) : (
                          trace.turns.map((turn, idx) => (
                            <div
                              key={idx}
                              className="rounded-lg border border-slate-200 bg-white p-3 space-y-2"
                            >
                              <div className="font-semibold text-[11px] text-slate-900">
                                Turn {turn.turn}
                              </div>
                              {turn.prompt_preview && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wide text-slate-400 font-semibold mb-0.5">
                                    Prompt Preview
                                  </div>
                                  <pre className="rounded bg-slate-50 border border-slate-200 p-2 text-[11px] font-mono text-slate-700 whitespace-pre-wrap overflow-x-auto max-h-40">
                                    {turn.prompt_preview}
                                  </pre>
                                </div>
                              )}
                              {turn.response_preview && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wide text-slate-400 font-semibold mb-0.5">
                                    Model Output
                                  </div>
                                  <pre className="rounded bg-slate-50 border border-slate-200 p-2 text-[11px] font-mono text-slate-700 whitespace-pre-wrap overflow-x-auto max-h-40">
                                    {turn.response_preview}
                                  </pre>
                                </div>
                              )}
                              {((turn.actions && turn.actions.length > 0) ||
                                (turn.action_results && turn.action_results.length > 0)) && (
                                <div>
                                  <div className="text-[10px] uppercase tracking-wide text-slate-400 font-semibold mb-0.5">
                                    Actions &amp; Results
                                  </div>
                                  <pre className="rounded bg-slate-950 text-emerald-300 p-2 text-[11px] font-mono overflow-x-auto max-h-48">
                                    {JSON.stringify(
                                      {
                                        actions: turn.actions ?? [],
                                        action_results: turn.action_results ?? [],
                                      },
                                      null,
                                      2,
                                    )}
                                  </pre>
                                </div>
                              )}
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
        ) : filteredLogs.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-200 p-8 text-center text-slate-500">
            No matching system logs in memory buffer.
          </div>
        ) : (
          <div className="rounded-xl border border-slate-200 bg-slate-950 text-slate-100 p-3 font-mono text-[11px] space-y-1.5 overflow-x-auto">
            {filteredLogs.map((entry) => {
              const levelTone =
                entry.level === "ERROR" || entry.level === "CRITICAL"
                  ? "text-rose-400"
                  : entry.level === "WARNING"
                    ? "text-amber-300"
                    : "text-emerald-300";
              return (
                <div
                  key={entry.seq}
                  className="border-b border-slate-800 pb-1 last:border-b-0 whitespace-pre-wrap break-words"
                >
                  <span className="text-slate-500">{entry.ts}</span>{" "}
                  <span className={`font-semibold ${levelTone}`}>[{entry.level}]</span>{" "}
                  <span className="text-sky-300">{entry.logger}</span>:{" "}
                  <span>{entry.message}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
