import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, Columns2, Loader2, Monitor, MoreHorizontal, Settings, Terminal, X } from "lucide-react";
import { ApiError, api } from "./api";
import { AuthGate } from "./components/AuthGate";
import { BotAvatar } from "./components/BotAvatar";
import { Inspector } from "./components/Inspector";
import { MobileBotsHub } from "./components/MobileBotsHub";
import { MobileBottomNav } from "./components/MobileBottomNav";
import { MobilePagesHub } from "./components/MobilePagesHub";
import { Modals, type ActiveModal } from "./components/Modals";
import { SSHTerminalPanel } from "./components/SSHTerminalPanel";
import { SettingsModal } from "./components/SettingsModal";
import { Sidebar } from "./components/Sidebar";
import { ViewErrorBoundary } from "./components/ViewErrorBoundary";
import { useIsMobile } from "./hooks/useIsMobile";
import { ActivityView } from "./components/views/ActivityView";
import { ApprovalsView } from "./components/views/ApprovalsView";
import { BotThreadView } from "./components/views/BotThreadView";
import { DesktopsView } from "./components/views/DesktopsView";
import { IntegrationsView } from "./components/views/IntegrationsView";
import { ModelsView } from "./components/views/ModelsView";
import { PagesView } from "./components/views/PagesView";
import type {
  ActiveThreadStream,
  ActivityEvent,
  ApprovalItem,
  AuthConfigResponse,
  BotMessage,
  BotRecord,
  BotRunActivity,
  CollectionRecord,
  DelegationPlan,
  DesktopBootProgress,
  DesktopInfo,
  DesktopLaunchQueueItem,
  HostTelemetry,
  IntegrationAccount,
  LiveTurnChip,
  LiveWorkspaceStatusResponse,
  ModelsResponse,
  PageRecord,
  RoomMessage,
  RoomRecord,
  SandboxInfo,
  SettingsTab,
  SkillRecord,
  SsoPrincipal,
  StyleRule,
  TeamGroupRecord,
  VaultSecretRecord,
  ViewId,
  WorkspaceFileRecord,
  WorkspaceSummary,
} from "./types";
import { friendlyAutonomyLabel, friendlyModelName } from "./utils/format";

function readInitialTheme(): "light" | "dark" {
  try {
    return window.localStorage.getItem("argo_theme") === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function App() {
  const isMobile = useIsMobile();
  const [activeView, setActiveView] = useState<ViewId>("activity");
  const [mobileThreadOpen, setMobileThreadOpen] = useState(false);
  const [mobilePageOpen, setMobilePageOpen] = useState(false);
  const [selectedBotSlug, setSelectedBotSlug] = useState<string | null>(null);
  const [selectedRoomSlug, setSelectedRoomSlug] = useState<string | null>(null);
  const [selectedPageSlug, setSelectedPageSlug] = useState<string | null>(null);
  const [splitPageSlug, setSplitPageSlug] = useState<string | null>(null);
  const [standalonePageSlug, setStandalonePageSlug] = useState<string | null>(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("standalone_page");
  });
  const [contextCorrelationId, setContextCorrelationId] = useState<string | null>(null);

  const [searchQuery, setSearchQuery] = useState("");
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [inspectorTabOverride, setInspectorTabOverride] = useState<"details" | "library" | "computer" | null>(null);
  const [terminalModalBotSlug, setTerminalModalBotSlug] = useState<string | null>(null);
  const [terminalModalSessionId, setTerminalModalSessionId] = useState<string | null>(null);
  const [sshRefreshTick, setSshRefreshTick] = useState(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("integrations");
  const [theme, setTheme] = useState<"light" | "dark">(readInitialTheme);

  const [activityFilter, setActivityFilter] = useState<"all" | "reviews" | "alerts">("all");
  const [approvalTab, setApprovalTab] = useState<"pending" | "history">("pending");
  const [modal, setModal] = useState<ActiveModal>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [prefillDraft, setPrefillDraft] = useState<{ id: number; text: string } | null>(null);
  const prefillSeqRef = useRef(0);

  const [authConfig, setAuthConfig] = useState<AuthConfigResponse | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authErrorParam, setAuthErrorParam] = useState<string | null>(() => {
    try {
      return new URLSearchParams(window.location.search).get("auth_error");
    } catch {
      return null;
    }
  });
  const [principal, setPrincipal] = useState<SsoPrincipal | null>(null);
  const [teams, setTeams] = useState<TeamGroupRecord[]>([]);
  const [summary, setSummary] = useState<WorkspaceSummary | null>(null);
  const [liveStatus, setLiveStatus] = useState<LiveWorkspaceStatusResponse | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [bots, setBots] = useState<BotRecord[]>([]);
  const [rooms, setRooms] = useState<RoomRecord[]>([]);
  const [botMessages, setBotMessages] = useState<BotMessage[]>([]);
  const [botMessagesHasMore, setBotMessagesHasMore] = useState(false);
  const [botMessagesTotal, setBotMessagesTotal] = useState(0);
  const [loadingBotMessages, setLoadingBotMessages] = useState(false);
  const [loadingOlderMessages, setLoadingOlderMessages] = useState(false);
  const [roomMessages, setRoomMessages] = useState<RoomMessage[]>([]);
  const [roomMessagesHasMore, setRoomMessagesHasMore] = useState(false);
  const [roomMessagesTotal, setRoomMessagesTotal] = useState(0);
  const [loadingRoomMessages, setLoadingRoomMessages] = useState(false);
  const [loadingOlderRoomMessages, setLoadingOlderRoomMessages] = useState(false);
  const activeMsgBotSlugRef = useRef<string | null>(null);
  const activeMsgRoomSlugRef = useRef<string | null>(null);
  const selectedBotSlugRef = useRef<string | null>(selectedBotSlug);
  selectedBotSlugRef.current = selectedBotSlug;
  const selectedRoomSlugRef = useRef<string | null>(selectedRoomSlug);
  selectedRoomSlugRef.current = selectedRoomSlug;
  const botMessagesRef = useRef<BotMessage[]>([]);
  botMessagesRef.current = botMessages;
  const botMessagesTotalRef = useRef<number>(0);
  botMessagesTotalRef.current = botMessagesTotal;
  const refreshCoreInFlightRef = useRef<Promise<void> | null>(null);
  const refreshCorePendingRef = useRef<boolean>(false);
  const refreshCoreRef = useRef<() => Promise<void>>(async () => undefined);
  const sseRefreshTimerRef = useRef<number | null>(null);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [styleRules, setStyleRules] = useState<StyleRule[]>([]);
  const [skills, setSkills] = useState<SkillRecord[]>([]);
  const [collections, setCollections] = useState<CollectionRecord[]>([]);
  const [pages, setPages] = useState<PageRecord[]>([]);
  const [workspaceFiles, setWorkspaceFiles] = useState<WorkspaceFileRecord[]>([]);
  const [desktopHost, setDesktopHost] = useState<HostTelemetry | null>(null);
  const [desktops, setDesktops] = useState<DesktopInfo[]>([]);
  const [sandboxes, setSandboxes] = useState<SandboxInfo[]>([]);
  const [desktopQueuedLaunches, setDesktopQueuedLaunches] = useState<DesktopLaunchQueueItem[]>([]);
  const [integrations, setIntegrations] = useState<IntegrationAccount[]>([]);
  const [vaultSecrets, setVaultSecrets] = useState<VaultSecretRecord[]>([]);
  const [modelsData, setModelsData] = useState<ModelsResponse | null>(null);
  const [runningBots, setRunningBots] = useState<Record<string, BotRunActivity>>({});
  const [activeStreamByThread, setActiveStreamByThread] = useState<
    Record<string, ActiveThreadStream>
  >({});
  const [queuedCountByThread, setQueuedCountByThread] = useState<Record<string, number>>({});
  const [desktopBootBySlug, setDesktopBootBySlug] = useState<Record<string, DesktopBootProgress>>({});
  const [togglingDesktops, setTogglingDesktops] = useState<Record<string, boolean>>({});
  const [togglingSandboxes, setTogglingSandboxes] = useState<Record<string, boolean>>({});

  const didInitViewRef = useRef(false);
  const urlRequestedViewRef = useRef(false);

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;
    const syncViewportHeight = () => {
      document.documentElement.style.setProperty("--argo-vh", `${Math.round(vv.height)}px`);
    };
    syncViewportHeight();
    vv.addEventListener("resize", syncViewportHeight);
    vv.addEventListener("scroll", syncViewportHeight);
    return () => {
      vv.removeEventListener("resize", syncViewportHeight);
      vv.removeEventListener("scroll", syncViewportHeight);
      document.documentElement.style.removeProperty("--argo-vh");
    };
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    const themeMeta = document.querySelector('meta[name="theme-color"]');
    if (themeMeta) {
      themeMeta.setAttribute("content", theme === "dark" ? "#13161c" : "#ffffff");
    }
    try {
      window.localStorage.setItem("argo_theme", theme);
    } catch {
      // Ignore storage failures in restricted browser modes.
    }
  }, [theme]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => {
      setToast((prev) => (prev === message ? null : prev));
    }, 3200);
  }, []);

  const refreshCore = useCallback(async () => {
    if (refreshCoreInFlightRef.current) {
      refreshCorePendingRef.current = true;
      return refreshCoreInFlightRef.current;
    }
    const run = (async () => {
      try {
        const [
          meRes,
          sumRes,
          botsRes,
          pagesRes,
          eventsRes,
          modelsRes,
          intRes,
          vaultRes,
          rulesRes,
          aprRes,
          skillsRes,
          colsRes,
          liveRes,
          deskRes,
          roomsRes,
          filesRes,
          teamsRes,
        ] = await Promise.all([
          api.getMe(),
          api.getSummary(),
          api.listBots(),
          api.listPages(),
          api.listActivity("all"),
          api.listModels(),
          api.listIntegrations(),
          api.listVaultSecrets(),
          api.listStyleRules(),
          api.listApprovals("all"),
          api.listSkills(),
          api.listCollections(),
          api.getLiveStatus(),
          api.listDesktops(),
          api.listRooms(),
          api.listWorkspaceFiles(),
          api.listMyTeams().catch(() => [] as TeamGroupRecord[]),
        ]);

        setPrincipal(meRes);
        setTeams(teamsRes);
        setSummary(sumRes);
        setBots(botsRes);
        setRooms(roomsRes);
        setPages(pagesRes);
        setWorkspaceFiles(filesRes);
        setEvents(eventsRes);
        setModelsData(modelsRes);
        setIntegrations(intRes);
        setVaultSecrets(vaultRes);
        setStyleRules(rulesRes);
        setApprovals(aprRes);
        setSkills(skillsRes);
        setCollections(colsRes);
        setLiveStatus(liveRes);
        setDesktopHost(deskRes.host);
        setDesktops(deskRes.desktops);
        setSandboxes(deskRes.sandboxes ?? []);
        setDesktopQueuedLaunches(deskRes.queued_launches ?? []);

        if (!didInitViewRef.current) {
          didInitViewRef.current = true;
          if (!urlRequestedViewRef.current && botsRes.length > 0) {
            const preferred = botsRes.find((b) => b.pinned) ?? botsRes[0];
            setSelectedBotSlug(preferred.slug);
            setActiveView("bot");
          }
        }

        setSelectedBotSlug((prev) => {
          if (prev && botsRes.some((b) => b.slug === prev)) return prev;
          return botsRes[0]?.slug ?? null;
        });
        setSelectedRoomSlug((prev) =>
          prev && roomsRes.some((r) => r.slug === prev) ? prev : null,
        );
        setSelectedPageSlug((prev) => {
          if (prev && pagesRes.some((p) => p.slug === prev)) return prev;
          return pagesRes[0]?.slug ?? null;
        });
        setSplitPageSlug((prev) =>
          prev && pagesRes.some((p) => p.slug === prev) ? prev : null,
        );
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          setPrincipal(null);
          void api.getAuthConfig().then(setAuthConfig).catch(() => undefined);
          return;
        }
        showToast(err instanceof Error ? err.message : "Failed to load workspace data");
      } finally {
        refreshCoreInFlightRef.current = null;
        if (refreshCorePendingRef.current) {
          refreshCorePendingRef.current = false;
          void refreshCoreRef.current();
        }
      }
    })();
    refreshCoreInFlightRef.current = run;
    return run;
  }, [showToast]);
  refreshCoreRef.current = refreshCore;

  const workspaceSessionReady =
    authChecked &&
    !authConfig?.needs_setup &&
    (authConfig?.auth_mode === "sso" || Boolean(principal?.authenticated)) &&
    !principal?.must_change_password;

  const loadAuthAndWorkspace = useCallback(async () => {
    try {
      const cfg = await api.getAuthConfig();
      setAuthConfig(cfg);
      if (cfg.needs_setup) {
        setPrincipal(null);
        setTeams([]);
        setAuthChecked(true);
        return;
      }
      try {
        const me = await api.getMe();
        setPrincipal(me);
        setAuthChecked(true);
        if (!me.must_change_password) {
          await refreshCoreRef.current();
        }
      } catch (err) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setPrincipal(null);
          if (err.status === 403 && err.message) {
            setAuthErrorParam(err.message);
          }
          setAuthChecked(true);
          return;
        }
        setAuthChecked(true);
        showToast(err instanceof Error ? err.message : "Failed to verify session");
      }
    } catch {
      setAuthChecked(true);
      await refreshCoreRef.current();
    }
  }, [showToast]);

  const handleSignOut = useCallback(async () => {
    const mode = authConfig?.auth_mode ?? principal?.auth_mode ?? "sso";
    if (mode === "sso") {
      window.location.assign(`/oauth2/sign_out?rd=${encodeURIComponent("/oauth2/sign_in")}`);
      return;
    }
    try {
      await api.logout();
    } catch {
      // Ignore network/session cleanup errors during sign-out
    }
    setPrincipal(null);
    setTeams([]);
    setSettingsOpen(false);
    setInspectorOpen(false);
    setAuthErrorParam(null);
    didInitViewRef.current = false;
    try {
      const cfg = await api.getAuthConfig();
      setAuthConfig(cfg);
    } catch {
      // Ignore refresh failures on sign-out
    }
  }, [authConfig, principal?.auth_mode]);

  const applyTailMessages = useCallback(
    (
      slug: string,
      tailMessages: BotMessage[],
      hasMoreHint?: boolean,
      totalHint?: number,
    ) => {
      if (activeMsgBotSlugRef.current !== slug) return;
      const prev = botMessagesRef.current;
      let nextMessages: BotMessage[];
      let resolvedTotal: number;
      let nextHasMore: boolean;

      if (prev.length === 0 || prev[0]?.bot_slug !== slug) {
        nextMessages = tailMessages;
        resolvedTotal = totalHint ?? tailMessages.length;
        nextHasMore =
          typeof hasMoreHint === "boolean"
            ? hasMoreHint
            : typeof totalHint === "number"
              ? tailMessages.length < totalHint
              : false;
      } else {
        const byId = new Map<string, BotMessage>();
        for (const m of prev) byId.set(m.id, m);
        for (const m of tailMessages) byId.set(m.id, m);
        nextMessages = Array.from(byId.values());
        resolvedTotal = totalHint ?? Math.max(nextMessages.length, botMessagesTotalRef.current);
        nextHasMore = nextMessages.length < resolvedTotal;
      }

      botMessagesRef.current = nextMessages;
      botMessagesTotalRef.current = resolvedTotal;
      setBotMessages(nextMessages);
      setBotMessagesTotal(resolvedTotal);
      setBotMessagesHasMore(nextHasMore);
    },
    [],
  );

  const loadBotMessagesWindow = useCallback(
    async (slug: string, opts?: { reset?: boolean }) => {
      const switched = activeMsgBotSlugRef.current !== slug;
      if (switched || opts?.reset) {
        activeMsgBotSlugRef.current = slug;
        botMessagesRef.current = [];
        botMessagesTotalRef.current = 0;
        setBotMessages([]);
        setBotMessagesHasMore(false);
        setBotMessagesTotal(0);
        setLoadingBotMessages(true);
      }
      try {
        const res = await api.listBotMessagesPage(slug, { limit: 40 });
        if (activeMsgBotSlugRef.current !== slug) return;
        if (switched || opts?.reset) {
          botMessagesRef.current = res.messages;
          botMessagesTotalRef.current = res.totalCount;
          setBotMessages(res.messages);
          setBotMessagesHasMore(res.hasMore);
          setBotMessagesTotal(res.totalCount);
        } else {
          applyTailMessages(slug, res.messages, res.hasMore, res.totalCount);
        }
      } catch (err) {
        if (activeMsgBotSlugRef.current === slug) {
          showToast(err instanceof Error ? err.message : "Failed to load messages");
        }
      } finally {
        if (activeMsgBotSlugRef.current === slug) {
          setLoadingBotMessages(false);
        }
      }
    },
    [applyTailMessages, showToast],
  );

  const handleLoadOlderMessages = useCallback(async () => {
    if (!selectedBotSlug || loadingOlderMessages || !botMessagesHasMore) return;
    const targetSlug = selectedBotSlug;
    const oldestId = botMessages.find((m) => m.bot_slug === targetSlug)?.id;
    if (!oldestId) return;
    setLoadingOlderMessages(true);
    try {
      const res = await api.listBotMessagesPage(targetSlug, {
        limit: 40,
        beforeId: oldestId,
      });
      if (activeMsgBotSlugRef.current !== targetSlug) return;
      setBotMessages((prev) => {
        const seen = new Set(res.messages.map((m) => m.id));
        const rest = prev.filter((m) => m.bot_slug === targetSlug && !seen.has(m.id));
        return [...res.messages, ...rest];
      });
      setBotMessagesHasMore(res.hasMore);
      setBotMessagesTotal(res.totalCount);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to load earlier messages");
    } finally {
      setLoadingOlderMessages(false);
    }
  }, [
    selectedBotSlug,
    loadingOlderMessages,
    botMessagesHasMore,
    botMessages,
    showToast,
  ]);

  const loadRoomMessagesWindow = useCallback(
    async (roomSlug: string, opts?: { reset?: boolean }) => {
      const switched = activeMsgRoomSlugRef.current !== roomSlug;
      if (switched || opts?.reset) {
        activeMsgRoomSlugRef.current = roomSlug;
        setRoomMessages([]);
        setRoomMessagesHasMore(false);
        setRoomMessagesTotal(0);
        setLoadingRoomMessages(true);
      }
      try {
        const res = await api.listRoomMessagesPage(roomSlug, { limit: 40 });
        if (activeMsgRoomSlugRef.current !== roomSlug) return;
        setRoomMessages(res.messages);
        setRoomMessagesHasMore(res.hasMore);
        setRoomMessagesTotal(res.totalCount);
        setLiveStatus((prev) =>
          prev && prev.rooms
            ? {
                ...prev,
                rooms: prev.rooms.map((r) =>
                  r.slug === roomSlug ? { ...r, unread: false } : r,
                ),
              }
            : prev,
        );
      } finally {
        if (activeMsgRoomSlugRef.current === roomSlug) {
          setLoadingRoomMessages(false);
        }
      }
    },
    [],
  );

  const loadBotMessagesWindowRef = useRef(loadBotMessagesWindow);
  loadBotMessagesWindowRef.current = loadBotMessagesWindow;
  const loadRoomMessagesWindowRef = useRef(loadRoomMessagesWindow);
  loadRoomMessagesWindowRef.current = loadRoomMessagesWindow;

  const handleLoadOlderRoomMessages = useCallback(async () => {
    if (!selectedRoomSlug || loadingOlderRoomMessages || !roomMessagesHasMore) return;
    const targetSlug = selectedRoomSlug;
    const oldestId = roomMessages.find((m) => m.room_slug === targetSlug)?.id;
    if (!oldestId) return;
    setLoadingOlderRoomMessages(true);
    try {
      const res = await api.listRoomMessagesPage(targetSlug, {
        limit: 40,
        beforeId: oldestId,
      });
      if (activeMsgRoomSlugRef.current !== targetSlug) return;
      setRoomMessages((prev) => {
        const seen = new Set(res.messages.map((m) => m.id));
        const rest = prev.filter((m) => m.room_slug === targetSlug && !seen.has(m.id));
        return [...res.messages, ...rest];
      });
      setRoomMessagesHasMore(res.hasMore);
      setRoomMessagesTotal(res.totalCount);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to load earlier room messages");
    } finally {
      setLoadingOlderRoomMessages(false);
    }
  }, [
    selectedRoomSlug,
    loadingOlderRoomMessages,
    roomMessagesHasMore,
    roomMessages,
    showToast,
  ]);

  const refreshViewSpecific = useCallback(async () => {
    if (!workspaceSessionReady) return;
    try {
      if (activeView === "approvals") {
        const [aprRes, rulesRes] = await Promise.all([
          api.listApprovals("all"),
          api.listStyleRules(),
        ]);
        setApprovals(aprRes);
        setStyleRules(rulesRes);
      } else if (activeView === "desktops") {
        const deskRes = await api.listDesktops();
        setDesktopHost(deskRes.host);
        setDesktops(deskRes.desktops);
        setSandboxes(deskRes.sandboxes ?? []);
        setDesktopQueuedLaunches(deskRes.queued_launches ?? []);
      } else if (activeView === "integrations") {
        setIntegrations(await api.listIntegrations());
      } else if (activeView === "bot") {
        if (selectedRoomSlug) {
          await loadRoomMessagesWindow(selectedRoomSlug);
        } else if (selectedBotSlug) {
          await loadBotMessagesWindow(selectedBotSlug);
        }
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to refresh view");
    }
  }, [
    workspaceSessionReady,
    activeView,
    selectedBotSlug,
    selectedRoomSlug,
    loadBotMessagesWindow,
    loadRoomMessagesWindow,
    showToast,
  ]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const viewParam = params.get("view");
    const slugParam = params.get("slug");
    const oauthStatus = params.get("oauth");
    const standaloneParam = params.get("standalone_page");
    const editPageParam = params.get("edit_page");
    const authErrorQuery = params.get("auth_error");

    if (standaloneParam) {
      urlRequestedViewRef.current = true;
      setStandalonePageSlug(standaloneParam);
    }

    if (viewParam === "integrations") {
      urlRequestedViewRef.current = true;
      setSettingsTab("integrations");
      setSettingsOpen(true);
    } else if (viewParam === "desktops" || viewParam === "models") {
      urlRequestedViewRef.current = true;
      setSettingsTab(viewParam);
      setSettingsOpen(true);
    } else if (viewParam === "approvals" || viewParam === "activity") {
      urlRequestedViewRef.current = true;
      setActiveView(viewParam);
    } else if (viewParam === "bot") {
      urlRequestedViewRef.current = true;
      if (slugParam) {
        setSelectedBotSlug(slugParam);
        setMobileThreadOpen(true);
      }
      setActiveView("bot");
    } else if (viewParam === "page") {
      urlRequestedViewRef.current = true;
      if (slugParam) {
        setSelectedPageSlug(slugParam);
        setMobilePageOpen(true);
      }
      setActiveView("page");
    }

    if (oauthStatus === "google_connected") {
      setSettingsTab("integrations");
      setSettingsOpen(true);
      showToast(
        slugParam ? `Connected Google account ${slugParam}.` : "Connected Google account.",
      );
      void refreshCore();
    } else if (oauthStatus === "google_error") {
      setSettingsTab("integrations");
      setSettingsOpen(true);
      showToast(
        params.get("detail") || params.get("message") || "Google OAuth authorization failed.",
      );
    }

    if (viewParam || oauthStatus || editPageParam || authErrorQuery) {
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, [refreshCore, showToast]);

  useEffect(() => {
    void loadAuthAndWorkspace();
  }, [loadAuthAndWorkspace]);

  useEffect(() => {
    void refreshViewSpecific();
  }, [refreshViewSpecific]);

  useEffect(() => {
    if (!workspaceSessionReady) {
      return;
    }
    const clearLiveBotRunningState = (botSlug: string) => {
      if (!botSlug) return;
      setLiveStatus((prev) => {
        if (!prev?.bots) return prev;
        let changed = false;
        const nextBots = prev.bots.map((b) => {
          if (b.slug === botSlug && b.state === "running") {
            changed = true;
            return { ...b, state: "idle" as const, active_step: undefined };
          }
          return b;
        });
        return changed ? { ...prev, bots: nextBots } : prev;
      });
    };
    const syncApprovalsNow = () =>
      api
        .listApprovals("all")
        .then((aprRes) => {
          setApprovals(aprRes);
          const pendingCnt = aprRes.filter((a) => a.status === "pending").length;
          setSummary((prev) =>
            prev
              ? { ...prev, counts: { ...prev.counts, pending_approvals: pendingCnt } }
              : prev,
          );
        })
        .catch(() => undefined);
    const scheduleSseRefresh = () => {
      if (sseRefreshTimerRef.current !== null) return;
      sseRefreshTimerRef.current = window.setTimeout(() => {
        sseRefreshTimerRef.current = null;
        void refreshCore();
        void refreshViewSpecific();
      }, 300);
    };
    const source = new EventSource("/api/activity/stream");
    source.addEventListener("activity", (ev) => {
      try {
        const parsed = JSON.parse(String((ev as MessageEvent).data ?? "{}")) as {
          event_type?: string;
          payload?: {
            target_type?: string;
            slug?: string;
          };
        };
        const eventType = String(parsed.event_type ?? "");
        if (eventType.startsWith("ssh.")) {
          setSshRefreshTick((t) => t + 1);
        }
        if (eventType === "approval.queued" || eventType === "approval.resolved") {
          void syncApprovalsNow();
        }
        if (eventType === "thread.cleared" && parsed.payload) {
          const tType = String(parsed.payload.target_type ?? "");
          const tSlug = String(parsed.payload.slug ?? "");
          const curRoom = selectedRoomSlugRef.current;
          const curBot = selectedBotSlugRef.current;
          if (curRoom && (tType === "all" || (tType === "room" && tSlug === curRoom))) {
            void loadRoomMessagesWindowRef.current(curRoom, { reset: true });
          } else if (!curRoom && curBot && (tType === "all" || (tType === "bot" && tSlug === curBot))) {
            void loadBotMessagesWindowRef.current(curBot, { reset: true });
          }
        }
      } catch {
        // Ignore malformed activity payload
      }
      scheduleSseRefresh();
    });
    source.addEventListener("bot_progress", (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) as {
          bot_slug?: string;
          state?: string;
          step?: string;
        };
        const slug = String(data.bot_slug ?? "").trim();
        if (!slug) return;
        const stepText = String(data.step ?? "").trim();
        const isDesktopBootStep =
          /starting virtual desktop|waking fedora|creating isolated|pulling fedora|injecting desktop|checking host memory gate|waiting for virtual desktop|warming up selkies|first-time setup: installing/i.test(
            stepText,
          );
        const isDesktopActiveStep =
          /browsing in virtual desktop|capturing virtual desktop|running virtual desktop action|interacting with browser/i.test(
            stepText,
          );

        if (data.state === "running" || data.state === "working") {
          setRunningBots((prev) => ({
            ...prev,
            [slug]: {
              step: stepText || prev[slug]?.step || "Working...",
              startedAt: prev[slug]?.startedAt ?? Date.now(),
            },
          }));
          if (isDesktopBootStep) {
            setDesktopBootBySlug((prev) => ({
              ...prev,
              [slug]: {
                state: "booting",
                step: stepText || prev[slug]?.step || "Starting Virtual Desktop...",
                updatedAt: Date.now(),
              },
            }));
          } else if (isDesktopActiveStep) {
            setDesktopBootBySlug((prev) => {
              const cur = prev[slug];
              if (!cur || cur.state !== "booting") return prev;
              const next = { ...prev };
              delete next[slug];
              return next;
            });
          }
        } else if (data.state === "desktop_boot") {
          setDesktopBootBySlug((prev) => ({
            ...prev,
            [slug]: {
              state: "booting",
              step: stepText || "Starting Virtual Desktop...",
              updatedAt: Date.now(),
            },
          }));
        } else if (data.state === "desktop_ready") {
          setDesktopBootBySlug((prev) => ({
            ...prev,
            [slug]: {
              state: "ready",
              step: stepText || "Virtual Desktop ready.",
              updatedAt: Date.now(),
            },
          }));
          void refreshCore();
          window.setTimeout(() => {
            setDesktopBootBySlug((prev) => {
              const cur = prev[slug];
              if (!cur || cur.state !== "ready") return prev;
              const next = { ...prev };
              delete next[slug];
              return next;
            });
          }, 3500);
        } else if (data.state === "desktop_error") {
          setDesktopBootBySlug((prev) => ({
            ...prev,
            [slug]: {
              state: "error",
              step: stepText || "Virtual Desktop failed to start.",
              updatedAt: Date.now(),
            },
          }));
        } else if (data.state === "idle") {
          setRunningBots((prev) => {
            if (!(slug in prev)) return prev;
            const next = { ...prev };
            delete next[slug];
            return next;
          });
          clearLiveBotRunningState(slug);
          setDesktopBootBySlug((prev) => {
            const cur = prev[slug];
            if (!cur || cur.state === "error") return prev;
            const next = { ...prev };
            delete next[slug];
            return next;
          });
          scheduleSseRefresh();
        }
      } catch {
        // Ignore malformed progress events.
      }
    });
    source.addEventListener("turn_stream", (ev) => {
      try {
        const data = JSON.parse((ev as MessageEvent).data) as {
          type?: string;
          run_id?: string;
          thread_key?: string;
          target_type?: "bot" | "room";
          target_slug?: string;
          bot_slug?: string;
          bot_name?: string;
          routed_reason?: string;
          routing_source?: string;
          delta?: string;
          queued_behind?: number;
          chip_id?: string;
          action_type?: string;
          label?: string;
          status?: string;
          elapsed_ms?: number;
          detail?: string;
          error?: string;
        };
        const threadKey = String(data.thread_key ?? "").trim();
        const runId = String(data.run_id ?? "").trim();
        if (!threadKey) return;

        if (data.type === "run_queued") {
          const qb = Number(data.queued_behind ?? 0);
          setQueuedCountByThread((prev) => ({
            ...prev,
            [threadKey]: Math.max(prev[threadKey] ?? 0, qb),
          }));
        } else if (data.type === "run_started" && runId) {
          const isHandoff = data.routing_source === "handoff";
          if (isHandoff && threadKey.startsWith("room:")) {
            const handoffRoomSlug = String(data.target_slug ?? threadKey.slice(5));
            if (activeMsgRoomSlugRef.current === handoffRoomSlug) {
              void api
                .listRoomMessagesPage(handoffRoomSlug, { limit: 40 })
                .then((res) => {
                  if (activeMsgRoomSlugRef.current !== handoffRoomSlug) return;
                  setRoomMessages(res.messages);
                  setRoomMessagesHasMore(res.hasMore);
                  setRoomMessagesTotal(res.totalCount);
                })
                .catch(() => undefined);
            }
          }
          setActiveStreamByThread((prev) => ({
            ...prev,
            [threadKey]: {
              runId,
              threadKey,
              targetType: data.target_type === "room" ? "room" : "bot",
              targetSlug: String(data.target_slug ?? ""),
              botSlug: String(data.bot_slug ?? ""),
              botName: String(data.bot_name ?? data.bot_slug ?? "Bot"),
              text: "",
              chips: [],
              routedReason: data.routed_reason || undefined,
              routingSource: data.routing_source || undefined,
              startedAt:
                prev[threadKey]?.runId === runId ? prev[threadKey].startedAt : Date.now(),
              finishing: false,
            },
          }));
          if (!isHandoff) {
            setQueuedCountByThread((prev) => {
              const cur = prev[threadKey] ?? 0;
              if (cur <= 0) return prev;
              const next = { ...prev };
              if (cur <= 1) delete next[threadKey];
              else next[threadKey] = cur - 1;
              return next;
            });
          }
        } else if (data.type === "text_delta" && runId) {
          const delta = String(data.delta ?? "");
          if (!delta) return;
          setActiveStreamByThread((prev) => {
            const cur = prev[threadKey];
            if (!cur || cur.runId !== runId) return prev;
            return {
              ...prev,
              [threadKey]: { ...cur, text: cur.text + delta },
            };
          });
        } else if (data.type === "text_reset" && runId) {
          setActiveStreamByThread((prev) => {
            const cur = prev[threadKey];
            if (!cur || cur.runId !== runId) return prev;
            return {
              ...prev,
              [threadKey]: { ...cur, text: "" },
            };
          });
        } else if (data.type === "chip_started" && runId && data.chip_id) {
          if (String(data.action_type ?? "").startsWith("ssh_")) {
            setSshRefreshTick((t) => t + 1);
          }
          const newChip: LiveTurnChip = {
            chip_id: data.chip_id,
            action_type: String(data.action_type ?? "action"),
            label: String(data.label ?? "Running action"),
            status: "running",
          };
          setActiveStreamByThread((prev) => {
            const cur = prev[threadKey];
            if (!cur || cur.runId !== runId) return prev;
            if (cur.chips.some((c) => c.chip_id === newChip.chip_id)) return prev;
            return {
              ...prev,
              [threadKey]: { ...cur, chips: [...cur.chips, newChip] },
            };
          });
        } else if (data.type === "chip_finished" && runId && data.chip_id) {
          if (String(data.action_type ?? "").startsWith("ssh_")) {
            setSshRefreshTick((t) => t + 1);
          }
          setActiveStreamByThread((prev) => {
            const cur = prev[threadKey];
            if (!cur || cur.runId !== runId) return prev;
            const updatedChips = cur.chips.map((c) =>
              c.chip_id === data.chip_id
                ? {
                    ...c,
                    status: String(data.status ?? "done"),
                    elapsed_ms: data.elapsed_ms,
                    detail: data.detail,
                  }
                : c,
            );
            return {
              ...prev,
              [threadKey]: { ...cur, chips: updatedChips },
            };
          });
        } else if (data.type === "run_finished" || data.type === "run_cancelled") {
          setActiveStreamByThread((prev) => {
            const cur = prev[threadKey];
            if (!cur || (runId && cur.runId !== runId)) return prev;
            return {
              ...prev,
              [threadKey]: { ...cur, finishing: true },
            };
          });
          if (data.status === "error" && data.error) {
            showToast(String(data.error));
          }
          const botSlug = String(data.bot_slug ?? "").trim();
          if (botSlug) {
            setRunningBots((prev) => {
              if (!(botSlug in prev)) return prev;
              const next = { ...prev };
              delete next[botSlug];
              return next;
            });
            clearLiveBotRunningState(botSlug);
          }
          const slug = String(data.target_slug ?? threadKey.split(":", 2)[1] ?? "");
          const finalize = () => {
            setActiveStreamByThread((prev) => {
              const cur = prev[threadKey];
              if (!cur || (runId && cur.runId !== runId)) return prev;
              const next = { ...prev };
              delete next[threadKey];
              return next;
            });
          };
          const approvalsSync = syncApprovalsNow();
          if (threadKey.startsWith("room:") && activeMsgRoomSlugRef.current === slug) {
            const messagesSync = api
              .listRoomMessagesPage(slug, { limit: 40 })
              .then((res) => {
                if (activeMsgRoomSlugRef.current !== slug) return;
                setRoomMessages(res.messages);
                setRoomMessagesHasMore(res.hasMore);
                setRoomMessagesTotal(res.totalCount);
                const lastBotMsg = [...res.messages].reverse().find((m) => m.sender === "bot");
                detectAndOpenPageAction(lastBotMsg?.metadata?.actions);
              })
              .catch(() => undefined);
            void Promise.all([messagesSync, approvalsSync]).finally(finalize);
          } else if (threadKey.startsWith("bot:") && activeMsgBotSlugRef.current === slug) {
            const messagesSync = api
              .listBotMessagesPage(slug, { limit: 40 })
              .then((res) => {
                if (activeMsgBotSlugRef.current !== slug) return;
                applyTailMessages(slug, res.messages, res.hasMore, res.totalCount);
                const lastBotMsg = [...res.messages].reverse().find((m) => m.sender === "bot");
                detectAndOpenPageAction(lastBotMsg?.metadata?.actions);
              })
              .catch(() => undefined);
            void Promise.all([messagesSync, approvalsSync]).finally(finalize);
          } else {
            void approvalsSync;
            finalize();
          }
          scheduleSseRefresh();
        }
      } catch {
        // Ignore malformed turn_stream events.
      }
    });
    return () => {
      source.close();
      refreshCorePendingRef.current = false;
      if (sseRefreshTimerRef.current !== null) {
        window.clearTimeout(sseRefreshTimerRef.current);
        sseRefreshTimerRef.current = null;
      }
    };
  }, [applyTailMessages, refreshCore, refreshViewSpecific, showToast, workspaceSessionReady]);

  const selectedBot = bots.find((b) => b.slug === selectedBotSlug) ?? bots[0] ?? null;
  const selectedRoom = selectedRoomSlug
    ? rooms.find((r) => r.slug === selectedRoomSlug) ?? null
    : null;
  const selectedPage = pages.find((p) => p.slug === selectedPageSlug) ?? pages[0] ?? null;
  const splitPage = splitPageSlug
    ? pages.find((p) => p.slug === splitPageSlug) ?? null
    : null;
  const pageOwnerBot = selectedPage
    ? bots.find((b) => b.slug === selectedPage.owner_bot_slug) ?? selectedBot
    : null;
  const splitPageOwnerBot = splitPage
    ? bots.find((b) => b.slug === splitPage.owner_bot_slug) ?? selectedBot
    : null;
  const inspectorBot = activeView === "page" ? pageOwnerBot : selectedBot;
  const standalonePage = standalonePageSlug
    ? (pages.find((p) => p.slug === standalonePageSlug) ?? null)
    : null;

  function handleSwitchView(view: ViewId, slug?: string) {
    if (view === "integrations" || view === "desktops" || view === "models") {
      setSettingsTab(view);
      setSettingsOpen(true);
      return;
    }
    setActiveView(view);
    setInspectorTabOverride(null);
    if (view !== "bot" && view !== "page") {
      setContextCorrelationId(null);
      setInspectorOpen(false);
    }
    if (view === "bot") {
      setSelectedRoomSlug(null);
      if (slug && slug !== selectedBotSlug) {
        setContextCorrelationId(null);
      }
      if (slug) {
        setSelectedBotSlug(slug);
        setMobileThreadOpen(true);
        setLiveStatus((prev) =>
          prev
            ? {
                ...prev,
                bots: prev.bots.map((b) =>
                  b.slug === slug ? { ...b, unread: false } : b,
                ),
              }
            : prev,
        );
      }
    }
    if (view === "page") {
      setSplitPageSlug(null);
      if (slug) {
        setSelectedPageSlug(slug);
        setMobilePageOpen(true);
      }
    }
  }

  function handleSelectRoom(roomSlug: string) {
    setInspectorTabOverride(null);
    setContextCorrelationId(null);
    setSelectedRoomSlug(roomSlug);
    setActiveView("bot");
    setMobileThreadOpen(true);
    setLiveStatus((prev) =>
      prev && prev.rooms
        ? {
            ...prev,
            rooms: prev.rooms.map((r) =>
              r.slug === roomSlug ? { ...r, unread: false } : r,
            ),
          }
        : prev,
    );
    void loadRoomMessagesWindow(roomSlug);
  }

  function handleOpenPage(pageSlug: string, sideBySide = false) {
    if (sideBySide && !isMobile) {
      setSplitPageSlug(pageSlug);
      if (activeView !== "bot") {
        setActiveView("bot");
      }
      return;
    }
    setSplitPageSlug(null);
    handleSwitchView("page", pageSlug);
  }

  function handlePrefillChat(botSlug: string, prompt: string) {
    const cleanPrompt = prompt.trim();
    if (!cleanPrompt) return;
    const requested = botSlug.trim();
    const targetBot =
      (requested && bots.find((b) => b.slug === requested)) ||
      selectedBot ||
      bots[0] ||
      null;
    if (targetBot) {
      handleSwitchView("bot", targetBot.slug);
    } else {
      setActiveView("bot");
    }
    prefillSeqRef.current += 1;
    setPrefillDraft({ id: prefillSeqRef.current, text: cleanPrompt });
  }

  function detectAndOpenPageAction(actions?: Array<Record<string, unknown>>) {
    if (!Array.isArray(actions)) return;
    const openAct = actions.find(
      (a) => a && a.type === "open_page" && a.status === "ok" && (a.slug || a.page_slug),
    );
    if (openAct) {
      const target = String(openAct.slug ?? openAct.page_slug ?? "").trim();
      if (target) {
        setSplitPageSlug(target);
      }
    }
  }

  function handleOpenSettings(tab: SettingsTab = "integrations") {
    setSettingsTab(tab);
    setSettingsOpen(true);
  }

  async function handleToggleDesktop(slug: string) {
    setTogglingDesktops((prev) => ({ ...prev, [slug]: true }));
    setDesktopBootBySlug((prev) => ({
      ...prev,
      [slug]: {
        state: "booting",
        step: "Starting or updating Virtual Desktop...",
        updatedAt: Date.now(),
      },
    }));
    try {
      await api.toggleDesktop(slug);
      await refreshCore();
      await refreshViewSpecific();
      setDesktopBootBySlug((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
      showToast(`Updated virtual desktop for ${slug}.`);
    } catch (err) {
      await refreshCore();
      await refreshViewSpecific();
      showToast(err instanceof Error ? err.message : "Desktop action blocked");
    } finally {
      setTogglingDesktops((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
    }
  }

  async function handleToggleSandbox(slug: string) {
    setTogglingSandboxes((prev) => ({ ...prev, [slug]: true }));
    try {
      await api.toggleSandbox(slug);
      await refreshCore();
      await refreshViewSpecific();
      showToast(`Updated script sandbox for ${slug}.`);
    } catch (err) {
      await refreshCore();
      await refreshViewSpecific();
      showToast(err instanceof Error ? err.message : "Sandbox action blocked");
    } finally {
      setTogglingSandboxes((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
    }
  }

  async function handleTriggerBot(slug: string, routineId?: string) {
    setRunningBots((prev) => ({
      ...prev,
      [slug]: {
        step: "Running check...",
        startedAt: prev[slug]?.startedAt ?? Date.now(),
      },
    }));
    try {
      const res = await api.triggerBot(slug, {
        routine_id: routineId,
        wait_for_chain: true,
      });
      await refreshCore();
      await refreshViewSpecific();
      showToast(`Executed ${slug}: ${res.status}`);
    } catch (err) {
      await refreshCore();
      showToast(err instanceof Error ? err.message : `Run failed for ${slug}`);
    } finally {
      setRunningBots((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
      setActiveStreamByThread((prev) => {
        const tk = `bot:${slug}`;
        if (!(tk in prev)) return prev;
        const next = { ...prev };
        delete next[tk];
        return next;
      });
      setQueuedCountByThread((prev) => {
        const tk = `bot:${slug}`;
        if (!(tk in prev)) return prev;
        const next = { ...prev };
        delete next[tk];
        return next;
      });
    }
  }

  async function handleApproveItem(id: string, opts?: { trust_command?: boolean }) {
    try {
      const res = await api.resolveApproval(id, {
        action: "approve",
        ...(opts?.trust_command ? { trust_command: true } : {}),
      });
      await refreshCore();
      await refreshViewSpecific();
      const isSsh = res.action_type === "ssh_exec" || res.action_type === "ssh_input";
      const added =
        res.trusted_prefixes_added ?? res.payload.execution_result?.trusted_prefixes_added ?? [];
      if (res.error_message) {
        showToast(res.error_message);
      } else if (isSsh && res.status === "executed") {
        showToast(
          added.length > 0
            ? `Approved, ran SSH command, and always allowed: ${added.join(", ")}`
            : "Approved and ran SSH command — output sent to bot chat.",
        );
      } else {
        showToast(
          res.status === "executed"
            ? "Approved and executed."
            : "Approved.",
        );
      }
    } catch (err) {
      await refreshCore();
      await refreshViewSpecific();
      showToast(err instanceof Error ? err.message : "Approval failed");
    }
  }

  async function handleBatchResolveApprovals(
    ids: string[],
    action: "approve" | "reject",
    opts?: { trust_command?: boolean },
  ) {
    if (ids.length === 0) return;
    try {
      const res = await api.batchResolveApprovals({
        approval_ids: ids,
        action,
        trust_command: Boolean(opts?.trust_command),
      });
      await refreshCore();
      await refreshViewSpecific();
      const added = res.trusted_prefixes_added ?? [];
      if (action === "reject") {
        showToast(`Rejected ${res.resolved_count} item(s).`);
      } else if (added.length > 0) {
        showToast(
          `Approved ${res.resolved_count} item(s) and always allowed: ${added.join(", ")}`,
        );
      } else {
        showToast(`Approved and executed ${res.resolved_count} item(s).`);
      }
    } catch (err) {
      await refreshCore();
      await refreshViewSpecific();
      showToast(err instanceof Error ? err.message : "Batch approval failed");
    }
  }

  async function handleRejectItem(id: string) {
    try {
      await api.resolveApproval(id, { action: "reject" });
      await refreshCore();
      await refreshViewSpecific();
      showToast("Item rejected.");
    } catch (err) {
      await refreshCore();
      await refreshViewSpecific();
      showToast(err instanceof Error ? err.message : "Reject failed");
    }
  }

  function applyQueuedAckStreamState(params: {
    threadKey: string;
    targetType: "bot" | "room";
    targetSlug: string;
    botSlug: string;
    botName: string;
    ack: { run_id: string; queued_behind: number };
  }) {
    const { threadKey, targetType, targetSlug, botSlug, botName, ack } = params;
    if (ack.queued_behind > 0) {
      setQueuedCountByThread((prev) => ({
        ...prev,
        [threadKey]: Math.max(prev[threadKey] ?? 0, ack.queued_behind),
      }));
    } else {
      setActiveStreamByThread((prev) => {
        if (prev[threadKey] && !prev[threadKey].finishing) return prev;
        return {
          ...prev,
          [threadKey]: {
            runId: ack.run_id,
            threadKey,
            targetType,
            targetSlug,
            botSlug,
            botName,
            text: "",
            chips: [],
            startedAt: Date.now(),
          },
        };
      });
    }
  }

  async function handleSendBotMessage(
    slug: string,
    text: string,
    options?: {
      skill_slugs?: string[];
      context_correlation_id?: string;
      target_page_slug?: string;
      reply_to_id?: string;
      attachment_ids?: string[];
    },
  ) {
    const threadKey = `bot:${slug}`;
    const targetBot = bots.find((b) => b.slug === slug);
    try {
      const ack = await api.sendBotMessageAsync(slug, text, options);
      if (ack.user_message) {
        applyTailMessages(slug, [ack.user_message as BotMessage]);
      }
      applyQueuedAckStreamState({
        threadKey,
        targetType: "bot",
        targetSlug: slug,
        botSlug: slug,
        botName: targetBot?.name ?? slug,
        ack,
      });
      setContextCorrelationId(null);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to send message");
      throw err;
    }
  }

  async function handleEditLastBotMessage(slug: string, messageId: string, newText: string) {
    const threadKey = `bot:${slug}`;
    const targetBot = bots.find((b) => b.slug === slug);
    try {
      const ack = await api.editLastBotMessage(slug, messageId, newText);
      const removed = new Set(ack.removed_message_ids ?? [messageId]);
      if (activeMsgBotSlugRef.current === slug || selectedBotSlugRef.current === slug) {
        const filtered = botMessagesRef.current.filter((m) => !removed.has(m.id));
        const nextUserMsg = ack.user_message as BotMessage | null;
        const nextMessages =
          nextUserMsg && !filtered.some((m) => m.id === nextUserMsg.id)
            ? [...filtered, nextUserMsg]
            : filtered;
        const nextTotal = Math.max(
          nextMessages.length,
          botMessagesTotalRef.current - removed.size + (nextUserMsg ? 1 : 0),
        );
        botMessagesRef.current = nextMessages;
        botMessagesTotalRef.current = nextTotal;
        setBotMessages(nextMessages);
        setBotMessagesTotal(nextTotal);
      }
      applyQueuedAckStreamState({
        threadKey,
        targetType: "bot",
        targetSlug: slug,
        botSlug: slug,
        botName: targetBot?.name ?? slug,
        ack,
      });
      void refreshCore();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to re-submit edited message");
      throw err;
    }
  }

  async function handleSendRoomMessage(
    roomSlug: string,
    payload: {
      text: string;
      reply_to_id?: string;
      attachment_ids?: string[];
      skill_slugs?: string[];
      target_page_slug?: string;
      approved_handoff_bot_slug?: string;
    },
  ) {
    const threadKey = `room:${roomSlug}`;
    const rm = rooms.find((r) => r.slug === roomSlug);
    const leadSlug = rm?.coordinator_bot_slug || rm?.member_bot_slugs[0] || "";
    const leadBot = bots.find((b) => b.slug === leadSlug);
    try {
      const ack = await api.sendRoomMessageAsync(roomSlug, payload);
      if (ack.user_message && activeMsgRoomSlugRef.current === roomSlug) {
        const userRoomMsg = ack.user_message as RoomMessage;
        setRoomMessages((prev) =>
          prev.some((m) => m.id === userRoomMsg.id) ? prev : [...prev, userRoomMsg],
        );
      }
      applyQueuedAckStreamState({
        threadKey,
        targetType: "room",
        targetSlug: roomSlug,
        botSlug: leadSlug,
        botName: leadBot?.name ?? rm?.title ?? "Room",
        ack,
      });
      setContextCorrelationId(null);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to send room message");
      throw err;
    }
  }

  async function handleEditLastRoomMessage(roomSlug: string, messageId: string, newText: string) {
    const threadKey = `room:${roomSlug}`;
    const rm = rooms.find((r) => r.slug === roomSlug);
    const leadSlug = rm?.coordinator_bot_slug || rm?.member_bot_slugs[0] || "";
    const leadBot = bots.find((b) => b.slug === leadSlug);
    try {
      const ack = await api.editLastRoomMessage(roomSlug, messageId, newText);
      const removed = new Set(ack.removed_message_ids ?? [messageId]);
      if (activeMsgRoomSlugRef.current === roomSlug || selectedRoomSlugRef.current === roomSlug) {
        const nextUserMsg = ack.user_message as RoomMessage | null;
        setRoomMessages((prev) => {
          const filtered = prev.filter((m) => !removed.has(m.id));
          return nextUserMsg && !filtered.some((m) => m.id === nextUserMsg.id)
            ? [...filtered, nextUserMsg]
            : filtered;
        });
        setRoomMessagesTotal((prev) =>
          Math.max(0, prev - removed.size + (nextUserMsg ? 1 : 0)),
        );
      }
      applyQueuedAckStreamState({
        threadKey,
        targetType: "room",
        targetSlug: roomSlug,
        botSlug: leadSlug,
        botName: leadBot?.name ?? rm?.title ?? "Room",
        ack,
      });
      void refreshCore();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to re-submit edited room message");
      throw err;
    }
  }

  async function handleCancelRun(runId: string) {
    try {
      await api.cancelRun(runId);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Unable to stop run");
    }
  }

  async function handleUploadWorkspaceFile(file: File) {
    const uploaded = await api.uploadWorkspaceFile(file);
    await refreshCore();
    showToast(`Uploaded ${uploaded.filename}`);
    return uploaded;
  }

  async function handleDeleteWorkspaceFile(fileId: string) {
    await api.deleteWorkspaceFile(fileId);
    await refreshCore();
    showToast("Removed workspace file.");
  }

  async function handleToggleReaction(
    messageId: string,
    emoji: string,
    collection: "bot_threads" | "room_threads",
  ) {
    await api.toggleMessageReaction(messageId, { collection, emoji });
    await refreshViewSpecific();
  }

  async function handleExecutePlan(plan: DelegationPlan) {
    try {
      if (plan.room_slug) {
        await api.executeRoomPlan(plan.room_slug, plan.id);
      } else {
        await api.executeBotPlan(plan.coordinator_slug, plan.id);
      }
      await refreshViewSpecific();
      await refreshCore();
      showToast(`Completed plan: ${plan.goal}`);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to run delegation plan");
      throw err;
    }
  }

  async function handleExportTeamPack(opts?: {
    room_slug?: string;
    bot_slugs?: string[];
    section?: string;
    title?: string;
  }) {
    const pack = await api.exportTeamPack(opts);
    const blob = new Blob([JSON.stringify(pack, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const baseName = (opts?.room_slug || opts?.section || opts?.bot_slugs?.[0] || "argo")
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-");
    link.download = `${baseName}-team-pack.json`;
    link.click();
    URL.revokeObjectURL(url);
    showToast(`Exported sanitized Team Pack "${pack.title}".`);
  }

  async function handleSaveSkill(payload: {
    name: string;
    description?: string;
    instructions: string;
    scope_slug?: string;
  }) {
    await api.upsertSkill(payload);
    await refreshCore();
    showToast(`Saved reusable Skill "${payload.name}".`);
  }

  async function handleExportBlueprint(slug: string) {
    const blueprint = await api.exportBotBlueprint(slug);
    const blob = new Blob([JSON.stringify(blueprint, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${slug}-blueprint.json`;
    link.click();
    URL.revokeObjectURL(url);
    showToast(`Exported sanitized blueprint for ${slug}.`);
  }

  async function handleDeleteBot(slug: string) {
    const botName = bots.find((b) => b.slug === slug)?.name ?? slug;
    try {
      if (modal?.type === "selkies" && modal.desktop.bot_slug === slug) {
        setModal(null);
      }
      await api.deleteBot(slug);
      setRunningBots((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
      setActiveStreamByThread((prev) => {
        const tk = `bot:${slug}`;
        if (!(tk in prev)) return prev;
        const next = { ...prev };
        delete next[tk];
        return next;
      });
      setQueuedCountByThread((prev) => {
        const tk = `bot:${slug}`;
        if (!(tk in prev)) return prev;
        const next = { ...prev };
        delete next[tk];
        return next;
      });
      setDesktopBootBySlug((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
      setTogglingDesktops((prev) => {
        if (!(slug in prev)) return prev;
        const next = { ...prev };
        delete next[slug];
        return next;
      });
      if (activeMsgBotSlugRef.current === slug || selectedBotSlug === slug) {
        activeMsgBotSlugRef.current = null;
        botMessagesRef.current = [];
        botMessagesTotalRef.current = 0;
        setBotMessages([]);
        setBotMessagesHasMore(false);
        setBotMessagesTotal(0);
        setLoadingBotMessages(false);
      }
      const remaining = bots.filter((b) => b.slug !== slug);
      setSelectedBotSlug((prev) => {
        if (prev && prev !== slug && remaining.some((b) => b.slug === prev)) return prev;
        return remaining[0]?.slug ?? null;
      });
      if (remaining.length === 0 && activeView === "bot") {
        setActiveView("activity");
      }
      if (selectedBotSlug === slug) {
        setMobileThreadOpen(false);
      }
      setInspectorOpen(false);
      await refreshCore();
      showToast(`Removed bot ${botName}.`);
    } catch (err) {
      showToast(err instanceof Error ? err.message : `Failed to remove bot ${botName}`);
      throw err;
    }
  }

  async function handleClearBotMessages(slug: string, opts?: { keep_last?: number }) {
    const res = await api.clearBotMessages(slug, opts);
    if (activeMsgBotSlugRef.current === slug || selectedBotSlugRef.current === slug) {
      botMessagesRef.current = res.messages;
      botMessagesTotalRef.current = res.total_count;
      setBotMessages(res.messages);
      setBotMessagesHasMore(res.has_more);
      setBotMessagesTotal(res.total_count);
    }
    await refreshCore();
    showToast(
      res.deleted_count > 0
        ? `Cleared ${res.deleted_count} message${res.deleted_count === 1 ? "" : "s"}.`
        : "No messages removed.",
    );
  }

  async function handleExportBotMessages(slug: string) {
    const filename = await api.exportBotMessagesMarkdown(slug);
    showToast(`Downloaded ${filename}.`);
  }

  async function handleClearRoomMessages(slug: string, opts?: { keep_last?: number }) {
    const res = await api.clearRoomMessages(slug, opts);
    if (activeMsgRoomSlugRef.current === slug || selectedRoomSlugRef.current === slug) {
      setRoomMessages(res.messages);
      setRoomMessagesHasMore(res.has_more);
      setRoomMessagesTotal(res.total_count);
    }
    await refreshCore();
    showToast(
      res.deleted_count > 0
        ? `Cleared ${res.deleted_count} room message${res.deleted_count === 1 ? "" : "s"}.`
        : "No room messages removed.",
    );
  }

  async function handleExportRoomMessages(slug: string) {
    const filename = await api.exportRoomMessagesMarkdown(slug);
    showToast(`Downloaded ${filename}.`);
  }

  function openSelkiesForBot(bot: BotRecord) {
    const existingDesktop = desktops.find((d) => d.bot_slug === bot.slug);
    setModal({
      type: "selkies",
      desktop: existingDesktop ?? {
        bot_slug: bot.slug,
        bot_name: bot.name,
        role: bot.role,
        container_name: `argo-desktop-${bot.slug}`,
        desktop_state: bot.desktop_state === "running" ? "running" : "hibernated",
        ram_mb: bot.ram_mb,
        ram_limit_mb: bot.ram_limit_mb,
        cdp_port: 9222,
        selkies_port: 3000,
        mcp_port: 9223,
      },
    });
  }

  const handleStartTakeover = useCallback(
    async (slug: string) => {
      const res = await api.startDesktopTakeover(slug);
      await refreshCore();
      return res.desktop;
    },
    [refreshCore],
  );

  const handleReleaseTakeover = useCallback(
    async (slug: string) => {
      const res = await api.releaseDesktopTakeover(slug);
      await refreshCore();
      await refreshViewSpecific();
      showToast(`Released desktop control for ${slug}.`);
      return res.desktop;
    },
    [refreshCore, refreshViewSpecific, showToast],
  );

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (modal) {
        if (modal.type === "selkies") {
          void handleReleaseTakeover(modal.desktop.bot_slug).finally(() => setModal(null));
        } else {
          setModal(null);
        }
        return;
      }
      if (settingsOpen) {
        setSettingsOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [modal, settingsOpen, handleReleaseTakeover]);

  const pendingApprovalsCount = summary?.counts.pending_approvals ?? 0;
  const activeThreadKey = selectedRoom
    ? `room:${selectedRoom.slug}`
    : selectedBot
      ? `bot:${selectedBot.slug}`
      : null;
  const activeThreadStream = activeThreadKey
    ? activeStreamByThread[activeThreadKey] ?? null
    : null;
  const activeThreadQueuedCount = activeThreadKey
    ? queuedCountByThread[activeThreadKey] ?? 0
    : 0;
  const activeBotRun = selectedRoom
    ? runningBots[selectedRoom.coordinator_bot_slug || selectedRoom.member_bot_slugs[0] || ""] ?? null
    : selectedBot
      ? runningBots[selectedBot.slug] ?? null
      : null;
  const isBotSplitActive = !isMobile && activeView === "bot" && Boolean(splitPage);
  const isMobileBotsHub = isMobile && activeView === "bot" && !mobileThreadOpen;
  const isMobilePagesHub = isMobile && activeView === "page" && !mobilePageOpen;
  const showMobileBottomNav =
    isMobile &&
    (isMobileBotsHub ||
      isMobilePagesHub ||
      activeView === "approvals" ||
      activeView === "activity");
  const showMainHeader = !isMobileBotsHub && !isMobilePagesHub;
  const botHasSshAccess = Boolean(
    !selectedRoom &&
      selectedBot &&
      (vaultSecrets.some(
        (v) =>
          v.secret_type === "ssh" &&
          (v.allowed_bots.includes("*") || v.allowed_bots.includes(selectedBot.slug)),
      ) ||
        botMessages.some(
          (m) =>
            Array.isArray(m.metadata?.actions) &&
            m.metadata.actions.some((a) => String(a.type ?? "").startsWith("ssh_")),
        )),
  );

  let centerTitle = "Activity";
  let centerTag: string | null = null;
  let centerSubtitle = "Bot updates, handoffs, and system notices";

  if (activeView === "bot") {
    if (selectedRoom) {
      centerTitle = selectedRoom.title;
      centerTag = `${selectedRoom.member_bot_slugs.length} Bots · Team Room`;
      centerSubtitle = activeBotRun
        ? activeBotRun.step
        : "Tag a bot to route directly, or describe a shared goal";
    } else {
      centerTitle = selectedBot?.name ?? "Bots";
      centerTag =
        selectedBot?.runtime === "desktop"
          ? "Virtual Desktop"
          : selectedBot?.runtime === "sandbox"
            ? "Script Sandbox"
            : null;
      centerSubtitle = activeBotRun
        ? activeBotRun.step
        : selectedBot
          ? `${friendlyAutonomyLabel(selectedBot.outbound_rbac)} · ${friendlyModelName(selectedBot.model)}`
          : "Choose or create a bot to start automating tasks";
    }
  } else if (activeView === "approvals") {
    centerTitle = "Approvals";
    centerTag = pendingApprovalsCount > 0 ? `${pendingApprovalsCount} waiting` : null;
    centerSubtitle = "Review drafts and proposed changes before anything sends";
  } else if (activeView === "page") {
    centerTitle = selectedPage?.title ?? "Pages";
    centerTag = selectedPage ? "Interactive Page" : null;
    centerSubtitle = "Live data views and interactive pages updated by your bots";
  }

  if (!authChecked) {
    return (
      <div className="min-h-dvh w-full bg-slate-100 dark:bg-[#0f1218] text-slate-600 dark:text-slate-300 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin" />
      </div>
    );
  }

  if (authConfig?.needs_setup) {
    return (
      <AuthGate
        mode="bootstrap"
        authConfig={authConfig}
        initialError={authErrorParam}
        onAuthenticated={async () => {
          setAuthErrorParam(null);
          await loadAuthAndWorkspace();
        }}
      />
    );
  }

  if (authConfig && authConfig.auth_mode !== "sso" && !principal?.authenticated) {
    return (
      <AuthGate
        mode="login"
        authConfig={authConfig}
        initialError={authErrorParam}
        onAuthenticated={async () => {
          setAuthErrorParam(null);
          await loadAuthAndWorkspace();
        }}
      />
    );
  }

  if (principal?.must_change_password) {
    return (
      <AuthGate
        mode="change_password"
        authConfig={authConfig}
        principal={principal}
        onAuthenticated={async () => {
          setAuthErrorParam(null);
          await loadAuthAndWorkspace();
        }}
        onLogout={handleSignOut}
      />
    );
  }

  if (standalonePageSlug) {
    const ownerBot =
      bots.find((b) => b.slug === standalonePage?.owner_bot_slug) ?? null;
    return (
      <div className="h-screen w-screen overflow-hidden bg-slate-50 text-slate-900">
        <PagesView
          standalone
          theme={theme}
          page={standalonePage}
          liveStatus={liveStatus}
          ownerBot={ownerBot}
          bots={bots}
          lastActivityId={events[0]?.id ?? null}
          onTriggerBot={(slug) => handleTriggerBot(slug)}
          onOpenBot={(slug) => {
            window.location.href = `/?view=bot&slug=${encodeURIComponent(slug)}`;
          }}
          onOpenApprovals={() => {
            window.location.href = "/?view=approvals";
          }}
          onOpenNewPage={() => undefined}
          onDeletePage={async () => undefined}
        />
      </div>
    );
  }

  return (
    <div className="flex h-[var(--argo-vh,100dvh)] w-screen overflow-hidden bg-slate-50 text-slate-900">
      {!isMobile && (
        <Sidebar
          activeView={activeView}
          selectedBotSlug={selectedRoom ? null : selectedBot?.slug ?? null}
          selectedRoomSlug={selectedRoom?.slug ?? null}
          selectedPageSlug={selectedPage?.slug ?? null}
          splitPageSlug={splitPage?.slug ?? null}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          onSwitchView={handleSwitchView}
          onSelectRoom={handleSelectRoom}
          onOpenNewBot={() => setModal({ type: "new-bot" })}
          onOpenNewRoom={() => setModal({ type: "new-bot", initialTab: "room" })}
          onOpenNewPage={() => setModal({ type: "new-page" })}
          onOpenPageInSplit={(pageSlug) => handleOpenPage(pageSlug, true)}
          onOpenSettings={handleOpenSettings}
          onToggleBotPin={(slug, nextPinned) => {
            void api.updateBot(slug, { pinned: nextPinned }).then(() => refreshCore());
          }}
          onToggleBotHidden={(slug, nextHidden) => {
            void api.updateBot(slug, { hidden_in_sidebar: nextHidden }).then(() => refreshCore());
          }}
          onDeleteBot={handleDeleteBot}
          bots={bots}
          rooms={rooms}
          pages={pages}
          integrations={integrations}
          runningBots={runningBots}
          liveStatus={liveStatus}
          summary={summary}
          principal={principal}
          theme={theme}
          onToggleTheme={setTheme}
          onSignOut={() => void handleSignOut()}
        />
      )}

      <main className="flex-1 flex flex-col min-w-0 h-full bg-slate-50">
        {showMainHeader && isMobile && (
          <header className="shrink-0 argo-safe-top border-b border-slate-200 bg-white px-3">
            <div className="h-14 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0 flex-1">
                {(activeView === "bot" || activeView === "page") ? (
                  <button
                    type="button"
                    onClick={() => {
                      setInspectorOpen(false);
                      if (activeView === "bot") {
                        setMobileThreadOpen(false);
                      } else {
                        setMobilePageOpen(false);
                      }
                    }}
                    aria-label={activeView === "bot" ? "Back to Bots" : "Back to Pages"}
                    className="w-9 h-9 -ml-1 rounded-full flex items-center justify-center text-slate-700 hover:bg-slate-100 shrink-0 cursor-pointer"
                  >
                    <ChevronLeft className="w-5 h-5" />
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => handleOpenSettings("integrations")}
                    aria-label="Settings"
                    className="w-9 h-9 -ml-1 rounded-full flex items-center justify-center text-slate-700 hover:bg-slate-100 shrink-0 cursor-pointer"
                  >
                    <Settings className="w-4 h-4" />
                  </button>
                )}

                {activeView === "bot" && !selectedRoom && selectedBot && (
                  <BotAvatar
                    icon={selectedBot.avatar_icon}
                    color={selectedBot.avatar_color}
                    initials={selectedBot.initials}
                    size="sm"
                  />
                )}
                {activeView === "bot" && selectedRoom && (
                  <div className="flex items-center -space-x-1.5 shrink-0">
                    {selectedRoom.member_bot_slugs
                      .map((slug) => bots.find((b) => b.slug === slug))
                      .filter((b): b is BotRecord => Boolean(b))
                      .slice(0, 2)
                      .map((mb) => (
                        <BotAvatar
                          key={mb.slug}
                          icon={mb.avatar_icon}
                          color={mb.avatar_color}
                          initials={mb.initials}
                          size="xs"
                        />
                      ))}
                  </div>
                )}

                <div className="min-w-0 flex-1">
                  <h1 className="text-[15px] font-semibold text-slate-900 truncate leading-tight">
                    {centerTitle}
                  </h1>
                  <p className="text-[11px] text-slate-500 truncate flex items-center gap-1 leading-tight">
                    {activeView === "bot" && activeBotRun && (
                      <Loader2 className="w-3 h-3 animate-spin text-blue-500 shrink-0" />
                    )}
                    <span className="truncate">{centerSubtitle}</span>
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-1 shrink-0">
                {activeView === "bot" && botHasSshAccess && selectedBot && (
                  <button
                    type="button"
                    aria-label="Live Terminal"
                    onClick={() => {
                      setTerminalModalBotSlug(selectedBot.slug);
                      setTerminalModalSessionId(null);
                    }}
                    className="w-9 h-9 rounded-full border border-slate-200 bg-white text-sky-600 flex items-center justify-center cursor-pointer"
                  >
                    <Terminal className="w-4 h-4" />
                  </button>
                )}
                {activeView === "bot" && !selectedRoom && selectedBot?.runtime === "desktop" && (
                  <button
                    type="button"
                    aria-label="Open Virtual Desktop"
                    onClick={() => openSelkiesForBot(selectedBot)}
                    className="w-9 h-9 rounded-full border border-slate-200 bg-white text-slate-800 flex items-center justify-center cursor-pointer"
                  >
                    <Monitor className="w-4 h-4" />
                  </button>
                )}
                {(activeView === "bot" || activeView === "page") && (
                  <button
                    type="button"
                    aria-label={inspectorOpen ? "Hide Details" : "Bot Details"}
                    onClick={() => setInspectorOpen((v) => !v)}
                    className={`w-9 h-9 rounded-full border flex items-center justify-center cursor-pointer ${
                      inspectorOpen
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-white text-slate-700"
                    }`}
                  >
                    <MoreHorizontal className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          </header>
        )}

        {showMainHeader && !isMobile && (
        <header className="h-14 shrink-0 px-5 border-b border-slate-200 bg-white flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              {selectedRoom && (
                <div className="flex items-center -space-x-1.5 shrink-0">
                  {selectedRoom.member_bot_slugs
                    .map((slug) => bots.find((b) => b.slug === slug))
                    .filter((b): b is BotRecord => Boolean(b))
                    .slice(0, 4)
                    .map((mb) => (
                      <BotAvatar
                        key={mb.slug}
                        icon={mb.avatar_icon}
                        color={mb.avatar_color}
                        initials={mb.initials}
                        size="xs"
                      />
                    ))}
                </div>
              )}
              <h1 className="text-sm font-semibold text-slate-900 truncate">{centerTitle}</h1>
              {centerTag && (
                <span className="inline-flex items-center px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] font-medium text-slate-600">
                  {centerTag}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 truncate flex items-center gap-1.5">
              {activeView === "bot" && activeBotRun && (
                <Loader2 className="w-3 h-3 animate-spin text-blue-500 shrink-0" />
              )}
              <span className="truncate">{centerSubtitle}</span>
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {pendingApprovalsCount > 0 && activeView !== "approvals" && (
              <button
                type="button"
                onClick={() => handleSwitchView("approvals")}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-slate-300 bg-white hover:bg-slate-50 text-xs font-medium text-slate-900 shadow-xs cursor-pointer"
              >
                <span className="w-2 h-2 rounded-full bg-[#c98a2c]" />
                <span>
                  {pendingApprovalsCount} waiting for approval
                </span>
              </button>
            )}
            {activeView === "bot" && (selectedBot || selectedRoom) && (
              <>
                {(() => {
                  const contextualPages = selectedRoom
                    ? pages
                        .filter(
                          (pg) =>
                            pg.slug === selectedRoom.pinned_page_slug ||
                            selectedRoom.member_bot_slugs.includes(pg.owner_bot_slug),
                        )
                        .sort((a, b) =>
                          a.slug === selectedRoom.pinned_page_slug
                            ? -1
                            : b.slug === selectedRoom.pinned_page_slug
                              ? 1
                              : 0,
                        )
                    : selectedBot
                      ? pages.filter((pg) => pg.owner_bot_slug === selectedBot.slug)
                      : [];
                  return (
                    <>
                      {contextualPages
                        .filter((pg) => pg.slug !== splitPage?.slug)
                        .slice(0, 2)
                        .map((pg) => (
                          <button
                            key={pg.id}
                            type="button"
                            onClick={() => handleOpenPage(pg.slug, true)}
                            title={`Dock beside chat: ${pg.title}`}
                            className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-medium text-slate-800 cursor-pointer max-w-[190px]"
                          >
                            <Columns2 className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                            <span className="truncate">{pg.title}</span>
                          </button>
                        ))}
                      {splitPage && (
                        <button
                          type="button"
                          onClick={() => setSplitPageSlug(null)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-900 bg-slate-900 text-white text-xs font-medium cursor-pointer"
                        >
                          <Columns2 className="w-3.5 h-3.5" />
                          <span>Hide Page</span>
                        </button>
                      )}
                    </>
                  );
                })()}
                {!selectedRoom &&
                  selectedBot &&
                  (vaultSecrets.some(
                    (v) =>
                      v.secret_type === "ssh" &&
                      (v.allowed_bots.includes("*") || v.allowed_bots.includes(selectedBot.slug)),
                  ) ||
                    botMessages.some(
                      (m) =>
                        Array.isArray(m.metadata?.actions) &&
                        m.metadata.actions.some((a) => String(a.type ?? "").startsWith("ssh_")),
                    )) && (
                    <button
                      type="button"
                      onClick={() => {
                        setTerminalModalBotSlug(selectedBot.slug);
                        setTerminalModalSessionId(null);
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-200 bg-white text-slate-800 hover:bg-slate-50 text-xs font-medium cursor-pointer"
                    >
                      <Terminal className="w-3.5 h-3.5 text-sky-600" />
                      <span>Live Terminal</span>
                    </button>
                  )}
                {!selectedRoom && selectedBot?.runtime === "desktop" && (
                  <button
                    type="button"
                    onClick={() => openSelkiesForBot(selectedBot)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-200 bg-white text-slate-800 hover:bg-slate-50 text-xs font-medium cursor-pointer"
                  >
                    <Monitor className="w-3.5 h-3.5" />
                    <span>Open Desktop</span>
                  </button>
                )}
                {!selectedRoom && selectedBot && (
                  <button
                    type="button"
                    disabled={Boolean(activeBotRun) || !selectedBot.enabled}
                    onClick={() => void handleTriggerBot(selectedBot.slug)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900 text-white hover:bg-slate-800 disabled:opacity-60 text-xs font-medium cursor-pointer"
                  >
                    {activeBotRun && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>{activeBotRun ? "Running..." : "Run Now"}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setInspectorOpen((v) => !v)}
                  className={`px-3 py-1.5 rounded-full border text-xs font-medium cursor-pointer ${
                    inspectorOpen
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-200 bg-white text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  {inspectorOpen ? "Hide Details" : "Details"}
                </button>
              </>
            )}
            {activeView === "page" && selectedPage && (
              <>
                {pageOwnerBot && (
                  <button
                    type="button"
                    onClick={() => handleSwitchView("bot", pageOwnerBot.slug)}
                    className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-medium text-slate-700 cursor-pointer"
                  >
                    <span>{pageOwnerBot.name}</span>
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setInspectorOpen((v) => !v)}
                  className={`px-3 py-1.5 rounded-full border text-xs font-medium cursor-pointer ${
                    inspectorOpen
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-200 bg-white text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  {inspectorOpen ? "Hide Details" : "Details"}
                </button>
                <button
                  type="button"
                  onClick={() => handleSwitchView("bot", pageOwnerBot?.slug ?? undefined)}
                  title="Close Page"
                  aria-label="Close Page"
                  className="p-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </>
            )}
          </div>
        </header>
        )}

        <section className="flex-1 min-h-0">
          {isMobileBotsHub ? (
            <MobileBotsHub
              bots={bots}
              rooms={rooms}
              integrations={integrations}
              runningBots={runningBots}
              liveStatus={liveStatus}
              summary={summary}
              principal={principal}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              onSelectBot={(slug) => handleSwitchView("bot", slug)}
              onSelectRoom={handleSelectRoom}
              onOpenNewBot={() => setModal({ type: "new-bot" })}
              onOpenNewRoom={() => setModal({ type: "new-bot", initialTab: "room" })}
              onOpenSettings={handleOpenSettings}
            />
          ) : isMobilePagesHub ? (
            <MobilePagesHub
              pages={pages}
              bots={bots}
              onSelectPage={(slug) => handleSwitchView("page", slug)}
              onOpenNewPage={() => setModal({ type: "new-page" })}
              onOpenSettings={handleOpenSettings}
            />
          ) : (
          <>
          {activeView === "activity" && (
            <ActivityView
              events={events}
              bots={bots}
              filter={activityFilter}
              onFilterChange={setActivityFilter}
              onDispatch={async (instruction, targetSlug) => {
                if (targetSlug && bots.some((b) => b.slug === targetSlug)) {
                  await handleSendBotMessage(targetSlug, instruction);
                  showToast(`Sent instruction to ${targetSlug}.`);
                } else {
                  const fallbackSlug = bots.find((b) => b.enabled)?.slug ?? bots[0]?.slug;
                  if (!fallbackSlug) {
                    showToast("Create a bot first to send workspace instructions.");
                    return;
                  }
                  await api.dispatchActivity(instruction, fallbackSlug);
                  await refreshCore();
                  showToast(`Sent instruction to ${fallbackSlug}.`);
                }
              }}
              onOpenApprovals={() => handleSwitchView("approvals")}
              onContinueInChat={(botSlug, corrId) => {
                setSelectedRoomSlug(null);
                setSelectedBotSlug(botSlug);
                setContextCorrelationId(corrId);
                setActiveView("bot");
                setMobileThreadOpen(true);
              }}
            />
          )}

          {activeView === "bot" && (
            <div className={isBotSplitActive ? "flex h-full min-h-0 overflow-hidden" : "h-full min-h-0"}>
              <div className={isBotSplitActive ? "flex-1 min-w-[360px] h-full min-h-0" : "h-full min-h-0"}>
                <ViewErrorBoundary
                  resetKey={selectedRoom ? `room:${selectedRoom.slug}` : `bot:${selectedBot?.slug ?? "none"}`}
                  title={
                    selectedRoom
                      ? `Unable to render Room "${selectedRoom.title}"`
                      : selectedBot
                        ? `Unable to render messages for ${selectedBot.name}`
                        : "Unable to render thread view"
                  }
                  onRetry={() => void refreshViewSpecific()}
                  onDeleteBot={
                    !selectedRoom && selectedBot
                      ? () => void handleDeleteBot(selectedBot.slug)
                      : undefined
                  }
                >
                  <BotThreadView
                    bot={selectedRoom ? null : selectedBot}
                    room={selectedRoom}
                    bots={bots}
                    messages={botMessages}
                    roomMessages={roomMessages}
                    approvals={approvals}
                    integrations={integrations}
                    models={modelsData?.providers ?? []}
                    pages={pages}
                    skills={skills}
                    vaultSecrets={vaultSecrets}
                    workspaceFiles={workspaceFiles}
                    activeRun={activeBotRun}
                    activeStream={activeThreadStream}
                    queuedCount={activeThreadQueuedCount}
                    desktopBootProgress={
                      !selectedRoom && selectedBot ? desktopBootBySlug[selectedBot.slug] ?? null : null
                    }
                    contextCorrelationId={contextCorrelationId}
                    targetPageSlug={splitPage?.slug ?? null}
                    onClearContextCorrelation={() => setContextCorrelationId(null)}
                    onSendMessage={handleSendBotMessage}
                    onSendRoomMessage={handleSendRoomMessage}
                    onEditLastMessage={
                      selectedRoom
                        ? (msgId, nextText) =>
                            handleEditLastRoomMessage(selectedRoom.slug, msgId, nextText)
                        : selectedBot
                          ? (msgId, nextText) =>
                              handleEditLastBotMessage(selectedBot.slug, msgId, nextText)
                          : undefined
                    }
                    onCancelRun={handleCancelRun}
                    onUploadFile={handleUploadWorkspaceFile}
                    onExecutePlan={handleExecutePlan}
                    onToggleReaction={handleToggleReaction}
                    onOpenNewBot={() => setModal({ type: "new-bot" })}
                    onTriggerBot={(slug) => handleTriggerBot(slug)}
                    onUpdateBot={async (slug, updates) => {
                      await api.updateBot(slug, updates);
                      await refreshCore();
                      showToast(`Updated ${slug}.`);
                    }}
                    onApproveItem={handleApproveItem}
                    onBatchResolveApprovals={handleBatchResolveApprovals}
                    onRejectItem={handleRejectItem}
                    onEditApprovalItem={(item) => setModal({ type: "edit-approval", item })}
                    onOpenPage={(pageSlug, sideBySide) =>
                      handleOpenPage(pageSlug, Boolean(sideBySide))
                    }
                    onOpenSelkies={openSelkiesForBot}
                    onOpenTerminal={(bSlug, sessionId) => {
                      setTerminalModalBotSlug(bSlug);
                      setTerminalModalSessionId(sessionId ?? null);
                    }}
                    onSaveSkill={handleSaveSkill}
                    hasMoreMessages={selectedRoom ? roomMessagesHasMore : botMessagesHasMore}
                    totalMessagesCount={selectedRoom ? roomMessagesTotal : botMessagesTotal}
                    loadingMessages={selectedRoom ? loadingRoomMessages : loadingBotMessages}
                    loadingOlderMessages={
                      selectedRoom ? loadingOlderRoomMessages : loadingOlderMessages
                    }
                    onLoadOlderMessages={
                      selectedRoom ? handleLoadOlderRoomMessages : handleLoadOlderMessages
                    }
                    prefillDraft={prefillDraft}
                    onConsumePrefillDraft={() => setPrefillDraft(null)}
                  />
                </ViewErrorBoundary>
              </div>
              {isBotSplitActive && splitPage && (
                <div className="w-[48%] min-w-[360px] h-full min-h-0 border-l border-slate-200">
                  <ViewErrorBoundary
                    resetKey={`split-page:${splitPage.slug}`}
                    title={`Unable to render Page "${splitPage.title}"`}
                    onRetry={() => void refreshCore()}
                  >
                    <PagesView
                      splitMode
                      theme={theme}
                      page={splitPage}
                      liveStatus={liveStatus}
                      ownerBot={splitPageOwnerBot}
                      bots={bots}
                      lastActivityId={events[0]?.id ?? null}
                      activeOwnerRun={
                        splitPageOwnerBot ? runningBots[splitPageOwnerBot.slug] ?? null : null
                      }
                      onSendMessageToOwner={handleSendBotMessage}
                      onPrefillChat={handlePrefillChat}
                      onOpenBot={(slug) => handleSwitchView("bot", slug)}
                      onOpenRoom={handleSelectRoom}
                      onOpenApprovals={() => handleSwitchView("approvals")}
                      onTriggerBot={(slug) => handleTriggerBot(slug)}
                      onPageUpdated={refreshCore}
                      onOpenNewPage={() => setModal({ type: "new-page" })}
                      onDeletePage={async () => undefined}
                      onCloseSplit={() => setSplitPageSlug(null)}
                      onExpandFull={(slug) => handleOpenPage(slug, false)}
                    />
                  </ViewErrorBoundary>
                </div>
              )}
            </div>
          )}

          {activeView === "approvals" && (
            <ApprovalsView
              tab={approvalTab}
              onTabChange={setApprovalTab}
              pendingCount={summary?.counts.pending_approvals ?? 0}
              approvals={approvals}
              styleRules={styleRules}
              bots={bots}
              integrations={integrations}
              onApprove={handleApproveItem}
              onBatchResolve={handleBatchResolveApprovals}
              onReject={handleRejectItem}
              onEditApproval={(item) => setModal({ type: "edit-approval", item })}
              onOpenBotTerminal={(botSlug) => {
                setTerminalModalBotSlug(botSlug);
                setTerminalModalSessionId(null);
              }}
              onAddStyleRule={async (ruleText) => {
                await api.addStyleRule(ruleText);
                await refreshViewSpecific();
                showToast("Saved style rule.");
              }}
              onDeleteStyleRule={async (id) => {
                await api.deleteStyleRule(id);
                await refreshViewSpecific();
              }}
            />
          )}

          {activeView === "page" && (
            <ViewErrorBoundary
              resetKey={`page:${selectedPage?.slug ?? "none"}`}
              title={selectedPage ? `Unable to render Page "${selectedPage.title}"` : "Unable to render Page"}
              onRetry={() => void refreshCore()}
            >
              <PagesView
                theme={theme}
                page={selectedPage}
                liveStatus={liveStatus}
                ownerBot={
                  bots.find((b) => b.slug === selectedPage?.owner_bot_slug) ??
                  bots[0] ??
                  null
                }
                bots={bots}
                lastActivityId={events[0]?.id ?? null}
                activeOwnerRun={pageOwnerBot ? runningBots[pageOwnerBot.slug] ?? null : null}
                onSendMessageToOwner={handleSendBotMessage}
                onPrefillChat={handlePrefillChat}
                onOpenBot={(slug) => handleSwitchView("bot", slug)}
                onOpenRoom={handleSelectRoom}
                onDockSideBySide={(slug) => handleOpenPage(slug, true)}
                onOpenApprovals={() => handleSwitchView("approvals")}
                onTriggerBot={(slug) => handleTriggerBot(slug)}
                onPageUpdated={refreshCore}
                onOpenNewPage={() => setModal({ type: "new-page" })}
                onDeletePage={async (slug) => {
                  await api.deletePage(slug);
                  await refreshCore();
                  setSelectedPageSlug((prev) => {
                    if (prev !== slug) return prev;
                    const remaining = pages.filter((p) => p.slug !== slug);
                    return remaining[0]?.slug ?? null;
                  });
                  showToast(`Deleted page ${slug}`);
                }}
              />
            </ViewErrorBoundary>
          )}

          {activeView === "desktops" && (
            <DesktopsView
              principal={principal}
              host={desktopHost ?? summary?.host ?? null}
              desktops={desktops}
              sandboxes={sandboxes}
              queuedLaunches={desktopQueuedLaunches}
              togglingDesktops={togglingDesktops}
              togglingSandboxes={togglingSandboxes}
              desktopBootBySlug={desktopBootBySlug}
              onToggleDesktop={(slug) => void handleToggleDesktop(slug)}
              onToggleSandbox={(slug) => void handleToggleSandbox(slug)}
              onStopAllDesktops={async () => {
                const res = await api.stopAllDesktops();
                await refreshCore();
                await refreshViewSpecific();
                showToast(
                  res.stopped_desktops.length > 0
                    ? `Paused desktops: ${res.stopped_desktops.join(", ")}`
                    : "No active desktops to pause.",
                );
              }}
              onStopAllSandboxes={async () => {
                const res = await api.stopAllSandboxes();
                await refreshCore();
                await refreshViewSpecific();
                showToast(
                  res.stopped_sandboxes.length > 0
                    ? `Stopped sandboxes: ${res.stopped_sandboxes.join(", ")}`
                    : "No active sandboxes to stop.",
                );
              }}
              onOpenSelkies={(desktop) => setModal({ type: "selkies", desktop })}
              onDeleteBot={handleDeleteBot}
            />
          )}

          {activeView === "integrations" && (
            <IntegrationsView
              principal={principal}
              integrations={integrations}
              onOpenGoogleWizard={(reauthAccount) =>
                setModal({ type: "google-wizard", reauthAccount })
              }
              onOpenTelegramWizard={() => setModal({ type: "telegram-onboard" })}
              onOpenLinkedInModal={() => setModal({ type: "linkedin-onboard" })}
              onOpenWebhookModal={() => setModal({ type: "webhook-onboard" })}
              onOpenNewIntegration={(defaultProvider) =>
                setModal({ type: "new-integration", defaultProvider })
              }
              onAddPublicMonitor={async (channelHandle) => {
                try {
                  const res = await api.addTelegramPublicMonitor({
                    channel_handle: channelHandle,
                    sync_immediately: true,
                  });
                  await refreshCore();
                  showToast(
                    res.sync_summary
                      ? `Synced ${channelHandle}: ${res.sync_summary.new_count} new`
                      : `Added public channel monitor ${channelHandle}`,
                  );
                } catch (err) {
                  showToast(
                    err instanceof Error ? err.message : `Failed to add monitor ${channelHandle}`,
                  );
                }
              }}
              onSyncIntegration={async (slug) => {
                const summaryRes = await api.syncIntegration(slug);
                await refreshCore();
                showToast(
                  `Synced ${slug}: ${summaryRes.new_count} new of ${summaryRes.fetched_count} posts`,
                );
              }}
              onTestIntegration={async (slug) => {
                await api.testIntegration(slug);
                await refreshCore();
                showToast(`Connection ${slug} is healthy.`);
              }}
              onSendTestMessage={async (slug) => {
                await api.testIntegration(slug, true);
                await refreshCore();
                showToast(`Sent test message via ${slug}.`);
              }}
              onProbeAll={async () => {
                const res = await api.probeAllIntegrations();
                await refreshCore();
                showToast(
                  `Checked ${res.total} connections: ${res.ok} healthy, ${res.degraded} degraded.`,
                );
              }}
              onDeleteIntegration={async (slug) => {
                await api.deleteIntegration(slug);
                await refreshCore();
                showToast(`Removed connection ${slug}.`);
              }}
            />
          )}

          {activeView === "models" && (
            <ModelsView
              principal={principal}
              modelsData={modelsData}
              onOpenNewModel={(initial) => setModal({ type: "new-model", initial })}
              onSetDefaultModel={async (slug) => {
                await api.setDefaultModel(slug);
                await refreshCore();
                showToast(`Set ${slug} as default model.`);
              }}
              onTestModel={async (slug) => {
                const res = await api.testModel(slug);
                await refreshCore();
                showToast(`Verified ${res.model_id} (${res.latency_ms} ms).`);
              }}
              onDeleteModel={async (slug) => {
                await api.deleteModel(slug);
                await refreshCore();
                showToast(`Removed model ${slug}.`);
              }}
            />
          )}
          </>
          )}
        </section>

        {showMobileBottomNav && (
          <MobileBottomNav
            activeView={activeView}
            pendingApprovals={pendingApprovalsCount}
            onSelectTab={(tab) => {
              setInspectorOpen(false);
              if (tab === "bot") {
                setMobileThreadOpen(false);
                setActiveView("bot");
              } else if (tab === "page") {
                setMobilePageOpen(false);
                setActiveView("page");
              } else {
                setActiveView(tab);
              }
            }}
          />
        )}
      </main>

      {inspectorOpen && (activeView === "bot" || activeView === "page") && (
        <div
          className={
            isMobile
              ? "fixed inset-0 z-40 bg-white argo-safe-top argo-safe-bottom"
              : isBotSplitActive
                ? "fixed right-0 top-14 bottom-0 z-40 shadow-2xl"
                : "h-full shrink-0"
          }
        >
          <Inspector
            principal={principal}
            teams={teams}
            bot={inspectorBot}
            room={activeView === "bot" ? selectedRoom : null}
            bots={bots}
            pages={pages}
            collections={collections}
            skills={skills}
            workspaceFiles={workspaceFiles}
            activePageSlug={activeView === "page" ? selectedPage?.slug ?? null : splitPage?.slug ?? null}
            initialTab={
              inspectorTabOverride
                ? inspectorTabOverride
                : activeView === "page"
                  ? "library"
                  : "details"
            }
            theme={theme}
            models={modelsData?.providers ?? []}
            integrations={integrations}
            vaultSecrets={vaultSecrets}
            styleRules={styleRules}
            onHide={() => {
              setInspectorOpen(false);
              setInspectorTabOverride(null);
            }}
            onInspectDebug={(slug) => setModal({ type: "debug", botSlug: slug })}
            onUpdateBot={async (slug, updates) => {
              await api.updateBot(slug, updates);
              await refreshCore();
              showToast(`Updated ${slug}.`);
            }}
            onUpdateRoom={async (slug, updates) => {
              await api.updateRoom(slug, updates);
              await refreshCore();
              showToast(`Updated room ${slug}.`);
            }}
            onDeleteRoom={async (slug) => {
              await api.deleteRoom(slug);
              setActiveStreamByThread((prev) => {
                const tk = `room:${slug}`;
                if (!(tk in prev)) return prev;
                const next = { ...prev };
                delete next[tk];
                return next;
              });
              setQueuedCountByThread((prev) => {
                const tk = `room:${slug}`;
                if (!(tk in prev)) return prev;
                const next = { ...prev };
                delete next[tk];
                return next;
              });
              setSelectedRoomSlug(null);
              setInspectorOpen(false);
              await refreshCore();
              showToast(`Deleted room ${slug}.`);
            }}
            onUploadFile={handleUploadWorkspaceFile}
            onDeleteFile={handleDeleteWorkspaceFile}
            onDeleteSkill={async (id) => {
              await api.deleteSkill(id);
              await refreshCore();
              showToast("Deleted skill.");
            }}
            onExportTeamPack={handleExportTeamPack}
            onDockPage={(pSlug) => handleOpenPage(pSlug, true)}
          onAddStyleRule={async (ruleText, scopeSlug) => {
            await api.addStyleRule(ruleText, scopeSlug);
            await refreshCore();
            showToast("Saved bot rule.");
          }}
          onDeleteStyleRule={async (ruleId) => {
            await api.deleteStyleRule(ruleId);
            await refreshCore();
          }}
          onTriggerBot={(slug, routineId) => handleTriggerBot(slug, routineId)}
          togglingDesktop={inspectorBot ? Boolean(togglingDesktops[inspectorBot.slug]) : false}
          togglingSandbox={inspectorBot ? Boolean(togglingSandboxes[inspectorBot.slug]) : false}
          desktopInfo={inspectorBot ? desktops.find((d) => d.bot_slug === inspectorBot.slug) ?? null : null}
          desktopBootProgress={inspectorBot ? desktopBootBySlug[inspectorBot.slug] ?? null : null}
          sshRefreshTick={sshRefreshTick}
          onExpandTerminal={(bSlug) => {
            setTerminalModalBotSlug(bSlug);
            setTerminalModalSessionId(null);
          }}
          onToggleDesktop={(slug) => void handleToggleDesktop(slug)}
          onToggleSandbox={(slug) => void handleToggleSandbox(slug)}
          onOpenSelkies={openSelkiesForBot}
          onExportBlueprint={handleExportBlueprint}
          onDeleteBot={handleDeleteBot}
          messageCount={
            selectedRoom
              ? roomMessagesTotal
              : activeView === "page" && inspectorBot?.slug !== selectedBot?.slug
                ? undefined
                : botMessagesTotal
          }
          onClearBotMessages={handleClearBotMessages}
          onExportBotMessages={handleExportBotMessages}
          onClearRoomMessages={handleClearRoomMessages}
          onExportRoomMessages={handleExportRoomMessages}
          onOpenIntegrations={() => handleOpenSettings("integrations")}
          onOpenVault={() => handleOpenSettings("vault")}
          onToggleVaultSecret={async (sec, botSlug) => {
            const allAllowed = sec.allowed_bots.includes("*");
            const nextAllowed = allAllowed
              ? bots.filter((b) => b.slug !== botSlug).map((b) => b.slug)
              : sec.allowed_bots.includes(botSlug)
                ? sec.allowed_bots.filter((s) => s !== botSlug)
                : [...sec.allowed_bots, botSlug];
            await api.updateVaultSecret(sec.slug, { allowed_bots: nextAllowed });
            await refreshCore();
            showToast(`Updated vault access for @${sec.slug}.`);
          }}
          onOpenPage={(slug) => handleSwitchView("page", slug)}
          onOpenNewPage={() => setModal({ type: "new-page" })}
          onTogglePagePin={(slug, nextPinned) => {
            void api.updatePage(slug, { pinned: nextPinned }).then(() => refreshCore());
          }}
          onCreateCompanionWriter={async (sourceBot) => {
            const tgAndSocial = integrations
              .filter((a) => a.provider === "telegram" || a.provider === "linkedin")
              .map((a) => a.slug);
            const sharedWrite = (sourceBot.collections?.write ?? []).filter(
              (c) => c !== "bot_threads",
            );
            const readCols = Array.from(new Set([...sharedWrite, "story_leads", "bot_threads"]));
            const writer = await api.createBot({
              name: `${sourceBot.name} Writer`,
              role: `Turn findings from ${sourceBot.name} into polished stories or drafts`,
              role_prompt: `Receive findings handed off from ${sourceBot.name}, read saved records, craft a clear engaging story or reply with source links, and queue drafts in Approvals.`,
              runtime: "api",
              outbound_rbac: "draft",
              model: "google:gemini-4-argon",
              daily_cap: 10,
              avatar_color: "violet",
              avatar_icon: "pen",
              collections: { read: readCols, write: ["bot_threads"] },
              linked_accounts: tgAndSocial.length > 0 ? tgAndSocial : undefined,
              routines: [
                {
                  type: "manual_trigger",
                  label: `Handoff from ${sourceBot.name}`,
                  schedule: "Manual",
                  enabled: true,
                },
              ],
            });
            await api.updateBot(sourceBot.slug, { handoff_bot_slug: writer.slug });
            await refreshCore();
            showToast(`Created ${writer.name} and linked handoff from ${sourceBot.name}.`);
          }}
        />
        </div>
      )}

      <SettingsModal
        open={settingsOpen}
        activeTab={settingsTab}
        onTabChange={setSettingsTab}
        onClose={() => setSettingsOpen(false)}
        theme={theme}
        onToggleTheme={setTheme}
        summary={summary}
        bots={bots}
        integrations={integrations}
        onOpenGoogleWizard={(reauthAccount) =>
          setModal({ type: "google-wizard", reauthAccount })
        }
        onOpenTelegramWizard={() => setModal({ type: "telegram-onboard" })}
        onOpenLinkedInModal={() => setModal({ type: "linkedin-onboard" })}
        onOpenWebhookModal={() => setModal({ type: "webhook-onboard" })}
        onOpenNewIntegration={(defaultProvider) =>
          setModal({ type: "new-integration", defaultProvider })
        }
        onAddPublicMonitor={async (channelHandle) => {
          const res = await api.addTelegramPublicMonitor({
            channel_handle: channelHandle,
            sync_immediately: true,
          });
          await refreshCore();
          showToast(
            res.sync_summary
              ? `Synced ${channelHandle}: ${res.sync_summary.new_count} new`
              : `Added public channel monitor ${channelHandle}`,
          );
        }}
        onSyncIntegration={async (slug) => {
          const summaryRes = await api.syncIntegration(slug);
          await refreshCore();
          showToast(
            `Synced ${slug}: ${summaryRes.new_count} new of ${summaryRes.fetched_count} posts`,
          );
        }}
        onTestIntegration={async (slug) => {
          await api.testIntegration(slug);
          await refreshCore();
          showToast(`Connection ${slug} is healthy.`);
        }}
        onSendTestMessage={async (slug) => {
          await api.testIntegration(slug, true);
          await refreshCore();
          showToast(`Sent test message via ${slug}.`);
        }}
        onProbeAll={async () => {
          const res = await api.probeAllIntegrations();
          await refreshCore();
          showToast(
            `Checked ${res.total} connections: ${res.ok} healthy, ${res.degraded} degraded.`,
          );
        }}
        onDeleteIntegration={async (slug) => {
          await api.deleteIntegration(slug);
          await refreshCore();
          showToast(`Removed connection ${slug}.`);
        }}
        modelsData={modelsData}
        onOpenNewModel={(initial) => setModal({ type: "new-model", initial })}
        onSetDefaultModel={(slug) => {
          void api
            .setDefaultModel(slug)
            .then(() => {
              void refreshCore();
              showToast(`Set ${slug} as default model.`);
            })
            .catch((err) =>
              showToast(err instanceof Error ? err.message : "Failed to set default model"),
            );
        }}
        onTestModel={(slug) => {
          void api
            .testModel(slug)
            .then((res) => {
              void refreshCore();
              showToast(`Verified ${res.model_id} (${res.latency_ms} ms).`);
            })
            .catch((err) =>
              showToast(err instanceof Error ? err.message : `Model test failed for ${slug}`),
            );
        }}
        onDeleteModel={(slug) => {
          void api.deleteModel(slug).then(() => {
            void refreshCore();
            showToast(`Removed model ${slug}.`);
          });
        }}
        onPauseBot={async (botSlug) => {
          await api.updateBot(botSlug, { enabled: false });
          await refreshCore();
          showToast(`Paused ${botSlug}.`);
        }}
        onSwitchBotToFlash={async (botSlug) => {
          await api.updateBot(botSlug, { model: "google:gemini-3.8-flash" });
          await refreshCore();
          showToast(`Switched ${botSlug} to Gemini 3.8 Flash.`);
        }}
        desktopHost={desktopHost ?? summary?.host ?? null}
        desktops={desktops}
        sandboxes={sandboxes}
        queuedLaunches={desktopQueuedLaunches}
        togglingDesktops={togglingDesktops}
        togglingSandboxes={togglingSandboxes}
        desktopBootBySlug={desktopBootBySlug}
        onToggleDesktop={(slug) => void handleToggleDesktop(slug)}
        onToggleSandbox={(slug) => void handleToggleSandbox(slug)}
        onStopAllDesktops={async () => {
          const res = await api.stopAllDesktops();
          await refreshCore();
          showToast(
            res.stopped_desktops.length > 0
              ? `Paused desktops: ${res.stopped_desktops.join(", ")}`
              : "No active desktops to pause.",
          );
        }}
        onStopAllSandboxes={async () => {
          const res = await api.stopAllSandboxes();
          await refreshCore();
          showToast(
            res.stopped_sandboxes.length > 0
              ? `Stopped sandboxes: ${res.stopped_sandboxes.join(", ")}`
              : "No active sandboxes to stop.",
          );
        }}
        onOpenSelkies={(desktop) => setModal({ type: "selkies", desktop })}
        onDeleteBot={handleDeleteBot}
        styleRules={styleRules}
        onAddStyleRule={async (ruleText, scopeSlug = "*") => {
          await api.addStyleRule(ruleText, scopeSlug);
          await refreshCore();
          showToast("Saved style rule.");
        }}
        onDeleteStyleRule={async (id) => {
          await api.deleteStyleRule(id);
          await refreshCore();
        }}
        onImportMemory={async (rawText, scopeSlug) => {
          const res = await api.importStyleRules(rawText, scopeSlug);
          await refreshCore();
          showToast(`Imported ${res.imported_count} memory rules.`);
          return res.imported_count;
        }}
        skills={skills}
        onSaveSkill={handleSaveSkill}
        onDeleteSkill={async (id) => {
          await api.deleteSkill(id);
          await refreshCore();
          showToast("Deleted skill.");
        }}
        onChatHistoryPruned={() => {
          if (selectedRoomSlugRef.current) {
            void loadRoomMessagesWindow(selectedRoomSlugRef.current, { reset: true });
          } else if (selectedBotSlugRef.current) {
            void loadBotMessagesWindow(selectedBotSlugRef.current, { reset: true });
          }
          void refreshCore();
          showToast("Pruned older chat history.");
        }}
        debugBotSlug={selectedBot?.slug ?? undefined}
        onLoadDebugOverview={(params) => api.getDebugOverview(params)}
        onClearDebug={() => api.clearDebugData()}
        vaultSecrets={vaultSecrets}
        onCreateVaultSecret={async (payload) => {
          const created = await api.createVaultSecret(payload);
          await refreshCore();
          showToast(`Saved encrypted secret @${created.slug}.`);
        }}
        onUpdateVaultSecret={async (slug, payload) => {
          await api.updateVaultSecret(slug, payload);
          await refreshCore();
          showToast(`Updated secret @${slug}.`);
        }}
        onDeleteVaultSecret={async (slug) => {
          await api.deleteVaultSecret(slug);
          await refreshCore();
          showToast(`Deleted secret @${slug}.`);
        }}
        onRefreshVault={async () => {
          await refreshCore();
        }}
        teams={teams}
        onRefreshTeamsAndUsers={refreshCore}
        principal={principal}
        onSignOut={() => void handleSignOut()}
      />

      <Modals
        modal={modal}
        teams={teams}
        principal={principal}
        onClose={() => setModal(null)}
        models={modelsData?.providers ?? []}
        integrations={integrations}
        bots={bots}
        collections={collections}
        onSkillSaved={refreshCore}
        desktopBootBySlug={desktopBootBySlug}
        onLoadDebugOverview={(params) => api.getDebugOverview(params)}
        onClearDebug={() => api.clearDebugData()}
        onDraftBotSpec={(payload) => api.draftBotSpec(payload)}
        onCreateBot={async (payload) => {
          const created = await api.createBot(payload);
          await refreshCore();
          setSelectedRoomSlug(null);
          setSelectedBotSlug(created.slug);
          setActiveView("bot");
          setMobileThreadOpen(true);
          showToast(`Created bot ${created.name}`);
        }}
        onCreateRoom={async (payload) => {
          const created = await api.createRoom(payload);
          await refreshCore();
          setSelectedRoomSlug(created.slug);
          setActiveView("bot");
          setMobileThreadOpen(true);
          void loadRoomMessagesWindow(created.slug, { reset: true });
          showToast(`Created Room "${created.title}"`);
        }}
        onImportTeamPack={async (payload) => {
          const imported = await api.importTeamPack(payload);
          await refreshCore();
          if (imported.rooms?.[0]) {
            setSelectedRoomSlug(imported.rooms[0].slug);
            setActiveView("bot");
            void loadRoomMessagesWindow(imported.rooms[0].slug, { reset: true });
          } else if (imported.bots?.[0]) {
            setSelectedRoomSlug(null);
            setSelectedBotSlug(imported.bots[0].slug);
            setActiveView("bot");
          }
          showToast(
            `Installed Team Pack: ${imported.bots.length} bot(s), ${imported.rooms.length} room(s).`,
          );
        }}
        onCreatePipeline={async (pipeline) => {
          const writer = await api.createBot({
            ...(pipeline.visibility
              ? {
                  visibility: pipeline.visibility,
                  ...(pipeline.visibility === "team" && pipeline.allowed_groups
                    ? { allowed_groups: pipeline.allowed_groups }
                    : {}),
                }
              : {}),
            name: pipeline.writerName,
            role: pipeline.writerStyle.slice(0, 160) || "Write stories from Scout leads",
            role_prompt: pipeline.writerStyle,
            runtime: "api",
            outbound_rbac: "draft",
            model: "google:gemini-4-argon",
            daily_cap: 10,
            avatar_color: "violet",
            avatar_icon: "pen",
            collections: { read: ["story_leads", "bot_threads"], write: ["bot_threads"] },
            linked_accounts:
              pipeline.writerAccounts.length > 0 ? pipeline.writerAccounts : undefined,
            routines: [
              {
                type: "manual_trigger",
                label: "Write on Scout Handoff",
                schedule: "Manual",
                enabled: true,
              },
            ],
          });
          const scout = await api.createBot({
            ...(pipeline.visibility
              ? {
                  visibility: pipeline.visibility,
                  ...(pipeline.visibility === "team" && pipeline.allowed_groups
                    ? { allowed_groups: pipeline.allowed_groups }
                    : {}),
                }
              : {}),
            name: pipeline.scoutName,
            role: pipeline.scoutSource.slice(0, 160) || "Collect leads for Story Writer",
            role_prompt: `${pipeline.scoutSource}\n\nWhen you find valuable items, save them to collection 'story_leads' and delegate to @${writer.slug}.`,
            runtime: "api",
            outbound_rbac: "internal",
            model: "google:gemini-3.8-flash",
            daily_cap: 0,
            avatar_color: "blue",
            avatar_icon: "mail",
            collections: {
              read: ["story_leads", "bot_threads"],
              write: ["story_leads", "bot_threads"],
            },
            linked_accounts:
              pipeline.scoutAccounts.length > 0 ? pipeline.scoutAccounts : undefined,
            handoff_bot_slug: writer.slug,
            routines: [
              {
                type: pipeline.scoutSchedule === "Manual" ? "manual_trigger" : "cron",
                label: "Scheduled Check",
                schedule: pipeline.scoutSchedule,
                enabled: true,
              },
            ],
          });
          await refreshCore();
          setSelectedBotSlug(scout.slug);
          setActiveView("bot");
          showToast(`Created pipeline: ${scout.name} -> ${writer.name}`);
        }}
        onImportBlueprint={async (payload) => {
          const created = await api.importBotBlueprint(payload);
          await refreshCore();
          setSelectedBotSlug(created.slug);
          setActiveView("bot");
          showToast(`Imported blueprint as ${created.name}`);
        }}
        onCreatePage={async (payload) => {
          const created = await api.createPage(payload);
          await refreshCore();
          setSelectedPageSlug(created.slug);
          setActiveView("page");
          setMobilePageOpen(true);
          showToast(`Created page ${created.title}`);
        }}
        onGeneratePage={async (payload) => {
          const created = await api.generatePage(payload);
          await refreshCore();
          setSelectedPageSlug(created.slug);
          setActiveView("page");
          setMobilePageOpen(true);
          showToast(`Created living page ${created.title}`);
        }}
        onStartTakeover={handleStartTakeover}
        onReleaseTakeover={handleReleaseTakeover}
        onResolveEditedApproval={async (id, editedText, styleRule) => {
          try {
            const res = await api.resolveApproval(id, {
              action: "edit_approve",
              edited_text: editedText,
              style_rule: styleRule || undefined,
            });
            await refreshCore();
            await refreshViewSpecific();
            const isSsh = res.action_type === "ssh_exec" || res.action_type === "ssh_input";
            if (res.error_message) {
              showToast(res.error_message);
            } else if (isSsh && res.status === "executed") {
              showToast("Updated, approved, and ran SSH command — output sent to bot chat.");
            } else {
              showToast("Draft updated, approved, and preference saved.");
            }
          } catch (err) {
            await refreshCore();
            await refreshViewSpecific();
            showToast(err instanceof Error ? err.message : "Approval edit failed");
          }
        }}
        onUpsertIntegration={async (payload) => {
          await api.upsertIntegration(payload);
          await refreshCore();
          await refreshViewSpecific();
          showToast(`Saved connection ${payload.slug}`);
        }}
        onOnboardTelegram={async (payload) => {
          try {
            const acc = await api.onboardTelegram(payload);
            await refreshCore();
            await refreshViewSpecific();
            showToast(`Connected Telegram bot ${acc.display_name}`);
          } catch (err) {
            showToast(err instanceof Error ? err.message : "Telegram setup failed");
            throw err;
          }
        }}
        onLoadGoogleWizardConfig={() => api.getGoogleWizardConfig()}
        onStartGoogleOAuth={(payload) => api.startGoogleOAuth(payload)}
        onCompleteGoogleOAuth={async (payload) => {
          try {
            const acc = await api.completeGoogleOAuth(payload);
            await refreshCore();
            await refreshViewSpecific();
            showToast(`Connected Google account ${acc.display_name}`);
            return acc;
          } catch (err) {
            showToast(err instanceof Error ? err.message : "Google sign-in failed");
            throw err;
          }
        }}
        onOnboardLinkedIn={async (payload) => {
          try {
            const acc = await api.onboardLinkedIn(payload);
            await refreshCore();
            await refreshViewSpecific();
            showToast(`Connected LinkedIn account ${acc.display_name}`);
          } catch (err) {
            showToast(err instanceof Error ? err.message : "LinkedIn setup failed");
            throw err;
          }
        }}
        onOnboardWebhook={async (payload) => {
          try {
            const res = await api.onboardWebhook(payload);
            await refreshCore();
            await refreshViewSpecific();
            showToast(`Created signed webhook ${res.slug}`);
            return res;
          } catch (err) {
            showToast(err instanceof Error ? err.message : "Webhook setup failed");
            throw err;
          }
        }}
        onUpsertModel={async (payload) => {
          await api.upsertModel(payload);
          await refreshCore();
          showToast(`Saved model ${payload.slug}`);
        }}
      />

      {terminalModalBotSlug && (
        <div
          className="fixed inset-0 z-50 argo-modal-backdrop flex items-center justify-center p-0 sm:p-4"
          onClick={() => {
            setTerminalModalBotSlug(null);
            setTerminalModalSessionId(null);
          }}
        >
          <div
            className="w-full sm:max-w-6xl h-[100dvh] sm:h-auto sm:max-h-[92vh] rounded-none sm:rounded-2xl border-0 sm:border argo-modal-panel overflow-hidden flex flex-col argo-safe-top argo-safe-bottom"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-4 py-3 border-b border-slate-200 argo-modal-header flex items-center justify-between gap-3 shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <Terminal className="w-4 h-4 text-slate-600 shrink-0" />
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-900 truncate">
                    Live Terminal ·{" "}
                    {bots.find((b) => b.slug === terminalModalBotSlug)?.name ?? terminalModalBotSlug}
                  </div>
                  <div className="hidden sm:block text-[11px] text-slate-500">
                    Watch live in read-only View Mode, switch host tabs, Take Over anytime, or Replay recordings.
                  </div>
                </div>
              </div>
              <button
                type="button"
                aria-label="Close Live Terminal"
                onClick={() => {
                  setTerminalModalBotSlug(null);
                  setTerminalModalSessionId(null);
                }}
                className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 cursor-pointer shrink-0"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-3 sm:p-4 flex-1 min-h-0 overflow-y-auto">
              <SSHTerminalPanel
                botSlug={terminalModalBotSlug}
                theme={theme}
                variant="modal"
                initialSessionId={terminalModalSessionId}
                refreshTick={sshRefreshTick}
                hasPermittedSSH={vaultSecrets.some(
                  (v) =>
                    v.secret_type === "ssh" &&
                    (v.allowed_bots.includes("*") ||
                      v.allowed_bots.includes(terminalModalBotSlug)),
                )}
                onStatusToast={showToast}
              />
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div
          className={`fixed z-[70] px-4 py-2.5 rounded-xl bg-slate-950 text-white border border-slate-700 text-xs font-medium shadow-xl ${
            showMobileBottomNav
              ? "bottom-20 left-4 right-4 md:left-auto md:right-5 md:bottom-5"
              : "bottom-5 left-4 right-4 md:left-auto md:right-5"
          }`}
        >
          {toast}
        </div>
      )}
    </div>
  );
}
