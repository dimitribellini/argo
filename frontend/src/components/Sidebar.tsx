import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckSquare,
  ChevronDown,
  ChevronRight,
  Columns2,
  Eye,
  EyeOff,
  FileText,
  Loader2,
  LogOut,
  Moon,
  Pin,
  Plus,
  Search,
  Settings,
  Sun,
  Trash2,
  Users,
} from "lucide-react";
import type {
  BotRecord,
  BotRunActivity,
  IntegrationAccount,
  LiveWorkspaceStatusResponse,
  PageRecord,
  RoomRecord,
  SettingsTab,
  SsoPrincipal,
  ViewId,
  WorkspaceSummary,
} from "../types";
import { formatFriendlyTime, stripMarkdownPreview } from "../utils/format";
import { BotAvatar, type BotStatusDot } from "./BotAvatar";

interface SidebarProps {
  activeView: ViewId;
  selectedBotSlug: string | null;
  selectedRoomSlug?: string | null;
  selectedPageSlug: string | null;
  splitPageSlug?: string | null;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  onSwitchView: (view: ViewId, slug?: string) => void;
  onSelectRoom?: (roomSlug: string) => void;
  onOpenNewBot: () => void;
  onOpenNewRoom?: () => void;
  onOpenNewPage: () => void;
  onOpenPageInSplit?: (pageSlug: string) => void;
  onOpenSettings: (tab?: SettingsTab) => void;
  onToggleBotPin: (slug: string, nextPinned: boolean) => void;
  onToggleBotHidden: (slug: string, nextHidden: boolean) => void;
  onDeleteBot?: (slug: string) => Promise<void>;
  bots: BotRecord[];
  rooms?: RoomRecord[];
  pages: PageRecord[];
  integrations: IntegrationAccount[];
  runningBots?: Record<string, BotRunActivity>;
  liveStatus?: LiveWorkspaceStatusResponse | null;
  summary: WorkspaceSummary | null;
  principal: SsoPrincipal | null;
  theme: "light" | "dark";
  onToggleTheme: (next: "light" | "dark") => void;
  onSignOut?: () => void;
}

export function Sidebar({
  activeView,
  selectedBotSlug,
  selectedRoomSlug = null,
  selectedPageSlug,
  splitPageSlug = null,
  searchQuery,
  onSearchChange,
  onSwitchView,
  onSelectRoom,
  onOpenNewBot,
  onOpenNewRoom,
  onOpenNewPage,
  onOpenPageInSplit,
  onOpenSettings,
  onToggleBotPin,
  onToggleBotHidden,
  onDeleteBot,
  bots,
  rooms = [],
  pages,
  integrations,
  runningBots = {},
  liveStatus = null,
  summary,
  principal,
  theme,
  onToggleTheme,
  onSignOut,
}: SidebarProps) {
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [showHiddenBots, setShowHiddenBots] = useState(false);
  const [confirmDeleteSlug, setConfirmDeleteSlug] = useState<string | null>(null);
  const [deletingSlug, setDeletingSlug] = useState<string | null>(null);

  const query = searchQuery.trim().toLowerCase();
  const filteredPages = pages.filter((p) => !query || p.title.toLowerCase().includes(query));
  const filteredRooms = rooms.filter(
    (r) =>
      !query ||
      r.title.toLowerCase().includes(query) ||
      r.member_bot_slugs.some((m) => m.toLowerCase().includes(query)),
  );
  const filteredBots = bots.filter(
    (b) =>
      !query ||
      b.name.toLowerCase().includes(query) ||
      b.role.toLowerCase().includes(query) ||
      (b.section ?? "").toLowerCase().includes(query),
  );

  const visibleBots = showHiddenBots
    ? filteredBots
    : filteredBots.filter((b) => !b.hidden_in_sidebar || b.slug === selectedBotSlug);
  const hiddenCount = filteredBots.filter((b) => b.hidden_in_sidebar).length;

  const pinnedBots = visibleBots.filter((b) => b.pinned);
  const sectionGroups = new Map<string, BotRecord[]>();
  const ungroupedBots: BotRecord[] = [];
  for (const bot of visibleBots) {
    if (bot.pinned) continue;
    const sec = (bot.section ?? "").trim();
    if (sec) {
      const list = sectionGroups.get(sec) ?? [];
      list.push(bot);
      sectionGroups.set(sec, list);
    } else {
      ungroupedBots.push(bot);
    }
  }

  const pendingApprovals = summary?.counts.pending_approvals ?? 0;
  const ramPct = summary?.host.ram_percent ?? 0;
  const hasExpiredIntegration = integrations.some(
    (acc) => acc.status === "expired" || acc.status === "degraded",
  );
  const hasHealthAlert = ramPct >= 80 || hasExpiredIntegration;

  const navBtnClass = (isActive: boolean) =>
    `flex items-center justify-between w-full px-2.5 py-1.5 rounded-xl text-[13px] font-medium transition text-left cursor-pointer border ${
      isActive
        ? "bg-white border-slate-200 shadow-xs font-semibold text-slate-900"
        : "border-transparent text-slate-700 hover:bg-slate-200"
    }`;

  const stationBySlug = new Map((liveStatus?.bots ?? []).map((s) => [s.slug, s]));
  const roomStationBySlug = new Map((liveStatus?.rooms ?? []).map((s) => [s.slug, s]));
  const botBySlug = new Map(bots.map((b) => [b.slug, b]));

  function getBotVisualStatus(bot: BotRecord) {
    const isSelected = activeView === "bot" && !selectedRoomSlug && selectedBotSlug === bot.slug;
    const activeRun = runningBots[bot.slug];
    const station = stationBySlug.get(bot.slug);
    const isRunning = Boolean(activeRun) || station?.state === "running";
    const activeStep = activeRun?.step || station?.active_step || "Working...";
    const pendingCount = station?.pending_approvals_count ?? 0;

    const statusDot: BotStatusDot = isRunning
      ? "running"
      : station?.state === "takeover_needed"
        ? "takeover_needed"
        : pendingCount > 0
          ? "waiting_approval"
          : !bot.enabled
            ? "paused"
            : (bot.runtime === "desktop" && bot.desktop_state === "running") ||
                (bot.runtime === "sandbox" && bot.sandbox_state === "running")
              ? "desktop"
              : "active";

    const primaryRoutine = (bot.routines ?? []).find((r) => r.enabled) ?? bot.routines?.[0];
    const scheduleText = station?.schedule_label || primaryRoutine?.schedule || "Manual";
    const lastRunRel = station?.last_run_at ? formatFriendlyTime(station.last_run_at) : "";
    const handoffTarget = bot.handoff_bot_slug ? botBySlug.get(bot.handoff_bot_slug) : undefined;
    const rawSub = stripMarkdownPreview(station?.last_action_subtitle ?? "");
    const cleanSub = /^(?:completed on |fallback succeeded on |ready! action mode)/i.test(rawSub)
      ? ""
      : rawSub;

    let sublineText = cleanSub || (lastRunRel ? `${scheduleText} · ${lastRunRel}` : scheduleText);
    let sublineClass = "text-slate-500";
    if (isRunning) {
      sublineText = activeStep;
      sublineClass = "text-blue-500 font-medium";
    } else if (station?.state === "takeover_needed") {
      sublineText = "Sign-in needed";
      sublineClass = "text-rose-600 font-medium";
    } else if (pendingCount > 0) {
      sublineText = `${pendingCount} waiting for approval`;
      sublineClass = "text-amber-600 font-medium";
    } else if (!bot.enabled) {
      sublineText = "Paused";
      sublineClass = "text-slate-400";
    } else if (!station?.last_action_subtitle && handoffTarget) {
      sublineText = `${scheduleText} → ${handoffTarget.name}`;
    }

    const isUnread = Boolean(station?.unread) && !isSelected;
    return { isSelected, isRunning, statusDot, sublineText, sublineClass, isUnread };
  }

  async function confirmAndDeleteBot(slug: string) {
    if (!onDeleteBot || deletingSlug) return;
    setDeletingSlug(slug);
    try {
      await onDeleteBot(slug);
      setConfirmDeleteSlug(null);
    } finally {
      setDeletingSlug(null);
    }
  }

  function renderBotRow(bot: BotRecord) {
    const { isSelected, isRunning, statusDot, sublineText, sublineClass, isUnread } =
      getBotVisualStatus(bot);
    const isConfirming = confirmDeleteSlug === bot.slug;
    const isDeleting = deletingSlug === bot.slug;

    if (isConfirming) {
      return (
        <div
          key={bot.id}
          onClick={(e) => e.stopPropagation()}
          className="rounded-xl border border-rose-200 bg-rose-50 px-2.5 py-2 flex items-center justify-between gap-1.5"
        >
          <span className="text-[11px] font-medium text-rose-700 truncate">
            Delete {bot.name}?
          </span>
          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              disabled={isDeleting}
              onClick={(e) => {
                e.stopPropagation();
                void confirmAndDeleteBot(bot.slug);
              }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-rose-600 hover:bg-rose-700 text-white text-[10.5px] font-medium disabled:opacity-50 cursor-pointer"
            >
              {isDeleting && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
              <span>{isDeleting ? "..." : "Delete"}</span>
            </button>
            <button
              type="button"
              disabled={isDeleting}
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDeleteSlug(null);
              }}
              className="px-1.5 py-0.5 rounded-md border border-slate-200 bg-white text-[10.5px] text-slate-600 hover:bg-slate-100 cursor-pointer"
            >
              Cancel
            </button>
          </div>
        </div>
      );
    }

    return (
      <div key={bot.id} className="group relative flex items-center">
        <button
          type="button"
          onClick={() => onSwitchView("bot", bot.slug)}
          className={`${navBtnClass(isSelected)} ${onDeleteBot ? "pr-16" : "pr-11"} py-2`}
        >
          <div className="flex items-center gap-2.5 min-w-0 w-full">
            <BotAvatar
              icon={bot.avatar_icon}
              color={bot.avatar_color}
              initials={bot.initials}
              size="sm"
              statusDot={statusDot}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-xs font-medium text-slate-900 truncate">{bot.name}</span>
                {isRunning && (
                  <Loader2 className="w-3 h-3 animate-spin text-blue-500 shrink-0" />
                )}
                {isUnread && !isRunning && (
                  <span
                    className="w-2 h-2 rounded-full bg-[#3b72b2] shrink-0"
                    title="Unread update"
                  />
                )}
              </div>
              <div className={`text-[10px] truncate leading-tight mt-0.5 ${sublineClass}`}>
                {sublineText}
              </div>
            </div>
          </div>
        </button>
        <div className="absolute right-1.5 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            type="button"
            title={bot.pinned ? "Unpin bot" : "Pin bot"}
            onClick={(e) => {
              e.stopPropagation();
              onToggleBotPin(bot.slug, !bot.pinned);
            }}
            className={`p-1 rounded hover:bg-slate-200 cursor-pointer ${
              bot.pinned ? "text-amber-600" : "text-slate-400 hover:text-slate-700"
            }`}
          >
            <Pin className="w-3 h-3" />
          </button>
          <button
            type="button"
            title={bot.hidden_in_sidebar ? "Show in sidebar" : "Hide from sidebar"}
            onClick={(e) => {
              e.stopPropagation();
              onToggleBotHidden(bot.slug, !bot.hidden_in_sidebar);
            }}
            className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-200 cursor-pointer"
          >
            {bot.hidden_in_sidebar ? <Eye className="w-3 h-3" /> : <EyeOff className="w-3 h-3" />}
          </button>
          {onDeleteBot && (
            <button
              type="button"
              title="Delete bot"
              onClick={(e) => {
                e.stopPropagation();
                setConfirmDeleteSlug(bot.slug);
              }}
              className="p-1 rounded text-slate-400 hover:text-rose-600 hover:bg-slate-200 cursor-pointer"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <aside className="w-[260px] shrink-0 h-full flex flex-col border-r border-slate-200 bg-slate-100">
      <div className="px-4 pt-4 pb-3 flex items-center justify-between border-b border-slate-200">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-slate-900 text-white flex items-center justify-center text-xs font-bold tracking-tight shadow-xs">
            A
          </div>
          <div className="text-sm font-semibold text-slate-900 tracking-tight">Argo</div>
        </div>
        <button
          type="button"
          onClick={onOpenNewBot}
          className="inline-flex items-center gap-1 bg-slate-900 text-white px-2.5 py-1.5 rounded-lg text-xs font-medium shadow-xs hover:bg-slate-800 transition cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          New Bot
        </button>
      </div>

      <div className="px-3 pt-3 pb-2">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search bots, rooms, or pages..."
            className="w-full rounded-xl border border-slate-200 bg-white pl-8 pr-3 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-300"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto custom-scroll px-3 py-1 space-y-5">
        {/* Primary: Bots & Pinned Hero Cards */}
        <div>
          <div className="px-2 mb-1.5 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Bots
            </span>
            <span className="text-[11px] text-slate-400">{bots.length}</span>
          </div>

          {pinnedBots.length > 0 && (
            <div className="mb-2.5 grid grid-cols-2 gap-1.5">
              {pinnedBots.map((bot) => {
                const { isSelected, isRunning, statusDot, sublineText, isUnread } =
                  getBotVisualStatus(bot);
                if (confirmDeleteSlug === bot.slug) {
                  const isDeleting = deletingSlug === bot.slug;
                  return (
                    <div
                      key={bot.id}
                      onClick={(e) => e.stopPropagation()}
                      className="rounded-xl border border-rose-200 bg-rose-50 p-2 space-y-1.5"
                    >
                      <div className="text-[11px] font-medium text-rose-700 truncate">
                        Delete {bot.name}?
                      </div>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          disabled={isDeleting}
                          onClick={() => void confirmAndDeleteBot(bot.slug)}
                          className="flex-1 inline-flex items-center justify-center gap-1 py-0.5 rounded bg-rose-600 text-white text-[10px] font-medium disabled:opacity-50 cursor-pointer"
                        >
                          {isDeleting && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
                          <span>Delete</span>
                        </button>
                        <button
                          type="button"
                          disabled={isDeleting}
                          onClick={() => setConfirmDeleteSlug(null)}
                          className="flex-1 py-0.5 rounded border border-slate-200 bg-white text-slate-600 text-[10px] cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  );
                }
                return (
                  <div
                    key={bot.id}
                    className={`group relative rounded-xl border p-2 transition cursor-pointer ${
                      isSelected
                        ? "bg-white border-slate-300 shadow-xs"
                        : "bg-white border-slate-200 hover:border-slate-300"
                    }`}
                    onClick={() => onSwitchView("bot", bot.slug)}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <BotAvatar
                        icon={bot.avatar_icon}
                        color={bot.avatar_color}
                        initials={bot.initials}
                        size="sm"
                        statusDot={statusDot}
                      />
                      <div className="flex items-center gap-1">
                        {isRunning && <Loader2 className="w-3 h-3 animate-spin text-blue-500" />}
                        {isUnread && !isRunning && (
                          <span
                            className="w-2 h-2 rounded-full bg-[#3b72b2]"
                            title="Unread update"
                          />
                        )}
                        <button
                          type="button"
                          title="Unpin"
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleBotPin(bot.slug, false);
                          }}
                          className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-amber-600 hover:bg-slate-100 cursor-pointer"
                        >
                          <Pin className="w-2.5 h-2.5" />
                        </button>
                        {onDeleteBot && (
                          <button
                            type="button"
                            title="Delete bot"
                            onClick={(e) => {
                              e.stopPropagation();
                              setConfirmDeleteSlug(bot.slug);
                            }}
                            className="opacity-0 group-hover:opacity-100 p-0.5 rounded text-slate-400 hover:text-rose-600 hover:bg-slate-100 cursor-pointer"
                          >
                            <Trash2 className="w-2.5 h-2.5" />
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="text-[11.5px] font-semibold text-slate-900 truncate">
                      {bot.name}
                    </div>
                    <div className="text-[10px] text-slate-500 truncate mt-0.5">{sublineText}</div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Multi-Bot Group Rooms (shown when 1+ Rooms exist) */}
          {filteredRooms.length > 0 && (
            <div className="mb-2.5">
              <div className="px-2 mb-1 flex items-center justify-between">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Rooms
                </span>
                {onOpenNewRoom && (
                  <button
                    type="button"
                    onClick={onOpenNewRoom}
                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full border border-slate-300 bg-white text-[10px] font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                  >
                    <Plus className="w-2.5 h-2.5" />
                    <span>Room</span>
                  </button>
                )}
              </div>
              <div className="space-y-0.5">
                {filteredRooms.map((room) => {
                  const isRoomSelected = activeView === "bot" && selectedRoomSlug === room.slug;
                  const roomStation = roomStationBySlug.get(room.slug);
                  const roomUnread = Boolean(roomStation?.unread) && !isRoomSelected;
                  const subtitle =
                    stripMarkdownPreview(roomStation?.last_message_preview ?? "") ||
                    `${room.member_bot_slugs.length} bots`;
                  const memberBots = room.member_bot_slugs
                    .map((s) => botBySlug.get(s))
                    .filter((b): b is BotRecord => Boolean(b));
                  return (
                    <button
                      key={room.id}
                      type="button"
                      onClick={() => onSelectRoom?.(room.slug)}
                      className={`${navBtnClass(isRoomSelected)} py-2`}
                    >
                      <div className="flex items-center gap-2 min-w-0 w-full">
                        {memberBots.length >= 2 ? (
                          <div className="flex items-center -space-x-1.5 shrink-0">
                            {memberBots.slice(0, 2).map((mb) => (
                              <BotAvatar
                                key={mb.slug}
                                icon={mb.avatar_icon}
                                color={mb.avatar_color}
                                initials={mb.initials}
                                size="xs"
                              />
                            ))}
                          </div>
                        ) : (
                          <div className="w-7 h-7 rounded-lg bg-slate-200 border border-slate-300 flex items-center justify-center shrink-0">
                            <Users className="w-3.5 h-3.5 text-slate-700" />
                          </div>
                        )}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-1.5">
                            <span className="text-xs font-medium text-slate-900 truncate">
                              {room.title}
                            </span>
                            {roomUnread && (
                              <span
                                className="w-2 h-2 rounded-full bg-[#3b72b2] shrink-0"
                                title="Unread room reply"
                              />
                            )}
                          </div>
                          <div className="text-[10px] text-slate-500 truncate mt-0.5">
                            {subtitle}
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {visibleBots.length === 0 ? (
            <div className="px-2.5 py-2 rounded-xl border border-dashed border-slate-300 text-[11px] text-slate-500">
              No bots yet. Click <strong>+ New Bot</strong> to create one.
            </div>
          ) : (
            <div className="space-y-2">
              {Array.from(sectionGroups.entries()).map(([secName, list]) => {
                const collapsed = Boolean(collapsedSections[secName]);
                return (
                  <div key={secName} className="space-y-0.5">
                    <button
                      type="button"
                      onClick={() =>
                        setCollapsedSections((prev) => ({ ...prev, [secName]: !prev[secName] }))
                      }
                      className="flex items-center justify-between px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 hover:text-slate-800 cursor-pointer w-full text-left"
                    >
                      <span className="flex items-center gap-1 min-w-0">
                        {collapsed ? (
                          <ChevronRight className="w-3 h-3 shrink-0" />
                        ) : (
                          <ChevronDown className="w-3 h-3 shrink-0" />
                        )}
                        <span className="truncate">{secName}</span>
                      </span>
                      <span className="text-[10px] font-normal text-slate-400">{list.length}</span>
                    </button>
                    {!collapsed && list.map((bot) => renderBotRow(bot))}
                  </div>
                );
              })}

              {ungroupedBots.length > 0 && (
                sectionGroups.size > 0 ? (
                  <div className="space-y-0.5">
                    <button
                      type="button"
                      onClick={() =>
                        setCollapsedSections((prev) => ({
                          ...prev,
                          Unassigned: !prev.Unassigned,
                        }))
                      }
                      className="flex items-center justify-between px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 hover:text-slate-800 cursor-pointer w-full text-left"
                    >
                      <span className="flex items-center gap-1">
                        {collapsedSections.Unassigned ? (
                          <ChevronRight className="w-3 h-3" />
                        ) : (
                          <ChevronDown className="w-3 h-3" />
                        )}
                        <span>Unassigned</span>
                      </span>
                      <span className="text-[10px] font-normal text-slate-400">
                        {ungroupedBots.length}
                      </span>
                    </button>
                    {!collapsedSections.Unassigned &&
                      ungroupedBots.map((bot) => renderBotRow(bot))}
                  </div>
                ) : (
                  <div className="space-y-0.5">{ungroupedBots.map((bot) => renderBotRow(bot))}</div>
                )
              )}
            </div>
          )}

          {hiddenCount > 0 && (
            <button
              type="button"
              onClick={() => setShowHiddenBots((v) => !v)}
              className="mt-1.5 px-2.5 py-1 text-[11px] text-slate-500 hover:text-slate-800 cursor-pointer"
            >
              {showHiddenBots ? "Hide background bots" : `Show ${hiddenCount} hidden bot(s)`}
            </button>
          )}
        </div>

        {/* Workspace: Approvals, Activity, Pages */}
        <div>
          <div className="px-2 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Workspace
          </div>
          <div className="space-y-0.5">
            <button
              type="button"
              onClick={() => onSwitchView("approvals")}
              className={navBtnClass(activeView === "approvals")}
            >
              <span className="flex items-center gap-2">
                <CheckSquare className="w-3.5 h-3.5 text-amber-600" />
                <span>Approvals</span>
              </span>
              {pendingApprovals > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500 text-white">
                  {pendingApprovals}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => onSwitchView("activity")}
              className={navBtnClass(activeView === "activity")}
            >
              <span className="flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-emerald-600" />
                <span>Activity</span>
              </span>
            </button>
          </div>

          <div className="mt-3">
            <div className="px-2 mb-1.5 flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Pages
              </span>
              <button
                type="button"
                onClick={onOpenNewPage}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-300 bg-white text-[10.5px] font-semibold text-slate-700 hover:bg-slate-50 cursor-pointer"
              >
                <Plus className="w-2.5 h-2.5" />
                <span>New</span>
              </button>
            </div>
            <div className="space-y-1">
              {filteredPages.length === 0 ? (
                <div className="px-2.5 py-1.5 text-[11px] text-slate-400">No pages yet</div>
              ) : (
                filteredPages.map((page) => {
                  const isActive =
                    (activeView === "page" && selectedPageSlug === page.slug) ||
                    (activeView === "bot" && splitPageSlug === page.slug);
                  return (
                    <div key={page.id} className="group relative flex items-center">
                      <button
                        type="button"
                        onClick={() => onSwitchView("page", page.slug)}
                        className={`w-full flex items-center gap-2 px-3 pr-8 py-1.5 rounded-full border text-left text-xs font-medium transition-colors cursor-pointer ${
                          isActive
                            ? "border-slate-900 bg-slate-900 text-white shadow-xs"
                            : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                        }`}
                      >
                        <FileText
                          className={`w-3.5 h-3.5 shrink-0 ${
                            isActive ? "text-sky-300" : "text-slate-400"
                          }`}
                        />
                        <span className="truncate">{page.title}</span>
                      </button>
                      {onOpenPageInSplit && (
                        <button
                          type="button"
                          title="Dock beside chat"
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenPageInSplit(page.slug);
                          }}
                          className={`absolute right-1.5 p-1 rounded-full opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer ${
                            isActive
                              ? "text-sky-200 hover:bg-slate-700"
                              : "text-slate-400 hover:text-slate-800 hover:bg-slate-200"
                          }`}
                        >
                          <Columns2 className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Operator + Settings Anchor */}
      <div className="p-3 border-t border-slate-200 bg-slate-100 space-y-2">
        {hasHealthAlert && (
          <button
            type="button"
            onClick={() => onOpenSettings(ramPct >= 80 ? "desktops" : "integrations")}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-xl bg-amber-50 border border-amber-200 text-[11px] font-medium text-amber-800 hover:bg-amber-100 cursor-pointer text-left"
          >
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">
              {ramPct >= 80
                ? `High memory usage (${ramPct}%)`
                : "An integration needs attention"}
            </span>
          </button>
        )}

        <div className="flex items-center justify-between gap-2 px-1">
          <button
            type="button"
            onClick={() => onOpenSettings("integrations")}
            className="flex items-center gap-2 min-w-0 flex-1 py-1.5 px-2 rounded-xl hover:bg-slate-200 cursor-pointer text-left"
          >
            <Settings className="w-4 h-4 text-slate-600 shrink-0" />
            <div className="min-w-0">
              <div className="text-xs font-medium text-slate-900">Settings</div>
              {principal?.email && (
                <div className="text-[10px] text-slate-500 truncate">{principal.email}</div>
              )}
            </div>
          </button>

          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              title={theme === "dark" ? "Switch to Light mode" : "Switch to Dark mode"}
              aria-label={theme === "dark" ? "Switch to Light mode" : "Switch to Dark mode"}
              onClick={() => onToggleTheme(theme === "dark" ? "light" : "dark")}
              className="p-2 rounded-xl border border-slate-200 bg-white text-slate-600 hover:text-slate-900 cursor-pointer shrink-0"
            >
              {theme === "dark" ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>
            {onSignOut && (
              <button
                type="button"
                title={principal?.email ? `Sign out (${principal.email})` : "Sign out"}
                aria-label="Sign out"
                onClick={onSignOut}
                className="p-2 rounded-xl border border-slate-200 bg-white text-slate-600 hover:text-rose-700 hover:border-rose-300 cursor-pointer shrink-0"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}
