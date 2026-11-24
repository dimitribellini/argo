import { useState } from "react";
import {
  AlertTriangle,
  Loader2,
  Plus,
  Search,
  Settings,
  Users,
  X,
} from "lucide-react";
import type {
  BotRecord,
  BotRunActivity,
  IntegrationAccount,
  LiveWorkspaceStatusResponse,
  RoomRecord,
  SettingsTab,
  SsoPrincipal,
  WorkspaceSummary,
} from "../types";
import { formatFriendlyTime, stripMarkdownPreview } from "../utils/format";
import { BotAvatar, type BotStatusDot } from "./BotAvatar";

interface MobileBotsHubProps {
  bots: BotRecord[];
  rooms: RoomRecord[];
  integrations: IntegrationAccount[];
  runningBots: Record<string, BotRunActivity>;
  liveStatus: LiveWorkspaceStatusResponse | null;
  summary: WorkspaceSummary | null;
  principal: SsoPrincipal | null;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  onSelectBot: (slug: string) => void;
  onSelectRoom: (roomSlug: string) => void;
  onOpenNewBot: () => void;
  onOpenNewRoom: () => void;
  onOpenSettings: (tab?: SettingsTab) => void;
}

export function MobileBotsHub({
  bots,
  rooms,
  integrations,
  runningBots,
  liveStatus,
  summary,
  principal,
  searchQuery,
  onSearchChange,
  onSelectBot,
  onSelectRoom,
  onOpenNewBot,
  onOpenNewRoom,
  onOpenSettings,
}: MobileBotsHubProps) {
  const [searchOpen, setSearchOpen] = useState(Boolean(searchQuery.trim()));
  const [showHiddenBots, setShowHiddenBots] = useState(false);

  const query = searchQuery.trim().toLowerCase();
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
    : filteredBots.filter((b) => !b.hidden_in_sidebar);
  const hiddenCount = filteredBots.filter((b) => b.hidden_in_sidebar).length;

  const pinnedBots = visibleBots.filter((b) => b.pinned);
  const listBots = visibleBots.filter((b) => !b.pinned);

  const stationBySlug = new Map((liveStatus?.bots ?? []).map((s) => [s.slug, s]));
  const roomStationBySlug = new Map((liveStatus?.rooms ?? []).map((s) => [s.slug, s]));
  const botBySlug = new Map(bots.map((b) => [b.slug, b]));

  const ramPct = summary?.host.ram_percent ?? 0;
  const hasExpiredIntegration = integrations.some(
    (acc) => acc.status === "expired" || acc.status === "degraded",
  );
  const hasHealthAlert = ramPct >= 80 || hasExpiredIntegration;

  const operatorInitial = (
    principal?.actor?.trim() ||
    principal?.email?.trim() ||
    "A"
  )
    .charAt(0)
    .toUpperCase();

  function getBotVisualStatus(bot: BotRecord) {
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

    let sublineText = cleanSub || (handoffTarget ? `${scheduleText} → ${handoffTarget.name}` : bot.role || scheduleText);
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
    }

    const isUnread = Boolean(station?.unread);
    return { isRunning, statusDot, sublineText, sublineClass, isUnread, lastRunRel };
  }

  return (
    <div className="flex flex-col h-full min-h-0 bg-slate-50">
      {/* Top Bar */}
      <header className="shrink-0 argo-safe-top bg-white border-b border-slate-200 px-4">
        <div className="h-14 flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => onOpenSettings("integrations")}
            aria-label="Workspace Settings"
            className="relative inline-flex items-center gap-2.5 min-w-0 cursor-pointer"
          >
            <span className="w-9 h-9 rounded-full bg-slate-900 text-white flex items-center justify-center text-sm font-semibold shrink-0">
              {operatorInitial}
            </span>
            {hasHealthAlert && (
              <span className="absolute -top-0.5 left-6 w-2.5 h-2.5 rounded-full bg-amber-500 ring-2 ring-white" />
            )}
            <div className="text-left min-w-0">
              <div className="text-[15px] font-semibold text-slate-900 leading-tight truncate">
                Argo
              </div>
              <div className="text-[11px] text-slate-500 leading-tight truncate">
                {bots.length} {bots.length === 1 ? "bot" : "bots"}
                {rooms.length > 0 ? ` · ${rooms.length} ${rooms.length === 1 ? "room" : "rooms"}` : ""}
              </div>
            </div>
          </button>

          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => {
                if (searchOpen) {
                  onSearchChange("");
                  setSearchOpen(false);
                } else {
                  setSearchOpen(true);
                }
              }}
              aria-label={searchOpen ? "Close search" : "Search bots"}
              className="w-10 h-10 rounded-full border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 flex items-center justify-center cursor-pointer"
            >
              {searchOpen ? <X className="w-4 h-4" /> : <Search className="w-4 h-4" />}
            </button>
            <button
              type="button"
              onClick={() => onOpenSettings("integrations")}
              aria-label="Settings"
              className="w-10 h-10 rounded-full border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 flex items-center justify-center cursor-pointer"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={onOpenNewBot}
              aria-label="New Bot"
              className="w-10 h-10 rounded-full bg-slate-900 text-white hover:bg-slate-800 flex items-center justify-center cursor-pointer"
            >
              <Plus className="w-5 h-5" />
            </button>
          </div>
        </div>

        {searchOpen && (
          <div className="pb-3">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                autoFocus
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Search bots or team rooms..."
                className="w-full rounded-full border border-slate-200 bg-slate-50 pl-9 pr-9 py-2 text-[16px] text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-300"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => onSearchChange("")}
                  aria-label="Clear search"
                  className="absolute right-2.5 top-2 p-1 text-slate-400 hover:text-slate-700 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        )}
      </header>

      {/* Scrollable Hub Body */}
      <div className="flex-1 overflow-y-auto custom-scroll px-4 py-4 space-y-5">
        {hasHealthAlert && (
          <button
            type="button"
            onClick={() => onOpenSettings(ramPct >= 80 ? "desktops" : "integrations")}
            className="w-full flex items-center gap-2.5 px-3.5 py-2.5 rounded-2xl bg-amber-50 border border-amber-200 text-xs font-medium text-amber-800 text-left cursor-pointer"
          >
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span className="truncate">
              {ramPct >= 80
                ? `High host memory usage (${ramPct}%) — tap to manage Desktops`
                : "An integration needs attention — tap to inspect"}
            </span>
          </button>
        )}

        {/* Pinned Bots Hero Row (Grok-style 3-up circular avatars) */}
        {pinnedBots.length > 0 && (
          <section aria-label="Pinned bots">
            <div className="grid grid-cols-3 gap-3">
              {pinnedBots.map((bot) => {
                const { isRunning, statusDot, isUnread } = getBotVisualStatus(bot);
                return (
                  <button
                    key={bot.id}
                    type="button"
                    onClick={() => onSelectBot(bot.slug)}
                    className="flex flex-col items-center gap-2 py-2 px-1 rounded-2xl active:bg-slate-200/70 transition cursor-pointer"
                  >
                    <div className="relative">
                      <BotAvatar
                        icon={bot.avatar_icon}
                        color={bot.avatar_color}
                        initials={bot.initials}
                        size="lg"
                        statusDot={statusDot}
                        ringClassName="ring-2 ring-[var(--argo-bg)]"
                      />
                      {isRunning && (
                        <span className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-white border border-slate-200 flex items-center justify-center shadow-xs">
                          <Loader2 className="w-3 h-3 animate-spin text-blue-500" />
                        </span>
                      )}
                      {isUnread && !isRunning && (
                        <span className="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-[#3b72b2] ring-2 ring-[var(--argo-bg)]" />
                      )}
                    </div>
                    <span className="text-xs font-semibold text-slate-900 text-center line-clamp-1 w-full">
                      {bot.name}
                    </span>
                  </button>
                );
              })}
            </div>
          </section>
        )}

        {/* Team Rooms */}
        {filteredRooms.length > 0 && (
          <section className="space-y-1.5">
            <div className="flex items-center justify-between px-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Team Rooms
              </span>
              <button
                type="button"
                onClick={onOpenNewRoom}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-[11px] font-medium text-slate-700 cursor-pointer"
              >
                <Plus className="w-3 h-3" />
                <span>Room</span>
              </button>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-100 overflow-hidden">
              {filteredRooms.map((room) => {
                const roomStation = roomStationBySlug.get(room.slug);
                const roomUnread = Boolean(roomStation?.unread);
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
                    onClick={() => onSelectRoom(room.slug)}
                    className="w-full flex items-center gap-3 px-3.5 py-3 text-left active:bg-slate-100 transition cursor-pointer"
                  >
                    {memberBots.length >= 2 ? (
                      <div className="flex items-center -space-x-2 shrink-0">
                        {memberBots.slice(0, 2).map((mb) => (
                          <BotAvatar
                            key={mb.slug}
                            icon={mb.avatar_icon}
                            color={mb.avatar_color}
                            initials={mb.initials}
                            size="sm"
                          />
                        ))}
                      </div>
                    ) : (
                      <div className="w-10 h-10 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center shrink-0">
                        <Users className="w-5 h-5 text-slate-600" />
                      </div>
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-semibold text-slate-900 truncate">
                          {room.title}
                        </span>
                        {roomUnread && (
                          <span className="w-2.5 h-2.5 rounded-full bg-[#3b72b2] shrink-0" />
                        )}
                      </div>
                      <div className="text-xs text-slate-500 truncate mt-0.5">{subtitle}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </section>
        )}

        {/* Main Bots List (Messaging-style rows) */}
        <section className="space-y-1.5">
          {pinnedBots.length > 0 && listBots.length > 0 && (
            <div className="px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              All Bots
            </div>
          )}

          {visibleBots.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 text-center space-y-3">
              <div className="text-sm font-semibold text-slate-900">
                {query ? "No matching bots" : "No bots yet"}
              </div>
              <p className="text-xs text-slate-500">
                {query
                  ? "Try a different search term or clear the filter."
                  : "Create your first bot to automate inbox triage, monitoring, or browser tasks."}
              </p>
              {!query && (
                <button
                  type="button"
                  onClick={onOpenNewBot}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-full bg-slate-900 text-white text-xs font-semibold cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  <span>New Bot</span>
                </button>
              )}
            </div>
          ) : listBots.length > 0 ? (
            <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-100 overflow-hidden">
              {listBots.map((bot) => {
                const { isRunning, statusDot, sublineText, sublineClass, isUnread, lastRunRel } =
                  getBotVisualStatus(bot);
                return (
                  <button
                    key={bot.id}
                    type="button"
                    onClick={() => onSelectBot(bot.slug)}
                    className="w-full flex items-center gap-3 px-3.5 py-3 text-left active:bg-slate-100 transition cursor-pointer"
                  >
                    <BotAvatar
                      icon={bot.avatar_icon}
                      color={bot.avatar_color}
                      initials={bot.initials}
                      size="md"
                      statusDot={statusDot}
                      ringClassName="ring-2 ring-[var(--argo-card)]"
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="text-sm font-semibold text-slate-900 truncate">
                            {bot.name}
                          </span>
                          {isRunning && (
                            <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-500 shrink-0" />
                          )}
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {lastRunRel && (
                            <span className="text-[11px] text-slate-400">{lastRunRel}</span>
                          )}
                          {isUnread && !isRunning && (
                            <span className="w-2.5 h-2.5 rounded-full bg-[#3b72b2]" />
                          )}
                        </div>
                      </div>
                      <div className={`text-xs truncate mt-0.5 ${sublineClass}`}>
                        {sublineText}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          ) : null}

          {hiddenCount > 0 && (
            <button
              type="button"
              onClick={() => setShowHiddenBots((v) => !v)}
              className="w-full py-2 text-xs font-medium text-slate-500 hover:text-slate-800 cursor-pointer"
            >
              {showHiddenBots ? "Hide background bots" : `Show ${hiddenCount} hidden bot(s)`}
            </button>
          )}
        </section>
      </div>
    </div>
  );
}
