import { useMemo, useState, type FormEvent } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  EyeOff,
  FileText,
  Layers,
  Monitor,
  Search,
  Sparkles,
} from "lucide-react";
import type { ActivityEvent, BotRecord } from "../../types";
import { formatFriendlyTime, friendlyModelName } from "../../utils/format";
import { BotAvatar } from "../BotAvatar";

interface ActivityViewProps {
  events: ActivityEvent[];
  bots?: BotRecord[];
  filter: "all" | "reviews" | "alerts";
  onFilterChange: (filter: "all" | "reviews" | "alerts") => void;
  onDispatch: (instruction: string, targetSlug?: string) => Promise<void>;
  onOpenApprovals: () => void;
  onContinueInChat?: (botSlug: string, correlationId: string) => void;
}

const FILTERS: Array<{ key: "all" | "reviews" | "alerts"; label: string }> = [
  { key: "all", label: "All Updates" },
  { key: "reviews", label: "Tasks & Handoffs" },
  { key: "alerts", label: "System Notices" },
];

interface PresentedEvent {
  event: ActivityEvent;
  primaryBot: BotRecord | null;
  handoffLabel: string | null;
  title: string;
  summary: string;
  tag: string | null;
  tagTone: "slate" | "emerald" | "amber" | "red" | "indigo";
  metaLine: string | null;
  isQuiet: boolean;
  needsReview: boolean;
  kind: "bot" | "desktop" | "page" | "approval" | "alert";
}

function formatCompactTokens(raw: number): string {
  if (raw >= 1000) return `${(raw / 1000).toFixed(1).replace(/\.0$/, "")}k tok`;
  return `${raw} tok`;
}

function cleanTriggerLabel(rawTrigger: string): string {
  const lower = rawTrigger.trim().toLowerCase();
  if (lower.startsWith("cron") || lower === "scheduled") return "Scheduled";
  if (lower === "manual_trigger" || lower === "manual") return "Manual";
  if (lower === "operator_event" || lower.startsWith("on_event")) return "Triggered";
  return "";
}

function dayGroupLabel(iso: string): string {
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return "Earlier";
  const now = new Date();
  const sameDay =
    dt.getFullYear() === now.getFullYear() &&
    dt.getMonth() === now.getMonth() &&
    dt.getDate() === now.getDate();
  if (sameDay) return "Today";
  const yest = new Date(now);
  yest.setDate(now.getDate() - 1);
  if (
    dt.getFullYear() === yest.getFullYear() &&
    dt.getMonth() === yest.getMonth() &&
    dt.getDate() === yest.getDate()
  ) {
    return "Yesterday";
  }
  return dt.toLocaleDateString([], { month: "short", day: "numeric" });
}

function presentActivityEvent(
  ev: ActivityEvent,
  botsBySlug: Map<string, BotRecord>,
): PresentedEvent {
  const sourceBot = botsBySlug.get(ev.source_slug) ?? null;
  const targetBot = ev.target_slug ? (botsBySlug.get(ev.target_slug) ?? null) : null;
  const primaryBot = sourceBot ?? targetBot;

  const rawTitle = String(ev.payload.title ?? ev.event_type);
  const rawSummary = String(ev.payload.summary ?? "").trim();
  const rawBadge = String(ev.payload.badge ?? "");
  const rawMeta = String(ev.payload.meta ?? "");
  const rawTone = String(ev.payload.badge_tone ?? "slate");

  const handoffLabel =
    sourceBot && targetBot && sourceBot.slug !== targetBot.slug
      ? `${sourceBot.name} -> ${targetBot.name}`
      : null;

  const isQuietDedup = ev.event_type === "bot.run.deduplicated";
  const isQuietDesktop =
    ev.event_type === "desktop.started" ||
    ev.event_type === "desktop.hibernated" ||
    ev.event_type === "desktop.takeover.started" ||
    ev.event_type === "desktop.takeover.released" ||
    /^Started argo-desktop-|^Hibernated argo-desktop-|^Selkies Takeover/i.test(rawTitle);

  const isQuiet = isQuietDedup || (isQuietDesktop && rawTone !== "red" && rawTone !== "amber");

  let kind: PresentedEvent["kind"] = "bot";
  if (ev.event_type.startsWith("desktop.") || isQuietDesktop) kind = "desktop";
  else if (ev.event_type.startsWith("page.")) kind = "page";
  else if (ev.event_type.startsWith("approval.")) kind = "approval";
  else if (rawTone === "red" || rawTone === "amber") kind = "alert";

  let title = rawTitle;
  let summary = rawSummary;
  let tag: string | null = null;
  let tagTone: PresentedEvent["tagTone"] =
    rawTone === "emerald" || rawTone === "amber" || rawTone === "red" || rawTone === "indigo"
      ? rawTone
      : "slate";

  if (ev.event_type === "bot.run.completed") {
    const trigMatch = /\s+Completed\s*\(([^)]+)\)\s*$/i.exec(rawTitle);
    const trigLabel = trigMatch ? cleanTriggerLabel(trigMatch[1]) : "";
    title = sourceBot?.name ?? rawTitle.replace(/\s+Completed\s*\([^)]+\)\s*$/i, "");
    tag = trigLabel || "Completed";
    tagTone = "emerald";
  } else if (isQuietDedup) {
    title = sourceBot?.name ?? rawTitle.replace(/\s*·\s*0 New Items.*$/i, "");
    summary = "Checked configured sources · no new updates";
    tag = "0 new · 0 tok";
    tagTone = "slate";
  } else if (ev.event_type === "desktop.hibernated" || /^Hibernated argo-desktop-/i.test(rawTitle)) {
    title = targetBot?.name ?? sourceBot?.name ?? "Virtual Desktop";
    summary = "Auto-hibernated after idle timeout · profile saved";
    tag = "Desktop Idle";
    tagTone = "slate";
  } else if (ev.event_type === "desktop.started" || /^Started argo-desktop-/i.test(rawTitle)) {
    title = targetBot?.name ?? sourceBot?.name ?? "Virtual Desktop";
    summary = "Isolated Fedora XFCE desktop started";
    tag = "Desktop Active";
    tagTone = "emerald";
  } else if (/^Selkies Takeover Started/i.test(rawTitle)) {
    title = targetBot?.name ?? sourceBot?.name ?? "Virtual Desktop";
    summary = "Live desktop session opened";
    tag = "Takeover";
    tagTone = "indigo";
  } else if (/^Selkies Takeover Released/i.test(rawTitle)) {
    title = targetBot?.name ?? sourceBot?.name ?? "Virtual Desktop";
    summary = "Live desktop session closed · cookies saved";
    tag = "Session Saved";
    tagTone = "slate";
  } else if (ev.event_type === "page.updated") {
    title = rawTitle.replace(/^(Updated Dynamic Page|Generated Page|Updated Page):\s*/i, "");
    tag = "Page Updated";
    tagTone = "indigo";
  } else if (ev.event_type === "bot.message") {
    title = targetBot ? `Message to ${targetBot.name}` : rawTitle;
    tag = "Chat";
    tagTone = "slate";
  } else if (rawBadge && !/^(Hop 1\/5|Selkies :3000|0 Tokens)/i.test(rawBadge)) {
    tag = rawBadge.replace(/Hop \d+\/\d+\s*·\s*/i, "").trim() || null;
  }

  const metaParts: string[] = [];
  const modelMatch = /([a-z0-9_-]+:[a-z0-9._:/-]+)/i.exec(rawBadge);
  if (modelMatch) {
    metaParts.push(friendlyModelName(modelMatch[1]));
  }
  const tokMatch = /(\d+)\s*tok(?:ens)?\b/i.exec(rawMeta);
  if (tokMatch) {
    const tokCount = Number(tokMatch[1]);
    if (tokCount > 0) metaParts.push(formatCompactTokens(tokCount));
  }
  const actMatch = /(\d+)\s*action\(s\)/i.exec(rawMeta);
  if (actMatch && Number(actMatch[1]) > 0) {
    const count = Number(actMatch[1]);
    metaParts.push(`${count} action${count === 1 ? "" : "s"}`);
  }
  const hopMatch = /Hop\s*(\d+)\/(\d+)/i.exec(`${rawBadge} ${rawMeta}`);
  if (hopMatch && Number(hopMatch[1]) > 1) {
    metaParts.push(`Step ${hopMatch[1]}/${hopMatch[2]}`);
  }

  return {
    event: ev,
    primaryBot,
    handoffLabel,
    title,
    summary,
    tag,
    tagTone,
    metaLine: metaParts.length > 0 ? metaParts.join(" · ") : null,
    isQuiet,
    needsReview: tagTone === "amber" || ev.event_type.startsWith("approval."),
    kind,
  };
}

function badgeClass(tone: PresentedEvent["tagTone"]): string {
  switch (tone) {
    case "emerald":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "amber":
      return "border-amber-200 bg-amber-50 text-amber-800";
    case "red":
      return "border-rose-200 bg-rose-50 text-rose-700";
    case "indigo":
      return "border-indigo-200 bg-indigo-50 text-indigo-700";
    default:
      return "border-slate-200 bg-slate-100 text-slate-600";
  }
}

export function ActivityView({
  events,
  bots = [],
  filter,
  onFilterChange,
  onDispatch,
  onOpenApprovals,
  onContinueInChat,
}: ActivityViewProps) {
  const [instruction, setInstruction] = useState("");
  const [targetBotSlug, setTargetBotSlug] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);
  const [groupByThread, setGroupByThread] = useState(false);
  const [hideQuietChecks, setHideQuietChecks] = useState(true);
  const [selectedBotFilter, setSelectedBotFilter] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [expandedQuietGroups, setExpandedQuietGroups] = useState<Record<string, boolean>>({});

  const botsBySlug = useMemo(() => new Map(bots.map((b) => [b.slug, b])), [bots]);

  const defaultDispatchBot = useMemo(() => {
    const supervisor = bots.find(
      (b) =>
        b.enabled &&
        ((b.tools ?? []).some((t) => typeof t === "object" && t?.name === "platform_status") ||
          b.avatar_icon === "shield"),
    );
    return supervisor ?? bots.find((b) => b.enabled) ?? bots[0] ?? null;
  }, [bots]);

  const activeTargetBot =
    (targetBotSlug ? botsBySlug.get(targetBotSlug) : null) ?? defaultDispatchBot;

  const presentedEvents = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return events
      .filter((ev) => filter === "all" || (ev.payload.category ?? "reviews") === filter)
      .filter((ev) => {
        if (selectedBotFilter === "all") return true;
        return ev.source_slug === selectedBotFilter || ev.target_slug === selectedBotFilter;
      })
      .map((ev) => presentActivityEvent(ev, botsBySlug))
      .filter((item) => {
        if (!q) return true;
        return (
          item.title.toLowerCase().includes(q) ||
          item.summary.toLowerCase().includes(q) ||
          (item.tag ?? "").toLowerCase().includes(q)
        );
      });
  }, [events, filter, selectedBotFilter, searchText, botsBySlug]);

  const quietCount = useMemo(
    () => presentedEvents.filter((item) => item.isQuiet).length,
    [presentedEvents],
  );

  type FeedCluster =
    | { kind: "event"; item: PresentedEvent }
    | { kind: "quiet_cluster"; id: string; items: PresentedEvent[] };

  const daySections = useMemo(() => {
    const byDay = new Map<string, PresentedEvent[]>();
    for (const item of presentedEvents) {
      const label = dayGroupLabel(item.event.created_at);
      const list = byDay.get(label) ?? [];
      list.push(item);
      byDay.set(label, list);
    }

    return Array.from(byDay.entries()).map(([dayLabel, items]) => {
      const clusters: FeedCluster[] = [];
      let quietBuffer: PresentedEvent[] = [];

      const flushQuiet = () => {
        if (quietBuffer.length === 0) return;
        const clusterId = `${dayLabel}:${quietBuffer[0].event.id}`;
        clusters.push({ kind: "quiet_cluster", id: clusterId, items: quietBuffer });
        quietBuffer = [];
      };

      for (const item of items) {
        if (hideQuietChecks && item.isQuiet) {
          quietBuffer.push(item);
        } else {
          flushQuiet();
          clusters.push({ kind: "event", item });
        }
      }
      flushQuiet();
      return { dayLabel, clusters };
    });
  }, [presentedEvents, hideQuietChecks]);

  const groupedThreads = useMemo(() => {
    const groups = new Map<string, PresentedEvent[]>();
    for (const item of presentedEvents) {
      if (hideQuietChecks && item.isQuiet) continue;
      const key = item.event.correlation_id || item.event.id;
      const list = groups.get(key) ?? [];
      list.push(item);
      groups.set(key, list);
    }
    return Array.from(groups.entries()).map(([correlationId, items]) => ({
      correlationId,
      items: [...items].reverse(),
    }));
  }, [presentedEvents, hideQuietChecks]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = instruction.trim();
    if (!trimmed || submitting) return;
    setSubmitting(true);
    try {
      await onDispatch(trimmed, activeTargetBot?.slug);
      setInstruction("");
    } finally {
      setSubmitting(false);
    }
  }

  function resolveChatBotSlug(ev: ActivityEvent): string | null {
    if (botsBySlug.has(ev.source_slug)) return ev.source_slug;
    if (ev.target_slug && botsBySlug.has(ev.target_slug)) return ev.target_slug;
    return null;
  }

  function renderEventRow(item: PresentedEvent, nested = false) {
    const { event: ev, primaryBot, handoffLabel, title, summary, tag, tagTone, metaLine, needsReview } =
      item;
    const chatBotSlug = resolveChatBotSlug(ev);

    return (
      <div
        key={ev.id}
        className={`flex items-start gap-3 ${nested ? "px-3 py-2" : "px-4 py-3"} hover:bg-slate-50 transition-colors`}
      >
        {primaryBot ? (
          <BotAvatar
            icon={primaryBot.avatar_icon}
            color={primaryBot.avatar_color}
            initials={primaryBot.initials}
            size="sm"
          />
        ) : (
          <div className="w-7 h-7 rounded-xl border border-slate-200 bg-slate-50 text-slate-600 flex items-center justify-center shrink-0">
            {item.kind === "desktop" ? (
              <Monitor className="w-3.5 h-3.5" />
            ) : item.kind === "page" ? (
              <FileText className="w-3.5 h-3.5 text-indigo-600" />
            ) : item.kind === "alert" ? (
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            ) : item.kind === "approval" ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            ) : (
              <Activity className="w-3.5 h-3.5" />
            )}
          </div>
        )}

        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-slate-900">{title}</span>
            {tag && (
              <span
                className={`px-2 py-0.5 rounded-full border text-[10px] font-medium ${badgeClass(
                  tagTone,
                )}`}
              >
                {tag}
              </span>
            )}
            {handoffLabel && (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium text-indigo-700">
                <ArrowRight className="w-3 h-3" />
                {handoffLabel}
              </span>
            )}
            {metaLine && <span className="text-[11px] text-slate-400">{metaLine}</span>}
          </div>
          {summary && (
            <p className="text-xs text-slate-600 leading-relaxed line-clamp-2">{summary}</p>
          )}
        </div>

        <div className="shrink-0 flex items-center gap-2 pt-0.5">
          <span className="text-[11px] text-slate-400 whitespace-nowrap">
            {formatFriendlyTime(ev.created_at)}
          </span>
          {needsReview && (
            <button
              type="button"
              onClick={onOpenApprovals}
              className="px-2 py-0.5 rounded-full border border-amber-200 bg-amber-50 text-[11px] font-medium text-amber-800 hover:bg-amber-100 cursor-pointer"
            >
              Review
            </button>
          )}
          {onContinueInChat && chatBotSlug && (
            <button
              type="button"
              onClick={() => onContinueInChat(chatBotSlug, ev.correlation_id)}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer"
            >
              <span>Open</span>
              <ArrowRight className="w-2.5 h-2.5" />
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-slate-50">
      <div className="flex-1 overflow-y-auto custom-scroll p-5">
        <div className="max-w-4xl mx-auto space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5 flex-wrap">
              {FILTERS.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => onFilterChange(f.key)}
                  className={`px-3 py-1 rounded-full text-xs font-medium border transition cursor-pointer ${
                    filter === f.key
                      ? "bg-slate-900 text-white border-transparent"
                      : "bg-white border-slate-200 text-slate-600 hover:text-slate-900"
                  }`}
                >
                  {f.label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setGroupByThread((v) => !v)}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition cursor-pointer ${
                  groupByThread
                    ? "bg-slate-900 text-white border-transparent"
                    : "bg-white border-slate-200 text-slate-600 hover:text-slate-900"
                }`}
              >
                <Layers className="w-3 h-3" />
                <span>{groupByThread ? "Workflows" : "Timeline"}</span>
              </button>
              <button
                type="button"
                onClick={() => setHideQuietChecks((v) => !v)}
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border transition cursor-pointer ${
                  hideQuietChecks
                    ? "bg-emerald-50 border-emerald-200 text-emerald-700"
                    : "bg-white border-slate-200 text-slate-600 hover:text-slate-900"
                }`}
              >
                <EyeOff className="w-3 h-3" />
                <span>
                  {hideQuietChecks
                    ? quietCount > 0
                      ? `Quiet checks collapsed (${quietCount})`
                      : "Hide quiet checks"
                    : "Showing all checks"}
                </span>
              </button>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {bots.length > 0 && (
                <select
                  value={selectedBotFilter}
                  onChange={(e) => setSelectedBotFilter(e.target.value)}
                  className="rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] text-slate-700 cursor-pointer"
                >
                  <option value="all">All Bots</option>
                  {bots.map((b) => (
                    <option key={b.slug} value={b.slug}>
                      {b.name}
                    </option>
                  ))}
                </select>
              )}
              <div className="relative">
                <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="search"
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  placeholder="Filter..."
                  className="w-36 rounded-full border border-slate-200 bg-white pl-7 pr-2.5 py-1 text-[11px] text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-slate-400"
                />
              </div>
              <span className="inline-flex items-center gap-1.5 text-[11px] text-slate-500">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Live
              </span>
            </div>
          </div>

          {presentedEvents.length === 0 ? (
            <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-xs text-slate-500">
              No matching activity yet. Trigger a bot or ask a bot below to get started.
            </div>
          ) : groupByThread ? (
            groupedThreads.length === 0 ? (
              <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-xs text-slate-500">
                Only quiet background checks were recorded. Toggle quiet checks to inspect them.
              </div>
            ) : (
              <div className="space-y-3">
                {groupedThreads.map((thread) => {
                  const threadBot =
                    thread.items.map((it) => resolveChatBotSlug(it.event)).find((s) => s !== null) ??
                    null;
                  const first = thread.items[0];
                  return (
                    <div
                      key={thread.correlationId}
                      className="rounded-2xl border border-slate-200 bg-white shadow-xs overflow-hidden"
                    >
                      <div className="px-4 py-2.5 border-b border-slate-100 bg-slate-50 flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-semibold text-slate-900 truncate">
                            {first?.title ?? "Workflow Run"}
                          </span>
                          <span className="text-[11px] text-slate-400">
                            {thread.items.length} step{thread.items.length === 1 ? "" : "s"}
                          </span>
                        </div>
                        {onContinueInChat && threadBot && (
                          <button
                            type="button"
                            onClick={() => onContinueInChat(threadBot, thread.correlationId)}
                            className="inline-flex items-center gap-1 text-[11px] font-medium text-indigo-600 hover:underline cursor-pointer shrink-0"
                          >
                            <span>Continue in Chat</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                      <div className="divide-y divide-slate-100">
                        {thread.items.map((item) => renderEventRow(item, true))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (
            <div className="space-y-4">
              {daySections.map((section) => (
                <div key={section.dayLabel} className="space-y-1.5">
                  <div className="px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    {section.dayLabel}
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-100 shadow-xs overflow-hidden">
                    {section.clusters.map((cluster) => {
                      if (cluster.kind === "event") {
                        return renderEventRow(cluster.item);
                      }
                      const expanded = Boolean(expandedQuietGroups[cluster.id]);
                      const dedupCount = cluster.items.filter(
                        (it) => it.event.event_type === "bot.run.deduplicated",
                      ).length;
                      const latestTime = formatFriendlyTime(
                        cluster.items[0]?.event.created_at,
                      );
                      return (
                        <div key={cluster.id} className="bg-slate-50">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedQuietGroups((prev) => ({
                                ...prev,
                                [cluster.id]: !prev[cluster.id],
                              }))
                            }
                            className="w-full px-4 py-2 flex items-center justify-between gap-2 text-[11px] text-slate-500 hover:bg-slate-100 cursor-pointer"
                          >
                            <span className="inline-flex items-center gap-1.5">
                              {expanded ? (
                                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                              ) : (
                                <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
                              )}
                              <span>
                                {cluster.items.length} quiet check
                                {cluster.items.length === 1 ? "" : "s"}
                                {dedupCount > 0 ? ` · ${dedupCount} saved at 0 tokens` : ""}
                              </span>
                            </span>
                            <span className="text-slate-400">{latestTime}</span>
                          </button>
                          {expanded && (
                            <div className="divide-y divide-slate-100 border-t border-slate-100 bg-white">
                              {cluster.items.map((item) => renderEventRow(item, true))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {bots.length > 0 && (
        <footer className="shrink-0 px-3 md:px-5 py-2.5 md:py-3 border-t border-slate-200 bg-white">
          <form onSubmit={handleSubmit} className="max-w-4xl mx-auto flex items-center gap-2">
            <div className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs text-slate-700 shrink-0 max-w-[135px] md:max-w-none">
              <Sparkles className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
              <select
                value={activeTargetBot?.slug ?? ""}
                onChange={(e) => setTargetBotSlug(e.target.value)}
                aria-label="Target bot"
                className="bg-transparent border-0 text-xs font-medium text-slate-800 focus:outline-none cursor-pointer truncate min-w-0"
              >
                {bots.map((b) => (
                  <option key={b.slug} value={b.slug}>
                    @{b.name}
                  </option>
                ))}
              </select>
            </div>
            <input
              type="text"
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              placeholder={
                activeTargetBot
                  ? `Ask @${activeTargetBot.name} to run a task...`
                  : "Send an instruction to a bot..."
              }
              className="flex-1 min-w-0 rounded-xl border border-slate-200 bg-slate-50 px-3.5 py-2 text-[16px] md:text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-slate-300"
            />
            <button
              type="submit"
              disabled={submitting || !instruction.trim()}
              className="bg-slate-900 text-white px-4 py-2 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800 disabled:opacity-50 shrink-0"
            >
              {submitting ? "Sending..." : "Send"}
            </button>
          </form>
        </footer>
      )}
    </div>
  );
}
