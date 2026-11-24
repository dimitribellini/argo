import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal, type ITheme } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import {
  Bookmark,
  ChevronDown,
  ChevronRight,
  Clock,
  FastForward,
  Hand,
  Maximize2,
  Pause,
  Play,
  RefreshCw,
  Search,
  Square,
  Terminal as TerminalIcon,
} from "lucide-react";
import { api } from "../api";
import type { SSHSessionRecord } from "../types";
import { formatFriendlyTime } from "../utils/format";

interface SSHTerminalPanelProps {
  botSlug: string;
  theme?: "light" | "dark";
  variant?: "sidebar" | "modal";
  initialSessionId?: string | null;
  refreshTick?: number;
  hasPermittedSSH?: boolean;
  onExpandModal?: () => void;
  onStatusToast?: (msg: string) => void;
}

interface CastEvent {
  delta: number;
  code: string;
  data: string;
}

function terminalThemeForMode(theme: "light" | "dark"): ITheme {
  if (theme === "dark") {
    return {
      background: "#14171d",
      foreground: "#e5e7eb",
      cursor: "#93a3b8",
      cursorAccent: "#14171d",
      selectionBackground: "#2c384b",
      black: "#1e232c",
      red: "#cf6a6a",
      green: "#6fa882",
      yellow: "#c9a66b",
      blue: "#6e92bd",
      magenta: "#9b84b8",
      cyan: "#6ba3ab",
      white: "#e5e7eb",
      brightBlack: "#64748b",
      brightRed: "#dfa0a0",
      brightGreen: "#8fbf9f",
      brightYellow: "#d9be8b",
      brightBlue: "#93b0d4",
      brightMagenta: "#b8a6cf",
      brightCyan: "#8ebac0",
      brightWhite: "#f8fafc",
    };
  }
  return {
    background: "#f8fafc",
    foreground: "#0f172a",
    cursor: "#475569",
    cursorAccent: "#f8fafc",
    selectionBackground: "#cbd5e1",
    black: "#0f172a",
    red: "#9b444c",
    green: "#2f6f54",
    yellow: "#9a6f2e",
    blue: "#3b6796",
    magenta: "#6d598a",
    cyan: "#2c6b74",
    white: "#f1f5f9",
    brightBlack: "#475569",
    brightRed: "#b25b63",
    brightGreen: "#3b8c62",
    brightYellow: "#b4863f",
    brightBlue: "#4f80b3",
    brightMagenta: "#846fa3",
    brightCyan: "#3c8089",
    brightWhite: "#ffffff",
  };
}

function formatSessionTimestamp(iso: string | undefined): string {
  if (!iso) return "Just now";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return formatFriendlyTime(iso);
  const friendly = formatFriendlyTime(iso);
  if (friendly.includes(":")) return friendly;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm} · ${friendly}`;
}

function friendlySessionStatus(session: SSHSessionRecord): {
  label: string;
  badgeClass: string;
} {
  if (session.status === "closed") {
    return { label: "Ended", badgeClass: "bg-slate-200 text-slate-700" };
  }
  if (session.paused) {
    return {
      label: "Frozen",
      badgeClass: "bg-rose-50 border border-rose-200 text-rose-700",
    };
  }
  if (session.operator_takeover) {
    return {
      label: "Control Active",
      badgeClass: "bg-amber-50 border border-amber-200 text-amber-800",
    };
  }
  if (session.status === "awaiting_input") {
    return {
      label: "Waiting for reply",
      badgeClass: "bg-slate-100 border border-slate-300 text-slate-700",
    };
  }
  return {
    label: "View Mode (Read-Only)",
    badgeClass: "bg-emerald-50 border border-emerald-200 text-emerald-700",
  };
}

function parseNdjsonCast(ndjson: string): CastEvent[] {
  const events: CastEvent[] = [];
  const lines = ndjson.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i].trim();
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed) && parsed.length >= 3) {
        events.push({
          delta: Math.max(0, Number(parsed[0]) || 0),
          code: String(parsed[1] ?? ""),
          data: String(parsed[2] ?? ""),
        });
      }
    } catch {
      // Skip malformed line
    }
  }
  return events;
}

export function SSHTerminalPanel({
  botSlug,
  theme = "light",
  variant = "sidebar",
  initialSessionId = null,
  refreshTick = 0,
  hasPermittedSSH = false,
  onExpandModal,
  onStatusToast,
}: SSHTerminalPanelProps) {
  const [sessions, setSessions] = useState<SSHSessionRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string>(initialSessionId ?? "");
  const [loading, setLoading] = useState<boolean>(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [replayMode, setReplayMode] = useState<boolean>(false);
  const [replayPlaying, setReplayPlaying] = useState<boolean>(false);
  const [replayEvents, setReplayEvents] = useState<CastEvent[]>([]);
  const [replayIndex, setReplayIndex] = useState<number>(0);
  const [sessionFilter, setSessionFilter] = useState<string>("");
  const [mobileSessionsExpanded, setMobileSessionsExpanded] = useState<boolean>(false);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const takeoverRef = useRef<boolean>(false);
  const replayTimerRef = useRef<number | null>(null);

  const loadSessions = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const list = await api.listSSHSessions({ bot_slug: botSlug, include_closed: true });
        setSessions(list);
        setSelectedId((prev) => {
          if (prev && list.some((s) => s.session_id === prev)) return prev;
          const liveFirst = list.find((s) => s.status !== "closed");
          return liveFirst?.session_id ?? list[0]?.session_id ?? "";
        });
      } catch (err) {
        if (!silent) {
          setErrorMsg(err instanceof Error ? err.message : "Could not load SSH sessions.");
        }
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [botSlug],
  );

  useEffect(() => {
    void loadSessions(false);
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void loadSessions(true);
      }
    }, 4000);
    return () => window.clearInterval(id);
  }, [loadSessions]);

  useEffect(() => {
    if (refreshTick > 0) {
      void loadSessions(true);
    }
  }, [refreshTick, loadSessions]);

  useEffect(() => {
    if (initialSessionId) {
      setSelectedId(initialSessionId);
    }
  }, [initialSessionId]);

  const activeSession = useMemo(
    () => sessions.find((s) => s.session_id === selectedId) ?? null,
    [sessions, selectedId],
  );

  const sortedSessions = useMemo(
    () =>
      [...sessions].sort((a, b) =>
        String(b.created_at || "").localeCompare(String(a.created_at || "")),
      ),
    [sessions],
  );
  const filteredSessions = useMemo(() => {
    const q = sessionFilter.trim().toLowerCase();
    if (!q) return sortedSessions;
    return sortedSessions.filter(
      (s) =>
        s.host.toLowerCase().includes(q) ||
        String(s.port).includes(q) ||
        String(s.last_command || "").toLowerCase().includes(q),
    );
  }, [sortedSessions, sessionFilter]);
  const isSessionLive = (s: SSHSessionRecord) => s.live !== false && s.status !== "closed";
  const liveSessions = useMemo(
    () => filteredSessions.filter(isSessionLive),
    [filteredSessions],
  );
  const historySessions = useMemo(
    () => filteredSessions.filter((s) => !isSessionLive(s)),
    [filteredSessions],
  );

  useEffect(() => {
    takeoverRef.current = Boolean(activeSession?.operator_takeover);
  }, [activeSession?.operator_takeover]);

  useEffect(() => {
    if (!activeSession) return;
    if (activeSession.live === false || activeSession.status === "closed") {
      setReplayMode(true);
    } else {
      setReplayMode(false);
    }
    setReplayPlaying(false);
    setReplayEvents([]);
    setReplayIndex(0);
  }, [activeSession?.session_id, activeSession?.status]);

  // Initialize and cleanly dispose xterm instance + ResizeObserver
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !activeSession) return;

    const term = new Terminal({
      cols: 120,
      rows: 36,
      cursorBlink: true,
      convertEol: true,
      fontSize: 12,
      lineHeight: 1.25,
      fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      theme: terminalThemeForMode(theme),
      scrollback: 1000,
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(el);
    try {
      fitAddon.fit();
    } catch {
      // Ignore fit timing error before layout settles
    }
    termRef.current = term;
    fitRef.current = fitAddon;

    const onDataDisposable = term.onData((data) => {
      const ws = wsRef.current;
      if (takeoverRef.current && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    });

    const ro = new ResizeObserver(() => {
      try {
        fitAddon.fit();
        const ws = wsRef.current;
        if (takeoverRef.current && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        }
      } catch {
        // Ignore transient resize errors
      }
    });
    ro.observe(el);

    return () => {
      ro.disconnect();
      onDataDisposable.dispose();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [activeSession?.session_id]);

  // Live Light/Dark theme synchronization without destroying buffer
  useEffect(() => {
    if (termRef.current) {
      termRef.current.options.theme = terminalThemeForMode(theme);
    }
  }, [theme]);

  // Connect live WebSocket when viewing an active session in Live Mode
  useEffect(() => {
    if (!activeSession || activeSession.status === "closed" || replayMode) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      return;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${proto}//${window.location.host}/api/ssh/sessions/${encodeURIComponent(
      activeSession.session_id,
    )}/ws`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const term = termRef.current;
      if (!term) return;
      try {
        const frame = JSON.parse(String(event.data)) as {
          type?: string;
          data?: string;
          status?: string;
          operator_takeover?: boolean;
          paused?: boolean;
          pinned?: boolean;
          detail?: string;
        };
        if (frame.type === "snapshot") {
          term.reset();
          if (frame.data) term.write(frame.data);
          takeoverRef.current = Boolean(frame.operator_takeover);
        } else if (frame.type === "output" && frame.data) {
          term.write(frame.data);
        } else if (frame.type === "state" || frame.type === "closed") {
          if (typeof frame.operator_takeover === "boolean") {
            takeoverRef.current = frame.operator_takeover;
          }
          void loadSessions(true);
        } else if (frame.type === "locked" && frame.detail) {
          onStatusToast?.(frame.detail);
        }
      } catch {
        // Ignore non-JSON frame
      }
    };

    ws.onerror = () => {
      setErrorMsg("Live terminal stream interrupted.");
    };

    return () => {
      ws.close();
      if (wsRef.current === ws) {
        wsRef.current = null;
      }
    };
  }, [activeSession?.session_id, activeSession?.status, replayMode, loadSessions, onStatusToast]);

  // Load recorded .cast.zst NDJSON when Replay Mode is active
  useEffect(() => {
    if (!activeSession || !replayMode) return;
    let cancelled = false;
    setErrorMsg(null);
    void api
      .getSSHCast(activeSession.session_id)
      .then(({ ndjson }) => {
        if (cancelled) return;
        const parsed = parseNdjsonCast(ndjson).filter((ev) => ev.code === "o");
        setReplayEvents(parsed);
        const term = termRef.current;
        if (term) {
          term.reset();
          for (const ev of parsed) {
            term.write(ev.data);
          }
        }
        setReplayIndex(parsed.length);
        setReplayPlaying(false);
      })
      .catch((err) => {
        if (!cancelled) {
          setErrorMsg(err instanceof Error ? err.message : "Could not load terminal recording.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeSession?.session_id, replayMode]);

  // Timed playback loop for Replay Mode
  useEffect(() => {
    if (!replayMode || !replayPlaying) {
      if (replayTimerRef.current !== null) {
        window.clearTimeout(replayTimerRef.current);
        replayTimerRef.current = null;
      }
      return;
    }
    if (replayIndex >= replayEvents.length) {
      setReplayPlaying(false);
      return;
    }
    const ev = replayEvents[replayIndex];
    const delayMs = Math.max(15, Math.min(800, Math.round(ev.delta * 1000)));
    replayTimerRef.current = window.setTimeout(() => {
      if (termRef.current) {
        termRef.current.write(ev.data);
      }
      setReplayIndex((idx) => idx + 1);
    }, delayMs);

    return () => {
      if (replayTimerRef.current !== null) {
        window.clearTimeout(replayTimerRef.current);
        replayTimerRef.current = null;
      }
    };
  }, [replayMode, replayPlaying, replayIndex, replayEvents]);

  async function runSessionAction(
    label: string,
    fn: (sid: string) => Promise<SSHSessionRecord>,
  ) {
    if (!activeSession || busyAction) return;
    setBusyAction(label);
    setErrorMsg(null);
    try {
      const updated = await fn(activeSession.session_id);
      setSessions((prev) =>
        prev.map((s) => (s.session_id === updated.session_id ? { ...s, ...updated } : s)),
      );
      await loadSessions(true);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Action failed.");
    } finally {
      setBusyAction(null);
    }
  }

  function handlePlayReplay() {
    if (!termRef.current) return;
    if (replayIndex >= replayEvents.length) {
      termRef.current.reset();
      setReplayIndex(0);
    }
    setReplayPlaying(true);
  }

  function handleJumpToEnd() {
    setReplayPlaying(false);
    const term = termRef.current;
    if (!term) return;
    term.reset();
    for (const ev of replayEvents) {
      term.write(ev.data);
    }
    setReplayIndex(replayEvents.length);
  }

  if (loading && sessions.length === 0) {
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-xs text-slate-500">
        Loading SSH sessions...
      </div>
    );
  }

  if (sessions.length === 0) {
    if (!hasPermittedSSH) return null;
    return (
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3.5 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-900">
            <TerminalIcon className="w-3.5 h-3.5 text-slate-600" />
            <span>Live Terminal</span>
          </span>
          <span className="px-2 py-0.5 rounded-full bg-slate-200 text-slate-700 text-[10.5px] font-medium">
            0 MB · Ready
          </span>
        </div>
        <p className="text-[11px] text-slate-600 leading-relaxed">
          This bot has SSH Server access configured. Ask it to check a server in chat to open a live, recorded terminal here — no Virtual Desktop container required.
        </p>
      </div>
    );
  }

  const statusMeta = activeSession ? friendlySessionStatus(activeSession) : null;

  const actionControls = activeSession ? (
    activeSession.status !== "closed" && !replayMode ? (
      <div className="flex items-center gap-1.5 flex-wrap">
        {activeSession.operator_takeover ? (
          <button
            type="button"
            disabled={busyAction !== null}
            onClick={() => void runSessionAction("handback", api.handbackSSHSession)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
          >
            <Hand className="w-3 h-3" />
            <span>Hand Back to Bot</span>
          </button>
        ) : (
          <button
            type="button"
            disabled={busyAction !== null}
            onClick={() => void runSessionAction("takeover", api.takeoverSSHSession)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
          >
            <Hand className="w-3 h-3" />
            <span>Take Over</span>
          </button>
        )}

        <button
          type="button"
          disabled={busyAction !== null}
          onClick={() =>
            void runSessionAction(
              activeSession.paused ? "resume" : "pause",
              (sid) => api.controlSSHSession(sid, activeSession.paused ? "resume" : "pause"),
            )
          }
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-800 text-[11px] font-medium cursor-pointer disabled:opacity-50"
        >
          {activeSession.paused ? (
            <>
              <Play className="w-3 h-3" />
              <span>Resume</span>
            </>
          ) : (
            <>
              <Pause className="w-3 h-3" />
              <span>Freeze Session</span>
            </>
          )}
        </button>

        <button
          type="button"
          disabled={busyAction !== null}
          onClick={() =>
            void runSessionAction("terminate", (sid) =>
              api.controlSSHSession(sid, "terminate"),
            )
          }
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-rose-200 bg-white hover:bg-rose-50 text-rose-700 text-[11px] font-medium cursor-pointer disabled:opacity-50"
        >
          <Square className="w-3 h-3" />
          <span>End Session</span>
        </button>

        <button
          type="button"
          disabled={busyAction !== null}
          onClick={() =>
            void runSessionAction("pin", (sid) =>
              api.controlSSHSession(sid, activeSession.pinned ? "unpin" : "pin"),
            )
          }
          className={`inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border text-[11px] font-medium cursor-pointer disabled:opacity-50 ${
            activeSession.pinned
              ? "border-amber-300 bg-amber-50 text-amber-800"
              : "border-slate-200 bg-white hover:bg-slate-100 text-slate-700"
          }`}
        >
          <Bookmark className="w-3 h-3" />
          <span>{activeSession.pinned ? "Recording Kept" : "Keep Recording"}</span>
        </button>
      </div>
    ) : (
      <div className="flex items-center gap-1.5 flex-wrap">
        {replayPlaying ? (
          <button
            type="button"
            onClick={() => setReplayPlaying(false)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer"
          >
            <Pause className="w-3 h-3" />
            <span>Pause</span>
          </button>
        ) : (
          <button
            type="button"
            disabled={replayEvents.length === 0}
            onClick={handlePlayReplay}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3 h-3" />
            <span>Play</span>
          </button>
        )}

        <button
          type="button"
          disabled={replayEvents.length === 0}
          onClick={handleJumpToEnd}
          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-800 text-[11px] font-medium cursor-pointer disabled:opacity-50"
        >
          <FastForward className="w-3 h-3" />
          <span>Jump to End</span>
        </button>

        <button
          type="button"
          disabled={busyAction !== null}
          onClick={() =>
            void runSessionAction("pin", (sid) =>
              api.controlSSHSession(sid, activeSession.pinned ? "unpin" : "pin"),
            )
          }
          className={`inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border text-[11px] font-medium cursor-pointer disabled:opacity-50 ${
            activeSession.pinned
              ? "border-amber-300 bg-amber-50 text-amber-800"
              : "border-slate-200 bg-white hover:bg-slate-100 text-slate-700"
          }`}
        >
          <Bookmark className="w-3 h-3" />
          <span>{activeSession.pinned ? "Recording Kept" : "Keep Recording"}</span>
        </button>

        {isSessionLive(activeSession) && (
          <button
            type="button"
            onClick={() => setReplayMode(false)}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-[11px] font-medium cursor-pointer"
          >
            <span>Back to Live</span>
          </button>
        )}
      </div>
    )
  ) : null;

  function renderSessionRow(s: SSHSessionRecord) {
    const isSel = s.session_id === selectedId;
    const isLive = isSessionLive(s);
    const rowStatus = friendlySessionStatus(s);
    return (
      <button
        key={s.session_id}
        type="button"
        onClick={() => setSelectedId(s.session_id)}
        className={`w-full text-left rounded-xl border px-2.5 py-2 transition cursor-pointer space-y-1 ${
          isSel
            ? "border-slate-500 bg-slate-100"
            : "border-slate-200 bg-white hover:bg-slate-100"
        }`}
      >
        <div className="flex items-center justify-between gap-1.5">
          <span className="inline-flex items-center gap-1.5 min-w-0 text-[11.5px] font-semibold text-slate-900">
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                s.paused
                  ? "bg-rose-500"
                  : isLive
                    ? "bg-emerald-500"
                    : "bg-slate-400"
              }`}
            />
            <span className="truncate font-mono">
              {s.host}:{s.port}
            </span>
          </span>
          <span className="inline-flex items-center gap-1 shrink-0">
            {s.pinned && <Bookmark className="w-3 h-3 text-amber-600" />}
            {isLive && (
              <span className={`px-1.5 py-0.5 rounded-full text-[9.5px] font-semibold ${rowStatus.badgeClass}`}>
                {s.operator_takeover ? "Control" : s.paused ? "Frozen" : "Live"}
              </span>
            )}
          </span>
        </div>
        <div className="flex items-center justify-between gap-1.5 text-[10px] text-slate-500">
          <span className="inline-flex items-center gap-1 min-w-0">
            <Clock className="w-2.5 h-2.5 shrink-0" />
            <span className="truncate">{formatSessionTimestamp(s.created_at)}</span>
          </span>
          {s.vault_slug && (
            <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-600 font-mono text-[9.5px] shrink-0">
              @{s.vault_slug}
            </span>
          )}
        </div>
        {s.last_command && (
          <div className="text-[10.5px] font-mono text-slate-600 truncate">
            {s.last_command}
          </div>
        )}
      </button>
    );
  }

  if (variant === "modal") {
    const renderModalSessionRow = (s: SSHSessionRecord) => (
      <div
        key={s.session_id}
        onClick={() => setMobileSessionsExpanded(false)}
      >
        {renderSessionRow(s)}
      </div>
    );
    return (
      <div className="grid grid-cols-1 md:grid-cols-[276px_minmax(0,1fr)] gap-3 items-stretch">
        {/* Chronological Session Sidebar (collapsible on mobile so terminal gets full height) */}
        <aside
          className={`rounded-xl border border-slate-200 bg-slate-50 p-2.5 flex flex-col gap-2.5 md:min-h-[420px] md:max-h-[68vh] ${
            mobileSessionsExpanded ? "max-h-[45vh]" : ""
          }`}
        >
          <div className="flex items-center justify-between gap-2 px-1">
            <button
              type="button"
              onClick={() => setMobileSessionsExpanded((v) => !v)}
              className="flex items-center gap-1.5 min-w-0 text-left cursor-pointer md:pointer-events-none"
            >
              <span className="md:hidden text-slate-500 shrink-0">
                {mobileSessionsExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5" />
                )}
              </span>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 shrink-0">
                Sessions ({sortedSessions.length})
              </span>
              {!mobileSessionsExpanded && activeSession && (
                <span className="md:hidden text-[11px] font-mono text-slate-600 truncate">
                  · {activeSession.host}:{activeSession.port}
                </span>
              )}
            </button>
            <button
              type="button"
              title="Refresh sessions"
              onClick={() => void loadSessions(false)}
              className="p-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-600 cursor-pointer shrink-0"
            >
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>

          <div
            className={`${
              mobileSessionsExpanded ? "flex" : "hidden md:flex"
            } flex-1 min-h-0 flex-col gap-2.5`}
          >
            {sortedSessions.length > 3 && (
              <div className="relative">
                <Search className="w-3 h-3 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={sessionFilter}
                  onChange={(e) => setSessionFilter(e.target.value)}
                  placeholder="Filter host or command..."
                  className="w-full rounded-lg border border-slate-200 bg-white pl-7 pr-2.5 py-1.5 text-[16px] md:text-[11px] text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-slate-400"
                />
              </div>
            )}

            <div className="flex-1 overflow-y-auto custom-scroll space-y-3 pr-0.5">
              {liveSessions.length > 0 && (
                <div className="space-y-1.5">
                  <div className="px-1 text-[10px] font-semibold uppercase tracking-wider text-emerald-700">
                    Live Now ({liveSessions.length})
                  </div>
                  <div className="space-y-1.5">{liveSessions.map(renderModalSessionRow)}</div>
                </div>
              )}

              <div className="space-y-1.5">
                <div className="px-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  History ({historySessions.length})
                </div>
                {historySessions.length === 0 ? (
                  <div className="px-2 py-2 text-[11px] text-slate-400">
                    No matching recorded sessions.
                  </div>
                ) : (
                  <div className="space-y-1.5">{historySessions.map(renderModalSessionRow)}</div>
                )}
              </div>
            </div>
          </div>
        </aside>

        {/* Focused Viewport */}
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 flex flex-col gap-2.5 min-w-0">
          {activeSession ? (
            <>
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 min-w-0 flex-wrap">
                  <TerminalIcon className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                  <span className="text-xs font-semibold font-mono text-slate-900">
                    {activeSession.host}:{activeSession.port}
                  </span>
                  <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                    <Clock className="w-3 h-3" />
                    <span>{formatSessionTimestamp(activeSession.created_at)}</span>
                  </span>
                </div>
                {statusMeta && (
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${statusMeta.badgeClass}`}
                  >
                    {statusMeta.label}
                  </span>
                )}
              </div>

              {activeSession.last_command && (
                <div className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px] font-mono text-slate-700 truncate">
                  {activeSession.last_command}
                </div>
              )}

              {errorMsg && (
                <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] text-rose-700">
                  {errorMsg}
                </div>
              )}

              <div className="rounded-lg border border-slate-200 overflow-hidden argo-ssh-terminal flex-1">
                <div ref={containerRef} className="w-full h-[54vh] min-h-[360px] p-1.5" />
              </div>

              {actionControls}
            </>
          ) : (
            <div className="p-6 text-xs text-slate-500">Select a session on the left to view output.</div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 space-y-2.5">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 min-w-0">
          <TerminalIcon className="w-3.5 h-3.5 text-slate-600 shrink-0" />
          <span className="text-xs font-semibold text-slate-900 truncate">
            {replayMode ? "Terminal Recording" : "Live Terminal"}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {statusMeta && (
            <span className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold ${statusMeta.badgeClass}`}>
              {statusMeta.label}
            </span>
          )}
          {onExpandModal && (
            <button
              type="button"
              title="Open full terminal view"
              onClick={onExpandModal}
              className="p-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-600 cursor-pointer"
            >
              <Maximize2 className="w-3 h-3" />
            </button>
          )}
          <button
            type="button"
            title="Refresh sessions"
            onClick={() => void loadSessions(false)}
            className="p-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-600 cursor-pointer"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        </div>
      </div>

      {sortedSessions.length > 0 && (
        <select
          value={selectedId}
          aria-label="Select SSH session"
          onChange={(e) => setSelectedId(e.target.value)}
          className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[11px] font-mono text-slate-800"
        >
          {liveSessions.length > 0 && (
            <optgroup label={`Live Now (${liveSessions.length})`}>
              {liveSessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  ● {s.host}:{s.port} · {formatSessionTimestamp(s.created_at)}
                  {s.last_command ? ` · ${s.last_command.slice(0, 32)}` : ""}
                </option>
              ))}
            </optgroup>
          )}
          {historySessions.length > 0 && (
            <optgroup label={`History (${historySessions.length})`}>
              {historySessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  {s.host}:{s.port} · {formatSessionTimestamp(s.created_at)}
                  {s.last_command ? ` · ${s.last_command.slice(0, 32)}` : ""}
                </option>
              ))}
            </optgroup>
          )}
        </select>
      )}

      {activeSession && (
        <>
          <div className="text-[11px] text-slate-500 flex items-center justify-between gap-2 flex-wrap">
            <span className="truncate font-medium text-slate-700">
              {activeSession.host}:{activeSession.port}
            </span>
            {activeSession.last_command && (
              <span className="truncate font-mono text-[10.5px] text-slate-500 max-w-[260px]">
                {activeSession.last_command}
              </span>
            )}
          </div>

          {errorMsg && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[11px] text-rose-700">
              {errorMsg}
            </div>
          )}

          <div className="rounded-lg border border-slate-200 overflow-hidden argo-ssh-terminal">
            <div ref={containerRef} className="w-full h-56 p-1" />
          </div>

          {actionControls}
        </>
      )}
    </div>
  );
}
