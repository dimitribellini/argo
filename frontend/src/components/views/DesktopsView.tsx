import { useState } from "react";
import { Loader2, Monitor, Terminal, Trash2 } from "lucide-react";
import type {
  DesktopBootProgress,
  DesktopInfo,
  DesktopLaunchQueueItem,
  HostTelemetry,
  SandboxInfo,
} from "../../types";
import { DesktopScreenPreview } from "../DesktopScreenPreview";
import { formatVisibilityLabel, visibilityBadgeClasses } from "../VisibilityPicker";

interface DesktopsViewProps {
  principal?: import("../../types").SsoPrincipal | null;
  host: HostTelemetry | null;
  desktops: DesktopInfo[];
  sandboxes?: SandboxInfo[];
  queuedLaunches: DesktopLaunchQueueItem[];
  togglingDesktops?: Record<string, boolean>;
  togglingSandboxes?: Record<string, boolean>;
  desktopBootBySlug?: Record<string, DesktopBootProgress>;
  onToggleDesktop: (slug: string) => void;
  onToggleSandbox?: (slug: string) => void;
  onStopAllDesktops: () => Promise<void>;
  onStopAllSandboxes?: () => Promise<void>;
  onOpenSelkies: (desktop: DesktopInfo) => void;
  onDeleteBot?: (slug: string) => Promise<void>;
}

export function DesktopsView({
  principal = null,
  host,
  desktops,
  sandboxes = [],
  queuedLaunches,
  togglingDesktops = {},
  togglingSandboxes = {},
  desktopBootBySlug = {},
  onToggleDesktop,
  onToggleSandbox,
  onStopAllDesktops,
  onStopAllSandboxes,
  onOpenSelkies,
  onDeleteBot,
}: DesktopsViewProps) {
  const [stoppingAll, setStoppingAll] = useState(false);
  const [stoppingAllSandboxes, setStoppingAllSandboxes] = useState(false);
  const [confirmDeleteSlug, setConfirmDeleteSlug] = useState<string | null>(null);
  const [deletingSlug, setDeletingSlug] = useState<string | null>(null);

  const ramPct = host?.ram_percent ?? 0;
  const cpuPct = host?.cpu_percent ?? 0;
  const diskPct = host?.disk_percent ?? 0;
  const totalGb = host?.ram_total_gb ?? 0;
  const anyRunning = desktops.some((d) => d.desktop_state === "running");
  const anySandboxRunning = sandboxes.some((s) => s.sandbox_state === "running");
  const isMultiUser = Boolean(principal?.multi_user);
  const isAdmin = Boolean(principal?.is_admin);
  const callerEmail = (principal?.email || "").toLowerCase();
  const canManage = (owner?: string) =>
    !isMultiUser || isAdmin || !owner || owner.toLowerCase() === callerEmail;
  const isOwnedByCaller = (owner?: string) =>
    Boolean(callerEmail) && (!owner || owner.toLowerCase() === callerEmail);
  const myRunningDesktops = isMultiUser
    ? desktops.filter((d) => d.desktop_state === "running" && isOwnedByCaller(d.owner_email)).length
    : desktops.filter((d) => d.desktop_state === "running").length;
  const myRunningSandboxes = isMultiUser
    ? sandboxes.filter((s) => s.sandbox_state === "running" && isOwnedByCaller(s.owner_email)).length
    : sandboxes.filter((s) => s.sandbox_state === "running").length;
  const maxDesktopsPerUser = principal?.max_active_desktops_per_user ?? 2;
  const maxSandboxesPerUser = principal?.max_active_sandboxes_per_user ?? 4;

  const handleStopAll = async () => {
    setStoppingAll(true);
    try {
      await onStopAllDesktops();
    } finally {
      setStoppingAll(false);
    }
  };

  const handleStopAllSandboxes = async () => {
    if (!onStopAllSandboxes) return;
    setStoppingAllSandboxes(true);
    try {
      await onStopAllSandboxes();
    } finally {
      setStoppingAllSandboxes(false);
    }
  };

  return (
    <div className="h-full overflow-y-auto custom-scroll p-5">
      <div className="max-w-4xl mx-auto space-y-5">
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h2 className="text-xs font-semibold text-slate-900">
                Server Capacity &amp; Virtual Desktops{totalGb > 0 ? ` · ${totalGb} GB RAM` : ""}
              </h2>
              <p className="text-[11px] text-slate-500">
                New virtual desktops pause above 80% memory and automatically sleep when idle
              </p>
            </div>
            <div className="flex items-center gap-2">
              {host?.ram_startup_gate_blocked && (
                <span className="px-2.5 py-1 rounded-full border border-amber-300 bg-amber-50 text-[11px] font-medium text-amber-800">
                  High Memory (&gt;= 80%)
                </span>
              )}
              {anyRunning && (
                <button
                  type="button"
                  disabled={stoppingAll}
                  onClick={() => void handleStopAll()}
                  className="px-2.5 py-1 rounded-xl border border-slate-200 bg-white text-[11px] font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                >
                  {stoppingAll
                    ? "Putting to sleep..."
                    : !principal?.multi_user || principal?.is_admin
                      ? "Sleep All Desktops"
                      : "Sleep My Desktops"}
                </button>
              )}
              {anySandboxRunning && onStopAllSandboxes && (
                <button
                  type="button"
                  disabled={stoppingAllSandboxes}
                  onClick={() => void handleStopAllSandboxes()}
                  className="px-2.5 py-1 rounded-xl border border-slate-200 bg-white text-[11px] font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                >
                  {stoppingAllSandboxes
                    ? "Stopping..."
                    : !principal?.multi_user || principal?.is_admin
                      ? "Sleep All Sandboxes"
                      : "Stop My Sandboxes"}
                </button>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-500">Host RAM</span>
                <span
                  className={`font-mono font-semibold ${
                    ramPct >= 80 ? "text-amber-700" : "text-slate-900"
                  }`}
                >
                  {ramPct}%
                </span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                <div
                  className={`h-full ${ramPct >= 80 ? "bg-amber-500" : "bg-emerald-500"}`}
                  style={{ width: `${Math.min(100, ramPct)}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-500">CPU Utilization</span>
                <span className="font-mono font-semibold text-slate-900">{cpuPct}%</span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                <div
                  className="h-full bg-blue-500"
                  style={{ width: `${Math.min(100, cpuPct)}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-500">Disk Usage</span>
                <span
                  className={`font-mono font-semibold ${
                    diskPct >= 85 ? "text-amber-700" : "text-slate-900"
                  }`}
                >
                  {diskPct}%
                </span>
              </div>
              <div className="h-2 rounded-full bg-slate-100 overflow-hidden">
                <div
                  className={`h-full ${diskPct >= 85 ? "bg-amber-500" : "bg-slate-700"}`}
                  style={{ width: `${Math.min(100, diskPct)}%` }}
                />
              </div>
            </div>
          </div>

          {isMultiUser && (
            <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center gap-2 text-[11px]">
              <span className="px-2.5 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-slate-700 font-medium">
                My Active Desktops: {myRunningDesktops} / {maxDesktopsPerUser}
              </span>
              <span className="px-2.5 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-slate-700 font-medium">
                My Active Sandboxes: {myRunningSandboxes} / {maxSandboxesPerUser}
              </span>
            </div>
          )}
        </div>

        {(host?.ram_startup_gate_blocked || queuedLaunches.length > 0) && (
          <div className="rounded-xl border border-amber-300 bg-amber-50 p-3.5 text-xs text-amber-900 space-y-1">
            <div className="font-semibold">
              80% RAM Startup Gate · Container Launch Queue ({queuedLaunches.length})
            </div>
            <p className="text-[11px] text-amber-800">
              {queuedLaunches.length > 0
                ? `Queued desktop launches waiting for host RAM below 80%: ${queuedLaunches
                    .map((item) => item.bot_slug)
                    .join(", ")}`
                : "New desktop startups are blocked until host memory drops below 80%."}
            </p>
          </div>
        )}

        {desktops.length === 0 && sandboxes.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-xs text-slate-500">
            No bots need a virtual desktop or script sandbox yet. Most bots use fast direct API connections.
          </div>
        ) : (
          <>
            {desktops.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {desktops.map((desktop) => {
              const running = desktop.desktop_state === "running";
              const toggling = Boolean(togglingDesktops[desktop.bot_slug]);
              const bootProgress = desktopBootBySlug[desktop.bot_slug] ?? null;
              const idleSeconds = desktop.idle_seconds ?? 0;
              const idleTimeout = desktop.idle_timeout_seconds ?? 300;
              return (
                <div
                  key={desktop.bot_slug}
                  className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-semibold text-slate-900">{desktop.bot_name}</div>
                      <div className="text-[11px] text-slate-500">
                        Isolated Fedora XFCE · {desktop.ram_limit_mb} MB cap · Persistent session
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap justify-end">
                      {isMultiUser && (
                        <>
                          {desktop.owner_email && (
                            <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[10px] text-slate-600">
                              {desktop.owner_email}
                            </span>
                          )}
                          <span
                            className={`px-2 py-0.5 rounded-full border text-[10px] font-medium ${visibilityBadgeClasses(
                              desktop.visibility,
                            )}`}
                          >
                            {formatVisibilityLabel(desktop.visibility, desktop.allowed_groups)}
                          </span>
                        </>
                      )}
                      {desktop.awaiting_takeover && (
                        <span className="px-2 py-0.5 rounded-full border border-rose-300 text-rose-700 bg-rose-50 text-[10px] font-semibold">
                          Sign-In Needed
                        </span>
                      )}
                      {desktop.takeover_active && (
                        <span className="px-2 py-0.5 rounded-full border border-blue-300 text-blue-700 bg-blue-50 text-[10px] font-semibold">
                          You Are Viewing
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${
                          running
                            ? "border-emerald-300 text-emerald-700 bg-emerald-50"
                            : "border-slate-200 text-slate-600 bg-slate-50"
                        }`}
                      >
                        {running ? "Running" : "Sleeping (Saved)"}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-500">{desktop.role}</p>

                  <DesktopScreenPreview
                    botSlug={desktop.bot_slug}
                    running={running}
                    hasScreenshot={desktop.has_screenshot}
                    toggling={toggling}
                    bootProgress={bootProgress}
                    onOpenScreen={() => onOpenSelkies(desktop)}
                  />

                  {(desktop.awaiting_takeover || desktop.takeover_reason) && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] text-amber-900">
                      <span className="font-semibold">Action needed:</span>{" "}
                      {desktop.takeover_reason ||
                        "Open the virtual desktop screen to sign in or pass a verification check."}
                    </div>
                  )}

                  <div className="rounded-xl bg-slate-50 border border-slate-200 px-3 py-2 text-[11px] text-slate-600 flex justify-between gap-2">
                    <span>
                      Memory:{" "}
                      {running
                        ? `${desktop.ram_mb} MB / ${desktop.ram_limit_mb} MB`
                        : "0 MB (session saved)"}
                    </span>
                    <span>
                      Auto-sleep: {Math.round(idleSeconds)}s / {Math.round(idleTimeout)}s
                    </span>
                  </div>

                  <div className="flex items-center gap-2 pt-1 flex-wrap">
                    <button
                      type="button"
                      disabled={toggling}
                      onClick={() => onOpenSelkies(desktop)}
                      className="inline-flex items-center gap-1.5 bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium disabled:opacity-50 cursor-pointer hover:bg-slate-800"
                    >
                      <Monitor className="w-3.5 h-3.5" />
                      <span>
                        {desktop.awaiting_takeover
                          ? "Take Over Screen"
                          : running
                            ? "Open Live Screen"
                            : "Start & Open Screen"}
                      </span>
                    </button>
                    <button
                      type="button"
                      disabled={toggling || deletingSlug === desktop.bot_slug}
                      onClick={() => onToggleDesktop(desktop.bot_slug)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                    >
                      {toggling && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                      <span>
                        {toggling
                          ? running
                            ? "Stopping..."
                            : "Starting..."
                          : running
                            ? "Put to Sleep"
                            : "Start Desktop"}
                      </span>
                    </button>
                    {onDeleteBot &&
                      canManage(desktop.owner_email) &&
                      (confirmDeleteSlug === desktop.bot_slug ? (
                        <div className="ml-auto inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            disabled={deletingSlug === desktop.bot_slug}
                            onClick={async () => {
                              setDeletingSlug(desktop.bot_slug);
                              try {
                                await onDeleteBot(desktop.bot_slug);
                                setConfirmDeleteSlug(null);
                              } finally {
                                setDeletingSlug(null);
                              }
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium disabled:opacity-50 cursor-pointer"
                          >
                            {deletingSlug === desktop.bot_slug && (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            )}
                            <span>
                              {deletingSlug === desktop.bot_slug ? "Deleting..." : "Confirm Delete"}
                            </span>
                          </button>
                          <button
                            type="button"
                            disabled={deletingSlug === desktop.bot_slug}
                            onClick={() => setConfirmDeleteSlug(null)}
                            className="px-2.5 py-1.5 rounded-xl border border-slate-200 bg-white text-xs text-slate-600 hover:bg-slate-50 cursor-pointer"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          type="button"
                          disabled={deletingSlug === desktop.bot_slug}
                          onClick={() => setConfirmDeleteSlug(desktop.bot_slug)}
                          className="ml-auto inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl border border-rose-200 bg-white text-xs font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          <span>Delete Bot</span>
                        </button>
                      ))}
                  </div>
                </div>
              );
            })}
              </div>
            )}

            {sandboxes.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 px-1">
                  <div>
                    <h3 className="text-xs font-semibold text-slate-900">
                      Script Sandboxes (Fedora 45 CLI · 512 MB cap)
                    </h3>
                    <p className="text-[11px] text-slate-500">
                      Lightweight isolated bash &amp; Python 3 containers with persistent /workspace volumes
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {sandboxes.map((sandbox) => {
                    const running = sandbox.sandbox_state === "running";
                    const toggling = Boolean(togglingSandboxes[sandbox.bot_slug]);
                    const idleSeconds = sandbox.idle_seconds ?? 0;
                    const idleTimeout = sandbox.idle_timeout_seconds ?? 300;
                    return (
                      <div
                        key={sandbox.bot_slug}
                        className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="text-xs font-semibold text-slate-900 flex items-center gap-1.5">
                              <Terminal className="w-3.5 h-3.5 text-emerald-600" />
                              <span>{sandbox.bot_name}</span>
                            </div>
                            <div className="text-[11px] text-slate-500">
                              Headless Fedora 45 CLI · {sandbox.ram_limit_mb} MB cap · /workspace persisted
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 flex-wrap justify-end">
                            {isMultiUser && (
                              <>
                                {sandbox.owner_email && (
                                  <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[10px] text-slate-600">
                                    {sandbox.owner_email}
                                  </span>
                                )}
                                <span
                                  className={`px-2 py-0.5 rounded-full border text-[10px] font-medium ${visibilityBadgeClasses(
                                    sandbox.visibility,
                                  )}`}
                                >
                                  {formatVisibilityLabel(sandbox.visibility, sandbox.allowed_groups)}
                                </span>
                              </>
                            )}
                            <span
                              className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${
                                running
                                  ? "border-emerald-300 text-emerald-700 bg-emerald-50"
                                  : "border-slate-200 text-slate-600 bg-slate-50"
                              }`}
                            >
                              {running ? "Running" : "Sleeping (Saved)"}
                            </span>
                          </div>
                        </div>

                        <p className="text-xs text-slate-500">{sandbox.role}</p>

                        <div className="rounded-xl bg-slate-50 border border-slate-200 px-3 py-2 text-[11px] text-slate-600 flex justify-between gap-2">
                          <span>
                            Memory:{" "}
                            {running
                              ? `${sandbox.ram_mb} MB / ${sandbox.ram_limit_mb} MB`
                              : "0 MB (/workspace saved)"}
                          </span>
                          <span>
                            Auto-sleep: {Math.round(idleSeconds)}s / {Math.round(idleTimeout)}s
                          </span>
                        </div>

                        <div className="flex items-center gap-2 pt-1 flex-wrap">
                          {onToggleSandbox && (
                            <button
                              type="button"
                              disabled={toggling || deletingSlug === sandbox.bot_slug}
                              onClick={() => onToggleSandbox(sandbox.bot_slug)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                            >
                              {toggling && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                              <span>
                                {toggling
                                  ? running
                                    ? "Stopping..."
                                    : "Starting..."
                                  : running
                                    ? "Put to Sleep"
                                    : "Start Sandbox"}
                              </span>
                            </button>
                          )}
                          {onDeleteBot &&
                            canManage(sandbox.owner_email) &&
                            (confirmDeleteSlug === sandbox.bot_slug ? (
                              <div className="ml-auto inline-flex items-center gap-1.5">
                                <button
                                  type="button"
                                  disabled={deletingSlug === sandbox.bot_slug}
                                  onClick={async () => {
                                    setDeletingSlug(sandbox.bot_slug);
                                    try {
                                      await onDeleteBot(sandbox.bot_slug);
                                      setConfirmDeleteSlug(null);
                                    } finally {
                                      setDeletingSlug(null);
                                    }
                                  }}
                                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium disabled:opacity-50 cursor-pointer"
                                >
                                  {deletingSlug === sandbox.bot_slug && (
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                  )}
                                  <span>
                                    {deletingSlug === sandbox.bot_slug ? "Deleting..." : "Confirm Delete"}
                                  </span>
                                </button>
                                <button
                                  type="button"
                                  disabled={deletingSlug === sandbox.bot_slug}
                                  onClick={() => setConfirmDeleteSlug(null)}
                                  className="px-2.5 py-1.5 rounded-xl border border-slate-200 bg-white text-xs text-slate-600 hover:bg-slate-50 cursor-pointer"
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : (
                              <button
                                type="button"
                                disabled={deletingSlug === sandbox.bot_slug}
                                onClick={() => setConfirmDeleteSlug(sandbox.bot_slug)}
                                className="ml-auto inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl border border-rose-200 bg-white text-xs font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                                <span>Delete Bot</span>
                              </button>
                            ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
