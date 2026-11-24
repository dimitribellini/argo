import { useCallback, useEffect, useRef, useState } from "react";
import { Camera, Loader2, RefreshCw } from "lucide-react";
import { api } from "../api";
import type { DesktopBootProgress } from "../types";

interface DesktopScreenPreviewProps {
  botSlug: string;
  running: boolean;
  hasScreenshot?: boolean;
  toggling?: boolean;
  bootProgress?: DesktopBootProgress | null;
  onOpenScreen?: () => void;
  compact?: boolean;
}

const LIVE_PREVIEW_INTERVAL_MS = 3500;

export function DesktopScreenPreview({
  botSlug,
  running,
  hasScreenshot = false,
  toggling = false,
  bootProgress = null,
  onOpenScreen,
  compact = false,
}: DesktopScreenPreviewProps) {
  const [displayedSrc, setDisplayedSrc] = useState<string | null>(null);
  const [imgFailed, setImgFailed] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const displayedSrcRef = useRef<string | null>(null);
  const inFlightRef = useRef(false);
  const activeSlugRef = useRef(botSlug);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    displayedSrcRef.current = displayedSrc;
  }, [displayedSrc]);

  useEffect(() => {
    activeSlugRef.current = botSlug;
    displayedSrcRef.current = null;
    inFlightRef.current = false;
    setDisplayedSrc(null);
    setImgFailed(false);
    setRefreshing(false);
  }, [botSlug]);

  const preloadFrame = useCallback(
    (opts: { refresh: boolean; passive: boolean; manual?: boolean }): (() => void) => {
      if (inFlightRef.current && !opts.manual) {
        return () => {};
      }
      inFlightRef.current = true;
      const targetSlug = botSlug;
      const nextUrl = api.desktopScreenshotUrl(targetSlug, {
        refresh: opts.refresh,
        passive: opts.passive,
        maxWidth: 960,
        cacheBust: Date.now(),
      });
      let cancelled = false;
      const probe = new Image();
      probe.onload = () => {
        if (cancelled || !mountedRef.current || activeSlugRef.current !== targetSlug) return;
        inFlightRef.current = false;
        displayedSrcRef.current = nextUrl;
        setDisplayedSrc(nextUrl);
        setImgFailed(false);
        if (opts.manual) {
          setRefreshing(false);
        }
      };
      probe.onerror = () => {
        if (cancelled || !mountedRef.current || activeSlugRef.current !== targetSlug) return;
        inFlightRef.current = false;
        if (!displayedSrcRef.current) {
          setImgFailed(true);
        }
        if (opts.manual) {
          setRefreshing(false);
        }
      };
      probe.src = nextUrl;
      return () => {
        cancelled = true;
        probe.onload = null;
        probe.onerror = null;
        inFlightRef.current = false;
      };
    },
    [botSlug],
  );

  useEffect(() => {
    if (!running && !hasScreenshot) {
      return undefined;
    }
    return preloadFrame({ refresh: false, passive: true });
  }, [running, hasScreenshot, preloadFrame]);

  useEffect(() => {
    if (!running) return undefined;
    let cancelPending: (() => void) | null = null;
    const pollId = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      cancelPending = preloadFrame({ refresh: true, passive: true });
    }, LIVE_PREVIEW_INTERVAL_MS);

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        cancelPending = preloadFrame({ refresh: true, passive: true });
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      window.clearInterval(pollId);
      document.removeEventListener("visibilitychange", handleVisibility);
      cancelPending?.();
    };
  }, [running, preloadFrame]);

  function handleRefreshClick() {
    setRefreshing(true);
    setImgFailed(false);
    preloadFrame({ refresh: true, passive: false, manual: true });
  }

  const showError = bootProgress?.state === "error";
  const canShowImage = Boolean(displayedSrc) && !imgFailed;
  const showBootWait = !canShowImage && (bootProgress?.state === "booting" || (toggling && !running));

  return (
    <div className="space-y-2">
      {showBootWait && (
        <div className="rounded-lg border border-sky-200 bg-sky-50 px-2.5 py-2 text-[11px] text-sky-900 flex items-start gap-2">
          <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-600 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="font-semibold">Starting Virtual Desktop — please wait</div>
            <div className="text-[10.5px] text-sky-700 break-words">
              {bootProgress?.step ||
                "Provisioning Fedora XFCE desktop, Selkies, Chromium & MCP agent (:9223)..."}
            </div>
          </div>
        </div>
      )}

      {showError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-2 text-[11px] text-rose-800">
          {bootProgress.step}
        </div>
      )}

      {(running || hasScreenshot || canShowImage) && (
        <div className="rounded-xl border border-slate-200 bg-slate-950 overflow-hidden">
          <div className="aspect-video w-full relative flex items-center justify-center bg-slate-950">
            {canShowImage && displayedSrc ? (
              <img
                src={displayedSrc}
                alt={`Desktop preview for ${botSlug}`}
                onClick={onOpenScreen}
                className={`w-full h-full object-cover ${onOpenScreen ? "cursor-pointer" : ""}`}
              />
            ) : (
              <div className="text-center px-3 py-4 space-y-1.5">
                <Camera className="w-4 h-4 text-slate-400 mx-auto" />
                <div className="text-[11px] text-slate-300">
                  {running
                    ? "Desktop screen warming up — capturing live preview frame…"
                    : "Desktop is sleeping — start it or capture to preview."}
                </div>
              </div>
            )}

            {running && canShowImage && (
              <span
                className={`pointer-events-none absolute ${
                  compact ? "top-1.5 left-1.5 px-1.5 py-0.5 text-[9.5px]" : "top-2 left-2 px-2 py-0.5 text-[10px]"
                } inline-flex items-center gap-1 rounded-full argo-code-block border font-medium`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Live Preview
              </span>
            )}

            <button
              type="button"
              onClick={handleRefreshClick}
              disabled={refreshing}
              title="Capture fresh desktop screenshot"
              className={`absolute ${
                compact
                  ? "bottom-1.5 right-1.5 px-2 py-1 text-[10px]"
                  : "bottom-2 right-2 px-2.5 py-1 text-[11px]"
              } inline-flex items-center gap-1 rounded-lg argo-studio-btn border cursor-pointer disabled:opacity-60`}
            >
              {refreshing ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <RefreshCw className="w-3 h-3" />
              )}
              <span>{canShowImage ? "Refresh" : "Capture Preview"}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
