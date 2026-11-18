import { useEffect, useState } from "react";
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

export function DesktopScreenPreview({
  botSlug,
  running,
  hasScreenshot = false,
  toggling = false,
  bootProgress = null,
  onOpenScreen,
  compact = false,
}: DesktopScreenPreviewProps) {
  const [nonce, setNonce] = useState(0);
  const [forceRefresh, setForceRefresh] = useState(false);
  const [imgFailed, setImgFailed] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    setImgFailed(false);
    setForceRefresh(false);
    setNonce(0);
    setRefreshing(false);
  }, [botSlug]);

  useEffect(() => {
    if (running || hasScreenshot) {
      setImgFailed(false);
    }
  }, [running, hasScreenshot]);

  const showBootWait = bootProgress?.state === "booting" || (toggling && !running);
  const showError = bootProgress?.state === "error";
  const canShowImage = (running || hasScreenshot || nonce > 0) && !imgFailed;

  const src = api.desktopScreenshotUrl(botSlug, {
    refresh: forceRefresh,
    maxWidth: 1280,
    cacheBust: nonce || undefined,
  });

  function handleRefreshClick() {
    setRefreshing(true);
    setImgFailed(false);
    setForceRefresh(true);
    setNonce((n) => n + 1);
  }

  return (
    <div className="space-y-2">
      {showBootWait && (
        <div className="rounded-lg border border-sky-200 bg-sky-50 px-2.5 py-2 text-[11px] text-sky-900 flex items-start gap-2">
          <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-600 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="font-semibold">Starting Virtual Desktop — please wait</div>
            <div className="text-[10.5px] text-sky-700 break-words">
              {bootProgress?.step || "Provisioning Fedora XFCE desktop, Selkies, Chromium & MCP agent (:9223)..."}
            </div>
          </div>
        </div>
      )}

      {showError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-2 text-[11px] text-rose-800">
          {bootProgress.step}
        </div>
      )}

      {(running || hasScreenshot || nonce > 0) && (
        <div className="rounded-xl border border-slate-200 bg-slate-950 overflow-hidden">
          <div className="aspect-video w-full relative flex items-center justify-center bg-slate-950">
            {canShowImage ? (
              <img
                src={src}
                alt={`Desktop preview for ${botSlug}`}
                onLoad={() => setRefreshing(false)}
                onError={() => {
                  setRefreshing(false);
                  setImgFailed(true);
                }}
                onClick={onOpenScreen}
                className={`w-full h-full object-cover ${onOpenScreen ? "cursor-pointer" : ""}`}
              />
            ) : (
              <div className="text-center px-3 py-4 space-y-1.5">
                <Camera className="w-4 h-4 text-slate-400 mx-auto" />
                <div className="text-[11px] text-slate-300">
                  {running
                    ? "Desktop screen warming up — capture a preview frame once X11 is ready."
                    : "Desktop is sleeping — start it or capture to preview."}
                </div>
              </div>
            )}

            <button
              type="button"
              onClick={handleRefreshClick}
              disabled={refreshing}
              title="Capture fresh desktop screenshot"
              className={`absolute ${
                compact ? "bottom-1.5 right-1.5 px-2 py-1 text-[10px]" : "bottom-2 right-2 px-2.5 py-1 text-[11px]"
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
