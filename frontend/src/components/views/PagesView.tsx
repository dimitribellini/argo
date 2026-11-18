import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  ArrowRight,
  ArrowUp,
  Check,
  Columns2,
  Copy,
  Download,
  ExternalLink,
  Loader2,
  Maximize2,
  RefreshCw,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { api } from "../../api";
import type {
  BotRecord,
  BotRunActivity,
  LiveWorkspaceStatusResponse,
  PageDataResponse,
  PageRecord,
} from "../../types";
import { formatFriendlyTime } from "../../utils/format";

const WEBUI_IFRAME_SCROLLBAR_STYLE = `<style id="argo-webui-scroll">html{color-scheme:dark;scrollbar-width:thin;scrollbar-color:#363e4d #161920;}::-webkit-scrollbar{width:6px;height:6px;}::-webkit-scrollbar-track{background:#161920;}::-webkit-scrollbar-thumb{background:#363e4d;border-radius:9999px;}::-webkit-scrollbar-thumb:hover{background:#4b5563;}</style>`;

const MAX_PAGE_DOWNLOAD_BYTES = 50 * 1024 * 1024;
const SAFE_PAGE_DOWNLOAD_EXT_TO_MIME: Record<string, string> = {
  ".webm": "video/webm",
  ".mp4": "video/mp4",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".csv": "text/csv;charset=utf-8",
  ".json": "application/json;charset=utf-8",
  ".md": "text/markdown;charset=utf-8",
  ".txt": "text/plain;charset=utf-8",
  ".html": "text/html;charset=utf-8",
  ".pdf": "application/pdf",
};
const SAFE_PAGE_DOWNLOAD_MIME_TO_EXT: Record<string, string> = {
  "video/webm": ".webm",
  "video/mp4": ".mp4",
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "image/svg+xml": ".svg",
  "text/csv": ".csv",
  "application/json": ".json",
  "text/markdown": ".md",
  "text/plain": ".txt",
  "text/html": ".html",
  "application/pdf": ".pdf",
};

function triggerSafeIframeDownload(msg: Record<string, unknown>): string | null {
  const rawName = String(msg.filename ?? msg.name ?? "").trim();
  const baseOnly = rawName.split(/[\\/]/).pop() ?? "";
  let cleanName = baseOnly.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "");
  if (!cleanName) cleanName = "bot-export";

  let reqMime = String(msg.mimeType ?? msg.mime_type ?? msg.contentType ?? "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  const rawPayload =
    msg.data ?? msg.bytes ?? msg.content ?? (typeof msg.base64 === "string" ? msg.base64 : undefined);

  if (typeof rawPayload === "string" && rawPayload.startsWith("data:") && !reqMime) {
    const semi = rawPayload.indexOf(";");
    const comma = rawPayload.indexOf(",");
    const mimeEnd = semi > 5 && (comma === -1 || semi < comma) ? semi : comma;
    if (mimeEnd > 5) {
      reqMime = rawPayload.slice(5, mimeEnd).trim().toLowerCase();
    }
  } else if (rawPayload instanceof Blob && rawPayload.type && !reqMime) {
    reqMime = rawPayload.type.split(";")[0].trim().toLowerCase();
  }

  const dotIdx = cleanName.lastIndexOf(".");
  let ext = dotIdx > 0 ? cleanName.slice(dotIdx).toLowerCase() : "";
  if (!ext) {
    ext = SAFE_PAGE_DOWNLOAD_MIME_TO_EXT[reqMime] ?? ".bin";
    if (ext !== ".bin") {
      cleanName = `${cleanName}${ext}`;
    }
  }
  const safeMime = SAFE_PAGE_DOWNLOAD_EXT_TO_MIME[ext];
  if (!safeMime) {
    return `Blocked unsupported export file extension '${ext || ".bin"}'.`;
  }

  let blob: Blob;
  if (rawPayload instanceof Blob) {
    if (rawPayload.size > MAX_PAGE_DOWNLOAD_BYTES) {
      return "Export exceeds the 50 MB Living Page download limit.";
    }
    blob = new Blob([rawPayload], { type: safeMime });
  } else if (rawPayload instanceof ArrayBuffer) {
    if (rawPayload.byteLength > MAX_PAGE_DOWNLOAD_BYTES) {
      return "Export exceeds the 50 MB Living Page download limit.";
    }
    blob = new Blob([new Uint8Array(rawPayload)], { type: safeMime });
  } else if (ArrayBuffer.isView(rawPayload)) {
    if (rawPayload.byteLength > MAX_PAGE_DOWNLOAD_BYTES) {
      return "Export exceeds the 50 MB Living Page download limit.";
    }
    const viewCopy = new Uint8Array(rawPayload.byteLength);
    viewCopy.set(new Uint8Array(rawPayload.buffer, rawPayload.byteOffset, rawPayload.byteLength));
    blob = new Blob([viewCopy], { type: safeMime });
  } else if (typeof rawPayload === "string") {
    const isBase64Msg =
      msg.encoding === "base64" ||
      typeof msg.base64 === "string" ||
      /^data:[^;]*;base64,/i.test(rawPayload);
    if (isBase64Msg) {
      const b64Part = rawPayload.includes(",") ? rawPayload.split(",", 2)[1] : rawPayload;
      if (Math.ceil((b64Part.length * 3) / 4) > MAX_PAGE_DOWNLOAD_BYTES) {
        return "Export exceeds the 50 MB Living Page download limit.";
      }
      try {
        const binary = window.atob(b64Part);
        if (binary.length > MAX_PAGE_DOWNLOAD_BYTES) {
          return "Export exceeds the 50 MB Living Page download limit.";
        }
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
          bytes[i] = binary.charCodeAt(i);
        }
        blob = new Blob([bytes], { type: safeMime });
      } catch {
        return "Invalid base64 download payload from Living Page.";
      }
    } else {
      blob = new Blob([rawPayload], { type: safeMime });
      if (blob.size > MAX_PAGE_DOWNLOAD_BYTES) {
        return "Export exceeds the 50 MB Living Page download limit.";
      }
    }
  } else {
    return "Missing downloadable payload in Living Page export request.";
  }

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = cleanName;
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 15_000);
  return null;
}

function injectWebUiScrollbar(rawHtml: string): string {
  if (!rawHtml || rawHtml.includes('id="argo-webui-scroll"')) {
    return rawHtml;
  }
  if (/<\/head>/i.test(rawHtml)) {
    return rawHtml.replace(/<\/head>/i, `${WEBUI_IFRAME_SCROLLBAR_STYLE}</head>`);
  }
  return `${WEBUI_IFRAME_SCROLLBAR_STYLE}${rawHtml}`;
}

interface PagesViewProps {
  page: PageRecord | null;
  onOpenNewPage: () => void;
  onDeletePage: (slug: string) => Promise<void>;
  liveStatus?: LiveWorkspaceStatusResponse | null;
  ownerBot?: BotRecord | null;
  bots?: BotRecord[];
  standalone?: boolean;
  splitMode?: boolean;
  lastActivityId?: string | null;
  activeOwnerRun?: BotRunActivity | null;
  onSendMessageToOwner?: (
    slug: string,
    text: string,
    options?: {
      skill_slugs?: string[];
      context_correlation_id?: string;
      target_page_slug?: string;
    },
  ) => Promise<void>;
  onOpenBot?: (slug: string) => void;
  onOpenRoom?: (slug: string) => void;
  onDockSideBySide?: (slug: string) => void;
  onCloseSplit?: () => void;
  onExpandFull?: (slug: string) => void;
  onOpenApprovals?: () => void;
  onTriggerBot?: (slug: string) => Promise<void>;
  onPageUpdated?: () => Promise<void> | void;
}

export function PagesView({
  page,
  onOpenNewPage,
  onDeletePage,
  liveStatus = null,
  ownerBot = null,
  bots = [],
  standalone = false,
  splitMode = false,
  lastActivityId = null,
  activeOwnerRun = null,
  onSendMessageToOwner,
  onOpenBot,
  onOpenRoom,
  onDockSideBySide,
  onCloseSplit,
  onExpandFull,
  onOpenApprovals,
  onTriggerBot,
  onPageUpdated,
}: PagesViewProps) {
  const [pageData, setPageData] = useState<PageDataResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterText, setFilterText] = useState("");
  const [copiedLink, setCopiedLink] = useState(false);
  const [composerText, setComposerText] = useState("");
  const [updatingPage, setUpdatingPage] = useState(false);
  const [lastEditNotice, setLastEditNotice] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);

  useEffect(() => {
    setLastEditNotice(null);
  }, [page?.slug]);

  const refreshPage = useCallback(
    async (silent = false) => {
      if (!page) {
        setPageData(null);
        return;
      }
      if (!silent) setLoading(true);
      setError(null);
      try {
        const data = await api.getPageData(page.slug);
        setPageData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load Page data.");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [page?.slug],
  );

  useEffect(() => {
    void refreshPage(false);
  }, [refreshPage]);

  useEffect(() => {
    if (!page) return;
    void refreshPage(true);
  }, [page?.updated_at, page?.content_payload, lastActivityId, refreshPage, page]);

  const postToIframe = useCallback((payload: unknown) => {
    const win = iframeRef.current?.contentWindow;
    if (!win) return;
    win.postMessage(payload, "*");
  }, []);

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html" || !pageData) return;
    postToIframe({
      type: "ARGO_PAGE_DATA",
      page: pageData.page,
      records: pageData.records,
      data: pageData,
      liveStatus,
    });
    if (liveStatus) {
      postToIframe({
        type: "ARGO_LIVE_STATUS",
        liveStatus,
      });
    }
  }, [page, pageData, liveStatus, postToIframe]);

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html") return;

    function handleMessage(event: MessageEvent) {
      const targetWindow = iframeRef.current?.contentWindow;
      if (!targetWindow || event.source !== targetWindow) return;
      if (!event.data || typeof event.data !== "object") return;
      const msg = event.data as Record<string, unknown>;

      if (msg.type === "ARGO_READY" && page) {
        postToIframe({
          type: "ARGO_PAGE_DATA",
          page: pageData?.page ?? page,
          records: pageData?.records ?? [],
          data: pageData,
          liveStatus,
        });
        if (liveStatus) {
          postToIframe({
            type: "ARGO_LIVE_STATUS",
            liveStatus,
          });
        }
      } else if (msg.type === "ARGO_QUERY_COLLECTION" && page) {
        const requestId = String(msg.requestId ?? "");
        const collection = String(msg.collection ?? "");
        const query = typeof msg.query === "string" ? msg.query : "";
        const limit = typeof msg.limit === "number" ? msg.limit : 25;
        void api
          .queryPageCollection(page.slug, { collection, query, limit })
          .then((result) => {
            postToIframe({
              type: "ARGO_COLLECTION_RESULT",
              requestId,
              result,
            });
          })
          .catch((err) => {
            postToIframe({
              type: "ARGO_COLLECTION_ERROR",
              requestId,
              error: err instanceof Error ? err.message : "Query failed",
            });
          });
      } else if (msg.type === "ARGO_OPEN_BOT") {
        const botSlug = String(msg.botSlug ?? "").trim();
        if (botSlug && onOpenBot) onOpenBot(botSlug);
      } else if (msg.type === "ARGO_OPEN_ROOM") {
        const roomSlug = String(msg.roomSlug ?? "").trim();
        if (roomSlug && onOpenRoom) onOpenRoom(roomSlug);
      } else if (msg.type === "ARGO_OPEN_APPROVALS") {
        if (onOpenApprovals) onOpenApprovals();
      } else if (msg.type === "ARGO_TRIGGER_BOT") {
        const botSlug = String(msg.botSlug ?? "").trim();
        if (botSlug && onTriggerBot) void onTriggerBot(botSlug);
      } else if (msg.type === "ARGO_DOWNLOAD_FILE") {
        const errText = triggerSafeIframeDownload(msg);
        if (errText) setError(errText);
      }
    }

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, [page, pageData, liveStatus, postToIframe, onOpenBot, onOpenRoom, onOpenApprovals, onTriggerBot]);

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html" || !liveStatus) return;
    postToIframe({
      type: "ARGO_LIVE_STATUS",
      liveStatus,
    });
  }, [page, liveStatus, postToIframe]);

  const flatRows = useMemo<Array<Record<string, string>>>(() => {
    const parsedRows = (pageData?.parsed_payload?.rows ?? []) as Array<Record<string, string>>;
    const collectionRows: Array<Record<string, string>> = (pageData?.records ?? []).map((rec) => {
      const doc = rec.doc ?? {};
      return {
        Collection: rec.collection,
        Title: String(doc.title ?? doc.name ?? doc.subject ?? rec.id),
        Status: String(doc.status ?? doc.category ?? "saved"),
        Updated: formatFriendlyTime(rec.updated_at),
      };
    });
    const combined: Array<Record<string, string>> = [...parsedRows, ...collectionRows];
    const q = filterText.trim().toLowerCase();
    if (!q) return combined;
    return combined.filter((row) =>
      Object.values(row).some((v) => String(v ?? "").toLowerCase().includes(q)),
    );
  }, [pageData, filterText]);

  const columns = useMemo(() => {
    const keys = new Set<string>();
    flatRows.forEach((row) => Object.keys(row).forEach((k) => keys.add(k)));
    return Array.from(keys);
  }, [flatRows]);

  if (!page) {
    return (
      <div className="h-full flex items-center justify-center p-6">
        <div className="max-w-md w-full rounded-xl border border-slate-200 bg-white p-6 text-center shadow-xs">
          <h2 className="text-sm font-semibold text-slate-900">No Pages Yet</h2>
          <p className="text-xs text-slate-500 mt-1">
            Turn live bot status, saved items, or custom ideas into an interactive Page you can
            explore, share, or tweak side-by-side with a bot.
          </p>
          <button
            type="button"
            onClick={onOpenNewPage}
            className="mt-4 bg-slate-900 text-white px-3.5 py-2 rounded-lg text-xs font-medium cursor-pointer"
          >
            + Create Page
          </button>
        </div>
      </div>
    );
  }

  const parsed = pageData?.parsed_payload ?? {};
  const blocks = Array.isArray(parsed.blocks) ? parsed.blocks : [];
  const activeOwner =
    ownerBot ??
    bots.find((b) => b.slug === page.owner_bot_slug) ??
    bots[0] ??
    null;

  function handleCopyLink() {
    if (!page) return;
    const url = `${window.location.origin}/?view=page&slug=${encodeURIComponent(page.slug)}`;
    if (navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(url);
    }
    setCopiedLink(true);
    window.setTimeout(() => setCopiedLink(false), 1800);
  }

  function handleDownloadHtml() {
    if (!page || page.render_mode !== "sandboxed_html") return;
    const blob = new Blob([page.content_payload], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${page.slug}.html`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 15_000);
  }

  async function handleQuickUpdate(e: FormEvent) {
    e.preventDefault();
    const prompt = composerText.trim();
    if (!page || !prompt || updatingPage) return;
    setUpdatingPage(true);
    setError(null);
    try {
      if (activeOwner && onSendMessageToOwner) {
        await onSendMessageToOwner(activeOwner.slug, prompt, {
          target_page_slug: page.slug,
        });
      } else {
        await api.generatePage({
          prompt,
          title: page.title,
          owner_bot_slug: page.owner_bot_slug || undefined,
          allowed_collections: page.allowed_collections,
          existing_page_slug: page.slug,
        });
      }
      setComposerText("");
      setLastEditNotice(`Updated "${page.title}" in-place`);
      await onPageUpdated?.();
      await refreshPage(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update page.");
    } finally {
      setUpdatingPage(false);
    }
  }

  return (
    <div className="h-full flex overflow-hidden bg-slate-50">
      <div className="flex-1 min-w-0 flex flex-col overflow-hidden bg-slate-50">
        {/* Slim Flattened Toolbar */}
        <div className="shrink-0 px-4 py-2 border-b border-slate-200 bg-white flex flex-wrap items-center justify-between gap-2.5 text-slate-700">
          <div className="flex flex-wrap items-center gap-2 min-w-0">
            {activeOwner && (
              <button
                type="button"
                onClick={() => onOpenBot?.(activeOwner.slug)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 hover:bg-slate-100 text-xs font-medium text-slate-900 cursor-pointer"
              >
                <span className="text-slate-500">Owner:</span>
                <span>{activeOwner.name}</span>
              </button>
            )}
            <span className="text-xs text-slate-500 hidden sm:inline">
              · Updated {formatFriendlyTime(page.updated_at)}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {splitMode && onExpandFull && (
              <button
                type="button"
                onClick={() => onExpandFull(page.slug)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer"
                title="Expand to full screen"
              >
                <Maximize2 className="w-3.5 h-3.5" />
                <span>Expand</span>
              </button>
            )}

            {!splitMode && !standalone && onDockSideBySide && (
              <button
                type="button"
                onClick={() => onDockSideBySide(page.slug)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer"
                title="Dock side-by-side beside chat"
              >
                <Columns2 className="w-3.5 h-3.5" />
                <span>Dock Beside Chat</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleCopyLink}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer"
            >
              {copiedLink ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Link</span>
                </>
              )}
            </button>

            {!standalone ? (
              <a
                href={`/?standalone_page=${encodeURIComponent(page.slug)}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Standalone</span>
              </a>
            ) : (
              <a
                href={`/?view=page&slug=${encodeURIComponent(page.slug)}`}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100"
              >
                <span>Back to Argo</span>
              </a>
            )}

            {page.render_mode === "sandboxed_html" && (
              <button
                type="button"
                onClick={handleDownloadHtml}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>HTML</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => void refreshPage()}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer"
              title="Refresh Page"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            </button>

            {!standalone && !splitMode && (
              <button
                type="button"
                onClick={() => void onDeletePage(page.slug)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-600 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700 cursor-pointer"
                title="Delete Page"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}

            {splitMode && onCloseSplit && (
              <button
                type="button"
                onClick={onCloseSplit}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-600 hover:bg-slate-100 hover:text-slate-900 cursor-pointer"
                title="Close split panel"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mx-4 mt-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2.5 text-xs text-rose-700">
            {error}
          </div>
        )}

        {/* Seamless Page Canvas */}
        <div className="flex-1 min-h-0 flex flex-col overflow-hidden relative">
          {page.render_mode === "sandboxed_html" ? (
            <iframe
              ref={iframeRef}
              title={page.title}
              sandbox="allow-scripts allow-downloads"
              srcDoc={injectWebUiScrollbar(page.content_payload)}
              onLoad={() => {
                postToIframe({
                  type: "ARGO_PAGE_DATA",
                  page: pageData?.page ?? page,
                  records: pageData?.records ?? [],
                  data: pageData,
                  liveStatus,
                });
                if (liveStatus) {
                  postToIframe({
                    type: "ARGO_LIVE_STATUS",
                    liveStatus,
                  });
                }
              }}
              className="w-full flex-1 min-h-[360px] border-0 bg-[#161920]"
            />
          ) : (
            <div className="flex-1 overflow-y-auto p-6 space-y-5 custom-scroll">
              <div className="max-w-5xl mx-auto space-y-5">
                {blocks.length > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {blocks.map((block, idx) => (
                      <div
                        key={`${block.label}-${idx}`}
                        className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs"
                      >
                        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                          {block.label}
                        </div>
                        <div className="text-xl font-semibold text-slate-900 mt-1">{block.value}</div>
                        {block.hint && (
                          <div className="text-xs text-slate-500 mt-1">{block.hint}</div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-xs">
                  <div className="px-4 py-3 border-b border-slate-200 bg-slate-50 flex flex-wrap items-center justify-between gap-2">
                    <div className="text-xs font-medium text-slate-700">
                      {loading ? "Refreshing..." : `${flatRows.length} items`}
                    </div>
                    <input
                      type="search"
                      value={filterText}
                      onChange={(e) => setFilterText(e.target.value)}
                      placeholder="Filter items..."
                      className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-slate-400"
                    />
                  </div>
                  {flatRows.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No matching records found in allowed data lists.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse">
                        <thead>
                          <tr className="border-b border-slate-200 text-xs uppercase tracking-wider text-slate-500 bg-slate-50">
                            {columns.map((col) => (
                              <th key={col} className="py-2.5 px-4 font-semibold">
                                {col}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 text-xs">
                          {flatRows.map((row, idx) => (
                            <tr key={idx} className="hover:bg-slate-50">
                              {columns.map((col) => (
                                <td key={col} className="py-2.5 px-4 text-slate-800">
                                  {String(row[col] ?? "")}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Single Unified Bottom Page Editor Composer */}
          {!standalone && (
            <div className="shrink-0 px-4 py-3 border-t border-slate-200 bg-white space-y-2">
              {(updatingPage || activeOwnerRun || lastEditNotice) && (
                <div className="max-w-2xl mx-auto flex items-center justify-between gap-2 px-3 py-1.5 rounded-xl border border-slate-200 bg-slate-50 text-xs">
                  <div className="flex items-center gap-2 min-w-0 text-slate-800">
                    {updatingPage || activeOwnerRun ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-600 shrink-0" />
                        <span className="truncate">
                          {activeOwnerRun?.step || `Updating "${page.title}" with ${activeOwner?.name ?? "Bot"}...`}
                        </span>
                      </>
                    ) : (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                        <span className="truncate">{lastEditNotice}</span>
                      </>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {activeOwner && onOpenBot && (
                      <button
                        type="button"
                        onClick={() => onOpenBot(activeOwner.slug)}
                        className="inline-flex items-center gap-1 text-blue-700 hover:text-blue-800 font-medium cursor-pointer"
                      >
                        <span>Open @{activeOwner.name}</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                    {lastEditNotice && !updatingPage && !activeOwnerRun && (
                      <button
                        type="button"
                        onClick={() => setLastEditNotice(null)}
                        className="text-slate-400 hover:text-slate-700 cursor-pointer"
                        aria-label="Dismiss status"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              )}
              <form
                onSubmit={handleQuickUpdate}
                className="max-w-2xl mx-auto flex items-center gap-2 rounded-full border border-slate-300 bg-slate-50 px-3.5 py-1.5 shadow-xs focus-within:border-slate-500"
              >
                <Sparkles className="w-4 h-4 text-slate-500 shrink-0" />
                <input
                  type="text"
                  value={composerText}
                  onChange={(e) => setComposerText(e.target.value)}
                  disabled={updatingPage}
                  placeholder={
                    activeOwner
                      ? `Ask ${activeOwner.name} to refine or update "${page.title}"...`
                      : `Describe changes to "${page.title}"...`
                  }
                  className="flex-1 min-w-0 bg-transparent border-0 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none py-1"
                />
                <button
                  type="submit"
                  disabled={updatingPage || !composerText.trim()}
                  className="w-7 h-7 rounded-full bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-white flex items-center justify-center shrink-0 cursor-pointer transition-colors"
                  title="Update Page"
                >
                  {updatingPage ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <ArrowUp className="w-3.5 h-3.5" />
                  )}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
