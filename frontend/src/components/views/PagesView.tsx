import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  AlertTriangle,
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
  Wrench,
  X,
} from "lucide-react";
import echartsRaw from "echarts/dist/echarts.min.js?raw";
import worldGeoJson from "../../assets/world.geo.json";
import { api } from "../../api";
import type {
  BotRecord,
  BotRunActivity,
  LiveWorkspaceStatusResponse,
  PageDataResponse,
  PageRecord,
} from "../../types";
import { formatFriendlyTime } from "../../utils/format";

const WEBUI_IFRAME_SCROLLBAR_STYLE = `<style id="argo-webui-scroll">:root,:root[data-theme="dark"]{color-scheme:dark;--bg:#161920;--surface:#181c23;--card:#1e232c;--border:#2d3440;--text:#f3f4f6;--muted:#9ca3af;--accent:#3b72b2;--good:#3b8c62;--warn:#c98a2c;--bad:#c24b4b;--series-1:#4f86c6;--series-2:#4aa376;--series-3:#d49b3e;--series-4:#8c7ae6;--series-5:#d16666;--series-6:#52a5b8;scrollbar-width:thin;scrollbar-color:#363e4d #161920;}:root[data-theme="light"]{color-scheme:light;--bg:#f8fafc;--surface:#f1f5f9;--card:#ffffff;--border:#e2e8f0;--text:#0f172a;--muted:#64748b;--accent:#2563eb;--good:#15803d;--warn:#b45309;--bad:#b91c1c;--series-1:#2563eb;--series-2:#16a34a;--series-3:#d97706;--series-4:#7c3aed;--series-5:#dc2626;--series-6:#0891b2;scrollbar-width:thin;scrollbar-color:#cbd5e1 #f8fafc;}::-webkit-scrollbar{width:6px;height:6px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--border);border-radius:9999px;}::-webkit-scrollbar-thumb:hover{background:var(--muted);}.argo-grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));}.argo-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;color:var(--text);}.argo-kpi{font-size:24px;font-weight:600;color:var(--text);line-height:1.2;}.argo-table{width:100%;border-collapse:collapse;font-size:13px;}.argo-table th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:600;}.argo-table td{padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text);}.argo-pill{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:12px;font-weight:500;}.argo-err-banner{position:sticky;top:0;z-index:9999;margin:0 0 12px;padding:8px 12px;border-radius:8px;border:1px solid var(--bad);background:var(--surface);color:var(--text);font:12px/1.4 monospace;display:flex;justify-content:space-between;align-items:center;gap:8px;}</style>`;

export const LIVING_PAGE_CSP_CONTENT =
  "default-src 'none'; script-src 'unsafe-inline' blob:; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; media-src data: blob:; worker-src blob:; connect-src 'none'; form-action 'none'; base-uri 'none';";

function escapeInlineScript(raw: string): string {
  return String(raw ?? "").replace(/<\/script/gi, "<\\/script");
}

function buildArgoRuntimeScript(worldGeo: unknown, initialTheme: "light" | "dark"): string {
  const safeGeoJson = escapeInlineScript(JSON.stringify(worldGeo ?? { type: "FeatureCollection", features: [] }));
  const code = `(function(){
  if (window.Argo) return;
  var WORLD_GEO = ${safeGeoJson};
  var currentTheme = ${JSON.stringify(initialTheme)};
  var lockedTheme = document.documentElement.getAttribute("data-argo-locked-theme") === "true";
  var latestSnapshot = null;
  var dataListeners = [];
  var pendingSql = {};
  var sqlSeq = 0;
  var charts = [];
  var echartsConfigured = false;

  function applyThemeAttr(nextTheme) {
    if (lockedTheme) return;
    currentTheme = nextTheme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", currentTheme);
  }

  function ensureEChartsSetup() {
    if (echartsConfigured || !window.echarts) return;
    echartsConfigured = true;
    var lightPalette = ["#2563eb","#16a34a","#d97706","#7c3aed","#dc2626","#0891b2"];
    var darkPalette = ["#4f86c6","#4aa376","#d49b3e","#8c7ae6","#d16666","#52a5b8"];
    if (typeof window.echarts.registerTheme === "function") {
      window.echarts.registerTheme("argo-light", {
        backgroundColor: "transparent",
        color: lightPalette,
        textStyle: { color: "#0f172a" },
        title: { textStyle: { color: "#0f172a" }, subtextStyle: { color: "#64748b" } },
        legend: { textStyle: { color: "#475569" } },
        categoryAxis: { axisLine: { lineStyle: { color: "#cbd5e1" } }, axisLabel: { color: "#475569" }, splitLine: { lineStyle: { color: "#e2e8f0" } } },
        valueAxis: { axisLine: { lineStyle: { color: "#cbd5e1" } }, axisLabel: { color: "#475569" }, splitLine: { lineStyle: { color: "#e2e8f0" } } }
      });
      window.echarts.registerTheme("argo-dark", {
        backgroundColor: "transparent",
        color: darkPalette,
        textStyle: { color: "#f3f4f6" },
        title: { textStyle: { color: "#f3f4f6" }, subtextStyle: { color: "#9ca3af" } },
        legend: { textStyle: { color: "#9ca3af" } },
        categoryAxis: { axisLine: { lineStyle: { color: "#2d3440" } }, axisLabel: { color: "#9ca3af" }, splitLine: { lineStyle: { color: "#232934" } } },
        valueAxis: { axisLine: { lineStyle: { color: "#2d3440" } }, axisLabel: { color: "#9ca3af" }, splitLine: { lineStyle: { color: "#232934" } } }
      });
    }
    if (typeof window.echarts.registerMap === "function" && WORLD_GEO && Array.isArray(WORLD_GEO.features)) {
      window.echarts.registerMap("world", WORLD_GEO);
    }
  }

  function themeName() {
    var attr = document.documentElement.getAttribute("data-theme");
    return (attr === "light" || (!attr && currentTheme === "light")) ? "argo-light" : "argo-dark";
  }

  function refreshAllCharts() {
    if (!window.echarts) return;
    ensureEChartsSetup();
    var tn = themeName();
    for (var i = 0; i < charts.length; i++) {
      var rec = charts[i];
      if (!rec.el || !document.body.contains(rec.el)) continue;
      if (rec.instance) { try { rec.instance.dispose(); } catch (_) {} }
      rec.instance = window.echarts.init(rec.el, tn, rec.opts || {});
      rec.instance.setOption(rec.option || {}, true);
    }
  }

  window.addEventListener("message", function(ev) {
    var msg = ev && ev.data;
    if (!msg || typeof msg !== "object") return;
    if (msg.type === "ARGO_PAGE_DATA") {
      if (msg.theme && !lockedTheme) applyThemeAttr(msg.theme);
      latestSnapshot = {
        page: msg.page || (msg.data && msg.data.page) || null,
        records: Array.isArray(msg.records) ? msg.records : ((msg.data && msg.data.records) || []),
        rows: Array.isArray(msg.rows) ? msg.rows : (Array.isArray(msg.records) ? msg.records : ((msg.data && msg.data.records) || [])),
        datasets: msg.datasets || (msg.data && msg.data.datasets) || {},
        dataset_profiles: msg.dataset_profiles || (msg.data && msg.data.dataset_profiles) || {},
        collection_counts: msg.collection_counts || (msg.data && msg.data.collection_counts) || {},
        liveStatus: msg.liveStatus || null,
        theme: currentTheme
      };
      for (var i = 0; i < dataListeners.length; i++) {
        try { dataListeners[i](latestSnapshot); } catch (err) { reportRuntimeError(err); }
      }
    } else if (msg.type === "ARGO_THEME_CHANGE") {
      if (!lockedTheme) {
        applyThemeAttr(msg.theme);
        refreshAllCharts();
        if (latestSnapshot) latestSnapshot.theme = currentTheme;
      }
    } else if (msg.type === "ARGO_SQL_RESULT") {
      var entry = pendingSql[String(msg.requestId || "")];
      if (entry) {
        delete pendingSql[String(msg.requestId || "")];
        clearTimeout(entry.timer);
        entry.resolve(msg.result || msg);
      }
    } else if (msg.type === "ARGO_SQL_ERROR") {
      var errEntry = pendingSql[String(msg.requestId || "")];
      if (errEntry) {
        delete pendingSql[String(msg.requestId || "")];
        clearTimeout(errEntry.timer);
        errEntry.reject(new Error(String(msg.error || "SQL query failed")));
      }
    }
  });

  function reportRuntimeError(err, lineNo) {
    var msg = (err && err.message) ? String(err.message) : String(err || "Unknown script error");
    var stack = (err && err.stack) ? String(err.stack).slice(0, 1200) : "";
    try {
      window.parent.postMessage({ type: "ARGO_RUNTIME_ERROR", message: msg, line: lineNo || null, stack: stack }, "*");
    } catch (_) {}
    try {
      var host = document.body || document.documentElement;
      if (host && !document.getElementById("argo-runtime-error-banner")) {
        var b = document.createElement("div");
        b.id = "argo-runtime-error-banner";
        b.className = "argo-err-banner";
        var s = document.createElement("span");
        s.textContent = "Page script error: " + msg;
        var closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.textContent = "Dismiss";
        closeBtn.style.cssText = "background:transparent;border:1px solid currentColor;border-radius:6px;padding:2px 8px;color:inherit;cursor:pointer;";
        closeBtn.onclick = function(){ b.remove(); };
        b.appendChild(s);
        b.appendChild(closeBtn);
        host.insertBefore(b, host.firstChild);
      }
    } catch (_) {}
  }

  window.addEventListener("error", function(ev) {
    reportRuntimeError(ev.error || ev.message || "Script error", ev.lineno);
  });
  window.addEventListener("unhandledrejection", function(ev) {
    reportRuntimeError(ev.reason || "Unhandled promise rejection");
  });

  function escapeHtml(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  window.Argo = {
    onData: function(cb) {
      if (typeof cb !== "function") return function(){};
      dataListeners.push(cb);
      if (latestSnapshot) {
        try { cb(latestSnapshot); } catch (err) { reportRuntimeError(err); }
      }
      return function() {
        dataListeners = dataListeners.filter(function(fn){ return fn !== cb; });
      };
    },
    querySQL: function(sql, params, rowCap, engine) {
      return new Promise(function(resolve, reject) {
        var reqId = "sql_" + (++sqlSeq) + "_" + Date.now();
        var timer = setTimeout(function() {
          delete pendingSql[reqId];
          reject(new Error("SQL query timed out"));
        }, 15000);
        pendingSql[reqId] = { resolve: resolve, reject: reject, timer: timer };
        window.parent.postMessage({
          type: "ARGO_QUERY_SQL",
          requestId: reqId,
          sql: String(sql || ""),
          params: Array.isArray(params) ? params : [],
          row_cap: typeof rowCap === "number" ? rowCap : 500,
          engine: engine || "auto"
        }, "*");
      });
    },
    chart: function(container, option, opts) {
      if (!window.echarts) return null;
      ensureEChartsSetup();
      var el = typeof container === "string" ? document.querySelector(container) : container;
      if (!el) return null;
      var rec = null;
      for (var i = 0; i < charts.length; i++) {
        if (charts[i].el === el) { rec = charts[i]; break; }
      }
      if (!rec) {
        var inst = window.echarts.init(el, themeName(), opts || {});
        rec = { el: el, option: option, opts: opts || {}, instance: inst };
        charts.push(rec);
        if (typeof ResizeObserver !== "undefined") {
          var ro = new ResizeObserver(function() {
            if (rec.instance) { try { rec.instance.resize(); } catch (_) {} }
          });
          ro.observe(el);
        }
      } else {
        rec.option = option;
        rec.opts = opts || rec.opts;
      }
      rec.instance.setOption(option || {}, true);
      return rec.instance;
    },
    fmt: {
      currency: function(n, cur) {
        var num = Number(n);
        if (!isFinite(num)) return "—";
        return new Intl.NumberFormat(undefined, { style: "currency", currency: cur || "USD", maximumFractionDigits: 2 }).format(num);
      },
      compact: function(n) {
        var num = Number(n);
        if (!isFinite(num)) return "—";
        return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(num);
      },
      number: function(n, digits) {
        var num = Number(n);
        if (!isFinite(num)) return "—";
        return new Intl.NumberFormat(undefined, { maximumFractionDigits: typeof digits === "number" ? digits : 2 }).format(num);
      },
      percent: function(n, digits) {
        var num = Number(n);
        if (!isFinite(num)) return "—";
        var d = typeof digits === "number" ? digits : 1;
        return new Intl.NumberFormat(undefined, { style: "percent", minimumFractionDigits: d, maximumFractionDigits: d }).format(num);
      },
      date: function(v) {
        if (!v) return "—";
        var d = new Date(v);
        return isNaN(d.getTime()) ? String(v) : new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(d);
      },
      relative: function(v) {
        if (!v) return "—";
        var d = new Date(v);
        if (isNaN(d.getTime())) return String(v);
        var diffSec = Math.round((d.getTime() - Date.now()) / 1000);
        var rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
        var abs = Math.abs(diffSec);
        if (abs < 60) return rtf.format(diffSec, "second");
        if (abs < 3600) return rtf.format(Math.round(diffSec / 60), "minute");
        if (abs < 86400) return rtf.format(Math.round(diffSec / 3600), "hour");
        return rtf.format(Math.round(diffSec / 86400), "day");
      }
    },
    mediaCover: function(url, label) {
      var u = String(url || "").trim();
      var lbl = String(label || "Item").trim() || "Item";
      var safeLbl = escapeHtml(lbl);
      if (/^(?:data:image\\/|blob:)/i.test(u)) {
        return '<img src="' + escapeHtml(u) + '" alt="' + safeLbl + '" style="width:100%;height:100%;object-fit:cover;border-radius:8px;" />';
      }
      var parts = lbl.split(/\\s+/).filter(Boolean);
      var initials = (parts[0] ? parts[0][0] : "A") + (parts[1] ? parts[1][0] : "");
      initials = escapeHtml(initials.toUpperCase());
      var linkHtml = /^https?:\\/\\//i.test(u)
        ? '<a href="' + escapeHtml(u) + '" target="_blank" rel="noopener noreferrer" style="margin-top:6px;font-size:11px;color:var(--accent);text-decoration:none;border:1px solid var(--border);border-radius:999px;padding:2px 8px;">Open Source ↗</a>'
        : "";
      return '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:12px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text);text-align:center;min-height:84px;">'
        + '<div style="width:36px;height:36px;border-radius:999px;background:var(--card);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:13px;">' + initials + '</div>'
        + '<div style="margin-top:6px;font-size:12px;font-weight:500;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + safeLbl + '</div>'
        + linkHtml + '</div>';
    },
    downloadCSV: function(filename, rows) {
      var arr = Array.isArray(rows) ? rows : [];
      var cols = [];
      if (arr.length && typeof arr[0] === "object" && !Array.isArray(arr[0])) {
        var seen = {};
        for (var i = 0; i < arr.length; i++) {
          var keys = Object.keys(arr[i] || {});
          for (var j = 0; j < keys.length; j++) {
            if (!seen[keys[j]]) { seen[keys[j]] = true; cols.push(keys[j]); }
          }
        }
      }
      function csvEsc(v) {
        var s = v == null ? "" : (typeof v === "object" ? JSON.stringify(v) : String(v));
        return /[",\\n\\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }
      var lines = [];
      if (cols.length) {
        lines.push(cols.map(csvEsc).join(","));
        for (var r = 0; r < arr.length; r++) {
          lines.push(cols.map(function(c){ return csvEsc(arr[r] ? arr[r][c] : ""); }).join(","));
        }
      } else {
        for (var k = 0; k < arr.length; k++) {
          var row = Array.isArray(arr[k]) ? arr[k] : [arr[k]];
          lines.push(row.map(csvEsc).join(","));
        }
      }
      window.parent.postMessage({
        type: "ARGO_DOWNLOAD_FILE",
        filename: String(filename || "export.csv"),
        mimeType: "text/csv",
        content: lines.join("\\n")
      }, "*");
    },
    syncBot: function(botSlug) {
      window.parent.postMessage({ type: "ARGO_TRIGGER_BOT", botSlug: String(botSlug || "") }, "*");
    },
    openBot: function(botSlug) {
      window.parent.postMessage({ type: "ARGO_OPEN_BOT", botSlug: String(botSlug || "") }, "*");
    },
    prefillChat: function(botSlug, draftPrompt) {
      window.parent.postMessage({
        type: "ARGO_PREFILL_CHAT",
        botSlug: String(botSlug || ""),
        prompt: String(draftPrompt || "")
      }, "*");
    }
  };
})();`;
  return `<script id="argo-runtime">${escapeInlineScript(code)}</script>`;
}

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

export function prepareSandboxedPageSrcDoc(
  rawHtml: string,
  theme?: "light" | "dark",
  runtimeAssets?: { echartsScript?: string; worldGeo?: unknown },
): string;
export function prepareSandboxedPageSrcDoc(rawHtml: string): string {
  const themeArg = arguments.length > 1 ? arguments[1] : undefined;
  const assetsArg = arguments.length > 2 ? arguments[2] : undefined;
  const resolvedTheme: "light" | "dark" = themeArg === "light" ? "light" : "dark";
  const input = String(rawHtml ?? "");
  const cleaned = input
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<meta\b[^>]*http-equiv\s*=\s*(['"]?)(?:Content-Security-Policy|refresh)\1[^>]*>/gi, "")
    .replace(/<base\b[^>]*>/gi, "");
  const cspMeta = `<meta http-equiv="Content-Security-Policy" content="${LIVING_PAGE_CSP_CONTENT}">`;
  const scrollStyle = cleaned.includes('id="argo-webui-scroll"') ? "" : WEBUI_IFRAME_SCROLLBAR_STYLE;
  const rawEc =
    assetsArg && typeof assetsArg.echartsScript === "string"
      ? assetsArg.echartsScript
      : typeof echartsRaw === "string"
        ? echartsRaw
        : "";
  const needsEcharts =
    !cleaned.includes("ArgoCanvasStage") || /\becharts\b|Argo\.chart/i.test(cleaned);
  const echartsTag =
    needsEcharts && rawEc && !cleaned.includes('id="argo-echarts"')
      ? `<script id="argo-echarts">${escapeInlineScript(rawEc)}</script>`
      : "";
  const resolvedGeo =
    assetsArg && assetsArg.worldGeo !== undefined
      ? assetsArg.worldGeo
      : typeof worldGeoJson !== "undefined"
        ? worldGeoJson
        : { type: "FeatureCollection", features: [] };
  const runtimeTag = cleaned.includes('id="argo-runtime"')
    ? ""
    : buildArgoRuntimeScript(resolvedGeo, resolvedTheme);
  const injected = `${cspMeta}${scrollStyle}${echartsTag}${runtimeTag}`;
  const headAtStartRe = /^(\s*(?:<!doctype\b[^>]*>\s*)?(?:<html\b[^>]*>\s*)?)(<head(?:\s[^>]*)?>)/i;
  const htmlAtStartRe = /^(\s*(?:<!doctype\b[^>]*>\s*)?)(<html(?:\s[^>]*)?>)/i;
  let out: string;
  if (headAtStartRe.test(cleaned)) {
    out = cleaned.replace(headAtStartRe, (_m, lead: string, headTag: string) => `${lead}${headTag}${injected}`);
  } else if (htmlAtStartRe.test(cleaned)) {
    out = cleaned.replace(htmlAtStartRe, (_m, lead: string, htmlTag: string) => `${lead}${htmlTag}<head>${injected}</head>`);
  } else {
    out = `<!DOCTYPE html><html data-theme="${resolvedTheme}"><head>${injected}</head><body>${cleaned}</body></html>`;
  }
  if (
    !/data-argo-locked-theme\s*=\s*(['"]?)true\1/i.test(out) &&
    /<html(\s[^>]*)?>/i.test(out) &&
    !/<html[^>]*\bdata-theme\s*=/i.test(out)
  ) {
    out = out.replace(/<html(\s[^>]*)?>/i, (m, attrs = "") => `<html${attrs} data-theme="${resolvedTheme}">`);
  }
  return out;
}

interface PagesViewProps {
  page: PageRecord | null;
  theme?: "light" | "dark";
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
  onPrefillChat?: (botSlug: string, prompt: string) => void;
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
  theme = "dark",
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
  onPrefillChat,
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
  const [runtimeError, setRuntimeError] = useState<{
    message: string;
    line?: number | null;
    stack?: string;
  } | null>(null);
  const [filterText, setFilterText] = useState("");
  const [copiedLink, setCopiedLink] = useState(false);
  const [composerText, setComposerText] = useState("");
  const [updatingPage, setUpdatingPage] = useState(false);
  const [lastEditNotice, setLastEditNotice] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const composerInputRef = useRef<HTMLInputElement | null>(null);
  const themeRef = useRef<"light" | "dark">(theme);
  themeRef.current = theme;
  const initialThemeRef = useRef<{ key: string; theme: "light" | "dark" }>({
    key: "",
    theme,
  });
  const pageDocKey = page ? `${page.slug}:${page.content_payload}` : "";
  if (initialThemeRef.current.key !== pageDocKey) {
    initialThemeRef.current = { key: pageDocKey, theme };
  }
  const sandboxedSrcDoc = useMemo(() => {
    if (!page || page.render_mode !== "sandboxed_html") return "";
    return prepareSandboxedPageSrcDoc(page.content_payload, initialThemeRef.current.theme);
  }, [page?.render_mode, page?.content_payload, pageDocKey]);

  useEffect(() => {
    setLastEditNotice(null);
  }, [page?.slug]);

  useEffect(() => {
    setRuntimeError(null);
  }, [page?.slug, page?.updated_at, page?.content_payload]);

  const refreshPage = useCallback(
    async (silent = false) => {
      if (!page) {
        setPageData(null);
        return;
      }
      if (!silent) setLoading(true);
      setError(null);
      try {
        const data = await api.getPageData(page.slug, { limit: 2000 });
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

  const buildPageDataPayload = useCallback(
    (targetPage: PageRecord, data: PageDataResponse | null) => ({
      type: "ARGO_PAGE_DATA",
      page: data?.page ?? targetPage,
      records: data?.records ?? [],
      rows: data?.records ?? [],
      datasets: data?.datasets ?? {},
      dataset_profiles: data?.dataset_profiles ?? {},
      collection_counts: data?.collection_counts ?? {},
      data,
      liveStatus,
      theme: themeRef.current,
    }),
    [liveStatus],
  );

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html" || !pageData) return;
    postToIframe(buildPageDataPayload(page, pageData));
    if (liveStatus) {
      postToIframe({
        type: "ARGO_LIVE_STATUS",
        liveStatus,
      });
    }
  }, [page, pageData, liveStatus, postToIframe, buildPageDataPayload]);

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html") return;
    postToIframe({
      type: "ARGO_THEME_CHANGE",
      theme,
    });
  }, [theme, page?.slug, page?.render_mode, postToIframe]);

  useEffect(() => {
    if (!page || page.render_mode !== "sandboxed_html") return;

    function handleMessage(event: MessageEvent) {
      const targetWindow = iframeRef.current?.contentWindow;
      if (!targetWindow || event.source !== targetWindow) return;
      if (!event.data || typeof event.data !== "object") return;
      const msg = event.data as Record<string, unknown>;

      if (msg.type === "ARGO_READY" && page) {
        postToIframe(buildPageDataPayload(page, pageData));
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
      } else if (msg.type === "ARGO_QUERY_SQL" && page) {
        const requestId = String(msg.requestId ?? "");
        const sql = String(msg.sql ?? "");
        const params = Array.isArray(msg.params) ? msg.params : [];
        const row_cap = typeof msg.row_cap === "number" ? msg.row_cap : 500;
        const engineRaw = String(msg.engine ?? "auto");
        const engine: "auto" | "duckdb" | "sqlite" =
          engineRaw === "duckdb" || engineRaw === "sqlite" ? engineRaw : "auto";
        void api
          .queryPageSql(page.slug, { sql, params, row_cap, engine })
          .then((result) => {
            postToIframe({
              type: "ARGO_SQL_RESULT",
              requestId,
              ...result,
              result,
            });
          })
          .catch((err) => {
            postToIframe({
              type: "ARGO_SQL_ERROR",
              requestId,
              error: err instanceof Error ? err.message : "SQL query failed",
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
      } else if (msg.type === "ARGO_PREFILL_CHAT" && page) {
        const prompt = String(msg.prompt ?? "").trim();
        const requestedBot = String(msg.botSlug ?? "").trim();
        const targetBotSlug =
          requestedBot ||
          page.owner_bot_slug ||
          ownerBot?.slug ||
          bots[0]?.slug ||
          "";
        if (prompt) {
          if (targetBotSlug && onPrefillChat) {
            onPrefillChat(targetBotSlug, prompt);
          } else {
            setComposerText(prompt);
            window.requestAnimationFrame(() => composerInputRef.current?.focus());
          }
        }
      } else if (msg.type === "ARGO_RUNTIME_ERROR") {
        const errMsg = String(msg.message ?? "Script runtime error").trim();
        if (errMsg) {
          setRuntimeError({
            message: errMsg,
            line: typeof msg.line === "number" ? msg.line : null,
            stack: typeof msg.stack === "string" ? msg.stack : undefined,
          });
        }
      }
    }

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, [
    page,
    pageData,
    liveStatus,
    buildPageDataPayload,
    postToIframe,
    onOpenBot,
    onOpenRoom,
    onOpenApprovals,
    onTriggerBot,
    onPrefillChat,
    ownerBot?.slug,
    bots,
  ]);

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

  function handleFixRuntimeErrorWithBot() {
    if (!page || !runtimeError) return;
    const targetBotSlug = activeOwner?.slug || page.owner_bot_slug || bots[0]?.slug || "";
    const lineHint = runtimeError.line ? ` (line ${runtimeError.line})` : "";
    const stackHint = runtimeError.stack ? `\nStack trace:\n${runtimeError.stack}` : "";
    const prompt = `Fix the JavaScript runtime error in Page "${page.title}" (${page.slug})${lineHint}: ${runtimeError.message}${stackHint}`;
    if (targetBotSlug && onPrefillChat) {
      onPrefillChat(targetBotSlug, prompt);
    } else {
      setComposerText(prompt);
      window.requestAnimationFrame(() => composerInputRef.current?.focus());
    }
  }

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

          <div className="flex flex-nowrap md:flex-wrap items-center gap-1.5 overflow-x-auto max-w-full pb-0.5 md:pb-0">
            {splitMode && onExpandFull && (
              <button
                type="button"
                onClick={() => onExpandFull(page.slug)}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
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
                className="hidden md:inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
                title="Dock side-by-side beside chat"
              >
                <Columns2 className="w-3.5 h-3.5" />
                <span>Dock Beside Chat</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleCopyLink}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
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
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 shrink-0"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Standalone</span>
              </a>
            ) : (
              <a
                href={`/?view=page&slug=${encodeURIComponent(page.slug)}`}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 shrink-0"
              >
                <span>Back to Argo</span>
              </a>
            )}

            {page.render_mode === "sandboxed_html" && (
              <button
                type="button"
                onClick={handleDownloadHtml}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                <span>HTML</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => void refreshPage()}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-slate-200 bg-white text-xs text-slate-700 hover:bg-slate-100 cursor-pointer shrink-0"
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

        {runtimeError && (
          <div className="mx-4 mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3.5 py-2 text-xs text-amber-900 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
              <span className="truncate font-mono">
                Page script error{runtimeError.line ? ` (line ${runtimeError.line})` : ""}:{" "}
                {runtimeError.message}
              </span>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {(onPrefillChat || !standalone) && (
                <button
                  type="button"
                  onClick={handleFixRuntimeErrorWithBot}
                  className="inline-flex items-center gap-1 rounded-lg border border-amber-300 bg-white px-2.5 py-1 text-xs font-medium text-amber-900 hover:bg-amber-100 cursor-pointer"
                >
                  <Wrench className="w-3 h-3" />
                  <span>Fix with Bot</span>
                </button>
              )}
              <button
                type="button"
                onClick={() => setRuntimeError(null)}
                className="p-1 text-amber-700 hover:text-amber-950 cursor-pointer"
                aria-label="Dismiss runtime error"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Seamless Page Canvas */}
        <div className="flex-1 min-h-0 flex flex-col overflow-hidden relative">
          {page.render_mode === "sandboxed_html" ? (
            <iframe
              ref={iframeRef}
              title={page.title}
              sandbox="allow-scripts allow-downloads"
              srcDoc={sandboxedSrcDoc}
              onLoad={() => {
                postToIframe(buildPageDataPayload(page, pageData));
                if (liveStatus) {
                  postToIframe({
                    type: "ARGO_LIVE_STATUS",
                    liveStatus,
                  });
                }
              }}
              className={`w-full flex-1 min-h-[360px] border-0 ${
                theme === "light" ? "bg-[#f8fafc]" : "bg-[#161920]"
              }`}
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
            <div className="shrink-0 px-3 md:px-4 py-2.5 md:py-3 border-t border-slate-200 bg-white space-y-2 argo-safe-bottom">
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
                  ref={composerInputRef}
                  type="text"
                  value={composerText}
                  onChange={(e) => setComposerText(e.target.value)}
                  disabled={updatingPage}
                  placeholder={
                    activeOwner
                      ? `Ask ${activeOwner.name} to refine or update "${page.title}"...`
                      : `Describe changes to "${page.title}"...`
                  }
                  className="flex-1 min-w-0 bg-transparent border-0 text-[16px] md:text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none py-1"
                />
                <button
                  type="submit"
                  disabled={updatingPage || !composerText.trim()}
                  className="w-9 h-9 md:w-7 md:h-7 rounded-full bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-white flex items-center justify-center shrink-0 cursor-pointer transition-colors"
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
