import { useState } from "react";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  Loader2,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import type { ApprovalItem, BotRecord, IntegrationAccount, StyleRule } from "../../types";
import {
  cleanEscalationNote,
  computeWordDiff,
  extractApprovalHost,
  extractSuggestedTrustPrefixes,
  formatFriendlyTime,
  formatShellCommandForDisplay,
  friendlyApprovalChannel,
  partitionSSHApprovalBatches,
} from "../../utils/format";
import { RichMarkdown } from "../RichMarkdown";

interface ApprovalsViewProps {
  tab: "pending" | "history";
  onTabChange: (tab: "pending" | "history") => void;
  pendingCount: number;
  approvals: ApprovalItem[];
  bots?: BotRecord[];
  integrations?: IntegrationAccount[];
  styleRules?: StyleRule[];
  onApprove: (id: string, opts?: { trust_command?: boolean }) => Promise<void> | void;
  onBatchResolve?: (
    ids: string[],
    action: "approve" | "reject",
    opts?: { trust_command?: boolean },
  ) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onEditApproval: (item: ApprovalItem) => void;
  onOpenBotTerminal?: (botSlug: string) => void;
  onAddStyleRule?: (ruleText: string) => Promise<void>;
  onDeleteStyleRule?: (id: string) => Promise<void>;
}

function outcomeBadge(status: ApprovalItem["status"]): { label: string; cls: string } {
  switch (status) {
    case "executed":
      return { label: "Sent", cls: "border-emerald-200 bg-emerald-50 text-emerald-700" };
    case "approved":
      return { label: "Approved", cls: "border-emerald-200 bg-emerald-50 text-emerald-700" };
    case "superseded":
      return { label: "Edited", cls: "border-amber-200 bg-amber-50 text-amber-800" };
    case "rejected":
      return { label: "Rejected", cls: "border-slate-200 bg-slate-100 text-slate-600" };
    default:
      return { label: "Waiting", cls: "border-amber-200 bg-amber-50 text-amber-800" };
  }
}

export function ApprovalsView({
  tab,
  onTabChange,
  pendingCount,
  approvals,
  bots = [],
  integrations = [],
  onApprove,
  onBatchResolve,
  onReject,
  onEditApproval,
  onOpenBotTerminal,
}: ApprovalsViewProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"approve" | "reject" | null>(null);
  const [batchBusy, setBatchBusy] = useState<boolean>(false);
  const [historyFilter, setHistoryFilter] = useState<"all" | "sent" | "rejected">("all");
  const [expandedHistory, setExpandedHistory] = useState<Record<string, boolean>>({});
  const [expandedBatchKeys, setExpandedBatchKeys] = useState<Record<string, boolean>>({});
  const [copiedApprovalKey, setCopiedApprovalKey] = useState<string | null>(null);

  function copyApprovalCommand(copyKey: string, commandText: string) {
    if (!commandText) return;
    void navigator.clipboard?.writeText(commandText);
    setCopiedApprovalKey(copyKey);
    window.setTimeout(() => {
      setCopiedApprovalKey((prev) => (prev === copyKey ? null : prev));
    }, 1600);
  }

  const botNameBySlug = new Map(bots.map((b) => [b.slug, b.name]));
  const accountNameBySlug = new Map(integrations.map((a) => [a.slug, a.display_name]));

  const visibleItems =
    tab === "history"
      ? approvals
          .filter((item) => {
            if (item.status === "pending") return false;
            if (historyFilter === "sent") {
              return item.status === "executed" || item.status === "approved";
            }
            if (historyFilter === "rejected") {
              return item.status === "rejected";
            }
            return true;
          })
          .sort((a, b) =>
            String(b.resolved_at || b.created_at || "").localeCompare(
              String(a.resolved_at || a.created_at || ""),
            ),
          )
      : approvals.filter((item) => item.status === "pending");

  async function runApprove(id: string, opts?: { trust_command?: boolean }) {
    setBusyId(id);
    setBusyAction("approve");
    try {
      await onApprove(id, opts);
    } finally {
      setBusyId(null);
      setBusyAction(null);
    }
  }

  async function runBatch(
    action: "approve" | "reject",
    opts?: { trust_command?: boolean },
    targetIds?: string[],
  ) {
    const ids = targetIds ?? visibleItems.map((it) => it.id);
    if (!onBatchResolve || ids.length === 0) return;
    setBatchBusy(true);
    try {
      await onBatchResolve(ids, action, opts);
    } finally {
      setBatchBusy(false);
    }
  }

  async function runReject(id: string) {
    setBusyId(id);
    setBusyAction("reject");
    try {
      await onReject(id);
    } finally {
      setBusyId(null);
      setBusyAction(null);
    }
  }

  return (
    <div className="h-full overflow-y-auto custom-scroll p-5">
      <div className="max-w-3xl mx-auto space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onTabChange("pending")}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-medium border cursor-pointer ${
                tab === "pending"
                  ? "bg-slate-900 text-white border-transparent"
                  : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50"
              }`}
            >
              Waiting for Review ({pendingCount})
            </button>
            <button
              type="button"
              onClick={() => onTabChange("history")}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-medium border cursor-pointer ${
                tab === "history"
                  ? "bg-slate-900 text-white border-transparent"
                  : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50"
              }`}
            >
              History
            </button>
          </div>

          {tab === "history" && (
            <div className="flex items-center gap-1 p-1 rounded-xl border border-slate-200 bg-white text-[11px]">
              {(
                [
                  ["all", "All"],
                  ["sent", "Sent"],
                  ["rejected", "Rejected"],
                ] as const
              ).map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setHistoryFilter(key)}
                  className={`px-2.5 py-1 rounded-lg font-medium cursor-pointer ${
                    historyFilter === key
                      ? "bg-slate-900 text-white"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>

        {visibleItems.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-xs text-slate-500">
            {tab === "pending"
              ? "Nothing is waiting for review right now."
              : "No matching items in review history."}
          </div>
        ) : tab === "history" ? (
          <div className="rounded-2xl border border-slate-200 bg-white divide-y divide-slate-100 shadow-xs">
            {visibleItems.map((item) => {
              const expanded = Boolean(expandedHistory[item.id]);
              const badge = outcomeBadge(item.status);
              const channelLabel = friendlyApprovalChannel(
                item.action_type,
                item.target_account_slug,
              );
              const botName = botNameBySlug.get(item.bot_slug) ?? item.bot_slug;
              const accountName =
                item.target_account_slug === "argo_workspace"
                  ? "Workspace"
                  : (accountNameBySlug.get(item.target_account_slug) ?? item.target_account_slug);
              const origText = String(item.payload.text ?? "");
              const editedText = item.edited_payload?.text ? String(item.edited_payload.text) : null;
              const hasDiff = Boolean(editedText && origText && editedText !== origText);
              const snippet = (editedText ?? origText ?? item.payload.title ?? "")
                .replace(/\s+/g, " ")
                .trim()
                .slice(0, 90);

              return (
                <div key={item.id} className="p-3.5 space-y-2.5">
                  <button
                    type="button"
                    onClick={() =>
                      setExpandedHistory((prev) => ({ ...prev, [item.id]: !prev[item.id] }))
                    }
                    className="w-full flex items-center justify-between gap-3 text-left cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5 min-w-0 flex-1">
                      {expanded ? (
                        <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      )}
                      <span
                        className={`px-2 py-0.5 rounded-full border text-[10px] font-medium shrink-0 ${badge.cls}`}
                      >
                        {badge.label}
                      </span>
                      <span className="text-xs font-medium text-slate-900 shrink-0">
                        {channelLabel}
                      </span>
                      {snippet && (
                        <span className="text-xs text-slate-500 truncate">{snippet}</span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-400 shrink-0">
                      {botName} · {formatFriendlyTime(item.resolved_at || item.created_at)}
                    </span>
                  </button>

                  {expanded && (
                    <div className="pl-6 space-y-2">
                      <div className="text-[11px] text-slate-500">
                        Via {accountName} · By {item.approved_by ?? "Operator"}
                      </div>
                      {item.error_message && (
                        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] text-rose-700">
                          {item.error_message}
                        </div>
                      )}
                      <div className="rounded-xl bg-slate-50 border border-slate-200 p-3 text-xs text-slate-900 whitespace-pre-wrap leading-relaxed">
                        {hasDiff && editedText ? (
                          computeWordDiff(origText, editedText).map((tok, i) =>
                            tok.type === "same" ? (
                              <span key={i}>{tok.text}</span>
                            ) : tok.type === "add" ? (
                              <span key={i} className="bg-emerald-100 text-emerald-900 px-0.5 rounded">
                                {tok.text}
                              </span>
                            ) : (
                              <span
                                key={i}
                                className="bg-rose-100 text-rose-800 line-through px-0.5 rounded"
                              >
                                {tok.text}
                              </span>
                            ),
                          )
                        ) : (
                          editedText ?? origText ?? JSON.stringify(item.payload, null, 2)
                        )}
                      </div>
                      {item.payload.execution_result?.screen_text && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500">
                            <span>
                              Terminal output · {item.payload.execution_result.host || "host"}
                              {item.payload.execution_result.exit_code != null
                                ? ` · exit ${item.payload.execution_result.exit_code}`
                                : ""}
                            </span>
                            {(item.action_type === "ssh_exec" || item.action_type === "ssh_input") &&
                              onOpenBotTerminal && (
                                <button
                                  type="button"
                                  onClick={() => onOpenBotTerminal(item.bot_slug)}
                                  className="text-indigo-600 hover:underline font-medium cursor-pointer"
                                >
                                  View Terminal / Replay
                                </button>
                              )}
                          </div>
                          <pre className="argo-ssh-terminal rounded-xl border border-slate-800 bg-slate-900 text-slate-100 p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto custom-scroll">
                            {item.payload.execution_result.screen_text}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="space-y-4">
            {(() => {
              const { batches, singles } = partitionSSHApprovalBatches(visibleItems, {
                scopeByBot: true,
              });
              const showGlobalBatchBar =
                visibleItems.length >= 2 &&
                Boolean(onBatchResolve) &&
                (batches.length > 1 ||
                  (batches.length === 1 && singles.length > 0) ||
                  (batches.length === 0 && singles.length >= 2));
              const trustableCount = visibleItems.filter(
                (it) =>
                  it.action_type === "ssh_exec" &&
                  extractSuggestedTrustPrefixes(it).length > 0,
              ).length;

              return (
                <>
                  {showGlobalBatchBar && (
                    <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 flex items-center justify-between gap-2 flex-wrap">
                      <span className="text-xs font-medium text-amber-900">
                        {visibleItems.length} pending approvals ready
                      </span>
                      <div className="flex items-center gap-2 flex-wrap">
                        <button
                          type="button"
                          disabled={batchBusy || busyId !== null}
                          onClick={() => void runBatch("approve")}
                          className="inline-flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3.5 py-1.5 rounded-xl text-xs font-medium cursor-pointer"
                        >
                          <Check className="w-3.5 h-3.5" />
                          <span>
                            {batchBusy ? "Running..." : `Approve All (${visibleItems.length})`}
                          </span>
                        </button>
                        {trustableCount > 0 && (
                          <button
                            type="button"
                            disabled={batchBusy || busyId !== null}
                            onClick={() => void runBatch("approve", { trust_command: true })}
                            className="inline-flex items-center gap-1.5 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 px-3.5 py-1.5 rounded-xl text-xs font-medium cursor-pointer"
                          >
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>Approve All &amp; Always Allow</span>
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={batchBusy || busyId !== null}
                          onClick={() => void runBatch("reject")}
                          className="px-3.5 py-1.5 rounded-xl border border-rose-200 bg-white text-rose-700 text-xs font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                        >
                          Reject All
                        </button>
                      </div>
                    </div>
                  )}

                  {batches.map((batch) => {
                    const first = batch.items[0];
                    const botName = botNameBySlug.get(batch.botSlug) ?? batch.botSlug;
                    const accountName =
                      accountNameBySlug.get(batch.vaultSlug) ?? batch.vaultSlug;
                    const note = cleanEscalationNote(first.escalation_note);
                    const batchIds = batch.items.map((it) => it.id);
                    const isExpanded = Boolean(expandedBatchKeys[batch.key]);
                    const formattedCmd = formatShellCommandForDisplay(batch.command);
                    const copyKey = `apr-batch-${batch.key}`;
                    const isCopied = copiedApprovalKey === copyKey;
                    const visiblePrefixes = batch.trustPrefixes.slice(0, 6);
                    const extraPrefixCount = Math.max(
                      0,
                      batch.trustPrefixes.length - visiblePrefixes.length,
                    );
                    const anyTelegram = batch.items.some((it) => it.telegram_message_id != null);

                    return (
                      <div
                        key={batch.key}
                        className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs space-y-3.5"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border border-indigo-200 bg-indigo-50 text-[11px] font-semibold text-indigo-700">
                                <Terminal className="w-3 h-3" />
                                <span>SSH Batch · {batch.items.length} hosts</span>
                              </span>
                              <span className="text-sm font-semibold text-slate-900">
                                Run SSH command across {batch.items.length} hosts
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-500">
                              From <strong className="text-slate-800">{botName}</strong> · Via{" "}
                              <strong className="text-slate-800">{accountName}</strong>{" "}
                              (<code className="font-mono">@{batch.vaultSlug}</code>) ·{" "}
                              {formatFriendlyTime(first.created_at)}
                              {anyTelegram && " · Also on Telegram"}
                            </div>
                            {note && <p className="text-[11px] text-amber-800">{note}</p>}
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5 flex-wrap">
                          {batch.items.map((it) => {
                            const hostLabel = extractApprovalHost(it) || "target host";
                            return (
                              <span
                                key={it.id}
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-slate-200 bg-slate-50 text-[11px] font-mono text-slate-800"
                              >
                                <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                                <span>{hostLabel}</span>
                              </span>
                            );
                          })}
                        </div>

                        <div className="argo-code-block rounded-xl border overflow-hidden">
                          <div className="argo-code-block-bar px-3.5 py-2 border-b flex items-center justify-between gap-2 text-[11px]">
                            <span className="font-medium">Shell command</span>
                            <button
                              type="button"
                              onClick={() => copyApprovalCommand(copyKey, batch.command)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded hover:bg-slate-700 transition-colors cursor-pointer"
                            >
                              {isCopied ? (
                                <>
                                  <Check className="w-3 h-3" />
                                  <span>Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3.5 text-xs leading-relaxed font-mono whitespace-pre-wrap break-words max-h-64 overflow-y-auto custom-scroll m-0">
                            {formattedCmd}
                          </pre>
                        </div>

                        {batch.trustPrefixes.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-600">
                            <span className="font-medium text-slate-700">
                              Always Allow will trust on @{batch.vaultSlug}:
                            </span>
                            {visiblePrefixes.map((pref) => (
                              <code
                                key={pref}
                                className="px-1.5 py-0.5 rounded border border-slate-300 bg-slate-100 text-[11px] font-mono text-slate-800"
                              >
                                {pref}
                              </code>
                            ))}
                            {extraPrefixCount > 0 && (
                              <span className="text-[11px] text-slate-500">
                                +{extraPrefixCount} more
                              </span>
                            )}
                          </div>
                        )}

                        <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            {onBatchResolve && (
                              <>
                                <button
                                  type="button"
                                  disabled={batchBusy || busyId !== null}
                                  onClick={() => void runBatch("approve", undefined, batchIds)}
                                  className="inline-flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white px-4 py-2 rounded-xl text-xs font-medium cursor-pointer"
                                >
                                  <Check className="w-3.5 h-3.5" />
                                  <span>
                                    {batchBusy
                                      ? "Running..."
                                      : `Approve All (${batch.items.length})`}
                                  </span>
                                </button>
                                {batch.trustPrefixes.length > 0 && (
                                  <button
                                    type="button"
                                    disabled={batchBusy || busyId !== null}
                                    title={`Approve, run now, and always allow on @${batch.vaultSlug}: ${batch.trustPrefixes.join(", ")}`}
                                    onClick={() =>
                                      void runBatch("approve", { trust_command: true }, batchIds)
                                    }
                                    className="inline-flex items-center gap-1.5 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-60 text-slate-900 px-3.5 py-2 rounded-xl text-xs font-medium cursor-pointer"
                                  >
                                    <ShieldCheck className="w-3.5 h-3.5" />
                                    <span>Approve All &amp; Always Allow</span>
                                  </button>
                                )}
                                <button
                                  type="button"
                                  disabled={batchBusy || busyId !== null}
                                  onClick={() => void runBatch("reject", undefined, batchIds)}
                                  className="px-3.5 py-2 rounded-xl border border-rose-200 text-rose-700 text-xs font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                                >
                                  Reject All
                                </button>
                              </>
                            )}
                          </div>

                          <button
                            type="button"
                            onClick={() =>
                              setExpandedBatchKeys((prev) => ({
                                ...prev,
                                [batch.key]: !prev[batch.key],
                              }))
                            }
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-xs font-medium text-slate-700 cursor-pointer"
                          >
                            {isExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5" />
                            )}
                            <span>Per-host controls ({batch.items.length})</span>
                          </button>
                        </div>

                        {isExpanded && (
                          <div className="rounded-xl border border-slate-200 bg-slate-50 divide-y divide-slate-200">
                            {batch.items.map((it) => {
                              const hostLabel = extractApprovalHost(it) || "target host";
                              const isItemBusy = busyId === it.id || batchBusy;
                              const itTrust = extractSuggestedTrustPrefixes(it);
                              return (
                                <div
                                  key={it.id}
                                  className="px-3.5 py-2.5 flex items-center justify-between gap-2 flex-wrap"
                                >
                                  <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-slate-800">
                                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                                    <span>{hostLabel}</span>
                                  </span>
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    <button
                                      type="button"
                                      disabled={isItemBusy}
                                      onClick={() => void runApprove(it.id)}
                                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-[11px] font-medium cursor-pointer"
                                    >
                                      <Check className="w-3 h-3" />
                                      <span>Approve</span>
                                    </button>
                                    {itTrust.length > 0 && (
                                      <button
                                        type="button"
                                        disabled={isItemBusy}
                                        onClick={() =>
                                          void runApprove(it.id, { trust_command: true })
                                        }
                                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-50 text-slate-900 text-[11px] font-medium cursor-pointer"
                                      >
                                        <ShieldCheck className="w-3 h-3" />
                                        <span>Always Allow</span>
                                      </button>
                                    )}
                                    <button
                                      type="button"
                                      disabled={isItemBusy}
                                      onClick={() => onEditApproval(it)}
                                      className="px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 text-[11px] font-medium disabled:opacity-50 cursor-pointer"
                                    >
                                      Edit
                                    </button>
                                    <button
                                      type="button"
                                      disabled={isItemBusy}
                                      onClick={() => void runReject(it.id)}
                                      className="px-2.5 py-1 rounded-lg border border-rose-200 bg-white hover:bg-rose-50 text-rose-700 text-[11px] font-medium disabled:opacity-50 cursor-pointer"
                                    >
                                      Reject
                                    </button>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {singles.map((item) => {
                    const origText = String(item.payload.text ?? "");
                    const editedText = item.edited_payload?.text
                      ? String(item.edited_payload.text)
                      : null;
                    const hasDiff = Boolean(editedText && origText && editedText !== origText);
                    const bodyText = editedText ?? (origText || JSON.stringify(item.payload, null, 2));
                    const isWorkspaceProposal = item.target_account_slug === "argo_workspace";
                    const isSshAction =
                      item.action_type === "ssh_exec" || item.action_type === "ssh_input";
                    const channelLabel = friendlyApprovalChannel(
                      item.action_type,
                      item.target_account_slug,
                    );
                    const botName = botNameBySlug.get(item.bot_slug) ?? item.bot_slug;
                    const accountName = isWorkspaceProposal
                      ? "Workspace"
                      : (accountNameBySlug.get(item.target_account_slug) ??
                        item.target_account_slug);
                    const note = cleanEscalationNote(item.escalation_note);
                    const isBusy = busyId === item.id || batchBusy;
                    const suggestedTrust = extractSuggestedTrustPrefixes(item);
                    const visiblePrefixes = suggestedTrust.slice(0, 6);
                    const extraPrefixCount = Math.max(
                      0,
                      suggestedTrust.length - visiblePrefixes.length,
                    );
                    const copyKey = `apr-single-${item.id}`;
                    const isCopied = copiedApprovalKey === copyKey;

                    return (
                      <div
                        key={item.id}
                        className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs space-y-3.5"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="px-2.5 py-0.5 rounded-full border border-indigo-200 bg-indigo-50 text-[11px] font-semibold text-indigo-700">
                                {channelLabel}
                              </span>
                              {item.payload.title && (
                                <span className="text-sm font-semibold text-slate-900 truncate">
                                  {item.payload.title}
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              From <strong className="text-slate-800">{botName}</strong> · Via{" "}
                              <strong className="text-slate-800">{accountName}</strong> ·{" "}
                              {formatFriendlyTime(item.created_at)}
                              {item.telegram_message_id != null && " · Also on Telegram"}
                            </div>
                            {note && <p className="text-[11px] text-amber-800">{note}</p>}
                            {item.error_message && (
                              <p className="text-[11px] text-rose-700">
                                Delivery error: {item.error_message}
                              </p>
                            )}
                          </div>
                        </div>

                        {Boolean(
                          item.payload.to || item.payload.subject || item.payload.gmail_draft_id,
                        ) && (
                          <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] text-slate-700 flex flex-wrap items-center gap-x-4 gap-y-1">
                            {Boolean(item.payload.to) && (
                              <span>
                                <strong className="text-slate-900">To:</strong>{" "}
                                {String(item.payload.to)}
                              </span>
                            )}
                            {Boolean(item.payload.subject) && (
                              <span>
                                <strong className="text-slate-900">Subject:</strong>{" "}
                                {String(item.payload.subject)}
                              </span>
                            )}
                            {Boolean(item.payload.gmail_draft_id) && (
                              <span className="px-2 py-0.5 rounded-full border border-emerald-200 bg-emerald-50 text-emerald-700 text-[10px]">
                                Saved in Gmail Drafts
                              </span>
                            )}
                          </div>
                        )}

                        {typeof item.payload.screen_excerpt === "string" &&
                          item.payload.screen_excerpt.trim() !== "" && (
                            <pre className="argo-ssh-terminal rounded-xl border border-slate-200 p-2.5 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">
                              {item.payload.screen_excerpt}
                            </pre>
                          )}

                        {hasDiff && editedText ? (
                          <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-[13px] text-slate-900 leading-relaxed whitespace-pre-wrap">
                            {computeWordDiff(origText, editedText).map((tok, i) =>
                              tok.type === "same" ? (
                                <span key={i}>{tok.text}</span>
                              ) : tok.type === "add" ? (
                                <span
                                  key={i}
                                  className="bg-emerald-100 text-emerald-900 px-0.5 rounded"
                                >
                                  {tok.text}
                                </span>
                              ) : (
                                <span
                                  key={i}
                                  className="bg-rose-100 text-rose-800 line-through px-0.5 rounded"
                                >
                                  {tok.text}
                                </span>
                              ),
                            )}
                          </div>
                        ) : isSshAction ? (
                          (() => {
                            const sshDisplayText =
                              origText ||
                              (item.action_type === "ssh_exec" &&
                              typeof item.payload.command === "string"
                                ? item.payload.command.trim()
                                : "");
                            const sshPromptLine =
                              typeof item.payload.prompt_line === "string"
                                ? item.payload.prompt_line.trim()
                                : "";
                            return (
                              <div className="space-y-2">
                                {sshPromptLine && item.action_type === "ssh_input" && (
                                  <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-[11px] font-mono text-slate-800 break-words">
                                    Prompt: {sshPromptLine}
                                  </div>
                                )}
                                <div className="argo-code-block rounded-xl border overflow-hidden">
                                  <div className="argo-code-block-bar px-3.5 py-2 border-b flex items-center justify-between gap-2 text-[11px]">
                                    <span className="font-medium">
                                      {item.action_type === "ssh_input"
                                        ? "Terminal input"
                                        : "Shell command"}
                                    </span>
                                    {sshDisplayText && (
                                      <button
                                        type="button"
                                        onClick={() =>
                                          copyApprovalCommand(copyKey, sshDisplayText)
                                        }
                                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded hover:bg-slate-700 transition-colors cursor-pointer"
                                      >
                                        {isCopied ? (
                                          <>
                                            <Check className="w-3 h-3" />
                                            <span>Copied</span>
                                          </>
                                        ) : (
                                          <>
                                            <Copy className="w-3 h-3" />
                                            <span>Copy</span>
                                          </>
                                        )}
                                      </button>
                                    )}
                                  </div>
                                  <pre className="p-3.5 text-xs leading-relaxed font-mono whitespace-pre-wrap break-words max-h-64 overflow-y-auto custom-scroll m-0">
                                    {sshDisplayText
                                      ? formatShellCommandForDisplay(sshDisplayText)
                                      : "(Empty input / Enter)"}
                                  </pre>
                                </div>
                              </div>
                            );
                          })()
                        ) : (
                          <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-[13px] text-slate-900 leading-relaxed space-y-2.5">
                            <RichMarkdown text={bodyText} />
                          </div>
                        )}

                        {item.action_type === "ssh_exec" && suggestedTrust.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-600">
                            <span className="font-medium text-slate-700">
                              Always Allow will trust on @{item.target_account_slug}:
                            </span>
                            {visiblePrefixes.map((pref) => (
                              <code
                                key={pref}
                                className="px-1.5 py-0.5 rounded border border-slate-300 bg-slate-100 text-[11px] font-mono text-slate-800"
                              >
                                {pref}
                              </code>
                            ))}
                            {extraPrefixCount > 0 && (
                              <span className="text-[11px] text-slate-500">
                                +{extraPrefixCount} more
                              </span>
                            )}
                          </div>
                        )}

                        {(item.source_excerpt || item.source_url) && (
                          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-[11px] text-emerald-900 flex items-center justify-between gap-2 flex-wrap">
                            <span className="min-w-0">
                              {item.source_excerpt ? (
                                <>
                                  <span className="font-semibold">Source quote: </span>
                                  {item.source_excerpt}
                                </>
                              ) : (
                                <span className="font-semibold">Source link attached</span>
                              )}
                            </span>
                            {item.source_url && (
                              <a
                                href={item.source_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-emerald-700 font-medium hover:underline shrink-0"
                              >
                                <span>Open source</span>
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        )}

                        <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
                          <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => void runApprove(item.id)}
                              className="inline-flex items-center justify-center gap-1.5 flex-1 md:flex-none min-h-[42px] md:min-h-0 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white px-4 py-2 rounded-xl text-xs font-medium cursor-pointer"
                            >
                              {isBusy && busyAction === "approve" && (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              )}
                              <span>
                                {isBusy && busyAction === "approve"
                                  ? "Running..."
                                  : isWorkspaceProposal
                                    ? "Approve & Apply"
                                    : isSshAction
                                      ? "Approve & Run"
                                      : "Approve & Send"}
                              </span>
                            </button>
                            {item.action_type === "ssh_exec" && suggestedTrust.length > 0 && (
                              <button
                                type="button"
                                disabled={isBusy}
                                title={`Approve, run now, and always allow on @${item.target_account_slug}: ${suggestedTrust.join(", ")}`}
                                onClick={() => void runApprove(item.id, { trust_command: true })}
                                className="inline-flex items-center justify-center gap-1.5 min-h-[42px] md:min-h-0 border border-slate-300 bg-slate-100 hover:bg-slate-200 disabled:opacity-60 text-slate-900 px-3.5 py-2 rounded-xl text-xs font-medium cursor-pointer"
                              >
                                <ShieldCheck className="w-3.5 h-3.5" />
                                <span>Always Allow on @{item.target_account_slug}</span>
                              </button>
                            )}
                            {!isWorkspaceProposal && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => onEditApproval(item)}
                                className="min-h-[42px] md:min-h-0 px-3.5 py-2 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                              >
                                Edit
                              </button>
                            )}
                            {isSshAction && onOpenBotTerminal && (
                              <button
                                type="button"
                                onClick={() => onOpenBotTerminal(item.bot_slug)}
                                className="min-h-[42px] md:min-h-0 px-3.5 py-2 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 cursor-pointer"
                              >
                                Take Over
                              </button>
                            )}
                          </div>
                          <button
                            type="button"
                            disabled={isBusy}
                            onClick={() => void runReject(item.id)}
                            className="w-full md:w-auto min-h-[42px] md:min-h-0 px-3.5 py-2 rounded-xl border border-rose-200 text-rose-700 text-xs font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                          >
                            {isBusy && busyAction === "reject" ? "Rejecting..." : "Reject"}
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </>
              );
            })()}
          </div>
        )}
      </div>
    </div>
  );
}
