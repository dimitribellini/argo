import { useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, Loader2 } from "lucide-react";
import type { ApprovalItem, BotRecord, IntegrationAccount, StyleRule } from "../../types";
import {
  cleanEscalationNote,
  computeWordDiff,
  friendlyApprovalChannel,
  formatFriendlyTime,
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
  onApprove: (id: string) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onEditApproval: (item: ApprovalItem) => void;
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
  onReject,
  onEditApproval,
}: ApprovalsViewProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<"approve" | "reject" | null>(null);
  const [historyFilter, setHistoryFilter] = useState<"all" | "sent" | "rejected">("all");
  const [expandedHistory, setExpandedHistory] = useState<Record<string, boolean>>({});

  const botNameBySlug = new Map(bots.map((b) => [b.slug, b.name]));
  const accountNameBySlug = new Map(integrations.map((a) => [a.slug, a.display_name]));

  const visibleItems =
    tab === "history"
      ? approvals.filter((item) => {
          if (historyFilter === "sent") {
            return item.status === "executed" || item.status === "approved";
          }
          if (historyFilter === "rejected") {
            return item.status === "rejected";
          }
          return true;
        })
      : approvals;

  async function runApprove(id: string) {
    setBusyId(id);
    setBusyAction("approve");
    try {
      await onApprove(id);
    } finally {
      setBusyId(null);
      setBusyAction(null);
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
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          visibleItems.map((item) => {
            const origText = String(item.payload.text ?? "");
            const editedText = item.edited_payload?.text ? String(item.edited_payload.text) : null;
            const hasDiff = Boolean(editedText && origText && editedText !== origText);
            const bodyText = editedText ?? (origText || JSON.stringify(item.payload, null, 2));
            const isWorkspaceProposal = item.target_account_slug === "argo_workspace";
            const channelLabel = friendlyApprovalChannel(
              item.action_type,
              item.target_account_slug,
            );
            const botName = botNameBySlug.get(item.bot_slug) ?? item.bot_slug;
            const accountName = isWorkspaceProposal
              ? "Workspace"
              : (accountNameBySlug.get(item.target_account_slug) ?? item.target_account_slug);
            const note = cleanEscalationNote(item.escalation_note);
            const isBusy = busyId === item.id;

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

                {Boolean(item.payload.to || item.payload.subject || item.payload.gmail_draft_id) && (
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] text-slate-700 flex flex-wrap items-center gap-x-4 gap-y-1">
                    {Boolean(item.payload.to) && (
                      <span>
                        <strong className="text-slate-900">To:</strong> {String(item.payload.to)}
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

                <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-[13px] text-slate-900 leading-relaxed">
                  {hasDiff && editedText ? (
                    <div className="whitespace-pre-wrap">
                      {computeWordDiff(origText, editedText).map((tok, i) =>
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
                      )}
                    </div>
                  ) : (
                    <RichMarkdown text={bodyText} />
                  )}
                </div>

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
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void runApprove(item.id)}
                      className="inline-flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white px-4 py-2 rounded-xl text-xs font-medium cursor-pointer"
                    >
                      {isBusy && busyAction === "approve" && (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      )}
                      <span>
                        {isBusy && busyAction === "approve"
                          ? "Sending..."
                          : isWorkspaceProposal
                            ? "Approve & Apply"
                            : "Approve & Send"}
                      </span>
                    </button>
                    {!isWorkspaceProposal && (
                      <button
                        type="button"
                        disabled={isBusy}
                        onClick={() => onEditApproval(item)}
                        className="px-3.5 py-2 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 disabled:opacity-50 cursor-pointer"
                      >
                        Edit
                      </button>
                    )}
                  </div>
                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={() => void runReject(item.id)}
                    className="px-3.5 py-2 rounded-xl border border-rose-200 text-rose-700 text-xs font-medium hover:bg-rose-50 disabled:opacity-50 cursor-pointer"
                  >
                    {isBusy && busyAction === "reject" ? "Rejecting..." : "Reject"}
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
