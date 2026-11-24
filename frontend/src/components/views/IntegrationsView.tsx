import { useState, type FormEvent } from "react";
import type { IntegrationAccount, SsoPrincipal } from "../../types";
import { formatVisibilityLabel, visibilityBadgeClasses } from "../VisibilityPicker";

interface IntegrationsViewProps {
  principal?: SsoPrincipal | null;
  integrations: IntegrationAccount[];
  onOpenGoogleWizard: (reauthAccount?: IntegrationAccount) => void;
  onOpenTelegramWizard: () => void;
  onOpenLinkedInModal: () => void;
  onOpenWebhookModal: () => void;
  onOpenNewIntegration: (defaultProvider?: IntegrationAccount["provider"]) => void;
  onAddPublicMonitor: (channelHandle: string) => Promise<void>;
  onSyncIntegration: (slug: string) => Promise<void>;
  onTestIntegration: (slug: string) => Promise<void>;
  onSendTestMessage?: (slug: string) => Promise<void>;
  onProbeAll: () => Promise<void>;
  onDeleteIntegration: (slug: string) => Promise<void>;
}

function statusDotClass(status: string): string {
  if (status === "ok" || status === "connected") {
    return "bg-[#3b8c62]";
  }
  if (status === "degraded") {
    return "bg-[#c98a2c]";
  }
  return "bg-[#c24b4b]";
}

function statusPillLabel(status: string): string {
  if (status === "ok" || status === "connected") return "Connected";
  if (status === "degraded") return "Needs attention";
  return status;
}

function renderAccountRow(
  acc: IntegrationAccount,
  options: {
    onTest: (slug: string) => Promise<void>;
    onSendTest?: (slug: string) => Promise<void>;
    onDelete: (slug: string) => Promise<void>;
    onReauth?: (acc: IntegrationAccount) => void;
    onSync?: (slug: string) => Promise<void>;
    isMultiUser?: boolean;
    canManage?: boolean;
  },
) {
  const canEdit = options.canManage !== false;
  return (
    <div key={acc.id} className="py-3 flex items-center justify-between gap-3 text-xs">
      <div className="min-w-0 space-y-0.5">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="font-medium text-slate-900">{acc.display_name}</span>
          {options.isMultiUser && (
            <>
              <span
                className={`px-1.5 py-0.2 rounded-full border text-[10px] font-medium ${visibilityBadgeClasses(
                  acc.visibility,
                )}`}
              >
                {formatVisibilityLabel(acc.visibility, acc.allowed_groups)}
              </span>
              {acc.owner_email && (
                <span className="text-[10.5px] text-slate-400 truncate">
                  {acc.owner_email}
                </span>
              )}
            </>
          )}
        </div>
        <div className="text-[11px] text-slate-500 truncate capitalize">
          {acc.account_identifier || acc.provider}
        </div>
        {acc.last_error && (
          <div className="text-[11px] text-rose-600 truncate">
            Error: {acc.last_error}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-700">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusDotClass(acc.status)}`} />
          <span>{statusPillLabel(acc.status)}</span>
        </span>
        {options.onSync && acc.scopes.includes("public_preview") && (
          <button
            type="button"
            onClick={() => void options.onSync!(acc.slug)}
            className="px-2 py-1 rounded border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            Sync Preview
          </button>
        )}
        {options.onReauth && canEdit && (
          <button
            type="button"
            onClick={() => options.onReauth!(acc)}
            className="px-2 py-1 rounded border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            Re-authorize
          </button>
        )}
        <button
          type="button"
          onClick={() => void options.onTest(acc.slug)}
          className="px-2 py-1 rounded border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-50 cursor-pointer"
        >
          Verify
        </button>
        {options.onSendTest &&
          acc.provider === "telegram" &&
          !acc.scopes.includes("public_preview") && (
            <button
              type="button"
              onClick={() => void options.onSendTest!(acc.slug)}
              className="px-2 py-1 rounded border border-slate-200 bg-white text-[11px] text-slate-700 hover:bg-slate-50 cursor-pointer"
            >
              Send Test
            </button>
          )}
        {canEdit && (
          <button
            type="button"
            onClick={() => void options.onDelete(acc.slug)}
            className="text-[11px] text-rose-600 hover:underline cursor-pointer"
          >
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

export function IntegrationsView({
  principal = null,
  integrations,
  onOpenGoogleWizard,
  onOpenTelegramWizard,
  onOpenLinkedInModal,
  onOpenWebhookModal,
  onOpenNewIntegration,
  onAddPublicMonitor,
  onSyncIntegration,
  onTestIntegration,
  onSendTestMessage,
  onProbeAll,
  onDeleteIntegration,
}: IntegrationsViewProps) {
  const [publicHandle, setPublicHandle] = useState("");
  const [addingPublic, setAddingPublic] = useState(false);

  const isMultiUser = Boolean(principal?.multi_user);
  const isAdmin = Boolean(principal?.is_admin);
  const callerEmail = (principal?.email || "").toLowerCase();
  const canManageAcc = (owner?: string) =>
    !isMultiUser || isAdmin || !owner || owner.toLowerCase() === callerEmail;

  const googleAccounts = integrations.filter((item) => item.provider === "google");
  const telegramAccounts = integrations.filter((item) => item.provider === "telegram");
  const mcpServers = integrations.filter((item) => item.provider === "mcp");
  const socialAndHooks = integrations.filter(
    (item) =>
      item.provider !== "google" && item.provider !== "telegram" && item.provider !== "mcp",
  );

  async function submitPublicMonitor(e: FormEvent) {
    e.preventDefault();
    const cleaned = publicHandle.trim();
    if (!cleaned || addingPublic) return;
    setAddingPublic(true);
    try {
      await onAddPublicMonitor(cleaned);
      setPublicHandle("");
    } finally {
      setAddingPublic(false);
    }
  }

  return (
    <div className="h-full overflow-y-auto custom-scroll p-5">
      <div className="max-w-4xl mx-auto space-y-5">
        {/* Top Bar */}
        <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-xs flex items-center justify-between flex-wrap gap-2">
          <div>
            <h2 className="text-xs font-semibold text-slate-900">
              Connected Accounts &amp; Channels
            </h2>
            <p className="text-[11px] text-slate-500">
              Your credentials are encrypted at rest; AI models are configured separately in Models &amp; Usage
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void onProbeAll()}
              className="border border-slate-200 bg-white text-slate-900 px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-50"
            >
              Check All Connections
            </button>
            <button
              type="button"
              onClick={() => onOpenNewIntegration()}
              className="border border-slate-200 bg-white text-slate-700 px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-50"
            >
              + Custom / MCP
            </button>
          </div>
        </div>

        {/* Google Multi-Account OAuth */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">
                Gmail &amp; Google Workspace
              </h3>
              <p className="text-[11px] text-slate-500">
                Connect separate Personal or Business Google accounts and assign them per bot
              </p>
            </div>
            <button
              type="button"
              onClick={() => onOpenGoogleWizard()}
              className="bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
            >
              + Connect Google Account
            </button>
          </div>

          {googleAccounts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 p-4 text-center text-xs text-slate-500">
              No Google accounts connected yet. Add Personal or Business Gmail accounts to let selected bots search, draft, or triage email.
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {googleAccounts.map((acc) =>
                renderAccountRow(acc, {
                  onTest: onTestIntegration,
                  onDelete: onDeleteIntegration,
                  onReauth: (item) => onOpenGoogleWizard(item),
                  isMultiUser,
                  canManage: canManageAcc(acc.owner_email),
                }),
              )}
            </div>
          )}
        </div>

        {/* Telegram Bot API + Public Preview */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">
                Telegram Bots &amp; Public Channels
              </h3>
              <p className="text-[11px] text-slate-500">
                Receive mobile approval cards, ask status questions, and monitor public channels
              </p>
            </div>
            <button
              type="button"
              onClick={onOpenTelegramWizard}
              className="bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
            >
              + Connect Telegram Bot
            </button>
          </div>

          {telegramAccounts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 p-4 text-center text-xs text-slate-500">
              No Telegram bots or channel monitors added yet.
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {telegramAccounts.map((acc) =>
                renderAccountRow(acc, {
                  onTest: onTestIntegration,
                  onSendTest: onSendTestMessage,
                  onDelete: onDeleteIntegration,
                  onSync: onSyncIntegration,
                  isMultiUser,
                  canManage: canManageAcc(acc.owner_email),
                }),
              )}
            </div>
          )}

          <form onSubmit={submitPublicMonitor} className="flex items-center gap-2 pt-1">
            <input
              type="text"
              value={publicHandle}
              onChange={(e) => setPublicHandle(e.target.value)}
              placeholder="Watch a public channel (e.g. @cloud_releases or https://t.me/s/cloud_releases)..."
              className="flex-1 rounded-xl border border-slate-200 px-3 py-1.5 text-xs bg-slate-50"
            />
            <button
              type="submit"
              disabled={addingPublic}
              className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white text-xs font-medium text-slate-900 hover:bg-slate-50 cursor-pointer disabled:opacity-50"
            >
              {addingPublic ? "Syncing..." : "+ Watch Channel"}
            </button>
          </form>
        </div>

        {/* LinkedIn & Inbound Webhooks */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">
                LinkedIn &amp; Webhooks
              </h3>
              <p className="text-[11px] text-slate-500">
                Draft and publish LinkedIn posts or trigger bots from external webhook events
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onOpenLinkedInModal}
                className="border border-slate-200 bg-white text-slate-900 px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-50"
              >
                + Connect LinkedIn
              </button>
              <button
                type="button"
                onClick={onOpenWebhookModal}
                className="bg-slate-900 text-white px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-800"
              >
                + Add Webhook
              </button>
            </div>
          </div>

          {socialAndHooks.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-slate-500">
              No LinkedIn accounts or inbound HMAC webhooks configured yet.
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {socialAndHooks.map((acc) =>
                renderAccountRow(acc, {
                  onTest: onTestIntegration,
                  onDelete: onDeleteIntegration,
                  isMultiUser,
                  canManage: canManageAcc(acc.owner_email),
                }),
              )}
            </div>
          )}
        </div>

        {/* Dynamic MCP Tool Servers */}
        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-xs font-semibold text-slate-900">
                MCP Tool Servers
              </h3>
              <p className="text-[11px] text-slate-500">
                Connect remote Streamable HTTP JSON-RPC 2.0 MCP endpoints; Verify discovers live tools automatically
              </p>
            </div>
            <button
              type="button"
              onClick={() => onOpenNewIntegration("mcp")}
              className="border border-slate-200 bg-white text-slate-900 px-3 py-1.5 rounded-xl text-xs font-medium cursor-pointer hover:bg-slate-50"
            >
              + Add MCP Server
            </button>
          </div>

          {mcpServers.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-200 p-4 text-center text-xs text-slate-500">
              No external MCP servers configured yet. Click + Add MCP Server and click Verify to discover tools dynamically.
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {mcpServers.map((acc) =>
                renderAccountRow(acc, {
                  onTest: onTestIntegration,
                  onDelete: onDeleteIntegration,
                  isMultiUser,
                  canManage: canManageAcc(acc.owner_email),
                }),
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
