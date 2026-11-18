import { useState, type FormEvent } from "react";
import {
  Activity,
  BookOpen,
  Cpu,
  Lock,
  Monitor,
  Pencil,
  Plug,
  Plus,
  Sparkles,
  Sun,
  Moon,
  Trash2,
  X,
} from "lucide-react";
import type {
  BotRecord,
  DebugOverviewResponse,
  DesktopBootProgress,
  DesktopInfo,
  DesktopLaunchQueueItem,
  HostTelemetry,
  IntegrationAccount,
  ModelProvider,
  ModelsResponse,
  SettingsTab,
  SkillRecord,
  StyleRule,
  VaultSecretRecord,
  WorkspaceSummary,
} from "../types";
import { DebugModal } from "./Modals";
import { BotAvatar } from "./BotAvatar";
import { vaultSecretIconComponent } from "./MentionText";
import { DesktopsView } from "./views/DesktopsView";
import { IntegrationsView } from "./views/IntegrationsView";
import { ModelsView } from "./views/ModelsView";

function formatVaultTypeLabel(secretType: string): string {
  switch ((secretType ?? "").toLowerCase()) {
    case "ssh":
      return "SSH Server";
    case "login":
      return "Web Login";
    case "api_token":
      return "API Token";
    default:
      return "Custom Secret";
  }
}

interface SettingsModalProps {
  open: boolean;
  activeTab: SettingsTab;
  onTabChange: (tab: SettingsTab) => void;
  onClose: () => void;
  theme: "light" | "dark";
  onToggleTheme: (next: "light" | "dark") => void;
  summary: WorkspaceSummary | null;
  bots: BotRecord[];

  // Integrations
  integrations: IntegrationAccount[];
  onOpenGoogleWizard: (reauthAccount?: IntegrationAccount) => void;
  onOpenTelegramWizard: () => void;
  onOpenLinkedInModal: () => void;
  onOpenWebhookModal: () => void;
  onOpenNewIntegration: () => void;
  onAddPublicMonitor: (channelHandle: string) => Promise<void>;
  onSyncIntegration: (slug: string) => Promise<void>;
  onTestIntegration: (slug: string) => Promise<void>;
  onSendTestMessage?: (slug: string) => Promise<void>;
  onProbeAll: () => Promise<void>;
  onDeleteIntegration: (slug: string) => Promise<void>;

  // Models & Usage
  modelsData: ModelsResponse | null;
  onOpenNewModel: (initial?: ModelProvider) => void;
  onSetDefaultModel: (slug: string) => void;
  onTestModel: (slug: string) => void;
  onDeleteModel: (slug: string) => void;
  onPauseBot?: (botSlug: string) => Promise<void>;
  onSwitchBotToFlash?: (botSlug: string) => Promise<void>;

  // Desktops
  desktopHost: HostTelemetry | null;
  desktops: DesktopInfo[];
  queuedLaunches: DesktopLaunchQueueItem[];
  togglingDesktops?: Record<string, boolean>;
  desktopBootBySlug?: Record<string, DesktopBootProgress>;
  onToggleDesktop: (slug: string) => void;
  onStopAllDesktops: () => Promise<void>;
  onOpenSelkies: (desktop: DesktopInfo) => void;
  onDeleteBot?: (slug: string) => Promise<void>;

  // Writing & Memory + Skills
  styleRules: StyleRule[];
  onAddStyleRule: (ruleText: string, scopeSlug?: string) => Promise<void>;
  onDeleteStyleRule: (id: string) => Promise<void>;
  onImportMemory: (rawText: string, scopeSlug: string) => Promise<number>;
  skills: SkillRecord[];
  onSaveSkill: (payload: {
    name: string;
    description?: string;
    instructions: string;
    scope_slug?: string;
  }) => Promise<void>;
  onDeleteSkill: (id: string) => Promise<void>;

  // Diagnostics
  debugBotSlug?: string;
  onLoadDebugOverview: (params?: {
    bot_slug?: string;
    level?: string;
    contains?: string;
    limit?: number;
  }) => Promise<DebugOverviewResponse>;
  onClearDebug: () => Promise<unknown>;

  // Encrypted Secrets Vault (Zero-AI Exposure)
  vaultSecrets: VaultSecretRecord[];
  onCreateVaultSecret: (payload: {
    name: string;
    slug?: string;
    secret_type: "ssh" | "login" | "api_token" | "custom";
    host?: string;
    port?: string;
    url?: string;
    secrets: Record<string, string>;
    allowed_bots?: string[];
  }) => Promise<void>;
  onUpdateVaultSecret: (
    slug: string,
    payload: {
      name?: string;
      secret_type?: "ssh" | "login" | "api_token" | "custom";
      host?: string;
      port?: string;
      url?: string;
      secrets?: Record<string, string>;
      allowed_bots?: string[];
    },
  ) => Promise<void>;
  onDeleteVaultSecret: (slug: string) => Promise<void>;
}

const TABS: Array<{ id: SettingsTab; label: string; icon: typeof Plug }> = [
  { id: "integrations", label: "Integrations", icon: Plug },
  { id: "vault", label: "Secrets Vault", icon: Lock },
  { id: "models", label: "Models & Usage", icon: Cpu },
  { id: "desktops", label: "Desktops", icon: Monitor },
  { id: "memory", label: "Writing & Memory", icon: BookOpen },
  { id: "diagnostics", label: "Diagnostics", icon: Activity },
];

export function SettingsModal({
  open,
  activeTab,
  onTabChange,
  onClose,
  theme,
  onToggleTheme,
  summary,
  bots,
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
  modelsData,
  onOpenNewModel,
  onSetDefaultModel,
  onTestModel,
  onDeleteModel,
  onPauseBot,
  onSwitchBotToFlash,
  desktopHost,
  desktops,
  queuedLaunches,
  togglingDesktops = {},
  desktopBootBySlug = {},
  onToggleDesktop,
  onStopAllDesktops,
  onOpenSelkies,
  onDeleteBot,
  styleRules,
  onAddStyleRule,
  onDeleteStyleRule,
  onImportMemory,
  skills,
  onSaveSkill,
  onDeleteSkill,
  debugBotSlug,
  onLoadDebugOverview,
  onClearDebug,
  vaultSecrets,
  onCreateVaultSecret,
  onUpdateVaultSecret,
  onDeleteVaultSecret,
}: SettingsModalProps) {
  const [newRuleText, setNewRuleText] = useState("");
  const [newRuleScope, setNewRuleScope] = useState("*");
  const [importText, setImportText] = useState("");
  const [importScope, setImportScope] = useState("*");
  const [importing, setImporting] = useState(false);

  const [skillName, setSkillName] = useState("");
  const [skillDesc, setSkillDesc] = useState("");
  const [skillInstr, setSkillInstr] = useState("");
  const [skillScope, setSkillScope] = useState("*");
  const [savingSkill, setSavingSkill] = useState(false);

  const [vaultName, setVaultName] = useState("");
  const [vaultType, setVaultType] = useState<"ssh" | "login" | "api_token" | "custom">("ssh");
  const [vaultHost, setVaultHost] = useState("");
  const [vaultPort, setVaultPort] = useState("22");
  const [vaultUrl, setVaultUrl] = useState("");
  const [vaultUsername, setVaultUsername] = useState("");
  const [vaultPassword, setVaultPassword] = useState("");
  const [vaultPrivateKey, setVaultPrivateKey] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [vaultCustomKey, setVaultCustomKey] = useState("value");
  const [vaultCustomValue, setVaultCustomValue] = useState("");
  const [vaultAllowedBots, setVaultAllowedBots] = useState<string[]>([]);
  const [vaultSaving, setVaultSaving] = useState(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [vaultFormOpen, setVaultFormOpen] = useState(false);
  const [editingVaultSlug, setEditingVaultSlug] = useState<string | null>(null);

  if (!open) return null;

  function resetVaultForm() {
    setVaultName("");
    setVaultType("ssh");
    setVaultHost("");
    setVaultPort("22");
    setVaultUrl("");
    setVaultUsername("");
    setVaultPassword("");
    setVaultPrivateKey("");
    setVaultToken("");
    setVaultCustomKey("value");
    setVaultCustomValue("");
    setVaultAllowedBots([]);
    setVaultError(null);
    setEditingVaultSlug(null);
  }

  function openCreateVaultForm() {
    resetVaultForm();
    setVaultFormOpen(true);
  }

  function openEditVaultForm(sec: VaultSecretRecord) {
    setVaultName(sec.name);
    setVaultType(
      sec.secret_type === "login" || sec.secret_type === "api_token" || sec.secret_type === "custom"
        ? sec.secret_type
        : "ssh",
    );
    setVaultHost(sec.host || "");
    setVaultPort(sec.port || "22");
    setVaultUrl(sec.url || "");
    setVaultUsername("");
    setVaultPassword("");
    setVaultPrivateKey("");
    setVaultToken("");
    setVaultCustomKey("value");
    setVaultCustomValue("");
    setVaultAllowedBots([...sec.allowed_bots]);
    setVaultError(null);
    setEditingVaultSlug(sec.slug);
    setVaultFormOpen(true);
  }

  function toggleVaultBotAccess(slug: string) {
    if (slug === "*") {
      setVaultAllowedBots((prev) => (prev.includes("*") ? [] : ["*"]));
      return;
    }
    setVaultAllowedBots((prev) => {
      const cleaned = prev.filter((item) => item !== "*");
      return cleaned.includes(slug)
        ? cleaned.filter((item) => item !== slug)
        : [...cleaned, slug];
    });
  }

  async function handleSaveVaultSecret(e: FormEvent) {
    e.preventDefault();
    if (!vaultName.trim() || vaultSaving) return;
    const secrets: Record<string, string> = {};
    if (vaultType === "ssh") {
      if (vaultUsername.trim()) secrets.username = vaultUsername.trim();
      if (vaultPassword) secrets.password = vaultPassword;
      if (vaultPrivateKey.trim()) secrets.private_key = vaultPrivateKey.trim();
    } else if (vaultType === "login") {
      if (vaultUsername.trim()) secrets.username = vaultUsername.trim();
      if (vaultPassword) secrets.password = vaultPassword;
    } else if (vaultType === "api_token") {
      if (vaultToken.trim()) secrets.token = vaultToken.trim();
    } else {
      const key = vaultCustomKey.trim() || "value";
      if (vaultCustomValue) secrets[key] = vaultCustomValue;
    }
    if (!editingVaultSlug && Object.keys(secrets).length === 0) {
      setVaultError("Provide at least one credential value before saving.");
      return;
    }
    setVaultSaving(true);
    setVaultError(null);
    try {
      if (editingVaultSlug) {
        await onUpdateVaultSecret(editingVaultSlug, {
          name: vaultName.trim(),
          secret_type: vaultType,
          host: vaultType === "ssh" ? vaultHost.trim() : "",
          port: vaultType === "ssh" ? vaultPort.trim() || "22" : "",
          url:
            vaultType === "login" || vaultType === "api_token"
              ? vaultUrl.trim()
              : "",
          ...(Object.keys(secrets).length > 0 ? { secrets } : {}),
          allowed_bots: vaultAllowedBots,
        });
      } else {
        await onCreateVaultSecret({
          name: vaultName.trim(),
          secret_type: vaultType,
          host: vaultType === "ssh" ? vaultHost.trim() || undefined : undefined,
          port: vaultType === "ssh" ? vaultPort.trim() || "22" : undefined,
          url:
            vaultType === "login" || vaultType === "api_token"
              ? vaultUrl.trim() || undefined
              : undefined,
          secrets,
          allowed_bots: vaultAllowedBots,
        });
      }
      resetVaultForm();
      setVaultFormOpen(false);
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : "Failed to save secret.");
    } finally {
      setVaultSaving(false);
    }
  }

  async function handleAddRule(e: FormEvent) {
    e.preventDefault();
    if (!newRuleText.trim()) return;
    await onAddStyleRule(newRuleText.trim(), newRuleScope);
    setNewRuleText("");
  }

  async function handleImportMemory(e: FormEvent) {
    e.preventDefault();
    if (!importText.trim() || importing) return;
    setImporting(true);
    try {
      await onImportMemory(importText.trim(), importScope);
      setImportText("");
    } finally {
      setImporting(false);
    }
  }

  async function handleCreateSkill(e: FormEvent) {
    e.preventDefault();
    if (!skillName.trim() || !skillInstr.trim() || savingSkill) return;
    setSavingSkill(true);
    try {
      await onSaveSkill({
        name: skillName.trim(),
        description: skillDesc.trim(),
        instructions: skillInstr.trim(),
        scope_slug: skillScope,
      });
      setSkillName("");
      setSkillDesc("");
      setSkillInstr("");
    } finally {
      setSavingSkill(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 argo-modal-backdrop flex items-center justify-center p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Settings"
        className="w-full max-w-5xl h-[86vh] rounded-2xl argo-modal-panel overflow-hidden flex flex-col"
      >
        <div className="h-14 px-5 border-b border-slate-200 argo-modal-header flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">Settings</h2>
            <p className="text-[11px] text-slate-500">
              Manage connected apps, AI models, virtual desktops, saved memory, and system health
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            Close
          </button>
        </div>

        <div className="flex-1 min-h-0 flex flex-col sm:flex-row">
          <nav className="sm:w-52 shrink-0 border-b sm:border-b-0 sm:border-r border-slate-200 bg-slate-50 p-3 flex sm:flex-col gap-1 overflow-x-auto">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => onTabChange(tab.id)}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium transition cursor-pointer shrink-0 text-left ${
                    active
                      ? "bg-white text-slate-900 border border-slate-200 shadow-xs font-semibold"
                      : "text-slate-600 hover:bg-slate-100 border border-transparent"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="flex-1 min-w-0 min-h-0 flex flex-col bg-slate-50">
            {activeTab === "integrations" && (
              <IntegrationsView
                integrations={integrations}
                onOpenGoogleWizard={onOpenGoogleWizard}
                onOpenTelegramWizard={onOpenTelegramWizard}
                onOpenLinkedInModal={onOpenLinkedInModal}
                onOpenWebhookModal={onOpenWebhookModal}
                onOpenNewIntegration={onOpenNewIntegration}
                onAddPublicMonitor={onAddPublicMonitor}
                onSyncIntegration={onSyncIntegration}
                onTestIntegration={onTestIntegration}
                onSendTestMessage={onSendTestMessage}
                onProbeAll={onProbeAll}
                onDeleteIntegration={onDeleteIntegration}
              />
            )}

            {activeTab === "vault" && (
              <div className="h-full overflow-y-auto custom-scroll p-5">
                <div className="max-w-4xl mx-auto space-y-4">
                  <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
                    <div className="min-w-0">
                      <h3 className="text-xs font-semibold text-slate-900">
                        Secrets Vault ({vaultSecrets.length})
                      </h3>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Encrypted credentials injected at runtime without exposing secret values to AI models.
                      </p>
                    </div>
                    {(!vaultFormOpen || editingVaultSlug) && (
                      <button
                        type="button"
                        onClick={openCreateVaultForm}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer shrink-0"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>New Secret</span>
                      </button>
                    )}
                  </div>

                  {vaultSecrets.length > 0 && (
                    <div className="rounded-xl border border-slate-200 bg-white overflow-hidden divide-y divide-slate-100">
                      {vaultSecrets.map((sec) => {
                        const allBotsAllowed = sec.allowed_bots.includes("*");
                        const SecretIcon = vaultSecretIconComponent(sec.secret_type);
                        const targetEndpoint = sec.host
                          ? `${sec.host}${sec.port && sec.port !== "22" ? `:${sec.port}` : ""}`
                          : sec.url || "";
                        const matchedBots = bots.filter((b) => sec.allowed_bots.includes(b.slug));
                        const isBeingEdited = editingVaultSlug === sec.slug && vaultFormOpen;
                        return (
                          <div
                            key={sec.slug}
                            className={`px-4 py-3 flex items-center justify-between gap-3 flex-wrap ${
                              isBeingEdited ? "bg-slate-50" : ""
                            }`}
                          >
                            <div className="flex items-center gap-3 min-w-0 flex-1">
                              <span className="w-8 h-8 rounded-lg border border-slate-200 bg-slate-50 text-slate-600 flex items-center justify-center shrink-0">
                                <SecretIcon className="w-4 h-4" />
                              </span>
                              <div className="min-w-0">
                                <div className="text-xs font-semibold text-slate-900 truncate">
                                  {sec.name}
                                </div>
                                <div className="text-[11px] text-slate-500 truncate">
                                  {formatVaultTypeLabel(sec.secret_type)}
                                  {targetEndpoint ? ` · ${targetEndpoint}` : ""}
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              {allBotsAllowed ? (
                                <span className="px-2.5 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-700">
                                  All bots
                                </span>
                              ) : matchedBots.length === 0 ? (
                                <span className="px-2.5 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-500">
                                  No bots assigned
                                </span>
                              ) : (
                                <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-[11px] text-slate-700">
                                  <div className="flex items-center -space-x-1">
                                    {matchedBots.slice(0, 3).map((b) => (
                                      <BotAvatar
                                        key={b.slug}
                                        icon={b.avatar_icon}
                                        initials={b.initials}
                                        color={b.avatar_color}
                                        size="xs"
                                      />
                                    ))}
                                  </div>
                                  <span>
                                    {matchedBots.length} bot{matchedBots.length === 1 ? "" : "s"}
                                  </span>
                                </div>
                              )}

                              <button
                                type="button"
                                onClick={() => openEditVaultForm(sec)}
                                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-[11px] font-medium text-slate-700 cursor-pointer"
                              >
                                <Pencil className="w-3 h-3" />
                                <span>Edit</span>
                              </button>
                              <button
                                type="button"
                                title="Delete secret"
                                onClick={() => void onDeleteVaultSecret(sec.slug)}
                                className="p-1.5 rounded-lg border border-slate-200 bg-white hover:bg-rose-50 hover:border-rose-200 text-slate-500 hover:text-rose-600 cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {(vaultFormOpen || vaultSecrets.length === 0) && (
                    <form
                      onSubmit={(e) => void handleSaveVaultSecret(e)}
                      className="rounded-xl border border-slate-200 bg-white p-4 space-y-3"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="text-xs font-semibold text-slate-900">
                          {editingVaultSlug ? "Edit Secret" : "New Secret"}
                        </h3>
                        {vaultSecrets.length > 0 && (
                          <button
                            type="button"
                            onClick={() => {
                              resetVaultForm();
                              setVaultFormOpen(false);
                            }}
                            className="text-[11px] text-slate-500 hover:text-slate-900 cursor-pointer"
                          >
                            Cancel
                          </button>
                        )}
                      </div>

                      {vaultError && (
                        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
                          {vaultError}
                        </div>
                      )}

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-[11px] font-medium text-slate-700 mb-1">
                            Name
                          </label>
                          <input
                            type="text"
                            required
                            value={vaultName}
                            onChange={(e) => setVaultName(e.target.value)}
                            placeholder="e.g. Production Linux SSH"
                            className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] font-medium text-slate-700 mb-1">
                            Credential Type
                          </label>
                          <select
                            value={vaultType}
                            onChange={(e) =>
                              setVaultType(
                                e.target.value as "ssh" | "login" | "api_token" | "custom",
                              )
                            }
                            className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs bg-white"
                          >
                            <option value="ssh">SSH Server</option>
                            <option value="login">Web Login</option>
                            <option value="api_token">API Token</option>
                            <option value="custom">Custom Secret</option>
                          </select>
                        </div>
                      </div>

                      {vaultType === "ssh" && (
                        <div className="space-y-3">
                          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                            <div className="sm:col-span-2">
                              <label className="block text-[11px] font-medium text-slate-700 mb-1">
                                Host / IP
                              </label>
                              <input
                                type="text"
                                value={vaultHost}
                                onChange={(e) => setVaultHost(e.target.value)}
                                placeholder="192.168.1.10 or host.example.com"
                                className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                              />
                            </div>
                            <div>
                              <label className="block text-[11px] font-medium text-slate-700 mb-1">
                                Port
                              </label>
                              <input
                                type="text"
                                value={vaultPort}
                                onChange={(e) => setVaultPort(e.target.value)}
                                placeholder="22"
                                className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                              />
                            </div>
                            <div>
                              <label className="block text-[11px] font-medium text-slate-700 mb-1">
                                Username
                              </label>
                              <input
                                type="text"
                                value={vaultUsername}
                                onChange={(e) => setVaultUsername(e.target.value)}
                                placeholder={editingVaultSlug ? "Leave blank to keep existing" : "root"}
                                className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                              />
                            </div>
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                              <label className="block text-[11px] font-medium text-slate-700 mb-1">
                                Password
                              </label>
                              <input
                                type="password"
                                value={vaultPassword}
                                onChange={(e) => setVaultPassword(e.target.value)}
                                placeholder={editingVaultSlug ? "Leave blank to keep existing" : "Optional if key provided"}
                                className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                              />
                            </div>
                            <div>
                              <label className="block text-[11px] font-medium text-slate-700 mb-1">
                                SSH Private Key
                              </label>
                              <textarea
                                rows={2}
                                value={vaultPrivateKey}
                                onChange={(e) => setVaultPrivateKey(e.target.value)}
                                placeholder={editingVaultSlug ? "Leave blank to keep existing" : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                                className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          </div>
                        </div>
                      )}

                      {vaultType === "login" && (
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Login URL
                            </label>
                            <input
                              type="text"
                              value={vaultUrl}
                              onChange={(e) => setVaultUrl(e.target.value)}
                              placeholder="https://portal.example.com/login"
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Username / Email
                            </label>
                            <input
                              type="text"
                              value={vaultUsername}
                              onChange={(e) => setVaultUsername(e.target.value)}
                              placeholder={editingVaultSlug ? "Leave blank to keep existing" : ""}
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Password
                            </label>
                            <input
                              type="password"
                              value={vaultPassword}
                              onChange={(e) => setVaultPassword(e.target.value)}
                              placeholder={editingVaultSlug ? "Leave blank to keep existing" : ""}
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                        </div>
                      )}

                      {vaultType === "api_token" && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Target URL
                            </label>
                            <input
                              type="text"
                              value={vaultUrl}
                              onChange={(e) => setVaultUrl(e.target.value)}
                              placeholder="https://api.example.com"
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Bearer Token / API Secret
                            </label>
                            <input
                              type="password"
                              value={vaultToken}
                              onChange={(e) => setVaultToken(e.target.value)}
                              placeholder={editingVaultSlug ? "Leave blank to keep existing" : ""}
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                        </div>
                      )}

                      {vaultType === "custom" && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Field Key
                            </label>
                            <input
                              type="text"
                              value={vaultCustomKey}
                              onChange={(e) => setVaultCustomKey(e.target.value)}
                              placeholder="api_key"
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                          <div>
                            <label className="block text-[11px] font-medium text-slate-700 mb-1">
                              Secret Value
                            </label>
                            <input
                              type="password"
                              value={vaultCustomValue}
                              onChange={(e) => setVaultCustomValue(e.target.value)}
                              placeholder={editingVaultSlug ? "Leave blank to keep existing" : ""}
                              className="w-full rounded-lg border border-slate-200 px-2.5 py-1.5 text-xs"
                            />
                          </div>
                        </div>
                      )}

                      <div className="space-y-2 pt-1">
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="text-[11px] font-medium text-slate-700">
                            Bot Access
                          </span>
                          <div className="inline-flex rounded-lg border border-slate-200 bg-slate-50 p-0.5 text-[11px]">
                            <button
                              type="button"
                              onClick={() =>
                                setVaultAllowedBots((prev) =>
                                  prev.includes("*") ? [] : prev,
                                )
                              }
                              className={`px-2.5 py-1 rounded-md cursor-pointer ${
                                !vaultAllowedBots.includes("*")
                                  ? "bg-white text-slate-900 font-medium shadow-xs"
                                  : "text-slate-600 hover:text-slate-900"
                              }`}
                            >
                              Selected Bots
                            </button>
                            <button
                              type="button"
                              onClick={() => setVaultAllowedBots(["*"])}
                              className={`px-2.5 py-1 rounded-md cursor-pointer ${
                                vaultAllowedBots.includes("*")
                                  ? "bg-white text-slate-900 font-medium shadow-xs"
                                  : "text-slate-600 hover:text-slate-900"
                              }`}
                            >
                              All Bots
                            </button>
                          </div>
                        </div>

                        {!vaultAllowedBots.includes("*") && (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            {bots.length === 0 ? (
                              <span className="text-[11px] text-slate-400">
                                Create a bot first to grant access.
                              </span>
                            ) : (
                              bots.map((b) => {
                                const selected = vaultAllowedBots.includes(b.slug);
                                return (
                                  <button
                                    key={b.slug}
                                    type="button"
                                    onClick={() => toggleVaultBotAccess(b.slug)}
                                    className={`inline-flex items-center gap-1.5 pl-1.5 pr-2.5 py-1 rounded-full border text-[11px] cursor-pointer ${
                                      selected
                                        ? "border-slate-900 bg-slate-900 text-white font-medium"
                                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                                    }`}
                                  >
                                    <BotAvatar
                                      icon={b.avatar_icon}
                                      initials={b.initials}
                                      color={b.avatar_color}
                                      size="xs"
                                    />
                                    <span>{b.name}</span>
                                  </button>
                                );
                              })
                            )}
                          </div>
                        )}
                      </div>

                      <div className="flex items-center justify-end gap-2 pt-1">
                        {vaultSecrets.length > 0 && (
                          <button
                            type="button"
                            onClick={() => {
                              resetVaultForm();
                              setVaultFormOpen(false);
                            }}
                            className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-xs text-slate-700 cursor-pointer"
                          >
                            Cancel
                          </button>
                        )}
                        <button
                          type="submit"
                          disabled={vaultSaving || !vaultName.trim()}
                          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium cursor-pointer disabled:opacity-50"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          {vaultSaving ? "Saving..." : "Save Secret"}
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              </div>
            )}

            {activeTab === "models" && (
              <ModelsView
                modelsData={modelsData}
                onOpenNewModel={onOpenNewModel}
                onSetDefaultModel={onSetDefaultModel}
                onTestModel={onTestModel}
                onDeleteModel={onDeleteModel}
                onPauseBot={onPauseBot}
                onSwitchBotToFlash={onSwitchBotToFlash}
              />
            )}

            {activeTab === "desktops" && (
              <DesktopsView
                host={desktopHost}
                desktops={desktops}
                queuedLaunches={queuedLaunches}
                togglingDesktops={togglingDesktops}
                desktopBootBySlug={desktopBootBySlug}
                onToggleDesktop={onToggleDesktop}
                onStopAllDesktops={onStopAllDesktops}
                onOpenSelkies={onOpenSelkies}
                onDeleteBot={onDeleteBot}
              />
            )}

            {activeTab === "memory" && (
              <div className="h-full overflow-y-auto custom-scroll p-5">
                <div className="max-w-4xl mx-auto space-y-5">
                  <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
                    <div className="flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-indigo-600" />
                      <div>
                        <h3 className="text-xs font-semibold text-slate-900">
                          Import Notes &amp; Preferences (Bring Your Memory)
                        </h3>
                        <p className="text-[11px] text-slate-500">
                          Paste exported ChatGPT/Claude instructions, bullet notes, or personal tone guidelines to import automatically.
                        </p>
                      </div>
                    </div>
                    <form onSubmit={handleImportMemory} className="space-y-2.5">
                      <textarea
                        rows={4}
                        value={importText}
                        onChange={(e) => setImportText(e.target.value)}
                        placeholder="- Always keep replies concise and direct&#10;- Never share internal pricing without approval&#10;- Include source links at the bottom"
                        className="w-full rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs"
                      />
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <select
                          value={importScope}
                          onChange={(e) => setImportScope(e.target.value)}
                          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                        >
                          <option value="*">Apply to All Bots</option>
                          {bots.map((b) => (
                            <option key={b.slug} value={b.slug}>
                              Only {b.name}
                            </option>
                          ))}
                        </select>
                        <button
                          type="submit"
                          disabled={importing || !importText.trim()}
                          className="bg-slate-900 text-white px-3.5 py-1.5 rounded-lg text-xs font-medium disabled:opacity-50 cursor-pointer"
                        >
                          {importing ? "Importing..." : "Import Memory Rules"}
                        </button>
                      </div>
                    </form>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
                    <div>
                      <h3 className="text-xs font-semibold text-slate-900">
                        Writing &amp; Tone Preferences ({styleRules.length})
                      </h3>
                      <p className="text-[11px] text-slate-500">
                        Active guidelines learned from your edits or saved rules.
                      </p>
                    </div>
                    <div className="space-y-1.5 max-h-56 overflow-y-auto custom-scroll">
                      {styleRules.length === 0 ? (
                        <div className="text-xs text-slate-400">No rules saved yet.</div>
                      ) : (
                        styleRules.map((rule) => (
                          <div
                            key={rule.id}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-slate-50 border border-slate-200 text-xs"
                          >
                            <div>
                              <span className="text-slate-900">{rule.rule_text}</span>
                              <span className="ml-2 text-[10px] text-slate-500">
                                ({rule.scope_slug === "*" ? "All bots" : rule.scope_slug})
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() => void onDeleteStyleRule(rule.id)}
                              className="text-[11px] text-rose-600 hover:underline cursor-pointer shrink-0"
                            >
                              Remove
                            </button>
                          </div>
                        ))
                      )}
                    </div>
                    <form onSubmit={handleAddRule} className="flex gap-2 flex-wrap">
                      <select
                        value={newRuleScope}
                        onChange={(e) => setNewRuleScope(e.target.value)}
                        className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                      >
                        <option value="*">All Bots</option>
                        {bots.map((b) => (
                          <option key={b.slug} value={b.slug}>
                            {b.name}
                          </option>
                        ))}
                      </select>
                      <input
                        type="text"
                        value={newRuleText}
                        onChange={(e) => setNewRuleText(e.target.value)}
                        placeholder="Add a writing or safety guideline..."
                        className="flex-1 min-w-[200px] rounded-lg border border-slate-200 px-3 py-1.5 text-xs bg-slate-50"
                      />
                      <button
                        type="submit"
                        disabled={!newRuleText.trim()}
                        className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-40 cursor-pointer"
                      >
                        Add Rule
                      </button>
                    </form>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-3">
                    <div>
                      <h3 className="text-xs font-semibold text-slate-900">
                        Reusable Skills ({skills.length})
                      </h3>
                      <p className="text-[11px] text-slate-500">
                        Saved step-by-step playbooks you can attach via @ in any bot chat.
                      </p>
                    </div>
                    {skills.length > 0 && (
                      <div className="space-y-2">
                        {skills.map((skill) => (
                          <div
                            key={skill.id}
                            className="rounded-lg border border-slate-200 bg-slate-50 p-3 flex items-start justify-between gap-3 text-xs"
                          >
                            <div className="space-y-0.5 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-slate-900">{skill.name}</span>
                                <span className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-[10px] text-slate-500">
                                  {skill.scope_slug === "*" ? "Global" : skill.scope_slug}
                                </span>
                              </div>
                              {skill.description && (
                                <div className="text-[11px] text-slate-500">{skill.description}</div>
                              )}
                              <div className="text-[11px] text-slate-700 whitespace-pre-wrap">
                                {skill.instructions}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => void onDeleteSkill(skill.id)}
                              className="text-[11px] text-rose-600 hover:underline shrink-0 cursor-pointer"
                            >
                              Delete
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                    <form onSubmit={handleCreateSkill} className="space-y-2 pt-1 border-t border-slate-100">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <input
                          type="text"
                          value={skillName}
                          onChange={(e) => setSkillName(e.target.value)}
                          placeholder="Skill name (e.g. Weekly Digest)"
                          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs bg-slate-50"
                        />
                        <input
                          type="text"
                          value={skillDesc}
                          onChange={(e) => setSkillDesc(e.target.value)}
                          placeholder="Short description (optional)"
                          className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs bg-slate-50"
                        />
                        <select
                          value={skillScope}
                          onChange={(e) => setSkillScope(e.target.value)}
                          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                        >
                          <option value="*">Available to All Bots</option>
                          {bots.map((b) => (
                            <option key={b.slug} value={b.slug}>
                              Only {b.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          value={skillInstr}
                          onChange={(e) => setSkillInstr(e.target.value)}
                          placeholder="Step-by-step playbook instructions..."
                          className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs bg-slate-50"
                        />
                        <button
                          type="submit"
                          disabled={savingSkill || !skillName.trim() || !skillInstr.trim()}
                          className="bg-slate-900 text-white px-3 py-1.5 rounded-lg text-xs font-medium disabled:opacity-40 cursor-pointer"
                        >
                          Save Skill
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "diagnostics" && (
              <div className="flex-1 min-h-0 flex flex-col">
                <div className="p-4 border-b border-slate-200 bg-white flex items-center justify-between flex-wrap gap-3 shrink-0">
                  <div className="flex items-center gap-3 flex-wrap text-xs">
                    <span className="px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 text-slate-700 font-medium">
                      Argo v{summary?.version ?? "0.1.0"} · Fedora 45
                    </span>
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 text-slate-600">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          summary?.valkey_connected ? "bg-emerald-500" : "bg-amber-500"
                        }`}
                      />
                      {summary?.valkey_connected ? "Valkey 9.1 Connected" : "In-Process Event Bus"} ·{" "}
                      {summary?.sqlite_wal ? "SQLite WAL" : "SQLite"}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] text-slate-500 mr-1">Appearance</span>
                    <button
                      type="button"
                      onClick={() => onToggleTheme("light")}
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-xs cursor-pointer ${
                        theme === "light"
                          ? "bg-slate-900 text-white border-transparent"
                          : "bg-white border-slate-200 text-slate-600"
                      }`}
                    >
                      <Sun className="w-3 h-3" />
                      Light
                    </button>
                    <button
                      type="button"
                      onClick={() => onToggleTheme("dark")}
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-xs cursor-pointer ${
                        theme === "dark"
                          ? "bg-slate-900 text-white border-transparent"
                          : "bg-white border-slate-200 text-slate-600"
                      }`}
                    >
                      <Moon className="w-3 h-3" />
                      Dark
                    </button>
                  </div>
                </div>
                <div className="flex-1 min-h-0 flex flex-col bg-white">
                  <DebugModal
                    initialBotSlug={debugBotSlug}
                    bots={bots}
                    onLoadOverview={onLoadDebugOverview}
                    onClear={onClearDebug}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
