import { useEffect, useState, type FormEvent } from "react";
import {
  Activity,
  BookOpen,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Cpu,
  KeyRound,
  Lock,
  LogOut,
  Monitor,
  Pencil,
  Plug,
  Plus,
  ShieldCheck,
  Sparkles,
  Sun,
  Moon,
  Trash2,
  Users,
  X,
} from "lucide-react";
import { api } from "../api";
import type {
  BotRecord,
  ChatRetentionSettings,
  DebugOverviewResponse,
  DesktopBootProgress,
  DesktopInfo,
  DesktopLaunchQueueItem,
  HostTelemetry,
  IntegrationAccount,
  ModelProvider,
  ModelsResponse,
  ResourceVisibility,
  SandboxInfo,
  SSHAuditSettings,
  SettingsTab,
  SkillRecord,
  SsoPrincipal,
  StyleRule,
  TeamGroupRecord,
  VaultSecretRecord,
  WorkspaceSummary,
} from "../types";
import { DebugModal } from "./Modals";
import { BotAvatar } from "./BotAvatar";
import { vaultSecretIconComponent } from "./MentionText";
import { VisibilityPicker, formatVisibilityLabel, visibilityBadgeClasses } from "./VisibilityPicker";
import { DesktopsView } from "./views/DesktopsView";
import { IntegrationsView } from "./views/IntegrationsView";
import { ModelsView } from "./views/ModelsView";
import { UsersTeamsView } from "./views/UsersTeamsView";

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
  onOpenNewIntegration: (defaultProvider?: IntegrationAccount["provider"]) => void;
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

  // Desktops & Sandboxes
  desktopHost: HostTelemetry | null;
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
  onChatHistoryPruned?: () => void;

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
    trusted_command_prefixes?: string[];
    visibility?: ResourceVisibility;
    allowed_groups?: string[];
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
      trusted_command_prefixes?: string[];
      visibility?: ResourceVisibility;
      allowed_groups?: string[];
    },
  ) => Promise<void>;
  onDeleteVaultSecret: (slug: string) => Promise<void>;
  onRefreshVault?: () => Promise<void>;
  teams?: TeamGroupRecord[];
  onRefreshTeamsAndUsers?: () => Promise<void>;
  principal?: SsoPrincipal | null;
  onSignOut?: () => void;
}

const TABS: Array<{ id: SettingsTab; label: string; icon: typeof Plug }> = [
  { id: "integrations", label: "Integrations", icon: Plug },
  { id: "vault", label: "Secrets Vault", icon: Lock },
  { id: "models", label: "Models & Usage", icon: Cpu },
  { id: "desktops", label: "Desktops", icon: Monitor },
  { id: "memory", label: "Writing & Memory", icon: BookOpen },
  { id: "users", label: "Users & Teams", icon: Users },
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
  styleRules,
  onAddStyleRule,
  onDeleteStyleRule,
  onImportMemory,
  skills,
  onSaveSkill,
  onDeleteSkill,
  onChatHistoryPruned,
  debugBotSlug,
  onLoadDebugOverview,
  onClearDebug,
  vaultSecrets,
  onCreateVaultSecret,
  onUpdateVaultSecret,
  onDeleteVaultSecret,
  onRefreshVault,
  teams = [],
  onRefreshTeamsAndUsers,
  principal,
  onSignOut,
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
  const [vaultSudoPassword, setVaultSudoPassword] = useState("");
  const [vaultPrivateKey, setVaultPrivateKey] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [vaultCustomKey, setVaultCustomKey] = useState("value");
  const [vaultCustomValue, setVaultCustomValue] = useState("");
  const [vaultAllowedBots, setVaultAllowedBots] = useState<string[]>([]);
  const [vaultVisibility, setVaultVisibility] = useState<ResourceVisibility>("private");
  const [vaultAllowedGroups, setVaultAllowedGroups] = useState<string[]>([]);
  const [changePwOpen, setChangePwOpen] = useState(false);
  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const [pwMsg, setPwMsg] = useState<string | null>(null);
  const [pwErr, setPwErr] = useState<string | null>(null);
  const [vaultTrustedPrefixes, setVaultTrustedPrefixes] = useState<string[]>([]);
  const [vaultTrustedInput, setVaultTrustedInput] = useState("");
  const [vaultSaving, setVaultSaving] = useState(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [vaultFormOpen, setVaultFormOpen] = useState(false);
  const [editingVaultSlug, setEditingVaultSlug] = useState<string | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkPrefix, setBulkPrefix] = useState("");
  const [bulkHostsText, setBulkHostsText] = useState("");
  const [bulkPort, setBulkPort] = useState("22");
  const [bulkSaving, setBulkSaving] = useState(false);
  const [sshAuditSettings, setSshAuditSettings] = useState<SSHAuditSettings>({
    retention_hours: 24,
    total_recordings: 0,
    pinned_recordings: 0,
  });
  const [retentionMode, setRetentionMode] = useState<"24" | "168" | "720" | "2160" | "custom">("24");
  const [customRetentionHours, setCustomRetentionHours] = useState("24");
  const [savingRetention, setSavingRetention] = useState(false);
  const [chatRetention, setChatRetention] = useState<ChatRetentionSettings>({
    retention_days: 0,
    bot_messages_count: 0,
    room_messages_count: 0,
  });
  const [savingChatRetention, setSavingChatRetention] = useState(false);
  const [pruningChatHistory, setPruningChatHistory] = useState(false);
  const [chatRetentionNote, setChatRetentionNote] = useState<string | null>(null);
  const [resettingKeyTarget, setResettingKeyTarget] = useState<string | null>(null);
  const [copiedVersion, setCopiedVersion] = useState(false);

  const isMultiUser = Boolean(principal?.multi_user);
  const isAdmin = Boolean(principal?.is_admin);
  const callerEmail = (principal?.email || "").toLowerCase();
  const canManageVault = (owner?: string) =>
    !isMultiUser || isAdmin || !owner || owner.toLowerCase() === callerEmail;
  const showUsersTab =
    isAdmin &&
    (isMultiUser || principal?.auth_mode === "local" || principal?.auth_mode === "hybrid");
  const visibleTabs = TABS.filter((t) => {
    if (t.id === "diagnostics") return !isMultiUser || isAdmin;
    if (t.id === "users") return showUsersTab;
    return true;
  });

  useEffect(() => {
    if (isMultiUser && !isAdmin && bots.length > 0) {
      const firstSlug = bots[0].slug;
      setNewRuleScope((prev) => (prev === "*" ? firstSlug : prev));
      setImportScope((prev) => (prev === "*" ? firstSlug : prev));
      setSkillScope((prev) => (prev === "*" ? firstSlug : prev));
    }
  }, [isMultiUser, isAdmin, bots]);

  useEffect(() => {
    if (!open || activeTab !== "vault" || (isMultiUser && !isAdmin)) return;
    let cancelled = false;
    void api
      .getSSHAuditSettings()
      .then((res) => {
        if (cancelled) return;
        setSshAuditSettings(res);
        const hr = String(res.retention_hours);
        if (hr === "24" || hr === "168" || hr === "720" || hr === "2160") {
          setRetentionMode(hr);
        } else {
          setRetentionMode("custom");
        }
        setCustomRetentionHours(hr);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [open, activeTab]);

  useEffect(() => {
    if (!open || activeTab !== "memory" || (isMultiUser && !isAdmin)) return;
    let cancelled = false;
    setChatRetentionNote(null);
    void api
      .getChatRetentionSettings()
      .then((res) => {
        if (!cancelled) setChatRetention(res);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [open, activeTab]);

  if (!open) return null;

  const normalizedVersion =
    (summary?.version || "0.1.0").trim().replace(/^v/i, "") || "0.1.0";
  const versionTag = `v${normalizedVersion}`;
  const shortCommit = (summary?.commit_sha || "").trim().slice(0, 7);
  const fullVersionCopyText = shortCommit
    ? `Argo ${versionTag} (${shortCommit})`
    : `Argo ${versionTag}`;

  async function handleCopyVersion() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(fullVersionCopyText);
        setCopiedVersion(true);
        window.setTimeout(() => setCopiedVersion(false), 1800);
      }
    } catch {
      // Clipboard API unavailable in non-secure contexts
    }
  }

  function resetVaultForm() {
    setVaultName("");
    setVaultType("ssh");
    setVaultHost("");
    setVaultPort("22");
    setVaultUrl("");
    setVaultUsername("");
    setVaultPassword("");
    setVaultSudoPassword("");
    setVaultPrivateKey("");
    setVaultToken("");
    setVaultCustomKey("value");
    setVaultCustomValue("");
    setVaultAllowedBots([]);
    setVaultVisibility("private");
    setVaultAllowedGroups([]);
    setVaultTrustedPrefixes([]);
    setVaultTrustedInput("");
    setVaultError(null);
    setEditingVaultSlug(null);
    setBulkOpen(false);
    setBulkPrefix("");
    setBulkHostsText("");
    setBulkPort("22");
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
    setVaultSudoPassword("");
    setVaultPrivateKey("");
    setVaultToken("");
    setVaultCustomKey("value");
    setVaultCustomValue("");
    setVaultAllowedBots([...sec.allowed_bots]);
    setVaultVisibility(
      sec.visibility === "shared" || sec.visibility === "team" ? sec.visibility : "private",
    );
    setVaultAllowedGroups([...(sec.allowed_groups ?? [])]);
    setVaultTrustedPrefixes([...(sec.trusted_command_prefixes ?? [])]);
    setVaultTrustedInput("");
    setVaultError(null);
    setEditingVaultSlug(sec.slug);
    setVaultFormOpen(true);
  }

  function addVaultTrustPrefix() {
    const clean = vaultTrustedInput.trim();
    if (!clean) return;
    setVaultTrustedPrefixes((prev) =>
      prev.some((p) => p.toLowerCase() === clean.toLowerCase()) ? prev : [...prev, clean],
    );
    setVaultTrustedInput("");
  }

  function removeVaultTrustPrefix(target: string) {
    setVaultTrustedPrefixes((prev) => prev.filter((p) => p !== target));
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
      if (vaultSudoPassword) secrets.sudo_password = vaultSudoPassword;
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
    if (isMultiUser && vaultVisibility === "team" && vaultAllowedGroups.length === 0) {
      setVaultError("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    setVaultSaving(true);
    setVaultError(null);
    const pendingTrust = vaultTrustedInput.trim();
    const finalTrusted =
      vaultType === "ssh"
        ? pendingTrust &&
          !vaultTrustedPrefixes.some((p) => p.toLowerCase() === pendingTrust.toLowerCase())
          ? [...vaultTrustedPrefixes, pendingTrust]
          : vaultTrustedPrefixes
        : undefined;
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
          ...(isMultiUser
            ? {
                visibility: vaultVisibility,
                allowed_groups: vaultVisibility === "team" ? vaultAllowedGroups : [],
              }
            : {}),
          ...(vaultType === "ssh" ? { trusted_command_prefixes: finalTrusted } : {}),
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
          ...(isMultiUser
            ? {
                visibility: vaultVisibility,
                allowed_groups: vaultVisibility === "team" ? vaultAllowedGroups : [],
              }
            : {}),
          ...(vaultType === "ssh" && finalTrusted && finalTrusted.length > 0
            ? { trusted_command_prefixes: finalTrusted }
            : {}),
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

  async function handleBulkAddSSH() {
    if (!bulkHostsText.trim() || bulkSaving) return;
    if (isMultiUser && vaultVisibility === "team" && vaultAllowedGroups.length === 0) {
      setVaultError("Select at least one Team Group when Visibility is set to Team.");
      return;
    }
    const secrets: Record<string, string> = {};
    if (vaultUsername.trim()) secrets.username = vaultUsername.trim();
    if (vaultPassword) secrets.password = vaultPassword;
    if (vaultSudoPassword) secrets.sudo_password = vaultSudoPassword;
    if (vaultPrivateKey.trim()) secrets.private_key = vaultPrivateKey.trim();
    if (Object.keys(secrets).length === 0) {
      setVaultError("Fill in username, password, or SSH private key before adding multiple servers.");
      return;
    }
    setBulkSaving(true);
    setVaultError(null);
    try {
      await api.bulkCreateSSHVaultSecrets({
        name_prefix: bulkPrefix.trim() || vaultName.trim() || "SSH Server",
        hosts_text: bulkHostsText,
        port: bulkPort.trim() || vaultPort.trim() || "22",
        secrets,
        allowed_bots: vaultAllowedBots,
        ...(isMultiUser
          ? {
              visibility: vaultVisibility,
              allowed_groups: vaultVisibility === "team" ? vaultAllowedGroups : [],
            }
          : {}),
      });
      await onRefreshVault?.();
      resetVaultForm();
      setVaultFormOpen(false);
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : "Failed to add servers.");
    } finally {
      setBulkSaving(false);
    }
  }

  async function handleResetHostKey(slug: string, hostPort?: string) {
    const keyId = `${slug}:${hostPort ?? "*"}`;
    setResettingKeyTarget(keyId);
    setVaultError(null);
    try {
      await api.resetVaultHostKey(slug, hostPort);
      await onRefreshVault?.();
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : "Failed to reset server key.");
    } finally {
      setResettingKeyTarget(null);
    }
  }

  async function handleRetentionChange(nextHours: number) {
    const clamped = Math.max(1, Math.min(8760, Math.round(nextHours)));
    setSavingRetention(true);
    try {
      const updated = await api.updateSSHAuditSettings(clamped);
      setSshAuditSettings(updated);
      setCustomRetentionHours(String(updated.retention_hours));
    } finally {
      setSavingRetention(false);
    }
  }

  async function handleChatRetentionChange(nextDays: number) {
    const clamped = Math.max(0, Math.min(3650, Math.round(nextDays)));
    setSavingChatRetention(true);
    setChatRetentionNote(null);
    try {
      const updated = await api.updateChatRetentionSettings(clamped, false);
      setChatRetention(updated);
      setChatRetentionNote(
        clamped === 0
          ? "Saved: keep all chat history forever."
          : `Saved: prune messages older than ${clamped} days automatically.`,
      );
    } catch (err) {
      setChatRetentionNote(
        err instanceof Error ? err.message : "Failed to save chat retention setting.",
      );
    } finally {
      setSavingChatRetention(false);
    }
  }

  async function handlePruneChatHistoryNow() {
    if (chatRetention.retention_days <= 0) return;
    setPruningChatHistory(true);
    setChatRetentionNote(null);
    try {
      const res = await api.updateChatRetentionSettings(chatRetention.retention_days, true);
      setChatRetention(res);
      const prunedTotal = Number(res.pruned_total ?? 0);
      if (prunedTotal > 0) {
        setChatRetentionNote(
          `Pruned ${prunedTotal} message${prunedTotal === 1 ? "" : "s"} older than ${res.retention_days} days.`,
        );
        onChatHistoryPruned?.();
      } else {
        setChatRetentionNote(`No messages older than ${res.retention_days} days.`);
      }
    } catch (err) {
      setChatRetentionNote(
        err instanceof Error ? err.message : "Failed to prune older messages.",
      );
    } finally {
      setPruningChatHistory(false);
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
      className="fixed inset-0 z-50 argo-modal-backdrop flex items-center justify-center p-0 sm:p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Settings"
        className="w-full sm:max-w-5xl h-[100dvh] sm:h-[86vh] rounded-none sm:rounded-2xl border-0 sm:border argo-modal-panel overflow-hidden flex flex-col argo-safe-top argo-safe-bottom"
      >
        <div className="min-h-14 px-4 sm:px-5 py-2.5 sm:py-0 border-b border-slate-200 argo-modal-header flex items-center justify-between gap-2 shrink-0">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-slate-900 truncate">
              Settings
              <span className="sm:hidden text-[11px] font-mono text-slate-400 font-normal ml-1.5">
                {versionTag}
              </span>
            </h2>
            <p className="hidden sm:block text-[11px] text-slate-500">
              Manage connected apps, AI models, virtual desktops, saved memory, and system health
            </p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => onToggleTheme(theme === "dark" ? "light" : "dark")}
              title={theme === "dark" ? "Switch to Light mode" : "Switch to Dark mode"}
              aria-label={theme === "dark" ? "Switch to Light mode" : "Switch to Dark mode"}
              className="sm:hidden w-8 h-8 rounded-lg border border-slate-200 bg-white text-slate-700 flex items-center justify-center cursor-pointer"
            >
              {theme === "dark" ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>
            {onSignOut && (
              <button
                type="button"
                onClick={onSignOut}
                title={principal?.email ? `Sign out (${principal.email})` : "Sign out"}
                aria-label="Sign out"
                className="sm:hidden w-8 h-8 rounded-lg border border-slate-200 bg-white text-slate-700 hover:text-rose-700 flex items-center justify-center cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              Close
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 flex flex-col sm:flex-row">
          <nav className="sm:w-52 shrink-0 border-b sm:border-b-0 sm:border-r border-slate-200 bg-slate-50 p-3 flex sm:flex-col gap-1 overflow-x-auto">
            {visibleTabs.map((tab) => {
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

            <div className="hidden sm:block mt-auto pt-3 border-t border-slate-200 space-y-1">
              {principal?.auth_mode && principal.auth_mode !== "sso" && (
                <div className="space-y-1.5 pb-1">
                  <button
                    type="button"
                    onClick={() => {
                      setChangePwOpen((v) => !v);
                      setPwErr(null);
                      setPwMsg(null);
                    }}
                    className="w-full px-3 py-2 rounded-xl text-left text-xs font-medium text-slate-600 hover:bg-slate-100 transition cursor-pointer flex items-center gap-2"
                  >
                    <KeyRound className="w-3.5 h-3.5 shrink-0" />
                    <span className="truncate">Change password</span>
                  </button>
                  {changePwOpen && (
                    <form
                      onSubmit={async (e) => {
                        e.preventDefault();
                        setPwErr(null);
                        setPwMsg(null);
                        if (newPw !== confirmPw) {
                          setPwErr("New passwords do not match.");
                          return;
                        }
                        setPwSaving(true);
                        try {
                          await api.changePassword({
                            ...(curPw ? { current_password: curPw } : {}),
                            new_password: newPw,
                          });
                          setCurPw("");
                          setNewPw("");
                          setConfirmPw("");
                          setPwMsg("Password updated.");
                          await onRefreshTeamsAndUsers?.();
                        } catch (err) {
                          setPwErr(err instanceof Error ? err.message : "Failed to update password.");
                        } finally {
                          setPwSaving(false);
                        }
                      }}
                      className="rounded-xl border border-slate-200 bg-white p-2.5 space-y-1.5 text-[11px]"
                    >
                      <input
                        type="password"
                        value={curPw}
                        onChange={(e) => setCurPw(e.target.value)}
                        placeholder="Current password"
                        autoComplete="current-password"
                        className="w-full rounded-lg border border-slate-200 px-2 py-1 text-[11px]"
                      />
                      <input
                        type="password"
                        required
                        minLength={8}
                        value={newPw}
                        onChange={(e) => setNewPw(e.target.value)}
                        placeholder="New password (8+)"
                        autoComplete="new-password"
                        className="w-full rounded-lg border border-slate-200 px-2 py-1 text-[11px]"
                      />
                      <input
                        type="password"
                        required
                        minLength={8}
                        value={confirmPw}
                        onChange={(e) => setConfirmPw(e.target.value)}
                        placeholder="Confirm password"
                        autoComplete="new-password"
                        className="w-full rounded-lg border border-slate-200 px-2 py-1 text-[11px]"
                      />
                      {pwErr && <div className="text-[10px] text-rose-600">{pwErr}</div>}
                      {pwMsg && <div className="text-[10px] text-emerald-600">{pwMsg}</div>}
                      <button
                        type="submit"
                        disabled={pwSaving}
                        className="w-full py-1 rounded-lg bg-slate-900 text-white font-medium text-[11px] disabled:opacity-50 cursor-pointer"
                      >
                        {pwSaving ? "Saving..." : "Save Password"}
                      </button>
                    </form>
                  )}
                </div>
              )}
              {onSignOut && (
                <button
                  type="button"
                  onClick={onSignOut}
                  title={principal?.email ? `Sign out (${principal.email})` : "Sign out"}
                  className="w-full px-3 py-2 rounded-xl text-left text-xs font-medium text-slate-600 hover:bg-rose-50 hover:text-rose-700 transition cursor-pointer flex items-center gap-2"
                >
                  <LogOut className="w-3.5 h-3.5 shrink-0" />
                  <span className="truncate">Sign out</span>
                </button>
              )}
              <button
                type="button"
                onClick={() => void handleCopyVersion()}
                title={copiedVersion ? `Copied: ${fullVersionCopyText}` : `Click to copy ${fullVersionCopyText}`}
                className="group w-full px-3 py-2 rounded-xl text-left hover:bg-slate-100 transition cursor-pointer flex items-center justify-between gap-2"
              >
                <span className="min-w-0 truncate">
                  <span className="text-[11px] font-medium text-slate-600">
                    Argo {versionTag}
                  </span>
                  {shortCommit && (
                    <span className="text-[10px] font-mono text-slate-400">
                      {" "}· {shortCommit}
                    </span>
                  )}
                </span>
                {copiedVersion ? (
                  <Check className="w-3 h-3 text-emerald-500 shrink-0" />
                ) : (
                  <Copy className="w-3 h-3 text-slate-400 opacity-70 group-hover:opacity-100 shrink-0" />
                )}
              </button>
            </div>
          </nav>

          <div className="flex-1 min-w-0 min-h-0 flex flex-col bg-slate-50">
            {activeTab === "integrations" && (
              <IntegrationsView
                principal={principal}
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
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="text-xs font-semibold text-slate-900 truncate">
                                    {sec.name}
                                  </span>
                                  {isMultiUser && (
                                    <>
                                      <span
                                        className={`px-1.5 py-0.2 rounded-full border text-[10px] font-medium ${visibilityBadgeClasses(
                                          sec.visibility,
                                        )}`}
                                      >
                                        {formatVisibilityLabel(sec.visibility, sec.allowed_groups)}
                                      </span>
                                      {sec.owner_email && (
                                        <span className="text-[10.5px] text-slate-400 truncate">
                                          {sec.owner_email}
                                        </span>
                                      )}
                                    </>
                                  )}
                                </div>
                                <div className="text-[11px] text-slate-500 truncate">
                                  {formatVaultTypeLabel(sec.secret_type)}
                                  {targetEndpoint ? ` · ${targetEndpoint}` : ""}
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              {sec.secret_type === "ssh" &&
                                (sec.trusted_command_prefixes?.length ?? 0) > 0 && (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-sky-200 bg-sky-50 text-[10.5px] font-medium text-sky-800">
                                    <ShieldCheck className="w-3 h-3" />
                                    <span>
                                      {sec.trusted_command_prefixes!.length} trusted cmd
                                      {sec.trusted_command_prefixes!.length === 1 ? "" : "s"}
                                    </span>
                                  </span>
                                )}
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

                              {canManageVault(sec.owner_email) && (
                                <>
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
                                </>
                              )}
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
                              <p className="text-[10.5px] text-slate-500 mt-1">
                                Optional — leave blank to pass server addresses directly in chat
                              </p>
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
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
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
                                Sudo Password
                              </label>
                              <input
                                type="password"
                                value={vaultSudoPassword}
                                onChange={(e) => setVaultSudoPassword(e.target.value)}
                                placeholder={editingVaultSlug ? "Leave blank to keep existing" : "Optional — used only for sudo"}
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

                          {!editingVaultSlug && (
                            <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 space-y-2">
                              <button
                                type="button"
                                onClick={() => setBulkOpen((v) => !v)}
                                className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-700 hover:text-slate-900 cursor-pointer"
                              >
                                {bulkOpen ? (
                                  <ChevronDown className="w-3.5 h-3.5" />
                                ) : (
                                  <ChevronRight className="w-3.5 h-3.5" />
                                )}
                                <span>Add multiple servers at once</span>
                              </button>
                              {bulkOpen && (
                                <div className="space-y-2 pt-1">
                                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    <input
                                      type="text"
                                      value={bulkPrefix}
                                      onChange={(e) => setBulkPrefix(e.target.value)}
                                      placeholder="Name prefix (e.g. Web Fleet)"
                                      className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                                    />
                                    <input
                                      type="text"
                                      value={bulkPort}
                                      onChange={(e) => setBulkPort(e.target.value)}
                                      placeholder="Default port (22)"
                                      className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                                    />
                                  </div>
                                  <textarea
                                    rows={3}
                                    value={bulkHostsText}
                                    onChange={(e) => setBulkHostsText(e.target.value)}
                                    placeholder={"10.0.1.10\nweb2.example.com\n10.0.1.12:2222"}
                                    className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-mono"
                                  />
                                  <button
                                    type="button"
                                    disabled={bulkSaving || !bulkHostsText.trim()}
                                    onClick={() => void handleBulkAddSSH()}
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer disabled:opacity-50"
                                  >
                                    <Plus className="w-3 h-3" />
                                    <span>{bulkSaving ? "Creating servers..." : "Create Server Entries"}</span>
                                  </button>
                                </div>
                              )}
                            </div>
                          )}

                          <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 space-y-2">
                            <div className="flex items-center justify-between gap-2">
                              <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-700">
                                <ShieldCheck className="w-3.5 h-3.5 text-slate-600" />
                                <span>Trusted Commands (Auto-Run)</span>
                              </span>
                              <span className="text-[10.5px] text-slate-500">
                                Skip Ask First for these command prefixes
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-500">
                              Works for custom POSIX or Windows prefixes (for example:{" "}
                              <code className="font-mono">systemctl status</code>,{" "}
                              <code className="font-mono">df -h</code>,{" "}
                              <code className="font-mono">Get-WinEvent</code>,{" "}
                              <code className="font-mono">ipconfig /all</code>). Shell escapes and destructive commands stay blocked.
                            </p>
                            {vaultTrustedPrefixes.length > 0 && (
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {vaultTrustedPrefixes.map((pref) => (
                                  <span
                                    key={pref}
                                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-slate-300 bg-white text-[11px] font-mono text-slate-800"
                                  >
                                    <span>{pref}</span>
                                    <button
                                      type="button"
                                      title={`Remove ${pref}`}
                                      onClick={() => removeVaultTrustPrefix(pref)}
                                      className="text-slate-400 hover:text-rose-600 cursor-pointer"
                                    >
                                      <X className="w-3 h-3" />
                                    </button>
                                  </span>
                                ))}
                              </div>
                            )}
                            <div className="flex items-center gap-1.5">
                              <input
                                type="text"
                                value={vaultTrustedInput}
                                onChange={(e) => setVaultTrustedInput(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.preventDefault();
                                    addVaultTrustPrefix();
                                  }
                                }}
                                placeholder="e.g. systemctl status, df -h, Get-WinEvent, ipconfig /all"
                                className="flex-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-mono"
                              />
                              <button
                                type="button"
                                disabled={!vaultTrustedInput.trim()}
                                onClick={addVaultTrustPrefix}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-800 cursor-pointer disabled:opacity-50"
                              >
                                <Plus className="w-3 h-3" />
                                <span>Add</span>
                              </button>
                            </div>
                          </div>

                          {editingVaultSlug && (() => {
                            const currentSec = vaultSecrets.find((v) => v.slug === editingVaultSlug);
                            const fps = Object.entries(currentSec?.host_key_fingerprints ?? {});
                            if (fps.length === 0) return null;
                            return (
                              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 space-y-2">
                                <div className="flex items-center justify-between gap-2">
                                  <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-700">
                                    <KeyRound className="w-3.5 h-3.5 text-slate-500" />
                                    <span>Saved Server Keys</span>
                                  </span>
                                  <button
                                    type="button"
                                    disabled={resettingKeyTarget !== null}
                                    onClick={() => void handleResetHostKey(editingVaultSlug)}
                                    className="px-2.5 py-1 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-[11px] font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                                  >
                                    Reset Server Key
                                  </button>
                                </div>
                                <div className="space-y-1">
                                  {fps.map(([hp, fp]) => (
                                    <div key={hp} className="flex items-center justify-between gap-2 text-[11px] text-slate-600">
                                      <span className="font-mono truncate">{hp} · {fp}</span>
                                      <button
                                        type="button"
                                        disabled={resettingKeyTarget !== null}
                                        onClick={() => void handleResetHostKey(editingVaultSlug, hp)}
                                        className="text-slate-500 hover:text-slate-900 underline shrink-0 cursor-pointer"
                                      >
                                        Reset
                                      </button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            );
                          })()}
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

                      {isMultiUser && (
                        <div className="pt-1">
                          <VisibilityPicker
                            value={vaultVisibility}
                            allowedGroups={vaultAllowedGroups}
                            teams={teams}
                            label="Visibility"
                            onChange={(vis, groups) => {
                              setVaultVisibility(vis);
                              setVaultAllowedGroups(groups);
                            }}
                          />
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
                          <div className="space-y-1.5">
                            <p className="text-[11px] text-slate-500">
                              Only select bots that should run commands. Leave audit or review bots unchecked.
                            </p>
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

                  {(!isMultiUser || isAdmin) && (
                    <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
                      <div className="min-w-0">
                        <h4 className="text-xs font-semibold text-slate-900">
                          Keep terminal recordings
                        </h4>
                        <p className="text-[11px] text-slate-500 mt-0.5">
                          Automatically remove older SSH recordings after this window unless marked Keep Recording ({sshAuditSettings.total_recordings} saved · {sshAuditSettings.pinned_recordings} kept).
                        </p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <select
                          value={retentionMode}
                          disabled={savingRetention}
                          aria-label="Keep terminal recordings"
                          onChange={(e) => {
                            const mode = e.target.value as "24" | "168" | "720" | "2160" | "custom";
                            setRetentionMode(mode);
                            if (mode !== "custom") {
                              void handleRetentionChange(Number(mode));
                            }
                          }}
                          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-900"
                        >
                          <option value="24">1 day (default)</option>
                          <option value="168">7 days</option>
                          <option value="720">30 days</option>
                          <option value="2160">90 days</option>
                          <option value="custom">Custom hours</option>
                        </select>
                        {retentionMode === "custom" && (
                          <div className="inline-flex items-center gap-1.5">
                            <input
                              type="number"
                              min={1}
                              max={8760}
                              value={customRetentionHours}
                              onChange={(e) => setCustomRetentionHours(e.target.value)}
                              className="w-20 rounded-lg border border-slate-200 px-2 py-1.5 text-xs"
                            />
                            <button
                              type="button"
                              disabled={savingRetention}
                              onClick={() => void handleRetentionChange(Number(customRetentionHours) || 24)}
                              className="px-2.5 py-1.5 rounded-lg bg-slate-900 text-white text-[11px] font-medium cursor-pointer"
                            >
                              Apply
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === "models" && (
              <ModelsView
                principal={principal}
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
                principal={principal}
                host={desktopHost}
                desktops={desktops}
                sandboxes={sandboxes}
                queuedLaunches={queuedLaunches}
                togglingDesktops={togglingDesktops}
                togglingSandboxes={togglingSandboxes}
                desktopBootBySlug={desktopBootBySlug}
                onToggleDesktop={onToggleDesktop}
                onToggleSandbox={onToggleSandbox}
                onStopAllDesktops={onStopAllDesktops}
                onStopAllSandboxes={onStopAllSandboxes}
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
                          {(!isMultiUser || isAdmin) && (
                            <option value="*">Apply to All Bots</option>
                          )}
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

                  {(!isMultiUser || isAdmin) && (
                    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-xs space-y-2.5">
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="min-w-0 space-y-0.5">
                          <h3 className="text-xs font-semibold text-slate-900">
                            Chat History Retention
                          </h3>
                          <p className="text-[11px] text-slate-500">
                            Automatically prune older 1:1 bot and room messages after this window. Keeps Skills, Writing Rules, Routines, Data Lists, Pages, Files, Approvals &amp; SSH recordings.
                          </p>
                          <div className="text-[11px] text-slate-500 pt-0.5">
                            {chatRetention.bot_messages_count} bot messages · {chatRetention.room_messages_count} room messages stored
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <select
                            aria-label="Chat history retention"
                            value={String(chatRetention.retention_days)}
                            disabled={savingChatRetention || pruningChatHistory}
                            onChange={(e) => void handleChatRetentionChange(Number(e.target.value))}
                            className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-900"
                          >
                            <option value="0">Keep forever (default)</option>
                            <option value="7">7 days</option>
                            <option value="30">30 days</option>
                            <option value="90">90 days</option>
                            <option value="180">180 days</option>
                            <option value="365">365 days</option>
                          </select>
                          {chatRetention.retention_days > 0 && (
                            <button
                              type="button"
                              disabled={savingChatRetention || pruningChatHistory}
                              onClick={() => void handlePruneChatHistoryNow()}
                              className="px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-[11px] font-medium text-slate-800 disabled:opacity-50 cursor-pointer"
                            >
                              {pruningChatHistory ? "Pruning..." : "Prune Now"}
                            </button>
                          )}
                        </div>
                      </div>
                      {chatRetentionNote && (
                        <div className="text-[11px] text-slate-600">{chatRetentionNote}</div>
                      )}
                    </div>
                  )}

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
                        {(!isMultiUser || isAdmin) && (
                          <option value="*">All Bots</option>
                        )}
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
                          {(!isMultiUser || isAdmin) && (
                          <option value="*">Available to All Bots</option>
                        )}
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

            {activeTab === "users" && showUsersTab && (
              <div className="flex-1 min-h-0 overflow-y-auto custom-scroll p-5">
                <div className="max-w-5xl mx-auto">
                  <UsersTeamsView
                    principal={principal ?? null}
                    onChanged={onRefreshTeamsAndUsers}
                  />
                </div>
              </div>
            )}

            {activeTab === "diagnostics" && (!isMultiUser || isAdmin) && (
              <div className="flex-1 min-h-0 flex flex-col">
                <div className="p-4 border-b border-slate-200 bg-white flex items-center justify-between flex-wrap gap-3 shrink-0">
                  <div className="flex items-center gap-3 flex-wrap text-xs">
                    <span className="px-2.5 py-1 rounded-full border border-slate-200 bg-slate-50 text-slate-700 font-medium">
                      Argo {versionTag}{shortCommit ? ` (${shortCommit})` : ""} · Fedora 45
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
