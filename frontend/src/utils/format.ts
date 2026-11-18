export function formatFriendlyTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return iso;

  const now = new Date();
  const diffSec = Math.floor((now.getTime() - dt.getTime()) / 1000);
  if (diffSec >= 0 && diffSec < 60) return "Just now";
  if (diffSec >= 60 && diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;

  const hhmm = dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  const sameDay =
    dt.getFullYear() === now.getFullYear() &&
    dt.getMonth() === now.getMonth() &&
    dt.getDate() === now.getDate();
  if (sameDay) return `Today, ${hhmm}`;

  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  const isYesterday =
    dt.getFullYear() === yesterday.getFullYear() &&
    dt.getMonth() === yesterday.getMonth() &&
    dt.getDate() === yesterday.getDate();
  if (isYesterday) return `Yesterday, ${hhmm}`;

  const dateLabel = dt.toLocaleDateString([], { month: "short", day: "numeric" });
  return `${dateLabel}, ${hhmm}`;
}

export function friendlyModelName(modelId: string | null | undefined): string {
  const raw = (modelId ?? "").trim();
  if (!raw) return "Default Model";
  const known: Record<string, string> = {
    "google:gemini-3.8-flash": "Gemini 3.8 Flash",
    "google:gemini-4-argon": "Gemini 4 Argon",
    "xai:grok-4": "Grok 4",
    "xai:grok-3": "Grok 3",
    "anthropic:claude-4.5-sonnet": "Claude 4.5 Sonnet",
    "openai:gpt-5-mini": "GPT-5 Mini",
    "openai:gpt-5": "GPT-5",
  };
  if (known[raw]) return known[raw];
  const [, namePart = raw] = raw.includes(":") ? raw.split(":", 2) : ["", raw];
  return namePart
    .split(/[-_/]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function friendlyAutonomyLabel(rbac: "internal" | "draft" | "execute" | string): string {
  if (rbac === "internal") return "Read only";
  if (rbac === "draft") return "Ask before sending";
  if (rbac === "execute") return "Auto-send";
  return rbac;
}

export function avatarColorClass(color: string | undefined): string {
  switch ((color ?? "slate").toLowerCase()) {
    case "emerald":
      return "bg-[#2f6b52] text-white";
    case "blue":
      return "bg-[#2b5278] text-white";
    case "indigo":
      return "bg-[#43536b] text-white";
    case "amber":
      return "bg-[#84592b] text-white";
    case "rose":
      return "bg-[#7d3c45] text-white";
    case "violet":
      return "bg-[#55506b] text-white";
    default:
      return "bg-slate-700 text-white border border-slate-600";
  }
}

export function formatBotSystemText(text: string): string {
  const trimmed = (text ?? "").trim();
  if (/^registered declaratively under\b/i.test(trimmed)) {
    return "Ready! Ask me to run a task, check your connected apps, or adjust my schedule.";
  }
  return text;
}

export function friendlyActionStepLabel(
  actionType: string,
  status?: string,
): { label: string; outcome: string } {
  const typeMap: Record<string, string> = {
    gmail_search: "Searched Gmail",
    create_draft: "Saved Gmail draft",
    gmail_draft: "Saved Gmail draft",
    send_email: "Email draft prepared",
    reply_email: "Email reply prepared",
    fetch_rss_feed: "Checked RSS feed",
    fetch_public_webpage: "Read webpage",
    fetch_telegram_public_channel: "Checked Telegram channel",
    upsert_document: "Saved items",
    publish_telegram: "Telegram message",
    send_telegram: "Telegram message",
    publish_linkedin: "LinkedIn post",
    linkedin_post: "LinkedIn post",
    request_human_approval: "Queued for your review",
    notify_approval: "Sent approval notification",
    upsert_page: "Updated Page",
    open_page: "Opened Living Board",
    configure_routine: "Updated schedule",
    update_self_config: "Updated bot configuration",
    propose_delegation_plan: "Proposed multi-bot plan",
    list_workspace_files: "Listed workspace files",
    read_workspace_file: "Read workspace file",
    write_workspace_file: "Saved workspace file",
    remember_rule: "Saved writing rule",
    save_skill: "Saved reusable skill",
    delegate_to_bot: "Delegated to another bot",
    propose_specialist_bot: "Proposed new specialist bot",
    propose_fleet_cleanup: "Proposed bot cleanup",
    desktop_browse: "Browsed in Virtual Desktop",
    desktop_inspect: "Inspected Virtual Desktop",
    desktop_screenshot: "Captured Virtual Desktop screenshot",
    desktop_check_app: "Checked desktop application",
    desktop_launch: "Launched desktop application",
    desktop_focus_window: "Switched desktop window",
    desktop_click: "Clicked in Virtual Desktop",
    desktop_type: "Typed in Virtual Desktop",
    desktop_key: "Sent key in Virtual Desktop",
    desktop_scroll: "Scrolled in Virtual Desktop",
    desktop_exec: "Ran command in Virtual Desktop",
  };
  const statusMap: Record<string, string> = {
    ok: "Done",
    queued_approval: "Waiting for review",
    executed: "Sent",
    blocked_unlinked_account: "App not linked",
    blocked_rbac: "Blocked by permission",
    blocked_collection_acl: "Blocked by list permission",
    halted_takeover_required: "Login needed",
    halted_hop_limit: "Stopped at loop limit",
    skipped_disabled: "Skipped (paused)",
    command_failed: "Failed (non-zero exit)",
    timeout: "Timed out",
  };
  const key = (actionType ?? "").trim().toLowerCase();
  const label =
    typeMap[key] ??
    (key ? key.replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase()) : "Completed step");
  const stKey = (status ?? "").trim().toLowerCase();
  const outcome = statusMap[stKey] ?? (stKey ? stKey.replaceAll("_", " ") : "Done");
  return { label, outcome };
}

export function friendlyApprovalChannel(actionType: string, targetSlug: string): string {
  const key = (actionType ?? "").trim().toLowerCase();
  const map: Record<string, string> = {
    publish_telegram: "Telegram Message",
    send_telegram: "Telegram Message",
    send_email: "Email Reply",
    reply_email: "Email Reply",
    create_draft: "Email Draft",
    gmail_draft: "Email Draft",
    publish_linkedin: "LinkedIn Post",
    linkedin_post: "LinkedIn Post",
    create_specialist_bot: "New Bot Proposal",
    fleet_cleanup: "Bot Cleanup Proposal",
    update_bot_config: "Bot Configuration Proposal",
  };
  if (map[key]) return map[key];
  if (targetSlug === "argo_workspace") return "Workspace Change";
  return (key || "Outbound Action")
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function cleanEscalationNote(note: string | null | undefined): string | null {
  const trimmed = (note ?? "").trim();
  if (!trimmed) return null;
  if (
    /connector rbac is set to/i.test(trimmed) ||
    /explicit request_human_approval escalation/i.test(trimmed) ||
    /proposed by .* for human confirmation/i.test(trimmed)
  ) {
    return null;
  }
  return trimmed;
}

export interface DiffToken {
  type: "same" | "add" | "del";
  text: string;
}

export function computeWordDiff(beforeText: string, afterText: string): DiffToken[] {
  const a = beforeText.split(/(\s+)/);
  const b = afterText.split(/(\s+)/);
  const m = a.length;
  const n = b.length;

  if (m * n > 25000) {
    return [
      { type: "del", text: beforeText },
      { type: "add", text: afterText },
    ];
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i -= 1) {
    for (let j = n - 1; j >= 0; j -= 1) {
      if (a[i] === b[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const tokens: DiffToken[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      tokens.push({ type: "same", text: a[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      tokens.push({ type: "del", text: a[i] });
      i += 1;
    } else {
      tokens.push({ type: "add", text: b[j] });
      j += 1;
    }
  }
  while (i < m) {
    tokens.push({ type: "del", text: a[i] });
    i += 1;
  }
  while (j < n) {
    tokens.push({ type: "add", text: b[j] });
    j += 1;
  }
  return tokens;
}
