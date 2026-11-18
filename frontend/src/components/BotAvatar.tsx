import {
  Bot,
  Globe,
  Layers,
  Mail,
  PenTool,
  Rss,
  Send,
  ShieldCheck,
  Sparkles,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { avatarColorClass } from "../utils/format";

export const BOT_ICON_OPTIONS: Array<{
  key: string;
  label: string;
  Icon: LucideIcon;
}> = [
  { key: "bot", label: "Bot", Icon: Bot },
  { key: "mail", label: "Mail", Icon: Mail },
  { key: "rss", label: "Feed", Icon: Rss },
  { key: "pen", label: "Writer", Icon: PenTool },
  { key: "shield", label: "Supervisor", Icon: ShieldCheck },
  { key: "send", label: "Messenger", Icon: Send },
  { key: "globe", label: "Browser", Icon: Globe },
  { key: "sparkles", label: "Assistant", Icon: Sparkles },
  { key: "zap", label: "Trigger", Icon: Zap },
  { key: "layers", label: "Pipeline", Icon: Layers },
];

const ICON_BY_KEY = new Map(BOT_ICON_OPTIONS.map((item) => [item.key, item.Icon]));

export type BotStatusDot =
  | "running"
  | "waiting_approval"
  | "takeover_needed"
  | "paused"
  | "desktop"
  | "active"
  | null;

interface BotAvatarProps {
  icon?: string;
  color?: string;
  initials?: string;
  size?: "xs" | "sm" | "md" | "lg";
  statusDot?: BotStatusDot;
  ringClassName?: string;
}

const SIZE_CLASSES: Record<"xs" | "sm" | "md" | "lg", { box: string; icon: string; dot: string }> = {
  xs: { box: "w-5 h-5 rounded-md text-[9px]", icon: "w-3 h-3", dot: "w-1.5 h-1.5 -bottom-0.5 -right-0.5" },
  sm: { box: "w-7 h-7 rounded-lg text-[10px]", icon: "w-3.5 h-3.5", dot: "w-2 h-2 -bottom-0.5 -right-0.5" },
  md: { box: "w-8 h-8 rounded-xl text-[11px]", icon: "w-4 h-4", dot: "w-2.5 h-2.5 -bottom-0.5 -right-0.5" },
  lg: { box: "w-11 h-11 rounded-2xl text-sm", icon: "w-5 h-5", dot: "w-3 h-3 -bottom-0.5 -right-0.5" },
};

const DOT_COLOR: Record<Exclude<BotStatusDot, null>, string> = {
  running: "bg-[#3b72b2]",
  waiting_approval: "bg-[#c98a2c]",
  takeover_needed: "bg-[#c24b4b]",
  paused: "bg-slate-400",
  desktop: "bg-[#43536b]",
  active: "bg-[#3b8c62]",
};

export function BotAvatar({
  icon = "bot",
  color = "slate",
  initials = "B",
  size = "md",
  statusDot = null,
  ringClassName = "ring-2 ring-[var(--argo-sidebar)]",
}: BotAvatarProps) {
  const IconComp = ICON_BY_KEY.get((icon ?? "bot").toLowerCase()) ?? Bot;
  const dims = SIZE_CLASSES[size];

  return (
    <div
      className={`${dims.box} ${avatarColorClass(color)} font-semibold flex items-center justify-center shrink-0 relative`}
    >
      {icon === "initials" ? <span>{initials}</span> : <IconComp className={dims.icon} />}
      {statusDot && (
        <span
          className={`${dims.dot} ${DOT_COLOR[statusDot]} rounded-full ${ringClassName} absolute`}
        />
      )}
    </div>
  );
}
