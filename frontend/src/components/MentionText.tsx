import { Fragment, type ReactNode } from "react";
import {
  AtSign,
  Bookmark,
  Bot as BotIcon,
  FileText,
  Globe,
  KeyRound,
  Lock,
  Mail,
  Paperclip,
  Plug,
  Send,
  Terminal,
  Users,
  Video,
  Webhook,
} from "lucide-react";
import { BotAvatar } from "./BotAvatar";
import type {
  BotRecord,
  IntegrationAccount,
  PageRecord,
  RoomRecord,
  SkillRecord,
  VaultSecretRecord,
  WorkspaceFileRecord,
} from "../types";

export interface MentionCatalog {
  bots: BotRecord[];
  integrations: IntegrationAccount[];
  vaultSecrets: VaultSecretRecord[];
  skills: SkillRecord[];
  rooms?: RoomRecord[];
  pages?: PageRecord[];
  files?: WorkspaceFileRecord[];
}

export interface ResolvedMentionEntity {
  kind: "bot" | "room" | "integration" | "vault" | "skill" | "page" | "file" | "unknown";
  slug: string;
  label: string;
  provider?: string;
  secretType?: string;
  isRecorded?: boolean;
  bot?: BotRecord;
}

export function resolveMentionEntity(
  rawSlug: string,
  catalog?: MentionCatalog | null,
): ResolvedMentionEntity {
  const slug = rawSlug.trim().toLowerCase();
  if (!catalog) {
    return { kind: "unknown", slug, label: `@${slug}` };
  }
  const bot = catalog.bots?.find((b) => b.slug.toLowerCase() === slug);
  if (bot) {
    return { kind: "bot", slug: bot.slug, label: bot.name, bot };
  }
  const room = catalog.rooms?.find((r) => r.slug.toLowerCase() === slug);
  if (room) {
    return { kind: "room", slug: room.slug, label: room.title };
  }
  const vault = catalog.vaultSecrets?.find((v) => v.slug.toLowerCase() === slug);
  if (vault) {
    return {
      kind: "vault",
      slug: vault.slug,
      label: vault.name,
      secretType: vault.secret_type,
    };
  }
  const app = catalog.integrations?.find((a) => a.slug.toLowerCase() === slug);
  if (app) {
    return {
      kind: "integration",
      slug: app.slug,
      label: app.display_name,
      provider: app.provider,
    };
  }
  const skill = catalog.skills?.find((s) => s.slug.toLowerCase() === slug);
  if (skill) {
    const isRecorded = (skill.description ?? "").toLowerCase().includes("recorded");
    return {
      kind: "skill",
      slug: skill.slug,
      label: skill.name,
      isRecorded,
    };
  }
  const page = catalog.pages?.find((p) => p.slug.toLowerCase() === slug);
  if (page) {
    return { kind: "page", slug: page.slug, label: page.title };
  }
  const file = catalog.files?.find(
    (f) => f.filename.toLowerCase() === slug || f.id.toLowerCase() === slug,
  );
  if (file) {
    return { kind: "file", slug: file.filename, label: file.filename };
  }
  return { kind: "unknown", slug, label: `@${slug}` };
}

export function integrationIconComponent(provider: string | undefined) {
  switch ((provider ?? "").toLowerCase()) {
    case "google":
      return Mail;
    case "telegram":
      return Send;
    case "linkedin":
      return Globe;
    case "webhook":
      return Webhook;
    default:
      return Plug;
  }
}

export function vaultSecretIconComponent(secretType: string | undefined) {
  switch ((secretType ?? "").toLowerCase()) {
    case "ssh":
      return Terminal;
    case "login":
      return Globe;
    case "api_token":
      return KeyRound;
    default:
      return Lock;
  }
}

export function skillIconComponent(isRecorded?: boolean) {
  return isRecorded ? Video : Bookmark;
}

const CHIP_CLASS_BY_KIND: Record<ResolvedMentionEntity["kind"], string> = {
  bot: "argo-mention-chip-bot",
  room: "argo-mention-chip-bot",
  integration: "argo-mention-chip-integration",
  vault: "argo-mention-chip-vault",
  skill: "argo-mention-chip-skill",
  page: "argo-mention-chip-integration",
  file: "argo-mention-chip-vault",
  unknown: "argo-mention-chip-unknown",
};

export function InlineMentionBadge({
  token,
  catalog,
  inverted = false,
  onMentionClick,
}: {
  token: string;
  catalog?: MentionCatalog | null;
  inverted?: boolean;
  onMentionClick?: (entity: ResolvedMentionEntity) => void;
}) {
  const cleanSlug = token.startsWith("@") ? token.slice(1) : token;
  const entity = resolveMentionEntity(cleanSlug, catalog);

  let IconComp = AtSign;
  if (entity.kind === "bot") IconComp = BotIcon;
  else if (entity.kind === "room") IconComp = Users;
  else if (entity.kind === "integration") IconComp = integrationIconComponent(entity.provider);
  else if (entity.kind === "vault") IconComp = vaultSecretIconComponent(entity.secretType);
  else if (entity.kind === "skill") IconComp = skillIconComponent(entity.isRecorded);
  else if (entity.kind === "page") IconComp = FileText;
  else if (entity.kind === "file") IconComp = Paperclip;

  const isKnown = entity.kind !== "unknown";
  const displayText = isKnown ? entity.label : `@${cleanSlug}`;
  const cls = inverted
    ? "bg-[#1d3554] text-[#dbeafe] border-[#35547a]"
    : CHIP_CLASS_BY_KIND[entity.kind];
  const interactive = Boolean(
    onMentionClick && (entity.kind === "page" || entity.kind === "bot" || entity.kind === "room"),
  );
  const iconNode =
    entity.kind === "bot" && entity.bot ? (
      <BotAvatar
        icon={entity.bot.avatar_icon}
        color={entity.bot.avatar_color}
        initials={entity.bot.initials}
        size="xs"
      />
    ) : (
      <IconComp className="w-3 h-3 shrink-0 opacity-75" />
    );

  if (interactive) {
    return (
      <button
        type="button"
        onClick={() => onMentionClick?.(entity)}
        title={isKnown ? entity.label : `@${cleanSlug}`}
        className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded-md border text-[12px] font-medium align-baseline mx-0.5 cursor-pointer hover:underline ${
          isKnown ? "" : "font-mono"
        } ${cls}`}
      >
        {iconNode}
        <span>{displayText}</span>
      </button>
    );
  }

  return (
    <span
      title={isKnown ? entity.label : `@${cleanSlug}`}
      className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded-md border text-[12px] font-medium align-baseline mx-0.5 ${
        isKnown ? "" : "font-mono"
      } ${cls}`}
    >
      {iconNode}
      <span>{displayText}</span>
    </span>
  );
}

const MENTION_SPLIT_RE = /(@[a-zA-Z0-9][a-zA-Z0-9._-]*)/g;

export function renderTextWithMentionBadges(
  rawText: string,
  catalog?: MentionCatalog | null,
  keyPrefix = "m",
  inverted = false,
  onMentionClick?: (entity: ResolvedMentionEntity) => void,
): ReactNode[] {
  const parts: ReactNode[] = [];
  let lastIdx = 0;
  const regex = new RegExp(MENTION_SPLIT_RE.source, "g");
  let match: RegExpExecArray | null;
  let seq = 0;

  while ((match = regex.exec(rawText)) !== null) {
    const start = match.index;
    const prevChar = start > 0 ? rawText[start - 1] : "";
    const isValidPrefix = start === 0 || /[\s([{"'`:;,]/.test(prevChar);
    if (!isValidPrefix) {
      continue;
    }
    if (start > lastIdx) {
      parts.push(<Fragment key={`${keyPrefix}-t-${seq++}`}>{rawText.slice(lastIdx, start)}</Fragment>);
    }
    parts.push(
      <InlineMentionBadge
        key={`${keyPrefix}-b-${seq++}`}
        token={match[1]}
        catalog={catalog}
        inverted={inverted}
        onMentionClick={onMentionClick}
      />,
    );
    lastIdx = start + match[1].length;
  }
  if (lastIdx < rawText.length) {
    parts.push(<Fragment key={`${keyPrefix}-tail`}>{rawText.slice(lastIdx)}</Fragment>);
  }
  return parts;
}

const COMPOSER_CLASS_BY_KIND: Record<ResolvedMentionEntity["kind"], string> = {
  bot: "argo-composer-mention argo-composer-mention-bot",
  room: "argo-composer-mention argo-composer-mention-bot",
  integration: "argo-composer-mention argo-composer-mention-integration",
  vault: "argo-composer-mention argo-composer-mention-vault",
  skill: "argo-composer-mention argo-composer-mention-skill",
  page: "argo-composer-mention argo-composer-mention-integration",
  file: "argo-composer-mention argo-composer-mention-vault",
  unknown: "argo-composer-mention argo-composer-mention-unknown",
};

export function renderComposerBackdropNodes(
  rawText: string,
  catalog?: MentionCatalog | null,
): ReactNode[] {
  const parts: ReactNode[] = [];
  let lastIdx = 0;
  const regex = new RegExp(MENTION_SPLIT_RE.source, "g");
  let match: RegExpExecArray | null;
  let seq = 0;

  while ((match = regex.exec(rawText)) !== null) {
    const start = match.index;
    const prevChar = start > 0 ? rawText[start - 1] : "";
    const isValidPrefix = start === 0 || /[\s([{"'`:;,]/.test(prevChar);
    if (!isValidPrefix) {
      continue;
    }
    if (start > lastIdx) {
      parts.push(<Fragment key={`c-t-${seq++}`}>{rawText.slice(lastIdx, start)}</Fragment>);
    }
    const cleanSlug = match[1].slice(1);
    const entity = resolveMentionEntity(cleanSlug, catalog);
    parts.push(
      <span key={`c-m-${seq++}`} className={COMPOSER_CLASS_BY_KIND[entity.kind]}>
        {match[1]}
      </span>,
    );
    lastIdx = start + match[1].length;
  }
  if (lastIdx < rawText.length) {
    parts.push(<Fragment key="c-tail">{rawText.slice(lastIdx)}</Fragment>);
  }
  if (rawText.endsWith("\n")) {
    parts.push(<Fragment key="c-eol">{"\u200b"}</Fragment>);
  }
  return parts;
}

export function HighlightedMessageText({
  text,
  catalog,
  inverted = false,
  onMentionClick,
}: {
  text: string;
  catalog?: MentionCatalog | null;
  inverted?: boolean;
  onMentionClick?: (entity: ResolvedMentionEntity) => void;
}) {
  return (
    <div className="whitespace-pre-wrap break-words">
      {renderTextWithMentionBadges(text, catalog, "msg", inverted, onMentionClick)}
    </div>
  );
}
