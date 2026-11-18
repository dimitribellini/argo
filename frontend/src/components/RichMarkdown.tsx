import { Fragment, type ReactNode } from "react";
import { renderTextWithMentionBadges, type MentionCatalog } from "./MentionText";

interface RichMarkdownProps {
  text: string;
  className?: string;
  catalog?: MentionCatalog | null;
}

const INLINE_TOKEN_RE =
  /(\[[^\]]+\]\(https?:\/\/[^\s)]+\)|\*\*[^*\n]+?\*\*|\*[^*\n]+?\*|`[^`\n]+?`|https?:\/\/[^\s<>()]+[^\s<>().,;:!?'"])/g;
const HEADING_RE = /^(#{1,6})\s+(.+)$/;
const isHeading = (s: string) => HEADING_RE.test(s.trim());

function renderInline(
  line: string,
  keyPrefix: string,
  catalog?: MentionCatalog | null,
): ReactNode[] {
  const nodes: ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  const regex = new RegExp(INLINE_TOKEN_RE.source, "g");

  let tokenIdx = 0;
  let segIdx = 0;
  while ((match = regex.exec(line)) !== null) {
    if (match.index > lastIndex) {
      const plain = line.slice(lastIndex, match.index);
      if (catalog) {
        nodes.push(...renderTextWithMentionBadges(plain, catalog, `${keyPrefix}-seg-${segIdx++}`));
      } else {
        nodes.push(plain);
      }
    }
    const token = match[0];
    const key = `${keyPrefix}-${tokenIdx++}`;

    if (token.startsWith("[")) {
      const linkMatch = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(token);
      if (linkMatch) {
        nodes.push(
          <a
            key={key}
            href={linkMatch[2]}
            target="_blank"
            rel="noreferrer"
            className="text-blue-700 underline underline-offset-2 hover:text-blue-800 break-all"
          >
            {linkMatch[1]}
          </a>,
        );
      } else {
        nodes.push(token);
      }
    } else if (token.startsWith("**") && token.endsWith("**")) {
      const inner = token.slice(2, -2);
      nodes.push(
        <strong key={key} className="font-semibold text-slate-900">
          {catalog ? renderTextWithMentionBadges(inner, catalog, `${key}-b`) : inner}
        </strong>,
      );
    } else if (token.startsWith("*") && token.endsWith("*")) {
      const inner = token.slice(1, -1);
      nodes.push(
        <em key={key} className="italic text-slate-800">
          {catalog ? renderTextWithMentionBadges(inner, catalog, `${key}-em`) : inner}
        </em>,
      );
    } else if (token.startsWith("`") && token.endsWith("`")) {
      nodes.push(
        <code
          key={key}
          className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[11px] font-mono text-slate-900"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else if (token.startsWith("http://") || token.startsWith("https://")) {
      nodes.push(
        <a
          key={key}
          href={token}
          target="_blank"
          rel="noreferrer"
          className="text-sky-600 underline underline-offset-2 hover:text-sky-500 break-all"
        >
          {token}
        </a>,
      );
    } else {
      nodes.push(token);
    }

    lastIndex = match.index + token.length;
  }

  if (lastIndex < line.length) {
    const tail = line.slice(lastIndex);
    if (catalog) {
      nodes.push(...renderTextWithMentionBadges(tail, catalog, `${keyPrefix}-tail`));
    } else {
      nodes.push(tail);
    }
  }
  return nodes;
}

export function RichMarkdown({ text, className = "", catalog }: RichMarkdownProps) {
  const raw = (text ?? "").replace(/\r\n/g, "\n");
  if (!raw.trim()) return null;

  const lines = raw.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let blockKey = 0;
  const isBullet = (s: string) => /^\s*(?:[-*•])\s+/.test(s);
  const isOrdered = (s: string) => /^\s*\d+[.)]\s+/.test(s);

  while (i < lines.length) {
    const prevIdx = i;
    const line = lines[i];

    // Fenced code blocks
    if (line.trimStart().startsWith("```")) {
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trimStart().startsWith("```")) {
        codeLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length) i += 1;
      blocks.push(
        <pre
          key={`b-${blockKey++}`}
          className="rounded-xl bg-slate-900 text-slate-100 p-3.5 text-xs leading-relaxed font-mono overflow-x-auto border border-slate-700"
        >
          <code>{codeLines.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    if (!line.trim()) {
      i += 1;
      continue;
    }

    // Headings (# through ######)
    const headingMatch = HEADING_RE.exec(line.trim());
    if (headingMatch) {
      const level = headingMatch[1].length;
      const cls =
        level === 1
          ? "text-sm font-semibold text-slate-900"
          : level <= 3
            ? "text-[13px] font-semibold text-slate-900"
            : "text-xs font-semibold text-slate-800";
      blocks.push(
        <div key={`b-${blockKey++}`} className={cls}>
          {renderInline(headingMatch[2], `h-${blockKey}`, catalog)}
        </div>,
      );
      i += 1;
      continue;
    }

    // Blockquotes
    if (line.trimStart().startsWith("> ")) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].trimStart().startsWith("> ")) {
        quoteLines.push(lines[i].trimStart().slice(2));
        i += 1;
      }
      blocks.push(
        <blockquote
          key={`b-${blockKey++}`}
          className="border-l-2 border-slate-300 pl-3 text-slate-600 space-y-1"
        >
          {quoteLines.map((ql, idx) => (
            <div key={idx}>{renderInline(ql, `q-${blockKey}-${idx}`, catalog)}</div>
          ))}
        </blockquote>,
      );
      continue;
    }

    // Bullet lists (grouping indented or bold-field continuation lines cleanly)
    if (isBullet(line)) {
      const items: string[][] = [];
      while (i < lines.length) {
        if (isBullet(lines[i])) {
          items.push([lines[i].replace(/^\s*(?:[-*•])\s+/, "")]);
          i += 1;
        } else if (
          items.length > 0 &&
          lines[i].trim() !== "" &&
          !isHeading(lines[i]) &&
          !lines[i].trimStart().startsWith("```") &&
          !isOrdered(lines[i]) &&
          (/^\s{2,}/.test(lines[i]) || /^\*\*/.test(lines[i].trimStart()))
        ) {
          items[items.length - 1].push(lines[i].trim());
          i += 1;
        } else {
          break;
        }
      }
      blocks.push(
        <ul key={`b-${blockKey++}`} className="list-disc pl-5 space-y-1.5">
          {items.map((itemLines, idx) => (
            <li key={idx} className="leading-relaxed">
              {itemLines.map((il, lineIdx) => (
                <Fragment key={lineIdx}>
                  {lineIdx > 0 && <br />}
                  {renderInline(il, `ul-${blockKey}-${idx}-${lineIdx}`, catalog)}
                </Fragment>
              ))}
            </li>
          ))}
        </ul>,
      );
      continue;
    }

    // Numbered lists
    if (isOrdered(line)) {
      const items: string[][] = [];
      while (i < lines.length && isOrdered(lines[i])) {
        items.push([lines[i].replace(/^\s*\d+[.)]\s+/, "")]);
        i += 1;
      }
      blocks.push(
        <ol key={`b-${blockKey++}`} className="list-decimal pl-5 space-y-1.5">
          {items.map((itemLines, idx) => (
            <li key={idx} className="leading-relaxed">
              {renderInline(itemLines[0], `ol-${blockKey}-${idx}`, catalog)}
            </li>
          ))}
        </ol>,
      );
      continue;
    }

    // Standard paragraph block
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].trimStart().startsWith("```") &&
      !isHeading(lines[i]) &&
      !lines[i].trimStart().startsWith("> ") &&
      !isBullet(lines[i]) &&
      !isOrdered(lines[i])
    ) {
      paraLines.push(lines[i]);
      i += 1;
    }
    if (paraLines.length === 0) {
      paraLines.push(lines[prevIdx]);
      i = prevIdx + 1;
    }
    blocks.push(
      <p key={`b-${blockKey++}`} className="leading-relaxed">
        {paraLines.map((pl, idx) => (
          <Fragment key={idx}>
            {idx > 0 && <br />}
            {renderInline(pl, `p-${blockKey}-${idx}`, catalog)}
          </Fragment>
        ))}
      </p>,
    );
    if (i <= prevIdx) {
      i = prevIdx + 1;
    }
  }

  return <div className={`space-y-2 ${className}`}>{blocks}</div>;
}
