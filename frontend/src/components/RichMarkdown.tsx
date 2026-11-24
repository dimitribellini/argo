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
const HR_RE = /^\s*(?:---+|\*\*\*+|___+)\s*$/;
const TABLE_SEP_RE = /^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$/;
const isHeading = (s: string) => HEADING_RE.test(s.trim());
const isHorizontalRule = (s: string) => HR_RE.test(s);

function splitTableCells(line: string): string[] {
  const cells: string[] = [];
  let cur = "";
  let inCode = false;
  for (let idx = 0; idx < line.length; idx += 1) {
    const ch = line[idx];
    if (ch === "\\" && idx + 1 < line.length && line[idx + 1] === "|") {
      cur += "|";
      idx += 1;
      continue;
    }
    if (ch === "`") {
      inCode = !inCode;
      cur += ch;
      continue;
    }
    if (ch === "|" && !inCode) {
      cells.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  cells.push(cur.trim());
  if (cells.length > 0 && cells[0] === "" && line.trimStart().startsWith("|")) {
    cells.shift();
  }
  if (cells.length > 0 && cells[cells.length - 1] === "" && line.trimEnd().endsWith("|")) {
    cells.pop();
  }
  return cells;
}

function isTableStart(lines: string[], idx: number): boolean {
  if (idx + 1 >= lines.length) return false;
  const header = lines[idx];
  const sep = lines[idx + 1];
  if (!header.includes("|") || !TABLE_SEP_RE.test(sep)) return false;
  const headerCells = splitTableCells(header);
  const sepCells = splitTableCells(sep);
  return headerCells.length >= 1 && sepCells.length >= 1 && headerCells.length === sepCells.length;
}

function parseTableAlignments(sepLine: string): Array<"left" | "center" | "right"> {
  return splitTableCells(sepLine).map((cell) => {
    const trimmed = cell.trim();
    const startsColon = trimmed.startsWith(":");
    const endsColon = trimmed.endsWith(":");
    if (startsColon && endsColon) return "center";
    if (endsColon) return "right";
    return "left";
  });
}

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
          className="argo-code-block rounded-xl bg-slate-900 text-slate-100 p-3.5 text-xs leading-relaxed font-mono overflow-x-auto border border-slate-700"
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

    // Horizontal rules (---, ***, ___)
    if (isHorizontalRule(line)) {
      blocks.push(<hr key={`b-${blockKey++}`} className="border-t border-slate-200 my-2" />);
      i += 1;
      continue;
    }

    // GFM Tables (| col | col | \n | --- | --- |)
    if (isTableStart(lines, i)) {
      const headers = splitTableCells(lines[i]);
      const alignments = parseTableAlignments(lines[i + 1]);
      i += 2;
      const bodyRows: string[][] = [];
      while (
        i < lines.length &&
        lines[i].trim() !== "" &&
        lines[i].includes("|") &&
        !lines[i].trimStart().startsWith("```") &&
        !isHeading(lines[i]) &&
        !isHorizontalRule(lines[i])
      ) {
        const rowCells = splitTableCells(lines[i]);
        const normalizedRow = headers.map((_, colIdx) => rowCells[colIdx] ?? "");
        bodyRows.push(normalizedRow);
        i += 1;
      }
      const bKey = blockKey++;
      blocks.push(
        <div key={`b-${bKey}`} className="overflow-x-auto rounded-xl border border-slate-200 my-1.5">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {headers.map((h, colIdx) => {
                  const align = alignments[colIdx] ?? "left";
                  const alignCls =
                    align === "center"
                      ? "text-center"
                      : align === "right"
                        ? "text-right"
                        : "text-left";
                  return (
                    <th
                      key={colIdx}
                      className={`px-2.5 py-2 font-semibold text-slate-900 ${alignCls}`}
                    >
                      {renderInline(h, `th-${bKey}-${colIdx}`, catalog)}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 bg-white">
              {bodyRows.map((row, rowIdx) => (
                <tr key={rowIdx} className="hover:bg-slate-50 transition-colors">
                  {row.map((cell, colIdx) => {
                    const align = alignments[colIdx] ?? "left";
                    const alignCls =
                      align === "center"
                        ? "text-center"
                        : align === "right"
                          ? "text-right"
                          : "text-left";
                    return (
                      <td key={colIdx} className={`px-2.5 py-2 text-slate-800 align-top ${alignCls}`}>
                        {renderInline(cell, `td-${bKey}-${rowIdx}-${colIdx}`, catalog)}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
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
          !isHorizontalRule(lines[i]) &&
          !isTableStart(lines, i) &&
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
      const startMatch = /^\s*(\d+)[.)]\s+/.exec(lines[i]);
      const startNum = startMatch ? Math.max(1, Number.parseInt(startMatch[1], 10)) : 1;
      const items: string[][] = [];
      while (i < lines.length && isOrdered(lines[i])) {
        items.push([lines[i].replace(/^\s*\d+[.)]\s+/, "")]);
        i += 1;
      }
      blocks.push(
        <ol key={`b-${blockKey++}`} start={startNum} className="list-decimal pl-5 space-y-1.5">
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
      !isHorizontalRule(lines[i]) &&
      !isTableStart(lines, i) &&
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
