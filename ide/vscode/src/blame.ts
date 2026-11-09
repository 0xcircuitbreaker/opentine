/**
 * The AI-blame gutter, from `tine blame FILE --lines --json` (`tine-blame/1`,
 * the per-line shape): one row per line, `ai` set when the attribution notes
 * name the run (and step and model) that wrote it. Pure functions, so they are
 * tested without an editor.
 */

export interface AiAttribution {
  run: string;
  seq: number | null;
  model: string;
}

export interface BlameLine {
  line: number;
  commit: string;
  author: string;
  summary: string;
  ai: AiAttribution | null;
}

export interface BlameRecord {
  path: string;
  revision: string;
  totalLines: number;
  aiLines: number;
  lines: BlameLine[];
}

export interface GutterRow {
  /** 0-based, as editors count. */
  index: number;
  label: string;
  hover: string;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** The per-line `tine-blame/1` record; refuses the other shape or another schema. */
export function parseBlame(document: Record<string, unknown>): BlameRecord {
  if (document.schema !== "tine-blame/1" || !Array.isArray(document.lines)) {
    throw new Error("not a `tine blame --lines --json` record (tine-blame/1)");
  }
  const lines: BlameLine[] = [];
  for (const raw of document.lines as unknown[]) {
    if (typeof raw !== "object" || raw === null) continue;
    const row = raw as Record<string, unknown>;
    const ai = row.ai && typeof row.ai === "object" ? (row.ai as Record<string, unknown>) : null;
    if (typeof row.line !== "number" || row.line < 1) continue;
    lines.push({
      line: row.line,
      commit: str(row.commit),
      author: str(row.author),
      summary: str(row.summary),
      ai: ai ? { run: str(ai.run), seq: typeof ai.seq === "number" ? ai.seq : null, model: str(ai.model) } : null,
    });
  }
  return {
    path: str(document.path),
    revision: str(document.revision),
    totalLines: typeof document.total_lines === "number" ? document.total_lines : lines.length,
    aiLines: typeof document.ai_lines === "number" ? document.ai_lines : lines.filter((l) => l.ai).length,
    lines,
  };
}

/** A run id shortened for a gutter: the digest's first 12 hex digits. */
export function shortRun(run: string): string {
  const hex = run.includes(":sha256:") ? run.slice(run.indexOf(":sha256:") + 8) : run;
  return hex.slice(0, 12);
}

/** One gutter row per AI-written line; human lines get none. */
export function gutterRows(record: BlameRecord): GutterRow[] {
  return record.lines
    .filter((line) => line.ai !== null)
    .map((line) => {
      const ai = line.ai as AiAttribution;
      const step = ai.seq === null ? "" : ` step ${ai.seq}`;
      return {
        index: line.line - 1,
        label: `AI ${ai.model || "agent"} ${shortRun(ai.run)}`.trim(),
        hover: [
          `**AI-written** by \`${ai.model || "an agent"}\``,
          `run \`${ai.run}\`${step}`,
          `commit \`${line.commit.slice(0, 12)}\` by ${line.author || "?"}: ${line.summary}`,
          "Run **OpenTine: Verify this line's provenance** to check it offline.",
        ].join("\n\n"),
      };
    });
}

/** "12 of 40 lines AI-written (30%)". */
export function aiShare(record: BlameRecord): string {
  const total = record.totalLines;
  const percent = total === 0 ? 0 : Math.round((100 * record.aiLines) / total);
  return `${record.aiLines} of ${total} lines AI-written (${percent}%)`;
}
