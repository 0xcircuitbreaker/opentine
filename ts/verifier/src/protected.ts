/**
 * 0.60: the protected-surfaces check of a self-improving agent loop, a port of
 * `opentine._integrity.check`. It judges one run's observations (the files its
 * tool calls touched, the current digest of every pinned file) against a
 * parsed protected list and answers tests/data/integrity_check.json exactly as
 * the Python reference does. `fail:protected-surface-modified` is a hash fact
 * and blocks; `advisory:` codes never block by default (owner decision D12).
 * These are `tine integrity` codes: `tine verify` is unchanged.
 */

export const MODIFIED = "fail:protected-surface-modified";
export const TEST_DELETED = "advisory:test-deleted";
export const HOLDOUT_READ = "advisory:holdout-read";

export interface Surface {
  name: string;
  kind: "grader" | "test" | "holdout" | "sandbox" | "scorer";
  globs: string[];
  pins: Record<string, string>;
}

export interface Protected {
  version: 1;
  surfaces: Surface[];
}

export interface Touched {
  path: string;
  op: "write" | "delete" | "read";
  step?: string;
}

export interface Observations {
  touched?: Touched[];
  digests?: Record<string, string | null>;
}

export interface ProtectedFinding {
  level: "fail" | "advisory";
  code: string;
  surface: string;
  path: string;
  detail: string;
}

export function normalize(path: string): string {
  return path
    .replace(/\\/g, "/")
    .split("/")
    .filter((p) => p !== "" && p !== ".")
    .join("/");
}

function escape(ch: string): string {
  return /[A-Za-z0-9_]/.test(ch) ? ch : `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`;
}

/** `**` spans directories, `*` and `?` stay inside one; nothing else is special. */
export function globRegex(pattern: string): RegExp {
  const out: string[] = [];
  let i = 0;
  while (i < pattern.length) {
    if (pattern.startsWith("**/", i)) {
      out.push("(?:.*/)?");
      i += 3;
    } else if (pattern.startsWith("**", i)) {
      out.push(".*");
      i += 2;
    } else if (pattern[i] === "*") {
      out.push("[^/]*");
      i += 1;
    } else if (pattern[i] === "?") {
      out.push("[^/]");
      i += 1;
    } else {
      out.push(escape(pattern[i]));
      i += 1;
    }
  }
  return new RegExp(`^${out.join("")}$`, "su");
}

export function matches(pattern: string, path: string): boolean {
  return globRegex(normalize(pattern)).test(normalize(path));
}

export function surfacesOf(list: Protected, path: string): Surface[] {
  const p = normalize(path);
  return list.surfaces.filter((s) => p in s.pins || s.globs.some((g) => matches(g, p)));
}

function cmp(a: string[], b: string[]): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/** Findings, sorted by (code, path, surface, detail) and de-duplicated. */
export function checkProtected(list: Protected, observations: Observations): ProtectedFinding[] {
  const found = new Map<string, { key: string[]; row: ProtectedFinding }>();
  const add = (code: string, surface: string, path: string, detail: string): void => {
    const key = [code, path, surface, detail];
    const level = code.split(":", 1)[0] as "fail" | "advisory";
    found.set(JSON.stringify(key), { key, row: { level, code, surface, path, detail } });
  };
  const digests = observations.digests ?? {};
  for (const surface of list.surfaces) {
    for (const [path, pin] of Object.entries(surface.pins)) {
      if (!Object.prototype.hasOwnProperty.call(digests, path)) continue;
      const now = digests[path];
      if (now === null) add(MODIFIED, surface.name, path, "pinned file is missing");
      else if (now !== pin) add(MODIFIED, surface.name, path, `sha256 ${now} is not the pin ${pin}`);
    }
  }
  for (const row of observations.touched ?? []) {
    const path = normalize(row.path);
    const step = String(row.step ?? "");
    for (const surface of surfacesOf(list, path)) {
      if (row.op === "write" || row.op === "delete") add(MODIFIED, surface.name, path, `${row.op} tool call at step ${step}`);
      if (row.op === "delete" && surface.kind === "test") add(TEST_DELETED, surface.name, path, `test deleted at step ${step}`);
      if (row.op === "read" && surface.kind === "holdout") add(HOLDOUT_READ, surface.name, path, `holdout read at step ${step}`);
    }
  }
  return [...found.values()].sort((a, b) => cmp(a.key, b.key)).map((v) => v.row);
}

/** Every `fail:`; `advisory:` only when strict (D12). */
export function blockingFindings(findings: ProtectedFinding[], strict = false): ProtectedFinding[] {
  return findings.filter((f) => f.level === "fail" || (strict && f.level === "advisory"));
}
