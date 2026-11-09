/**
 * "Verify this line's provenance": `tine why FILE:LINE --json` names the commit,
 * the run and the causal slice behind a line; when there is a run,
 * `tine verify RUN --offline --json` checks it with no network. The verdict is
 * the verifier's, reported as it is: this module only words it.
 */

export interface Provenance {
  path: string;
  line: number;
  commit: string;
  run: string;
  steps: number;
  model: string;
}

export interface Verdict {
  ok: boolean;
  verdict: string;
  reason: string;
}

export function whyArgs(path: string, line: number): string[] {
  if (!Number.isInteger(line) || line < 1) throw new Error("lines start at 1");
  return ["why", `${path}:${line}`, "--json"];
}

export function blameArgs(path: string): string[] {
  return ["blame", path, "--lines", "--json"];
}

export function verifyArgs(run: string): string[] {
  if (run.startsWith("-")) throw new Error("a run id never starts with '-'");
  return ["verify", run, "--offline", "--json"];
}

export function parseWhy(document: Record<string, unknown>): Provenance {
  const attribution = document.attribution && typeof document.attribution === "object"
    ? (document.attribution as Record<string, unknown>) : {};
  return {
    path: typeof document.path === "string" ? document.path : "",
    line: typeof document.line === "number" ? document.line : 0,
    commit: typeof document.commit === "string" ? document.commit : "",
    run: typeof document.run === "string" ? document.run : "",
    steps: Array.isArray(document.slice) ? document.slice.length : 0,
    model: typeof attribution.model === "string" ? attribution.model : "",
  };
}

/** The verdict of `tine verify --offline --json` (a `tine-verify-report/2` or the CLI shape). */
export function parseVerdict(document: Record<string, unknown>): Verdict {
  const verdict = typeof document.verdict === "string" ? document.verdict : document.ok === true ? "pass" : "fail";
  const checks = Array.isArray(document.checks) ? (document.checks as Record<string, unknown>[]) : [];
  const failed = checks.find((check) => check && check.outcome === "fail");
  const reason = failed && typeof failed.reason === "string" ? failed.reason : "";
  return { ok: verdict === "pass", verdict, reason };
}

/** One line for a notification. */
export function explain(provenance: Provenance, verdict: Verdict | null): string {
  const where = `${provenance.path}:${provenance.line}`;
  if (!provenance.run) return `${where}: no agent run is linked to this line (human-written, or not attributed).`;
  const by = provenance.model ? ` by ${provenance.model}` : "";
  const head = `${where}: written${by} in run ${provenance.run} (commit ${provenance.commit.slice(0, 12) || "-"}, ${provenance.steps} step(s) in its causal slice)`;
  if (verdict === null) return `${head}; the run is not held here, so it was not verified.`;
  if (verdict.ok) return `${head}; verified offline: ${verdict.verdict}.`;
  return `${head}; verification FAILED${verdict.reason ? ` (${verdict.reason})` : ""}.`;
}
