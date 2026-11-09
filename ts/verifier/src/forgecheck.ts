/**
 * SPEC 4.24 `opentine.forge-check` (0.48): the unsigned record `tine forge
 * publish` shows on a forge for one commit. A port of
 * `opentine._forge_check.check`: the field rules, the share
 * (`floor(ai_lines * 1000000 / total_lines)`), the conclusion that follows
 * the verify state, and the linked bundle's SHA-256 when its bytes are given.
 * Refusals carry `forge-check.*` codes.
 */

import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";

const KEYS = ["kind", "check_version", "forge", "forge_repo_id", "project_id", "commit", "verify", "ai", "bundle", "overlay", "conclusion"];
const CONCLUSION: Record<string, string> = { verified: "success", failed: "failure", unverified: "neutral" };
const URL_RE = /^https:\/\/[A-Za-z0-9._~:/?#@!$&*+,;=%-]{1,2040}$/;

function no(code: string, message: string): never {
  throw new TineError(message, `forge-check.${code}`);
}

function bad(what: string): never {
  no("malformed", `forge check is malformed: ${what}`);
}

/** A non-negative integer below 2^53 as a number, or null (booleans and floats are not counts). */
function count(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value >= 0n && value < 9007199254740992n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value < 9007199254740992) return value;
  return null;
}

function obj(value: JValue | undefined, keys: string[], what: string): JObject {
  if (!isObject(value) || value.size !== keys.length || !keys.every((k) => value.has(k))) bad(`wrong set of ${what} fields`);
  return value as JObject;
}

function text(value: JValue | undefined, re: RegExp): value is string {
  return typeof value === "string" && re.test(value);
}

function overlay(rows: JValue | undefined): void {
  if (!Array.isArray(rows) || rows.length > 50) bad("overlay is not a list of at most 50 ranges");
  for (const raw of rows as JValue[]) {
    const row = obj(raw, ["path", "start_line", "end_line", "run"], "overlay");
    const path = row.get("path");
    if (typeof path !== "string" || path.length === 0 || path.length > 1024 || path.startsWith("/") ||
        path.includes("\\") || path.includes("\0") || path.split("/").includes("..")) {
      bad("overlay path is not a relative posix path");
    }
    const start = count(row.get("start_line"));
    const end = count(row.get("end_line"));
    if (start === null || end === null || !(start >= 1 && start <= end)) bad("overlay lines are not 1 <= start_line <= end_line");
    const run = row.get("run");
    if (run !== null && !text(run, /^[A-Za-z0-9_.:-]{1,128}$/)) bad("overlay run is not a run id");
  }
}

function shape(check: JValue): JObject {
  if (!isObject(check) || check.get("kind") !== "opentine.forge-check") bad("wrong kind or set of fields");
  const c = check as JObject;
  if (c.size !== KEYS.length || !KEYS.every((k) => c.has(k))) bad("wrong kind or set of fields");
  const version = c.get("check_version");
  if (!(typeof version === "bigint" ? version === 1n : version === 1)) bad("check_version is not 1");
  if (!["github", "gitlab", "forgejo", "entire"].includes(c.get("forge") as string)) bad("unknown forge");
  if (!text(c.get("forge_repo_id"), /^[A-Za-z0-9_.:/-]{1,128}$/)) bad("bad forge_repo_id");
  if (!text(c.get("commit"), /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/)) bad("bad commit");
  const project = c.get("project_id");
  if (project !== null && !text(project, /^[a-z0-9][a-z0-9._-]{0,63}$/)) bad("bad project_id");
  const verify = obj(c.get("verify"), ["state", "runs"], "verify");
  if (!(typeof verify.get("state") === "string" && (verify.get("state") as string) in CONCLUSION) || count(verify.get("runs")) === null) {
    bad("bad verify state or run count");
  }
  const ai = obj(c.get("ai"), ["ai_lines", "total_lines", "share_ppm"], "ai");
  if ([...ai.values()].some((v) => count(v) === null)) bad("ai counts are not non-negative integers");
  const bundle = obj(c.get("bundle"), ["url", "digest"], "bundle");
  const url = bundle.get("url");
  const digest = bundle.get("digest");
  if (digest !== null && !text(digest, /^sha256:[0-9a-f]{64}$/)) bad("bundle digest is not sha256:<64 hex>");
  if (url !== null && !text(url, URL_RE)) bad("bundle url is not an https URL");
  if (url !== null && digest === null) bad("a bundle url without a digest cannot be checked offline");
  overlay(c.get("overlay"));
  if (!["success", "failure", "neutral"].includes(c.get("conclusion") as string)) bad("unknown conclusion");
  return c;
}

export function verifyForgeCheck(check: JValue, bundle: Uint8Array | null): Record<string, unknown> {
  const c = shape(check);
  const ai = c.get("ai") as JObject;
  const lines = count(ai.get("ai_lines")) as number;
  const total = count(ai.get("total_lines")) as number;
  const share = count(ai.get("share_ppm")) as number;
  if (lines > total) no("share-mismatch", "forge check share does not match: more AI lines than lines");
  const want = total === 0 ? 0 : Number((BigInt(lines) * 1000000n) / BigInt(total));
  if (share !== want) no("share-mismatch", "forge check share does not match its line counts");
  const state = (c.get("verify") as JObject).get("state") as string;
  if (c.get("conclusion") !== CONCLUSION[state]) no("conclusion-mismatch", "forge check conclusion does not follow its verify state");
  const digest = (c.get("bundle") as JObject).get("digest");
  let found = digest === null ? "absent" : "unchecked";
  if (bundle !== null) {
    if (digest !== "sha256:" + sha256Hex(bundle)) no("bundle-mismatch", "forge check bundle does not hash to its digest");
    found = "matched";
  }
  return {
    commit: c.get("commit"),
    forge: c.get("forge"),
    forge_repo_id: c.get("forge_repo_id"),
    project_id: c.get("project_id"),
    conclusion: c.get("conclusion"),
    share_ppm: share,
    bundle: found,
  };
}
