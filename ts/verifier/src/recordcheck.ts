/**
 * One signed record dropped into a viewer, checked by its `kind` (0.51): the
 * 0.46-0.50 record families the Python verifier and `tine-verify.pyz` check
 * (reviews, review bundles, merge records and approvals, eval verdicts,
 * prompts, memory notes, review findings, forge checks, tombstones, redacted
 * copies, projects), each with the same function the conformance vectors
 * pin. No key is pinned in a viewer: an Ed25519 record that holds under its
 * embedded key reads `pass` with state `verified-tofu`; an HMAC record, or one
 * whose check needs context the file does not carry (a review gate's
 * version, a forge claim's branch and project, a VSA's policy), reads
 * `unchecked` with the reason, never `pass`.
 */

import { TineError } from "./errors.js";
import { verifyEvalVerdict } from "./evalverdict.js";
import { verifyReviewFinding } from "./finding.js";
import { verifyForgeCheck } from "./forgecheck.js";
import { isObject, KERNEL, parseBytes, type JObject, type JValue } from "./json.js";
import { verifyMerge, verifyMergeApproval } from "./merge.js";
import { verifyProject } from "./project.js";
import { verifyRedactedCopy, verifyTombstone } from "./records.js";
import { verifyMemory, verifyPrompt } from "./registry.js";
import { verifyReview, verifyReviewBundle } from "./review.js";

export interface RecordCheck {
  kind: string;
  state: "pass" | "fail" | "unchecked";
  reason: string;
  result: Record<string, unknown> | null;
}

type Checker = (record: JValue) => Record<string, unknown>;

const CHECKERS: Record<string, Checker> = {
  "opentine.review": (r) => verifyReview(r),
  "opentine.review-bundle": (r) => verifyReviewBundle(r),
  "opentine.merge": (r) => verifyMerge(r),
  "opentine.merge-approval": (r) => verifyMergeApproval(r),
  "opentine.prompt": (r) => verifyPrompt(r),
  "opentine.memory": (r) => verifyMemory(r),
  "opentine.review-finding": (r) => verifyReviewFinding(r),
  "opentine.forge-check": (r) => verifyForgeCheck(r, null),
  "opentine.tombstone": (r) => ({ ...verifyTombstone(r) }),
  "opentine.redacted-copy": (r) => ({ ...verifyRedactedCopy(r) }),
  "opentine.project": (r) => ({ ...verifyProject(r) }),
  "tine-eval-verdict/1": (r) => ({ ...verifyEvalVerdict(r) }),
};

/** Families whose check needs inputs a single file does not carry. */
const NEEDS: Record<string, string> = {
  "opentine.review-gate": "a review-gate decision is checked against the review version it decides (drop the review bundle)",
  "opentine.forge-claim": "a forge claim is checked against its branch and project records",
  "application/vnd.in-toto+json": "an admission VSA is checked against a pinned key, subject and policy (`tine admission verify`)",
};

const plain = (value: unknown): unknown =>
  typeof value === "bigint" ? Number(value) : Array.isArray(value) ? value.map(plain) : value instanceof Map ? Object.fromEntries([...value].map(([k, v]) => [k, plain(v)])) : value;

function kindOf(value: JValue): string {
  if (!isObject(value)) return "";
  const object = value as JObject;
  for (const key of ["kind", "scheme", "payloadType"]) {
    const found = object.get(key);
    if (typeof found === "string") return found;
  }
  return "";
}

export function recordKinds(): string[] {
  return [...Object.keys(CHECKERS), ...Object.keys(NEEDS)].sort();
}

/** Check one record's JSON bytes; never throws. */
export function verifyRecordBytes(raw: Uint8Array): RecordCheck {
  let value: JValue;
  try {
    value = parseBytes(raw, KERNEL, "record");
  } catch (exc) {
    return { kind: "", state: "fail", reason: `not a JSON record: ${(exc as Error).message}`, result: null };
  }
  return verifyRecord(value);
}

export function verifyRecord(value: JValue): RecordCheck {
  const kind = kindOf(value);
  if (NEEDS[kind]) return { kind, state: "unchecked", reason: NEEDS[kind], result: null };
  const checker = CHECKERS[kind];
  if (!checker) return { kind, state: "unchecked", reason: kind ? `no browser check for ${kind}` : "not a known OpenTine record", result: null };
  try {
    const result = plain(checker(value)) as Record<string, unknown>;
    const state = typeof result.state === "string" ? result.state : "verified";
    return { kind, state: "pass", reason: state === "verified-tofu" ? "holds under its embedded key (unpinned)" : state, result };
  } catch (exc) {
    const code = exc instanceof TineError ? exc.code : "error";
    if (code.endsWith(".no-key")) return { kind, state: "unchecked", reason: `${code}: an HMAC record needs the signer's key`, result: null };
    return { kind, state: "fail", reason: `${code}: ${(exc as Error).message}`, result: null };
  }
}
