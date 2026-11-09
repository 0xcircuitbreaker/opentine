/**
 * SPEC 4.25 `opentine.review-finding` (one reviewer's signed finding on a
 * Review), 0.48. A port of `opentine._review_finding.check`: exactly the
 * kind's fields, then a `tine-sig/3` Ed25519 block over
 * `opentine.review-finding.v1:` + JCS of `{"body", "header"}` (under the pinned
 * key or, without one, the embedded key: trust on first use), then, given the
 * Review's reviewers, the signer must be one. Refusals carry `review-finding.*`.
 */

import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { projectDigest, signedBy } from "./project.js";

const FIELDS = ["kind", "finding_version", "review_id", "finding_id", "severity", "path", "line", "message", "reviewer", "run", "created_at"];
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const PATH = /^[A-Za-z0-9_.@+-][A-Za-z0-9_.@+/ -]{0,1023}$/;
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const WHEN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/;
const encoder = new TextEncoder();

function refuse(code: string, message: string): never {
  throw new TineError(message, code);
}

function int(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value >= 0n && value < 2n ** 53n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  return null;
}

function is(value: JValue | undefined, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function pathOk(value: JValue | undefined): boolean {
  return is(value, PATH) && value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

function textOk(value: JValue | undefined): boolean {
  return typeof value === "string" && value.trim() !== "" && encoder.encode(value).length <= 1024 && !CONTROL.test(value);
}

function fields(record: JValue): JObject {
  if (!isObject(record) || record.get("kind") !== "opentine.review-finding") {
    refuse("review-finding.malformed", "review finding is malformed: kind is not opentine.review-finding");
  }
  const object = record as JObject;
  const keys = [...object.keys()];
  if (keys.some((key) => key !== "signature" && !FIELDS.includes(key)) || FIELDS.some((key) => !object.has(key))) {
    refuse("review-finding.malformed", "review finding is malformed: wrong set of fields");
  }
  return new Map(FIELDS.map((name) => [name, object.get(name) as JValue]));
}

/** Verify one review finding under `publicKey`, the Review's `reviewers` (hex keys), or its embedded key. */
export function verifyReviewFinding(record: JValue, publicKey: Uint8Array | null = null, reviewers: JValue = []): Record<string, unknown> {
  const found = fields(record);
  const path = found.get("path") ?? null;
  const line = found.get("line") ?? null;
  const lineNumber = int(line);
  const run = found.get("run") ?? null;
  const checks: [boolean, string][] = [
    [int(found.get("finding_version")) === 1, "finding_version is 1"],
    [is(found.get("review_id"), ID) && is(found.get("finding_id"), ID), "review_id and finding_id are ids"],
    [SEVERITIES.includes(found.get("severity") as string), "severity is info, low, medium, high or critical"],
    [path === null || pathOk(path), "path is a repository-relative POSIX path or null"],
    [line === null || (lineNumber !== null && lineNumber >= 1 && lineNumber <= 2 ** 31 - 1 && path !== null), "line counts from 1, with a path, or is null"],
    [textOk(found.get("message")), "message is 1 to 1024 bytes of text"],
    [is(found.get("reviewer"), NAME), "reviewer must be a name"],
    [run === null || is(run, RUN), "run is a run oid or null"],
    [is(found.get("created_at"), WHEN), "created_at must be an RFC 3339 UTC time"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("review-finding.malformed", `review finding is malformed: ${message}`);
  const signer = signedBy(record, found, "opentine.review-finding.v1:", "review-finding", "review finding", publicKey);
  const members = new Set(Array.isArray(reviewers) ? reviewers.filter((key): key is string => typeof key === "string") : []);
  if (members.size > 0 && !members.has(signer)) refuse("review-finding.untrusted-signer", "the review finding's signer is not a reviewer");
  return {
    review_id: found.get("review_id"),
    finding_id: found.get("finding_id"),
    severity: found.get("severity"),
    path,
    line: lineNumber,
    digest: projectDigest(record),
    signer,
    state: publicKey !== null || members.size > 0 ? "verified" : "verified-tofu",
  };
}
