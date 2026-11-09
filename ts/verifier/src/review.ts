/**
 * SPEC 4.20 Reviews: `opentine.review` (a reviewer-signed, hash-chained unit of
 * work across runs and commits in one or more repositories), `opentine.review-gate`
 * (a reviewer's signed decision on one gate of one version) and the
 * `opentine.review-bundle` that carries a Review whole. A port of
 * `opentine._review.check`, `check_gate` and `verify_bundle`: exactly each
 * kind's fields, a `tine-sig/3` Ed25519 block over the kind's domain + JCS of
 * `{"body", "header"}`. Refusals carry `review.*` and `review-gate.*` codes.
 * Browser-safe: SHA-256 and Ed25519 only.
 */

import { canonicalJson } from "./canon.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { projectDigest } from "./project.js";
import { HEADER_KEYS, verifyBlock, type Header } from "./signature.js";

const FIELDS = ["kind", "review_version", "review_id", "seq", "prev", "title", "reviewers", "repos", "subjects", "findings", "monitors", "gates", "updated_at"];
const GATE_FIELDS = ["kind", "gate_version", "review_id", "review", "seq", "gate", "decision", "reason", "decided_at"];
const ROWS: Record<string, [string[], number]> = {
  repos: [["name", "project"], 16],
  subjects: [["repo", "type", "id"], 1024],
  findings: [["id", "severity", "subject", "message", "status"], 1024],
  monitors: [["name", "scorer", "score", "threshold", "passed", "verdict"], 64],
};
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const MONITORS = ["risk", "intent-drift", "coverage"];
const RE = {
  id: /^[a-z0-9][a-z0-9._-]{0,63}$/,
  key: /^[0-9a-f]{64}$/,
  blob: /^blob:sha256:[0-9a-f]{64}$/,
  run: /^run:sha256:[0-9a-f]{64}$/,
  commit: /^([0-9a-f]{40}|[0-9a-f]{64})$/,
  scorer: /^[a-z0-9][a-z0-9-]{0,63}$/,
  score: /^(0|1|0\.[0-9]{0,5}[1-9])$/,
  digest: /^sha256:[0-9a-f]{64}$/,
  when: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/,
};
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/;
const encoder = new TextEncoder();
const is = (value: JValue | undefined, pattern: RegExp): value is string => typeof value === "string" && pattern.test(value);

function count(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value >= 0n && value < 2n ** 53n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  return null;
}

function refuse(code: string, message: string): never {
  throw new TineError(message, code);
}

function textOk(value: JValue | undefined, limit: number, empty = false): boolean {
  if (typeof value !== "string" || (!empty && value.trim() === "")) return false;
  return encoder.encode(value).length <= limit && !CONTROL.test(value);
}

/** A score string in millionths: "0.75" is 750000. */
export function micros(score: string): number {
  if (score === "0" || score === "1") return Number(score) * 1_000_000;
  return Number(score.slice(2).padEnd(6, "0"));
}

function fieldsOf(record: JValue, kind: string, names: string[], code: string, subject: string): JObject {
  if (!isObject(record) || record.get("kind") !== kind) refuse(`${code}.malformed`, `${subject} is malformed: kind is not ${kind}`);
  const object = record as JObject;
  const keys = [...object.keys()];
  if (keys.some((key) => key !== "signature" && !names.includes(key)) || names.some((key) => !object.has(key))) {
    refuse(`${code}.malformed`, `${subject} is malformed: wrong set of fields`);
  }
  return new Map(names.map((name) => [name, object.get(name) as JValue]));
}

const bad = (message: string): never => refuse("review.malformed", `review is malformed: ${message}`);

function rows(value: JValue | undefined, what: string): JObject[] {
  const [names, limit] = ROWS[what];
  if (!Array.isArray(value) || value.length > limit) bad(`${what} is a list of at most ${limit}`);
  for (const row of value as JValue[]) {
    if (!isObject(row) || row.size !== names.length || names.some((n) => !row.has(n))) bad(`each of ${what} has exactly ${names.join(", ")}`);
  }
  return value as JObject[];
}

function distinct(values: string[], what: string): void {
  if (new Set(values).size !== values.length) bad(`${what} must be distinct`);
}

function sortedDistinct(values: string[]): boolean {
  return values.every((v, i) => i === 0 || values[i - 1] < v);
}

function reviewBody(record: JValue): JObject {
  const body = fieldsOf(record, "opentine.review", FIELDS, "review", "review");
  const seq = count(body.get("seq"));
  const checks: [boolean, string][] = [
    [count(body.get("review_version")) === 1, "review_version is 1"],
    [is(body.get("review_id"), RE.id), "review_id"],
    [seq !== null, "seq is a count"],
    [seq === 0 ? body.get("prev") === null : is(body.get("prev"), RE.blob), "prev and seq disagree"],
    [textOk(body.get("title"), 256), "title is 1 to 256 bytes of text"],
    [is(body.get("updated_at"), RE.when), "updated_at is an RFC 3339 UTC time"],
  ];
  for (const [ok, message] of checks) if (!ok) bad(message);
  const reviewers = body.get("reviewers");
  if (!Array.isArray(reviewers) || reviewers.length < 1 || reviewers.length > 16 || !reviewers.every((k) => is(k, RE.key))) bad("reviewers is 1 to 16 Ed25519 public keys");
  distinct(reviewers as string[], "reviewers");
  const repos = rows(body.get("repos"), "repos");
  const names = repos.map((row) => row.get("name"));
  if (repos.length === 0 || !names.every((n) => is(n, RE.id)) || !sortedDistinct(names as string[])) bad("repos is 1 to 16 repos, sorted by distinct name");
  if (!repos.every((row) => row.get("project") === null || is(row.get("project"), RE.id))) bad("a repo's project is a project id or null");
  const subjects = rows(body.get("subjects"), "subjects");
  for (const row of subjects) {
    const type = row.get("type");
    const pattern = type === "run" ? RE.run : type === "commit" ? RE.commit : null;
    if (!names.includes(row.get("repo") as string) || pattern === null || !is(row.get("id"), pattern)) bad("a subject is a run oid or commit id in a listed repo");
  }
  distinct(subjects.map((r) => JSON.stringify([r.get("repo"), r.get("type"), r.get("id")])), "subjects");
  const findings = rows(body.get("findings"), "findings");
  for (const row of findings) {
    const at = row.get("subject");
    const index = count(at);
    if (
      !is(row.get("id"), RE.id) ||
      !SEVERITIES.includes(row.get("severity") as string) ||
      !["open", "resolved"].includes(row.get("status") as string) ||
      !textOk(row.get("message"), 1024) ||
      !(at === null || (index !== null && index < subjects.length))
    ) {
      bad("a finding has an id, severity, status, message, subject");
    }
  }
  distinct(findings.map((r) => r.get("id") as string), "finding ids");
  const monitors = rows(body.get("monitors"), "monitors");
  for (const row of monitors) {
    const verdict = row.get("verdict");
    if (
      !MONITORS.includes(row.get("name") as string) ||
      !is(row.get("scorer"), RE.scorer) ||
      !is(row.get("score"), RE.score) ||
      !is(row.get("threshold"), RE.score) ||
      typeof row.get("passed") !== "boolean" ||
      !(verdict === null || is(verdict, RE.digest))
    ) {
      bad("a monitor is risk, intent-drift or coverage with a score");
    }
  }
  distinct(monitors.map((r) => r.get("name") as string), "monitor names");
  for (const row of monitors) {
    if (row.get("passed") !== micros(row.get("score") as string) >= micros(row.get("threshold") as string)) {
      refuse("review.inconsistent", `monitor ${row.get("name")}: passed disagrees with its score`);
    }
  }
  const gates = body.get("gates");
  if (!Array.isArray(gates) || gates.length > 32 || !gates.every((g) => is(g, RE.id)) || !sortedDistinct(gates as string[])) bad("gates is at most 32 sorted, distinct gate names");
  return body;
}

function gateBody(record: JValue): JObject {
  const body = fieldsOf(record, "opentine.review-gate", GATE_FIELDS, "review-gate", "review gate decision");
  const checks: [boolean, string][] = [
    [count(body.get("gate_version")) === 1, "gate_version is 1"],
    [is(body.get("review_id"), RE.id) && is(body.get("gate"), RE.id), "review_id and gate are ids"],
    [is(body.get("review"), RE.blob), "review is the decided version's blob oid"],
    [count(body.get("seq")) !== null, "seq is a count"],
    [["approve", "reject"].includes(body.get("decision") as string), "decision is approve or reject"],
    [textOk(body.get("reason"), 1024, true), "reason is at most 1024 bytes of text"],
    [is(body.get("decided_at"), RE.when), "decided_at is an RFC 3339 UTC time"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("review-gate.malformed", `review gate decision is malformed: ${message}`);
  return body;
}

function signer(record: JValue, body: JObject, gate: boolean): string {
  const [code, domain, subject] = gate ? ["review-gate", "opentine.review-gate.v1:", "review gate decision"] : ["review", "opentine.review.v1:", "review"];
  const block = (record as JObject).get("signature");
  if (block === undefined || block === null) refuse(`${code}.unsigned`, `the ${subject} is unsigned`);
  if (!isObject(block)) refuse(`${code}.bad-signature`, `the ${subject} signature is not a block`);
  const sig = block as JObject;
  if (sig.get("alg") !== "ed25519") refuse(`${code}.wrong-signer`, `a ${subject} is signed with a reviewer's Ed25519 key`);
  const result = verifyBlock(
    sig,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", body],
        ["header", new Map(HEADER_KEYS.map((name) => [name, header.get(name) ?? null]))],
      ]);
      const tail = canonicalJson(view);
      const head = encoder.encode(domain);
      const message = new Uint8Array(head.length + tail.length);
      message.set(head);
      message.set(tail, head.length);
      return message;
    },
    [SCHEME_V3],
    subject,
    { trustEmbedded: true },
  );
  if (!result.ok) refuse(`${code}.bad-signature`, `the ${subject} signature does not hold (${result.state}: ${result.reason})`);
  return sig.get("public_key") as string;
}

export function verifyReview(record: JValue, previous: JValue | null = null, reviewerKey: string | null = null): Record<string, unknown> {
  const body = reviewBody(record);
  const by = signer(record, body, false);
  let state = "verified-tofu";
  let reviewers = body.get("reviewers") as JValue[];
  if (previous !== null && previous !== undefined) {
    const prior = reviewBody(previous);
    if (
      body.get("prev") !== projectDigest(previous) ||
      count(body.get("seq")) !== (count(prior.get("seq")) as number) + 1 ||
      body.get("review_id") !== prior.get("review_id")
    ) {
      refuse("review.chain-break", `version ${count(body.get("seq"))} breaks the review chain`);
    }
    state = "verified";
    reviewers = prior.get("reviewers") as JValue[];
  } else if (reviewerKey !== null && reviewerKey !== undefined) {
    if (by !== reviewerKey) refuse("review.wrong-signer", "not signed by the pinned reviewer key");
    state = "verified";
  }
  if (!reviewers.includes(by)) refuse("review.wrong-signer", "the review is not signed by a reviewer");
  return { review_id: body.get("review_id"), seq: count(body.get("seq")), digest: projectDigest(record), signer: by, state };
}

function chain(versions: JValue, reviewerKey: string | null): Record<string, unknown> {
  if (!Array.isArray(versions) || versions.length < 1 || versions.length > 10000) bad("not a history");
  const list = versions as JValue[];
  const first = verifyReview(list[0], null, reviewerKey);
  if (first.seq !== 0) refuse("review.chain-break", "the history does not start at seq 0");
  let last = first;
  for (let i = 1; i < list.length; i++) last = verifyReview(list[i], list[i - 1]);
  return { review_id: first.review_id, head: last.digest, seq: last.seq, versions: list.length, state: first.state };
}

function blocked(version: JObject): string | null {
  for (const row of version.get("monitors") as JObject[]) if (row.get("passed") !== true) return `monitor ${row.get("name")} fails`;
  for (const row of version.get("findings") as JObject[]) {
    if (row.get("severity") === "critical" && row.get("status") === "open") return `critical finding ${row.get("id")} is open`;
  }
  return null;
}

export function verifyReviewGate(record: JValue, version: JValue): Record<string, unknown> {
  const body = gateBody(record);
  const review = reviewBody(version);
  const by = signer(record, body, true);
  if (body.get("review") !== projectDigest(version) || count(body.get("seq")) !== count(review.get("seq")) || body.get("review_id") !== review.get("review_id")) {
    refuse("review-gate.wrong-review", "the decision names another review version");
  }
  if (!(review.get("gates") as JValue[]).includes(body.get("gate") as string)) refuse("review-gate.unknown-gate", `gate ${body.get("gate")} is not a gate of it`);
  if (!(review.get("reviewers") as JValue[]).includes(by)) refuse("review-gate.wrong-signer", "the decision is not signed by a reviewer");
  const why = body.get("decision") === "approve" ? blocked(review) : null;
  if (why !== null) refuse("review-gate.blocked", `an approval is blocked: ${why}`);
  return { review_id: body.get("review_id"), gate: body.get("gate"), decision: body.get("decision"), seq: count(body.get("seq")), signer: by, state: "verified" };
}

export function verifyReviewBundle(value: JValue, reviewerKey: string | null = null): Record<string, unknown> {
  const keys = isObject(value) ? [...value.keys()].sort().join(",") : "";
  const object = value as JObject;
  const decisions = isObject(value) ? object.get("decisions") : undefined;
  if (
    keys !== "bundle_version,decisions,kind,versions" ||
    object.get("kind") !== "opentine.review-bundle" ||
    count(object.get("bundle_version")) !== 1 ||
    !Array.isArray(decisions) ||
    decisions.length > 10000
  ) {
    bad("not a review bundle");
  }
  const versions = object.get("versions") as JValue[];
  const found = chain(versions, reviewerKey);
  const byDigest = new Map<string, JValue>();
  for (const record of versions) byDigest.set(projectDigest(record), record);
  const current: Record<string, unknown>[] = [];
  for (const record of decisions as JValue[]) {
    const named = gateBody(record).get("review") as string;
    const version = byDigest.get(named);
    if (version === undefined) refuse("review-gate.wrong-review", "the decision names no version here");
    const checked = verifyReviewGate(record, version as JValue);
    if (named === found.head) current.push(checked);
  }
  const gates: Record<string, string> = {};
  for (const gate of (versions[versions.length - 1] as JObject).get("gates") as string[]) gates[gate] = "pending";
  for (const row of current) {
    const gate = row.gate as string;
    if (gates[gate] !== "rejected") gates[gate] = row.decision === "reject" ? "rejected" : "approved";
  }
  const states = new Set(Object.values(gates));
  let status = Object.keys(gates).length > 0 && states.size === 1 && states.has("approved") ? "approved" : "pending";
  if (states.has("rejected")) status = "rejected";
  return { ...found, decisions: (decisions as JValue[]).length, gates, status };
}
