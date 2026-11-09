/**
 * SPEC 4.16 `opentine.project` (an owner-signed, hash-chained project manifest)
 * and SPEC 4.17 `opentine.mirror-state` (a host's statement about a code slot's
 * sync, which a verifier never reports as a pass). A port of
 * `opentine._project.check`/`chain` and `opentine._mirror_state.check`: exactly
 * each kind's fields, a `tine-sig/3` Ed25519 block over the kind's domain + JCS
 * of `{"body", "header"}`. Refusals carry `project.*` and `mirror-state.*`
 * codes. Browser-safe: SHA-256 and Ed25519 only, through `./crypto.js`.
 */

import { canonicalJson } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { HEADER_KEYS, verifyBlock, type Header } from "./signature.js";

const PROJECT_FIELDS = ["kind", "project_version", "project_id", "tenant", "seq", "prev", "visibility", "owners", "slots", "forked_from", "created_at"];
const SLOT_FIELDS = ["role", "forge", "forge_repo_id", "upstream_visibility", "locator", "default_branch"];
const MIRROR_FIELDS = ["kind", "mirror_state_version", "tenant", "project_id", "manifest", "slot", "object_format", "refs", "synced_at", "status", "reasons"];
const FORGES = ["github", "gitlab", "forgejo", "git", "entire"];
const MIRROR_CODES: Record<string, string> = {
  "mirror.stale": "caveat",
  "mirror.history-truncated": "caveat",
  "mirror.host-statement": "caveat",
  "mirror.upstream-unverifiable": "caveat",
  "mirror.blob-not-mirrored": "unavailable",
  "mirror.upstream-unreachable": "unavailable",
  "mirror.limit-exceeded": "unavailable",
};
export const HOST_LABEL = "host statement, not verified by you";
const RE = {
  id: /^[a-z0-9][a-z0-9._-]{0,63}$/,
  tenant: /^[a-z0-9][a-z0-9._-]{0,127}$/,
  owner: /^[0-9a-f]{64}$/,
  blob: /^blob:sha256:[0-9a-f]{64}$/,
  when: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/,
  repo: /^[A-Za-z0-9_.:/-]{1,128}$/,
  branch: /^[A-Za-z0-9._/-]{1,255}$/,
  url: /^(https:\/\/|ssh:\/\/|git@)[\x21-\x7e]{1,2040}$/,
  userinfo: /^[a-z]+:\/\/[^/@]*:[^/@]*@/,
  digest: /^sha256:[0-9a-f]{64}$/,
  ref: /^refs\/(heads|tags)\/[A-Za-z0-9._/-]{1,240}$/,
  sha1: /^[0-9a-f]{40}$/,
  sha256: /^[0-9a-f]{64}$/,
};
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

function fieldsOf(record: JValue, kind: string, names: string[], code: string, subject: string): JObject {
  if (!isObject(record) || record.get("kind") !== kind) refuse(`${code}.malformed`, `${subject} is malformed: kind is not ${kind}`);
  const object = record as JObject;
  const keys = [...object.keys()];
  if (keys.some((key) => key !== "signature" && !names.includes(key)) || names.some((key) => !object.has(key))) {
    refuse(`${code}.malformed`, `${subject} is malformed: wrong set of fields`);
  }
  return new Map(names.map((name) => [name, object.get(name) as JValue]));
}

function slotProblem(slot: JValue, isPrivate: boolean): [string, string] | null {
  const bad = "project.malformed";
  if (!isObject(slot) || slot.size !== SLOT_FIELDS.length || SLOT_FIELDS.some((key) => !slot.has(key))) return [bad, "a slot has exactly its six fields"];
  if (!["primary", "secondary"].includes(slot.get("role") as string)) return [bad, "a slot role is primary or secondary"];
  if (!FORGES.includes(slot.get("forge") as string)) return [bad, "forge is not a known forge"];
  const rid = slot.get("forge_repo_id");
  if (rid !== null && (slot.get("forge") === "git" || !is(rid, RE.repo))) return [bad, "forge_repo_id is null for a plain git forge, else a forge id"];
  if (!["public", "private"].includes(slot.get("upstream_visibility") as string)) return [bad, "upstream_visibility is public or private"];
  const branch = slot.get("default_branch");
  if (!is(branch, RE.branch) || branch.includes("..") || branch.startsWith("/") || branch.startsWith("-")) return [bad, "default_branch is a branch name"];
  const loc = slot.get("locator");
  if (!isObject(loc) || loc.size !== 1) return [bad, "a locator is an object with exactly url or commitment"];
  if (loc.has("commitment")) {
    if (!is(loc.get("commitment"), RE.digest)) return [bad, "a commitment is sha256:<64 hex>"];
  } else {
    const url = loc.get("url");
    if (!is(url, RE.url) || encoder.encode(url).length > 2048 || RE.userinfo.test(url)) return [bad, "a url is a clone URL without credentials"];
  }
  if (!isPrivate && slot.get("upstream_visibility") === "private") return ["project.private-upstream", "a public project over a private upstream is refused"];
  if (isPrivate && loc.has("url")) return ["project.plaintext-locator", "a plaintext locator in a private project"];
  if (!isPrivate && loc.has("commitment")) return [bad, "a public project names its upstream by url"];
  return null;
}

function projectBody(record: JValue): JObject {
  const body = fieldsOf(record, "opentine.project", PROJECT_FIELDS, "project", "project manifest");
  const seq = count(body.get("seq"));
  const owners = body.get("owners");
  const slots = body.get("slots");
  const checks: [boolean, string][] = [
    [count(body.get("project_version")) === 1, "project_version must be 1"],
    [is(body.get("project_id"), RE.id) && is(body.get("tenant"), RE.tenant), "project_id and tenant"],
    [seq !== null, "seq must be a count"],
    [seq === 0 ? body.get("prev") === null : is(body.get("prev"), RE.blob), "prev and seq disagree"],
    [body.get("forked_from") === null || is(body.get("forked_from"), RE.id), "forked_from"],
    [is(body.get("created_at"), RE.when), "created_at must be an RFC 3339 UTC time"],
    [["public", "private"].includes(body.get("visibility") as string), "visibility is public or private"],
    [Array.isArray(owners) && owners.length >= 1 && owners.length <= 16 && owners.every((o) => is(o, RE.owner)) && new Set(owners).size === owners.length, "owners is 1 to 16 distinct keys"],
    [Array.isArray(slots) && slots.length >= 1 && slots.length <= 2, "slots holds 1 or 2 slots"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("project.malformed", `project manifest is malformed: ${message}`);
  const roles = (slots as JValue[]).map((slot) => (isObject(slot) ? slot.get("role") : null));
  if (roles[0] !== "primary" || new Set(roles).size !== roles.length) refuse("project.malformed", "project manifest is malformed: slot roles");
  for (const slot of slots as JValue[]) {
    const problem = slotProblem(slot, body.get("visibility") === "private");
    if (problem) refuse(problem[0], problem[0] === "project.malformed" ? `project manifest is malformed: ${problem[1]}` : problem[1]);
  }
  return body;
}

function signedBy(record: JValue, body: JObject, domain: string, code: string, subject: string, key: Uint8Array | null): string {
  const block = (record as JObject).get("signature");
  if (block === undefined || block === null) refuse(`${code}.unsigned`, `the ${subject} is unsigned`);
  if (!isObject(block)) refuse(`${code}.bad-signature`, `the ${subject} signature is not a block`);
  const sig = block as JObject;
  if (sig.get("alg") !== "ed25519") refuse(code === "project" ? "project.wrong-signer" : `${code}.wrong-key`, `a ${subject} is signed with an Ed25519 key`);
  const raw = sig.get("public_key");
  if (key !== null && raw !== Buffer.from(key).toString("hex")) refuse(`${code}.wrong-key`, "signed by a key other than the trusted key");
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
    key !== null ? { publicKey: key } : { trustEmbedded: true },
  );
  if (!result.ok) refuse(`${code}.bad-signature`, `the ${subject} signature does not hold (${result.state}: ${result.reason})`);
  return raw as string;
}

/** The blob oid of a manifest's canonical bytes: what the next version's `prev` names. */
export function projectDigest(record: JValue): string {
  const body = canonicalJson(record);
  const framed = new Uint8Array(7 + body.length);
  framed.set(encoder.encode("blob\u00001\u0000"));
  framed.set(body, 7);
  return `blob:sha256:${sha256Hex(framed)}`;
}

export interface ProjectResult {
  project_id: string;
  tenant: string;
  seq: number;
  digest: string;
  signer: string;
  visibility: string;
  state: string;
}

export function verifyProject(record: JValue, previous: JValue | null = null, ownerKey: string | null = null): ProjectResult {
  const body = projectBody(record);
  const signer = signedBy(record, body, "opentine.project.v1:", "project", "project manifest", null);
  let state = "verified-tofu";
  let owners = body.get("owners") as JValue[];
  if (previous !== null && previous !== undefined) {
    const prior = projectBody(previous);
    if (
      body.get("prev") !== projectDigest(previous) ||
      count(body.get("seq")) !== (count(prior.get("seq")) as number) + 1 ||
      body.get("project_id") !== prior.get("project_id") ||
      body.get("tenant") !== prior.get("tenant")
    ) {
      refuse("project.chain-break", `version ${count(body.get("seq"))} breaks the project chain`);
    }
    state = "verified";
    owners = prior.get("owners") as JValue[];
  } else if (ownerKey !== null && ownerKey !== undefined) {
    if (signer !== ownerKey) refuse("project.wrong-signer", "not signed by the pinned owner key");
    state = "verified";
  }
  if (!owners.includes(signer)) refuse("project.wrong-signer", "the manifest is not signed by an owner");
  return {
    project_id: body.get("project_id") as string,
    tenant: body.get("tenant") as string,
    seq: count(body.get("seq")) as number,
    digest: projectDigest(record),
    signer,
    visibility: body.get("visibility") as string,
    state,
  };
}

export function verifyProjectChain(versions: JValue, ownerKey: string | null = null): Record<string, unknown> {
  if (!Array.isArray(versions) || versions.length < 1 || versions.length > 10000) refuse("project.malformed", "project manifest is malformed: not a history");
  const list = versions as JValue[];
  const first = verifyProject(list[0], null, ownerKey);
  if (first.seq !== 0) refuse("project.chain-break", "the history does not start at seq 0");
  let last = first;
  for (let i = 1; i < list.length; i++) last = verifyProject(list[i], list[i - 1]);
  return { project_id: first.project_id, tenant: first.tenant, head: last.digest, seq: last.seq, versions: list.length, visibility: last.visibility, state: first.state };
}

/** A host statement: what a mirror said, labelled so, never a pass. */
export function verifyMirrorState(record: JValue, hostKey: Uint8Array | null, owners: JValue): Record<string, unknown> {
  const body = fieldsOf(record, "opentine.mirror-state", MIRROR_FIELDS, "mirror-state", "mirror state");
  const fmt = body.get("object_format") as string;
  const refs = body.get("refs");
  const reasons = body.get("reasons");
  const hex = fmt === "sha1" ? RE.sha1 : RE.sha256;
  const sorted = Array.isArray(reasons) && reasons.every((c) => typeof c === "string") ? [...new Set(reasons as string[])].sort() : null;
  const checks: [boolean, string][] = [
    [count(body.get("mirror_state_version")) === 1, "version"],
    [is(body.get("tenant"), RE.tenant) && is(body.get("project_id"), RE.id), "names"],
    [is(body.get("manifest"), RE.blob) && ["primary", "secondary"].includes(body.get("slot") as string), "manifest/slot"],
    [fmt === "sha1" || fmt === "sha256", "object_format is sha1 or sha256"],
    [isObject(refs) && refs.size <= 10000 && (fmt === "sha1" || fmt === "sha256") && [...refs].every(([n, v]) => RE.ref.test(n) && !n.includes("..") && is(v, hex)), "refs"],
    [is(body.get("synced_at"), RE.when), "synced_at must be an RFC 3339 UTC time"],
    [["synced", "stale", "failed", "paused"].includes(body.get("status") as string), "status"],
    [sorted !== null && sorted.length === (reasons as string[]).length && sorted.every((c, i) => c === (reasons as string[])[i]), "reasons are sorted and distinct"],
  ];
  for (const [ok, message] of checks) if (!ok) refuse("mirror-state.malformed", `mirror state is malformed: ${message}`);
  const signer = signedBy(record, body, "opentine.mirror-state.v1:", "mirror-state", "mirror state", hostKey);
  if (Array.isArray(owners) && owners.includes(signer)) refuse("mirror-state.user-signed", "signed by a project owner, not the host key");
  const given = new Set(reasons as string[]);
  const unknown = [...given].filter((code) => !(code in MIRROR_CODES)).sort();
  if (unknown.length > 0) refuse("mirror-state.unknown-reason", `unknown mirror reason ${unknown[0]}`);
  const status = body.get("status") as string;
  const gone = [...given].some((code) => MIRROR_CODES[code] === "unavailable");
  if (
    (status === "synced" && (gone || given.has("mirror.stale"))) ||
    (status === "stale" && !given.has("mirror.stale")) ||
    (status === "failed" && !gone) ||
    (status === "paused" && !given.has("mirror.limit-exceeded"))
  ) {
    refuse("mirror-state.inconsistent", `the reasons do not explain status ${status}`);
  }
  return {
    project_id: body.get("project_id"),
    slot: body.get("slot"),
    manifest: body.get("manifest"),
    status,
    refs: (refs as JObject).size,
    reasons: [...(reasons as string[])],
    synced_at: body.get("synced_at"),
    state: hostKey !== null ? "host-statement" : "host-statement-tofu",
    label: HOST_LABEL,
  };
}
