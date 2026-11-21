/**
 * 0.75 curated dataset versions: a port of `opentine._dataset_claims.offline`.
 *
 * A version is an attestation under the `opentine.dataset-version/1` claim
 * convention: the member runs (each with a content digest, distinct after
 * content-defined-chunking dedup), the runs dropped as duplicates, the taint
 * filter applied and the runs withdrawn. The offline check needs only the
 * payload: the claim's shape, the members digest, the filter's consistency,
 * an Ed25519 signature under the embedded key, that key being the payload
 * `signer` and the claim's `curator`. Whether the curator holds a pinned role
 * needs the repository and is not decided here. A CLI-level check outside the
 * frozen vector families. Shared vectors: tests/data/dataset_version.json.
 */

import { canonicalJson, canonicalText } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { verifyAttestation } from "./signature.js";

export const CONVENTION = "opentine.dataset-version/1";
export const SOURCES = ["integrity-taint", "monitor-verdict", "oversight-reject", "sabotage-task", "transcript-flag"];
const CHUNKING = new Map<string, JValue>([["scheme", "fastcdc-gear49"], ["min", 64n], ["avg", 256n], ["max", 2048n]]);
const FIELDS = ["convention", "name", "version", "previous", "selection", "members", "members_digest", "dedup",
  "taint_filter", "withdrawn", "curator", "created_at"];
const FILTER = ["mode", "sources", "excluded", "included_tainted", "justification"];
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const ATT = /^attestation:sha256:[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const HEX = /^[0-9a-f]{64}$/;

export interface DatasetVersionCheck {
  ok: boolean; signature: string; problems: string[]; members: number; excluded: number;
}

const str = (v: JValue | undefined): v is string => typeof v === "string";
const keysAre = (o: JObject, keys: string[]): boolean => o.size === keys.length && keys.every((k) => o.has(k));
const same = (a: JValue, b: JValue): boolean => canonicalText(a) === canonicalText(b);

/** A sorted list of distinct run ids (Python sorts by code point; run ids are ASCII). */
function runs(value: JValue | undefined): value is string[] {
  if (!Array.isArray(value) || !value.every((r) => str(r) && RUN.test(r))) return false;
  const list = value as string[];
  return list.every((r, i) => i === 0 || list[i - 1] < r);
}

export function membersDigest(members: JValue): string {
  return `sha256:${sha256Hex(canonicalJson(members))}`;
}

function checkMembers(members: JValue | undefined): string[] {
  if (!Array.isArray(members) || !members.every((m) => isObject(m) && keysAre(m, ["run", "content"]))) {
    return ["members are {run, content} objects"];
  }
  const rows = members as JObject[];
  if (!runs(rows.map((m) => m.get("run") as JValue))) return ["members are sorted by run, each run once"];
  const content = rows.map((m) => m.get("content"));
  if (!content.every((c) => str(c) && DIGEST.test(c))) return ["member content is a sha256: digest"];
  if (new Set(content).size !== content.length) return ["two members share content: the deduplication does not hold"];
  return [];
}

function checkDedup(dedup: JValue | undefined, members: Set<string>): string[] {
  if (!isObject(dedup) || !keysAre(dedup, ["chunking", "candidates", "dropped"])) {
    return ["dedup is {chunking, candidates, dropped}"];
  }
  if (!same(dedup.get("chunking") as JValue, CHUNKING)) return ["dedup chunking is not the fastcdc-gear49 parameters"];
  const dropped = dedup.get("dropped");
  if (!Array.isArray(dropped) || !dropped.every((d) => isObject(d) && keysAre(d, ["run", "same_as"]))) {
    return ["dropped rows are {run, same_as}"];
  }
  const ids = (dropped as JObject[]).map((d) => d.get("run") as JValue);
  if (!runs(ids) || ids.some((r) => members.has(r))) return ["dropped runs are sorted, distinct and not members"];
  if ((dropped as JObject[]).some((d) => !members.has(d.get("same_as") as string))) {
    return ["a dropped run's same_as is not a member"];
  }
  const candidates = dedup.get("candidates");
  if (typeof candidates !== "bigint" || candidates < BigInt(members.size + ids.length)) {
    return ["dedup candidates is a count at least members plus dropped"];
  }
  return [];
}

function checkFilter(flt: JValue | undefined, members: Set<string>): string[] {
  if (!isObject(flt) || !keysAre(flt, FILTER)) return ["taint_filter has the wrong set of fields"];
  if (!same(flt.get("sources") as JValue, SOURCES)) return ["taint_filter sources are not the five taint sources"];
  const excluded = flt.get("excluded");
  if (!runs(excluded) || excluded.some((r) => members.has(r))) return ["excluded runs are sorted, distinct and not members"];
  const included = flt.get("included_tainted");
  if (!runs(included) || !included.every((r) => members.has(r))) return ["included_tainted runs are sorted members"];
  const mode = flt.get("mode");
  const just = flt.get("justification");
  if (mode === "default") {
    if (included.length || just !== null) return ["the default filter includes no tainted run and has no justification"];
  } else if (mode === "include-tainted") {
    if (!str(just) || !ATT.test(just)) return ["include-tainted names its justification attestation"];
  } else {
    return ["taint_filter mode is default or include-tainted"];
  }
  return [];
}

export function checkVersion(claim: JValue | undefined): string[] {
  if (!isObject(claim) || claim.get("convention") !== CONVENTION) return [`not an ${CONVENTION} claim`];
  if (!keysAre(claim, FIELDS)) return ["wrong set of fields"];
  const name = claim.get("name");
  if (!str(name) || !NAME.test(name)) return ["name is lower-case letters, digits, dot, underscore and hyphen"];
  const version = claim.get("version");
  if (typeof version !== "bigint" || version < 1n) return ["version is a positive integer"];
  const previous = claim.get("previous");
  if ((version === 1n) !== (previous === null) || (previous !== null && !(str(previous) && ATT.test(previous)))) {
    return ["previous is null for version 1 and an attestation id after"];
  }
  const selection = claim.get("selection");
  if (!str(selection) || !selection.trim()) return ["selection is the expression that chose the candidates"];
  const problems = checkMembers(claim.get("members"));
  if (problems.length) return problems;
  if (claim.get("members_digest") !== membersDigest(claim.get("members") as JValue)) {
    return ["members_digest does not match the members"];
  }
  const members = new Set((claim.get("members") as JObject[]).map((m) => m.get("run") as string));
  const more = checkDedup(claim.get("dedup"), members);
  if (more.length) return more;
  const filter = checkFilter(claim.get("taint_filter"), members);
  if (filter.length) return filter;
  const withdrawn = claim.get("withdrawn");
  if (!runs(withdrawn) || withdrawn.some((r) => members.has(r))) return ["withdrawn runs are sorted, distinct and not members"];
  const curator = claim.get("curator");
  if (!str(curator) || !DIGEST.test(curator)) return ["curator is a key fingerprint"];
  const created = claim.get("created_at");
  if (!str(created) || !AT.test(created)) return ["created_at is YYYY-MM-DDTHH:MM:SSZ"];
  return [];
}

function signatureState(payload: JObject): string {
  const block = payload.get("signature");
  if (!isObject(block) || block.get("alg") !== "ed25519") return "unsigned";
  const key = block.get("public_key");
  if (!str(key) || !HEX.test(key)) return "signer-mismatch";
  if (`sha256:${sha256Hex(Uint8Array.from(Buffer.from(key, "hex")))}` !== payload.get("signer")) return "signer-mismatch";
  return verifyAttestation(payload, { trustEmbedded: true }).ok ? "verified-tofu" : "bad-signature";
}

export function checkDatasetVersion(payloadIn: JValue): DatasetVersionCheck {
  const payload: JObject = isObject(payloadIn) ? payloadIn : new Map();
  const claim = payload.get("claim");
  const problems = checkVersion(claim);
  const target = payload.get("target_id");
  if (!(str(target) && RUN.test(target))) problems.push("the record does not target a run");
  let state = signatureState(payload);
  if (state === "verified-tofu" && isObject(claim) && claim.get("curator") !== payload.get("signer")) {
    state = "curator-mismatch";
  }
  const good = isObject(claim) && problems.length === 0;
  const flt = good ? (claim.get("taint_filter") as JObject) : null;
  return {
    ok: good && state === "verified-tofu", signature: state, problems,
    members: good ? (claim.get("members") as JValue[]).length : 0,
    excluded: flt ? (flt.get("excluded") as JValue[]).length : 0,
  };
}
