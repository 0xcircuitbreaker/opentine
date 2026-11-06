/**
 * The portable `.tine` reader (SPEC 3.1, 3.7) and the format v4 integrity
 * check (SPEC Part 9): every envelope id re-derives, the root is a run the
 * file carries, every object is reachable from it, and the annotations form
 * one chain on the root.
 */

import { canonicalJson, validateJsonShape } from "./canon.js";
import { TineError } from "./errors.js";
import { ObjectEnvelope, parseOid, validateLinks } from "./envelope.js";
import {
  codePointCompare,
  containsLoneSurrogate,
  isInt,
  isObject,
  MAX_SAFE,
  parseBytes,
  STRICT,
  type JObject,
  type JValue,
} from "./json.js";

export const V4_KIND = "tine-artifact/4";
export const V4_KEYS = ["annotations", "format_version", "kind", "objects", "root", "signatures"];
export const MAX_V4_OBJECTS = 1_000_000;
export const MAX_V4_ANNOTATIONS = 1024;
export const MAX_V4_SIGNATURES = 16;
export const SCHEME_V3 = "tine-sig/3";
const BUNDLED = new Set(["blob", "event", "run"]);
const HEADER = ["encoding", "schema", "type"];

function structuralTokenBudget(length: number): number {
  return Math.min(16_000_000, Math.max(200_000, Math.floor(length / 4)));
}

const ARTIFACT_CODES: Record<string, string> = {
  "duplicate-key": "artifact.duplicate-key",
  "non-finite": "artifact.non-finite",
  "integer-digits": "artifact.integer-too-many-digits",
  "text.lone-surrogate": "artifact.lone-surrogate",
};

/** Decode portable JSON, refusing every parser-differential construct (SPEC 3.7). */
export function parseArtifactJson(raw: Uint8Array): JValue {
  if (raw.includes(0)) throw new TineError(".tine artifacts must use UTF-8 JSON", "artifact.nul-byte");
  try {
    validateJsonShape(raw, structuralTokenBudget(raw.length));
  } catch {
    throw new TineError(
      ".tine artifact nesting exceeds the parser limit or structure is excessive",
      "artifact.structure-excessive",
    );
  }
  let parsed: JValue;
  try {
    parsed = parseBytes(raw, STRICT, ".tine artifact");
  } catch (exc) {
    if (!(exc instanceof TineError)) throw exc;
    throw new TineError(exc.message, ARTIFACT_CODES[exc.code] ?? "artifact.malformed-json");
  }
  if (containsLoneSurrogate(parsed)) {
    throw new TineError(".tine artifact holds an unpaired UTF-16 surrogate", "artifact.lone-surrogate");
  }
  return parsed;
}

/** The top-level keys of a parsed artifact, in Python's `sorted()` order. */
export function topLevelKeys(parsed: JValue): string[] {
  return isObject(parsed) ? [...parsed.keys()].sort(codePointCompare) : [];
}

export function isV4Artifact(data: unknown): data is JObject {
  return isObject(data) && data.get("format_version") === 4n && data.get("kind") === V4_KIND;
}

/** A value with every integer wider than 2**53-1 read back as a double (kernel._parse_int). */
function widenIntegers(value: JValue): JValue {
  if (isInt(value)) return value > MAX_SAFE || value < -MAX_SAFE ? Number(value) : value;
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TineError(`Out of range float values are not JSON compliant: ${value}`, "canon.non-finite");
  }
  if (Array.isArray(value)) return value.map(widenIntegers);
  if (isObject(value)) return new Map([...value].map(([key, item]) => [key, widenIntegers(item)]));
  return value;
}

function sameKeys(entry: JObject, keys: string[]): boolean {
  return entry.size === keys.length && keys.every((key) => entry.has(key));
}

/** Rebuild one stored envelope from its v4 spelling and check its oid. */
export function v4Envelope(entry: JValue | undefined, oid: JValue | undefined, where: string): ObjectEnvelope {
  if (!isObject(entry) || typeof oid !== "string") throw new TineError(`${where}: malformed v4 envelope`);
  const raw = entry.get("encoding") === "raw";
  if (!sameKeys(entry, [...HEADER, raw ? "data" : "body"])) {
    throw new TineError(`${where}: a v4 envelope is encoding, schema, type and data|body`);
  }
  try {
    let body: Uint8Array;
    if (raw) {
      const data = entry.get("data");
      if (typeof data !== "string") throw new TineError("'data' must be a string");
      if (!/^[\x00-\x7f]*$/.test(data)) throw new TineError("string argument should contain only ASCII characters");
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data) || data.length % 4 !== 0) {
        throw new TineError("Non-base64 digit found");
      }
      body = Buffer.from(data, "base64");
      if (Buffer.from(body).toString("base64") !== data) throw new TineError("blob data is not canonical base64");
    } else {
      body = canonicalJson(widenIntegers(entry.get("body") as JValue));
    }
    const header = canonicalJson(new Map(HEADER.map((name) => [name, entry.get(name) as JValue])));
    const stored = new Uint8Array(header.length + 1 + body.length);
    stored.set(header);
    stored[header.length] = 0x0a;
    stored.set(body, header.length + 1);
    return ObjectEnvelope.decode(stored, oid);
  } catch (exc) {
    if (exc instanceof TineError) throw new TineError(`${where}: ${exc.message}`, exc.code);
    throw exc;
  }
}

function closure(objects: Map<string, ObjectEnvelope>, root: string): Set<string> {
  const seen = new Set([root]);
  const stack = [root];
  while (stack.length) {
    for (const link of validateLinks(objects.get(stack.pop() as string) as ObjectEnvelope)) {
      const oid = link as string;
      if (seen.has(oid)) continue;
      if (!objects.has(oid)) throw new TineError(`v4 artifact is missing linked object ${oid}`);
      seen.add(oid);
      stack.push(oid);
    }
  }
  return seen;
}

const ISO = /^\p{Nd}{4}-\p{Nd}{2}-\p{Nd}{2}T\p{Nd}{2}:\p{Nd}{2}:\p{Nd}{2}(\.\p{Nd}+)?(Z|[+-]\p{Nd}{2}:\p{Nd}{2})\n?$/u;
const HEX64 = /^[0-9a-f]{64}\n?$/;
const RUN_OID = /^run:sha256:[0-9a-f]{64}\n?$/;
const UPGRADE_KEYS = ["digest", "digest_algorithm", "format", "integrity_digest", "signature", "tool", "upgraded_at"];
const UPGRADE_SIGNATURE_KEYS = ["key_fingerprint", "scheme", "state", "trust_basis"];
const UPGRADE_STATES = new Set(["verified", "verified-tofu", "unsigned", "no-key", "mismatch", "error", "not-applicable"]);

function shortText(value: JValue | undefined, nullable = true): boolean {
  if (value === null) return nullable;
  return typeof value === "string" && value.length <= 512;
}

/** SPEC 9.9: a well-formed `upgraded_from` record (`_provenance_v4.valid_upgraded_from`). */
export function validUpgradedFrom(value: JValue | undefined): boolean {
  if (!isObject(value) || !sameKeys(value, UPGRADE_KEYS)) return false;
  const fmt = value.get("format");
  const digest = value.get("digest");
  if (typeof fmt !== "string" || !["tine/1", "tine/2", "tine-repo/3"].includes(fmt)) return false;
  if (value.get("digest_algorithm") !== "sha256") return false;
  if (typeof digest !== "string" || !(fmt === "tine-repo/3" ? RUN_OID : HEX64).test(digest)) return false;
  const integrity = value.get("integrity_digest");
  if (integrity !== null && !(typeof integrity === "string" && HEX64.test(integrity))) return false;
  const stamp = value.get("upgraded_at");
  const tool = value.get("tool");
  if (typeof stamp !== "string" || !ISO.test(stamp)) return false;
  if (!(shortText(tool, false) && (tool as string).startsWith("opentine/"))) return false;
  const block = value.get("signature");
  if (!isObject(block) || !sameKeys(block, UPGRADE_SIGNATURE_KEYS)) return false;
  const state = block.get("state");
  return (
    typeof state === "string" &&
    UPGRADE_STATES.has(state) &&
    shortText(block.get("scheme")) &&
    shortText(block.get("key_fingerprint")) &&
    shortText(block.get("trust_basis"), false)
  );
}

export interface V4Contents {
  root: string;
  objects: Map<string, ObjectEnvelope>;
  annotations: ObjectEnvelope[];
}

function pyList(keys: string[]): string {
  return "[" + keys.map((key) => `'${key}'`).join(", ") + "]";
}

/**
 * Check a parsed v4 artifact's integrity (a port of `_artifact_v4_read.read_v4_data`
 * up to, not including, the v3 run loader's graph validators).
 */
export function readV4(data: JValue): V4Contents {
  if (!isV4Artifact(data)) throw new TineError(`not a format v4 artifact (kind '${V4_KIND}')`);
  if (!sameKeys(data, V4_KEYS)) throw new TineError(`v4 artifact keys must be exactly ${pyList(V4_KEYS)}`);
  const objects = data.get("objects");
  if (!isObject(objects) || objects.size > MAX_V4_OBJECTS) {
    throw new TineError(`v4 objects must be a map of at most ${MAX_V4_OBJECTS} envelopes`);
  }
  const annotations = data.get("annotations");
  if (!Array.isArray(annotations) || annotations.length > MAX_V4_ANNOTATIONS) {
    throw new TineError(`v4 annotations must be a list of at most ${MAX_V4_ANNOTATIONS}`);
  }
  const signatures = data.get("signatures");
  if (!Array.isArray(signatures) || signatures.length > MAX_V4_SIGNATURES) {
    throw new TineError(`v4 signatures must be a list of at most ${MAX_V4_SIGNATURES}`);
  }
  if (signatures.some((block) => !isObject(block) || block.get("scheme") !== SCHEME_V3)) {
    throw new TineError(`every v4 signature must be a ${SCHEME_V3} block`);
  }
  const root = data.get("root");
  const envelopes = new Map<string, ObjectEnvelope>();
  for (const [oid, entry] of objects) {
    if (!BUNDLED.has(parseOid(oid)[0])) {
      throw new TineError(`v4 objects hold only blob, event and run envelopes: ${oid}`);
    }
    envelopes.set(oid, v4Envelope(entry, oid, `objects[${oid}]`));
  }
  if (typeof root !== "string" || parseOid(root)[0] !== "run" || !envelopes.has(root)) {
    throw new TineError("v4 root must name a run envelope the artifact carries");
  }
  if (closure(envelopes, root).size !== envelopes.size) {
    throw new TineError("v4 artifact carries objects its root does not reach");
  }
  const runPayload = (envelopes.get(root) as ObjectEnvelope).payload() as JObject;
  if (runPayload.has("upgraded_from") && !validUpgradedFrom(runPayload.get("upgraded_from"))) {
    throw new TineError("run upgraded_from is malformed (SPEC 9.9)");
  }
  const chain: ObjectEnvelope[] = [];
  annotations.forEach((entry, index) => {
    const where = `annotations[${index}]`;
    let body: JObject | null = null;
    if (isObject(entry)) body = new Map([...entry].filter(([key]) => key !== "id"));
    const envelope = v4Envelope(body ?? undefined, body !== null ? (entry as JObject).get("id") : undefined, where);
    const payload = envelope.payload();
    if (!isObject(payload)) throw new TineError(`${where}: annotation payload must be an object`);
    const previous = chain.length ? chain[chain.length - 1].oid : null;
    if (envelope.objectType !== "annotation" || payload.get("target_id") !== root) {
      throw new TineError(`${where}: must be an annotation of the root run`);
    }
    const stated = payload.has("previous_id") ? payload.get("previous_id") : null;
    if (stated !== previous) throw new TineError(`${where}: annotations must form one chain, oldest first`);
    chain.push(envelope);
  });
  return { root, objects: envelopes, annotations: chain };
}

/** `verify_v4`: integrity as a result, never a throw. */
export function verifyV4(data: JValue): { ok: boolean; root: string | null; reason: string } {
  const root = isObject(data) && typeof data.get("root") === "string" ? (data.get("root") as string) : null;
  try {
    readV4(data);
  } catch (exc) {
    if (exc instanceof TineError) return { ok: false, root, reason: `invalid v4 artifact: ${exc.message}` };
    throw exc;
  }
  return { ok: true, root, reason: "ok" };
}
