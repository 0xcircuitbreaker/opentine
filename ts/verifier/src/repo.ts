/**
 * SPEC Part 2, the repository layout a reader meets on disk: the config
 * descriptor (2.2), object paths (2.3), ref names, ref files and ref targets
 * (2.4-2.5), reflog rows (2.6) and the shallow boundary file (2.7).
 *
 * Ports of `opentine.repository._config`, `_refs`, `_ref_store`, `_reflog`
 * and `_shallow`, over bytes and values instead of a directory.
 */

import { canonicalJson, validateJsonShape } from "./canon.js";
import { ObjectEnvelope, parseOid } from "./envelope.js";
import { TineError } from "./errors.js";
import { isInt, isObject, parseText, STRICT, type JObject, type JValue } from "./json.js";

const encoder = new TextEncoder();
const utf8Length = (text: string) => encoder.encode(text).length;

// --------------------------------------------------------------------------- //
// SPEC 2.2: the repository descriptor
// --------------------------------------------------------------------------- //

export const MAX_CONFIG_BYTES = 64 * 1024;
const OBJECTS_V4 = 4n;
const VERSIONS = [1n, 2n, 3n];
/** The newest `min_reader` this verifier honours (the reference's READER_VERSION). */
export const READER_VERSION: [number, number, number] = [0, 50, 0];
const SEMVER = /^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,5})$/;
const FIXED_V3: [string, JValue][] = [
  ["format", 3n],
  ["object_hash", "sha256"],
  ["repository", "opentine"],
];
const FIXED_V4: [string, JValue][] = [
  ["object_hash", "sha256"],
  ["objects", OBJECTS_V4],
  ["repository", "opentine"],
];
const CODECS = new Set(["zlib", "zstd", "none"]);

function incompatible(detail = ""): never {
  throw new TineError(`repository config is incompatible${detail}`, "config.incompatible");
}

function compareVersion(a: number[], b: number[]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function objectFormat(value: JObject): [string, JValue][] {
  if (value.has("min_reader")) {
    const text = value.get("min_reader");
    const match = typeof text === "string" ? SEMVER.exec(text) : null;
    if (!match) incompatible(": min_reader is not a MAJOR.MINOR.PATCH version");
    if (compareVersion(match.slice(1).map(Number), READER_VERSION) > 0) {
      incompatible(`: this repository needs opentine ${text as string} or newer to read it`);
    }
  }
  if (!value.has("objects")) return FIXED_V3;
  const objects = value.get("objects");
  if (isInt(objects) && objects > OBJECTS_V4) incompatible(`: object format ${objects} is newer than this reader`);
  if (value.has("format") || !value.has("min_reader")) incompatible();
  return FIXED_V4;
}

/** `_config.read_config`: accept the descriptor SPEC 2.2 describes, else refuse. */
export function validateConfig(raw: Uint8Array): JObject {
  if (raw.length > MAX_CONFIG_BYTES) throw new TineError("repository config exceeds maximum size", "config.oversized");
  validateJsonShape(raw, 10_000);
  let value: JValue;
  try {
    const start = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf ? 3 : 0;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw.subarray(start));
    value = parseText(text, { ...STRICT, constants: true, integers: "big", finiteFloats: false });
  } catch {
    throw new TineError("repository config is malformed", "config.malformed");
  }
  if (!isObject(value)) incompatible();
  for (const [key, expected] of objectFormat(value)) {
    if (value.get(key) !== expected) incompatible();
  }
  const version = value.get("version");
  if (isInt(version) && version > VERSIONS[VERSIONS.length - 1]) incompatible(`: storage version ${version} is newer`);
  if (!isInt(version) || !VERSIONS.includes(version)) incompatible();
  if (version !== 1n) {
    const storage = value.get("storage");
    const codec = isObject(storage) ? storage.get("compression") : undefined;
    if (typeof codec !== "string" || !CODECS.has(codec)) {
      throw new TineError("repository storage codec is not supported", "config.incompatible");
    }
  }
  return value;
}

// --------------------------------------------------------------------------- //
// SPEC 2.3: object paths
// --------------------------------------------------------------------------- //

export function objectPath(oid: JValue): string {
  let parsed: [string, string];
  try {
    parsed = parseOid(oid);
  } catch (exc) {
    throw new TineError((exc as Error).message, "path.invalid-oid");
  }
  const [objectType, digest] = parsed;
  return `objects/${objectType}/${digest.slice(0, 2)}/${digest.slice(2)}`;
}

// --------------------------------------------------------------------------- //
// SPEC 2.4-2.5: refs
// --------------------------------------------------------------------------- //

const NAMESPACES = ["annotations", "heads", "tags", "experiments", "promotions", "remotes"];
const TYPED_NAMESPACES: Record<string, string> = {
  annotations: "annotation",
  experiments: "run",
  heads: "run",
  promotions: "run",
};
const WINDOWS_NAMES = new Set(["con", "prn", "aux", "nul"]);
for (const prefix of ["com", "lpt"]) for (let n = 1; n <= 9; n++) WINDOWS_NAMES.add(`${prefix}${n}`);
export const MAX_REF_COMPONENT_BYTES = 240;
export const MAX_REF_NAME_BYTES = 512;

/** `_refs.normalize_ref`: the ref without `refs/`, or a refusal naming the rule. */
export function normalizeRef(name: JValue): string {
  if (typeof name !== "string") throw new TineError("invalid ref name", "ref.name-charset");
  const normalized = name.startsWith("refs/") ? name.slice(5) : name;
  const bad = (code: string): never => {
    throw new TineError(`invalid ref name: ${name}`, code);
  };
  const namespace = normalized.split("/", 1)[0];
  if (!NAMESPACES.includes(namespace) || !normalized.includes("/")) bad("ref.name-namespace");
  if (normalized !== normalized.toLowerCase()) bad("ref.name-not-casefolded");
  if (!/^[a-z]+\/[a-z0-9._/-]+$/.test(normalized)) bad("ref.name-charset");
  if (utf8Length(normalized) > MAX_REF_NAME_BYTES) bad("ref.name-too-long");
  for (const part of normalized.split("/")) {
    if (
      part === "" ||
      part === "." ||
      part === ".." ||
      part.includes("..") ||
      part.toLowerCase().endsWith(".lock") ||
      part.endsWith(".") ||
      part.endsWith(" ")
    ) {
      bad("ref.component-reserved");
    }
    if (WINDOWS_NAMES.has(part.split(".", 1)[0].toLowerCase())) bad("ref.component-windows-device");
    if (utf8Length(part) > MAX_REF_COMPONENT_BYTES) bad("ref.component-too-long");
  }
  return normalized;
}

export const MAX_REF_BYTES = 256;

/** `_ref_store.read_loose_oid` over the file's bytes. */
export function readRefFile(raw: Uint8Array): string {
  if (raw.length > MAX_REF_BYTES) throw new TineError("repository ref exceeds its size limit", "ref.file-oversized");
  if (raw.some((byte) => byte > 0x7f)) throw new TineError("repository ref is not ASCII", "ref.file-not-ascii");
  const text = String.fromCharCode(...raw);
  const oid = text.endsWith("\r\n") ? text.slice(0, -2) : text.endsWith("\n") ? text.slice(0, -1) : text;
  if (/\s/.test(oid)) throw new TineError("repository ref is not canonically encoded", "ref.file-not-canonical");
  parseOid(oid);
  return oid;
}

function namespaceOf(name: string): string {
  return (name.startsWith("refs/") ? name.slice(5) : name).split("/", 1)[0];
}

function checkTargetType(name: string, objectType: string): void {
  const namespace = namespaceOf(name);
  const expected = TYPED_NAMESPACES[namespace];
  if (expected && objectType !== expected) {
    throw new TineError(`${namespace} refs require ${expected} objects, got ${objectType}`, "ref.target-type");
  }
}

/**
 * `_refs.validate_ref_oid` then, when the target's stored bytes are known,
 * `validate_ref_target` (an annotation ref is named after the run it targets).
 */
export function validateRefTarget(name: string, oid: JValue, stored: Map<string, Uint8Array>): void {
  const [objectType] = parseOid(oid);
  checkTargetType(name, objectType);
  const raw = stored.get(oid as string);
  if (raw === undefined) return;
  const envelope = ObjectEnvelope.decode(raw, oid as string);
  checkTargetType(name, envelope.objectType);
  if (namespaceOf(name) !== "annotations") return;
  const payload = envelope.encoding === "json" ? envelope.payload() : null;
  const target = isObject(payload) ? payload.get("target_id") : undefined;
  if (typeof target !== "string") {
    throw new TineError("annotation refs require a run-targeted annotation", "ref.annotation-name-mismatch");
  }
  const [targetType, digest] = parseOid(target);
  const suffix = (name.startsWith("refs/") ? name.slice(5) : name).split("/").slice(1).join("/");
  if (targetType !== "run" || suffix !== digest) {
    throw new TineError("annotation ref name must match its target run", "ref.annotation-name-mismatch");
  }
}

// --------------------------------------------------------------------------- //
// SPEC 2.6: reflog rows
// --------------------------------------------------------------------------- //

export const MAX_REFLOG_ACTOR = 4096;

/** A reflog row's bytes: canonical JSON of the five fields, then LF. */
export function reflogRow(row: JValue): Uint8Array {
  if (!isObject(row)) throw new TineError("a reflog row is an object", "reflog.malformed");
  const field = (key: string) => (row.has(key) ? (row.get(key) as JValue) : null);
  const actor = field("actor");
  normalizeRef(field("ref"));
  parseOid(field("new"));
  if (field("old") !== null) parseOid(field("old"));
  if (typeof actor !== "string") throw new TineError("reflog actor must be a string", "reflog.malformed");
  if ([...actor].length > MAX_REFLOG_ACTOR) {
    throw new TineError("reflog actor exceeds its size limit", "reflog.actor-too-long");
  }
  const time = field("time_ns");
  if (typeof time !== "string" || !/^[0-9]+$/.test(time)) {
    throw new TineError("reflog time_ns must be decimal digits in a JSON string", "reflog.time-not-string");
  }
  const fields: JObject = new Map<string, JValue>([
    ["actor", actor],
    ["new", field("new")],
    ["old", field("old")],
    ["ref", field("ref")],
    ["time_ns", time],
  ]);
  const body = canonicalJson(fields);
  const out = new Uint8Array(body.length + 1);
  out.set(body);
  out[body.length] = 0x0a;
  return out;
}

// --------------------------------------------------------------------------- //
// SPEC 2.7: the shallow boundary
// --------------------------------------------------------------------------- //

export const MAX_SHALLOW_OBJECTS = 10_000;
export const MAX_SHALLOW_BYTES = 1024 * 1024;

/** `_shallow._decode`: the boundary oids, refusing every non-canonical spelling. */
export function parseShallow(raw: Uint8Array): string[] {
  if (raw.length > MAX_SHALLOW_BYTES) {
    throw new TineError("shallow boundary state exceeds its byte limit", "shallow.oversized");
  }
  if (raw.some((byte) => byte > 0x7f)) throw new TineError("shallow boundary state must be ASCII", "shallow.not-ascii");
  const text = Buffer.from(raw).toString("latin1");
  if (text.includes("\r")) {
    throw new TineError("shallow boundary state has invalid line endings", "shallow.carriage-return");
  }
  const lines = text.split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  if (lines.some((line) => !line)) {
    throw new TineError("shallow boundary state contains an empty object id", "shallow.empty-line");
  }
  if (lines.length > MAX_SHALLOW_OBJECTS) {
    throw new TineError("shallow boundary state exceeds its object limit", "shallow.too-many");
  }
  for (const oid of lines) parseOid(oid);
  if (new Set(lines).size !== lines.length) {
    throw new TineError("shallow boundary state contains duplicate object ids", "shallow.duplicate");
  }
  return [...new Set(lines)].sort();
}

/** `_shallow.encode_shallow`: sorted, deduplicated, LF-terminated. */
export function encodeShallow(values: JValue): Uint8Array {
  if (!Array.isArray(values)) throw new TineError("shallow oids must be a list", "oid.malformed");
  const unique = new Set<string>();
  for (const oid of values) {
    parseOid(oid);
    unique.add(oid as string);
    if (unique.size > MAX_SHALLOW_OBJECTS) {
      throw new TineError("shallow boundary state exceeds its object limit", "shallow.too-many");
    }
  }
  const sorted = [...unique].sort();
  const body = encoder.encode(sorted.join("\n") + (sorted.length ? "\n" : ""));
  if (body.length > MAX_SHALLOW_BYTES) {
    throw new TineError("shallow boundary state exceeds its byte limit", "shallow.oversized");
  }
  return body;
}
