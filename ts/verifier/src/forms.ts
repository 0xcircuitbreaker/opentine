/**
 * Storage-only object forms (SPEC 2.8, "Pack v3"): `FULL`, `RUN_DELTA`,
 * `EVENT_SLIM` (ports of `opentine.repository._run_delta`) and the 0.40
 * `BLOB_DELTA` (`_blob_delta`). Every form is rebuilt to the object's
 * canonical envelope bytes, which the caller checks against the object id, so
 * a stored form can make an object unreadable but never read as other bytes.
 */

import { canonicalJson, validateJsonShape } from "./canon.js";
import { objectId } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, LENIENT, parseBytes, type JObject, type JValue } from "./json.js";

export const FULL = 0;
export const RUN_DELTA = 1;
export const EVENT_SLIM = 2;
export const BLOB_DELTA = 3;
export const ENCODINGS = [FULL, RUN_DELTA, EVENT_SLIM, BLOB_DELTA];
/** A reader resolves at most this many deltas for one object. */
export const MAX_DELTA_DEPTH = 64;
const MAX_BODY_TOKENS = 4_000_000;

/** Defaults an `EVENT_SLIM` form leaves out (`_run_delta.EVENT_DEFAULTS`). */
const EVENT_DEFAULTS: [string, () => JValue][] = [
  ["actor", () => ""],
  ["attributes", () => new Map()],
  ["billing", () => new Map()],
  ["causal_ids", () => []],
  ["cost", () => 0n],
  ["duration", () => 0n],
  ["parent_ids", () => []],
  ["usage", () => new Map()],
];

export class FormError extends TineError {}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
}

/** (header line, body) of a stored object. */
export function split(raw: Uint8Array): [Uint8Array, Uint8Array] {
  const newline = raw.indexOf(0x0a);
  if (newline < 0 || newline > 256) throw new FormError("stored object has no envelope header", "localpack.object-id-mismatch");
  return [raw.subarray(0, newline), raw.subarray(newline + 1)];
}

function bodyObject(body: Uint8Array): JObject {
  let value: JValue;
  try {
    validateJsonShape(body, MAX_BODY_TOKENS);
    value = parseBytes(body, LENIENT, "stored object body");
  } catch {
    throw new FormError("stored object body is not JSON", "localpack.object-id-mismatch");
  }
  if (!isObject(value)) throw new FormError("stored object body is not a JSON object", "localpack.object-id-mismatch");
  return value;
}

/** The id a canonical envelope hashes to; the header is parsed, not trusted (`_packs.oid_of`). */
export function oidOf(raw: Uint8Array): string {
  const newline = raw.indexOf(0x0a);
  let header: JValue = null;
  try {
    if (newline >= 0 && newline <= 256) header = parseBytes(raw.subarray(0, newline), LENIENT, "object header");
  } catch {
    header = null;
  }
  if (!isObject(header)) throw new TineError("malformed object envelope", "envelope.malformed");
  const type = header.get("type");
  return objectId(typeof type === "string" ? type : "None", header.get("schema"), raw.subarray(newline + 1));
}

function isDefault(value: JValue, fallback: JValue): boolean {
  if (typeof fallback === "string") return value === fallback;
  if (typeof fallback === "bigint") return value === fallback;
  if (Array.isArray(fallback)) return Array.isArray(value) && value.length === 0;
  return isObject(value) && value.size === 0;
}

/** An `EVENT_SLIM` form with its defaults put back. A stored default is refused. */
export function unslimEvent(stored: Uint8Array): Uint8Array {
  const [header, body] = split(stored);
  const value = bodyObject(body);
  for (const [key, make] of EVENT_DEFAULTS) {
    if (value.has(key)) {
      if (isDefault(value.get(key) as JValue, make())) {
        throw new FormError("slim event stores a default it should omit", "localpack.slim-default");
      }
    } else {
      value.set(key, make());
    }
  }
  return concatBytes(header, Uint8Array.of(0x0a), canonicalJson(value));
}

export interface RunDelta {
  append: JObject;
  drop: string[];
  set: JObject;
}

/** The delta of a `RUN_DELTA` form, its shape fully checked. */
export function parseRunDelta(stored: Uint8Array): RunDelta {
  const delta = bodyObject(split(stored)[1]);
  const bad = (message: string): never => {
    throw new FormError(message, "localpack.object-id-mismatch");
  };
  if (delta.size !== 3 || !["append", "drop", "set"].every((key) => delta.has(key))) bad("run delta has the wrong keys");
  const append = delta.get("append");
  const drop = delta.get("drop");
  const changed = delta.get("set");
  if (!isObject(append) || !isObject(changed)) bad("run delta is malformed");
  if (!Array.isArray(drop) || !drop.every((key) => typeof key === "string")) bad("run delta is malformed");
  const appended = append as JObject;
  const set = changed as JObject;
  const dropped = drop as string[];
  if ([...appended.values()].some((tail) => !Array.isArray(tail) || !tail.length)) bad("run delta appends nothing");
  const twice =
    [...appended.keys()].some((key) => set.has(key)) ||
    dropped.some((key) => appended.has(key) || set.has(key));
  if (twice) bad("run delta names one key twice");
  return { append: appended, drop: dropped, set };
}

/** *base* with *delta* applied (`_run_delta.apply_delta`). */
export function applyRunDelta(base: Uint8Array, delta: RunDelta): Uint8Array {
  const [header, body] = split(base);
  const value = bodyObject(body);
  const bad = (message: string): never => {
    throw new FormError(message, "localpack.object-id-mismatch");
  };
  for (const key of delta.drop) {
    if (!value.has(key)) bad("run delta drops a key its base lacks");
    value.delete(key);
  }
  for (const [key, tail] of delta.append) {
    const current = value.get(key);
    if (!Array.isArray(current) || !current.length) bad("run delta appends to a key that is not a list");
    value.set(key, [...(current as JValue[]), ...(tail as JValue[])]);
  }
  for (const [key, item] of delta.set) value.set(key, item);
  return concatBytes(header, Uint8Array.of(0x0a), canonicalJson(value));
}

export interface BlobDelta {
  header: Uint8Array;
  base: string;
  prefix: number;
  suffix: number;
  middle: Uint8Array;
}

const BLOB_LINE = /^blob:sha256:([0-9a-f]{64}) (0|[1-9][0-9]{0,9}) (0|[1-9][0-9]{0,9})$/;

/** (target header, base oid, prefix, suffix, middle) of a `BLOB_DELTA` form. */
export function parseBlobDelta(stored: Uint8Array): BlobDelta {
  const [header, rest] = split(stored);
  const newline = rest.indexOf(0x0a);
  const line = newline < 0 ? "" : Buffer.from(rest.subarray(0, newline)).toString("latin1");
  const match = newline < 0 ? null : BLOB_LINE.exec(line);
  if (!match) throw new FormError("blob delta is malformed", "localpack.object-id-mismatch");
  return {
    header,
    base: `blob:sha256:${match[1]}`,
    prefix: Number(match[2]),
    suffix: Number(match[3]),
    middle: rest.subarray(newline + 1),
  };
}

/** The bytes a `BLOB_DELTA` rebuilds from its base (the caller checks them against the id). */
export function applyBlobDelta(delta: BlobDelta, base: Uint8Array): Uint8Array {
  const baseBody = split(base)[1];
  if (delta.prefix + delta.suffix > baseBody.length) {
    throw new FormError("blob delta takes more bytes than its base has", "localpack.object-id-mismatch");
  }
  return concatBytes(
    delta.header,
    Uint8Array.of(0x0a),
    baseBody.subarray(0, delta.prefix),
    delta.middle,
    baseBody.subarray(baseBody.length - delta.suffix),
  );
}

