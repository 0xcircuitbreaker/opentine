/**
 * SPEC 1.2 object envelopes, SPEC 1.3 typed object ids, SPEC 1.5 link fields.
 */

import { bytesEqual, canonicalJson, validateJsonShape } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isInt, isObject, KERNEL, LENIENT, parseBytes, pyRepr, truthy, type JObject, type JValue } from "./json.js";

export const OBJECT_TYPES = new Set(["blob", "event", "run", "attestation", "annotation"]);
export const OID_RE = /^(blob|event|run|attestation|annotation):sha256:([0-9a-f]{64})$/;
export const TREE_SCHEMA = 2n;
const MAX_SCHEMA = 2n ** 53n;
const encoder = new TextEncoder();

/** A `TYPE:TAG:HEX` oid shape with any hash-algorithm tag (SPEC 1.3.1). */
const TAGGED_OID_RE = /^(blob|event|run|attestation|annotation):([a-z0-9][a-z0-9-]{0,31}):[0-9a-f]+$/;
const RESERVED_HASH_ALGORITHMS = new Set(["sha3-256", "sha512", "blake3"]);

export function parseOid(oid: unknown): [string, string] {
  const match = typeof oid === "string" ? OID_RE.exec(oid) : null;
  if (!match) {
    // A well-formed oid under a hash tag other than sha256 is refused by name.
    const tag = typeof oid === "string" ? TAGGED_OID_RE.exec(oid)?.[2] : undefined;
    if (tag !== undefined && tag !== "sha256") {
      const kind = RESERVED_HASH_ALGORITHMS.has(tag) ? "reserved" : "unknown";
      throw new TineError(
        `unsupported hash algorithm ${pyRepr(tag)} in object id ${pyRepr(oid)}: the tag is ${kind}, ` +
          "and this reader implements only sha256 (SPEC 1.3.1)",
        "oid.hash-unsupported",
      );
    }
    throw new TineError(`invalid typed object id: ${pyRepr(oid)}`, "oid.malformed");
  }
  return [match[1], match[2]];
}

export function objectId(objectType: string, schema: unknown, stored: Uint8Array): string {
  if (!OBJECT_TYPES.has(objectType) || !isInt(schema) || schema < 1n || schema >= MAX_SCHEMA) {
    throw new TineError("invalid object type or schema", "envelope.unknown-type");
  }
  const head = encoder.encode(`${objectType}\0${schema}\0`);
  const framed = new Uint8Array(head.length + stored.length);
  framed.set(head);
  framed.set(stored, head.length);
  return `${objectType}:sha256:${sha256Hex(framed)}`;
}

export class ObjectEnvelope {
  constructor(
    readonly objectType: string,
    readonly schema: bigint,
    readonly body: Uint8Array,
    readonly encoding: string,
  ) {}

  get oid(): string {
    return objectId(this.objectType, this.schema, this.body);
  }

  payload(): JValue | Uint8Array {
    return this.encoding === "raw" ? this.body : parseBytes(this.body, KERNEL, "object body");
  }

  encode(): Uint8Array {
    const header: JObject = new Map<string, JValue>([
      ["encoding", this.encoding],
      ["schema", this.schema],
      ["type", this.objectType],
    ]);
    const head = canonicalJson(header);
    const out = new Uint8Array(head.length + 1 + this.body.length);
    out.set(head);
    out[head.length] = 0x0a;
    out.set(this.body, head.length + 1);
    return out;
  }

  static create(objectType: string, payload: JValue | Uint8Array, schema = 1n): ObjectEnvelope {
    if (!OBJECT_TYPES.has(objectType)) {
      throw new TineError(`unknown object type: ${objectType}`, "envelope.unknown-type");
    }
    if (objectType === "blob") {
      if (!(payload instanceof Uint8Array)) throw new TineError("blob payload must be bytes", "envelope.malformed");
      return new ObjectEnvelope(objectType, schema, payload, "raw");
    }
    if (payload instanceof Uint8Array) throw new TineError("a json payload must be a value", "envelope.malformed");
    const body = canonicalJson(payload);
    validateJsonShape(body);
    return new ObjectEnvelope(objectType, schema, body, "json");
  }

  /** Decode stored bytes, refusing every non-canonical spelling (SPEC 1.2). */
  static decode(stored: Uint8Array, expectedOid?: string | null): ObjectEnvelope {
    const newline = stored.indexOf(0x0a);
    if (newline < 0) throw new TineError("malformed object envelope", "envelope.malformed");
    const rawHeader = stored.subarray(0, newline);
    const body = stored.subarray(newline + 1);
    if (rawHeader.length > 256) throw new TineError("malformed object envelope", "envelope.malformed");
    let header: JValue;
    try {
      header = parseBytes(rawHeader, LENIENT, "object header");
    } catch {
      throw new TineError("malformed object envelope", "envelope.malformed");
    }
    if (!isObject(header) || header.size !== 3) {
      throw new TineError("non-canonical object header", "envelope.header-non-canonical");
    }
    if (!bytesEqual(canonicalJson(header), rawHeader)) {
      throw new TineError("non-canonical object header", "envelope.header-non-canonical");
    }
    const schema = header.get("schema");
    if (!isInt(schema) || schema < 1n || schema >= MAX_SCHEMA) {
      throw new TineError("invalid object schema", "envelope.schema-out-of-range");
    }
    const objectType = pyStr(header.get("type"));
    const encoding = pyStr(header.get("encoding"));
    const envelope = new ObjectEnvelope(objectType, schema, body, encoding);
    const expected = objectType === "blob" ? "raw" : "json";
    if (!OBJECT_TYPES.has(objectType) || encoding !== expected) {
      throw new TineError("unknown object type or encoding/type mismatch", "envelope.unknown-type");
    }
    if (encoding === "json") {
      let parsed: JValue;
      validateJsonShape(body);
      try {
        parsed = parseBytes(body, KERNEL, "object body");
      } catch (exc) {
        if (exc instanceof TineError && exc.code === "text.lone-surrogate") {
          // CPython decodes CESU-8 with surrogatepass; the canonical encoder then refuses it
          throw new TineError("canonical JSON nesting or Unicode key is invalid", "canon.unencodable-text");
        }
        throw new TineError("malformed object JSON", "envelope.body-malformed-json");
      }
      if (!bytesEqual(canonicalJson(parsed), body)) {
        throw new TineError("non-canonical object body", "envelope.body-non-canonical");
      }
    }
    if (expectedOid !== undefined && expectedOid !== null && envelope.oid !== expectedOid) {
      throw new TineError("object id mismatch", "envelope.oid-mismatch");
    }
    return envelope;
  }
}

/** Python `str()` of a header value, as `ObjectEnvelope.decode` applies it. */
function pyStr(value: JValue | undefined): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "bigint") return value.toString();
  return "<non-string>";
}

function getOr(payload: JObject, key: string, fallback: JValue): JValue {
  return payload.has(key) ? (payload.get(key) as JValue) : fallback;
}

function eventIds(ids: JValue): ids is string[] {
  return Array.isArray(ids) && ids.every((oid) => parseOid(oid)[0] === "event");
}

function unique(values: string[]): boolean {
  return new Set(values).size === values.length;
}

/**
 * SPEC 1.5: the links an envelope's payload carries, with their type rules.
 * A port of `kernel.validate_links`; *exists*, when given, must hold for each.
 */
export function validateLinks(envelope: ObjectEnvelope, exists?: (oid: string) => boolean): unknown[] {
  if (envelope.encoding === "raw" && envelope.schema !== TREE_SCHEMA) return [];
  let payload: JValue;
  try {
    payload =
      envelope.encoding === "json"
        ? (envelope.payload() as JValue)
        : parseBytes(envelope.body, LENIENT, "tree blob");
  } catch {
    throw new TineError("malformed tree blob", "link.malformed");
  }
  if (!isObject(payload)) {
    throw new TineError(`${envelope.objectType} payload must be an object`, "sig.payload-not-object");
  }
  let links: unknown[] = [];
  if (envelope.encoding === "raw") {
    const listed = payload.get("entries");
    const entries: JValue[] = Array.isArray(listed) ? listed : [null];
    links = entries.map((entry) => (isObject(entry) ? (entry.get("oid") ?? null) : null));
    if (links.some((link) => typeof link !== "string" || parseOid(link)[0] !== "blob")) {
      throw new TineError("tree entries must link blob ids", "link.tree-not-blob");
    }
  }
  if (envelope.objectType === "event") {
    for (const field of ["parent_ids", "causal_ids"]) {
      const values = getOr(payload, field, []);
      if (!eventIds(values) || !unique(values)) {
        throw new TineError(`${field} must contain event ids; unique event ids are required`, "link.parent-ids-not-events");
      }
      links.push(...values);
    }
    const parts = getOr(payload, "input_parts", new Map());
    const pairs: [string, JValue | undefined][] = ["input_blob", "output_blob", "artifact_blob", "tree"].map(
      (key) => [key, payload.get(key)],
    );
    if (isObject(parts)) pairs.push(...parts.entries());
    else pairs.push(["input_parts", "-"]);
    for (const [field, value] of pairs) {
      if (truthy(value) && parseOid(value)[0] !== "blob") {
        throw new TineError(`${field} must contain a blob id`, "link.event-blob-not-blob");
      }
      if (truthy(value)) links.push(value);
    }
  }
  if (envelope.objectType === "run") {
    const manifests = getOr(payload, "manifests", new Map());
    if (!isObject(manifests)) throw new TineError("manifests must be an object", "link.run-manifests-not-object");
    const evs = getOr(payload, "events", []);
    if (!eventIds(evs) || !unique(evs)) {
      throw new TineError("events must contain unique event ids", "link.run-events-invalid");
    }
    const fieldValues: string[] = [];
    for (const field of ["roots", "tips"]) {
      const values = getOr(payload, field, []);
      if (!eventIds(values) || !unique(values)) {
        throw new TineError(`${field} must contain unique events from the run`, "link.run-roots-tips-invalid");
      }
      if (!values.every((value) => evs.includes(value))) {
        throw new TineError(`${field} must be a subset of events`, "link.run-roots-tips-not-subset");
      }
      fieldValues.push(...values);
    }
    const blobs: JValue[] = [...manifests.values()];
    for (const [key, value] of payload) if (key.endsWith("_blob") && truthy(value)) blobs.push(value);
    if (blobs.some((value) => parseOid(value)[0] !== "blob")) {
      throw new TineError("run blob fields must contain blob ids", "link.run-blob-not-blob");
    }
    links = [...fieldValues, ...evs, ...blobs];
  }
  if (envelope.objectType === "annotation" || envelope.objectType === "attestation") {
    links = truthy(payload.get("target_id")) ? [payload.get("target_id")] : [];
    const previous = payload.get("previous_id");
    if (envelope.objectType === "annotation" && truthy(previous)) {
      if (parseOid(previous)[0] !== "annotation") {
        throw new TineError("previous_id must contain an annotation id", "link.annotation-previous-not-annotation");
      }
      links.push(previous);
    }
    const evidence = getOr(payload, "evidence_ids", []);
    links.push(...(Array.isArray(evidence) ? evidence : [null]));
    if (envelope.objectType === "attestation") {
      if (parseOid(getOr(payload, "target_id", ""))[0] !== "run") {
        throw new TineError("attestation target_id must contain a run id", "link.attestation-target-not-run");
      }
    }
  }
  if (links.includes(envelope.oid)) throw new TineError("object cannot link to itself", "link.self");
  for (const link of links) {
    parseOid(link);
    if (exists && !exists(link as string)) {
      throw new TineError(`missing linked object: ${link as string}`, "link.missing-object");
    }
  }
  return links;
}
