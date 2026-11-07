/**
 * SPEC 2.8 network packs: `TINEPACK3` (a zlib'd canonical JSON manifest),
 * `TINEPACK4` (a binary header over one codec-wrapped body) and `TINEPACK5`
 * (recording order, stored forms, one long-distance zstd frame in blocks).
 * Ports of `opentine.repository.pack`, `_pack4`, `_pack5` and the link checks
 * of `_pack_install`, every limit checked before anything is inflated.
 */

import { inflateSync } from "node:zlib";
import { createHash } from "node:crypto";
import { bytesEqual, canonicalJson, validateJsonShape } from "./canon.js";
import { isWrapped, readUvarint, unwrap } from "./codec.js";
import { ObjectEnvelope, parseOid, validateLinks } from "./envelope.js";
import { TineError } from "./errors.js";
import {
  applyRunDelta,
  EVENT_SLIM,
  FULL,
  MAX_DELTA_DEPTH,
  oidOf,
  parseRunDelta,
  RUN_DELTA,
  unslimEvent,
} from "./forms.js";
import { isInt, isObject, KERNEL, LENIENT, parseBytes, type JObject, type JValue } from "./json.js";
import { decompressChunks, WINDOW_LOG } from "./zstd.js";

const ascii = (text: string) => Uint8Array.from(Buffer.from(text, "latin1"));
export const MAGIC3 = ascii("TINEPACK3\0");
export const MAGIC4 = ascii("TINEPACK4\0");
export const MAGIC5 = ascii("TINEPACK5\0");
export const MAX_PACK_BYTES = 256 * 1024 * 1024;
export const MAX_PACK_BODY_BYTES = 256 * 1024 * 1024;
/** `_traversal.MAX_TRAVERSAL_OBJECTS`. */
export const MAX_PACK_OBJECTS = 10_000;
const MAX_HEADER_BYTES = 16 * 1024 * 1024;

export interface InspectedPack {
  packId: string;
  objects: [string, Uint8Array][];
  shallow: string[];
}

const fail = (message: string, code: string): never => {
  throw new TineError(message, code);
};

function startsWith(data: Uint8Array, magic: Uint8Array): boolean {
  return data.length >= magic.length && bytesEqual(data.subarray(0, magic.length), magic);
}

const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest();
const hexOf = (data: Uint8Array) => Buffer.from(data).toString("hex");

/** Python `base64.b64decode(text, validate=True)`. */
export function strictBase64(text: unknown): Uint8Array {
  if (typeof text !== "string" || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    fail("invalid packed object", "pack.entry-base64");
  }
  return Uint8Array.from(Buffer.from(text as string, "base64"));
}

function packedObject(raw: Uint8Array, oid: JValue | undefined): void {
  try {
    ObjectEnvelope.decode(raw, typeof oid === "string" ? oid : "\0");
  } catch (exc) {
    fail(`invalid packed object: ${(exc as Error).message}`, "pack.entry-oid-mismatch");
  }
}

function sorted(values: string[]): string[] {
  return values.slice().sort();
}

// --------------------------------------------------------------------------- //
// TINEPACK3
// --------------------------------------------------------------------------- //

function boundedInflate(data: Uint8Array, limit: number): Uint8Array {
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(data, { info: true, maxOutputLength: limit }) as unknown as typeof result;
  } catch (exc) {
    const code = (exc as { code?: string }).code;
    if (code === "ERR_BUFFER_TOO_LARGE") fail("pack exceeds maximum decompressed size", "pack.oversized");
    if (code === "Z_BUF_ERROR") fail("pack has truncated or trailing compressed data", "pack.truncated-or-trailing");
    fail("invalid compressed pack", "pack.invalid-compression");
  }
  if (result!.engine.bytesWritten !== data.length) {
    fail("pack has truncated or trailing compressed data", "pack.truncated-or-trailing");
  }
  return result!.buffer;
}

function inspectV3(data: Uint8Array, maxBody: number): InspectedPack {
  if (!startsWith(data, MAGIC3) || data.length < MAGIC3.length + 32) fail("invalid pack header", "pack.bad-magic");
  const expected = data.subarray(MAGIC3.length, MAGIC3.length + 32);
  const body = boundedInflate(data.subarray(MAGIC3.length + 32), maxBody);
  const actual = sha256(body);
  if (!bytesEqual(actual, expected)) fail("pack checksum mismatch", "pack.checksum-mismatch");
  validateJsonShape(body);
  let payload: JValue;
  let canonical: Uint8Array;
  try {
    payload = parseBytes(body, LENIENT, "pack manifest");
    canonical = canonicalJson(payload);
  } catch {
    fail("invalid pack manifest", "pack.manifest-malformed");
  }
  if (!isObject(payload!) || !bytesEqual(canonical!, body)) {
    fail("non-canonical or unsupported pack", "pack.manifest-non-canonical");
  }
  const manifest = payload! as JObject;
  if (manifest.size !== 3 || !["objects", "shallow", "version"].every((key) => manifest.has(key))) {
    fail("non-canonical or unsupported pack", "pack.manifest-key-set");
  }
  if (manifest.get("version") !== 1n) fail("non-canonical or unsupported pack", "pack.version-unsupported");
  const entries = manifest.get("objects");
  const shallow = manifest.get("shallow");
  if (!Array.isArray(entries) || !Array.isArray(shallow)) fail("invalid pack manifest", "pack.arrays-invalid");
  const list = entries as JValue[];
  const boundary = shallow as JValue[];
  if (list.length > MAX_PACK_OBJECTS || boundary.length > MAX_PACK_OBJECTS) {
    fail("pack exceeds maximum object count", "pack.too-many-objects");
  }
  const objects: [string, Uint8Array][] = [];
  for (const entry of list) {
    if (!isObject(entry) || entry.size !== 2 || !entry.has("data") || !entry.has("id")) {
      fail("invalid packed object", "pack.entry-shape");
    }
    const item = entry as JObject;
    const raw = strictBase64(item.get("data"));
    packedObject(raw, item.get("id"));
    objects.push([item.get("id") as string, raw]);
  }
  if (!boundary.every((oid) => typeof oid === "string")) fail("invalid shallow object id", "pack.shallow-invalid-oid");
  const ids = objects.map(([oid]) => oid);
  const names = boundary as string[];
  if (new Set(ids).size !== ids.length || new Set(names).size !== names.length) {
    fail("pack contains duplicate object ids", "pack.duplicate-ids");
  }
  const idSet = new Set(ids);
  if (names.some((oid) => idSet.has(oid))) {
    fail("packed objects cannot also be shallow boundaries", "pack.shallow-overlaps-objects");
  }
  for (const oid of names) {
    try {
      parseOid(oid);
    } catch {
      fail(`invalid shallow object id: ${oid}`, "pack.shallow-invalid-oid");
    }
  }
  return { packId: `sha256:${hexOf(actual)}`, objects, shallow: names };
}

// --------------------------------------------------------------------------- //
// TINEPACK4 and TINEPACK5
// --------------------------------------------------------------------------- //

function packHeader(payload: Uint8Array, keys: string[]): [JObject, number] {
  let length: number;
  let start: number;
  try {
    [length, start] = readUvarint(payload, 0);
  } catch {
    fail("invalid pack header", "pack.manifest-malformed");
  }
  if (length! > MAX_HEADER_BYTES || start! + length! > payload.length) fail("invalid pack header", "pack.manifest-malformed");
  const raw = payload.subarray(start!, start! + length!);
  validateJsonShape(raw);
  let header: JValue;
  let canonical: Uint8Array;
  try {
    header = parseBytes(raw, KERNEL, "pack header");
    canonical = canonicalJson(header);
  } catch {
    fail("invalid pack header", "pack.manifest-malformed");
  }
  if (!bytesEqual(canonical!, raw) || !isObject(header!)) {
    fail("non-canonical or unsupported pack", "pack.manifest-non-canonical");
  }
  const value = header! as JObject;
  if (value.size !== keys.length || !keys.every((key) => value.has(key))) {
    fail("non-canonical or unsupported pack", "pack.manifest-key-set");
  }
  if (value.get("version") !== 1n) fail("non-canonical or unsupported pack", "pack.version-unsupported");
  if (keys.includes("codec") && !["zlib", "zstd"].includes(value.get("codec") as string)) {
    fail("unsupported pack codec", "pack.invalid-compression");
  }
  if (keys.includes("objects") && (!Array.isArray(value.get("objects")) || !Array.isArray(value.get("shallow")))) {
    fail("invalid pack manifest", "pack.arrays-invalid");
  }
  return [value, start! + length!];
}

/** `_pack4.check_ids`: ids unique, the boundary sorted, unique, disjoint, and oids. */
function checkIds(objects: [string, Uint8Array][], shallow: JValue): [string, Uint8Array][] {
  const ids = sorted(objects.map(([oid]) => oid));
  if (!Array.isArray(shallow) || !shallow.every((oid) => typeof oid === "string")) {
    fail("invalid pack shallow list", "pack.shallow-invalid-oid");
  }
  const names = shallow as string[];
  const canonicalShallow = sorted([...new Set(names)]);
  if (new Set(ids).size !== ids.length || canonicalShallow.join("\n") !== names.join("\n") || canonicalShallow.length !== names.length) {
    fail("pack objects must be sorted and unique", "pack.duplicate-ids");
  }
  const idSet = new Set(ids);
  if (names.some((oid) => idSet.has(oid))) {
    fail("packed objects cannot also be shallow boundaries", "pack.shallow-overlaps-objects");
  }
  for (const oid of names) {
    try {
      parseOid(oid);
    } catch {
      fail(`invalid shallow object id: ${oid}`, "pack.shallow-invalid-oid");
    }
  }
  return objects.slice().sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function checksummed(data: Uint8Array, magic: Uint8Array): [Uint8Array, Buffer] {
  if (data.length < magic.length + 32 || !startsWith(data, magic)) fail("invalid pack header", "pack.bad-magic");
  const expected = data.subarray(magic.length, magic.length + 32);
  const payload = data.subarray(magic.length + 32);
  const actual = sha256(payload);
  if (!bytesEqual(actual, expected)) fail("pack checksum mismatch", "pack.checksum-mismatch");
  return [payload, actual];
}

function inspectV4(data: Uint8Array, maxBody: number): InspectedPack {
  const [payload, actual] = checksummed(data, MAGIC4);
  const [header, offset] = packHeader(payload, ["codec", "objects", "shallow", "version"]);
  const entries = header.get("objects") as JValue[];
  const shallow = header.get("shallow") as JValue[];
  if (entries.length > MAX_PACK_OBJECTS || shallow.length > MAX_PACK_OBJECTS) {
    fail("pack exceeds maximum object count", "pack.too-many-objects");
  }
  const lengths: [string, number][] = [];
  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || !isInt(entry[1]) || entry[1] < 0n) {
      fail("invalid pack manifest", "pack.entry-shape");
    }
    lengths.push([(entry as JValue[])[0] as string, Number((entry as JValue[])[1])]);
  }
  const total = lengths.reduce((sum, [, length]) => sum + length, 0);
  if (total > maxBody) fail("pack exceeds maximum decompressed size", "pack.oversized");
  const body = payload.subarray(offset);
  if (!isWrapped(body) || readUvarint(body, 8)[0] !== total) {
    fail("pack body does not match its manifest", "pack.truncated-or-trailing");
  }
  let raw: Uint8Array;
  try {
    raw = unwrap(body, total);
  } catch (exc) {
    fail(`invalid compressed pack: ${(exc as Error).message}`, "pack.invalid-compression");
  }
  const objects: [string, Uint8Array][] = [];
  let cursor = 0;
  for (const [oid, length] of lengths) {
    const chunk = raw!.subarray(cursor, cursor + length);
    cursor += length;
    packedObject(chunk, oid);
    objects.push([oid, chunk]);
  }
  const ids = objects.map(([oid]) => oid);
  if (ids.join("\n") !== sorted(ids).join("\n")) fail("pack objects must be sorted and unique", "pack.duplicate-ids");
  return { packId: `sha256:${hexOf(actual)}`, objects: checkIds(objects, shallow), shallow: shallow as string[] };
}

function nonNegativeRows(value: JValue | undefined, width: number): number[][] {
  if (
    !Array.isArray(value) ||
    !value.every((row) => Array.isArray(row) && row.length === width && row.every((n) => isInt(n) && n >= 0n))
  ) {
    fail("invalid pack manifest", "pack.manifest-malformed");
  }
  return (value as bigint[][]).map((row) => row.map(Number));
}

function v5Manifest(raw: Uint8Array): [number[][], JValue] {
  let manifest: JValue;
  let canonical: Uint8Array;
  try {
    validateJsonShape(raw);
    manifest = parseBytes(raw, KERNEL, "pack manifest");
    canonical = canonicalJson(manifest);
  } catch {
    fail("invalid pack manifest", "pack.manifest-malformed");
  }
  const value = manifest!;
  if (!bytesEqual(canonical!, raw) || !isObject(value) || value.size !== 2 || !value.has("objects") || !value.has("shallow")) {
    fail("non-canonical or unsupported pack", "pack.manifest-non-canonical");
  }
  return [nonNegativeRows((value as JObject).get("objects"), 3), (value as JObject).get("shallow") as JValue];
}

function rebuild(stored: Uint8Array, encoding: number, base: Uint8Array | null): Uint8Array {
  if (encoding === FULL) return stored;
  if (encoding === EVENT_SLIM) return unslimEvent(stored);
  if (encoding === RUN_DELTA && base !== null) return applyRunDelta(base, parseRunDelta(stored));
  return fail("invalid stored form in pack", "pack.entry-shape");
}

function inspectV5(data: Uint8Array, maxBody: number): InspectedPack {
  const [payload, actual] = checksummed(data, MAGIC5);
  const [header, offset] = packHeader(payload, ["blocks", "version", "window_log"]);
  if (header.get("window_log") !== BigInt(WINDOW_LOG)) fail("unsupported pack window", "pack.invalid-compression");
  const blocks = nonNegativeRows(header.get("blocks"), 2);
  if (!blocks.length || blocks.length > MAX_PACK_OBJECTS + 1 || blocks[0][1] > MAX_HEADER_BYTES) {
    fail("invalid pack manifest", "pack.manifest-malformed");
  }
  const bodyBytes = blocks.slice(1).reduce((sum, [, raw]) => sum + raw, 0);
  if (bodyBytes > maxBody) fail("pack exceeds maximum decompressed size", "pack.oversized");
  if (offset + blocks.reduce((sum, [frame]) => sum + frame, 0) !== payload.length) {
    fail("pack body does not match its manifest", "pack.truncated-or-trailing");
  }
  const frames: [Uint8Array, number][] = [];
  let cursor = offset;
  for (const [frame, raw] of blocks) {
    frames.push([payload.subarray(cursor, cursor + frame), raw]);
    cursor += frame;
  }
  let inflated: Uint8Array[];
  try {
    inflated = decompressChunks(frames);
  } catch (exc) {
    fail(`invalid compressed pack: ${(exc as Error).message}`, "pack.invalid-compression");
  }
  const [entries, shallow] = v5Manifest(inflated![0]);
  if (entries.length > MAX_PACK_OBJECTS || (Array.isArray(shallow) && shallow.length > MAX_PACK_OBJECTS)) {
    fail("pack exceeds maximum object count", "pack.too-many-objects");
  }
  if (entries.reduce((sum, [, , size]) => sum + size, 0) > maxBody) {
    fail("pack exceeds maximum decompressed size", "pack.oversized");
  }
  if (entries.reduce((sum, [, stored]) => sum + stored, 0) !== bodyBytes) {
    fail("pack body does not match its manifest", "pack.truncated-or-trailing");
  }
  const body = Buffer.concat(inflated!.slice(1));
  const objects: [string, Uint8Array][] = [];
  let base: Uint8Array | null = null;
  let depth = 0;
  let at = 0;
  for (const [encoding, stored, size] of entries) {
    const chunk = body.subarray(at, at + stored);
    at += stored;
    depth = encoding === RUN_DELTA ? depth + 1 : 0;
    if (depth > MAX_DELTA_DEPTH) fail("packed run delta chain is too deep", "pack.entry-shape");
    let raw: Uint8Array;
    let oid: string;
    try {
      raw = rebuild(chunk, encoding, base);
      oid = oidOf(raw);
      const kind = encoding === RUN_DELTA ? "run:" : encoding === EVENT_SLIM ? "event:" : "";
      if (raw.length !== size || !oid.startsWith(kind)) throw new TineError("stored form does not match its object");
      ObjectEnvelope.decode(raw, oid);
    } catch (exc) {
      fail(`invalid packed object: ${(exc as Error).message}`, "pack.entry-oid-mismatch");
    }
    objects.push([oid!, raw!]);
    base = oid!.startsWith("run:") ? raw! : null;
  }
  return { packId: `sha256:${hexOf(actual)}`, objects: checkIds(objects, shallow), shallow: shallow as string[] };
}

/** `pack.inspect_pack`: (pack id, objects, shallow boundary) of any wire pack format. */
export function inspectPack(data: Uint8Array, maxBody = MAX_PACK_BODY_BYTES, maxPack = MAX_PACK_BYTES): InspectedPack {
  if (data.length > maxPack) fail("pack exceeds maximum transfer size", "pack.oversized");
  if (startsWith(data, MAGIC4)) return inspectV4(data, maxBody);
  if (startsWith(data, MAGIC5)) return inspectV5(data, maxBody);
  return inspectV3(data, maxBody);
}

// --------------------------------------------------------------------------- //
// The writer half and installation's link checks
// --------------------------------------------------------------------------- //

/** The canonical `TINEPACK3` manifest body (and pack id) for stored envelopes. */
export function packManifest(raws: Uint8Array[]): { body: Uint8Array; packId: string } {
  const envelopes = raws.map((raw) => [ObjectEnvelope.decode(raw), raw] as const);
  const packed = new Set(envelopes.map(([envelope]) => envelope.oid));
  const shallow = new Set<string>();
  const entries: JObject[] = [];
  for (const [envelope, raw] of envelopes) {
    entries.push(
      new Map<string, JValue>([
        ["data", Buffer.from(raw).toString("base64")],
        ["id", envelope.oid],
      ]),
    );
    for (const link of validateLinks(envelope) as string[]) if (!packed.has(link)) shallow.add(link);
  }
  entries.sort((a, b) => ((a.get("id") as string) < (b.get("id") as string) ? -1 : 1));
  const body = canonicalJson(
    new Map<string, JValue>([
      ["objects", entries],
      ["shallow", sorted([...shallow])],
      ["version", 1n],
    ]),
  );
  return { body, packId: `sha256:${hexOf(sha256(body))}` };
}

/**
 * `_pack_install.install_inspected`'s refusals: every link outside the pack is
 * held by the destination or listed as a boundary, and the boundary is exactly
 * those links. Returns the pack id and object ids installation would write.
 */
export function checkInstall(data: Uint8Array, held: Set<string>): { packId: string; objects: string[] } {
  const pack = inspectPack(data);
  const packed = new Set(pack.objects.map(([oid]) => oid));
  const incoming = new Set(pack.shallow);
  const external = new Set<string>();
  for (const [oid, raw] of pack.objects) {
    for (const link of validateLinks(ObjectEnvelope.decode(raw, oid)) as string[]) {
      if (packed.has(link)) continue;
      external.add(link);
      if (!held.has(link) && !incoming.has(link)) fail(`pack has unresolved link: ${link}`, "pack.unresolved-link");
    }
  }
  if (incoming.size !== external.size || [...incoming].some((oid) => !external.has(oid))) {
    fail("pack shallow boundaries do not match its external links", "pack.shallow-not-link-closure");
  }
  return { packId: pack.packId, objects: sorted([...packed]) };
}
