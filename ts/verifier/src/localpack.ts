/**
 * SPEC 2.8 "Pack v3": a storage-v3 local pack (`TINELP3\n` + TINEZ1 blocks)
 * read through its binary `.tidx`, every stored form rebuilt and checked
 * against its id. Ports of `_pack_v3_index.parse_index`, `_pack_v3.resolve`
 * and the block reads of `_packs.PackSet`, including the 0.40 `BLOB_DELTA`.
 */

import { createHash } from "node:crypto";
import { bytesEqual } from "./canon.js";
import { readUvarint, isWrapped, unwrap } from "./codec.js";
import { TineError } from "./errors.js";
import type { DictLookup } from "./zstddict.js";
import {
  applyBlobDelta,
  applyRunDelta,
  BLOB_DELTA,
  ENCODINGS,
  EVENT_SLIM,
  FULL,
  MAX_DELTA_DEPTH,
  oidOf,
  parseBlobDelta,
  parseRunDelta,
  RUN_DELTA,
  split,
  unslimEvent,
  type BlobDelta,
  type RunDelta,
} from "./forms.js";

const ascii = (text: string) => Uint8Array.from(Buffer.from(text, "latin1"));
export const INDEX_MAGIC = ascii("TINEIX3\n");
export const PACK3_MAGIC = ascii("TINELP3\n");
export const KINDS = ["annotation", "attestation", "blob", "event", "run"];
export const MAX_BLOCK_BYTES = 16 * 1024 * 1024;
export const MAX_OBJECT_BYTES = 256 * 1024 * 1024;
export const MAX_INDEX_OBJECTS = 4_000_000;
const HEAD = 8 + 32 + 4 + 4;
const BLOCK = 4 + 4 + 1;
const ENTRY = 1 + 32 + 4 + 4 + 4 + 4 + 1;
const ALLOWED: Record<number, Set<string>> = {
  [FULL]: new Set(KINDS),
  [RUN_DELTA]: new Set(["run"]),
  [EVENT_SLIM]: new Set(["event"]),
  [BLOB_DELTA]: new Set(["blob"]),
};

export interface Entry {
  block: number;
  start: number;
  length: number;
  size: number;
  encoding: number;
}

export interface Index {
  /** Rows of [offset in the pack, stored length, inflated length]. */
  table: [number, number, number][];
  entries: Map<string, Entry>;
}

const fail = (message: string, code: string): never => {
  throw new TineError(message, code);
};

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

/** `_pack_v3_index.parse_index`: the block table and entries, every rule checked. */
export function parseIndex(data: Uint8Array, digest: string, packSize: number): Index {
  if (data.length < HEAD + 32 || !bytesEqual(data.subarray(0, 8), INDEX_MAGIC)) {
    fail("pack index is malformed", "localpack.index-length");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const count = view.getUint32(40);
  const objects = view.getUint32(44);
  if (count > MAX_INDEX_OBJECTS || objects > MAX_INDEX_OBJECTS) {
    fail("pack index lists too many objects", "localpack.index-length");
  }
  if (data.length !== HEAD + count * BLOCK + objects * ENTRY + 32) {
    fail("pack index is truncated or has trailing bytes", "localpack.index-length");
  }
  if (!bytesEqual(sha256(data.subarray(0, data.length - 32)), data.subarray(data.length - 32))) {
    fail("pack index checksum does not match", "localpack.index-checksum");
  }
  if (Buffer.from(data.subarray(8, 40)).toString("hex") !== digest) {
    fail("pack index does not describe its pack", "localpack.index-checksum");
  }
  const table: [number, number, number][] = [];
  const kinds: number[] = [];
  let cursor = PACK3_MAGIC.length;
  for (let number = 0; number < count; number++) {
    const at = HEAD + number * BLOCK;
    const stored = view.getUint32(at);
    const inflated = view.getUint32(at + 4);
    const kind = data[at + 8];
    if (stored < 1 || inflated < 1 || kind >= KINDS.length || inflated > MAX_OBJECT_BYTES) {
      fail("pack index block table is malformed", "localpack.block-size");
    }
    table.push([cursor, stored, inflated]);
    kinds.push(kind);
    cursor += stored;
  }
  if (cursor !== packSize) fail("pack index does not cover its pack exactly", "localpack.block-size");
  const base = HEAD + count * BLOCK;
  const entries = new Map<string, Entry>();
  const spans: [number, number][][] = table.map(() => []);
  let previous: Uint8Array = new Uint8Array(0);
  for (let number = 0; number < objects; number++) {
    const at = base + number * ENTRY;
    const key = data.subarray(at, at + 33);
    if (Buffer.compare(key, previous) <= 0) fail("pack index entries are not sorted and unique", "localpack.index-order");
    previous = key;
    const kind = data[at];
    const block = view.getUint32(at + 33);
    const start = view.getUint32(at + 37);
    const length = view.getUint32(at + 41);
    const size = view.getUint32(at + 45);
    const encoding = data[at + 49];
    if (kind >= KINDS.length || !ENCODINGS.includes(encoding) || !ALLOWED[encoding].has(KINDS[kind])) {
      fail("pack index entry is malformed", "localpack.encoding-kind");
    }
    if (block >= count || kinds[block] !== kind) fail("pack index entry points outside its pack", "localpack.index-order");
    if (length < 1 || size > MAX_OBJECT_BYTES || (encoding === FULL && length !== size)) {
      fail("pack index entry sizes are inconsistent", "localpack.object-id-mismatch");
    }
    if (encoding === RUN_DELTA && start === 0) {
      fail("pack index run delta has no base before it in its block", "localpack.delta-no-base");
    }
    spans[block].push([start, length]);
    const oid = `${KINDS[kind]}:sha256:${Buffer.from(data.subarray(at + 1, at + 33)).toString("hex")}`;
    entries.set(oid, { block, start, length, size, encoding });
  }
  table.forEach((row, number) => tile(row[2], spans[number]));
  return { table, entries };
}

function tile(inflated: number, items: [number, number][]): void {
  items.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let cursor = 0;
  for (const [start, length] of items) {
    if (start !== cursor) fail("pack index block entries do not tile their block", "localpack.block-size");
    cursor += length;
  }
  if (!items.length || cursor !== inflated) fail("pack index block is empty or its length is wrong", "localpack.block-size");
  if (items.length > 1 && inflated > MAX_BLOCK_BYTES) fail("pack index block is oversized", "localpack.block-size");
}

/** A storage-v3 pack and its index, read object by object. */
export class LocalPack {
  readonly index: Index;
  private readonly blocks = new Map<number, Uint8Array>();
  private readonly ends = new Map<string, string>();

  constructor(
    readonly pack: Uint8Array,
    indexBytes: Uint8Array,
    /** The repository's `dicts/<sha256>.zdict` files, for codec-3 blocks. */
    private readonly dictionaries?: DictLookup,
  ) {
    if (pack.length < PACK3_MAGIC.length || !bytesEqual(pack.subarray(0, 8), PACK3_MAGIC)) {
      fail("not a storage-v3 pack", "localpack.index-length");
    }
    if (!bytesEqual(indexBytes.subarray(0, 8), INDEX_MAGIC)) fail("not a storage-v3 index", "localpack.index-length");
    this.digest = sha256(pack).toString("hex");
    this.index = parseIndex(indexBytes, this.digest, pack.length);
    for (const [oid, entry] of this.index.entries) this.ends.set(`${entry.block}:${entry.start + entry.length}`, oid);
  }

  readonly digest: string;

  block(number: number): Uint8Array {
    let data = this.blocks.get(number);
    if (data === undefined) {
      const [offset, stored, inflated] = this.index.table[number];
      const frame = this.pack.subarray(offset, offset + stored);
      const declared = isWrapped(frame) ? readUvarint(frame, 8)[0] : frame.length;
      if (declared !== inflated) fail("pack block size does not match its index", "localpack.block-size");
      data = unwrap(frame, inflated, this.dictionaries);
      this.blocks.clear(); // one block at a time: reads go in block order
      this.blocks.set(number, data);
    }
    return data;
  }

  /** (stored bytes, encoding, canonical size, the object stored just before it) */
  stored(oid: string): [Uint8Array, number, number, string | null] | null {
    const entry = this.index.entries.get(oid);
    if (entry === undefined) return null;
    const data = this.block(entry.block);
    if (entry.start + entry.length > data.length) fail(`pack index points past its block: ${oid}`, "localpack.block-size");
    const before = entry.encoding === RUN_DELTA && entry.start ? (this.ends.get(`${entry.block}:${entry.start}`) ?? null) : null;
    return [data.subarray(entry.start, entry.start + entry.length), entry.encoding, entry.size, before];
  }

  /** Every oid ordered so each block is inflated once. */
  inBlockOrder(): string[] {
    return [...this.index.entries]
      .sort(([, a], [, b]) => a.block - b.block || a.start - b.start)
      .map(([oid]) => oid);
  }

  /** `_pack_v3.resolve`: the canonical bytes of *oid*, every rebuilt object checked. */
  read(oid: string, known = new Map<string, [Uint8Array, number]>()): Uint8Array {
    type Link = [string, number, BlobDelta | [RunDelta, Uint8Array], number];
    const chain: Link[] = [];
    const seen = new Set<string>();
    let current = oid;
    let data: Uint8Array = new Uint8Array(0);
    let encoding = FULL;
    let size = 0;
    const kind = oid.split(":")[0];
    while (!known.has(current)) {
      if (seen.has(current)) fail(`packed delta chain loops back to ${current}: ${oid}`, "localpack.delta-too-deep");
      seen.add(current);
      const found = this.stored(current);
      if (found === null) fail(`packed delta base is not in its pack: ${current}`, "localpack.delta-no-base");
      let base: string | null;
      [data, encoding, size, base] = found!;
      if (encoding !== RUN_DELTA && encoding !== BLOB_DELTA) break;
      if (chain.length >= MAX_DELTA_DEPTH) fail(`packed ${kind} delta chain is too deep: ${oid}`, "localpack.delta-too-deep");
      let payload: BlobDelta | [RunDelta, Uint8Array];
      if (encoding === BLOB_DELTA) {
        const delta = parseBlobDelta(data);
        payload = delta;
        base = delta.base;
      } else {
        payload = [parseRunDelta(data), split(data)[0]];
      }
      if (base === null) fail(`packed run delta starts its block: ${current}`, "localpack.delta-no-base");
      chain.push([current, encoding, payload, size]);
      current = base as string;
    }
    let depth = chain.length;
    let raw: Uint8Array;
    if (known.has(current)) {
      const [bytes, below] = known.get(current) as [Uint8Array, number];
      raw = bytes;
      depth += below;
      if (depth > MAX_DELTA_DEPTH) fail(`packed ${kind} delta chain is too deep: ${oid}`, "localpack.delta-too-deep");
    } else {
      raw = encoding === EVENT_SLIM ? unslimEvent(data) : data;
      check(current, raw, size);
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      const [target, form, payload, targetSize] = chain[i];
      if (form === BLOB_DELTA) {
        raw = applyBlobDelta(payload as BlobDelta, raw);
      } else {
        const [delta, header] = payload as [RunDelta, Uint8Array];
        if (!bytesEqual(split(raw)[0], header)) {
          fail(`packed run delta header differs from its base: ${target}`, "localpack.object-id-mismatch");
        }
        raw = applyRunDelta(raw, delta);
      }
      check(target, raw, targetSize);
    }
    if (oid.startsWith("run:") || oid.startsWith("blob:")) known.set(oid, [raw, depth]);
    return raw;
  }
}

function check(oid: string, raw: Uint8Array, size: number): void {
  if (raw.length !== size) fail(`packed object size does not match its index: ${oid}`, "localpack.object-id-mismatch");
  let actual: string;
  try {
    actual = oidOf(raw);
  } catch {
    actual = "";
  }
  if (actual !== oid) fail(`packed object does not match its id: ${oid}`, "localpack.object-id-mismatch");
}

/** The localpack.read op: each object's id and the SHA-256 of its rebuilt bytes. */
export function readLocalPack(
  indexBytes: Uint8Array,
  pack: Uint8Array,
  dictionaries?: DictLookup,
): { pack_id: string; objects: [string, string][] } {
  const local = new LocalPack(pack, indexBytes, dictionaries);
  const known = new Map<string, [Uint8Array, number]>();
  const objects: [string, string][] = local
    .inBlockOrder()
    .map((oid) => [oid, sha256(local.read(oid, known)).toString("hex")]);
  objects.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return { pack_id: local.digest, objects };
}
