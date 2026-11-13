/**
 * Streaming reads for opentine bundles (0.51): a `ByteSource` over a browser
 * `Blob` (`Blob.slice`) or bytes in memory, incremental SHA-256 over byte
 * ranges, and the constant-memory-per-object fast path for a bundle's
 * `TINEPACK3`: the zlib body is inflated incrementally (pako) and matched
 * against the one canonical manifest grammar as it streams, one packed object
 * at a time (each decoded and checked, then dropped; only its oid is kept).
 *
 * The fast path only ever *accepts*. Anything it does not recognise -- a
 * stream error, a byte off the canonical grammar, a bad object, a duplicate,
 * a checksum mismatch, a cap -- sends the caller to the exact in-memory reader
 * (`inspectPack`, bounded by the same caps as Python), so every refusal carries
 * the reason code the conformance vectors pin.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { inflate, inflateEnd, inflateInit } from "pako/lib/zlib/inflate.js";
import ZStream from "pako/lib/zlib/zstream.js";
import { bytesEqual } from "./canon.js";
import { ObjectEnvelope, parseOid } from "./envelope.js";
import { MAGIC3, MAX_PACK_BODY_BYTES, MAX_PACK_OBJECTS, strictBase64 } from "./pack.js";

/** Random access to a byte range, so a 1 GiB file is never one buffer. */
export interface ByteSource {
  readonly size: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

export const CHUNK_BYTES = 4 * 1024 * 1024;

/** Read and inflate sizes; tests shrink them to cross every token boundary. */
export const tuning = { chunk: CHUNK_BYTES, out: 256 * 1024 };

/** A `ByteSource` over bytes already in memory. */
export function bytesSource(data: Uint8Array): ByteSource {
  return { size: data.length, read: async (offset, length) => data.subarray(offset, offset + length) };
}

interface BlobLike {
  readonly size: number;
  slice(start: number, end: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

/** A `ByteSource` over a browser `Blob` / `File`: each read is one `Blob.slice`. */
export function blobSource(blob: BlobLike): ByteSource {
  return {
    size: blob.size,
    read: async (offset, length) => new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer()),
  };
}

/** The bytes of `[start, end)` in chunks of at most `tuning.chunk`. */
export async function* ranges(source: ByteSource, start: number, end: number): AsyncGenerator<Uint8Array> {
  for (let at = start; at < end; at += tuning.chunk) yield source.read(at, Math.min(tuning.chunk, end - at));
}

export const hexOf = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** The pack fast path's result; `null` from `streamV3` means "ask the exact reader". */
export interface StreamedPack {
  packId: string;
  oids: Set<string>;
  shallow: string[];
}

const enc = new TextEncoder();
const SAFE = /^[A-Za-z0-9:._-]+$/;
const latin1 = (bytes: Uint8Array) => String.fromCharCode(...bytes.subarray(0, 512)) + (bytes.length > 512 ? "\u0000" : "");

class Mismatch extends Error {}


/** The canonical `TINEPACK3` manifest grammar, matched byte by byte as it streams. */
class V3Matcher {
  readonly oids = new Set<string>();
  readonly shallow: string[] = [];
  done = false;
  private lit: Uint8Array | null = enc.encode('{"objects":[');
  private li = 0;
  private after: () => void = () => this.choose((b) => (b === 0x5d ? this.toShallow() : b === 0x7b ? this.entry() : this.bad()));
  private parts: Uint8Array[] | null = null;
  private onString: (value: Uint8Array) => void = () => undefined;
  private choice: ((byte: number) => void) | null = null;
  private data: Uint8Array = new Uint8Array(0);

  private bad(): never {
    throw new Mismatch();
  }
  private expect(text: string, then: () => void): void {
    this.lit = enc.encode(text);
    this.li = 0;
    this.after = then;
  }
  private choose(then: (byte: number) => void): void {
    this.choice = then;
  }
  private string(then: (value: Uint8Array) => void): void {
    this.parts = [];
    this.onString = then;
  }
  private entry(): void {
    this.expect('"data":"', () => this.string((data) => {
      this.data = data;
      this.expect(',"id":"', () => this.string((id) => this.object(id)));
    }));
  }
  private object(rawId: Uint8Array): void {
    const id = latin1(rawId);
    if (!SAFE.test(id) || this.oids.has(id) || this.oids.size >= MAX_PACK_OBJECTS) this.bad();
    try {
      ObjectEnvelope.decode(strictBase64(new TextDecoder().decode(this.data)), id);
    } catch {
      this.bad();
    }
    this.data = new Uint8Array(0);
    this.oids.add(id);
    this.expect("}", () => this.choose((b) => (b === 0x2c ? this.expect("{", () => this.entry()) : b === 0x5d ? this.toShallow() : this.bad())));
  }
  private toShallow(): void {
    this.expect(',"shallow":[', () => this.choose((b) => (b === 0x5d ? this.toEnd() : b === 0x22 ? this.string((s) => this.boundary(s)) : this.bad())));
  }
  private boundary(raw: Uint8Array): void {
    const oid = latin1(raw);
    if (!SAFE.test(oid) || this.shallow.length >= MAX_PACK_OBJECTS) this.bad();
    this.shallow.push(oid);
    this.choose((b) => (b === 0x2c ? this.expect('"', () => this.string((s) => this.boundary(s))) : b === 0x5d ? this.toEnd() : this.bad()));
  }
  private toEnd(): void {
    this.expect(',"version":1}', () => {
      this.done = true;
    });
  }

  push(chunk: Uint8Array): void {
    let i = 0;
    while (i < chunk.length) {
      if (this.lit) {
        if (chunk[i++] !== this.lit[this.li++]) this.bad();
        if (this.li === this.lit.length) {
          this.lit = null;
          this.after();
        }
      } else if (this.parts) {
        const quote = chunk.indexOf(0x22, i);
        const end = quote < 0 ? chunk.length : quote;
        if (chunk.subarray(i, end).includes(0x5c)) this.bad(); // an escape: not the plain canonical form
        this.parts.push(chunk.slice(i, end));
        i = end;
        if (quote >= 0) {
          i++;
          const parts = this.parts;
          this.parts = null;
          const size = parts.reduce((n, p) => n + p.length, 0);
          const value = new Uint8Array(size);
          let at = 0;
          for (const part of parts) {
            value.set(part, at);
            at += part.length;
          }
          this.onString(value);
        }
      } else if (this.choice) {
        const choice = this.choice;
        this.choice = null;
        choice(chunk[i++]);
      } else {
        this.bad(); // bytes after the closing brace
      }
    }
  }

  finish(): void {
    if (!this.done || this.lit || this.parts || this.choice) this.bad();
    const ids = this.oids;
    if (new Set(this.shallow).size !== this.shallow.length || this.shallow.some((oid) => ids.has(oid))) this.bad();
    for (const oid of this.shallow) {
      try {
        parseOid(oid);
      } catch {
        this.bad();
      }
    }
  }
}

const Z_OK = 0;
const Z_STREAM_END = 1;
const Z_BUF_ERROR = -5;

/**
 * Accept the `TINEPACK3` at `[start, end)` of `source` in constant memory per
 * object, or return `null` for the exact reader to give the verdict. Inflate
 * is pako's zlib port fed chunk by chunk, the same engine in every browser and
 * in Node, so a stream that ends early or has trailing bytes is never
 * accepted.
 */
export async function streamV3(source: ByteSource, start: number, end: number): Promise<StreamedPack | null> {
  if (end - start < MAGIC3.length + 32) return null;
  const head = await source.read(start, MAGIC3.length + 32);
  if (!bytesEqual(head.subarray(0, MAGIC3.length), MAGIC3)) return null;
  const expected = head.slice(MAGIC3.length);
  const strm = new ZStream();
  if (inflateInit(strm) !== Z_OK) return null;
  const hash = sha256.create();
  const matcher = new V3Matcher();
  let total = 0;
  let ended = false;
  try {
    for await (const chunk of ranges(source, start + MAGIC3.length + 32, end)) {
      if (ended) throw new Mismatch(); // trailing bytes after the zlib stream
      strm.input = chunk;
      strm.next_in = 0;
      strm.avail_in = chunk.length;
      while (!ended) {
        const size = tuning.out;
        const out = new Uint8Array(size);
        strm.output = out;
        strm.next_out = 0;
        strm.avail_out = size;
        const status = inflate(strm, 0);
        const produced = out.subarray(0, size - strm.avail_out);
        total += produced.length;
        if (total > MAX_PACK_BODY_BYTES) throw new Mismatch();
        hash.update(produced);
        matcher.push(produced);
        if (status === Z_STREAM_END) ended = true;
        else if (status !== Z_OK && status !== Z_BUF_ERROR) throw new Mismatch();
        if (ended && strm.avail_in > 0) throw new Mismatch();
        // Next chunk once this one is consumed and the output did not fill (no output pending).
        if (status === Z_BUF_ERROR || (strm.avail_in === 0 && strm.avail_out > 0)) break;
      }
    }
    if (!ended) throw new Mismatch();
    matcher.finish();
  } catch {
    return null;
  } finally {
    inflateEnd(strm);
  }
  const actual = hash.digest();
  if (!bytesEqual(actual, expected)) return null;
  return { packId: `sha256:${hexOf(actual)}`, oids: matcher.oids, shallow: matcher.shallow };
}
