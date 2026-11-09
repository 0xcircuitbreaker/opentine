/**
 * The `TINEZ1\0` storage wrapper (SPEC 2.3): magic, codec byte, uvarint length,
 * frame. Codec 0 is stored, 1 is zlib, 2 is zstd (`./zstd.ts`). xz (4), the
 * opt-in archival codec, and 3, zstd with a local pack dictionary (0.50), are
 * refused with a clear message.
 */

import { inflateSync } from "node:zlib";
import { TineError } from "./errors.js";
import { zstdDecompress } from "./zstd.js";

export const MAGIC = new Uint8Array([0x54, 0x49, 0x4e, 0x45, 0x5a, 0x31, 0x00]);
export const MAX_TINE_ARTIFACT_BYTES = 256 * 1024 * 1024;
const MAX_RATIO = 1000;
const READ_RATIO = 100_000;
const READ_RATIO_BYTES = 64 << 20;
const MAX_VARINT_BYTES = 10;

export function isWrapped(data: Uint8Array): boolean {
  if (data.length < MAGIC.length) return false;
  return MAGIC.every((byte, index) => data[index] === byte);
}

export function readUvarint(data: Uint8Array, start: number): [number, number] {
  let value = 0;
  let scale = 1;
  for (let index = start; index < Math.min(data.length, start + MAX_VARINT_BYTES); index++) {
    const byte = data[index];
    value += (byte & 0x7f) * scale;
    if (!(byte & 0x80)) {
      if (byte === 0 && index > start) {
        throw new TineError("compressed header length is not minimally encoded", "codec.malformed");
      }
      return [value, index + 1];
    }
    scale *= 128;
  }
  throw new TineError("compressed header length is malformed", "codec.malformed");
}

/** The uncompressed bytes of a stored body; legacy (unwrapped) bytes come back as they are. */
export function unwrap(data: Uint8Array, limit = MAX_TINE_ARTIFACT_BYTES): Uint8Array {
  if (!isWrapped(data)) return data;
  const start = MAGIC.length;
  if (data.length <= start) throw new TineError("compressed header is truncated", "codec.malformed");
  const codec = data[start];
  const [size, offset] = readUvarint(data, start + 1);
  const frame = data.subarray(offset);
  if (size > limit) {
    throw new TineError("compressed body declares more bytes than the reader allows", "codec.oversized");
  }
  const ratio = size <= READ_RATIO_BYTES ? READ_RATIO : MAX_RATIO;
  if (size > Math.max(frame.length, 1) * ratio) {
    throw new TineError("compressed body exceeds the decompression ratio limit", "codec.ratio");
  }
  let out: Uint8Array;
  if (codec === 0) out = frame;
  else if (codec === 1) {
    let result: { buffer: Buffer; engine: { bytesWritten: number } };
    try {
      const options = { info: true, maxOutputLength: Math.max(size, 1) };
      result = inflateSync(frame, options) as unknown as typeof result;
    } catch {
      throw new TineError("compressed body is corrupt", "codec.corrupt");
    }
    if (result.engine.bytesWritten !== frame.length) {
      throw new TineError("compressed body has trailing or missing data", "codec.corrupt");
    }
    out = result.buffer;
  } else if (codec === 2) {
    out = zstdDecompress(frame, size);
  } else if (codec === 3) {
    throw new TineError(
      "this local pack block uses a zstd dictionary (`tine gc --dictionaries`, 0.50), which @opentine/verify does not read yet; `tine gc --no-dictionaries` rewrites it",
      "codec.unsupported",
    );
  } else if (codec === 4) {
    throw new TineError("this file is xz-compressed, which @opentine/verify does not read yet", "codec.unsupported");
  } else {
    throw new TineError(`unknown storage codec byte ${codec}; a newer opentine wrote this`, "codec.unsupported");
  }
  if (out.length !== size) {
    throw new TineError("compressed body does not match its declared length", "codec.corrupt");
  }
  if (isWrapped(out)) throw new TineError("nested compression is not allowed", "codec.malformed");
  return out;
}
