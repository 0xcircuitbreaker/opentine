/**
 * zstd decoding for the storage wrapper (codec 2), `TINEPACK4` bodies and the
 * long-distance `TINEPACK5` frame, over the pure-JS `fzstd` decoder.
 *
 * Before `fzstd` sees a byte, the frame's structure is walked here (RFC 8878
 * section 3.1.1): one frame, no dictionary, a window of at most 2**27 (the
 * reference reader's `window_log_max`, X17), and an exact end. A crafted
 * frame therefore cannot make this reader reserve more than 128 MiB, carry
 * trailing data, or stop short; output is bounded by the declared size.
 */

import { Decompress } from "fzstd";
import { TineError } from "./errors.js";

/** The largest window any OpenTine reader accepts (`_codec_long.WINDOW_LOG`). */
export const WINDOW_LOG = 27;
const MAGIC = 0xfd2fb528;

export interface FrameInfo {
  windowSize: number;
  contentSize: number | null;
  /** The frame's length in bytes, header to checksum. */
  length: number;
}

function corrupt(message: string): never {
  throw new TineError(message, "codec.corrupt");
}

/** Walk one zstd frame's header and block headers without decoding anything. */
export function scanFrame(data: Uint8Array): FrameInfo {
  if (data.length < 6) corrupt("zstd frame is truncated");
  const magic = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
  if (magic !== MAGIC) corrupt("not a zstd frame");
  const descriptor = data[4];
  const fcsFlag = descriptor >> 6;
  const single = (descriptor >> 5) & 1;
  const reserved = (descriptor >> 3) & 1;
  const checksum = (descriptor >> 2) & 1;
  const dictFlag = descriptor & 3;
  if (reserved) corrupt("zstd frame header sets a reserved bit");
  let pos = 5;
  let windowSize = 0;
  if (!single) {
    const byte = data[pos++];
    const base = 2 ** (10 + (byte >> 3));
    windowSize = base + (base / 8) * (byte & 7);
  }
  const dictBytes = [0, 1, 2, 4][dictFlag];
  let dictId = 0;
  for (let i = 0; i < dictBytes; i++) dictId += data[pos + i] * 2 ** (8 * i);
  pos += dictBytes;
  if (dictId !== 0) corrupt("zstd frame needs a dictionary");
  const fcsBytes = [single ? 1 : 0, 2, 4, 8][fcsFlag];
  let contentSize: number | null = null;
  if (fcsBytes) {
    if (pos + fcsBytes > data.length) corrupt("zstd frame header is truncated");
    let value = 0;
    for (let i = 0; i < fcsBytes; i++) value += data[pos + i] * 2 ** (8 * i);
    contentSize = fcsBytes === 2 ? value + 256 : value;
    pos += fcsBytes;
  }
  if (single) windowSize = contentSize as number;
  if (windowSize > 2 ** WINDOW_LOG) {
    throw new TineError(`zstd frame window exceeds 2**${WINDOW_LOG}`, "codec.ratio");
  }
  for (;;) {
    if (pos + 3 > data.length) corrupt("zstd frame is truncated");
    const header = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16);
    pos += 3;
    const type = (header >> 1) & 3;
    const size = header >>> 3;
    if (type === 3) corrupt("zstd block type is reserved");
    pos += type === 1 ? 1 : size;
    if (pos > data.length) corrupt("zstd frame is truncated");
    if (header & 1) break;
  }
  pos += checksum ? 4 : 0;
  if (pos > data.length) corrupt("zstd frame is truncated");
  return { windowSize, contentSize, length: pos };
}

function concat(parts: Uint8Array[], total: number): Uint8Array {
  if (parts.length === 1) return parts[0];
  const out = new Uint8Array(total);
  let cursor = 0;
  for (const part of parts) {
    out.set(part, cursor);
    cursor += part.length;
  }
  return out;
}

/**
 * Inflate one or more chunks that together hold exactly one zstd frame; each
 * chunk must inflate to exactly its declared size (a frame flushed in blocks,
 * `_codec_long.decompress_blocks`; a plain frame is one chunk).
 */
export function decompressChunks(chunks: [Uint8Array, number][]): Uint8Array[] {
  const whole = concat(
    chunks.map(([chunk]) => chunk),
    chunks.reduce((sum, [chunk]) => sum + chunk.length, 0),
  );
  if (scanFrame(whole).length !== whole.length) corrupt("compressed body has trailing or missing data");
  const out: Uint8Array[] = [];
  let pending: Uint8Array[] = [];
  let produced = 0;
  let limit = 0;
  const engine = new Decompress((data) => {
    produced += data.length;
    if (produced > limit) corrupt("zstd block inflates past its declared size");
    if (data.length) pending.push(data.slice());
  });
  try {
    chunks.forEach(([chunk, size], index) => {
      produced = 0;
      limit = size;
      pending = [];
      engine.push(chunk, index === chunks.length - 1);
      if (produced !== size) corrupt("zstd block does not match its declared size");
      out.push(concat(pending, size));
    });
  } catch (exc) {
    if (exc instanceof TineError) throw exc;
    corrupt(`compressed body is corrupt: ${(exc as Error).message}`);
  }
  return out;
}

/** One zstd frame inflated to exactly *size* bytes. */
export function zstdDecompress(frame: Uint8Array, size: number): Uint8Array {
  return decompressChunks([[frame, size]])[0];
}
