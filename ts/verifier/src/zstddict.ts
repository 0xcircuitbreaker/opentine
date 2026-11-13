/**
 * Codec 3 (SPEC 2.3, 0.50): zstd with a trained dictionary, the stored form of
 * local storage-v3 pack blocks in a repository opted in to `tine gc
 * --dictionaries`. Port of `opentine/_codec_dict.py`.
 *
 * The frame is `sha256(dictionary) | zstd frame`. The dictionary is looked up
 * by that digest and refused unless its bytes hash to it, and must be a
 * formatted dictionary (RFC 8878 section 5: magic, id, Huffman and FSE
 * tables, three repeat offsets, content), as `zstd --train` writes. The frame is walked
 * by `scanFrame` first (one frame, window at most 2**27, exact end, its
 * dictionary id 0 or the dictionary's own), then decoded by the vendored
 * fzstd block decoder (`./vendor/fzstd-blocks.ts`) with its state seeded from
 * the dictionary. Output is bounded by the declared size, and every object a
 * block holds is still checked against its id by the caller (`localpack.ts`).
 */

import { createHash } from "node:crypto";
import { TineError } from "./errors.js";
import { rfse, rhu, rzb, rzfh } from "./vendor/fzstd-blocks.js";
import { scanFrame } from "./zstd.js";

export const ID_BYTES = 32;
/** The largest dictionary a reader loads (`_codec_dict.MAX_DICT_BYTES`). */
export const MAX_DICT_BYTES = 1 << 20;
const DICT_MAGIC = 0xec30a437;

/** Finds a dictionary by its lowercase hex sha256: its bytes, or `null`. */
export type DictLookup = (idHex: string) => Uint8Array | null;

/** fzstd's internal frame state and tables are untyped (`any`). */
interface Dictionary {
  id: number;
  content: Uint8Array;
  huffman: any;
  tables: any[];
  repeats: [number, number, number];
}

function u32(data: Uint8Array, at: number): number {
  return (data[at] | (data[at + 1] << 8) | (data[at + 2] << 16) | (data[at + 3] << 24)) >>> 0;
}

function bad(message: string, code = "codec.corrupt"): never {
  throw new TineError(message, code);
}

/** RFC 8878 section 5: a formatted dictionary's tables, repeat offsets and content. */
export function parseDictionary(bytes: Uint8Array): Dictionary {
  if (bytes.length < 8 || u32(bytes, 0) !== DICT_MAGIC) {
    // `_codec_dict` loads dictionaries as formatted (`ZstdDict(content)`), so a
    // raw-content one is refused here too rather than read by one reader only.
    bad("zstd dictionary is not a formatted dictionary");
  }
  const id = u32(bytes, 4);
  try {
    let pos = 8;
    const step = (result: any[]): any => {
      pos = result[0] as number;
      return result[1];
    };
    const huffman = step(rhu(bytes, pos));
    const of = step(rfse(bytes, pos, 8));
    const ml = step(rfse(bytes, pos, 9));
    const ll = step(rfse(bytes, pos, 9));
    if (pos + 12 > bytes.length) bad("zstd dictionary is truncated");
    const content = bytes.subarray(pos + 12);
    const repeats = [u32(bytes, pos), u32(bytes, pos + 4), u32(bytes, pos + 8)] as [number, number, number];
    if (repeats.some((rep) => rep === 0 || rep > content.length)) bad("zstd dictionary repeat offset is out of range");
    return { id, content, huffman, tables: [ml, of, ll], repeats };
  } catch (exc) {
    if (exc instanceof TineError) throw exc;
    bad(`zstd dictionary is malformed: ${(exc as Error).message}`);
  }
}

/** One zstd *frame* inflated with *dictionary* to exactly *size* bytes. */
export function zstdDecompressWithDictionary(frame: Uint8Array, size: number, dictionary: Uint8Array): Uint8Array {
  const dict = parseDictionary(dictionary);
  if (scanFrame(frame, dict.id).length !== frame.length) bad("compressed body has trailing or missing data");
  const prefix = dict.content.length;
  const out = new Uint8Array(prefix + size + 1);
  out.set(dict.content, 0);
  try {
    const st: any = rzfh(frame, out);
    if (typeof st !== "object") bad("not a zstd frame");
    st.y = st.e = prefix;
    st.h = dict.huffman;
    st.t = dict.tables;
    st.o.set(dict.repeats);
    while (!st.l) {
      if (!rzb(frame, st, out)) bad("zstd frame is truncated");
      if (st.y > prefix + size) bad("zstd frame inflates past its declared size");
      st.e = st.y;
    }
    if (st.y !== prefix + size) bad("compressed body does not match its declared length");
    if (st.b + st.c * 4 !== frame.length) bad("compressed body has trailing or missing data");
  } catch (exc) {
    if (exc instanceof TineError) throw exc;
    bad(`compressed body is corrupt: ${(exc as Error).message}`);
  }
  return out.slice(prefix, prefix + size);
}

/** `_codec_dict.decompress`: the body of a codec-3 *frame*, its dictionary found by *lookup*. */
export function decompressCodec3(frame: Uint8Array, size: number, lookup: DictLookup | undefined): Uint8Array {
  if (frame.length <= ID_BYTES) bad("compressed body is truncated");
  const wanted = Buffer.from(frame.subarray(0, ID_BYTES)).toString("hex");
  const content = lookup?.(wanted) ?? null;
  if (content === null) {
    bad(
      `this body needs zstd dictionary sha256:${wanted}, which is not here (dictionary packs are local only; \`tine gc --no-dictionaries\` rewrites them)`,
      "localpack.dictionary",
    );
  }
  const actual = createHash("sha256").update(content).digest("hex");
  if (content.length > MAX_DICT_BYTES || actual !== wanted) {
    bad(`zstd dictionary sha256:${wanted} does not match its id`, "localpack.dictionary");
  }
  return zstdDecompressWithDictionary(frame.subarray(ID_BYTES), size, content);
}
