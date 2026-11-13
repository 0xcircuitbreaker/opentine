/**
 * Codec 3 (zstd with a trained dictionary) beyond the three `29-localpack`
 * vectors: the frame is taken from `localpack.codec3.dictionary`, whose pinned
 * bytes the Python reference wrote, and broken here in ways no vector pins.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { MAGIC, readUvarint, unwrap } from "../src/codec.js";
import { TineError } from "../src/errors.js";
import { readLocalPack } from "../src/localpack.js";
import { parseDictionary, zstdDecompressWithDictionary } from "../src/zstddict.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const FAMILY = JSON.parse(readFileSync(join(ROOT, "docs", "conformance", "vectors", "29-localpack.json"), "utf8")) as {
  cases: { id: string; input: { bytes_b64: string }; args: { pack_b64: string; dicts_b64?: Record<string, string> } }[];
};
const CASE = FAMILY.cases.find((item) => item.id === "localpack.codec3.dictionary")!;
const PACK = new Uint8Array(Buffer.from(CASE.args.pack_b64, "base64"));
const INDEX = new Uint8Array(Buffer.from(CASE.input.bytes_b64, "base64"));
const [DICT_ID, DICT_B64] = Object.entries(CASE.args.dicts_b64!)[0];
const DICT = new Uint8Array(Buffer.from(DICT_B64, "base64"));
const BLOCK = PACK.subarray(8);
const [SIZE, START] = readUvarint(BLOCK, MAGIC.length + 1);
const ZSTD_FRAME = BLOCK.subarray(START + 32);
const lookup = (id: string) => (id === DICT_ID ? DICT : null);

function refuses(run: () => unknown, code: string): void {
  assert.throws(run, (exc: unknown) => exc instanceof TineError && exc.code === code);
}

test("the pinned codec-3 block inflates and every object matches its id", () => {
  const out = unwrap(BLOCK, SIZE, lookup);
  assert.equal(out.length, SIZE);
  const read = readLocalPack(INDEX, PACK, lookup);
  assert.equal(read.objects.length, 6);
});

test("the dictionary is a formatted one whose id the frame header names", () => {
  const parsed = parseDictionary(DICT);
  assert.notEqual(parsed.id, 0);
  assert.equal(createHash("sha256").update(DICT).digest("hex"), DICT_ID);
});

test("a codec-3 body is refused without a dictionary lookup, never read without it", () => {
  refuses(() => unwrap(BLOCK, SIZE), "localpack.dictionary");
});

test("a raw-content dictionary is refused, as the Python reader refuses it", () => {
  const raw = new TextEncoder().encode("raw content dictionary, no magic");
  refuses(() => zstdDecompressWithDictionary(ZSTD_FRAME, SIZE, raw), "codec.corrupt");
});

test("a frame decoded with another formatted dictionary is refused by its dictionary id", () => {
  const other = DICT.slice();
  other[4] ^= 1; // the dictionary id in its header
  refuses(() => zstdDecompressWithDictionary(ZSTD_FRAME, SIZE, other), "codec.corrupt");
});

test("a truncated, padded or wrongly sized frame is refused", () => {
  refuses(() => zstdDecompressWithDictionary(ZSTD_FRAME.subarray(0, ZSTD_FRAME.length - 1), SIZE, DICT), "codec.corrupt");
  const padded = new Uint8Array(ZSTD_FRAME.length + 1);
  padded.set(ZSTD_FRAME);
  refuses(() => zstdDecompressWithDictionary(padded, SIZE, DICT), "codec.corrupt");
  refuses(() => zstdDecompressWithDictionary(ZSTD_FRAME, SIZE - 1, DICT), "codec.corrupt");
  refuses(() => zstdDecompressWithDictionary(ZSTD_FRAME, SIZE + 1, DICT), "codec.corrupt");
});

test("a dictionary over 1 MiB is refused even when filed under its own digest", () => {
  const big = new Uint8Array((1 << 20) + 1);
  big.set(DICT);
  const id = createHash("sha256").update(big).digest("hex");
  const frame = new Uint8Array(BLOCK);
  frame.set(Buffer.from(id, "hex"), START);
  refuses(() => unwrap(frame, SIZE, (want) => (want === id ? big : null)), "localpack.dictionary");
});
