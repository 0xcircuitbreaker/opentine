/**
 * The zstd paths no conformance vector pins (compressor output is not
 * reproducible): codec 2 bodies, TINEPACK4 with zstd, TINEPACK5's long-distance
 * frame with its EVENT_SLIM and RUN_DELTA forms, and a storage-v3 local pack
 * holding BLOB_DELTA objects in zstd blocks. Inputs were written once by the
 * Python reference (test/fixtures/make_fixtures.py); the answers are its readers'.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readUvarint, unwrap } from "../src/codec.js";
import { TineError } from "../src/errors.js";
import { readLocalPack } from "../src/localpack.js";
import { inspectPack } from "../src/pack.js";
import { verifyBytes } from "../src/verify.js";
import { scanFrame, zstdDecompress } from "../src/zstd.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(readFileSync(join(HERE, "..", "..", "test", "fixtures", "zstd-packs.json"), "utf8")) as {
  artifact: { sha256: string; zstd_wrapped_hex: string };
  packs: Record<string, { hex: string; pack_id: string; objects: string[]; shallow: string[] }>;
  localpack: { pack_id: string; tpk_hex: string; tidx_hex: string; objects: [string, string][] };
};
const KEYS = JSON.parse(
  readFileSync(join(HERE, "..", "..", "..", "..", "docs", "conformance", "keys.json"), "utf8"),
) as Record<string, string>;

const hex = (text: string) => Uint8Array.from(Buffer.from(text, "hex"));
const sha = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
const refused = (code: string) => (exc: unknown) => exc instanceof TineError && exc.code === code;

test("a zstd-wrapped .tine unwraps and verifies", () => {
  const wrapped = hex(FIXTURE.artifact.zstd_wrapped_hex);
  assert.equal(sha(unwrap(wrapped)), FIXTURE.artifact.sha256);
  const report = verifyBytes(wrapped, "x.tine", { hmacKey: hex(KEYS.hmac_a) });
  assert.equal(report.signature?.state, "verified");
  assert.equal(report.verdict, "pass");
});

test("a zstd body with trailing bytes, a short frame or a wrong length is refused", () => {
  const wrapped = hex(FIXTURE.artifact.zstd_wrapped_hex);
  assert.throws(() => unwrap(Buffer.concat([wrapped, Buffer.from([0])])), refused("codec.corrupt"));
  assert.throws(() => unwrap(wrapped.subarray(0, wrapped.length - 2)), refused("codec.corrupt"));
  const frame = wrapped.subarray(readUvarint(wrapped, 8)[1]);
  const size = scanFrame(frame).contentSize as number;
  assert.throws(() => zstdDecompress(frame, size - 1), refused("codec.corrupt"));
});

test("a zstd window beyond 2**27 is refused before decoding", () => {
  // magic, descriptor (no single segment, no checksum), window 2**28, one empty raw last block
  const frame = Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 0x00, 18 << 3, 0x01, 0x00, 0x00]);
  assert.throws(() => scanFrame(frame), refused("codec.ratio"));
  const small = Uint8Array.from([0x28, 0xb5, 0x2f, 0xfd, 0x00, 17 << 3, 0x01, 0x00, 0x00]);
  assert.equal(zstdDecompress(small, 0).length, 0);
});

for (const [name, expected] of Object.entries(FIXTURE.packs)) {
  test(`${name} pack inspects as the reference reads it`, () => {
    const pack = inspectPack(hex(expected.hex));
    assert.equal(pack.packId, expected.pack_id);
    assert.deepEqual(pack.objects.map(([oid]) => oid).sort(), expected.objects);
    assert.deepEqual([...pack.shallow].sort(), expected.shallow);
  });

  test(`${name} pack with a flipped byte is refused`, () => {
    const data = hex(expected.hex);
    data[data.length - 3] ^= 0x01;
    assert.throws(() => inspectPack(data), refused("pack.checksum-mismatch"));
  });
}

test("a storage-v3 local pack with BLOB_DELTA objects in zstd blocks reads back", () => {
  const { tidx_hex, tpk_hex, pack_id, objects } = FIXTURE.localpack;
  assert.deepEqual(readLocalPack(hex(tidx_hex), hex(tpk_hex)), { pack_id, objects });
});
