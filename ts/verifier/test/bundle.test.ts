/**
 * 0.51: the streaming bundle reader. Every pack.inspect vector, wrapped in a
 * bundle, gets the pinned verdict (the TINEPACK3 fast path never accepts a
 * pack the exact reader refuses, at any chunk size); records dropped into a
 * viewer get their family's verdict; and the browser zlib stand-in keeps
 * Node's contract. The Python corpus is compared in
 * tests/test_051_browser_bundles.py and ts/browser-tests.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { deflateSync, inflateSync as nodeInflate } from "node:zlib";
import { inflateSync as browserInflate } from "../src/browser/zlib.js";
import { isBundle, verifyBundleBytes } from "../src/bundle.js";
import { tuning } from "../src/bundlepack.js";
import { canonicalJson } from "../src/canon.js";
import { decodeTagged } from "../src/ops.js";
import { verifyRecord } from "../src/recordcheck.js";
import { loadSuite, resolveInput, type Case } from "../src/suite.js";
import { type JValue } from "../src/json.js";
import { OPENTINE_VERSION } from "../src/version.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const SUITE = loadSuite(ROOT);
const cases = (family: string): Case[] =>
  (JSON.parse(readFileSync(join(SUITE.dir, "vectors", family), "utf8")) as { cases: Case[] }).cases;

function bundle(pack: Uint8Array, refs: Record<string, string> = {}, manifestOverride?: Uint8Array): Uint8Array {
  const manifest =
    manifestOverride ??
    canonicalJson(
      new Map<string, JValue>([
        ["format", "opentine-bundle/1"],
        ["pack", `sha256:${createHash("sha256").update(pack).digest("hex")}`],
        ["pack_bytes", BigInt(pack.length)],
        ["refs", new Map(Object.entries(refs))],
      ]),
    );
  const size = Buffer.alloc(4);
  size.writeUInt32BE(manifest.length);
  const body = Buffer.concat([size, manifest, pack]);
  return Buffer.concat([Buffer.from("TINEBUNDLE1\n", "latin1"), createHash("sha256").update(body).digest(), body]);
}

const PACKS = cases("28-pack.json").filter((item) => item.op === "pack.inspect" && !item.args);

for (const [chunk, out] of [
  [4 * 1024 * 1024, 256 * 1024],
  [3, 7],
]) {
  test(`every pack.inspect vector, bundled, keeps its verdict (read ${chunk}, inflate ${out})`, async () => {
    tuning.chunk = chunk;
    tuning.out = out;
    try {
      assert.ok(PACKS.length >= 20);
      for (const item of PACKS) {
        const input = resolveInput(item.input, SUITE.dir, ROOT) as { bytes: Uint8Array };
        const report = await verifyBundleBytes(bundle(input.bytes));
        assert.equal(report.ok, item.expect === "accept", `${item.id}: ${report.reason}`);
        if (item.expect === "accept") {
          const output = item.output as { pack_id: string; objects: string[] };
          assert.equal(report.pack, output.pack_id, item.id);
          assert.equal(report.objects, output.objects.length, item.id);
          const v3 = Buffer.from(input.bytes.subarray(0, 10)).toString("latin1") === "TINEPACK3\0";
          assert.equal(report.pack_reader, v3 ? "streamed" : "in-memory", item.id);
        } else {
          assert.match(report.code ?? "", /^bundle\.pack-invalid:pack\./, item.id);
        }
      }
    } finally {
      tuning.chunk = 4 * 1024 * 1024;
      tuning.out = 256 * 1024;
    }
  });
}

test("the outer layer refuses in Python's order, with bundle.* codes", async () => {
  const pack = resolveInput(PACKS.find((item) => item.id === "pack.inspect.two-blobs")!.input, SUITE.dir, ROOT) as { bytes: Uint8Array };
  const good = bundle(pack.bytes);
  assert.equal((await verifyBundleBytes(good)).ok, true);
  assert.ok(isBundle(good));
  const flipped = Uint8Array.from(good);
  flipped[good.length - 1] ^= 1;
  assert.equal((await verifyBundleBytes(flipped)).code, "bundle.checksum-mismatch");
  assert.equal((await verifyBundleBytes(good.subarray(0, 40))).code, "bundle.bad-magic");
  const loose = new TextEncoder().encode('{"format": "opentine-bundle/1"}');
  assert.equal((await verifyBundleBytes(bundle(pack.bytes, {}, loose))).code, "bundle.manifest-invalid");
  const report = await verifyBundleBytes(bundle(pack.bytes, { "heads/main": "run:sha256:" + "1".repeat(64) }));
  assert.equal(report.code, "bundle.ref-outside");
  assert.equal(report.opentine_version, OPENTINE_VERSION);
  assert.ok(report.checks.some((row) => row.state === "fail"));
});

test("a record dropped into a viewer gets its family's verdict, never a pass it did not check", () => {
  const families: [string, string, string[]][] = [
    ["70-review.json", "review.verify", ["version"]],
    ["70-review.json", "review.bundle", ["bundle"]],
    ["68-merge.json", "merge-approval.verify", ["record"]],
    ["68-merge.json", "merge.verify", ["record"]],
    ["71-prompt.json", "prompt.verify", ["record"]],
    ["69-memory.json", "memory.verify", ["record"]],
    ["74-review-finding.json", "review-finding.verify", ["record"]],
    ["73-forge-check.json", "forge-check.verify", ["check"]],
    ["58-eval-verdict.json", "eval-verdict.verify", ["verdict"]],
    ["63-tombstone.json", "tombstone.verify", ["tombstone"]],
    ["64-redacted-copy.json", "redacted-copy.verify", ["record"]],
  ];
  let checked = 0;
  for (const [family, op, [field]] of families) {
    for (const item of cases(family).filter((c) => c.op === op)) {
      const value = decodeTagged((item.input as { value: unknown }).value) as Map<string, JValue>;
      const context = [...value.entries()].filter(([key, v]) => key !== field && v !== null && !(Array.isArray(v) && v.length === 0));
      if (context.length) continue; // the vector needs a key or context a lone file does not carry
      const found = verifyRecord(value.get(field) as JValue);
      if (item.expect === "accept") assert.equal(found.state, "pass", `${item.id}: ${found.reason}`);
      else assert.notEqual(found.state, "pass", item.id);
      checked++;
    }
  }
  assert.ok(checked >= 40, `${checked} record vectors`);
  assert.equal(verifyRecord(new Map([["kind", "opentine.review-gate"]])).state, "unchecked");
  assert.equal(verifyRecord(new Map([["kind", "opentine.unknown"]])).state, "unchecked");
});

test("the browser zlib stand-in keeps Node's inflateSync contract", () => {
  const data = deflateSync(Buffer.from("tine ".repeat(5000)));
  const node = nodeInflate(data, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  const mine = browserInflate(data, { info: true }) as { buffer: Uint8Array; engine: { bytesWritten: number } };
  assert.deepEqual(Buffer.from(mine.buffer), node.buffer);
  const trailing = browserInflate(Buffer.concat([data, Buffer.from("xx")]), { info: true }) as typeof mine;
  assert.equal(trailing.engine.bytesWritten, data.length);
  const code = (fn: () => unknown) => {
    try {
      fn();
      return "ok";
    } catch (exc) {
      return (exc as { code?: string }).code;
    }
  };
  assert.equal(code(() => browserInflate(data.subarray(0, data.length - 3))), "Z_BUF_ERROR");
  assert.equal(code(() => browserInflate(data, { maxOutputLength: 100 })), "ERR_BUFFER_TOO_LARGE");
  const corrupt = Buffer.from(data);
  corrupt[5] ^= 0xff;
  assert.equal(code(() => browserInflate(corrupt)), "Z_DATA_ERROR");
});
