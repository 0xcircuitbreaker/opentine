/**
 * TINEPACK6 (0.81, HEC) has no TS decoder yet: the verifier must refuse a
 * TINEPACK6 pack and a bundle carrying one with the precise reason
 * ("unsupported pack format TINEPACK6", `pack.version-unsupported`) instead of
 * misparsing them. The inputs were written by the Python reference
 * (scripts/gen_tinepack6_ts_fixture.py), which reads both.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { verifyBundleBytes } from "../src/bundle.js";
import { TineError } from "../src/errors.js";
import { inspectPack } from "../src/pack.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  readFileSync(join(HERE, "..", "..", "..", "..", "tests", "vectors", "tinepack6", "ts-refusal.json"), "utf8"),
) as {
  pack_hex: string;
  bundle_hex: string;
  ts: { pack: { code: string; message: string }; bundle: { code: string; message: string } };
};
const hex = (text: string) => Uint8Array.from(Buffer.from(text, "hex"));

test("a TINEPACK6 pack is refused with its precise reason", () => {
  assert.throws(
    () => inspectPack(hex(FIXTURE.pack_hex)),
    (exc: unknown) =>
      exc instanceof TineError && exc.code === FIXTURE.ts.pack.code && exc.message === FIXTURE.ts.pack.message,
  );
});

test("a bundle carrying TINEPACK6 is refused, not misparsed", async () => {
  const report = await verifyBundleBytes(hex(FIXTURE.bundle_hex));
  assert.equal(report.ok, false);
  assert.equal(report.code, FIXTURE.ts.bundle.code);
  assert.ok(String(report.reason).includes(FIXTURE.ts.bundle.message));
});
