/**
 * The file reader and the CLI, over v4 artifacts rebuilt from the sig-v4 vectors.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import { canonicalJson } from "../src/canon.js";
import { MAGIC, unwrap } from "../src/codec.js";
import { TineError } from "../src/errors.js";
import { decodeTagged } from "../src/ops.js";
import { verifyBytes } from "../src/verify.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..", "..", "..");
const CLI = join(HERE, "..", "src", "cli.js");
const SUITE = join(ROOT, "docs", "conformance");
const KEYS = JSON.parse(readFileSync(join(SUITE, "keys.json"), "utf8")) as Record<string, string>;
const CASES = (JSON.parse(readFileSync(join(SUITE, "vectors", "53-sig-v4.json"), "utf8")) as {
  cases: { id: string; input: { value: unknown } }[];
}).cases;

function artifact(id: string): Uint8Array {
  const found = CASES.find((item) => item.id === id);
  assert.ok(found, id);
  return canonicalJson(decodeTagged(found.input.value));
}

function wrap(raw: Uint8Array, codec: number, frame: Uint8Array): Uint8Array {
  const varint: number[] = [];
  let size = raw.length;
  do {
    varint.push((size & 0x7f) | (size > 0x7f ? 0x80 : 0));
    size >>>= 7;
  } while (size);
  return Buffer.concat([MAGIC, Buffer.from([codec, ...varint]), frame]);
}

const hmacA = Uint8Array.from(Buffer.from(KEYS.hmac_a, "hex"));

test("a plain v4 artifact verifies under its HMAC key", () => {
  const report = verifyBytes(artifact("sig3.verdict.verified-hmac"), "x.tine", { hmacKey: hmacA });
  assert.equal(report.verdict, "pass");
  assert.equal(report.integrity.ok, true);
  assert.equal(report.signature?.state, "verified");
});

const V5_CASES = (JSON.parse(readFileSync(join(SUITE, "vectors", "54-artifact-v5.json"), "utf8")) as {
  cases: { id: string; input: { value: unknown } }[];
}).cases;

function v5Artifact(id: string): Uint8Array {
  const found = V5_CASES.find((item) => item.id === id);
  assert.ok(found, id);
  return canonicalJson(decodeTagged(found.input.value));
}

test("a v5 artifact (text blobs) verifies with the v4 signature, and a tampered one fails", () => {
  const report = verifyBytes(v5Artifact("v5.verdict.verified-hmac"), "x.tine", { hmacKey: hmacA });
  assert.equal(report.format, "tine-artifact/5");
  assert.equal(report.verdict, "pass");
  assert.equal(report.root, verifyBytes(artifact("sig3.verdict.verified-hmac"), "y.tine").root);
  const tampered = verifyBytes(v5Artifact("v5.verdict.mismatch-edited-text"), "x.tine", { hmacKey: hmacA });
  assert.equal(tampered.verdict, "fail");
  assert.equal(tampered.signature?.state, "mismatch");
});

test("a zlib-wrapped v4 artifact reads like the plain one", () => {
  const raw = artifact("sig3.verdict.verified-hmac");
  const wrapped = wrap(raw, 1, deflateSync(raw));
  assert.equal(Buffer.compare(unwrap(wrapped), raw), 0);
  assert.equal(verifyBytes(wrapped, "x.tine", { hmacKey: hmacA }).signature?.state, "verified");
});

test("zlib trailing data and a wrong declared length are refused", () => {
  const raw = artifact("sig3.verdict.verified-hmac");
  const frame = deflateSync(raw);
  assert.throws(() => unwrap(wrap(raw, 1, Buffer.concat([frame, Buffer.from("x")]))), TineError);
  assert.throws(() => unwrap(wrap(raw.subarray(1), 1, frame)), TineError);
});

test("xz is refused with a message that names it", () => {
  const raw = artifact("sig3.verdict.verified-hmac");
  assert.throws(() => unwrap(wrap(raw, 4, raw)), (exc: Error) => exc instanceof TineError && /xz/.test(exc.message));
  const report = verifyBytes(wrap(raw, 4, raw), "x.tine");
  assert.equal(report.ok, false);
  assert.match(report.integrity.reason, /xz-compressed/);
});

test("a tampered envelope fails integrity before any key is consulted", () => {
  const report = verifyBytes(artifact("sig3.verdict.mismatch-edited-envelope"), "x.tine", { hmacKey: hmacA });
  assert.equal(report.integrity.ok, false);
  assert.equal(report.signature?.state, "mismatch");
  assert.equal(report.verdict, "fail");
});

test("a legacy v2 artifact is named as out of scope, not passed", () => {
  const report = verifyBytes(readFileSync(join(ROOT, "tests", "fixtures", "golden_v2.tine")), "golden_v2.tine");
  assert.equal(report.ok, false);
  assert.equal(report.format, "tine/2");
  assert.match(report.integrity.reason, /only format v4/);
});

test("the CLI exits 0 on a verified file, 1 on a tampered one and 2 on misuse", () => {
  const dir = mkdtempSync(join(tmpdir(), "opentine-verify-"));
  const good = join(dir, "good.tine");
  const bad = join(dir, "bad.tine");
  const pub = join(dir, "key.pub");
  writeFileSync(good, artifact("sig3.verdict.verified-ed25519"));
  writeFileSync(bad, artifact("sig3.verdict.mismatch-edited-envelope"));
  writeFileSync(pub, "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8\n");
  const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  const ok = run(good, "--pubkey", pub);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).signature.state, "verified");
  assert.equal(run(bad).status, 1);
  assert.equal(run().status, 2);
  assert.equal(run(good, "--bogus").status, 2);
});

test("the CLI verifies a tine eval verdicts.jsonl and refuses a tampered verdict", () => {
  const vectors = (JSON.parse(readFileSync(join(SUITE, "vectors", "58-eval-verdict.json"), "utf8")) as {
    cases: { id: string; input: { value: unknown } }[];
  }).cases;
  const verdict = (id: string): string => {
    const found = vectors.find((item) => item.id === id);
    assert.ok(found, id);
    const value = decodeTagged(found.input.value) as Map<string, unknown>;
    return Buffer.from(canonicalJson(value.get("verdict") as never)).toString("utf8");
  };
  const dir = mkdtempSync(join(tmpdir(), "opentine-eval-"));
  const good = join(dir, "good.jsonl");
  const bad = join(dir, "bad.jsonl");
  const ids = ["eval-verdict.valid-tofu", "eval-verdict.valid-trusted", "eval-verdict.valid-judge"];
  writeFileSync(good, ids.map(verdict).join("\n") + "\n");
  writeFileSync(bad, verdict("eval-verdict.score-edited") + "\n");
  const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  // Each vector verdict is good on its own, but the vectors carry a placeholder
  // eval id, so as one eval file the id binding refuses them. The good-file path
  // is exercised on a real 1k-item eval by tests/test_045_eval_verifiers.py.
  const mixed = run(good);
  assert.equal(mixed.status, 1, mixed.stderr);
  const report = JSON.parse(mixed.stdout);
  assert.equal(report.failures.length, 3);
  assert.ok(report.failures.every((f: { reason: string }) => f.reason === "eval.id-mismatch"));
  const refused = run(bad);
  assert.equal(refused.status, 1);
  assert.equal(JSON.parse(refused.stdout).failures[0].reason, "eval-verdict.bad-signature");
});
