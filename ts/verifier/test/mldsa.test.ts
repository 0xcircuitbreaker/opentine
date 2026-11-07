/**
 * ML-DSA-65 (FIPS 204) against the NIST ACVP sigVer vectors the Python
 * verifier pins (tests/fixtures/acvp/ml_dsa_65_sigver.json): the external
 * (pure, with context) and internal interfaces, both verdicts.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { mldsa65Verify, mldsa65VerifyInternal } from "../src/crypto.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const ACVP = JSON.parse(readFileSync(join(ROOT, "tests", "fixtures", "acvp", "ml_dsa_65_sigver.json"), "utf8")) as {
  testGroups: { parameterSet: string; signatureInterface: string; tests: Record<string, unknown>[] }[];
};

const hex = (text: unknown) => Uint8Array.from(Buffer.from(text as string, "hex"));

test("the ACVP fixture is ML-DSA-65 with both verdicts", () => {
  assert.deepEqual(new Set(ACVP.testGroups.map((group) => group.parameterSet)), new Set(["ML-DSA-65"]));
  const verdicts = new Set(ACVP.testGroups.flatMap((group) => group.tests.map((item) => item.testPassed)));
  assert.deepEqual(verdicts, new Set([true, false]));
});

for (const group of ACVP.testGroups) {
  for (const item of group.tests) {
    test(`ACVP ML-DSA-65 sigVer ${group.signatureInterface} tc${String(item.tcId)}`, () => {
      const [pk, message, signature] = [hex(item.pk), hex(item.message), hex(item.signature)];
      const ok =
        group.signatureInterface === "external"
          ? mldsa65Verify(pk, message, signature, hex(item.context))
          : mldsa65VerifyInternal(pk, message, signature);
      assert.equal(ok, item.testPassed, String(item.reason));
    });
  }
}
