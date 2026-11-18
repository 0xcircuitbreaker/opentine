/**
 * 0.60: the TS protected-surfaces check answers tests/data/integrity_check.json
 * exactly as `opentine._integrity.check` does (tests/test_060_integrity.py
 * regenerates the fixture and checks the Python answers).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { blockingFindings, checkProtected, matches, MODIFIED, type Observations, type Protected } from "../src/protected.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
type Case = { id: string; observations: Observations; expect: [string, string][] };
const fixture = JSON.parse(readFileSync(join(ROOT, "tests", "data", "integrity_check.json"), "utf-8")) as {
  protected: Protected;
  cases: Case[];
};

test("the fixture covers the fail: code, both advisories and a clean run", () => {
  const codes = new Set(fixture.cases.flatMap((c) => c.expect.map(([code]) => code)));
  assert.ok(codes.has(MODIFIED) && codes.has("advisory:test-deleted") && codes.has("advisory:holdout-read"));
  assert.ok(fixture.cases.some((c) => c.expect.length === 0));
});

for (const entry of fixture.cases) {
  test(`protected check ${entry.id} matches the Python reference`, () => {
    const findings = checkProtected(fixture.protected, entry.observations);
    assert.deepEqual(
      findings.map((f) => [f.code, f.path]),
      entry.expect,
    );
    const blocks = blockingFindings(findings).length > 0;
    assert.equal(blocks, entry.expect.some(([code]) => code.startsWith("fail:")));
  });
}

test("glob metacharacters other than * ? ** are literal", () => {
  assert.ok(matches("a.b/[x]", "a.b/[x]"));
  assert.ok(!matches("a.b/[x]", "aXb/x"));
});
