/**
 * 0.59: the TS lineage check answers tests/data/lineage_check.json exactly as
 * `opentine._lineage_check.check` does (tests/test_059_lineage_fixture.py
 * regenerates the fixture and checks the Python answers).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkLineage } from "../src/lineage.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
type Case = { id: string; variant: string; expect: [string, string][] };
const fixture = JSON.parse(readFileSync(join(ROOT, "tests", "data", "lineage_check.json"), "utf-8")) as {
  files: Record<string, string>;
  cases: Case[];
};
const files = new Map(Object.entries(fixture.files).map(([k, v]) => [k, Uint8Array.from(Buffer.from(v, "base64"))]));

test("the fixture covers every lineage code and a passing variant", () => {
  const codes = new Set(fixture.cases.flatMap((c) => c.expect.map(([code]) => code)));
  assert.equal(codes.size, 6);
  assert.ok(fixture.cases.some((c) => c.expect.length === 0));
});

for (const entry of fixture.cases) {
  test(`lineage check ${entry.id} matches the Python reference`, () => {
    const report = checkLineage(files, entry.variant);
    assert.deepEqual(report.findings.map((f) => [f.code, f.variant]), entry.expect);
    assert.equal(report.ok, entry.expect.length === 0);
  });
}

test("an edited eval file is evidence-missing in TS too", () => {
  const good = fixture.cases.find((c) => c.id === "good");
  assert.ok(good);
  const edited = new Map(files);
  for (const [path, raw] of edited) {
    if (path.startsWith("evals/")) edited.set(path, Uint8Array.from([...raw, 10]));
  }
  const codes = checkLineage(edited, good.variant).findings.map((f) => f.code);
  assert.ok(codes.includes("lineage.evidence-missing"));
});
