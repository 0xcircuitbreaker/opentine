/**
 * The phase-1 acceptance gate: every in-scope vector in docs/conformance agrees
 * with its pinned verdict, and every out-of-scope vector is skipped under a
 * category this file names.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  loadSuite,
  OUT_OF_SCOPE_ALGS,
  OUT_OF_SCOPE_FAMILIES,
  OUT_OF_SCOPE_OPS,
  OUT_OF_SCOPE_SCHEMES,
  reasonOk,
  runSuite,
  suiteCases,
  type Row,
} from "../src/suite.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const suite = loadSuite(ROOT);
const rows = runSuite(suite);

/** The exact set of skip categories phase 1 is allowed to report. */
const EXPECTED_SKIPS = new Set([
  ...Object.keys(OUT_OF_SCOPE_OPS).map((op) => `op:${op}`),
  ...Object.keys(OUT_OF_SCOPE_SCHEMES).map((scheme) => `scheme:${scheme}`),
  ...Object.keys(OUT_OF_SCOPE_FAMILIES).map((family) => `family:${family}`),
  ...Object.keys(OUT_OF_SCOPE_ALGS).map((alg) => `alg:${alg}`),
]);

/** Families whose every case is format v4 (SPEC Part 9): the 0.39 acceptance set. */
const V4_FAMILIES = ["vectors/09-canon-v4.json", "vectors/53-sig-v4.json"];

function tally(selected: Row[]): Record<string, number> {
  const out: Record<string, number> = { pass: 0, fail: 0, repaired: 0, skip: 0, unsupported: 0 };
  for (const row of selected) out[row.status]++;
  return out;
}

test("the suite's files match MANIFEST.json digests", () => {
  for (const [name, expected] of Object.entries(suite.manifest.files)) {
    const local = join(suite.dir, name);
    const path = existsSync(local) ? local : join(ROOT, name);
    const actual = createHash("sha256").update(readFileSync(path)).digest("hex");
    assert.equal(actual, expected, name);
  }
});

test("the case count matches MANIFEST.totals", () => {
  const totals = suite.manifest.totals as { cases: number };
  assert.equal(suiteCases(suite).length, totals.cases);
});

test("the tagged-value self-test passes first", () => {
  const selftest = rows.filter((row) => row.file === "vectors/01-selftest.json" && row.status !== "skip");
  assert.ok(selftest.length > 0);
  for (const row of selftest) assert.equal(row.status, "pass", `${row.id}: ${row.detail}`);
});

test("every in-scope vector agrees with its pinned verdict (Level 1)", () => {
  const failures = rows.filter((row) => row.status === "fail" || row.status === "repaired" || row.status === "unsupported");
  const counts = tally(rows);
  console.log(
    `conformance: ${counts.pass} pass  ${counts.fail} fail  ${counts.repaired} repaired  ` +
      `${counts.unsupported} unimplemented  ${counts.skip} skipped (out of phase-1 scope)`,
  );
  assert.deepEqual(
    failures.map((row) => `${row.status} ${row.id} (${row.op}): ${row.detail}`),
    [],
  );
});

test("every format v4 vector passes (0.39.0 acceptance)", () => {
  for (const file of V4_FAMILIES) {
    const selected = rows.filter((row) => row.file === file);
    assert.ok(selected.length > 0, file);
    const counts = tally(selected);
    console.log(`${file}: ${counts.pass}/${selected.length} pass`);
    assert.equal(counts.pass, selected.length, file);
  }
});

test("every format v5 vector passes (0.40.0 acceptance)", () => {
  const selected = rows.filter((row) => row.file === "vectors/54-artifact-v5.json");
  assert.ok(selected.length > 0);
  assert.equal(tally(selected).pass, selected.length);
});

test("out-of-scope vectors are skipped only under the named categories", () => {
  const seen = new Set<string>();
  for (const row of rows.filter((item) => item.status === "skip")) {
    assert.ok(EXPECTED_SKIPS.has(row.detail), `${row.id} skipped under an unnamed category ${row.detail}`);
    seen.add(row.detail);
  }
  // A named category that no longer matches anything is stale scope, not slack.
  assert.deepEqual([...EXPECTED_SKIPS].filter((name) => !seen.has(name)), []);
});

test("rejections carry the vector's reason code (Level 2)", () => {
  const groups = suite.manifest.alias_groups;
  const cases = new Map(suiteCases(suite).map(({ testCase }) => [testCase.id, testCase]));
  const checked = rows.filter((row) => row.status === "pass" && row.reasonExpected);
  const disagree = checked.filter((row) => {
    const testCase = cases.get(row.id);
    const expected = testCase?.reason_any ?? (row.reasonExpected ? [row.reasonExpected] : []);
    return !reasonOk(row.reasonActual, expected, groups);
  });
  console.log(`reason agreement: ${checked.length - disagree.length}/${checked.length}`);
  assert.deepEqual(
    disagree.map((row) => `${row.id}: expected ${row.reasonExpected}, got ${row.reasonActual}`),
    [],
  );
});
