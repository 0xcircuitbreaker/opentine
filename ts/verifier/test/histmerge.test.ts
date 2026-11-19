/**
 * 0.69: the TS history merge answers tests/data/history_merge.json exactly as
 * `opentine._history_merge_record.check` and the pyz port do
 * (tests/test_069_history_merge_fixture.py regenerates the fixture).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalText } from "../src/canon.js";
import { checkHistoryMerge, conflictJson, KINDS, merge, toJson } from "../src/histmerge.js";
import { KERNEL, parseBytes, type JObject, type JValue } from "../src/json.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const fixture = parseBytes(readFileSync(join(ROOT, "tests", "data", "history_merge.json")), KERNEL) as JObject;
const cases = fixture.get("cases") as JObject[];
const FIELDS = ["ok", "signature", "merged", "merged_matches", "conflicts_match", "conflicts"];

test("the fixture covers every conflict kind", () => {
  const kinds = new Set(cases.flatMap((c) => ((c.get("expect") as JObject).get("conflict_rows") as JObject[]).map((r) => r.get("kind"))));
  assert.deepEqual([...kinds].sort(), [...KINDS].sort());
});

for (const entry of cases) {
  test(`history merge ${String(entry.get("id"))} matches the Python reference`, () => {
    const expect = entry.get("expect") as JObject;
    const [base, ours, theirs] = ["base", "ours", "theirs"].map((k) => entry.get(k) as JValue);
    const key = entry.get("public_key");
    const found = checkHistoryMerge(entry.get("record") as JValue, base, ours, theirs,
      typeof key === "string" ? Uint8Array.from(Buffer.from(key, "hex")) : null);
    for (const field of FIELDS) {
      const want = expect.get(field);
      assert.equal(String((found as unknown as Record<string, unknown>)[field]), String(want), field);
    }
    const merged = merge(base, ours, theirs);
    assert.equal(canonicalText(toJson(merged.merged)), canonicalText(expect.get("merged_snapshot") as JValue));
    assert.equal(canonicalText(merged.conflicts.map(conflictJson)), canonicalText(expect.get("conflict_rows") as JValue));
  });
}

test("the merge is the same whichever side is ours", () => {
  for (const entry of cases) {
    const [base, ours, theirs] = ["base", "ours", "theirs"].map((k) => entry.get(k) as JValue);
    const one = merge(base, ours, theirs);
    const two = merge(base, theirs, ours);
    assert.equal(one.digests.merged, two.digests.merged);
    assert.equal(canonicalText(one.conflicts.map(conflictJson)), canonicalText(two.conflicts.map(conflictJson)));
  }
});
