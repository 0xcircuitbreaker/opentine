/**
 * 0.75: the TS dataset-version check answers tests/data/dataset_version.json
 * exactly as `opentine._dataset_claims.offline` does
 * (tests/test_075_dataset_vectors.py checks the fixture is current).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalText } from "../src/canon.js";
import { checkDatasetVersion } from "../src/datasetversion.js";
import { KERNEL, parseBytes, type JObject, type JValue } from "../src/json.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const fixture = parseBytes(readFileSync(join(ROOT, "tests", "data", "dataset_version.json")), KERNEL) as JObject;
const cases = fixture.get("cases") as JObject[];

test("the fixture has good and bad cases", () => {
  const oks = cases.filter((c) => (c.get("expect") as JObject).get("ok") === true);
  assert.equal(oks.length, 6);
  assert.ok(cases.length > oks.length);
});

for (const entry of cases) {
  test(`dataset version ${String(entry.get("id"))} matches the Python reference`, () => {
    const expect = entry.get("expect") as JObject;
    const found = checkDatasetVersion(entry.get("payload") as JValue);
    assert.equal(found.ok, expect.get("ok"), "ok");
    assert.equal(found.signature, expect.get("signature"), "signature");
    assert.equal(canonicalText(found.problems), canonicalText(expect.get("problems") as JValue), "problems");
    assert.equal(BigInt(found.members), expect.get("members"), "members");
    assert.equal(BigInt(found.excluded), expect.get("excluded"), "excluded");
  });
}
