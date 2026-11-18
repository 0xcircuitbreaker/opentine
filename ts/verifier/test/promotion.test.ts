/**
 * 0.58: promote, revert, promote verifies offline in the TS verifier.
 *
 * Promotion emits only existing kinds: the admission VSA (`vsa.verify`) and
 * attestations (`sig.verify`, attestation family). Same fixture as
 * tests/test_058_promotion_offline.py, which regenerates it.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { isObject, parseText, STRICT, type JObject, type JValue } from "../src/json.js";
import { runOp } from "../src/ops.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
type Case = {
  id: string;
  op: string;
  args: Record<string, unknown>;
  expect: string;
};
const text = readFileSync(join(ROOT, "tests", "data", "promotion_chain.json"), "utf-8");
const fixture = JSON.parse(text) as { cases: Case[] };
const parsed = (parseText(text, STRICT) as JObject).get("cases") as JObject[];
const values = parsed.map((entry) => entry.get("value") as JObject);
const RUN_A = `run:sha256:${"a".repeat(64)}`;

function outcome(entry: Case, value: JValue): string {
  const out = runOp(entry.op, { value }, entry.args as never, {}) as Record<
    string,
    unknown
  >;
  return String(entry.op === "vsa.verify" ? out.class : out.state);
}

function tampered(entry: Case, value: JObject): JObject {
  const edited = new Map(value);
  if (entry.op === "vsa.verify") {
    edited.set("subject", RUN_A);
    return edited;
  }
  const claim = value.get("claim");
  assert.ok(isObject(claim));
  edited.set("claim", new Map(claim).set("label", "staging"));
  return edited;
}

test("the fixture holds promote, revert and promote", () => {
  assert.ok(fixture.cases.some((c) => c.id === "two/decision"));
  assert.equal(fixture.cases.filter((c) => c.op === "vsa.verify").length, 2);
});

fixture.cases.forEach((entry, index) => {
  test(`promotion ${entry.id} verifies offline and an edit does not`, () => {
    assert.equal(outcome(entry, values[index]), entry.expect);
    assert.notEqual(outcome(entry, tampered(entry, values[index])), entry.expect);
  });
});
