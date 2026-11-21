/**
 * 0.75: the TS policy-file loader refuses what Python's strict_json and check_policy
 * refuse (duplicate keys, NaN/Infinity, unsafe integers; malformed policies), on the
 * shared `files` vectors in tests/data/policy_vectors.json.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import * as api from "../src/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
type FileCase = { id: string; text: string; expect: "ok" | "json" | "policy" };
const vectors = JSON.parse(readFileSync(join(ROOT, "tests", "data", "policy_vectors.json"), "utf-8")) as {
  files: FileCase[];
};

function stage(text: string): string {
  try {
    api.loadPolicy(text);
    return "ok";
  } catch (e) {
    if (e instanceof api.PolicyFileError) return e.stage;
    throw e;
  }
}

test("every policy-file vector loads or is refused as in Python", () => {
  assert.ok(vectors.files.length >= 20);
  const bad = vectors.files.map((c) => ({ id: c.id, got: stage(c.text) })).filter((r, i) => r.got !== vectors.files[i].expect);
  assert.deepEqual(bad, []);
});

test("strictPolicyJson keeps a __proto__ key as data and the policy decides", () => {
  const doc = api.strictPolicyJson('{"__proto__": {"x": 1}}') as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(doc), Object.prototype);
  assert.deepEqual(Object.keys(doc), ["__proto__"]);
  const policy = api.loadPolicy('{"schema": "opentine.policy/1", "name": "p", "rules": [{"id": "a", "effect": "require", "expr": "n > 1"}]}');
  assert.equal(api.decidePolicy(policy, { n: 2 }).decision, "allow");
  assert.equal(api.decidePolicy(policy, { n: 0 }).decision, "deny");
});
