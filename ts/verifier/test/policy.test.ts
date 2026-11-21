/**
 * 0.74: the policy language gives the same results in TypeScript as in Python, on the
 * shared vectors in tests/data/policy_vectors.json (tests/test_075_policy_vectors.py runs
 * the same file; scripts/gen_policy_vectors.py regenerates it).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parse, PolicyError, type PValue } from "../src/policy.js";
import { checkInput, decide, evaluate } from "../src/policyeval.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
type Expect = { outcome: string; value?: PValue; code?: string };
type Case = { id: string; expr: string; input: Record<string, PValue> | null; expect: Expect };
type PolicyCase = {
  id: string;
  policy: { rules: { id: string; effect: string; expr: string }[] };
  input?: Record<string, PValue>;
  decision: string;
  outcomes: string[];
  codes?: string[];
};
const vectors = JSON.parse(
  readFileSync(join(ROOT, "tests", "data", "policy_vectors.json"), "utf-8"),
) as { input: Record<string, PValue>; cases: Case[]; policies: PolicyCase[] };

function run(c: Case): Expect {
  const input = c.input ?? vectors.input;
  try {
    checkInput(input);
    return { outcome: "value", value: evaluate(parse(c.expr), input) };
  } catch (e) {
    if (e instanceof PolicyError) return { outcome: "error", code: e.code };
    throw e;
  }
}

test("every expression vector matches the Python evaluator", () => {
  assert.ok(vectors.cases.length >= 150);
  const bad = vectors.cases
    .map((c) => ({ id: c.id, got: run(c), want: c.expect }))
    .filter((r) => JSON.stringify(r.got) !== JSON.stringify(r.want));
  assert.deepEqual(bad, []);
});

test("every policy vector decides as in Python (advisory never blocks)", () => {
  for (const p of vectors.policies) {
    const result = decide(p.policy, p.input ?? vectors.input);
    assert.equal(result.decision, p.decision, p.id);
    assert.deepEqual(
      result.rules.map((r) => r.outcome),
      p.outcomes,
      p.id,
    );
    if (p.codes) {
      assert.deepEqual(
        result.rules.map((r) => r.code),
        p.codes,
        p.id,
      );
    }
  }
});
