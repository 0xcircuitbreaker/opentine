/**
 * FREEZE.md ruling (b): an unknown predicate inside a frozen envelope is `unchecked`.
 *
 * The envelope (the tine-attest/1 and /2 signature) still verifies exactly as
 * before; the claim is reported `unchecked:claim.unknown-predicate`, never
 * pass or fail. Same fixture as tests/test_051_unknown_claim.py.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { claimStatus, GRANTED_PREDICATES } from "../src/claim.js";
import { isObject, parseText, STRICT, type JObject } from "../src/json.js";
import { verifyAttestation } from "../src/signature.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const text = readFileSync(join(ROOT, "tests", "data", "unknown_claim_attestation.json"), "utf-8");
const fixture = JSON.parse(text) as {
  expect_claim: { status: string; reason: string; predicate: string };
  cases: Array<{ id: string; args: { key?: string; public_key?: string } }>;
};
const parsed = parseText(text, STRICT) as JObject;
const keys = JSON.parse(readFileSync(join(ROOT, "docs", "conformance", "keys.json"), "utf-8")) as Record<string, string>;

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

const values = (parsed.get("cases") as JObject[]).map((entry) => entry.get("value") as JObject);

test("no predicate is granted", () => {
  assert.equal(GRANTED_PREDICATES.size, 0);
});

fixture.cases.forEach((entry, index) => {
  test(`unknown predicate in ${entry.id}: envelope verified, claim unchecked`, () => {
    const value = values[index];
    const verifyKeys = entry.args.key
      ? { hmacKey: hex(keys[entry.args.key]) }
      : { publicKey: hex(entry.args.public_key as string) };
    const result = verifyAttestation(value, verifyKeys);
    assert.equal(result.state, "verified", result.reason);
    const status = claimStatus(value.get("claim"));
    assert.deepEqual(status, fixture.expect_claim);
    assert.notEqual(status.status as string, "pass");
    assert.notEqual(status.status as string, "fail");
    const claim = value.get("claim");
    assert.ok(isObject(claim));
    const edited = new Map(value);
    const editedClaim = new Map(claim);
    editedClaim.set("predicateType", `${fixture.expect_claim.predicate}-edited`);
    edited.set("claim", editedClaim);
    assert.equal(verifyAttestation(edited, verifyKeys).state, "mismatch");
  });
});

test("an unnamed claim is unchecked too", () => {
  for (const claim of [null, [], new Map(), new Map([["result", "pass"]])]) {
    assert.deepEqual(claimStatus(claim), { status: "unchecked", reason: "claim.unnamed", predicate: null });
  }
});
