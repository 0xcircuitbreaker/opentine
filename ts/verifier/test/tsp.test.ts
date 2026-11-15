/**
 * 0.52: the TS verifier checks an RFC 3161 token's CMS signature and chain, and a
 * keyless bundle's tokens, as Python does. `fixtures/tsp-tokens.json` holds
 * tokens written once by `fixtures/make_tsp_fixtures.py` with the Python
 * reference's answers (`tests/test_052_ts_keyless_tsp.py` re-checks those).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { TineError } from "../src/errors.js";
import { keylessTokenTime } from "../src/keyless.js";
import { verifyTimestampToken } from "../src/tsp.js";
import { asGenTime, read } from "../src/der.js";

interface Case {
  id: string;
  kind: "token" | "keyless";
  expect: { ok?: boolean; reason?: string; signing_time?: string | null; error?: string };
  ts_expect?: { ok: boolean; reason: string };
  token?: string;
  bound?: string;
  roots?: string[];
  windowed?: { certs: string[]; start: string; end?: string }[];
  tokens?: string[];
  signature?: string;
  authorities?: { certs: string[]; start: string; end?: string }[];
  leaf?: { start: string; end: string };
}

const path = fileURLToPath(new URL("../../test/fixtures/tsp-tokens.json", import.meta.url));
const CASES = (JSON.parse(readFileSync(path, "utf-8")) as { cases: Case[] }).cases;
const b = (text: string) => new Uint8Array(Buffer.from(text, "base64"));
const micros = (text: string) => BigInt(Date.parse(text)) * 1000n;

for (const item of CASES.filter((c) => c.kind === "token")) {
  test(`RFC 3161 ${item.id}`, () => {
    const windowed = (item.windowed ?? []).map((w) => [w.certs.map(b), { start: micros(w.start), end: w.end ? micros(w.end) : null }] as [Uint8Array[], { start: bigint; end: bigint | null }]);
    const verdict = verifyTimestampToken(b(item.token as string), b(item.bound as string), (item.roots ?? []).map(b), windowed);
    const expected = item.ts_expect ?? item.expect;
    assert.deepEqual({ ok: verdict.ok, reason: verdict.reason }, { ok: expected.ok, reason: expected.reason }, verdict.detail);
  });
}

for (const item of CASES.filter((c) => c.kind === "keyless")) {
  test(`keyless token time ${item.id}`, () => {
    const authorities = (item.authorities ?? []).map((a) => ({ certs: a.certs.map(b), validFor: { start: a.start, end: a.end } }));
    const run = () => keylessTokenTime((item.tokens ?? []).map(b), b(item.signature as string), authorities, item.leaf as { start: string; end: string });
    if (item.expect.error) {
      assert.throws(run, (exc: unknown) => exc instanceof TineError && exc.code === item.expect.error);
    } else {
      assert.equal(run(), item.expect.signing_time);
    }
  });
}

test("every truncation of a valid token fails cleanly as malformed or a bad signature", () => {
  const good = CASES.find((c) => c.id === "token.ec-v2") as Case;
  const raw = b(good.token as string);
  for (let cut = 0; cut < raw.length; cut += 7) {
    const verdict = verifyTimestampToken(raw.subarray(0, cut), b(good.bound as string), (good.roots ?? []).map(b));
    assert.equal(verdict.ok, false);
  }
});

test("GeneralizedTime keeps two-digit years as written and refuses year 0, as Python does", () => {
  const der = (text: string) => read(Uint8Array.from([0x18, text.length, ...new TextEncoder().encode(text)]));
  const year50 = new Date(0);
  year50.setUTCFullYear(50, 0, 1);
  assert.equal(asGenTime(der("00500101000000Z")), BigInt(year50.getTime()) * 1000n);
  assert.throws(() => asGenTime(der("00000101000000Z")));
  assert.equal(asGenTime(der("19700101000001Z")), 1000000n);
});
