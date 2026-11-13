/**
 * Trust bundles (0.51, SPEC 8.26): a signed note over canonical JSON, opened
 * against the owner key a viewer pins. Bundles are signed here with Node's
 * Ed25519; tests/test_051_trust_bundle.py opens Python-signed ones in the
 * committed browser build.
 */

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { TineError } from "../src/errors.js";
import { keyFingerprint, openTrustBundle } from "../src/trustbundle.js";

const NAME = "example.com/trust";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const RAW = publicKey.export({ format: "der", type: "spki" }).subarray(-32);

function vkey(name: string, raw: Uint8Array): string {
  const id = createHash("sha256").update(`${name}\n`).update(Uint8Array.of(1)).update(raw).digest().subarray(0, 4);
  return `${name}+${id.toString("hex")}+${Buffer.concat([Buffer.of(1), raw]).toString("base64")}`;
}

const OWNER = vkey(NAME, RAW);
const PIN = `sha256:${"a".repeat(64)}`;

function note(json: string, name = NAME): Uint8Array {
  const body = `${name}\n${json}\n`;
  const id = Buffer.from(OWNER.split("+")[1], "hex");
  const signature = sign(null, Buffer.from(body), privateKey);
  return Buffer.from(`${body}\n— ${name} ${Buffer.concat([id, signature]).toString("base64")}\n`);
}

const GOOD = `{"issued_at":"2026-11-13T00:00:00Z","serial":3,"trust_bundle":1,"trust_policy":{"pin":["${PIN}"]}}`;

function refuses(run: () => unknown, pattern: RegExp): void {
  assert.throws(run, (exc: unknown) => exc instanceof TineError && exc.code === "trust-bundle.invalid" && pattern.test(exc.message));
}

test("a bundle signed by the pinned owner opens and names its pins", () => {
  const bundle = openTrustBundle(note(GOOD), OWNER);
  assert.equal(bundle.serial, 3);
  assert.deepEqual([...bundle.pins], [PIN]);
  assert.equal(bundle.owner, NAME);
  assert.match(bundle.digest, /^sha256:[0-9a-f]{64}$/);
});

test("another owner key, a tampered payload or a renamed owner is refused", () => {
  const other = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  refuses(() => openTrustBundle(note(GOOD), vkey(NAME, other)), /not signed by the pinned owner/);
  const tampered = Buffer.from(Buffer.from(note(GOOD)).toString("utf8").replace('"serial":3', '"serial":9'));
  refuses(() => openTrustBundle(tampered, OWNER), /not signed by the pinned owner/);
  refuses(() => openTrustBundle(note(GOOD, "other.example/trust"), OWNER), /names owner/);
});

test("a payload that is not canonical, or not a bundle, is refused", () => {
  refuses(() => openTrustBundle(note(GOOD.replace(",", ", ")), OWNER), /not canonical/);
  refuses(() => openTrustBundle(note(GOOD.replace('"trust_bundle":1', '"trust_bundle":2')), OWNER), /not a trust bundle/);
  refuses(() => openTrustBundle(note(GOOD.replace(`"${PIN}"]}`, `"${PIN}"],"pubkey":"/k"}`)), OWNER), /may only hold/);
  refuses(() => openTrustBundle(note(GOOD.replace(PIN, "sha256:abc")), OWNER), /fingerprints/);
});

test("an expired bundle and a rollback below the accepted serial are refused", () => {
  const expiring = GOOD.replace('"issued_at"', '"expires_at":"2026-12-01T00:00:00Z","issued_at"');
  assert.equal(openTrustBundle(note(expiring), OWNER, { now: Date.parse("2026-11-20T00:00:00Z") }).expiresAt, "2026-12-01T00:00:00Z");
  refuses(() => openTrustBundle(note(expiring), OWNER, { now: Date.parse("2027-01-01T00:00:00Z") }), /expired/);
  refuses(() => openTrustBundle(note(GOOD), OWNER, { minSerial: 4 }), /older than 4/);
});

test("times Python refuses (Feb 30, 24:00), a BOM-prefixed note and a boolean version are refused, as in Python", () => {
  refuses(() => openTrustBundle(note(GOOD.replace("2026-11-13T00", "2026-02-30T00")), OWNER), /RFC 3339/);
  refuses(() => openTrustBundle(note(GOOD.replace("2026-11-13T00", "2026-11-13T24")), OWNER), /RFC 3339/);
  refuses(() => openTrustBundle(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), note(GOOD)]), OWNER), /names owner/);
  refuses(() => openTrustBundle(note(GOOD.replace('"trust_bundle":1', '"trust_bundle":true')), OWNER), /not a trust bundle/);
});

test("a key fingerprint is sha256 of the raw key, as tine verify prints it", () => {
  assert.equal(keyFingerprint("00".repeat(32)), `sha256:${createHash("sha256").update(Buffer.alloc(32)).digest("hex")}`);
});
