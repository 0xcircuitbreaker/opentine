import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { TineClient, type Capabilities } from "../src/index.js";
import { fetchVerified, getReviewVerified, readObjectVerified, VerificationError, verifyPack, verifyWebhook } from "../src/verified.js";

const fixtures = new URL("../../test/fixtures/", import.meta.url);
const pack = new Uint8Array(readFileSync(new URL("run.pack", fixtures)));
const object = new Uint8Array(readFileSync(new URL("run.object", fixtures)));
const { run, objects } = JSON.parse(readFileSync(new URL("fixture.json", fixtures), "utf8")) as {
  run: string;
  objects: string[];
};

const serving = (bytes: Uint8Array) =>
  new TineClient({
    baseUrl: "https://t",
    tenant: "a",
    fetch: (async () => new Response(bytes, { status: 200 })) as typeof fetch,
  });

test("a fetched pack is verified object by object", async () => {
  const verified = await fetchVerified(serving(pack), { wants: [run] });
  assert.deepEqual([...verified.keys()].sort(), objects);
});

test("a pack missing a want, or with one changed byte, is refused", () => {
  assert.throws(() => verifyPack(pack, ["run:sha256:" + "0".repeat(64)]), VerificationError);
  const tampered = pack.slice();
  tampered[tampered.length - 5] ^= 1;
  assert.throws(() => verifyPack(tampered, [run]), VerificationError);
});

test("a read object must hash to the oid it was asked for", async () => {
  assert.equal((await readObjectVerified(serving(object), run)).oid, run);
  const other = "run:sha256:" + "1".repeat(64);
  await assert.rejects(readObjectVerified(serving(object), other), VerificationError);
});

test("webhook deliveries verify against the advertised keys", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const kid = "ed25519:0123456789abcdef";
  const caps = {
    webhooks: { keys: { [kid]: raw.toString("base64url") }, replay_window: 300 },
  } as unknown as Capabilities;
  const body = new TextEncoder().encode(JSON.stringify({ format: "tine-webhook/1", event: {} }));
  const now = 1_800_000_000;
  const signed = Buffer.concat([Buffer.from(`opentine-webhook/1\n${now}\n`), body]);
  const sig = sign(null, signed, privateKey).toString("base64url");
  const header = `t=${now},kid=${kid},sig=${sig}`;
  assert.equal(verifyWebhook(body, header, caps, now), "valid");
  assert.equal(verifyWebhook(body, header, caps, now + 301), "stale");
  const altered = body.slice();
  altered[0] ^= 1;
  assert.equal(verifyWebhook(altered, header, caps, now), "bad-signature");
});

test("a fetched Review verifies whole, every gate decision included", async () => {
  const review = readFileSync(new URL("review.json", fixtures), "utf8");
  const client = (text: string) =>
    new TineClient({
      baseUrl: "https://t",
      tenant: "a",
      fetch: (async () => new Response(text, { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch,
    });
  const result = await getReviewVerified(client(review), "auth-rework");
  assert.equal(result.status, "approved");
  assert.equal(result.decisions, 2);
  const forged = review.replace("coverage and risk hold", "forged approval");
  await assert.rejects(getReviewVerified(client(forged), "auth-rework"), VerificationError);
});
