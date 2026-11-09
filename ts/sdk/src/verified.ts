/**
 * Fetch and verify: every byte the client gets back is checked with the TS
 * verifier (`@opentine/verify`) before it is returned. A server, a cache or a
 * share link can only withhold objects; it cannot hand back altered ones.
 */

import { inspectPack, ObjectEnvelope, webhookClass } from "@opentine/verify";

import type { TineClient } from "./client.js";
import type { Capabilities, FetchRequest, Oid } from "./types.js";

/** Bytes that do not match the ids they were asked for. */
export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

/** Every object of a pack, each id recomputed from its bytes; every `want` must be present. */
export function verifyPack(pack: Uint8Array, wants: Oid[] = []): Map<Oid, Uint8Array> {
  let objects: [string, Uint8Array][];
  try {
    objects = inspectPack(pack).objects;
  } catch (error) {
    throw new VerificationError(`pack failed verification: ${(error as Error).message}`);
  }
  const map = new Map(objects);
  const absent = wants.filter((oid) => !map.has(oid));
  if (absent.length) throw new VerificationError(`pack is missing ${absent.join(", ")}`);
  return map;
}

/** `fetchPack`, verified. */
export async function fetchVerified(client: TineClient, request: FetchRequest): Promise<Map<Oid, Uint8Array>> {
  return verifyPack(await client.fetchPack(request), request.wants);
}

/** `readObject`, verified: the stored envelope must hash to `oid`. */
export async function readObjectVerified(client: TineClient, oid: Oid): Promise<ObjectEnvelope> {
  const raw = await client.readObject(oid);
  try {
    return ObjectEnvelope.decode(raw, oid);
  } catch (error) {
    throw new VerificationError(`object ${oid} failed verification: ${(error as Error).message}`);
  }
}

/** `runClosure`, verified, and holding the run itself. */
export async function runClosureVerified(client: TineClient, oid: Oid): Promise<Map<Oid, Uint8Array>> {
  return verifyPack(await client.runClosure(oid), [oid]);
}

/** Decode base64url without Node's Buffer, so this module also runs in browsers. */
function base64url(text: string): Uint8Array {
  const plain = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(plain + "=".repeat((4 - (plain.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/**
 * A `tine-webhook/1` delivery checked against the keys the remote advertises in
 * `GET /v1/capabilities` (`webhooks.keys`): `valid`, `stale`, `unknown-key`,
 * `bad-signature` or `malformed`.
 */
export function verifyWebhook(
  body: Uint8Array,
  header: string,
  caps: Capabilities,
  now: number = Math.floor(Date.now() / 1000),
): string {
  const listed = caps.webhooks?.keys ?? {};
  const keys = new Map(Object.entries(listed).map(([kid, key]) => [kid, base64url(key)]));
  const window = BigInt(caps.webhooks?.replay_window ?? 300);
  return webhookClass(body, header, keys, BigInt(now), window);
}
