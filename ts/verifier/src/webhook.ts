/**
 * SPEC 8.13 (0.45.1): a signed `tine-webhook/1` delivery. A port of
 * `opentine/_webhook_sig.py`: the header grammar, the inclusive replay window,
 * the pinned key id and Ed25519 over `opentine-webhook/1\n<t>\n<body>`, answered
 * in the same order. A verdict: never throws on bad input.
 */

import { ed25519Verify } from "./crypto.js";
import { isObject, type JValue } from "./json.js";

const MAX_BODY = 256 * 1024;
const HEADER = /^t=([0-9]{1,12}),kid=(ed25519:[0-9a-f]{16}),sig=([A-Za-z0-9_-]{86})$/;

export function webhookClass(
  body: Uint8Array,
  header: string,
  keys: Map<string, Uint8Array>,
  now: bigint,
  window: bigint,
): string {
  const match = HEADER.exec(header.trim());
  if (match === null || body.length > MAX_BODY) return "malformed";
  const stamp = BigInt(match[1]);
  const kid = match[2];
  const delta = now > stamp ? now - stamp : stamp - now;
  if (delta > window) return "stale";
  const key = keys.get(kid);
  if (key === undefined) return "unknown-key";
  const signed = Buffer.concat([Buffer.from(`opentine-webhook/1\n${stamp.toString()}\n`, "ascii"), body]);
  const signature = Uint8Array.from(Buffer.from(match[3], "base64url"));
  if (key.length !== 32 || signature.length !== 64 || !ed25519Verify(key, signature, signed)) {
    return "bad-signature";
  }
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    return "malformed";
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return "malformed";
  return (payload as Record<string, unknown>).format === "tine-webhook/1" ? "valid" : "malformed";
}

export function webhookVerify(value: JValue): Record<string, unknown> {
  let kind = "malformed";
  try {
    if (!isObject(value)) throw new Error("not an object");
    const bodyText = value.get("body_b64");
    const header = value.get("header");
    const listed = value.get("keys");
    const now = value.get("now");
    const window = value.get("window");
    if (typeof bodyText !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(bodyText) || bodyText.length % 4 !== 0) {
      throw new Error("body is not base64");
    }
    if (typeof header !== "string" || !isObject(listed) || typeof now !== "bigint" || typeof window !== "bigint") {
      throw new Error("bad webhook input");
    }
    const keys = new Map<string, Uint8Array>();
    for (const [kid, raw] of listed) {
      if (typeof raw !== "string") throw new Error("key is not base64url");
      keys.set(kid, Uint8Array.from(Buffer.from(raw, "base64url")));
    }
    kind = webhookClass(Uint8Array.from(Buffer.from(bodyText, "base64")), header, keys, now, window);
  } catch {
    kind = "malformed";
  }
  return { ok: kind === "valid", class: kind };
}
