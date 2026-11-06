/**
 * SPEC 4.7 / 9.6: `tine-sig/3` (format v4 artifacts) and `tine-attest/2`
 * (attestations on a run root), with the fail-closed five-state verdict.
 *
 * Every refusal is a *returned* verdict, never a throw, and the check order is
 * the reference's: scheme, key count, block keys, nulls, types, algorithm,
 * value spelling, message, key.
 */

import { verifyV4, SCHEME_V3, MAX_V4_SIGNATURES, V4_KIND } from "./artifact.js";
import { canonicalJson } from "./canon.js";
import { constantTimeEqual, ed25519Verify, hmacSha256Hex, weakPublicKey } from "./crypto.js";
import { parseOid } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";

export const HEADER_KEYS = ["alg", "key_id", "scheme", "signed_at", "signer"] as const;
const BLOCK_KEYS = new Set<string>([...HEADER_KEYS, "value", "public_key"]);
const VALUE_LENGTHS: Record<string, number> = { "hmac-sha256": 64, ed25519: 128 };
export const MIN_HMAC_KEY_BYTES = 16;
export const SCHEME_ATTEST_V2 = "tine-attest/2";
export const SCHEME_ATTEST_V1 = "tine-attest/1";
const DOMAIN_V3 = "opentine.signature.v3:";
const ATTEST_DOMAIN_V2 = "opentine.attestation.v2:";
const encoder = new TextEncoder();

export type State = "verified" | "verified-tofu" | "unsigned" | "no-key" | "mismatch" | "error";

export interface SignatureResult {
  ok: boolean;
  state: State;
  algorithm: string | null;
  key_id: string | null;
  signer: string | null;
  signed_at: string | null;
  reason: string;
}

export interface VerifyKeys {
  hmacKey?: Uint8Array | null;
  publicKey?: Uint8Array | null;
  trustEmbedded?: boolean;
}

export type Header = Map<string, JValue>;
export type MessageBuilder = (header: Header) => Uint8Array;

class SignatureError extends TineError {}

function prefixed(domain: string, body: Uint8Array): Uint8Array {
  const head = encoder.encode(domain);
  const out = new Uint8Array(head.length + body.length);
  out.set(head);
  out.set(body, head.length);
  return out;
}

function headerView(header: Header): JObject {
  return new Map(HEADER_KEYS.map((key) => [key, header.has(key) ? (header.get(key) as JValue) : null]));
}

/** `tine-sig/3`: the exact bytes signed for a v4 artifact (SPEC 9.6). */
export function artifactMessage(data: JValue, header: Header): Uint8Array {
  const root = isObject(data) ? data.get("root") : undefined;
  if (typeof root !== "string") throw new SignatureError("v4 artifact has no root", "sig.payload-not-object");
  const annotations = (data as JObject).get("annotations");
  if (!Array.isArray(annotations)) throw new SignatureError("v4 annotations must be a list");
  let head: JValue = null;
  if (annotations.length) {
    const last = annotations[annotations.length - 1];
    head = isObject(last) ? (last.get("id") ?? null) : null;
    if (typeof head !== "string") throw new SignatureError("v4 annotation head has no id");
  }
  const view: JObject = new Map<string, JValue>([
    ["annotations_head", head],
    ["format_version", 4n],
    ["header", headerView(header)],
    ["kind", V4_KIND],
    ["root", root],
  ]);
  try {
    return prefixed(DOMAIN_V3, canonicalJson(view));
  } catch (exc) {
    throw new SignatureError(`v4 signed view cannot be canonicalized: ${(exc as Error).message}`);
  }
}

/** `tine-attest/2`: Ed25519 over the JCS payload without `signature`, beside the header. */
export function attestMessage(payload: JValue, header: Header): Uint8Array {
  if (header.get("alg") !== "ed25519") throw new SignatureError("tine-attest/2 is Ed25519 only");
  if (!isObject(payload)) {
    throw new SignatureError("attestation payload must be an object", "sig.payload-not-object");
  }
  const target = payload.get("target_id");
  if (typeof target !== "string" || parseOid(target)[0] !== "run") {
    throw new SignatureError("tine-attest/2 must target a run root");
  }
  const body: JObject = new Map([...payload].filter(([key]) => key !== "signature"));
  const view: JObject = new Map<string, JValue>([
    ["body", body],
    ["header", headerView(header)],
  ]);
  try {
    return prefixed(ATTEST_DOMAIN_V2, canonicalJson(view));
  } catch (exc) {
    throw new SignatureError(`attestation cannot be canonicalized: ${(exc as Error).message}`);
  }
}

function lowerHex(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
}

function hex(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text, "hex"));
}

/** Check one block against the content *build* projects (`_signing_verify.verify_block`). */
export function verifyBlock(
  block: JValue | undefined,
  build: MessageBuilder,
  schemes: readonly string[],
  subject: string,
  keys: VerifyKeys,
): SignatureResult {
  const refusal = (state: State, reason: string): SignatureResult => ({
    ok: false,
    state,
    algorithm: null,
    key_id: null,
    signer: null,
    signed_at: null,
    reason,
  });
  if (block === undefined || block === null) return refusal("unsigned", "no signature present");
  if (!isObject(block)) return refusal("error", `${subject} signature is not an object`);
  const algorithm = block.get("alg");
  const rawOptional = [block.get("key_id"), block.get("signer"), block.get("signed_at")];
  const [keyId, signer, signedAt] = rawOptional.map((item) => (typeof item === "string" ? item : null));
  const result = (ok: boolean, state: State, reason: string): SignatureResult => ({
    ok,
    state,
    algorithm: typeof algorithm === "string" ? algorithm : null,
    key_id: keyId,
    signer,
    signed_at: signedAt,
    reason,
  });
  const scheme = block.get("scheme");
  if (typeof scheme !== "string" || !schemes.includes(scheme)) {
    return result(false, "error", "unsupported signature scheme");
  }
  const supplied = Number(keys.hmacKey != null) + Number(keys.publicKey != null) + Number(Boolean(keys.trustEmbedded));
  if (supplied > 1) return result(false, "error", "pass exactly one verification key");
  if ([...block.keys()].some((key) => !BLOCK_KEYS.has(key)) || (algorithm !== "ed25519" && block.has("public_key"))) {
    return result(false, "error", "malformed signature header");
  }
  if ([...block.values()].some((item) => item === null)) return result(false, "error", "malformed signature header");
  if (typeof algorithm !== "string" || rawOptional.some((item) => item !== undefined && typeof item !== "string")) {
    return result(false, "error", "malformed signature header");
  }
  if (!(algorithm in VALUE_LENGTHS)) return result(false, "error", "unsupported signature algorithm");
  const value = block.get("value");
  if (!lowerHex(value, VALUE_LENGTHS[algorithm])) return result(false, "error", "malformed signature value");
  const header: Header = new Map(HEADER_KEYS.map((key) => [key, block.has(key) ? (block.get(key) as JValue) : null]));
  header.set("alg", algorithm);
  let message: Uint8Array;
  try {
    message = build(header);
  } catch (exc) {
    if (exc instanceof TineError) return result(false, "error", `malformed signed ${subject} content`);
    throw exc;
  }
  if (algorithm === "hmac-sha256") {
    const key = keys.hmacKey;
    if (key == null) return result(false, "no-key", "HMAC signature present but no key supplied");
    if (key.length === 0) return result(false, "error", "HMAC key must be non-empty bytes");
    if (key.length < MIN_HMAC_KEY_BYTES) {
      return result(false, "error", `HMAC key too short (${key.length} bytes); use at least ${MIN_HMAC_KEY_BYTES}`);
    }
    const valid = constantTimeEqual(hmacSha256Hex(key, message), value);
    return result(valid, valid ? "verified" : "mismatch", valid ? "ok" : "signature mismatch");
  }
  const embedded = block.get("public_key");
  if (!lowerHex(embedded, 64)) return result(false, "error", "malformed ed25519 public key");
  let publicKey: Uint8Array;
  let state: State;
  if (keys.publicKey != null) {
    if (keys.publicKey.length !== 32) return result(false, "error", "malformed ed25519 public key");
    publicKey = keys.publicKey;
    if (weakPublicKey(publicKey)) {
      return result(false, "error", "ed25519 public key has small order or a non-canonical encoding");
    }
    state = "verified";
    if (embedded !== Buffer.from(publicKey).toString("hex")) {
      return result(false, "mismatch", "embedded public key is not the trusted key");
    }
  } else if (keys.trustEmbedded) {
    publicKey = hex(embedded);
    if (weakPublicKey(publicKey)) {
      return result(false, "error", "ed25519 public key has small order or a non-canonical encoding");
    }
    state = "verified-tofu";
  } else {
    return result(false, "no-key", "ed25519 signature present but no trusted public key");
  }
  if (!ed25519Verify(publicKey, hex(value), message)) return result(false, "mismatch", "signature mismatch");
  return result(true, state, "ok");
}

function refusal(state: State, reason: string): SignatureResult {
  return { ok: false, state, algorithm: null, key_id: null, signer: null, signed_at: null, reason };
}

/**
 * The SPEC 4.7 verdict for a parsed v4 artifact. Content is checked against the
 * root first: a tampered envelope under an intact signature is `mismatch`. With
 * several blocks the first one the key verifies wins, else the first verdict.
 */
export function verifyArtifactV4(data: JObject, keys: VerifyKeys = {}): SignatureResult {
  const signatures = data.get("signatures");
  if (!Array.isArray(signatures) || signatures.length > MAX_V4_SIGNATURES) {
    return refusal("error", `v4 signatures must be a list of at most ${MAX_V4_SIGNATURES}`);
  }
  if (!signatures.length) return refusal("unsigned", "no signature present");
  if (signatures.some((block) => !isObject(block) || block.get("scheme") !== SCHEME_V3)) {
    return refusal("error", "unsupported signature scheme");
  }
  const integrity = verifyV4(data);
  if (!integrity.ok) return refusal("mismatch", `content does not match the signed root: ${integrity.reason}`);
  const results = signatures.map((block) =>
    verifyBlock(block, (header) => artifactMessage(data, header), [SCHEME_V3], "artifact", keys),
  );
  return results.find((result) => result.ok) ?? results[0];
}

/**
 * The verdict for an attestation payload's `signature` block. Phase 1 builds
 * only `tine-attest/2` messages; a `tine-attest/1` block (the legacy v2
 * canonicalizer) is reported as an error rather than guessed at.
 */
export function verifyAttestation(payload: JValue, keys: VerifyKeys = {}): SignatureResult {
  const block = isObject(payload) ? payload.get("signature") : undefined;
  return verifyBlock(
    block,
    (header) => {
      if (header.get("scheme") !== SCHEME_ATTEST_V2) {
        throw new SignatureError("tine-attest/1 needs the legacy canonicalizer, not in phase 1");
      }
      return attestMessage(payload, header);
    },
    [SCHEME_ATTEST_V1, SCHEME_ATTEST_V2],
    "attestation",
    keys,
  );
}
