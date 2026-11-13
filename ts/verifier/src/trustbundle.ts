/**
 * Browser trust bundles (0.51, SPEC 8.26): port of `opentine/_trust_bundle.py`.
 *
 * A bundle is a C2SP signed note by the bundle owner's Ed25519 key whose text
 * is `<owner name>\n<canonical JSON payload>\n`; the payload carries only
 * existing trust documents (a trust-policy entry's portable fields, an
 * `opentine-witness-network/1` registry, signed-note log keys and
 * `opentine.admission-policy` documents). A viewer pins the owner's verifier
 * key (`name+hash+key`) out of band, may cache the bundle by its digest, and
 * keeps the highest serial it has accepted so an older bundle cannot be
 * replayed. `openTrustBundle` refuses anything the Python reader refuses on
 * the same bytes for signature, owner, canonical form, serial, times and the
 * shape of each part; the deeper validators of the witness registry and the
 * admission policies run in `tine trust bundle verify`.
 */

import { createHash } from "node:crypto";
import { canonicalText } from "./canon.js";
import { ed25519Verify } from "./crypto.js";
import { TineError } from "./errors.js";
import { isInt, isObject, KERNEL, parseText, type JObject, type JValue } from "./json.js";

export const MAX_BUNDLE_BYTES = 1 << 20;
const DASH = "— ";
const TOP = new Set([
  "trust_bundle",
  "serial",
  "issued_at",
  "expires_at",
  "trust_policy",
  "witness_network",
  "log_keys",
  "admission_policies",
]);
const PORTABLE = new Set(["pin", "require_receipt", "cert_identity", "cert_oidc_issuer", "require_sct", "key_lifecycle"]);
const PIN = /^sha256:[0-9a-f]{64}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface TrustBundle {
  owner: string;
  serial: number;
  issuedAt: string;
  expiresAt: string | null;
  /** Pinned Ed25519 signer fingerprints (`sha256:` + 64 hex), from the trust policy's `pin`. */
  pins: Set<string>;
  logKeys: string[];
  witnessNetwork: JObject | null;
  admissionPolicies: string[];
  /** `sha256:` + hex of the bundle bytes: a cache key. */
  digest: string;
}

function bad(message: string): never {
  throw new TineError(`trust bundle: ${message}`, "trust-bundle.invalid");
}

function keyId(name: string, publicKey: Uint8Array): Uint8Array {
  return createHash("sha256").update(Buffer.from(`${name}\n`, "utf8")).update(Uint8Array.of(1)).update(publicKey).digest().subarray(0, 4);
}

function base64(text: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) throw new Error("not base64");
  return Uint8Array.from(Buffer.from(text, "base64"));
}

/** A signed-note Ed25519 verifier key, `name+hash+base64(0x01 || key)`. */
export function parseVkey(vkey: string): [string, Uint8Array] {
  const parts = vkey.trim().split("+");
  let raw: Uint8Array;
  try {
    raw = base64(parts.slice(2).join("+"));
  } catch {
    bad("verifier key is not name+hash+key");
  }
  const [name, hint] = parts;
  if (parts.length < 3 || !name || raw.length !== 33 || raw[0] !== 1) bad("verifier key is not an Ed25519 signed-note key");
  if (Buffer.from(keyId(name, raw.subarray(1))).toString("hex") !== hint) bad("verifier key hash does not match");
  return [name, raw.subarray(1)];
}

function time(value: JValue | undefined, what: string): number {
  const parsed = typeof value === "string" && RFC3339.test(value) ? Date.parse(value) : NaN;
  if (Number.isNaN(parsed)) bad(`${what} must be an RFC 3339 time with an offset`);
  return parsed;
}

function strings(value: JValue | undefined, what: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) bad(`${what} must be a list of strings`);
  return value as string[];
}

function payloadOf(payload: JValue): JObject {
  if (!isObject(payload) || [...payload.keys()].some((key) => !TOP.has(key)) || payload.get("trust_bundle") !== 1n) {
    bad("not a trust bundle payload (trust_bundle: 1)");
  }
  const serial = payload.get("serial");
  if (!isInt(serial) || serial < 1n || serial >= 2n ** 53n) bad("serial must be a positive integer");
  const issued = time(payload.get("issued_at"), "issued_at");
  if (payload.has("expires_at") && time(payload.get("expires_at"), "expires_at") <= issued) bad("expires_at must be after issued_at");
  const policy = payload.get("trust_policy");
  if (!isObject(policy) || [...policy.keys()].some((key) => !PORTABLE.has(key))) {
    bad(`trust_policy may only hold ${[...PORTABLE].join(", ")}`);
  }
  if (strings(policy.get("pin"), "pin").some((pin) => !PIN.test(pin))) bad("pin must list sha256:<64 hex> fingerprints");
  for (const vkey of strings(payload.get("log_keys"), "log_keys")) parseVkey(vkey);
  const network = payload.get("witness_network");
  if (network !== undefined && (!isObject(network) || network.get("schema") !== "opentine-witness-network/1")) {
    bad("witness_network is not an opentine-witness-network/1 registry");
  }
  const admission = payload.get("admission_policies");
  if (admission !== undefined) {
    if (!isObject(admission)) bad("admission_policies must map names to policies");
    for (const doc of admission.values()) {
      if (!isObject(doc) || doc.get("kind") !== "opentine.admission-policy") bad("admission policy is not an opentine.admission-policy");
    }
  }
  return payload;
}

export interface OpenOptions {
  /** The current time (milliseconds); defaults to `Date.now()`. */
  now?: number;
  /** The highest serial this viewer accepted before: an older bundle is refused. */
  minSerial?: number;
}

/** The bundle in *note* if the pinned *ownerVkey* signed it and it is current. */
export function openTrustBundle(note: Uint8Array, ownerVkey: string, options: OpenOptions = {}): TrustBundle {
  const [name, publicKey] = parseVkey(ownerVkey);
  if (note.length > MAX_BUNDLE_BYTES) bad(`exceeds ${MAX_BUNDLE_BYTES} bytes`);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(note);
  } catch {
    bad("is not UTF-8");
  }
  const split = text.indexOf("\n\n");
  const body = split < 0 ? "" : text.slice(0, split);
  const lines = body.split("\n");
  if (split < 0 || lines.length !== 2) bad("is not a signed note over one JSON line");
  const [owner, json] = lines;
  if (owner !== name) bad(`names owner ${JSON.stringify(owner)}, not the pinned ${JSON.stringify(name)}`);
  let payload: JValue;
  try {
    payload = parseText(json, KERNEL);
  } catch {
    bad("is not a signed note over one JSON line");
  }
  if (canonicalText(payload) !== json) bad("payload is not canonical JSON");
  const message = Buffer.from(`${body}\n`, "utf8");
  const id = Buffer.from(keyId(name, publicKey)).toString("hex");
  let signed = false;
  for (const line of text.slice(split + 2).split("\n")) {
    if (!line.startsWith(DASH)) continue;
    const [who, sig] = line.slice(DASH.length).split(" ");
    if (who !== name || sig === undefined) continue;
    let raw: Uint8Array;
    try {
      raw = base64(sig);
    } catch {
      continue;
    }
    if (raw.length === 68 && Buffer.from(raw.subarray(0, 4)).toString("hex") === id && ed25519Verify(publicKey, raw.subarray(4), message)) {
      signed = true;
    }
  }
  if (!signed) bad("is not signed by the pinned owner key");
  const doc = payloadOf(payload);
  const serial = Number(doc.get("serial") as bigint);
  const expires = doc.get("expires_at");
  if (typeof expires === "string" && time(expires, "expires_at") <= (options.now ?? Date.now())) bad("has expired");
  if (serial < (options.minSerial ?? 0)) bad(`serial ${serial} is older than ${options.minSerial}`);
  const policy = doc.get("trust_policy") as JObject;
  const admission = doc.get("admission_policies");
  return {
    owner: name,
    serial,
    issuedAt: doc.get("issued_at") as string,
    expiresAt: typeof expires === "string" ? expires : null,
    pins: new Set(strings(policy.get("pin"), "pin")),
    logKeys: strings(doc.get("log_keys"), "log_keys"),
    witnessNetwork: (doc.get("witness_network") as JObject | undefined) ?? null,
    admissionPolicies: isObject(admission) ? [...admission.keys()].sort() : [],
    digest: `sha256:${createHash("sha256").update(note).digest("hex")}`,
  };
}

/** `sha256:` + hex of a raw Ed25519 public key: the fingerprint a bundle pins. */
export function keyFingerprint(hexKey: string): string {
  return `sha256:${createHash("sha256").update(Buffer.from(hexKey, "hex")).digest("hex")}`;
}
