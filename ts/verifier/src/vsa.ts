/**
 * SPEC 8.14 (0.46): a remote's DSSE-signed SLSA Verification Summary
 * Attestation for one pushed object. A port of `opentine/_vsa_verify.py`:
 * the same checks, answered in the same order. A verdict: never throws.
 */

import { ed25519Verify } from "./crypto.js";
import { isObject, type JValue } from "./json.js";

const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const VSA_TYPE = "https://slsa.dev/verification_summary/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const MAX_ENVELOPE_BYTES = 1 << 20;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const HEX64 = /^[0-9a-f]{64}$/;

function b64(text: JValue | undefined): Uint8Array {
  if (typeof text !== "string" || text.length % 4 !== 0 || !B64.test(text)) throw new Error("not base64");
  return Uint8Array.from(Buffer.from(text, "base64"));
}

function pae(body: Uint8Array): Uint8Array {
  const kind = Buffer.from(PAYLOAD_TYPE, "utf8");
  const head = Buffer.from(`DSSEv1 ${kind.length} ${PAYLOAD_TYPE} ${body.length} `, "utf8");
  return Uint8Array.from(Buffer.concat([head, body]));
}

type Rec = Record<string, unknown>;
const isRec = (v: unknown): v is Rec => typeof v === "object" && v !== null && !Array.isArray(v);

function statementOf(body: Uint8Array): Rec | null {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return null;
  }
  if (!isRec(value) || value._type !== STATEMENT_TYPE || value.predicateType !== VSA_TYPE) return null;
  const subject = value.subject;
  const predicate = value.predicate;
  if (!isRec(predicate) || !Array.isArray(subject) || subject.length !== 1 || !isRec(subject[0])) return null;
  const digest = subject[0].digest;
  if (!isRec(digest) || typeof digest.sha256 !== "string" || !HEX64.test(digest.sha256)) return null;
  const levels = predicate.verifiedLevels;
  if (!Array.isArray(levels) || !levels.every((x) => typeof x === "string")) return null;
  const policy = predicate.policy;
  if (!isRec(policy) || typeof policy.uri !== "string") return null;
  if (predicate.resourceUri !== undefined && typeof predicate.resourceUri !== "string") return null;
  return value;
}

export function vsaClass(envelope: JValue | undefined, key: Uint8Array, subject: string, levels: string[], policy: string, resource = ""): string {
  let body: Uint8Array;
  const sigs: Uint8Array[] = [];
  try {
    if (!isObject(envelope) || envelope.get("payloadType") !== PAYLOAD_TYPE) return "malformed";
    body = b64(envelope.get("payload"));
    const signatures = envelope.get("signatures");
    if (!Array.isArray(signatures) || signatures.length === 0 || body.length > MAX_ENVELOPE_BYTES) return "malformed";
    for (const entry of signatures) {
      if (!isObject(entry) || [...entry.keys()].some((k) => k !== "keyid" && k !== "sig")) return "malformed";
      sigs.push(b64(entry.get("sig")));
    }
  } catch {
    return "malformed";
  }
  const message = pae(body);
  if (key.length !== 32 || !sigs.some((s) => s.length === 64 && ed25519Verify(key, s, message))) {
    return "bad-signature";
  }
  const statement = statementOf(body);
  if (statement === null) return "malformed";
  const predicate = statement.predicate as Rec;
  const digest = ((statement.subject as Rec[])[0].digest as Rec).sha256;
  const parts = subject.split(":");
  if (digest !== parts[parts.length - 1]) return "wrong-subject";
  if (resource !== "" && predicate.resourceUri !== resource) return "wrong-resource";
  if (predicate.verificationResult !== "PASSED") return "failed";
  if (policy !== "" && (predicate.policy as Rec).uri !== policy) return "wrong-policy";
  const have = new Set(predicate.verifiedLevels as string[]);
  if (!levels.every((level) => have.has(level))) return "missing-level";
  return "valid";
}

export function vsaVerify(value: JValue): Record<string, unknown> {
  let kind = "malformed";
  try {
    if (!isObject(value)) throw new Error("not an object");
    const key = value.get("key");
    const subject = value.get("subject");
    const levels = value.get("levels");
    const policy = value.get("policy");
    const resource = value.has("resource") ? value.get("resource") : "";
    if (typeof key !== "string" || typeof subject !== "string" || typeof policy !== "string" || typeof resource !== "string") {
      throw new Error("bad vsa input");
    }
    if (!Array.isArray(levels) || !levels.every((x) => typeof x === "string")) throw new Error("bad levels");
    const raw = Uint8Array.from(Buffer.from(key, "base64url"));
    kind = vsaClass(value.get("envelope"), raw, subject, levels as string[], policy, resource);
  } catch {
    kind = "malformed";
  }
  return { ok: kind === "valid", class: kind };
}
