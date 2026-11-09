/**
 * SPEC 4.26 OMS model signatures (0.48): an OpenSSF Model Signing v1.0
 * Sigstore bundle (DSSE envelope, in-toto Statement v1, `files`
 * serialization) verified with a pinned P-256 key, then its manifest against
 * the model's `{name: sha256 hex}`. A port of `opentine._oms.check`; refusals
 * carry `oms.*` codes. ECDSA P-256 from the audited `@noble/curves` (DER
 * signatures, high-S accepted as OpenSSL does), so Node and the browser agree.
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import type { JValue } from "./json.js";

const TYPE = "application/vnd.in-toto+json";
const STATEMENT = "https://in-toto.io/Statement/v1";
const PREDICATE = "https://model_signing/signature/v1.0";
export const OMS_LABEL = "model signature verified (OMS v1.0, pinned key)";
const HEX64 = /^[0-9a-f]{64}$/;

type Plain = null | boolean | number | string | Plain[] | { [key: string]: Plain };

function no(code: string, message: string): never {
  throw new TineError(message, `oms.${code}`);
}

/** A tagged-decoded value as plain JSON (Maps to objects, bigints to numbers). */
function plain(value: JValue | undefined): Plain {
  if (value === undefined || value === null) return null;
  if (value instanceof Map) {
    const out: { [key: string]: Plain } = {};
    for (const [key, item] of value) out[key] = plain(item as JValue);
    return out;
  }
  if (Array.isArray(value)) return value.map((item) => plain(item as JValue));
  if (typeof value === "bigint") return Number(value);
  return value as Plain;
}

function isRecord(value: unknown): value is { [key: string]: Plain } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unbase64(value: unknown, what: string): Uint8Array {
  if (typeof value !== "string" || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    no("malformed", `OMS bundle is malformed: ${what} is not base64`);
  }
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function pae(body: Uint8Array): Uint8Array {
  const text = new TextEncoder();
  return concat(text.encode(`DSSEv1 ${TYPE.length} ${TYPE} ${body.length} `), body);
}

function p256Verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return p256.verify(signature, message, key, { format: "der", lowS: false, prehash: true });
  } catch {
    return false;
  }
}

function resources(predicate: { [key: string]: Plain }): [string, string][] {
  const listed = Array.isArray(predicate.resources) ? predicate.resources : [null];
  const rows: [string, string][] = [];
  const seen = new Set<string>();
  for (const item of listed) {
    if (!isRecord(item) || item.algorithm !== "sha256" || typeof item.name !== "string" || !item.name) {
      no("malformed", "OMS payload is malformed: bad resource");
    }
    if (typeof item.digest !== "string" || !HEX64.test(item.digest)) no("malformed", "OMS payload is malformed: bad resource");
    if (seen.has(item.name)) no("malformed", `OMS payload is malformed: duplicate resource ${item.name}`);
    seen.add(item.name);
    rows.push([item.name, item.digest]);
  }
  return rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function statementOf(body: Uint8Array): { [key: string]: Plain } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    no("malformed", "OMS payload is malformed: not JSON");
  }
  if (!isRecord(parsed) || parsed._type !== STATEMENT) no("malformed", "OMS payload is malformed: not an in-toto Statement v1");
  return parsed;
}

export function verifyOms(bundleValue: JValue, filesValue: JValue | null, keyHex: JValue | null): Record<string, unknown> {
  const bundle = plain(bundleValue);
  const env = isRecord(bundle) ? bundle.dsseEnvelope : null;
  if (!isRecord(env)) no("malformed", "OMS bundle is malformed: no dsseEnvelope");
  const signatures = env.signatures;
  if (!Array.isArray(signatures) || signatures.length === 0) no("malformed", "OMS bundle is malformed: no signatures");
  if (signatures.length > 16) no("malformed", "OMS bundle is malformed: more than 16 signatures");
  if (env.payloadType !== TYPE) no("unsupported", "OMS bundle payloadType is not in-toto JSON");
  const body = unbase64(env.payload, "payload");
  const material = (bundle as { [key: string]: Plain }).verificationMaterial;
  if (isRecord(material) && ("certificate" in material || "x509CertificateChain" in material)) {
    no("unsupported", "keyless OMS bundles (Fulcio certificate) are not verified here");
  }
  if (typeof keyHex !== "string") no("no-key", "no public key given for the OMS bundle");
  const key = Uint8Array.from(Buffer.from(keyHex, "hex"));
  const sigs = signatures.map((entry) => unbase64(isRecord(entry) ? entry.sig : null, "signature"));
  const message = pae(body);
  if (!sigs.some((sig) => p256Verify(key, message, sig))) {
    no("bad-signature", "OMS bundle signature does not verify with the given key");
  }
  const statement = statementOf(body);
  if (statement.predicateType !== PREDICATE) no("unsupported", "OMS predicateType is not model_signing v1.0");
  const subjects = statement.subject;
  const predicate = statement.predicate;
  if (!Array.isArray(subjects) || subjects.length !== 1 || !isRecord(predicate)) {
    no("malformed", "OMS payload is malformed: one subject and a predicate");
  }
  const subject = isRecord(subjects[0]) ? subjects[0] : {};
  const root = isRecord(subject.digest) ? subject.digest.sha256 : null;
  if (typeof subject.name !== "string" || typeof root !== "string" || !HEX64.test(root)) {
    no("malformed", "OMS payload is malformed: bad subject");
  }
  const serialization = predicate.serialization;
  if (!isRecord(serialization) || serialization.method !== "files") no("unsupported", "OMS serialization is not the 'files' method");
  if ((serialization.hash_type ?? "sha256") !== "sha256") no("unsupported", "OMS hash_type is not sha256");
  const ignored = serialization.ignore_paths ?? [];
  if (!Array.isArray(ignored) || ignored.some((path) => typeof path !== "string")) {
    no("malformed", "OMS payload is malformed: bad ignore_paths");
  }
  const rows = resources(predicate);
  const computed = sha256Hex(concat(...rows.map(([, digest]) => Uint8Array.from(Buffer.from(digest, "hex")))));
  if (computed !== root) no("root-mismatch", "OMS subject digest is not the digest of its resources");
  const files = plain(filesValue ?? null);
  if (isRecord(files)) {
    const tops = (ignored as string[]).map((path) => path.replace(/^\/+|\/+$/g, ""));
    const have = new Map<string, Plain>();
    for (const [name, digest] of Object.entries(files)) {
      if (!tops.some((top) => name === top || name.startsWith(`${top}/`))) have.set(name, digest);
    }
    for (const [name, digest] of rows) {
      if (!have.has(name)) no("missing-file", `model file is missing: ${name}`);
      if (have.get(name) !== digest) no("digest-mismatch", `model file does not match its signed digest: ${name}`);
    }
    const signed = new Set(rows.map(([name]) => name));
    const extra = [...have.keys()].filter((name) => !signed.has(name)).sort();
    if (extra.length > 0) no("extra-file", `model file is not covered by the signature: ${extra[0]}`);
  }
  return {
    model: subject.name,
    root_digest: `sha256:${root}`,
    files: rows.length,
    key: `sha256:${sha256Hex(key)}`,
    state: "verified",
    label: OMS_LABEL,
  };
}
