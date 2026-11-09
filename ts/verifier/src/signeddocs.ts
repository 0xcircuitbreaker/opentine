/**
 * The six pre-cutoff document kinds that had no vectors until 0.50 (families 79-84).
 *
 * `tine-verify-report/2` (SPEC 8.7), exported `tine-custody/1` records (8.4), the
 * DSSE-signed in-toto `replay/v1` statement (8.8), the `TINEAES6` header (Part 11,
 * no decryption), `opentine-line-attribution/1` (8.24) and `tine-cost-statement/1`
 * (8.25). Ports of `_verify_report_sign.check`, `_custody.check_records`,
 * `_intoto_replay.verify_envelope`, `remote._sealed6.parse_header`,
 * `_line_attrib.verify_lines` and `_cost_export.verify_against`. The signed
 * documents carry an Ed25519 `tine-sig/3` block over `<domain>` + JCS({body,
 * header}); with no key the embedded one is trusted (TOFU).
 */

import { createHash } from "node:crypto";
import { canonicalJson } from "./canon.js";
import { ed25519Verify, sha256Hex, weakPublicKey } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, LENIENT, parseText, pyEqual, type JObject, type JValue } from "./json.js";
import { HEADER_KEYS, verifyBlock, type Header, type SignatureResult } from "./signature.js";

type Plain = null | boolean | number | string | Plain[] | { [key: string]: Plain };

const encoder = new TextEncoder();
const CUSTODY = "opentine-custody/1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const REPLAY = "https://opentine.dev/attestation/replay/v1";

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

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function hex(text: string): Uint8Array {
  return Uint8Array.from(Buffer.from(text, "hex"));
}

function keyOf(value: JObject): Uint8Array | null {
  const key = value.get("public_key");
  return typeof key === "string" && key ? hex(key) : null;
}

function without(doc: JObject, ...names: string[]): JObject {
  return new Map([...doc].filter(([key]) => !names.includes(key)));
}

/** `_signed_doc.verify`: Ed25519 `tine-sig/3`; no key trusts the embedded one. */
function signedDoc(domain: string, body: JObject, block: JValue | undefined, publicKey: Uint8Array | null): SignatureResult {
  if (isObject(block) && block.get("alg") !== "ed25519") {
    return { ok: false, state: "error", algorithm: null, key_id: null, signer: null, signed_at: null, reason: "Ed25519 only" };
  }
  const message = (header: Header) => {
    const view: JObject = new Map<string, JValue>([
      ["body", body],
      ["header", new Map(HEADER_KEYS.map((key) => [key, header.get(key) ?? null]))],
    ]);
    return concat(encoder.encode(domain), canonicalJson(view));
  };
  const keys = publicKey ? { publicKey } : { trustEmbedded: true };
  return verifyBlock(block, message, ["tine-sig/3"], "document", keys);
}

function basis(block: JValue | undefined, publicKey: Uint8Array | null): string {
  const raw = isObject(block) ? block.get("public_key") : undefined;
  const found = typeof raw === "string" && /^([0-9a-fA-F]{2})*$/.test(raw) ? "sha256:" + sha256Hex(hex(raw)) : "?";
  return publicKey ? `supplied key ${found}` : `embedded key ${found} (trust on first use)`;
}

const bound = (block: JValue) => "sig:sha256:" + sha256Hex(canonicalJson(block));

export function verifyReport(value: JObject): Record<string, unknown> {
  const doc = value.get("report") as JObject;
  const key = keyOf(value);
  const result: Record<string, unknown> = {
    schema: plain(doc.get("schema")), report_verdict: plain(doc.get("verdict")), path: plain(doc.get("path")),
    signed: doc.has("signature"), signature: null, timestamps: [], signing_time: null,
  };
  if (doc.get("schema") === "tine-verify-report/1" || !doc.has("signature")) {
    return { ...result, evidence: false, ok: false, reason: "report.unsigned" };
  }
  const stamps = doc.get("signature_timestamps");
  if (Array.isArray(stamps) && stamps.length) throw new TineError("RFC 3161 tokens are not checked here", "verify-report.timestamps-unsupported");
  const block = doc.get("signature") as JValue;
  const verdict = signedDoc("opentine.verify-report.v2:", without(doc, "signature", "signature_timestamps"), block, key);
  result.signature = {
    ok: verdict.ok, state: verdict.state, reason: verdict.reason, signer: verdict.signer, signed_at: verdict.signed_at,
    trust_basis: basis(block, key),
  };
  return { ...result, evidence: verdict.ok, ok: verdict.ok, reason: verdict.ok ? "report.verified" : "report.signature-invalid" };
}

export function custodyChain(value: JObject): Record<string, unknown> {
  const records = value.get("records");
  const key = keyOf(value);
  if (!Array.isArray(records)) throw new TineError("custody records must be a list", "custody.malformed");
  const out: Record<string, unknown>[] = [];
  let prev: string | null = null;
  records.forEach((rec, index) => {
    if (!isObject(rec) || rec.get("format") !== CUSTODY) {
      throw new TineError(`custody record ${index} is not an ${CUSTODY} record`, "custody.malformed");
    }
    if ((rec.get("prev") ?? null) !== prev) throw new TineError(`custody record ${index} breaks the hash chain`, "custody.chain-broken");
    const verdict = signedDoc("opentine.custody.v1:", without(rec, "signature"), rec.get("signature"), key);
    if (!verdict.ok) throw new TineError(`custody record ${index}: signature ${verdict.reason}`, "custody.bad-signature");
    prev = sha256Hex(concat(new Uint8Array([0]), canonicalJson(rec)));
    out.push({
      index, action: plain(rec.get("action")), subject: plain(rec.get("subject")), signer: verdict.signer,
      state: verdict.state, sig_bound: bound(rec.get("signature") as JValue),
    });
  });
  return { size: out.length, records: out, head: prev };
}

/** `_evidence_export.verify_custody`: an evidence folder's `tine-custody/1` record under its own key. */
export function custodyRecord(value: JObject): Record<string, unknown> {
  const record = value.get("record") as JObject;
  const block = record.get("signature");
  let valid = false;
  if (isObject(block)) {
    const key = block.get("public_key");
    const sig = block.get("value");
    const isHex = (text: unknown): text is string => typeof text === "string" && /^([0-9a-fA-F]{2})*$/.test(text);
    if (isHex(key) && isHex(sig)) {
      const message = concat(encoder.encode("opentine.custody.v1:"), canonicalJson(without(record, "signature")));
      valid = hex(key).length === 32 && ed25519Verify(hex(key), hex(sig), message);
    }
  }
  return {
    schema: plain(record.get("schema")), manifest_sha256: plain(record.get("manifest_sha256")), signed: isObject(block), valid,
  };
}

function predicateErrors(predicate: JValue | undefined): string[] {
  if (!isObject(predicate)) return ["predicate is not an object"];
  const errors: string[] = [];
  if (!["cache", "rerun"].includes(predicate.get("mode") as string)) errors.push("mode must be cache or rerun");
  const replay = predicate.get("replay");
  const result = predicate.get("result");
  if (!isObject(replay) || typeof replay.get("replay_id") !== "string") errors.push("replay.replay_id must be a string");
  if (!isObject(result)) return [...errors, "result must be an object"];
  for (const name of ["reproduced", "identity_ok", "integrity_ok", "ignore_cost_drift"]) {
    if (typeof result.get(name) !== "boolean") errors.push(`result.${name} must be a boolean`);
  }
  if (![true, false, null, undefined].includes(result.get("slice_ok") as never)) errors.push("result.slice_ok must be a boolean or null");
  for (const name of ["structural_drift", "accounting_drift"]) {
    const found = result.get(name);
    if (!Array.isArray(found) || !found.every((item) => typeof item === "string")) errors.push(`result.${name} must be a list of strings`);
  }
  for (const name of ["fidelity", "verifier"]) if (!isObject(predicate.get(name))) errors.push(`${name} must be an object`);
  if (typeof predicate.get("verified_at") !== "string") errors.push("verified_at must be a string");
  return errors;
}

function strictB64(text: JValue | undefined): Uint8Array {
  if (typeof text !== "string" || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new TineError("malformed DSSE envelope", "replay.malformed");
  }
  return Uint8Array.from(Buffer.from(text, "base64"));
}

export function replayVerify(value: JObject): Record<string, unknown> {
  const envelope = value.get("envelope");
  const key = keyOf(value);
  if (!key || key.length !== 32 || weakPublicKey(key)) throw new TineError("the pinned key is not a usable Ed25519 key", "replay.malformed");
  if (!isObject(envelope) || envelope.get("payloadType") !== PAYLOAD_TYPE) {
    throw new TineError(`payloadType must be ${PAYLOAD_TYPE}`, "replay.malformed");
  }
  const body = strictB64(envelope.get("payload"));
  const listed = envelope.get("signatures");
  if (!Array.isArray(listed)) throw new TineError("malformed DSSE envelope", "replay.malformed");
  const sigs = listed.map((entry) => strictB64(isObject(entry) ? entry.get("sig") : undefined));
  const signed = concat(encoder.encode(`DSSEv1 ${PAYLOAD_TYPE.length} ${PAYLOAD_TYPE} ${body.length} `), body);
  if (!sigs.some((sig) => ed25519Verify(key, sig, signed))) throw new TineError("no signature verifies over the payload", "replay.bad-signature");
  const statement = parseText(new TextDecoder("utf-8").decode(body), LENIENT);
  if (!isObject(statement) || statement.get("predicateType") !== REPLAY) throw new TineError(`predicateType is not ${REPLAY}`, "replay.malformed");
  const errors = predicateErrors(statement.get("predicate"));
  if (errors.length) throw new TineError(errors.join("; "), "replay.malformed");
  return plain(statement) as Record<string, unknown>;
}

export function sealed6Header(raw: Uint8Array): Record<string, unknown> {
  const magic = encoder.encode("TINEAES6");
  const bad = () => new TineError("invalid encrypted object header", "sealed6.malformed");
  if (raw.length < magic.length + 1 || !magic.every((byte, index) => raw[index] === byte)) throw bad();
  const at = magic.length + 1;
  const end = at + raw[magic.length];
  if (end + 14 + 24 + 16 > raw.length || end === at) throw bad();
  const id = raw.subarray(at, end);
  if (id.some((byte) => byte > 0x7f)) throw new TineError("the key id is not ASCII", "sealed6.malformed");
  const flags = raw[end + 4];
  if (flags & ~0x01) throw new TineError("encrypted object has unknown flags", "sealed6.malformed");
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  return {
    key_id: Buffer.from(id).toString("ascii"), epoch: view.getUint32(end), flags, codec: raw[end + 5],
    size: Number(view.getBigUint64(end + 6)), header_length: end + 14,
  };
}

function linesHash(lines: string[]): string {
  return "sha256:" + createHash("sha256").update(Buffer.from(lines.join("\n"), "utf8")).digest("hex");
}

export function lineAttribution(value: JObject): Record<string, unknown> {
  const record = value.get("record") as JObject;
  const key = keyOf(value);
  const added = new Map<string, Map<number, string>>();
  for (const [path, rows] of value.get("added") as JObject) {
    added.set(path, new Map([...(rows as JObject)].map(([n, text]) => [Number(n), text as string])));
  }
  const stale: string[] = [];
  const files = record.get("files");
  for (const entry of Array.isArray(files) ? files : []) {
    const item = entry as JObject;
    const lines = added.get(item.get("path") as string) ?? new Map<number, string>();
    const ranges = item.get("ranges");
    for (const range of Array.isArray(ranges) ? ranges : []) {
      const span = range as JObject;
      const start = Number(span.get("start_line"));
      const stop = Number(span.get("end_line"));
      const numbers = Array.from({ length: Math.max(0, stop - start + 1) }, (_, offset) => start + offset);
      if (numbers.some((n) => !lines.has(n)) || linesHash(numbers.map((n) => lines.get(n) as string)) !== span.get("content_hash")) {
        stale.push(`${String(item.get("path"))}:${start}-${stop}`);
      }
    }
  }
  const block = record.get("signature");
  const signature: Record<string, unknown> = { present: isObject(block) };
  if (isObject(block)) {
    const verdict = signedDoc("opentine.line-attribution.v1:", without(record, "signature"), block, key);
    Object.assign(signature, { valid: verdict.ok, state: verdict.state, basis: basis(block, key) });
  }
  return { signature, content_matches: stale.length === 0, stale_ranges: stale };
}

export function costStatement(value: JObject): Record<string, unknown> {
  const doc = value.get("statement") as JObject;
  const key = keyOf(value);
  const body = without(doc, "signature");
  const matches = pyEqual(body, value.get("expected"));
  const block = doc.get("signature");
  if (!isObject(block)) return { ok: false, matches_run: matches, signature: "unsigned", basis: null };
  const verdict = signedDoc("opentine.cost-statement.v1:", body, block, key);
  return {
    ok: matches && verdict.ok, matches_run: matches, signature: verdict.ok ? "verified" : verdict.state,
    basis: verdict.ok ? basis(block, key) : null,
  };
}
