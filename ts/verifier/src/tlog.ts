/**
 * SPEC 8.10-8.11 (0.44): RFC 9162 inclusion and consistency proofs over
 * SHA-256, and C2SP `cosignature/v1` witness quorums on signed-note
 * checkpoints. A port of `opentine/repository/_tlog_proof.py` and
 * `_tlog_cosign.py`; every op is a verdict and never throws on bad input.
 */

import { createHash } from "node:crypto";

import { ed25519Verify } from "./crypto.js";
import { isObject, type JObject, type JValue } from "./json.js";

export const MAX_PROOF_HASHES = 64;
const COSIGNATURE_TYPE = 0x04;
const DASH = "— ";
const MAX_NOTE_BYTES = 1 << 16;
const MAX_SIGNATURE_LINES = 100;

class LogError extends Error {}

function sha256(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

export function leafHash(entry: Uint8Array): Uint8Array {
  return sha256(Uint8Array.of(0), entry);
}

function node(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(Uint8Array.of(1), left, right);
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** Python's `base64.b64decode(text, validate=True)`. */
function b64(text: unknown): Uint8Array {
  if (typeof text !== "string" || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new LogError("not base64");
  }
  return Uint8Array.from(Buffer.from(text, "base64"));
}

function int(value: JValue | undefined): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new LogError("not a tree size or index");
  }
  return Number(value);
}

function decodeProof(proof: JValue | undefined): Uint8Array[] {
  if (!Array.isArray(proof) || proof.length > MAX_PROOF_HASHES) throw new LogError("proof is not a list");
  return checked(proof.map((item) => b64(item)));
}

function checked(proof: Uint8Array[]): Uint8Array[] {
  if (proof.length > MAX_PROOF_HASHES || proof.some((h) => h.length !== 32)) {
    throw new LogError("proof is not a list of SHA-256 hashes");
  }
  return proof;
}

/** RFC 9162 §2.1.3.2: the root a valid inclusion proof implies. */
export function rootFromInclusion(leaf: Uint8Array, index: number, size: number, proof: Uint8Array[]): Uint8Array {
  if (!(index >= 0 && index < size)) throw new LogError("inclusion proof index is out of range");
  let fn = BigInt(index);
  let sn = BigInt(size - 1);
  let r = leaf;
  for (const p of checked(proof)) {
    if (sn === 0n) throw new LogError("inclusion proof is too long");
    if (fn & 1n || fn === sn) {
      r = node(p, r);
      while (!(fn & 1n) && fn) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = node(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new LogError("inclusion proof is too short");
  return r;
}

/** RFC 9162 §2.1.4.2; throws `rollback`/`fork` errors as the reference does. */
export function verifyConsistency(
  old: number,
  size: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  input: Uint8Array[],
): void {
  let proof = checked(input);
  if (old > size) throw new LogError(`rollback: tree shrank from ${old} to ${size}`);
  if (old === size) {
    if (proof.length || !equal(oldRoot, newRoot)) throw new LogError("fork: two different roots for the same tree size");
    return;
  }
  if (old === 0) {
    if (proof.length) throw new LogError("consistency proof from the empty tree must be empty");
    return;
  }
  const o = BigInt(old);
  if ((o & (o - 1n)) === 0n) proof = [oldRoot, ...proof];
  if (!proof.length) throw new LogError("consistency proof is empty");
  let fn = o - 1n;
  let sn = BigInt(size - 1);
  while (fn & 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = proof[0];
  let sr = proof[0];
  for (const c of proof.slice(1)) {
    if (sn === 0n) throw new LogError("consistency proof is too long");
    if (fn & 1n || fn === sn) {
      fr = node(c, fr);
      sr = node(c, sr);
      while (!(fn & 1n) && fn) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = node(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n || !equal(fr, oldRoot) || !equal(sr, newRoot)) {
    throw new LogError("fork: the new checkpoint is not consistent with the old one");
  }
}

function keyId(name: string, publicKey: Uint8Array): Uint8Array {
  return sha256(Buffer.from(name + "\n", "utf8"), Uint8Array.of(COSIGNATURE_TYPE), publicKey).subarray(0, 4);
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function parseWitnessVkey(vkey: unknown): [string, Uint8Array] {
  if (typeof vkey !== "string") throw new LogError("witness key is not a string");
  const parts = vkey.trim().split("+");
  if (parts.length < 3) throw new LogError("witness key is not name+hash+key");
  const [name, hint] = parts;
  const raw = b64(parts.slice(2).join("+"));
  if (!name || /[ +\n]/.test(name) || raw.length !== 33) throw new LogError("witness key is malformed");
  if (raw[0] !== COSIGNATURE_TYPE || hex(keyId(name, raw.subarray(1))) !== hint) {
    throw new LogError("witness key is not an Ed25519 cosignature/v1 key");
  }
  return [name, raw.subarray(1)];
}

function splitNote(note: Uint8Array): [string, string[]] {
  if (note.length > MAX_NOTE_BYTES) throw new LogError("checkpoint note is too large");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(note);
  } catch {
    throw new LogError("checkpoint note is not UTF-8");
  }
  const at = text.indexOf("\n\n");
  if (at < 0) throw new LogError("checkpoint is not a signed note");
  const lines = text.slice(at + 2).split("\n").filter((line) => line);
  if (lines.length > MAX_SIGNATURE_LINES) throw new LogError("checkpoint carries too many signatures");
  return [text.slice(0, at) + "\n", lines];
}

/** `{witness name: timestamp}` of every pinned witness whose cosignature verifies. */
export function cosigners(note: Uint8Array, vkeys: unknown[]): Map<string, bigint> {
  const [body, lines] = splitNote(note);
  const keys = new Map<string, Uint8Array>();
  for (const vkey of vkeys) {
    const [name, publicKey] = parseWitnessVkey(vkey);
    keys.set(`${name} ${hex(keyId(name, publicKey))}`, publicKey);
  }
  const found = new Map<string, bigint>();
  for (const line of lines) {
    if (!line.startsWith(DASH)) continue;
    const rest = line.slice(DASH.length);
    const space = rest.indexOf(" ");
    const name = space < 0 ? rest : rest.slice(0, space);
    let raw: Uint8Array;
    try {
      raw = b64(space < 0 ? "" : rest.slice(space + 1));
    } catch {
      continue;
    }
    const publicKey = keys.get(`${name} ${hex(raw.subarray(0, 4))}`);
    if (publicKey === undefined || raw.length !== 76) continue;
    const stamp = Buffer.from(raw.subarray(4, 12)).readBigUInt64BE();
    const message = Buffer.from(`cosignature/v1\ntime ${stamp}\n${body}`, "utf8");
    if (!ed25519Verify(publicKey, raw.subarray(12), message)) continue;
    found.set(name, stamp);
  }
  return found;
}

function fields(value: JValue): JObject {
  if (!isObject(value)) throw new LogError("input is not an object");
  return value;
}

export function tlogInclusion(value: JValue): Record<string, unknown> {
  try {
    const v = fields(value);
    const leaf = leafHash(b64(v.get("entry_b64")));
    const root = b64(v.get("root_b64"));
    const proof = decodeProof(v.get("path"));
    const implied = rootFromInclusion(leaf, int(v.get("index")), int(v.get("size")), proof);
    return { ok: equal(implied, root) };
  } catch {
    return { ok: false };
  }
}

export function tlogConsistency(value: JValue): Record<string, unknown> {
  try {
    const v = fields(value);
    const oldRoot = b64(v.get("old_root_b64"));
    const newRoot = b64(v.get("new_root_b64"));
    const proof = decodeProof(v.get("proof"));
    verifyConsistency(int(v.get("old_size")), int(v.get("new_size")), oldRoot, newRoot, proof);
  } catch (exc) {
    const text = String((exc as Error).message);
    return { ok: false, class: text.includes("rollback") ? "rollback" : text.includes("fork") ? "fork" : "invalid" };
  }
  return { ok: true, class: "consistent" };
}

export function tlogQuorum(value: JValue): Record<string, unknown> {
  let found: Map<string, bigint>;
  let witnesses: JValue[];
  let v: JObject;
  try {
    v = fields(value);
    const checkpoint = v.get("checkpoint");
    const listed = v.get("witnesses");
    if (typeof checkpoint !== "string" || !Array.isArray(listed)) throw new LogError("bad quorum input");
    witnesses = listed;
    found = cosigners(Buffer.from(checkpoint, "utf8"), witnesses);
  } catch {
    return { ok: false, cosigners: [] };
  }
  const need = v.get("need");
  const total = v.get("total");
  const ok =
    typeof need === "bigint" && typeof total === "bigint" && BigInt(witnesses.length) === total && BigInt(found.size) >= need;
  return { ok, cosigners: [...found.keys()].sort() };
}
