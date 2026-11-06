/**
 * The conformance operations (docs/conformance/PROTOCOL.md) this package answers.
 *
 * Phase 1 implements the reader/verifier ops that `tine-sig/3` and `.tine` v4
 * rest on. Every other op answers `unsupported`, which the suite scores as
 * unimplemented, never as a failure.
 */

import { parseArtifactJson, topLevelKeys } from "./artifact.js";
import { canonicalJson, validateJsonShape } from "./canon.js";
import { hmacSha256Hex } from "./crypto.js";
import { ObjectEnvelope, objectId, parseOid } from "./envelope.js";
import { TineError } from "./errors.js";
import { containsLoneSurrogate, isObject, LENIENT, parseText, type JObject, type JValue } from "./json.js";
import {
  artifactMessage,
  attestMessage,
  verifyArtifactV4,
  verifyAttestation,
  type Header,
  type SignatureResult,
  type VerifyKeys,
} from "./signature.js";

export type OpInput = { bytes: Uint8Array } | { value: JValue };
export type Args = Record<string, unknown>;
export type Output = Record<string, unknown>;

/** The six published test keys of docs/conformance/keys.json, by name. */
export type KeyTable = Record<string, Uint8Array>;

export class Unsupported extends Error {}

// --------------------------------------------------------------------------- //
// The tagged value tree (PROTOCOL.md)
// --------------------------------------------------------------------------- //

/** Decode one tagged tree, as `JSON.parse` returned it, into the value model. */
export function decodeTagged(node: unknown): JValue {
  if (Array.isArray(node)) return node.map(decodeTagged);
  if (node === null || typeof node !== "object") {
    if (typeof node === "number") throw new TineError("a bare number in a tagged tree");
    return node as JValue;
  }
  const entries = Object.entries(node as Record<string, unknown>);
  if (entries.length === 1) {
    const [tag, payload] = entries[0];
    if (tag === "$i") return BigInt(payload as string);
    if (tag === "$f") {
      const special: Record<string, number> = { nan: NaN, inf: Infinity, "-inf": -Infinity };
      return (payload as string) in special ? special[payload as string] : Number(payload);
    }
    if (tag === "$u") return String.fromCharCode(...(payload as string[]).map((unit) => parseInt(unit, 16)));
    if (tag === "$obj") {
      const out: JObject = new Map();
      if (Array.isArray(payload)) {
        for (const [key, item] of payload as [unknown, unknown][]) out.set(decodeTagged(key) as string, decodeTagged(item));
      } else {
        for (const [key, item] of Object.entries(payload as Record<string, unknown>)) out.set(key, decodeTagged(item));
      }
      return out;
    }
  }
  return new Map(entries.map(([key, item]) => [key, decodeTagged(item)]));
}

// --------------------------------------------------------------------------- //
// The ops
// --------------------------------------------------------------------------- //

const b64 = (data: Uint8Array) => Buffer.from(data).toString("base64");

function bytesOf(input: OpInput): Uint8Array {
  if (!("bytes" in input)) throw new TineError("this op consumes bytes; the case supplied a value");
  return input.bytes;
}

function valueOf(input: OpInput): JValue {
  if (!("value" in input)) throw new TineError("this op consumes a value; the case supplied bytes");
  return input.value;
}

function textValidate(input: OpInput): Output {
  const raw = bytesOf(input);
  // CPython's json.loads(bytes): utf-8 (BOM dropped), surrogatepass, last-wins
  // duplicates, NaN/Infinity accepted; only the surrogate rule is under test.
  let text: string;
  const start = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf ? 3 : 0;
  for (let i = start; i + 1 < raw.length; i++) {
    if (raw[i] === 0xed && raw[i + 1] >= 0xa0 && raw[i + 1] <= 0xbf) {
      throw new TineError("conformance input holds an unpaired UTF-16 surrogate", "text.lone-surrogate");
    }
  }
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw.subarray(start));
  } catch {
    throw new TineError("input is not UTF-8", "malformed");
  }
  const parsed = parseText(text, LENIENT);
  if (containsLoneSurrogate(parsed)) {
    throw new TineError("conformance input holds an unpaired UTF-16 surrogate", "text.lone-surrogate");
  }
  return {};
}

function verdict(result: SignatureResult): Output {
  return { ...result };
}

function keysFrom(args: Args, table: KeyTable): VerifyKeys {
  const keys: VerifyKeys = {};
  if (args.key) {
    const key = table[args.key as string];
    if (!key) throw new TineError(`unknown test key ${String(args.key)}`);
    keys.hmacKey = key;
  }
  if (args.public_key) {
    const text = args.public_key as string;
    if (!/^([0-9a-fA-F]{2})*$/.test(text)) throw new TineError("non-hexadecimal number found in fromhex()");
    keys.publicKey = Uint8Array.from(Buffer.from(text, "hex"));
  }
  if (args.trust_embedded) keys.trustEmbedded = true;
  return keys;
}

const MESSAGES: Record<string, (document: JValue, header: Header) => Uint8Array> = {
  "tine-sig/3": artifactMessage,
  "tine-attest/2": attestMessage,
};

export function runOp(op: string, input: OpInput, args: Args, table: KeyTable): Output {
  switch (op) {
    case "text.validate":
      return textValidate(input);
    case "canon.v3":
      return { bytes_b64: b64(canonicalJson(valueOf(input))) };
    case "envelope.decode": {
      const envelope = ObjectEnvelope.decode(bytesOf(input), (args.expected_oid as string | undefined) ?? null);
      return {
        oid: envelope.oid,
        type: envelope.objectType,
        schema: Number(envelope.schema),
        encoding: envelope.encoding,
        body_b64: b64(envelope.body),
      };
    }
    case "envelope.encode": {
      const header = args.header as Record<string, unknown>;
      const payload = "bytes" in input ? input.bytes : input.value;
      const envelope = ObjectEnvelope.create(String(header.type), payload, BigInt((header.schema as number) ?? 1));
      return { bytes_b64: b64(envelope.encode()), oid: envelope.oid };
    }
    case "oid.derive": {
      const header = args.header as Record<string, unknown>;
      const schema = header.schema;
      const typed = typeof schema === "number" && Number.isInteger(schema) ? BigInt(schema) : schema;
      return { oid: objectId(String(header.type), typed, bytesOf(input)) };
    }
    case "oid.parse": {
      const [type, digest] = parseOid(valueOf(input));
      return { type, digest };
    }
    case "artifact.parse":
      return { top_level_keys: topLevelKeys(parseArtifactJson(bytesOf(input))) };
    case "sig.message": {
      const value = valueOf(input);
      const builder = MESSAGES[args.scheme as string];
      if (!builder) throw new Unsupported(`scheme ${String(args.scheme)}`);
      if (!isObject(value)) throw new TineError("sig.message input must be an object");
      const header = value.get("header");
      if (!isObject(header)) throw new TineError("header must be an object");
      const message = builder(value.get("document") as JValue, header);
      const out: Output = { message_b64: b64(message) };
      if (args.key) out.value = hmacSha256Hex(keysFrom({ key: args.key }, table).hmacKey as Uint8Array, message);
      return out;
    }
    case "sig.verify": {
      const document = "bytes" in input ? parseArtifactJson(input.bytes) : input.value;
      const keys = keysFrom(args, table);
      const family = (args.family as string | undefined) ?? "attestation";
      if (family === "artifact-v4" || family === "artifact-v5") {
        if (!isObject(document)) throw new TineError("'NoneType' object has no attribute 'get'");
        return verdict(verifyArtifactV4(document, keys));
      }
      if (family === "attestation") {
        const block = isObject(document) ? document.get("signature") : undefined;
        if (isObject(block) && block.get("scheme") === "tine-attest/1") {
          throw new Unsupported("tine-attest/1 (the legacy canonicalizer)");
        }
        return verdict(verifyAttestation(document, keys));
      }
      throw new Unsupported(`signature family ${family}`);
    }
    case "shape.scan":
      validateJsonShape(bytesOf(input), Number(args.max_tokens ?? 200_000));
      return {};
    default:
      throw new Unsupported(op);
  }
}

/** The ops `runOp` answers (some only for particular schemes or families). */
export const IMPLEMENTED_OPS = [
  "text.validate",
  "canon.v3",
  "shape.scan",
  "envelope.decode",
  "envelope.encode",
  "oid.derive",
  "oid.parse",
  "artifact.parse",
  "sig.message",
  "sig.verify",
] as const;
