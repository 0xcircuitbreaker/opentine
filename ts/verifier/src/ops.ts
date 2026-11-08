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
import { actionsChain, agentRef, validateAgent } from "./agent.js";
import { canonicalBytesV2 } from "./canon2.js";
import { verifyDelegation } from "./delegation.js";
import { verifyEvalVerdict } from "./evalverdict.js";
import { verifyRedactionReport } from "./redactreport.js";
import { tlogConsistency, tlogInclusion, tlogQuorum } from "./tlog.js";
import { webhookVerify } from "./webhook.js";
import { integrityDigest, verifyIntegrity } from "./integrity.js";
import { readLocalPack } from "./localpack.js";
import { checkInstall, inspectPack, packManifest, strictBase64 } from "./pack.js";
import {
  extractLinks,
  loadObject,
  memRepo,
  validateAnnotationChain,
  validateEventMetrics,
  validateRunGraph,
  type RepoArgs,
} from "./graph.js";
import {
  encodeShallow,
  normalizeRef,
  objectPath,
  parseShallow,
  readRefFile,
  reflogRow,
  validateConfig,
  validateRefTarget,
} from "./repo.js";
import { containsLoneSurrogate, isObject, LENIENT, parseText, type JObject, type JValue } from "./json.js";
import {
  actionsMessage,
  artifactMessage,
  attestationMessage,
  attestMessage,
  legacyArtifactMessage,
  verifyLegacyArtifact,
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

/** `args.objects`, base64 stored envelopes, as an oid -> bytes map. */
export function storedObjects(args: Args): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const encoded of (args.objects as string[] | undefined) ?? []) {
    const raw = Uint8Array.from(Buffer.from(encoded, "base64"));
    out.set(ObjectEnvelope.decode(raw).oid, raw);
  }
  return out;
}

function repoArgs(args: Args): RepoArgs {
  return {
    objects: storedObjects(args),
    present: (args.present as string[] | undefined) ?? [],
    shallow: (args.shallow as string[] | undefined) ?? [],
    checkExistence: ["present", "objects", "shallow"].some((key) => key in args),
  };
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
  "tine-sig/1": legacyArtifactMessage,
  "tine-sig/2": legacyArtifactMessage,
  "tine-attest/1": attestationMessage,
  "tine-actions/1": actionsMessage,
  "tine-sig/3": artifactMessage,
  "tine-attest/2": attestMessage,
};

export function runOp(op: string, input: OpInput, args: Args, table: KeyTable): Output {
  switch (op) {
    case "text.validate":
      return textValidate(input);
    case "tlog.inclusion":
      return tlogInclusion(valueOf(input));
    case "tlog.consistency":
      return tlogConsistency(valueOf(input));
    case "tlog.quorum":
      return tlogQuorum(valueOf(input));
    case "webhook.verify":
      return webhookVerify(valueOf(input));
    case "delegation.verify": {
      const value = valueOf(input) as JObject;
      const actions = value.get("actions");
      return verifyDelegation({
        chain: value.get("chain") as JValue,
        signer: value.get("signer") as string,
        at: value.get("at") as JValue,
        agent: value.get("agent"),
        actions: Array.isArray(actions) ? (actions as string[]) : [],
      });
    }
    case "eval-verdict.verify": {
      const value = valueOf(input) as JObject;
      const key = value.get("public_key");
      const trusted = typeof key === "string" ? Uint8Array.from(Buffer.from(key, "hex")) : undefined;
      const found = verifyEvalVerdict(value.get("verdict") as JValue, trusted);
      return { item: found.item, passed: found.passed, signer: found.signer };
    }
    case "redaction-report.verify": {
      const value = valueOf(input) as JObject;
      const hexKey = (name: string) => {
        const key = value.get(name);
        return typeof key === "string" ? Uint8Array.from(Buffer.from(key, "hex")) : undefined;
      };
      const found = verifyRedactionReport(value.get("report") as JValue, hexKey("hmac_key_hex"), hexKey("public_key"));
      return { ...found };
    }
    case "actions.chain": {
      const value = valueOf(input) as JObject;
      return { chain: actionsChain(value.get("run_id") as string, value.get("digests") as string[]) };
    }
    case "agent.ref": {
      const { ref, hashed } = agentRef(validateAgent(valueOf(input)));
      return { ref, hashed_b64: b64(hashed) };
    }
    case "integrity.digest": {
      const data = parseArtifactJson(bytesOf(input));
      if (!isObject(data)) throw new TineError("'list' object has no attribute 'items'");
      return { digest: integrityDigest(data) };
    }
    case "integrity.verify":
      return { ...verifyIntegrity(parseArtifactJson(bytesOf(input))) };
    case "canon.v2":
      return { bytes_b64: b64(canonicalBytesV2(valueOf(input))) };
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
      if (family === "attestation") return verdict(verifyAttestation(document, keys));
      if (family === "artifact") return verdict(verifyLegacyArtifact(document, keys));
      throw new Unsupported(`signature family ${family}`);
    }
    case "shape.scan":
      validateJsonShape(bytesOf(input), Number(args.max_tokens ?? 200_000));
      return {};
    case "config.validate":
      validateConfig(bytesOf(input));
      return {};
    case "object.path":
      return { path: objectPath(valueOf(input)) };
    case "ref.name":
      return { name: normalizeRef(valueOf(input)) };
    case "ref.file":
      return { oid: readRefFile(bytesOf(input)) };
    case "ref.target":
      validateRefTarget(args.name as string, valueOf(input), storedObjects(args));
      return {};
    case "reflog.row":
      return { bytes_b64: b64(reflogRow(valueOf(input))) };
    case "shallow.parse":
      return { oids: parseShallow(bytesOf(input)) };
    case "shallow.encode":
      return { bytes_b64: b64(encodeShallow(valueOf(input))) };
    case "links.extract":
      return { links: extractLinks(bytesOf(input), repoArgs(args)) };
    case "event.metrics":
      validateEventMetrics(ObjectEnvelope.decode(bytesOf(input)));
      return {};
    case "run.graph":
      validateRunGraph(memRepo(repoArgs(args)), ObjectEnvelope.decode(bytesOf(input)));
      return {};
    case "annotation.chain":
      validateAnnotationChain(memRepo(repoArgs(args)), ObjectEnvelope.decode(bytesOf(input)));
      return {};
    case "pack.inspect": {
      const pack = inspectPack(bytesOf(input));
      return { pack_id: pack.packId, objects: pack.objects.map(([oid]) => oid).sort(), shallow: [...pack.shallow].sort() };
    }
    case "pack.manifest": {
      const raws = (valueOf(input) as JValue[]).map((item) => strictBase64(item));
      const { body, packId } = packManifest(raws);
      return { manifest_body_b64: b64(body), pack_id: packId };
    }
    case "pack.install": {
      const result = checkInstall(bytesOf(input), new Set(storedObjects(args).keys()));
      return { pack_id: result.packId, objects: result.objects };
    }
    case "localpack.read":
      return readLocalPack(bytesOf(input), strictBase64(args.pack_b64));
    case "object.load":
      return { ...loadObject(bytesOf(input), (args.expected_oid as string | undefined) ?? null, repoArgs(args)) };
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
