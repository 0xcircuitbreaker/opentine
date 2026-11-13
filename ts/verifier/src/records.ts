/**
 * SPEC 4.14 `opentine.tombstone` (a signed purge record) and SPEC 4.15
 * `opentine.redacted-copy` (a public copy's link to its private run). A port of
 * `opentine._tombstone.check` and `opentine._redacted_copy.check`: exactly each
 * kind's fields, a `tine-sig/3` block over the kind's domain prefix + JCS of
 * `{"body", "header"}` (HMAC-SHA256, or Ed25519 under the trusted key or,
 * without one, the embedded key: trust on first use). Refusals carry
 * `tombstone.*` and `redacted-copy.*` codes.
 */

import { canonicalJson } from "./canon.js";
import { ObjectEnvelope, validateLinks } from "./envelope.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { HEADER_KEYS, verifyBlock, type Header, type VerifyKeys } from "./signature.js";

export const TOMBSTONE_KIND = "opentine.tombstone";
export const COPY_KIND = "opentine.redacted-copy";
const TOMBSTONE_FIELDS = ["kind", "tombstone_version", "oid", "reason", "actor", "purged_at"];
const COPY_FIELDS = ["kind", "copy_version", "source_run", "public_run", "ruleset", "objects", "redacted", "pack"];
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const WHEN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const BLOB = /^blob:sha256:[0-9a-f]{64}$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/;
const encoder = new TextEncoder();

export interface Kind {
  code: string;
  subject: string;
  domain: string;
  fields: string[];
}

const TOMBSTONE: Kind = { code: "tombstone", subject: "tombstone", domain: "opentine.tombstone.v1:", fields: TOMBSTONE_FIELDS };
const COPY: Kind = { code: "redacted-copy", subject: "redacted copy", domain: "opentine.redacted-copy.v1:", fields: COPY_FIELDS };

function count(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value >= 0n && value < 2n ** 53n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  return null;
}

function text(value: JValue | undefined, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function tombstoneRule(body: JObject): string | null {
  if (count(body.get("tombstone_version")) !== 1) return "tombstone_version must be 1";
  if (!text(body.get("oid"), BLOB)) return "oid must be a blob oid";
  const reason = body.get("reason");
  if (typeof reason !== "string" || reason.trim() === "" || encoder.encode(reason).length > 1024 || CONTROL.test(reason)) {
    return "reason must be 1 to 1024 bytes of text without control characters";
  }
  if (!text(body.get("actor"), NAME)) return "actor must be a name";
  if (!text(body.get("purged_at"), WHEN)) return "purged_at must be an RFC 3339 UTC time";
  return null;
}

function copyRule(body: JObject): string | null {
  if (count(body.get("copy_version")) !== 1) return "copy_version must be 1";
  if (!text(body.get("source_run"), RUN) || !text(body.get("public_run"), RUN)) return "source_run and public_run must be run oids";
  if (!text(body.get("ruleset"), NAME)) return "ruleset must be a name";
  if (count(body.get("objects")) === null || count(body.get("redacted")) === null) return "objects and redacted must be counts";
  if (!text(body.get("pack"), DIGEST)) return "pack must be sha256:<64 hex>";
  return null;
}

export function signed(kind: Kind, record: JValue, rule: (body: JObject) => string | null, hmacKey?: Uint8Array | null, publicKey?: Uint8Array | null): { body: JObject; state: string } {
  const fail = (code: string, message: string): never => {
    throw new TineError(message, `${kind.code}.${code}`);
  };
  if (!isObject(record)) fail("malformed", `${kind.subject} is malformed: not an object`);
  const object = record as JObject;
  const keys = [...object.keys()];
  if (keys.some((key) => key !== "signature" && !kind.fields.includes(key)) || kind.fields.some((key) => !object.has(key))) {
    fail("malformed", `${kind.subject} is malformed: wrong set of fields`);
  }
  const body: JObject = new Map(kind.fields.map((name) => [name, object.get(name) as JValue]));
  const problem = rule(body);
  if (problem !== null) fail("malformed", `${kind.subject} is malformed: ${problem}`);
  const block = object.get("signature");
  if (block === undefined || block === null) fail("unsigned", `the ${kind.subject} is unsigned`);
  if (!isObject(block)) fail("bad-signature", `the ${kind.subject} signature is not a block`);
  const sig = block as JObject;
  const algorithm = sig.get("alg");
  if (algorithm === "hmac-sha256" && hmacKey == null) fail("no-key", `no key for an hmac-sha256 ${kind.subject}`);
  if (hmacKey != null && algorithm !== "hmac-sha256") fail("wrong-key", "not the trusted key's algorithm");
  if (publicKey != null) {
    if (algorithm !== "ed25519") fail("wrong-key", "not the trusted key's algorithm");
    if (sig.get("public_key") !== Buffer.from(publicKey).toString("hex")) fail("wrong-key", "signed by a key that is not the trusted key");
  }
  const verifyKeys: VerifyKeys =
    algorithm === "hmac-sha256" ? { hmacKey } : publicKey != null ? { publicKey } : { trustEmbedded: true };
  const result = verifyBlock(
    sig,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", body],
        ["header", new Map(HEADER_KEYS.map((key) => [key, header.get(key) ?? null]))],
      ]);
      const tail = canonicalJson(view);
      const head = encoder.encode(kind.domain);
      const message = new Uint8Array(head.length + tail.length);
      message.set(head);
      message.set(tail, head.length);
      return message;
    },
    [SCHEME_V3],
    kind.subject,
    verifyKeys,
  );
  if (!result.ok) fail("bad-signature", `the ${kind.subject} signature does not hold (${result.state}: ${result.reason})`);
  return { body, state: result.state };
}

export interface TombstoneResult {
  oid: string;
  actor: string;
  purged_at: string;
  state: string;
}

/** Verify one tombstone under `hmacKey`, a trusted Ed25519 `publicKey`, or (Ed25519 only) its embedded key. */
export function verifyTombstone(record: JValue, hmacKey?: Uint8Array | null, publicKey?: Uint8Array | null): TombstoneResult {
  const { body, state } = signed(TOMBSTONE, record, tombstoneRule, hmacKey, publicKey);
  return {
    oid: body.get("oid") as string,
    actor: body.get("actor") as string,
    purged_at: body.get("purged_at") as string,
    state,
  };
}

export interface CopyResult {
  source_run: string;
  public_run: string;
  objects: number;
  redacted: number;
  state: string;
}

/** Verify one redacted-copy record, and that it names `pack` when one is given. */
export function verifyRedactedCopy(record: JValue, hmacKey?: Uint8Array | null, publicKey?: Uint8Array | null, pack?: string | null): CopyResult {
  const { body, state } = signed(COPY, record, copyRule, hmacKey, publicKey);
  const objects = count(body.get("objects")) as number;
  const redacted = count(body.get("redacted")) as number;
  const source = body.get("source_run") as string;
  const pub = body.get("public_run") as string;
  if (redacted > objects || (redacted === 0) !== (source === pub)) {
    throw new TineError("the counts disagree with the run oids", "redacted-copy.inconsistent");
  }
  if (pack != null && pack !== body.get("pack")) {
    throw new TineError("the record names another pack", "redacted-copy.pack-mismatch");
  }
  return { source_run: source, public_run: pub, objects, redacted, state };
}

export interface ClosureResult {
  run: string;
  objects: number;
  content_unavailable: string[];
  state: string;
}

/**
 * SPEC 4.14: walk `run`'s closure through `objects`. A missing blob a tombstone
 * names is content-unavailable (its oid is still bound by every link); any
 * other missing object fails with `tombstone.missing-content`. Only the
 * tombstones' shape is checked here, never their signatures.
 */
export function tombstoneClosure(run: string, objects: Map<string, Uint8Array>, tombstones: JValue): ClosureResult {
  if (!Array.isArray(tombstones)) throw new TineError("tombstone is malformed: not a list", "tombstone.malformed");
  const marked = new Set<string>();
  for (const record of tombstones) {
    const fail = (message: string): never => {
      throw new TineError(`tombstone is malformed: ${message}`, "tombstone.malformed");
    };
    if (!isObject(record) || record.get("kind") !== TOMBSTONE_KIND) fail("kind");
    const object = record as JObject;
    const keys = [...object.keys()];
    if (keys.some((key) => key !== "signature" && !TOMBSTONE_FIELDS.includes(key)) || TOMBSTONE_FIELDS.some((key) => !object.has(key))) {
      fail("wrong set of fields");
    }
    const problem = tombstoneRule(new Map(TOMBSTONE_FIELDS.map((name) => [name, object.get(name) as JValue])));
    if (problem !== null) fail(problem);
    marked.add(object.get("oid") as string);
  }
  const seen = new Set<string>();
  const unavailable = new Set<string>();
  const stack: string[] = [run];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const raw = objects.get(oid);
    if (raw === undefined) {
      if (marked.has(oid)) {
        unavailable.add(oid);
        continue;
      }
      throw new TineError(`linked object ${oid} is missing and no tombstone names it`, "tombstone.missing-content");
    }
    for (const link of validateLinks(ObjectEnvelope.decode(raw, oid))) stack.push(link as string);
  }
  return {
    run,
    objects: seen.size - unavailable.size,
    content_unavailable: [...unavailable].sort(),
    state: unavailable.size > 0 ? "content-unavailable" : "verified",
  };
}

/**
 * `_tombstone.well_formed` / `_redacted_copy.body`: the field rules and a
 * signature block present, never the signature itself (what a bundle reader
 * checks before it knows any key). Returns the signed body.
 */
export function wellFormed(which: "tombstone" | "redacted-copy", record: JValue): JObject {
  const [kind, rule] = which === "tombstone" ? [TOMBSTONE, tombstoneRule] : [COPY, copyRule];
  if (isObject(record) && !isObject((record as JObject).get("signature") ?? null)) {
    const bare: JObject = new Map([...(record as JObject)].filter(([key]) => key !== "signature"));
    try {
      signed(kind, bare, rule);
    } catch (exc) {
      if ((exc as TineError).code !== `${kind.code}.unsigned`) throw exc;
    }
    throw new TineError(`the ${kind.subject} is unsigned`, `${kind.code}.unsigned`);
  }
  try {
    return signed(kind, record, rule, null, null).body;
  } catch (exc) {
    const code = (exc as TineError).code;
    if (code === `${kind.code}.malformed` || code === `${kind.code}.unsigned`) throw exc;
    const object = record as JObject;
    return new Map(kind.fields.map((name) => [name, object.get(name) as JValue]));
  }
}
