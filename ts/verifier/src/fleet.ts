/**
 * SPEC 4.11 `opentine-fleet/1` and its signed `opentine-fleet-record/1` document
 * (vectors 0.48). A port of `opentine._fleet_record.validate` / `verify`: the record
 * has exactly its five fields, each already normalised; the document's `tine-sig/3`
 * Ed25519 block is over `opentine.fleet.v1:` + JCS({body, header}) with the record
 * bound to its run id and digest. Refusals carry `fleet.*` codes.
 */

import { canonicalJson } from "./canon.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { normalizeName } from "./agent.js";
import { HEADER_KEYS, verifyBlock, type Header, type VerifyKeys } from "./signature.js";

const SCHEME = "opentine-fleet/1";
const SIGNED_SCHEME = "opentine-fleet-record/1";
const DOMAIN = "opentine.fleet.v1:";
const FIELDS = ["fleet_id", "member", "role", "parent"];
const ID_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const encoder = new TextEncoder();

function fail(code: string, message: string): never {
  throw new TineError(message, `fleet.${code}`);
}

function validate(record: JValue | undefined): JObject {
  if (!isObject(record) || record.get("scheme") !== SCHEME) fail("malformed", "not an opentine-fleet/1 record");
  const value = record as JObject;
  const keys = [...value.keys()].sort();
  if (keys.join(",") !== ["scheme", ...FIELDS].sort().join(",")) {
    fail("malformed", `an opentine-fleet/1 record has exactly scheme and ${FIELDS.join(", ")}`);
  }
  for (const name of FIELDS) {
    const item = value.get(name);
    if (typeof item !== "string" || item !== normalizeName(item)) fail("malformed", `fleet field '${name}' must be a normalised short string`);
  }
  if (!ID_RE.test(value.get("fleet_id") as string)) fail("malformed", "fleet_id must be 1..128 of [A-Za-z0-9_.-]");
  return value;
}

export function verifyFleet(document: JValue, publicKey: Uint8Array | null): Record<string, JValue> {
  if (!isObject(document) || document.get("scheme") !== SIGNED_SCHEME) fail("malformed", `not an ${SIGNED_SCHEME} document`);
  const doc = document as JObject;
  const record = validate(doc.get("record"));
  for (const name of ["run_id", "run_digest"]) if (!doc.has(name)) fail("malformed", `the document has no ${name}`);
  const body: JObject = new Map(["scheme", "record", "run_id", "run_digest"].map((key) => [key, doc.get(key) as JValue]));
  const block = doc.get("signature");
  if (isObject(block) && block.get("alg") !== "ed25519") fail("bad-signature", "signature error: Ed25519 only");
  const keys: VerifyKeys = publicKey ? { publicKey } : { trustEmbedded: true };
  const result = verifyBlock(
    block,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", body],
        ["header", new Map(HEADER_KEYS.map((key) => [key, header.get(key) ?? null]))],
      ]);
      const tail = canonicalJson(view);
      const head = encoder.encode(DOMAIN);
      const message = new Uint8Array(head.length + tail.length);
      message.set(head);
      message.set(tail, head.length);
      return message;
    },
    [SCHEME_V3],
    "document",
    keys,
  );
  if (!result.ok) {
    const code = /not the trusted key/.test(result.reason) ? "wrong-key" : "bad-signature";
    fail(code, `signature ${result.state}: ${result.reason}`);
  }
  return {
    ...Object.fromEntries(record),
    run_id: doc.get("run_id") as JValue,
    run_digest: doc.get("run_digest") as JValue,
    state: publicKey ? "verified" : "verified-tofu",
  };
}
