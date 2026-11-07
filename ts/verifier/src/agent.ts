/**
 * SPEC 4.8 `tine-actions/1` entry chains and SPEC 4.9 `opentine-agent/1`
 * records: ports of `opentine._actions_manifest.chain` and
 * `opentine._agent_identity.validate` / `agent_ref`.
 */

import { canonicalJson } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";

const encoder = new TextEncoder();

/** The entry hash chain over *digests*, seeded from the run id. */
export function actionsChain(runId: string, digests: string[]): string[] {
  let link = sha256Hex(encoder.encode(`tine-actions/1\0${runId}`));
  return digests.map((digest) => (link = sha256Hex(encoder.encode(`${link}:${digest}`))));
}

export const AGENT_SCHEME = "opentine-agent/1";
export const AGENT_DOMAIN = "opentine.agent.v1:";
const STABLE_FIELDS = ["harness", "definition_digest", "model", "key_fpr"];
const TEXT_FIELDS = ["harness", "harness_version", "model", "provider"];
const FIELDS = ["scheme", ...TEXT_FIELDS, "definition_digest", "key_fpr", "instance", "parent", "parent_run", "spawn_step"];
const MAX_TEXT = 128;
const PATTERNS: [string, RegExp][] = [
  ["definition_digest", /^sha256:[0-9a-f]{64}$/],
  ["key_fpr", /^sha256:[0-9a-f]{64}$/],
  ["instance", /^[0-9a-f]{32}$/],
  ["parent", /^agt_[0-9a-f]{32}$/],
];
/** CPython `str.isspace()` code points, which `str.strip()` removes. */
const SPACE_CLASS = "[\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]";
const PY_SPACE = new RegExp(`^${SPACE_CLASS}+|${SPACE_CLASS}+$`, "g");

/** NFKC, stripped, controls removed, bounded: the spelling that gets hashed. */
export function normalizeName(value: JValue | undefined): string {
  if (typeof value !== "string") return "";
  const text = value.normalize("NFKC").replace(PY_SPACE, "").replace(/\p{C}/gu, "");
  return Array.from(text).slice(0, MAX_TEXT).join("");
}

function identityError(message: string, code: string): never {
  throw new TineError(message, code);
}

/** `_agent_identity.validate`: the record checked field by field. */
export function validateAgent(record: JValue): JObject {
  if (!isObject(record) || record.get("scheme") !== AGENT_SCHEME) {
    identityError("not an opentine-agent/1 record", "agent.field-malformed");
  }
  const value = record as JObject;
  if ([...value.keys()].some((key) => !FIELDS.includes(key))) identityError("unknown field in agent identity", "agent.unknown-field");
  const out: JObject = new Map([["scheme", AGENT_SCHEME]]);
  for (const name of FIELDS.slice(1)) {
    const item = value.has(name) ? value.get(name) : "";
    if (typeof item !== "string" || Array.from(item).length > MAX_TEXT) {
      identityError(`agent identity field '${name}' must be a short string`, "agent.field-malformed");
    }
    out.set(name, item as string);
  }
  if (!out.get("harness")) identityError("agent identity needs a harness", "agent.harness-missing");
  for (const name of [...TEXT_FIELDS, "parent_run", "spawn_step"]) {
    const item = out.get(name) as string;
    if (item !== normalizeName(item)) identityError(`agent identity field '${name}' is not normalised`, "agent.not-normalised");
  }
  for (const [name, pattern] of PATTERNS) {
    const item = out.get(name) as string;
    if (item && !pattern.test(item)) identityError(`agent identity field '${name}' is malformed`, "agent.field-malformed");
  }
  return out;
}

/** The hashed bytes and `agt_` ref of a validated record. */
export function agentRef(record: JObject): { ref: string; hashed: Uint8Array } {
  const stable: JObject = new Map(STABLE_FIELDS.map((name) => [name, (record.get(name) as string) ?? ""]));
  const body = canonicalJson(stable);
  const hashed = new Uint8Array(AGENT_DOMAIN.length + body.length);
  hashed.set(encoder.encode(AGENT_DOMAIN));
  hashed.set(body, AGENT_DOMAIN.length);
  return { ref: `agt_${sha256Hex(hashed).slice(0, 32)}`, hashed };
}
