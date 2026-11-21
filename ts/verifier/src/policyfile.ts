/**
 * Policy files (0.75): a port of `opentine._policy.strict_json`, `check_policy` and the
 * byte bound of `load`. A policy file is refused as JSON on a duplicate key, NaN or
 * Infinity, a float that overflows, or a number that is not JSON-safe (an integral
 * value beyond +-(2**53 - 1)); then as a policy when it is not `opentine.policy/1`.
 * Shared vectors: the `files` section of tests/data/policy_vectors.json.
 */

import { decide, type Policy, type RuleResult } from "./policyeval.js";
import { numberOk, type PValue } from "./policy.js";
import { isObject, parseText, STRICT, MAX_SAFE, type JValue } from "./json.js";

export const POLICY_SCHEMA = "opentine.policy/1";
export const MAX_RULES = 64;
export const MAX_POLICY_BYTES = 256 * 1024;
const RULE_ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const FIELDS = new Set(["schema", "name", "description", "params", "rules"]);
const RULE_FIELDS = new Set(["id", "expr", "effect", "description"]);

export class PolicyFileError extends Error {
  /** "json": not strict JSON; "policy": not an opentine.policy/1 document; "size": too large. */
  constructor(readonly stage: "json" | "policy" | "size", message: string) {
    super(message);
  }
}

function convert(value: JValue): PValue {
  if (typeof value === "bigint") {
    if (value > MAX_SAFE || value < -MAX_SAFE) throw new Error(`number ${value} is not JSON-safe`);
    return Number(value);
  }
  if (typeof value === "number") {
    if (!numberOk(value)) throw new Error(`number ${value} is not finite or not JSON-safe`);
    return value;
  }
  if (Array.isArray(value)) return value.map(convert);
  if (isObject(value)) {
    const out: { [key: string]: PValue } = {};
    for (const [key, item] of value) {
      Object.defineProperty(out, key, { value: convert(item), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

/** JSON with no duplicate keys, no NaN/Infinity and only JSON-safe numbers (strict_json). */
export function strictPolicyJson(text: string): PValue {
  try {
    return convert(parseText(text, STRICT));
  } catch (e) {
    throw new PolicyFileError("json", `not JSON: ${(e as Error).message}`);
  }
}

const isMap = (v: unknown): v is { [key: string]: PValue } => typeof v === "object" && v !== null && !Array.isArray(v);
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Problems with *doc* as a policy (empty: valid); expressions are not parsed here. */
export function checkPolicy(doc: unknown): string[] {
  if (!isMap(doc) || doc.schema !== POLICY_SCHEMA) return [`not an ${POLICY_SCHEMA} document`];
  const extra = Object.keys(doc).filter((k) => !FIELDS.has(k)).sort();
  if (extra.length) return [`unknown fields ${JSON.stringify(extra)}`];
  if (typeof doc.name !== "string" || !doc.name) return ["name is a non-empty string"];
  if (has(doc, "description") && typeof doc.description !== "string") return ["description is a string"];
  if (has(doc, "params") && !isMap(doc.params)) return ["params is an object"];
  const rules = doc.rules;
  if (!Array.isArray(rules) || rules.length < 1 || rules.length > MAX_RULES) return [`rules is a list of 1-${MAX_RULES} rules`];
  const seen = new Set<string>();
  for (const rule of rules) {
    if (!isMap(rule) || !["id", "expr", "effect"].every((k) => has(rule, k)) || Object.keys(rule).some((k) => !RULE_FIELDS.has(k))) {
      return ["a rule has id, expr, effect and an optional description"];
    }
    if (typeof rule.id !== "string" || !RULE_ID.test(rule.id)) return [`rule id ${JSON.stringify(rule.id)} is 1-64 of A-Z a-z 0-9 _ . : -`];
    if (seen.has(rule.id)) return [`rule id ${rule.id} is repeated`];
    if ((rule.effect !== "require" && rule.effect !== "advisory") || typeof rule.expr !== "string") {
      return [`rule ${rule.id}: effect is require or advisory, expr a string`];
    }
    seen.add(rule.id);
  }
  return [];
}

/** A policy file's text or UTF-8 bytes as a checked `opentine.policy/1` document. */
export function loadPolicy(source: string | Uint8Array): Policy & { [key: string]: PValue } {
  const size = typeof source === "string" ? new TextEncoder().encode(source).length : source.length;
  if (size > MAX_POLICY_BYTES) throw new PolicyFileError("size", `policy is larger than ${MAX_POLICY_BYTES} bytes`);
  let text: string;
  try {
    text = typeof source === "string" ? source : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source);
  } catch {
    throw new PolicyFileError("json", "policy is not UTF-8");
  }
  const doc = strictPolicyJson(text);
  const problems = checkPolicy(doc);
  if (problems.length) throw new PolicyFileError("policy", `policy: ${problems[0]}`);
  return doc as unknown as Policy & { [key: string]: PValue };
}

/** `{decision, rules}` of a loaded policy over an input document (`_policy.decide`). */
export function decidePolicy(policy: Policy, document: unknown): { decision: string; rules: RuleResult[] } {
  return decide(policy, document);
}
