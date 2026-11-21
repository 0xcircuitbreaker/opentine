/**
 * Evaluate a parsed policy expression (0.74), as opentine/_policy_eval.py does, and
 * decide a policy as opentine/_policy.py does. Every node evaluated is a step; both
 * sides of && and || and every element of all/exists are evaluated, left first, so
 * step counts and the first error match the Python evaluator.
 */

import {
  MAX_INPUT_DEPTH,
  MAX_STEPS,
  numberOk,
  parse,
  PolicyError,
  type Node,
  type PValue,
} from "./policy.js";

class Fatal extends Error {
  constructor(readonly error: PolicyError) {
    super(error.message);
  }
}

type PMap = { [key: string]: PValue };
const own = (m: PMap, k: string): boolean => Object.prototype.hasOwnProperty.call(m, k);
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

export function kind(v: PValue): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number") return "number";
  if (typeof v === "string") return "string";
  return Array.isArray(v) ? "list" : "map";
}

export function checkInput(value: unknown, depth = 0): void {
  if (depth > MAX_INPUT_DEPTH) throw new PolicyError("policy.input", "input nested too deeply");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!numberOk(value)) throw new PolicyError("policy.input", "input number is not finite or not JSON-safe");
    return;
  }
  if (typeof value === "string") {
    if (LONE.test(value)) throw new PolicyError("policy.input", "input string has a lone surrogate");
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) checkInput(item, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value as PMap)) {
      checkInput(key, depth + 1);
      checkInput(item, depth + 1);
    }
    return;
  }
  throw new PolicyError("policy.input", "input holds a value that is not JSON");
}

/** Compare by Unicode code point (Python str order), not UTF-16 unit. */
export function cmpStrings(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = (x[i].codePointAt(0) as number) - (y[i].codePointAt(0) as number);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

export function equal(a: PValue, b: PValue): boolean {
  const ka = kind(a);
  if (ka !== kind(b)) return false;
  if (ka === "list") {
    const x = a as PValue[];
    const y = b as PValue[];
    return x.length === y.length && x.every((v, i) => equal(v, y[i]));
  }
  if (ka === "map") {
    const x = a as PMap;
    const y = b as PMap;
    const kx = Object.keys(x);
    return kx.length === Object.keys(y).length && kx.every((k) => own(y, k) && equal(x[k], y[k]));
  }
  return a === b;
}

function order(rel: string, a: PValue, b: PValue): boolean {
  const ka = kind(a);
  if (ka !== kind(b) || !["number", "string", "bool"].includes(ka)) {
    throw new PolicyError("policy.type", `cannot order ${ka} and ${kind(b)}`);
  }
  const d = ka === "string" ? cmpStrings(a as string, b as string) : (a as number) < (b as number) ? -1 : (a as number) > (b as number) ? 1 : 0;
  return { "<": d < 0, "<=": d <= 0, ">": d > 0, ">=": d >= 0 }[rel] as boolean;
}

type Result = [boolean | null, PolicyError | null];

class Evaluator {
  steps = 0;
  constructor(private env: PMap) {}

  run(tree: Node): PValue {
    try {
      return this.ev(tree, new Map());
    } catch (e) {
      if (e instanceof Fatal) throw e.error;
      throw e;
    }
  }

  tryBool(tree: Node, scope: Map<string, PValue>): Result {
    let value: PValue;
    try {
      value = this.ev(tree, scope);
    } catch (e) {
      if (e instanceof PolicyError) return [null, e];
      throw e;
    }
    if (typeof value !== "boolean") return [null, new PolicyError("policy.type", `expected a bool, got ${kind(value)}`)];
    return [value, null];
  }

  logic(results: Result[], short: boolean): boolean {
    if (results.some(([v, err]) => err === null && v === short)) return short;
    for (const [, err] of results) if (err !== null) throw err;
    return !short;
  }

  ev(t: Node, scope: Map<string, PValue>): PValue {
    this.steps += 1;
    if (this.steps > MAX_STEPS) throw new Fatal(new PolicyError("policy.steps", `more than ${MAX_STEPS} steps`));
    switch (t.op) {
      case "lit":
        return t.value;
      case "var":
        if (scope.has(t.name)) return scope.get(t.name) as PValue;
        if (own(this.env, t.name)) return this.env[t.name];
        throw new PolicyError("policy.no-such-var", `undeclared reference ${t.name}`);
      case "list":
        return t.items.map((item) => this.ev(item, scope));
      case "and":
      case "or": {
        const results = [this.tryBool(t.a, scope), this.tryBool(t.b, scope)];
        return this.logic(results, t.op === "or");
      }
      case "not": {
        const v = this.ev(t.a, scope);
        if (typeof v !== "boolean") throw new PolicyError("policy.type", "! takes a bool");
        return !v;
      }
      case "neg": {
        const v = this.ev(t.a, scope);
        if (typeof v !== "number") throw new PolicyError("policy.type", "- takes a number");
        return -v;
      }
      case "cmp": {
        const a = this.ev(t.a, scope);
        const b = this.ev(t.b, scope);
        if (t.rel === "==" || t.rel === "!=") return equal(a, b) === (t.rel === "==");
        return order(t.rel, a, b);
      }
      case "in": {
        const a = this.ev(t.a, scope);
        const b = this.ev(t.b, scope);
        if (Array.isArray(b)) return b.some((x) => equal(a, x));
        if (kind(b) === "map") return typeof a === "string" && own(b as PMap, a);
        throw new PolicyError("policy.type", `'in' takes a list or map, got ${kind(b)}`);
      }
      case "sel": {
        const v = this.ev(t.a, scope);
        if (kind(v) !== "map") throw new PolicyError("policy.type", `cannot select .${t.field} on ${kind(v)}`);
        if (!own(v as PMap, t.field)) throw new PolicyError("policy.no-such-key", `no such key: ${t.field}`);
        return (v as PMap)[t.field];
      }
      case "has": {
        const v = this.ev(t.a, scope);
        if (kind(v) !== "map") throw new PolicyError("policy.type", `has() on ${kind(v)}`);
        return own(v as PMap, t.field);
      }
      case "idx":
        return this.index(this.ev(t.a, scope), this.ev(t.b, scope));
      case "size": {
        const v = this.ev(t.a, scope);
        if (typeof v === "string") return Array.from(v).length;
        if (Array.isArray(v)) return v.length;
        if (kind(v) === "map") return Object.keys(v as PMap).length;
        throw new PolicyError("policy.type", `size() of ${kind(v)}`);
      }
      default:
        return this.macro(t, scope);
    }
  }

  index(v: PValue, key: PValue): PValue {
    if (Array.isArray(v)) {
      if (typeof key !== "number" || !Number.isInteger(key)) {
        throw new PolicyError("policy.type", "a list index is an integral number");
      }
      if (key < 0 || key >= v.length) throw new PolicyError("policy.index", "list index out of range");
      return v[key];
    }
    if (kind(v) === "map") {
      if (typeof key !== "string") throw new PolicyError("policy.type", "a map key is a string");
      if (!own(v as PMap, key)) throw new PolicyError("policy.no-such-key", `no such key: ${key}`);
      return (v as PMap)[key];
    }
    throw new PolicyError("policy.type", `cannot index ${kind(v)}`);
  }

  macro(t: Extract<Node, { op: "all" | "exists" }>, scope: Map<string, PValue>): boolean {
    let items = this.ev(t.a, scope);
    if (kind(items) === "map") items = Object.keys(items as PMap).sort(cmpStrings);
    if (!Array.isArray(items)) throw new PolicyError("policy.type", `${t.op}() over ${kind(items)}`);
    const results = items.map((item) => this.tryBool(t.body, new Map([...scope, [t.name, item]])));
    return this.logic(results, t.op === "exists");
  }
}

export function evaluate(tree: Node, env: PMap): PValue {
  return new Evaluator(env).run(tree);
}

export type RuleResult = { id: string; effect: string; outcome: string; code: string | null };
export type Policy = { rules: { id: string; effect: string; expr: string }[] };

export function ruleResult(expr: string, env: PMap): Omit<RuleResult, "id" | "effect"> {
  let value: PValue;
  try {
    value = evaluate(parse(expr), env);
  } catch (e) {
    if (e instanceof PolicyError) return { outcome: "error", code: e.code };
    throw e;
  }
  if (typeof value !== "boolean") return { outcome: "error", code: "policy.not-bool" };
  return { outcome: value ? "true" : "false", code: null };
}

/** `{decision, rules}`: allow only when every `require` rule is true (advisory never blocks). */
export function decide(policy: Policy, document: unknown): { decision: string; rules: RuleResult[] } {
  let bad: Omit<RuleResult, "id" | "effect"> | null = null;
  try {
    checkInput(document);
    if (kind(document as PValue) !== "map") throw new PolicyError("policy.input", "the input document is an object");
  } catch (e) {
    if (!(e instanceof PolicyError)) throw e;
    bad = { outcome: "error", code: e.code };
  }
  const rules = policy.rules.map((r) => ({
    id: r.id,
    effect: r.effect,
    ...(bad ?? ruleResult(r.expr, document as PMap)),
  }));
  const allow = rules.filter((r) => r.effect === "require").every((r) => r.outcome === "true");
  return { decision: allow ? "allow" : "deny", rules };
}
