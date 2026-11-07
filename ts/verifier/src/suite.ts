/**
 * A runner for docs/conformance in-process: input assembly (PROTOCOL.md), the
 * phase-1 scope, and scoring exactly as `run_conformance.py` scores.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { TineError } from "./errors.js";
import { decodeTagged, runOp, Unsupported, type KeyTable, type OpInput } from "./ops.js";

export type Status = "pass" | "fail" | "repaired" | "skip" | "unsupported";

export interface Case {
  id: string;
  op: string;
  section: string;
  expect: "accept" | "reject" | "verdict";
  input: Record<string, unknown>;
  args?: Record<string, unknown>;
  output?: unknown;
  output_sha256?: string;
  forbidden?: unknown;
  reason?: string;
  reason_any?: string[];
  requires?: string[];
  twin?: string;
  must_differ?: boolean;
  profile: string;
  tier: string;
}

export interface Row {
  id: string;
  file: string;
  op: string;
  status: Status;
  detail: string;
  reasonExpected: string | null;
  reasonActual: string | null;
  output?: unknown;
}

/**
 * Vector categories outside phase 1, each with the reason. A case is out of
 * scope exactly when `outOfScope` names it; every other case must pass.
 */
export const OUT_OF_SCOPE_OPS: Record<string, string> = {
  "canon.v2": "the legacy (format v1-v3) canonicalizer, SPEC 0.3",
  "links.extract": "repository link existence checks, SPEC 1.5",
  "annotation.chain": "repository annotation chains, SPEC 1.5.5",
  "event.metrics": "event metric rules, SPEC 1.5.2",
  "run.graph": "the v3 run graph loader, SPEC 1.5.3",
  "object.load": "full repository object reads, SPEC 1.5",
  "object.put": "writer-side redaction, SPEC 1.4",
  "redact.blob": "writer-side redaction, SPEC 1.4",
  "redact.value": "writer-side redaction, SPEC 1.4",
  "pack.inspect": "network packs, SPEC 2.8",
  "pack.install": "network packs, SPEC 2.8",
  "pack.manifest": "network packs, SPEC 2.8",
  "localpack.read": "storage-v3 local packs, SPEC 2.8",
  "integrity.digest": "the legacy v1/v2 artifact digest, SPEC 3.5",
  "integrity.verify": "the legacy v1/v2 artifact digest, SPEC 3.5",
  "attest.sign": "signing (this package only verifies), SPEC 4.5",
  "actions.chain": "tine-actions/1, SPEC 4.8",
  "delegation.verify": "opentine-delegation/1 chains, SPEC 4.10",
  "agent.ref": "opentine-agent/1 records, SPEC 4.9",
};

export const OUT_OF_SCOPE_SCHEMES: Record<string, string> = {
  "tine-sig/1": "legacy artifact signatures over the v2 canonicalizer, SPEC 4.2",
  "tine-sig/2": "legacy artifact signatures over the v2 canonicalizer, SPEC 4.2",
  "tine-attest/1": "legacy attestation signatures over the v2 canonicalizer, SPEC 4.2",
  "tine-actions/1": "tine-actions/1, SPEC 4.8",
};

export const OUT_OF_SCOPE_FAMILIES: Record<string, string> = {
  artifact: "legacy tine-sig/1 and tine-sig/2 artifact verdicts, SPEC 4.7",
};

/**
 * Signature algorithms out of scope. Empty: ML-DSA-65 and the Ed25519 +
 * ML-DSA-65 composite (SPEC 4.6.1) verify through `@noble/post-quantum`.
 */
export const OUT_OF_SCOPE_ALGS: Record<string, string> = {};

/** The category name a case is skipped under, or `null` when phase 1 must answer it. */
export function outOfScope(testCase: Case): string | null {
  if (testCase.op in OUT_OF_SCOPE_OPS) return `op:${testCase.op}`;
  const args = testCase.args ?? {};
  if (testCase.op === "sig.message" && (args.scheme as string) in OUT_OF_SCOPE_SCHEMES) {
    return `scheme:${args.scheme as string}`;
  }
  if (testCase.op === "sig.verify") {
    const family = (args.family as string | undefined) ?? "attestation";
    if (family in OUT_OF_SCOPE_FAMILIES) return `family:${family}`;
    const value = testCase.input.value as Record<string, unknown> | undefined;
    const blocks = value && typeof value === "object" ? value.signatures : undefined;
    if (Array.isArray(blocks)) {
      for (const block of blocks) {
        const alg = block && typeof block === "object" ? (block as Record<string, unknown>).alg : undefined;
        if (typeof alg === "string" && alg in OUT_OF_SCOPE_ALGS) return `alg:${alg}`;
      }
    }
    if (family === "attestation") {
      const value = testCase.input.value as Record<string, unknown> | undefined;
      const block = value && typeof value === "object" ? value.signature : undefined;
      const scheme = block && typeof block === "object" ? (block as Record<string, unknown>).scheme : undefined;
      if (scheme === "tine-attest/1") return "scheme:tine-attest/1";
    }
  }
  return null;
}

// --------------------------------------------------------------------------- //
// Input assembly
// --------------------------------------------------------------------------- //

function assembleValue(recipe: Record<string, unknown>): unknown {
  let node = recipe.inner;
  for (let i = 0; i < Number(recipe.depth); i++) {
    node = (recipe.container ?? "array") === "array" ? [node] : { [recipe.key as string]: node };
  }
  return node;
}

function assembleBytes(recipe: Record<string, unknown>): Buffer {
  const kind = recipe.kind;
  if (kind === "nest") {
    const depth = Number(recipe.depth);
    return Buffer.from((recipe.open as string).repeat(depth) + recipe.inner + (recipe.close as string).repeat(depth));
  }
  if (kind === "repeat") {
    const prefix = Buffer.from((recipe.prefix_b64 as string) ?? "", "base64");
    const suffix = Buffer.from((recipe.suffix_b64 as string) ?? "", "base64");
    const unit = Buffer.from(recipe.unit_b64 as string, "base64");
    return Buffer.concat([prefix, Buffer.concat(Array(Number(recipe.count)).fill(unit)), suffix]);
  }
  if (kind === "fill") return Buffer.alloc(Number(recipe.count), Number(recipe.byte));
  if (kind === "oids") {
    const start = Number(recipe.start ?? 0);
    const end = (recipe.terminator as string) ?? "\n";
    const lines: string[] = [];
    for (let index = start; index < start + Number(recipe.count); index++) {
      lines.push(`${recipe.object_type as string}:sha256:${index.toString(16).padStart(64, "0")}${end}`);
    }
    return Buffer.from(lines.join(""), "ascii");
  }
  throw new Error(`unknown input.gen recipe: ${String(kind)}`);
}

export function resolveInput(spec: Record<string, unknown>, suite: string, root: string): OpInput {
  const gen = spec.gen as Record<string, unknown> | undefined;
  if ("value" in spec) return { value: decodeTagged(spec.value) };
  if (gen && gen.kind === "nest-value") return { value: decodeTagged(assembleValue(gen)) };
  let raw: Buffer;
  if (gen) raw = assembleBytes(gen);
  else if ("blob" in spec) raw = readFileSync(join(suite, spec.blob as string));
  else if ("path" in spec) raw = readFileSync(join(root, spec.path as string));
  else raw = Buffer.from(spec.bytes_b64 as string, "base64");
  if (typeof spec.sha256 === "string" && createHash("sha256").update(raw).digest("hex") !== spec.sha256) {
    throw new Error("assembled input does not match input.sha256");
  }
  return { bytes: Uint8Array.from(raw) };
}

// --------------------------------------------------------------------------- //
// Scoring
// --------------------------------------------------------------------------- //

/** CPython `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. */
export function pythonDumps(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return Number.isInteger(value) ? value.toFixed(0) : String(value);
  if (typeof value === "string") {
    return JSON.stringify(value).replace(/[\u007f-￿]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
  }
  if (Array.isArray(value)) return "[" + value.map(pythonDumps).join(",") + "]";
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return "{" + keys.map((key) => pythonDumps(key) + ":" + pythonDumps(record[key])).join(",") + "}";
}

function subsetMatches(actual: unknown, forbidden: unknown): boolean {
  if (typeof actual !== "object" || actual === null || typeof forbidden !== "object" || forbidden === null) {
    return isDeepStrictEqual(actual, forbidden);
  }
  const entries = Object.entries(forbidden);
  return entries.length > 0 && entries.every(([key, value]) => key in actual && isDeepStrictEqual((actual as Record<string, unknown>)[key], value));
}

export function reasonOk(actual: string | null, expected: string[], groups: string[][]): boolean {
  if (!expected.length) return true;
  const allowed = new Set(expected);
  for (const group of groups) if (group.some((code) => allowed.has(code))) group.forEach((code) => allowed.add(code));
  return actual !== null && allowed.has(actual);
}

export interface Suite {
  manifest: Record<string, unknown> & { families: { file: string }[]; alias_groups: string[][]; files: Record<string, string> };
  keys: KeyTable;
  dir: string;
  root: string;
}

export function loadSuite(root: string): Suite {
  const dir = join(root, "docs", "conformance");
  const manifest = JSON.parse(readFileSync(join(dir, "MANIFEST.json"), "utf8"));
  const raw = JSON.parse(readFileSync(join(dir, "keys.json"), "utf8")) as Record<string, string>;
  const keys: KeyTable = {};
  for (const [name, text] of Object.entries(raw)) keys[name] = Uint8Array.from(Buffer.from(text, "hex"));
  return { manifest, keys, dir, root };
}

export function suiteCases(suite: Suite): { file: string; testCase: Case }[] {
  const found: { file: string; testCase: Case }[] = [];
  for (const family of suite.manifest.families) {
    const data = JSON.parse(readFileSync(join(suite.dir, family.file), "utf8")) as { cases: Case[] };
    for (const testCase of data.cases) found.push({ file: family.file, testCase });
  }
  return found;
}

export function runCase(suite: Suite, file: string, testCase: Case): Row {
  const row: Row = {
    id: testCase.id,
    file,
    op: testCase.op,
    status: "fail",
    detail: "",
    reasonExpected: testCase.reason ?? null,
    reasonActual: null,
  };
  const category = outOfScope(testCase);
  if (category) {
    row.status = "skip";
    row.detail = category;
    return row;
  }
  let output: Record<string, unknown> | undefined;
  let accepted: boolean;
  try {
    output = runOp(testCase.op, resolveInput(testCase.input, suite.dir, suite.root), testCase.args ?? {}, suite.keys);
    accepted = true;
  } catch (exc) {
    if (exc instanceof Unsupported) {
      row.status = "unsupported";
      row.detail = exc.message;
      return row;
    }
    accepted = false;
    row.reasonActual = exc instanceof TineError ? exc.code : null;
    row.detail = (exc as Error).message;
  }
  if (testCase.expect === "reject") {
    if (accepted) {
      const repaired = testCase.forbidden !== undefined && subsetMatches(output, testCase.forbidden);
      row.status = repaired ? "repaired" : "fail";
      row.detail = repaired ? "accepted and silently repaired the input" : "accepted input the format requires be refused";
      return row;
    }
    row.status = "pass";
    return row;
  }
  if (!accepted) {
    row.detail = `refused a valid input: ${row.detail}`;
    return row;
  }
  if (testCase.output_sha256 !== undefined) {
    const digest = createHash("sha256").update(pythonDumps(output)).digest("hex");
    if (digest !== testCase.output_sha256) {
      row.detail = "output digest does not match output_sha256";
      return row;
    }
  } else if (!isDeepStrictEqual(output, testCase.output)) {
    row.detail = `output mismatch: ${JSON.stringify(output).slice(0, 300)}`;
    return row;
  }
  row.status = "pass";
  row.output = output;
  return row;
}

/** Every case, plus the pair rule (`must_differ`) applied afterwards. */
export function runSuite(suite: Suite): Row[] {
  const cases = suiteCases(suite);
  const rows = cases.map(({ file, testCase }) => runCase(suite, file, testCase));
  const byId = new Map(rows.map((row) => [row.id, row]));
  for (const { testCase } of cases) {
    if (testCase.must_differ === undefined || testCase.must_differ === null || !testCase.twin) continue;
    const row = byId.get(testCase.id) as Row;
    const twin = byId.get(testCase.twin);
    if (!twin || row.status !== "pass" || twin.status === "skip") continue;
    const differ = !isDeepStrictEqual(row.output, twin.output);
    if (differ !== testCase.must_differ) {
      row.status = "fail";
      row.detail = `must_differ is ${testCase.must_differ} against ${testCase.twin}`;
    }
  }
  return rows;
}
