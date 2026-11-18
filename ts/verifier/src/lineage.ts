/**
 * 0.58 `tine lineage check VARIANT`: a port of `opentine._lineage_check.check`.
 *
 * Input is a lineage folder as a map of relative path to bytes
 * (`variants/HEX.json`, `evals/HEX.jsonl`, `decisions/HEX.json`). Records are
 * attestations under the `opentine.lineage.variant` claim convention. Every
 * variant reachable through `parents` is checked; each finding names the
 * variant it is about. Codes: `lineage.variant-unknown`, `lineage.record-invalid`,
 * `lineage.parent-missing`, `lineage.cycle`, `lineage.evidence-missing`,
 * `lineage.decision-mismatch`. These are CLI-only codes: `verify` does not emit
 * them. Shared fixture: tests/data/lineage_check.json.
 */

import { canonicalJson } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { evalId, verifyEvalVerdict } from "./evalverdict.js";
import { isObject, KERNEL, parseBytes, parseText, type JObject, type JValue } from "./json.js";
import { verifyAttestation } from "./signature.js";

export const CONVENTION = "opentine.lineage.variant";
const DECISION = "opentine.promotion-decision/1";
const DOMAIN = new TextEncoder().encode("opentine.lineage.variant.v1:");
const ARTIFACTS = ["code_tree", "prompt", "config", "weights"];
const CLAIM = ["convention", "variant", "artifacts", "parents", "mutation_run", "evals", "selector",
  "decision", "policy", "loop"];
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const RUN = /^run:sha256:[0-9a-f]{64}$/;
const LOOP = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export interface LineageFinding { code: string; variant: string; detail: string }
/** Who may sign justifying verdicts (the pinned scorer role -- 0.59: only from an owner-signed trust bundle, never an unsigned .tine/key-roles.toml -- and the promotion policy). */
export interface LineageTrust { eval_signers: string[]; optimizer: string[] }
export interface LineageReport {
  ok: boolean; variant: string; signers: "pinned" | "unpinned"; ancestors: string[]; findings: LineageFinding[];
}

/** Duplicate keys are refused: one reader, one meaning (no last-wins laundering). */
const READ = { ...KERNEL, duplicates: "reject" as const };
const str = (v: JValue | undefined): v is string => typeof v === "string";
const finding = (code: string, variant: string, detail: string): LineageFinding =>
  ({ code: `lineage.${code}`, variant, detail });

function sameKeys(value: JObject, keys: string[]): boolean {
  return value.size === keys.length && keys.every((k) => value.has(k));
}

export function variantId(artifacts: JObject): string {
  const tail = canonicalJson(artifacts);
  const message = new Uint8Array(DOMAIN.length + tail.length);
  message.set(DOMAIN);
  message.set(tail, DOMAIN.length);
  return `sha256:${sha256Hex(message)}`;
}

function parse(raw: Uint8Array): JValue | undefined {
  try {
    return parseBytes(raw, READ);
  } catch {
    return undefined;
  }
}

/** Ed25519-signed, verifying under its embedded key, and that key is the signer. */
function signed(payload: JValue | undefined): boolean {
  if (!isObject(payload)) return false;
  const block = payload.get("signature");
  if (!isObject(block) || block.get("alg") !== "ed25519") return false;
  const key = block.get("public_key");
  if (!str(key) || !HEX.test(key)) return false;
  if (`sha256:${sha256Hex(Uint8Array.from(Buffer.from(key, "hex")))}` !== payload.get("signer")) return false;
  return verifyAttestation(payload, { trustEmbedded: true }).ok;
}

function shape(claim: JValue | undefined, variant: string): string | null {
  if (!isObject(claim) || claim.get("convention") !== CONVENTION) return `not an ${CONVENTION} claim`;
  if (!sameKeys(claim, CLAIM)) return "the claim's fields are not the convention's";
  const arts = claim.get("artifacts");
  if (!isObject(arts) || !arts.size || ![...arts].every(([k, v]) => ARTIFACTS.includes(k) && str(v) && DIGEST.test(v))) {
    return "artifacts must map code_tree/prompt/config/weights to sha256: digests";
  }
  if (claim.get("variant") !== variant || variantId(arts) !== variant) return "the variant id is not the digest of its artifacts";
  const parents = claim.get("parents");
  if (!Array.isArray(parents) || !parents.every((p) => str(p) && DIGEST.test(p))) return "parents must be sha256: variant ids";
  const evals = claim.get("evals");
  if (!Array.isArray(evals) || !evals.every((e) => isObject(e) && sameKeys(e, ["eval", "verdicts_sha256"])
      && str(e.get("eval")) && DIGEST.test(e.get("eval") as string)
      && str(e.get("verdicts_sha256")) && HEX.test(e.get("verdicts_sha256") as string))) {
    return "evals must be {eval, verdicts_sha256} rows";
  }
  const run = claim.get("mutation_run");
  if (!str(run) || !RUN.test(run)) return "mutation_run must be a run:sha256: oid";
  const cited = claim.get("decision");
  if (cited !== null && !(isObject(cited) && sameKeys(cited, ["sha256"]) && str(cited.get("sha256")) && HEX.test(cited.get("sha256") as string))) {
    return "decision must be null or {sha256}";
  }
  const policy = claim.get("policy");
  if (policy !== null && !(str(policy) && HEX.test(policy))) return "policy must be null or 64 hex";
  if (!str(claim.get("selector"))) return "selector must be text";
  const loop = claim.get("loop");
  if (loop !== null && !(str(loop) && LOOP.test(loop))) return "loop must be null or a loop id";
  return null;
}

function evalProblem(files: Map<string, Uint8Array>, row: JObject, run: string, signers: Set<string>): string | null {
  const id = row.get("eval") as string;
  const raw = files.get(`evals/${id.slice(7)}.jsonl`);
  if (raw === undefined) return `eval ${id} is absent`;
  if (sha256Hex(raw) !== row.get("verdicts_sha256")) return `eval ${id}: the verdicts do not hash to verdicts_sha256`;
  const lines = Buffer.from(raw).toString("utf8").split("\n").filter((line) => line.trim());
  if (!lines.length) return `eval ${id} has no verdicts`;
  const seen = new Set<string>();
  for (let i = 0; i < lines.length; i += 1) {
    let verdict: JValue | undefined;
    let ok = false;
    try {
      verdict = parseText(lines[i], READ);
      verifyEvalVerdict(verdict);
      ok = isObject(verdict) && verdict.get("eval") === id && evalId(verdict) === id;
    } catch {
      ok = false;
    }
    if (!ok || !isObject(verdict)) return `eval ${id}: verdict ${i + 1} is unsigned or does not verify`;
    if (verdict.get("run") !== run) return `eval ${id}: verdict ${i + 1} scores another run than ${run}`;
    const item = String(verdict.get("item"));
    if (seen.has(item)) return `eval ${id}: verdict ${i + 1} repeats an item`;
    seen.add(item);
    signers.add(String(verdict.get("signer")));
  }
  return null;
}

function decisionProblem(files: Map<string, Uint8Array>, claim: JObject): string | null {
  const digest = (claim.get("decision") as JObject).get("sha256") as string;
  const run = claim.get("mutation_run") as string;
  const raw = files.get(`decisions/${digest}.json`);
  if (raw === undefined || sha256Hex(raw) !== digest) return `decision ${digest} is absent`;
  const document = parse(raw);
  if (document === undefined) return `decision ${digest} is not JSON`;
  if (!signed(document)) return `decision ${digest} is not signed by its signer`;
  const said = (document as JObject).get("claim");
  if (!isObject(said) || said.get("schema") !== DECISION) return `decision ${digest} is not an ${DECISION} claim`;
  if (said.get("action") !== "promote" || said.get("candidate") !== run) return `decision ${digest} does not promote ${run}`;
  if ((document as JObject).get("target_id") !== run) return `decision ${digest} is not on ${run}`;
  if (claim.get("policy") !== null && said.get("policy_sha256") !== claim.get("policy")) {
    return `decision ${digest} was made under another policy`;
  }
  const inputs = Array.isArray(said.get("inputs")) ? (said.get("inputs") as JValue[]) : [];
  const cited = new Set<string>();
  for (const i of inputs) {
    if (isObject(i) && isObject(i.get("digest"))) cited.add(`${String(i.get("uri"))}\u0000${String((i.get("digest") as JObject).get("sha256"))}`);
  }
  const evals = claim.get("evals") as JObject[];
  if (!evals.some((e) => cited.has(`eval:${e.get("eval") as string}\u0000${e.get("verdicts_sha256") as string}`))) {
    return `decision ${digest} cites none of the variant's evals`;
  }
  return null;
}

/** Why some verdict signer is not trusted (not an allowed eval signer, or an optimizer key). */
function untrusted(signers: Set<string>, trust: LineageTrust | null): string | null {
  if (trust === null) return null;
  const allowed = new Set(trust.eval_signers);
  const optimizer = new Set(trust.optimizer);
  const bad = [...signers].filter((s) => !allowed.has(s) || optimizer.has(s)).sort();
  if (!bad.length) return null;
  return `verdicts signed by ${bad.join(", ")}: not an allowed eval-signer key, or an optimizer key`;
}

function node(files: Map<string, Uint8Array>, variant: string, out: LineageFinding[], trust: LineageTrust | null): string[] {
  const raw = files.get(`variants/${variant.slice(7)}.json`);
  if (raw === undefined) return [];
  const payload = parse(raw);
  if (payload === undefined) {
    out.push(finding("record-invalid", variant, "the record is not JSON"));
    return [];
  }
  const claim = isObject(payload) ? payload.get("claim") : undefined;
  let problem = shape(claim, variant);
  if (problem === null && (payload as JObject).get("target_id") !== (claim as JObject).get("mutation_run")) {
    problem = "the attestation does not target the mutation run";
  }
  if (problem === null && !signed(payload)) problem = "the record is not Ed25519-signed by its signer";
  if (problem !== null) {
    out.push(finding("record-invalid", variant, problem));
    return [];
  }
  const c = claim as JObject;
  const parents = c.get("parents") as string[];
  const evals = c.get("evals") as JObject[];
  if (parents.length && !evals.length) out.push(finding("evidence-missing", variant, "a derived variant names no eval"));
  const signers = new Set<string>();
  for (const row of evals) {
    const found = evalProblem(files, row, c.get("mutation_run") as string, signers);
    if (found) out.push(finding("evidence-missing", variant, found));
  }
  const distrust = untrusted(signers, trust);
  if (distrust) out.push(finding("signer-untrusted", variant, distrust));
  if (c.get("decision") !== null) {
    const found = decisionProblem(files, c);
    if (found) out.push(finding("decision-mismatch", variant, found));
  }
  return [...parents];
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Iterative depth-first walk, parents in order; the same findings as the Python check. */
export function checkLineage(files: Map<string, Uint8Array>, variant: string, trust: LineageTrust | null = null): LineageReport {
  const signers = trust === null ? "unpinned" : "pinned";
  if (!DIGEST.test(variant)) throw new Error("VARIANT must be a sha256:HEX variant id");
  const out: LineageFinding[] = [];
  const has = (v: string): boolean => files.has(`variants/${v.slice(7)}.json`);
  if (!has(variant)) {
    return { ok: false, variant, signers, ancestors: [], findings: [finding("variant-unknown", variant, "no record names this variant")] };
  }
  const state = new Map<string, "open" | "done">();
  const order: string[] = [];
  const stack: { node: string; parents: string[]; index: number }[] = [];
  const enter = (v: string): void => {
    state.set(v, "open");
    order.push(v);
    stack.push({ node: v, parents: node(files, v, out, trust), index: 0 });
  };
  enter(variant);
  while (stack.length) {
    const top = stack[stack.length - 1];
    if (top.index === top.parents.length) {
      state.set(top.node, "done");
      stack.pop();
      continue;
    }
    const parent = top.parents[top.index];
    top.index += 1;
    if (!has(parent)) out.push(finding("parent-missing", top.node, `parent ${parent} has no record`));
    else if (state.get(parent) === "open") out.push(finding("cycle", top.node, `parent ${parent} is its own ancestor`));
    else if (!state.has(parent)) enter(parent);
  }
  out.sort((a, b) => cmp(a.variant, b.variant) || cmp(a.code, b.code) || cmp(a.detail, b.detail));
  return { ok: !out.length, variant, signers, ancestors: order.slice(1), findings: out };
}
