/**
 * SPEC 4.11 `tine-eval-verdict/1`: one signed score for one dataset item. A port
 * of `opentine._eval_verdict.verify`: the field rules, the embedded key must be
 * the named `signer` (and the trusted key when one is given), the Ed25519
 * `tine-sig/3` block is over `opentine.eval-verdict.v1:` + JCS of
 * `{"body", "header"}`, `passed` must equal `score >= threshold`, and only an
 * `llm-judge` verdict names a `judge_run`. Refusals carry `eval-verdict.*` codes.
 */

import { readFileSync } from "node:fs";
import { canonicalJson } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, KERNEL, parseText, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { verifyBlock, type Header } from "./signature.js";

export const EVAL_VERDICT_SCHEME = "tine-eval-verdict/1";
const DOMAIN = "opentine.eval-verdict.v1:";
const FIELDS = [
  "scheme", "eval", "dataset", "item", "item_digest", "run", "scorer", "scorer_version",
  "score", "threshold", "passed", "judge_run", "signer", "created_at",
];
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const SCORE = /^(?:0|1|0\.[0-9]{0,5}[1-9])$/;
const PATTERNS: Record<string, RegExp> = {
  eval: DIGEST, dataset: DIGEST, item_digest: DIGEST, signer: DIGEST, item: NAME, run: NAME,
  scorer: /^[a-z0-9][a-z0-9-]{0,63}$/,
  scorer_version: /^[A-Za-z0-9_.:+/-]{1,160}$/,
  score: SCORE, threshold: SCORE,
  created_at: /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/,
};
const encoder = new TextEncoder();

function fail(code: string, message: string): never {
  throw new TineError(message, `eval-verdict.${code}`);
}

/** A canonical score string as millionths, so the comparison is exact. */
function micros(text: string): number {
  const [whole, frac = ""] = text.split(".");
  return Number(whole) * 1_000_000 + Number((frac + "000000").slice(0, 6));
}

function body(verdict: JValue): JObject {
  if (!isObject(verdict) || verdict.get("scheme") !== EVAL_VERDICT_SCHEME) fail("malformed", "not a tine-eval-verdict/1 object");
  const keys = [...verdict.keys()];
  if (keys.some((key) => key !== "signature" && !FIELDS.includes(key)) || FIELDS.some((key) => !verdict.has(key))) {
    fail("malformed", "a verdict has exactly the tine-eval-verdict/1 fields");
  }
  const out: JObject = new Map(FIELDS.map((name) => [name, verdict.get(name) as JValue]));
  for (const [name, pattern] of Object.entries(PATTERNS)) {
    const value = out.get(name);
    if (typeof value !== "string" || !pattern.test(value)) fail("malformed", `${name} is malformed`);
  }
  const judge = out.get("judge_run");
  if (typeof out.get("passed") !== "boolean" || !(judge === "" || (typeof judge === "string" && NAME.test(judge)))) {
    fail("malformed", "passed or judge_run is malformed");
  }
  return out;
}

export interface EvalVerdictResult {
  item: string;
  passed: boolean;
  signer: string;
}

/** Verify one verdict; with `publicKey` it must be the signing key, else the embedded key is trusted. */
export function verifyEvalVerdict(verdict: JValue, publicKey?: Uint8Array): EvalVerdictResult {
  const checked = body(verdict);
  const block = (verdict as JObject).get("signature");
  const raw = isObject(block) ? block.get("public_key") : undefined;
  const embedded = typeof raw === "string" && /^[0-9a-f]{64}$/.test(raw) ? Uint8Array.from(Buffer.from(raw, "hex")) : new Uint8Array();
  if (embedded.length !== 32 || `sha256:${sha256Hex(embedded)}` !== checked.get("signer")) {
    fail("bad-signature", "the signing key is not the signer");
  }
  if (publicKey && Buffer.compare(Buffer.from(publicKey), Buffer.from(embedded)) !== 0) {
    fail("wrong-key", "signed by a key other than the trusted one");
  }
  if (!isObject(block) || block.get("alg") !== "ed25519") fail("bad-signature", "Ed25519 only");
  const result = verifyBlock(
    block,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", checked],
        ["header", new Map(["alg", "key_id", "scheme", "signed_at", "signer"].map((key) => [key, header.get(key) ?? null]))],
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
    { publicKey: embedded },
  );
  if (!result.ok) fail("bad-signature", `signature ${result.state}: ${result.reason}`);
  const passed = checked.get("passed") as boolean;
  if (passed !== micros(checked.get("score") as string) >= micros(checked.get("threshold") as string)) {
    fail("inconsistent", "passed disagrees with score");
  }
  if ((checked.get("scorer") === "llm-judge") !== (checked.get("judge_run") !== "")) {
    fail("judge-mismatch", "an llm-judge verdict, and only one, names a judge_run");
  }
  return { item: checked.get("item") as string, passed, signer: checked.get("signer") as string };
}

export interface EvalReport {
  schema: "opentine-verify-eval/1";
  file: string;
  ok: boolean;
  verdicts: number;
  verified: number;
  passed: number;
  evals: string[];
  failures: { line: number; reason: string; detail: string }[];
}

/** Every verdict of a `verdicts.jsonl`; one eval id across the file. */
export function verifyEvalFile(file: string, publicKey?: Uint8Array): EvalReport {
  const lines = readFileSync(file, "utf8").split("\n").filter((line) => line.trim());
  const failures: EvalReport["failures"] = [];
  const evals = new Set<string>();
  let verified = 0;
  let passed = 0;
  lines.forEach((line, index) => {
    try {
      const value = parseText(line, KERNEL);
      const found = verifyEvalVerdict(value, publicKey);
      evals.add((value as JObject).get("eval") as string);
      verified += 1;
      passed += found.passed ? 1 : 0;
    } catch (exc) {
      const code = exc instanceof TineError && exc.code ? exc.code : "eval-verdict.malformed";
      failures.push({ line: index + 1, reason: code, detail: (exc as Error).message });
    }
  });
  const ok = lines.length > 0 && !failures.length && evals.size === 1;
  return { schema: "opentine-verify-eval/1", file, ok, verdicts: lines.length, verified, passed, evals: [...evals], failures };
}
