/**
 * SPEC 4.19 `opentine.forge-claim` (0.47): an upstream's own, unsigned
 * `.opentine/project` file, matched against a project's id, tenant, default
 * branch and genesis fingerprint. A port of `opentine._forge_claim.check`.
 * It never reports a pass: a match is `claimed-as-mirrored`. Refusals carry
 * `forge-claim.*` codes. SHA-256 only, through `./crypto.js`.
 */

import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";

const KEYS = ["kind", "claim_version", "project_id", "tenant", "fingerprint"];
export const CLAIM_LABEL = "claimed by upstream (as mirrored)";
const RULES: [string, RegExp][] = [
  ["project_id", /^[a-z0-9][a-z0-9._-]{0,63}$/],
  ["tenant", /^[a-z0-9][a-z0-9._-]{0,127}$/],
  ["fingerprint", /^sha256:[0-9a-f]{64}$/],
];

function no(code: string, message: string): never {
  throw new TineError(message, `forge-claim.${code}`);
}

export function claimFingerprint(genesis: JValue): string {
  if (typeof genesis !== "string" || !/^blob:sha256:[0-9a-f]{64}$/.test(genesis)) {
    no("malformed", "forge claim is malformed: genesis is not a blob digest");
  }
  return "sha256:" + sha256Hex(new TextEncoder().encode("opentine.forge-claim.v1:" + genesis));
}

export interface ForgeClaimResult {
  project_id: string;
  tenant: string;
  fingerprint: string;
  branch: string;
  state: "claimed-as-mirrored";
  label: string;
}

export function verifyForgeClaim(claim: JValue, branch: JValue, project: JValue): ForgeClaimResult {
  if (claim === null) no("missing", "no forge claim: the upstream holds no .opentine/project");
  if (!isObject(claim) || claim.get("kind") !== "opentine.forge-claim") {
    no("malformed", "forge claim is malformed: wrong kind or set of fields");
  }
  const record = claim as JObject;
  const keys = [...record.keys()].sort();
  if (keys.length !== KEYS.length || !KEYS.every((key) => record.has(key))) {
    no("malformed", "forge claim is malformed: wrong kind or set of fields");
  }
  const version = record.get("claim_version");
  if (!(typeof version === "bigint" ? version === 1n : version === 1)) {
    no("malformed", "forge claim is malformed: claim_version is not 1");
  }
  for (const [name, pattern] of RULES) {
    const value = record.get(name);
    if (typeof value !== "string" || !pattern.test(value)) no("malformed", `forge claim is malformed: bad ${name}`);
  }
  if (typeof branch !== "string" || !/^[A-Za-z0-9._/-]{1,255}$/.test(branch)) {
    no("malformed", "forge claim is malformed: bad branch");
  }
  const want = project as JObject;
  if (branch !== want.get("default_branch")) {
    no("not-default-branch", `forge claim is only on ${branch}, not the default branch ${String(want.get("default_branch"))}`);
  }
  if (record.get("project_id") !== want.get("project_id") || record.get("tenant") !== want.get("tenant")) {
    no("wrong-project", "forge claim names another project or tenant");
  }
  if (record.get("fingerprint") !== claimFingerprint(want.get("genesis") as JValue)) {
    no("wrong-fingerprint", "forge claim fingerprint names another project");
  }
  return {
    project_id: record.get("project_id") as string,
    tenant: record.get("tenant") as string,
    fingerprint: record.get("fingerprint") as string,
    branch,
    state: "claimed-as-mirrored",
    label: CLAIM_LABEL,
  };
}
