/**
 * SPEC 4.10 `opentine-delegation/1`: an issuer key hands a scoped, time-boxed
 * authority to a subject key with a `tine-sig/3` Ed25519 block over its own
 * domain. Ports of `opentine._delegation.body` / `digest` and
 * `_delegation_verify.verify_chain`; every refusal carries a `delegation.*` code.
 */

import { canonicalJson } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import { TineError } from "./errors.js";
import { codePointCompare, isInt, isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { verifyBlock, type Header } from "./signature.js";

export const DELEGATION_SCHEME = "opentine-delegation/1";
const DOMAIN = "opentine.delegation.v1:";
const FPR_RE = /^sha256:[0-9a-f]{64}$/;
const NAME_RE = /^[A-Za-z0-9_.:*/-]{1,128}$/;
const FIELDS = ["scheme", "issuer", "subject", "scope", "not_before", "not_after", "parent"];
export const MAX_CHAIN = 8;
const MAX_NAMES = 64;
const encoder = new TextEncoder();
const RFC3339 = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})$/i;

interface Cert {
  issuer: string;
  subject: string;
  scope: { agents: string[]; actions: string[]; max_depth: bigint };
  not_before: string;
  not_after: string;
  parent: string;
  body: JObject;
}

function fail(code: string, message: string): never {
  throw new TineError(message, `delegation.${code}`);
}

/** `_key_lifecycle.parse_time`: an RFC 3339 instant with a zone, as epoch ms. */
export function parseTime(value: JValue | undefined, what: string): number {
  const when = typeof value === "string" && RFC3339.test(value) ? Date.parse(value.replace(" ", "T")) : NaN;
  if (Number.isNaN(when)) fail("malformed", `${what} is not an RFC 3339 time with a zone`);
  return when;
}

function names(value: JValue | undefined, what: string): string[] {
  if (!Array.isArray(value) || !value.length || value.length > MAX_NAMES) {
    fail("malformed", `scope.${what} must be a non-empty list of names`);
  }
  const list = value as JValue[];
  if (!list.every((item) => typeof item === "string" && NAME_RE.test(item))) {
    fail("malformed", `scope.${what} holds a malformed name`);
  }
  const canonical = [...new Set(list as string[])].sort(codePointCompare);
  if (canonical.join("\0") !== (list as string[]).join("\0")) {
    fail("malformed", "scope lists must be sorted and free of duplicates");
  }
  return canonical;
}

/** `_delegation.body`: the signed part of a certificate, field by field. */
function body(cert: JValue): Cert {
  if (!isObject(cert) || cert.get("scheme") !== DELEGATION_SCHEME) {
    fail("malformed", "not an opentine-delegation/1 certificate");
  }
  const value = cert as JObject;
  if ([...value.keys()].some((key) => key !== "signature" && !FIELDS.includes(key))) {
    fail("malformed", "unknown field in delegation certificate");
  }
  const out: JObject = new Map(FIELDS.map((name) => [name, value.has(name) ? (value.get(name) as JValue) : null]));
  for (const name of ["issuer", "subject"]) {
    const item = out.get(name);
    if (typeof item !== "string" || !FPR_RE.test(item)) fail("malformed", `${name} must be sha256: + 64 lower hex`);
  }
  const parent = out.get("parent");
  if (parent !== "" && !(typeof parent === "string" && FPR_RE.test(parent))) {
    fail("malformed", "parent must be empty or sha256: + 64 lower hex");
  }
  const scope = out.get("scope");
  if (!isObject(scope) || scope.size !== 3 || !["agents", "actions", "max_depth"].every((key) => scope.has(key))) {
    fail("malformed", "scope must have exactly agents, actions and max_depth");
  }
  const depth = (scope as JObject).get("max_depth");
  if (!isInt(depth) || depth < 0n || depth >= BigInt(MAX_CHAIN)) {
    fail("malformed", `scope.max_depth must be an integer 0..${MAX_CHAIN - 1}`);
  }
  const agents = names((scope as JObject).get("agents"), "agents");
  const actions = names((scope as JObject).get("actions"), "actions");
  const start = parseTime(out.get("not_before"), "not_before");
  const end = parseTime(out.get("not_after"), "not_after");
  if (end <= start) fail("malformed", "not_after must be later than not_before");
  return {
    issuer: out.get("issuer") as string,
    subject: out.get("subject") as string,
    scope: { agents, actions, max_depth: depth as bigint },
    not_before: out.get("not_before") as string,
    not_after: out.get("not_after") as string,
    parent: parent as string,
    body: out,
  };
}

function prefixed(body: Uint8Array): Uint8Array {
  const head = encoder.encode(DOMAIN);
  const out = new Uint8Array(head.length + body.length);
  out.set(head);
  out.set(body, head.length);
  return out;
}

/** `sha256:` over the domain and JCS of the whole certificate, signature included. */
export function certDigest(cert: JValue): string {
  try {
    return `sha256:${sha256Hex(prefixed(canonicalJson(cert)))}`;
  } catch (exc) {
    return fail("malformed", `certificate cannot be canonicalized: ${(exc as Error).message}`);
  }
}

function checkSignature(cert: JObject, checked: Cert, index: number): void {
  const block = cert.get("signature");
  const raw = isObject(block) ? block.get("public_key") : undefined;
  const embedded = typeof raw === "string" && /^([0-9a-fA-F]{2})*$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.alloc(0);
  if (embedded.length !== 32 || `sha256:${sha256Hex(embedded)}` !== checked.issuer) {
    fail("bad-signature", `certificate ${index}: the signing key is not the named issuer`);
  }
  if (isObject(block) && block.get("alg") !== "ed25519") fail("bad-signature", `certificate ${index}: Ed25519 only`);
  const verdict = verifyBlock(
    block,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", checked.body],
        ["header", new Map(["alg", "key_id", "scheme", "signed_at", "signer"].map((key) => [key, header.get(key) ?? null]))],
      ]);
      return prefixed(canonicalJson(view));
    },
    [SCHEME_V3],
    "document",
    { publicKey: Uint8Array.from(embedded) },
  );
  if (!verdict.ok) fail("bad-signature", `certificate ${index}: signature ${verdict.state}: ${verdict.reason}`);
}

const covers = (parent: string[], child: string[]) => parent.includes("*") || child.every((name) => parent.includes(name));

function narrows(parent: Cert, child: Cert, index: number): void {
  if (parent.scope.max_depth < 1n) fail("too-deep", `certificate ${index}: the parent allows no further delegation`);
  if (child.scope.max_depth > parent.scope.max_depth - 1n) {
    fail("too-deep", `certificate ${index}: max_depth must shrink by at least one per link`);
  }
  for (const name of ["agents", "actions"] as const) {
    if (!covers(parent.scope[name], child.scope[name])) fail("scope-violation", `certificate ${index}: ${name} wider than the parent's`);
  }
  if (
    parseTime(child.not_before, "not_before") < parseTime(parent.not_before, "not_before") ||
    parseTime(child.not_after, "not_after") > parseTime(parent.not_after, "not_after")
  ) {
    fail("scope-violation", `certificate ${index}: validity window wider than the parent's`);
  }
}

export interface DelegationRequest {
  chain: JValue;
  signer: string;
  at: JValue;
  agent?: JValue;
  actions?: string[];
  root?: string | null;
}

/** `verify_chain`: the root issuer and each link's digest, or a `delegation.*` refusal. */
export function verifyDelegation(request: DelegationRequest): { root: string; links: string[] } {
  const chain = request.chain;
  if (!Array.isArray(chain) || !chain.length || chain.length > MAX_CHAIN) {
    fail("malformed", `a chain holds 1..${MAX_CHAIN} certificates`);
  }
  const certs = chain as JValue[];
  const when = parseTime(request.at, "signing time");
  const checked: Cert[] = [];
  certs.forEach((cert, index) => {
    const current = body(cert);
    checkSignature(cert as JObject, current, index);
    if (index === 0) {
      if (current.parent) fail("broken-chain", "certificate 0: the root certificate names a parent");
      if (request.root != null && current.issuer !== request.root) {
        fail("broken-chain", `certificate 0: root issuer is not the trusted ${request.root}`);
      }
    } else {
      const previous = checked[checked.length - 1];
      if (current.issuer !== previous.subject) fail("broken-chain", `certificate ${index}: issuer is not the previous subject`);
      if (current.parent !== certDigest(certs[index - 1])) {
        fail("broken-chain", `certificate ${index}: parent is not the previous certificate`);
      }
      narrows(previous, current, index);
    }
    if (!(parseTime(current.not_before, "not_before") <= when && when < parseTime(current.not_after, "not_after"))) {
      fail("expired", `certificate ${index}: ${String(request.at)} is outside its window`);
    }
    checked.push(current);
  });
  const leaf = checked[checked.length - 1];
  const last = certs.length - 1;
  if (leaf.subject !== request.signer) fail("wrong-signer", `certificate ${last}: subject is not the signer ${request.signer}`);
  const agent = request.agent;
  if (agent !== undefined && agent !== null) {
    const asked = typeof agent === "string" ? [agent] : Array.isArray(agent) ? (agent as string[]) : [];
    if (!asked.some((name) => covers(leaf.scope.agents, [name]))) {
      fail("scope-violation", `certificate ${last}: agent is not delegated`);
    }
  }
  const outside = (request.actions ?? []).filter((action) => !covers(leaf.scope.actions, [action]));
  if (outside.length) fail("scope-violation", `certificate ${last}: actions not delegated: ${outside.join(", ")}`);
  return { root: checked[0].issuer, links: certs.map(certDigest) };
}
