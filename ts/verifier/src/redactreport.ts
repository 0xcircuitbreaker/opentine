/**
 * SPEC 4.13 `opentine.redaction-report`: one signed re-scan of a run. A port of
 * `opentine._redact_report.check`: exactly the report fields, a `tine-sig/3`
 * block over `opentine.redaction-report.v1:` + JCS of `{"body", "header"}`
 * (HMAC-SHA256, or Ed25519 under the trusted key or, without one, the embedded
 * key: trust on first use), and `clean` must equal "no findings". Refusals
 * carry `redaction-report.*` codes.
 */

import { canonicalJson } from "./canon.js";
import { TineError } from "./errors.js";
import { isObject, type JObject, type JValue } from "./json.js";
import { SCHEME_V3 } from "./artifact.js";
import { HEADER_KEYS, verifyBlock, type Header, type VerifyKeys } from "./signature.js";

export const REPORT_KIND = "opentine.redaction-report";
const DOMAIN = "opentine.redaction-report.v1:";
const FIELDS = ["kind", "report_version", "ruleset", "run", "objects", "findings", "clean"];
const NAME = /^[A-Za-z0-9_.:/@+-]{1,256}$/;
const encoder = new TextEncoder();

function fail(code: string, message: string): never {
  throw new TineError(message, `redaction-report.${code}`);
}

function malformed(message: string): never {
  fail("malformed", `redaction report is malformed: ${message}`);
}

function count(value: JValue | undefined): number | null {
  if (typeof value === "bigint") return value >= 0n && value < 2n ** 53n ? Number(value) : null;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  return null;
}

function body(report: JValue): JObject {
  if (!isObject(report) || report.get("kind") !== REPORT_KIND) malformed(`kind is not ${REPORT_KIND}`);
  const keys = [...report.keys()];
  if (keys.some((key) => key !== "signature" && !FIELDS.includes(key)) || FIELDS.some((key) => !report.has(key))) {
    malformed("a report has exactly the redaction report fields");
  }
  const out: JObject = new Map(FIELDS.map((name) => [name, report.get(name) as JValue]));
  if (count(out.get("report_version")) !== 1) malformed("report_version must be 1");
  for (const name of ["ruleset", "run"]) {
    const value = out.get(name);
    if (typeof value !== "string" || !NAME.test(value)) malformed(`${name} must be a name`);
  }
  const objects = count(out.get("objects"));
  if (objects === null) malformed("objects must be a count");
  const findings = out.get("findings");
  if (!Array.isArray(findings) || findings.length > objects) malformed("findings must be a list no longer than objects");
  for (const hit of findings) {
    const ok =
      isObject(hit) &&
      hit.size === 2 &&
      ["oid", "kind"].every((key) => typeof hit.get(key) === "string" && NAME.test(hit.get(key) as string));
    if (!ok) malformed("each finding is {oid, kind}");
  }
  if (typeof out.get("clean") !== "boolean") malformed("clean must be a boolean");
  return out;
}

export interface ReportResult {
  run: string;
  clean: boolean;
  objects: number;
  findings: number;
  state: string;
}

/** Verify one report under `hmacKey`, a trusted Ed25519 `publicKey`, or (Ed25519 only) its embedded key. */
export function verifyRedactionReport(
  report: JValue,
  hmacKey?: Uint8Array | null,
  publicKey?: Uint8Array | null,
): ReportResult {
  const checked = body(report);
  const block = (report as JObject).get("signature");
  if (block === undefined || block === null) fail("unsigned", "the redaction report is unsigned");
  if (!isObject(block)) fail("bad-signature", "the report signature is not a block");
  const algorithm = block.get("alg");
  if (algorithm === "hmac-sha256" && hmacKey == null) fail("no-key", "no key for an hmac-sha256 report");
  if (publicKey != null) {
    if (algorithm !== "ed25519") fail("wrong-key", "not the trusted key's algorithm");
    if (block.get("public_key") !== Buffer.from(publicKey).toString("hex")) {
      fail("wrong-key", "signed by a key that is not the trusted key");
    }
  }
  const keys: VerifyKeys =
    algorithm === "hmac-sha256" ? { hmacKey } : publicKey != null ? { publicKey } : { trustEmbedded: true };
  const result = verifyBlock(
    block,
    (header: Header) => {
      const view: JObject = new Map<string, JValue>([
        ["body", checked],
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
    "redaction report",
    keys,
  );
  if (!result.ok) fail("bad-signature", `the report signature does not hold (${result.state}: ${result.reason})`);
  const findings = checked.get("findings") as JValue[];
  if (checked.get("clean") !== (findings.length === 0)) fail("inconsistent", "clean disagrees with the findings");
  return {
    run: checked.get("run") as string,
    clean: checked.get("clean") as boolean,
    objects: count(checked.get("objects")) as number,
    findings: findings.length,
    state: result.state,
  };
}
