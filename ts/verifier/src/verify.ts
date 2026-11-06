/**
 * One file in, one report out: the `.tine` v4 check the CLI prints.
 */

import { readFileSync, statSync } from "node:fs";
import { isV4Artifact, parseArtifactJson, verifyV4 } from "./artifact.js";
import { MAX_TINE_ARTIFACT_BYTES, unwrap } from "./codec.js";
import { TineError } from "./errors.js";
import { isObject } from "./json.js";
import { verifyArtifactV4, type SignatureResult, type VerifyKeys } from "./signature.js";

export const REPORT_SCHEMA = "opentine-verify-ts/1";

export interface Report {
  schema: string;
  path: string;
  /** `pass` only when the content is intact and no signature check failed. */
  verdict: "pass" | "fail";
  ok: boolean;
  format: string | null;
  root: string | null;
  integrity: { ok: boolean; reason: string };
  signature: SignatureResult | null;
}

export function verifyBytes(raw: Uint8Array, path: string, keys: VerifyKeys = {}): Report {
  const report: Report = {
    schema: REPORT_SCHEMA,
    path,
    verdict: "fail",
    ok: false,
    format: null,
    root: null,
    integrity: { ok: false, reason: "" },
    signature: null,
  };
  let data;
  try {
    data = parseArtifactJson(unwrap(raw));
  } catch (exc) {
    if (!(exc instanceof TineError)) throw exc;
    report.integrity.reason = exc.message;
    return report;
  }
  if (!isV4Artifact(data)) {
    const version = isObject(data) ? data.get("format_version") : undefined;
    report.format = typeof version === "bigint" ? `tine/${version}` : null;
    report.integrity.reason =
      "only format v4 (tine-artifact/4) is verified by this build; " +
      "upgrade the file with `tine migrate` or verify it with the Python reader";
    return report;
  }
  report.format = "tine-artifact/4";
  const integrity = verifyV4(data);
  report.root = integrity.root;
  report.integrity = { ok: integrity.ok, reason: integrity.reason };
  report.signature = verifyArtifactV4(data, keys);
  const signatureFailed = report.signature.state === "mismatch" || report.signature.state === "error";
  report.ok = integrity.ok && !signatureFailed;
  report.verdict = report.ok ? "pass" : "fail";
  return report;
}

export function verifyFile(path: string, keys: VerifyKeys = {}): Report {
  const info = statSync(path);
  if (!info.isFile()) throw new TineError(".tine artifact must be a regular file");
  if (info.size > MAX_TINE_ARTIFACT_BYTES) throw new TineError(".tine artifact exceeds the 256 MiB size limit");
  return verifyBytes(readFileSync(path), path, keys);
}
