/**
 * SPEC 3.5: the unkeyed integrity digest of format v1/v2 artifacts, SHA-256
 * over the legacy canonical body without `metadata`, and its verdict. Ports
 * of `opentine._canon._integrity_digest` and `_graph_serde.verify_integrity`.
 */

import { isV4Artifact, verifyV4 } from "./artifact.js";
import { canonicalBytesV2 } from "./canon2.js";
import { sha256Hex } from "./crypto.js";
import { isInt, isObject, pyRepr, type JObject, type JValue } from "./json.js";
import { asV4, isV5Artifact } from "./v5.js";

export const FORMAT_VERSION = 2n;
export const SUPPORTED_VERSIONS = [1n, 2n];

export interface IntegrityResult {
  ok: boolean;
  algorithm: string | null;
  expected: JValue;
  actual: string | null;
  reason: string;
}

/** `_integrity_digest`: the digest of every top-level key but `metadata`. */
export function integrityDigest(data: JObject): string {
  const body: JObject = new Map([...data].filter(([key]) => key !== "metadata"));
  return sha256Hex(canonicalBytesV2(body));
}

/** Python `str()` of a JSON value, as the verdict spells a foreign algorithm. */
function pyStr(value: JValue | undefined): string {
  if (typeof value === "string") return value;
  if (typeof value === "number") return pyRepr(value);
  return pyRepr(value ?? null);
}

/** Python `int(text, 16)` accepts it (whitespace, a sign, `0x`, single underscores). */
function pyHexInt(text: string): boolean {
  return /^\s*[+-]?(?:0[xX]_?)?[0-9a-fA-F](?:_?[0-9a-fA-F])*\s*$/.test(text);
}

/** `verify_integrity` over an already parsed artifact. */
export function verifyIntegrity(data: JValue): IntegrityResult {
  const result = (ok: boolean, algorithm: string | null, expected: JValue, actual: string | null, reason: string) => ({
    ok,
    algorithm,
    expected,
    actual,
    reason,
  });
  if (!isObject(data)) return result(false, null, null, null, "artifact root is not an object");
  const modern: boolean = isV4Artifact(data) || isV5Artifact(data);
  if (modern) {
    const verdict = verifyV4(asV4(data));
    return result(verdict.ok, "sha256", verdict.root, verdict.ok ? verdict.root : null, verdict.reason);
  }
  const version = data.get("format_version");
  if (!isInt(version) || !SUPPORTED_VERSIONS.includes(version)) {
    const found = version === undefined || version === null ? "'missing'" : pyRepr(version);
    let reason = `unsupported .tine format_version=${found}; supported (1, 2)`;
    if (isInt(version) && version > FORMAT_VERSION) {
      reason = `unsupported .tine format_version=${version}; written by a newer opentine`;
    }
    return result(false, null, null, null, reason);
  }
  const metadata = data.get("metadata");
  const integrity = isObject(metadata) ? metadata.get("integrity") : undefined;
  if (!isObject(integrity)) return result(false, null, null, null, "missing integrity digest");
  const algorithm = integrity.get("algorithm");
  const expected = integrity.has("digest") ? (integrity.get("digest") as JValue) : null;
  if (algorithm !== "sha256") return result(false, pyStr(algorithm), expected, null, "unsupported algorithm");
  if (typeof expected !== "string" || expected.length !== 64 || !pyHexInt(expected)) {
    return result(false, "sha256", expected, null, "malformed digest");
  }
  let actual: string | null;
  try {
    actual = integrityDigest(data);
  } catch {
    actual = null;
  }
  return result(actual === expected, "sha256", expected, actual, actual === expected ? "ok" : "digest mismatch");
}
