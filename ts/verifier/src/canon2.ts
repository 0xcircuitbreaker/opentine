/**
 * SPEC 0.3: the legacy canonicalizer of formats v1-v3, `opentine._canon.
 * _canonical_bytes`: CPython `json.dumps(sort_keys=True, separators=(",", ":"))`
 * with `ensure_ascii` over `_jsonable`. It is what `tine-sig/1`, `tine-sig/2`,
 * `tine-attest/1`, `tine-actions/1` and the v1/v2 integrity digest sign or hash.
 *
 * It differs from RFC 8785 (`canon.ts`) on purpose and forever: non-ASCII is
 * escaped, floats are spelled as CPython's `repr`, integers are unbounded, and
 * lone surrogates are written as escapes rather than refused.
 */

import { TineError } from "./errors.js";
import { codePointCompare, isObject, type JValue } from "./json.js";

export const MAX_CANONICAL_DEPTH = 768;

/** CPython `float.__repr__`: shortest round-trip digits, `repr`'s layout. */
export function pyFloatRepr(value: number): string {
  if (Number.isNaN(value) || !Number.isFinite(value)) {
    throw new TineError("canonical JSON forbids NaN and infinity", "canon.non-finite");
  }
  if (value === 0) return Object.is(value, -0) ? "-0.0" : "0.0";
  const [mantissa, exponentText] = Math.abs(value).toExponential().split("e");
  const exponent = Number(exponentText);
  const digits = mantissa.replace(".", "");
  const sign = value < 0 ? "-" : "";
  if (exponent < -4 || exponent >= 16) {
    const body = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const magnitude = String(Math.abs(exponent)).padStart(2, "0");
    return `${sign}${body}e${exponent < 0 ? "-" : "+"}${magnitude}`;
  }
  if (exponent < 0) return `${sign}0.${"0".repeat(-exponent - 1)}${digits}`;
  const whole = digits.slice(0, exponent + 1).padEnd(exponent + 1, "0");
  const fraction = digits.slice(exponent + 1);
  return `${sign}${whole}.${fraction || "0"}`;
}

/** CPython `json.dumps(..., ensure_ascii=True)` of a str. */
export function asciiString(text: string): string {
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    const ch = text[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (unit < 0x20 || unit > 0x7e) out += "\\u" + unit.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function encode(value: JValue, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new TineError(`value nesting exceeds the ${MAX_CANONICAL_DEPTH}-level limit`, "canon.depth-exceeded");
  }
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") return pyFloatRepr(value);
  if (typeof value === "string") return asciiString(value);
  if (Array.isArray(value)) return "[" + value.map((item) => encode(item, depth + 1)).join(",") + "]";
  if (isObject(value)) {
    const keys = [...value.keys()].sort(codePointCompare);
    return "{" + keys.map((key) => asciiString(key) + ":" + encode(value.get(key) as JValue, depth + 1)).join(",") + "}";
  }
  throw new TineError("value is not JSON", "canon.unencodable-text");
}

/** `_canonical_bytes`: the legacy canonical text (always ASCII) as bytes. */
export function canonicalBytesV2(value: JValue): Uint8Array {
  return Buffer.from(encode(value, 0), "latin1");
}
