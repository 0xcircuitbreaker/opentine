/**
 * SPEC 0.2: RFC 8785 (JCS) canonical JSON, the v3/v4 canonicalizer.
 *
 * - integers: decimal, |n| <= 2**53-1, anything wider is refused;
 * - doubles: ECMAScript Number.prototype.toString (which is what `String(x)`
 *   is), -0 as "0", NaN and infinities refused;
 * - strings: `"`, `\\` and C0 controls escaped (\b \f \n \r \t, else \u00xx),
 *   everything else literal UTF-8; an unpaired surrogate is refused;
 * - object members sorted by UTF-16 code units, which is JavaScript's own `<`;
 * - at most 512 nested containers.
 */

import { TineError } from "./errors.js";
import { hasLoneSurrogate, isObject, MAX_SAFE, type JValue } from "./json.js";

export const MAX_JSON_DEPTH = 512;

const encoder = new TextEncoder();

export function canonString(value: string): string {
  if (hasLoneSurrogate(value)) {
    throw new TineError("canonical JSON nesting or Unicode key is invalid", "canon.unencodable-text");
  }
  let out = '"';
  let chunk = 0;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0x20 && code !== 0x22 && code !== 0x5c) continue;
    out += value.slice(chunk, i);
    chunk = i + 1;
    switch (code) {
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += "\\\\";
        break;
      case 0x08:
        out += "\\b";
        break;
      case 0x0c:
        out += "\\f";
        break;
      case 0x0a:
        out += "\\n";
        break;
      case 0x0d:
        out += "\\r";
        break;
      case 0x09:
        out += "\\t";
        break;
      default:
        out += "\\u" + code.toString(16).padStart(4, "0");
    }
  }
  return out + value.slice(chunk) + '"';
}

export function canonNumber(value: bigint | number): string {
  if (typeof value === "bigint") {
    if (value > MAX_SAFE || value < -MAX_SAFE) {
      throw new TineError(
        "canonical JSON integer exceeds 2**53-1; encode big ints as strings",
        "canon.integer-overflow",
      );
    }
    return value.toString();
  }
  if (!Number.isFinite(value)) {
    throw new TineError("canonical JSON forbids NaN and infinity", "canon.non-finite");
  }
  return String(value); // ECMAScript Number::toString; -0 already prints "0"
}

function compareUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The canonical text of *value*; iterative, so depth is bounded by the rule, not the stack. */
export function canonicalText(value: JValue): string {
  const out: string[] = [];
  type Item = { v: JValue; depth: number } | string;
  const stack: Item[] = [{ v: value, depth: 0 }];
  while (stack.length) {
    const item = stack.pop() as Item;
    if (typeof item === "string") {
      out.push(item);
      continue;
    }
    const { v, depth } = item;
    if (v === null) out.push("null");
    else if (v === true) out.push("true");
    else if (v === false) out.push("false");
    else if (typeof v === "string") out.push(canonString(v));
    else if (typeof v === "bigint" || typeof v === "number") out.push(canonNumber(v));
    else {
      if (depth >= MAX_JSON_DEPTH) {
        throw new TineError(`canonical JSON nesting exceeds ${MAX_JSON_DEPTH} levels`, "canon.depth-exceeded");
      }
      const seq: Item[] = [];
      if (Array.isArray(v)) {
        seq.push("[");
        v.forEach((child, index) => {
          if (index) seq.push(",");
          seq.push({ v: child, depth: depth + 1 });
        });
        seq.push("]");
      } else if (isObject(v)) {
        const keys = [...v.keys()];
        for (const key of keys) {
          if (hasLoneSurrogate(key)) {
            throw new TineError("canonical JSON nesting or Unicode key is invalid", "canon.unencodable-text");
          }
        }
        keys.sort(compareUnits);
        seq.push("{");
        keys.forEach((key, index) => {
          if (index) seq.push(",");
          seq.push(canonString(key) + ":");
          seq.push({ v: v.get(key) as JValue, depth: depth + 1 });
        });
        seq.push("}");
      } else {
        throw new TineError("unsupported canonical JSON type", "canon.unsupported");
      }
      for (let i = seq.length - 1; i >= 0; i--) stack.push(seq[i]);
    }
  }
  return out.join("");
}

export function canonicalJson(value: JValue): Uint8Array {
  return encoder.encode(canonicalText(value));
}

/** SPEC 0.5: the byte scanner every JSON body passes before it is parsed. */
export function validateJsonShape(raw: Uint8Array, maxTokens = 200_000): void {
  if (raw.includes(0)) throw new TineError("JSON body is not UTF-8 text", "shape.not-utf8");
  let depth = 0;
  let tokens = 0;
  let inString = false;
  let escaped = false;
  for (const byte of raw) {
    if (inString) {
      if (escaped) escaped = false;
      else {
        escaped = byte === 0x5c;
        inString = byte !== 0x22;
      }
      continue;
    }
    if (byte === 0x22) inString = true;
    else if (byte === 0x5b || byte === 0x7b) {
      depth++;
      tokens++;
    } else if (byte === 0x2c || byte === 0x3a || byte === 0x5d || byte === 0x7d) {
      tokens++;
      if (byte === 0x5d || byte === 0x7d) depth--;
    }
    if (depth > MAX_JSON_DEPTH || tokens > maxTokens) {
      throw new TineError("JSON structure exceeds semantic parser limits", "shape.tokens-exceeded");
    }
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
