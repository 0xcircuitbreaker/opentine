/**
 * The JSON value model and the byte-level parser every reader in this package uses.
 *
 * SPEC 0.2 distinguishes integers from doubles, so the model does too: an integer
 * is a `bigint`, a double is a `number`, and an object is a `Map` (insertion
 * order kept, no prototype keys, no integer-key reordering).
 */

import { TineError } from "./errors.js";

export type JValue = null | boolean | string | bigint | number | JValue[] | JObject;
export type JObject = Map<string, JValue>;

export const MAX_SAFE = 9007199254740991n;

export function isObject(value: unknown): value is JObject {
  return value instanceof Map;
}

export function isInt(value: unknown): value is bigint {
  return typeof value === "bigint";
}

/** Python truthiness, which several SPEC rules are written in terms of. */
export function truthy(value: JValue | undefined): boolean {
  if (value === undefined || value === null || value === false) return false;
  if (typeof value === "bigint") return value !== 0n;
  if (typeof value === "number") return value !== 0; // NaN is truthy in Python
  if (typeof value === "string") return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return isObject(value) ? value.size > 0 : true;
}

/** Python `==` over the value model (int 1 equals double 1.0). */
export function pyEqual(a: JValue | undefined, b: JValue | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  const num = (v: JValue) => typeof v === "bigint" || typeof v === "number" || typeof v === "boolean";
  if (num(a) && num(b)) {
    const x = typeof a === "boolean" ? (a ? 1n : 0n) : a;
    const y = typeof b === "boolean" ? (b ? 1n : 0n) : b;
    if (typeof x === "bigint" && typeof y === "bigint") return x === y;
    if (typeof x === "number" && typeof y === "number") return x === y;
    const [i, f] = typeof x === "bigint" ? [x, y as number] : [y as bigint, x as number];
    return Number.isInteger(f) && BigInt(f) === i;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((item, index) => pyEqual(item, b[index]));
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b) || a.size !== b.size) return false;
    for (const [key, item] of a) if (!b.has(key) || !pyEqual(item, b.get(key))) return false;
    return true;
  }
  return a === b;
}

/** Python `repr` of a str, as error messages spell it. */
export function pyRepr(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") return Number.isInteger(value) ? value.toFixed(1) : String(value);
  if (typeof value !== "string") return "<value>";
  const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0) as number;
    if (ch === quote || ch === "\\") out += "\\" + ch;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20 || code === 0x7f) out += "\\x" + code.toString(16).padStart(2, "0");
    else if (code >= 0xd800 && code <= 0xdfff) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return quote + out + quote;
}

/** Code-point order, what Python's `sorted()` gives a list of str. */
export function codePointCompare(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = (x[i].codePointAt(0) as number) - (y[i].codePointAt(0) as number);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

export function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return true;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return true;
  }
  return false;
}

/** Whether any string or key anywhere in *value* holds an unpaired surrogate. */
export function containsLoneSurrogate(value: JValue): boolean {
  const stack: JValue[] = [value];
  while (stack.length) {
    const item = stack.pop() as JValue;
    if (typeof item === "string") {
      if (hasLoneSurrogate(item)) return true;
    } else if (Array.isArray(item)) {
      stack.push(...item);
    } else if (isObject(item)) {
      for (const [key, child] of item) {
        if (hasLoneSurrogate(key)) return true;
        stack.push(child);
      }
    }
  }
  return false;
}

// --------------------------------------------------------------------------- //
// UTF-8 decoding, the way CPython's json.loads(bytes) does it
// --------------------------------------------------------------------------- //

/**
 * Decode UTF-8 strictly. A leading BOM is dropped (CPython reads bytes with
 * `utf-8-sig`). Raw CESU-8 surrogate bytes (ED A0..BF) decode, under CPython's
 * `surrogatepass`, to a lone surrogate no reader may accept; they are refused
 * here with that reason so the caller can tell the two failures apart.
 */
export function decodeUtf8(raw: Uint8Array, where: string): string {
  let start = 0;
  if (raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) start = 3;
  for (let i = start; i + 1 < raw.length; i++) {
    if (raw[i] === 0xed && raw[i + 1] >= 0xa0 && raw[i + 1] <= 0xbf) {
      throw new TineError(`${where} holds an unpaired UTF-16 surrogate`, "text.lone-surrogate");
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw.subarray(start));
  } catch {
    throw new TineError(`${where} is not valid UTF-8`, "malformed");
  }
}

// --------------------------------------------------------------------------- //
// The parser
// --------------------------------------------------------------------------- //

export interface ParseOptions {
  /** "reject" (the `.tine` reader) or "last" (CPython's default, last wins). */
  duplicates: "reject" | "last";
  /** Accept CPython's NaN / Infinity / -Infinity extensions. */
  constants: boolean;
  /**
   * "big": every integer literal is a bigint. "safe": a literal beyond 2**53-1
   * becomes a double (kernel._parse_int). "bounded": at most 4096 digits.
   */
  integers: "big" | "safe" | "bounded";
  /** Refuse a double literal that overflows to infinity (`.tine` finite_float). */
  finiteFloats: boolean;
}

export const STRICT: ParseOptions = {
  duplicates: "reject",
  constants: false,
  integers: "bounded",
  finiteFloats: true,
};
export const LENIENT: ParseOptions = {
  duplicates: "last",
  constants: true,
  integers: "big",
  finiteFloats: false,
};
export const KERNEL: ParseOptions = { ...LENIENT, integers: "safe" };

export const MAX_INTEGER_DIGITS = 4096;

class Parser {
  pos = 0;
  constructor(
    readonly text: string,
    readonly options: ParseOptions,
  ) {}

  fail(message: string, code = "malformed"): never {
    throw new TineError(`${message} at char ${this.pos}`, code);
  }

  ws(): void {
    const t = this.text;
    while (this.pos < t.length) {
      const c = t.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else break;
    }
  }

  document(): JValue {
    this.ws();
    const value = this.value();
    this.ws();
    if (this.pos !== this.text.length) this.fail("Extra data");
    return value;
  }

  value(): JValue {
    // Iterative over containers: depth is bounded by the caller's shape scan, but
    // an explicit stack keeps this parser's limit independent of the JS stack.
    type Frame = { kind: "a"; items: JValue[] } | { kind: "o"; map: JObject; key: string };
    const stack: Frame[] = [];
    let current: JValue;
    for (;;) {
      this.ws();
      const c = this.text[this.pos];
      if (c === "[") {
        this.pos++;
        this.ws();
        if (this.text[this.pos] === "]") {
          this.pos++;
          current = [];
        } else {
          stack.push({ kind: "a", items: [] });
          continue;
        }
      } else if (c === "{") {
        this.pos++;
        this.ws();
        if (this.text[this.pos] === "}") {
          this.pos++;
          current = new Map();
        } else {
          const key = this.key();
          stack.push({ kind: "o", map: new Map(), key });
          continue;
        }
      } else {
        current = this.scalar();
      }
      // Attach the completed value to its parents, closing as many as end here.
      for (;;) {
        const top = stack[stack.length - 1];
        if (!top) return current;
        if (top.kind === "a") top.items.push(current);
        else {
          if (top.map.has(top.key)) {
            if (this.options.duplicates === "reject") {
              this.fail(`duplicate object key: ${pyRepr(top.key.slice(0, 80))}`, "duplicate-key");
            }
            top.map.delete(top.key); // last wins, keeping CPython's dict position
            top.map.set(top.key, current);
          } else top.map.set(top.key, current);
        }
        this.ws();
        const next = this.text[this.pos];
        if (next === ",") {
          this.pos++;
          if (top.kind === "o") {
            this.ws();
            top.key = this.key();
          }
          break;
        }
        if (top.kind === "a" && next === "]") {
          this.pos++;
          stack.pop();
          current = top.items;
          continue;
        }
        if (top.kind === "o" && next === "}") {
          this.pos++;
          stack.pop();
          current = top.map;
          continue;
        }
        this.fail("Expecting ',' delimiter");
      }
    }
  }

  key(): string {
    if (this.text[this.pos] !== '"') this.fail("Expecting property name enclosed in double quotes");
    const key = this.string();
    this.ws();
    if (this.text[this.pos] !== ":") this.fail("Expecting ':' delimiter");
    this.pos++;
    return key;
  }

  scalar(): JValue {
    const t = this.text;
    const c = t[this.pos];
    if (c === '"') return this.string();
    if (t.startsWith("null", this.pos)) {
      this.pos += 4;
      return null;
    }
    if (t.startsWith("true", this.pos)) {
      this.pos += 4;
      return true;
    }
    if (t.startsWith("false", this.pos)) {
      this.pos += 5;
      return false;
    }
    for (const [word, value] of [
      ["NaN", NaN],
      ["Infinity", Infinity],
      ["-Infinity", -Infinity],
    ] as const) {
      if (t.startsWith(word, this.pos)) {
        if (!this.options.constants) this.fail(`non-finite number: ${word}`, "non-finite");
        this.pos += word.length;
        return value;
      }
    }
    const match = /^(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?/.exec(t.slice(this.pos, this.pos + 8192));
    if (!match || match[0].length === 0) this.fail("Expecting value");
    let literal = match[0];
    if (literal.length === 8192) {
      // a pathological literal: re-scan without the window
      literal = (/^(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?/.exec(t.slice(this.pos)) as RegExpExecArray)[0];
    }
    this.pos += literal.length;
    const isFloat = literal.includes(".") || literal.includes("e") || literal.includes("E");
    if (isFloat) {
      const value = Number(literal);
      if (this.options.finiteFloats && !Number.isFinite(value)) {
        this.fail(`non-finite number: ${literal}`, "non-finite");
      }
      return value;
    }
    const digits = literal.startsWith("-") ? literal.length - 1 : literal.length;
    if (this.options.integers === "bounded" && digits > MAX_INTEGER_DIGITS) {
      this.fail("integer exceeds the parser limit", "integer-digits");
    }
    if (digits > 4300 && this.options.integers !== "bounded") {
      // CPython's int() refuses more than 4300 digits (sys.int_info)
      this.fail("Exceeds the limit (4300 digits) for integer string conversion");
    }
    const big = BigInt(literal);
    if (this.options.integers === "safe" && (big > MAX_SAFE || big < -MAX_SAFE)) return Number(literal);
    return big;
  }

  string(): string {
    const t = this.text;
    this.pos++; // opening quote
    let out = "";
    let chunk = this.pos;
    for (;;) {
      if (this.pos >= t.length) this.fail("Unterminated string starting");
      const code = t.charCodeAt(this.pos);
      if (code === 0x22) {
        out += t.slice(chunk, this.pos);
        this.pos++;
        return out;
      }
      if (code < 0x20) this.fail("Invalid control character");
      if (code !== 0x5c) {
        this.pos++;
        continue;
      }
      out += t.slice(chunk, this.pos);
      const esc = t[this.pos + 1];
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (esc !== undefined && esc in simple) {
        out += simple[esc];
        this.pos += 2;
      } else if (esc === "u") {
        const hex = t.slice(this.pos + 2, this.pos + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("Invalid \\uXXXX escape");
        out += String.fromCharCode(parseInt(hex, 16));
        this.pos += 6;
      } else this.fail("Invalid \\escape");
      chunk = this.pos;
    }
  }
}

/** Parse decoded JSON text into the value model. */
export function parseText(text: string, options: ParseOptions): JValue {
  return new Parser(text, options).document();
}

/** Parse UTF-8 JSON bytes into the value model. */
export function parseBytes(raw: Uint8Array, options: ParseOptions, where = "JSON document"): JValue {
  return parseText(decodeUtf8(raw, where), options);
}
