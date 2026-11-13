/**
 * The slice of Node's `Buffer` the verifier uses (hex, base64, base64url,
 * latin1 and utf8 conversions, compare, concat, alloc, readBigUInt64BE),
 * injected as the global `Buffer` into the browser bundle. Base64 decoding is
 * strict about the alphabet but, like Node, tolerant of missing padding: the
 * verifier re-encodes and compares wherever canonical base64 matters.
 */

type Encoding = "hex" | "base64" | "base64url" | "latin1" | "binary" | "ascii" | "utf8" | "utf-8";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function fromBase64(text: string, url: boolean): Uint8Array {
  let b64 = url ? text.replace(/-/g, "+").replace(/_/g, "/") : text;
  b64 = b64.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(b64) || b64.length % 4 === 1) {
    b64 = b64.replace(/[^A-Za-z0-9+/]/g, "");
  }
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// @ts-expect-error -- like Node's, this `from` takes an encoding where Uint8Array.from takes a map function
export class Buffer extends Uint8Array {
  static from(value: string | ArrayLike<number> | ArrayBufferLike | Iterable<number>, encoding?: Encoding): Buffer {
    if (typeof value !== "string") {
      const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : Uint8Array.from(value as ArrayLike<number>);
      const out = new Buffer(bytes.length);
      out.set(bytes);
      return out;
    }
    let bytes: Uint8Array;
    switch (encoding ?? "utf8") {
      case "hex": {
        const even = value.length - (value.length % 2);
        bytes = new Uint8Array(even / 2);
        for (let i = 0; i < bytes.length; i++) {
          const byte = parseInt(value.slice(2 * i, 2 * i + 2), 16);
          if (Number.isNaN(byte)) {
            bytes = bytes.subarray(0, i);
            break;
          }
          bytes[i] = byte;
        }
        break;
      }
      case "base64":
        bytes = fromBase64(value, false);
        break;
      case "base64url":
        bytes = fromBase64(value, true);
        break;
      case "latin1":
      case "binary":
      case "ascii":
        bytes = Uint8Array.from(value, (c) => c.charCodeAt(0) & 0xff);
        break;
      default:
        bytes = encoder.encode(value);
    }
    return Buffer.from(bytes);
  }

  static alloc(size: number, fill?: number | Uint8Array): Buffer {
    const out = new Buffer(size);
    if (fill !== undefined) out.fill(fill);
    return out;
  }

  /** Node's `buf.copy(target, targetStart, sourceStart, sourceEnd)`; returns the bytes copied. */
  copy(target: Uint8Array, targetStart = 0, sourceStart = 0, sourceEnd = this.length): number {
    const part = this.subarray(sourceStart, Math.min(sourceEnd, sourceStart + target.length - targetStart));
    target.set(part, targetStart);
    return part.length;
  }

  /** Node's `fill`: a byte, or a repeated byte pattern. */
  override fill(value: number | Uint8Array, start = 0, end = this.length): this {
    if (typeof value === "number") return super.fill(value, start, end);
    if (value.length === 0) return super.fill(0, start, end);
    for (let at = start; at < end; at += value.length) this.set(value.subarray(0, Math.min(value.length, end - at)), at);
    return this;
  }

  static concat(list: readonly Uint8Array[]): Buffer {
    const out = new Buffer(list.reduce((total, part) => total + part.length, 0));
    let at = 0;
    for (const part of list) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  static compare(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  }

  override toString(encoding?: Encoding): string {
    switch (encoding ?? "utf8") {
      case "hex":
        return Array.from(this, (b) => b.toString(16).padStart(2, "0")).join("");
      case "base64":
        return toBase64(this);
      case "base64url":
        return toBase64(this).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      case "latin1":
      case "binary":
        return Array.from(this, (b) => String.fromCharCode(b)).join("");
      default:
        return decoder.decode(this);
    }
  }

  readBigUInt64BE(offset = 0): bigint {
    return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(offset, false);
  }
}
