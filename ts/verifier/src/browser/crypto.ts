/**
 * Browser stand-in for the `node:crypto` calls the verifier makes (SHA-256,
 * HMAC-SHA256, timing-safe compare, Ed25519 verify), built on the audited
 * `@noble/hashes` and `@noble/curves`. The browser bundle aliases `node:crypto`
 * here (ts/run-viewer/build-verifier.mjs); Node keeps OpenSSL.
 *
 * Ed25519 verifies with `zip215: false`, the strict RFC 8032 rules OpenSSL
 * applies, so the browser and Node agree on every signature vector.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

const hexOf = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const encoder = new TextEncoder();

function bytesOf(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? encoder.encode(data) : data;
}

class Digest {
  private readonly parts: Uint8Array[] = [];
  constructor(private readonly finish: (data: Uint8Array) => Uint8Array) {}
  update(data: Uint8Array | string): this {
    this.parts.push(bytesOf(data));
    return this;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  digest(encoding?: "hex"): any {
    const size = this.parts.reduce((total, part) => total + part.length, 0);
    const all = new Uint8Array(size);
    let at = 0;
    for (const part of this.parts) {
      all.set(part, at);
      at += part.length;
    }
    const out = this.finish(all);
    return encoding === "hex" ? hexOf(out) : out;
  }
}

function only256(algorithm: string): void {
  if (algorithm !== "sha256") throw new Error(`unsupported hash ${algorithm} in the browser verifier`);
}

export function createHash(algorithm: string): Digest {
  only256(algorithm);
  return new Digest((data) => sha256(data));
}

export function createHmac(algorithm: string, key: Uint8Array): Digest {
  only256(algorithm);
  return new Digest((data) => hmac(sha256, key, data));
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) throw new RangeError("inputs must have the same length");
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

interface PublicKey {
  raw: Uint8Array;
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function createPublicKey(spec: { key: { kty: string; crv: string; x: string } }): PublicKey {
  if (spec.key.kty !== "OKP" || spec.key.crv !== "Ed25519") throw new Error("only Ed25519 keys");
  return { raw: fromBase64Url(spec.key.x) };
}

export function verify(_algorithm: null, message: Uint8Array, key: PublicKey, signature: Uint8Array): boolean {
  return ed25519.verify(signature, message, key.raw, { zip215: false });
}
