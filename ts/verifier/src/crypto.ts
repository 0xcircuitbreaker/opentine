/**
 * The platform primitives: SHA-256, HMAC-SHA256 and Ed25519 verification from
 * Node's built-in `crypto` (OpenSSL), and nothing else.
 */

import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function hmacSha256Hex(key: Uint8Array, message: Uint8Array): string {
  return createHmac("sha256", key).update(message).digest("hex");
}

export function constantTimeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Ed25519 (RFC 8032) verification; any failure, including a bad key, is `false`. */
export function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey).toString("base64url") },
      format: "jwk",
    });
    return verify(null, message, key, signature);
  } catch {
    return false;
  }
}

const P = 2n ** 255n - 19n;

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

const mod = (x: bigint) => ((x % P) + P) % P;
const inv = (x: bigint) => modPow(x, P - 2n, P);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = modPow(2n, (P - 1n) / 4n, P);

function littleEndian(raw: Uint8Array): bigint {
  let value = 0n;
  for (let i = raw.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(raw[i]);
  return value;
}

function decodePoint(raw: Uint8Array): [bigint, bigint] | null {
  const value = littleEndian(raw);
  const sign = value >> 255n;
  const y = value & ((1n << 255n) - 1n);
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * modPow(v, 3n, P) * modPow(mod(u * modPow(v, 7n, P)), (P - 5n) / 8n, P));
  if (mod(v * x * x) === mod(-u)) x = mod(x * SQRT_M1);
  else if (mod(v * x * x) !== u) return null;
  return [(x & 1n) !== sign ? mod(P - x) : x, y];
}

function double([x, y]: [bigint, bigint]): [bigint, bigint] {
  const t = mod(D * x * x * y * y);
  return [mod(2n * x * y * inv(mod(1n + t))), mod((y * y + x * x) * inv(mod(1n - t)))];
}

/**
 * A 32-byte Ed25519 key no honest signer holds: a non-canonical encoding
 * (y >= p) or a point of small order, which verifies a crafted signature over
 * every message. A port of `opentine._ed25519_order.weak_public_key`.
 */
export function weakPublicKey(raw: Uint8Array): boolean {
  if (raw.length !== 32) return true;
  if ((littleEndian(raw) & ((1n << 255n) - 1n)) >= P) return true;
  let point = decodePoint(raw);
  if (point === null) return false;
  for (let i = 0; i < 3; i++) point = double(point);
  return point[0] === 0n && point[1] === 1n;
}
