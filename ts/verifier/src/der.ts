/**
 * A small, strict DER reader for CMS, RFC 3161 and X.509 (0.52): a port of
 * `opentine._der`. Indefinite and non-minimal lengths, truncation, trailing
 * bytes and high tag numbers are refused with `DerError`. Nothing recurses.
 */

export const SEQUENCE = 0x30;
export const SET = 0x31;
export const INTEGER = 0x02;
export const OCTETS = 0x04;
export const OID = 0x06;
export const GENTIME = 0x18;
export const UTCTIME = 0x17;
export const BOOLEAN = 0x01;
export const BITS = 0x03;
const MAX_DER = 1024 * 1024;

export class DerError extends Error {}

export class Node {
  constructor(
    readonly tag: number,
    /** The whole TLV, header included (what a signature covers). */
    readonly raw: Uint8Array,
    readonly value: Uint8Array,
  ) {}

  get constructed(): boolean {
    return (this.tag & 0x20) !== 0;
  }

  children(): Node[] {
    if (!this.constructed) throw new DerError(`tag 0x${this.tag.toString(16)} is not constructed`);
    const out: Node[] = [];
    let at = 0;
    while (at < this.value.length) {
      const [node, end] = tlv(this.value, at);
      out.push(node);
      at = end;
    }
    return out;
  }

  expect(tag: number, what: string): Node {
    if (this.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${this.tag.toString(16)}`);
    return this;
  }
}

function tlv(data: Uint8Array, at: number): [Node, number] {
  if (at + 2 > data.length) throw new DerError("truncated DER header");
  const tag = data[at];
  if ((tag & 0x1f) === 0x1f) throw new DerError("high-tag-number form is not used here");
  const first = data[at + 1];
  let head = at + 2;
  let length: number;
  if (first < 0x80) length = first;
  else if (first === 0x80) throw new DerError("indefinite length is not DER");
  else {
    const count = first & 0x7f;
    if (count > 4 || head + count > data.length) throw new DerError("bad DER length");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + data[head + i];
    if (length < 0x80 || data[head] === 0) throw new DerError("non-minimal DER length");
    head += count;
  }
  const end = head + length;
  if (end > data.length) throw new DerError("truncated DER value");
  return [new Node(tag, data.subarray(at, end), data.subarray(head, end)), end];
}

/** Exactly one TLV filling `data`. */
export function read(data: Uint8Array): Node {
  if (!(data instanceof Uint8Array) || data.length > MAX_DER) throw new DerError("not DER bytes, or too large");
  const [node, end] = tlv(data, 0);
  if (end !== data.length) throw new DerError("trailing bytes after DER value");
  return node;
}

export function asInt(node: Node): bigint {
  node.expect(INTEGER, "INTEGER");
  if (!node.value.length) throw new DerError("empty INTEGER");
  let out = 0n;
  for (const byte of node.value) out = (out << 8n) | BigInt(byte);
  if (node.value[0] & 0x80) out -= 1n << BigInt(8 * node.value.length);
  return out;
}

export function asOid(node: Node): string {
  node.expect(OID, "OBJECT IDENTIFIER");
  const value = node.value;
  if (!value.length || value[value.length - 1] & 0x80) throw new DerError("malformed OBJECT IDENTIFIER");
  const arcs: bigint[] = [];
  let acc = 0n;
  for (const byte of value) {
    acc = (acc << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(acc);
      acc = 0n;
    }
  }
  const first = arcs[0] / 40n < 2n ? arcs[0] / 40n : 2n;
  return [first, arcs[0] - 40n * first, ...arcs.slice(1)].join(".");
}

function digits(text: string): boolean {
  return /^[0-9]+$/.test(text);
}

function micros(y: number, mo: number, d: number, h: number, mi: number, s: number): bigint {
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  if (back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || s > 59) {
    throw new DerError("not a calendar time");
  }
  return BigInt(ms) * 1000n;
}

/** GeneralizedTime `YYYYMMDDHHMMSS[.f]Z` as microseconds since the epoch. */
export function asGenTime(node: Node): bigint {
  node.expect(GENTIME, "GeneralizedTime");
  const text = new TextDecoder().decode(node.value);
  if (text.length < 15 || !text.endsWith("Z") || !digits(text.slice(0, 14))) {
    throw new DerError("GeneralizedTime must be YYYYMMDDHHMMSS[.f]Z");
  }
  const n = (a: number, b: number) => Number(text.slice(a, b));
  let out = micros(n(0, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12), n(12, 14));
  const fraction = text.slice(14, -1);
  if (fraction) {
    if (!(fraction.startsWith(".") && digits(fraction.slice(1)) && fraction.length <= 7)) {
      throw new DerError("malformed GeneralizedTime fraction");
    }
    out += BigInt(fraction.slice(1).padEnd(6, "0"));
  }
  return out;
}

/** An X.509 Validity time (UTCTime before 2050, else GeneralizedTime). */
export function asCertTime(node: Node): bigint {
  if (node.tag === GENTIME) return asGenTime(node);
  node.expect(UTCTIME, "UTCTime");
  const text = new TextDecoder().decode(node.value);
  if (text.length !== 13 || !text.endsWith("Z") || !digits(text.slice(0, 12))) throw new DerError("UTCTime must be YYMMDDHHMMSSZ");
  const n = (a: number, b: number) => Number(text.slice(a, b));
  const year = n(0, 2) < 50 ? 2000 + n(0, 2) : 1900 + n(0, 2);
  return micros(year, n(2, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12));
}

/** `node`'s TLV with its tag byte replaced (IMPLICIT [0] SET -> SET for signing). */
export function retag(node: Node, tag: number): Uint8Array {
  const out = Uint8Array.from(node.raw);
  out[0] = tag;
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
