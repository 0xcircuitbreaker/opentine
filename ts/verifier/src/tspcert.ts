/**
 * The X.509 pieces an RFC 3161 check needs (0.52): parse a certificate, verify a
 * signature with its key, and the 0.41 rules of `opentine._tsp_checks` and the
 * chain walk of `opentine._tsp_verify` (each link's signature, CA flag, issuer
 * KeyUsage, no unknown critical extension, validity at genTime). Signatures go
 * through Node's OpenSSL (`node:crypto`): RSA PKCS#1 v1.5, ECDSA and Ed25519.
 */

import { createPublicKey, verify } from "node:crypto";

import { asCertTime, asInt, asOid, BITS, BOOLEAN, DerError, equalBytes, Node, OCTETS, read, SEQUENCE } from "./der.js";

const EXT_BASIC = "2.5.29.19";
const EXT_KEY_USAGE = "2.5.29.15";
export const EXT_EKU = "2.5.29.37";
const EXT_SKI = "2.5.29.14";
export const TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
/** Extensions `cryptography` decodes; any other one marked critical is refused. */
const KNOWN = new Set([
  "2.5.29.9", "2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.18", "2.5.29.19", "2.5.29.30",
  "2.5.29.31", "2.5.29.32", "2.5.29.33", "2.5.29.35", "2.5.29.36", "2.5.29.37", "2.5.29.46",
  "2.5.29.54", "1.3.6.1.5.5.7.1.1", "1.3.6.1.5.5.7.1.11", "1.3.6.1.5.5.7.1.24",
  "1.3.6.1.5.5.7.48.1.5", "1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.4.1.11129.2.4.3",
]);
const HASH_OF: Record<string, string | null> = {
  "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512",
  "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512",
  "1.3.101.112": null,
};

export interface Extension {
  critical: boolean;
  value: Uint8Array;
}

export interface Cert {
  raw: Uint8Array;
  tbs: Uint8Array;
  sigOid: string;
  signature: Uint8Array;
  serial: bigint;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: bigint;
  notAfter: bigint;
  spki: Uint8Array;
  extensions: Map<string, Extension>;
}

function bitString(node: Node): Uint8Array {
  node.expect(BITS, "BIT STRING");
  if (!node.value.length) throw new DerError("empty BIT STRING");
  return node.value.subarray(1);
}

export function parseCert(der: Uint8Array): Cert {
  try {
    const node = read(der);
    const [tbsNode, algNode, sigNode] = node.expect(SEQUENCE, "Certificate").children();
    let fields = tbsNode.expect(SEQUENCE, "TBSCertificate").children();
    if (fields[0].tag === 0xa0) fields = fields.slice(1);
    const [serial, , issuer, validity, subject, spki, ...rest] = fields;
    const [notBefore, notAfter] = validity.expect(SEQUENCE, "Validity").children();
    const extensions = new Map<string, Extension>();
    const block = rest.find((item) => item.tag === 0xa3);
    for (const item of block ? block.children()[0].expect(SEQUENCE, "Extensions").children() : []) {
      const parts = item.expect(SEQUENCE, "Extension").children();
      const critical = parts.length === 3 && parts[1].tag === BOOLEAN && !(parts[1].value.length === 1 && parts[1].value[0] === 0);
      const oid = asOid(parts[0]);
      if (extensions.has(oid)) throw new DerError(`duplicate extension ${oid}`);
      extensions.set(oid, { critical, value: parts[parts.length - 1].expect(OCTETS, "extnValue").value });
    }
    return {
      raw: node.raw, tbs: tbsNode.raw, sigOid: asOid(algNode.children()[0]), signature: bitString(sigNode),
      serial: asInt(serial), issuer: issuer.expect(SEQUENCE, "issuer").raw, subject: subject.expect(SEQUENCE, "subject").raw,
      notBefore: asCertTime(notBefore), notAfter: asCertTime(notAfter), spki: spki.expect(SEQUENCE, "spki").raw, extensions,
    };
  } catch (exc) {
    if (exc instanceof DerError) throw exc;
    throw new DerError(`malformed certificate: ${(exc as Error).message}`);
  }
}

export class Unsupported extends Error {}

/** Verify `signature` over `data` with `cert`'s key: false when it does not verify. */
export function verifyWith(cert: Cert, hash: string | null, data: Uint8Array, signature: Uint8Array): boolean {
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(cert.spki), format: "der", type: "spki" });
  } catch {
    throw new Unsupported("unsupported TSA key type");
  }
  const type = key.asymmetricKeyType;
  if (type === "ed25519") return verify(null, data, key, signature);
  if (type !== "rsa" && type !== "ec") throw new Unsupported("unsupported TSA key type");
  if (hash === null) throw new Unsupported("unsupported signature or digest algorithm");
  try {
    return verify(hash, data, key, signature);
  } catch {
    return false;
  }
}

function issuedBySignature(child: Cert, parent: Cert): boolean {
  const hash = HASH_OF[child.sigOid];
  if (hash === undefined) return false;
  try {
    return verifyWith(parent, hash, child.tbs, child.signature);
  } catch {
    return false;
  }
}

export function unknownCritical(cert: Cert): string | null {
  for (const [oid, ext] of cert.extensions) if (ext.critical && !KNOWN.has(oid)) return oid;
  return null;
}

function isCa(cert: Cert): boolean | null {
  const ext = cert.extensions.get(EXT_BASIC);
  if (!ext) return null;
  const parts = read(ext.value).expect(SEQUENCE, "BasicConstraints").children();
  return parts.length > 0 && parts[0].tag === BOOLEAN && parts[0].value[0] !== 0;
}

/** An issuer's KeyUsage, if any, allows keyCertSign; no unknown critical extension. */
export function issuerOk(parent: Cert): boolean {
  if (unknownCritical(parent)) return false;
  const ext = parent.extensions.get(EXT_KEY_USAGE);
  if (!ext) return true;
  const bits = bitString(read(ext.value));
  return bits.length > 0 && (bits[0] & 0x04) !== 0;
}

function issued(child: Cert, parent: Cert, when: bigint): boolean {
  if (!equalBytes(child.issuer, parent.subject) || !issuedBySignature(child, parent)) return false;
  let ca: boolean | null;
  try {
    ca = isCa(parent);
  } catch {
    return false;
  }
  return ca === true && parent.notBefore <= when && when <= parent.notAfter && issuerOk(parent);
}

/** Whether `leaf` chains, each link valid at `when`, to one of `roots` (at most 8 links). */
export function chains(leaf: Cert, pool: Cert[], roots: Cert[], when: bigint): boolean {
  let current = leaf;
  for (let i = 0; i < 8; i++) {
    if (roots.some((root) => equalBytes(root.raw, current.raw))) return true;
    const issuers = [...roots, ...pool].filter((c) => equalBytes(c.subject, current.issuer));
    const next = issuers.find((c) => issued(current, c, when));
    if (!next) return false;
    current = next;
  }
  return false;
}

export function subjectKeyId(cert: Cert): Uint8Array | null {
  const ext = cert.extensions.get(EXT_SKI);
  return ext ? read(ext.value).expect(OCTETS, "SubjectKeyIdentifier").value : null;
}

/** RFC 3161 §2.3: one EKU, critical, holding only id-kp-timeStamping. */
export function ekuProblem(cert: Cert): string | null {
  const ext = cert.extensions.get(EXT_EKU);
  const purposes = ext ? read(ext.value).expect(SEQUENCE, "ExtendedKeyUsage").children().map(asOid) : [];
  if (!ext || !purposes.includes(TIME_STAMPING)) return "TSA certificate lacks timeStamping";
  if (!ext.critical) return "TSA certificate's timeStamping EKU is not marked critical";
  if (purposes.length !== 1) return "TSA certificate's EKU holds purposes other than timeStamping";
  return null;
}
