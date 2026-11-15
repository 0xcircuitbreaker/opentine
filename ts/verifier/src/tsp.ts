/**
 * Verify an RFC 3161 timestamp token offline (0.52): a port of
 * `opentine._tsp.parse` and `opentine._tsp_verify.verify_token`, so the TS
 * verifier checks a keyless token's CMS signature and chain as Python does.
 *
 * In order: the DER parses; the messageImprint is the token's hash of the bound
 * bytes; the signed attributes name a TSTInfo and carry its digest; the TSA
 * signature over them; the ESS signingCertificate(V2) binding; a critical,
 * timeStamping-only EKU; no critical TSTInfo extension and no unknown critical
 * certificate extension; genTime (with its accuracy) inside the TSA
 * certificate's validity; an anchor whose `validFor` holds genTime; and a chain
 * to it, each link valid at genTime. The first failed step is the verdict, with
 * Python's `timestamp.*` reason. Revocation data embedded in `SignedData.crls`
 * is not read here: a token that carries any fails closed
 * (`timestamp.revocation-unchecked`).
 */

import { createHash } from "node:crypto";

import { asGenTime, asInt, asOid, DerError, equalBytes, Node, OCTETS, OID, read, retag, SEQUENCE, SET } from "./der.js";
import { chains, ekuProblem, parseCert, subjectKeyId, unknownCritical, Unsupported, verifyWith, type Cert } from "./tspcert.js";

const SIGNED_DATA = "1.2.840.113549.1.7.2";
const TST_INFO = "1.2.840.113549.1.9.16.1.4";
const ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const ESS_V1 = "1.2.840.113549.1.9.16.2.12";
const ESS_V2 = "1.2.840.113549.1.9.16.2.47";
const PSS = "1.2.840.113549.1.1.10";
export const HASHES: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

interface Token {
  hashOid: string;
  imprint: Uint8Array;
  genTime: bigint;
  tstInfo: Uint8Array;
  accuracyUs: bigint | null;
  extensions: [string, boolean][];
  certs: Uint8Array[];
  revocation: number;
  signerSerial: bigint | null;
  signerIssuer: Uint8Array | null;
  signerSki: Uint8Array | null;
  digestOid: string;
  signedAttrs: Uint8Array;
  attrs: Map<string, Node[]>;
  sigOid: string;
  signature: Uint8Array;
}

export interface Window {
  start: bigint;
  end: bigint | null;
}

export interface Verdict {
  ok: boolean;
  reason: string;
  detail: string;
  hashAlgorithm?: string;
  genTime?: bigint;
  accuracyUs?: bigint | null;
}

function signedData(node: Node): Node {
  let items = node.expect(SEQUENCE, "token").children();
  if (items.length && items[0].tag === SEQUENCE) {
    const status = asInt(items[0].children()[0]);
    if ((status !== 0n && status !== 1n) || items.length < 2) throw new DerError(`timestamp response status ${status}: not granted`);
    items = items[1].expect(SEQUENCE, "ContentInfo").children();
  }
  if (items.length !== 2 || asOid(items[0]) !== SIGNED_DATA || items[1].tag !== 0xa0) throw new DerError("not a CMS SignedData ContentInfo");
  const inner = items[1].children();
  if (inner.length !== 1) throw new DerError("not a CMS SignedData ContentInfo");
  return inner[0].expect(SEQUENCE, "SignedData");
}

function accuracy(node: Node): bigint {
  let total = 0n;
  for (const part of node.children()) {
    if (part.tag === 0x02) total += asInt(part) * 1000000n;
    else if (part.tag === 0x80 || part.tag === 0x81) {
      const value = asInt(new Node(0x02, part.raw, part.value));
      if (value < 1n || value > 999n) throw new DerError("accuracy millis/micros must be 1..999");
      total += value * (part.tag === 0x80 ? 1000n : 1n);
    } else throw new DerError("malformed accuracy");
  }
  if (total < 0n) throw new DerError("negative accuracy");
  return total;
}

function tstInfo(raw: Uint8Array): Pick<Token, "hashOid" | "imprint" | "genTime" | "tstInfo" | "accuracyUs" | "extensions"> {
  const items = read(raw).expect(SEQUENCE, "TSTInfo").children();
  if (items.length < 5 || asInt(items[0]) !== 1n) throw new DerError("TSTInfo must be version 1");
  asOid(items[1]);
  const imprint = items[2].expect(SEQUENCE, "messageImprint").children();
  const algorithm = imprint[0].expect(SEQUENCE, "hashAlgorithm").children();
  const out = {
    hashOid: asOid(algorithm[0]), imprint: imprint[1].expect(OCTETS, "hashedMessage").value,
    genTime: (asInt(items[3]), asGenTime(items[4])), tstInfo: raw, accuracyUs: null as bigint | null,
    extensions: [] as [string, boolean][],
  };
  let parsed = 0;
  let nonce = false;
  for (const node of items.slice(5)) {
    if (node.tag === SEQUENCE && parsed === 0) out.accuracyUs = accuracy(node);
    else if (node.tag === 0x01 && !nonce) void 0;
    else if (node.tag === 0x02) (asInt(node), (nonce = true));
    else if (node.tag === 0xa0) continue;
    else if (node.tag === 0xa1) {
      out.extensions = node.children().map((ext) => {
        const parts = ext.expect(SEQUENCE, "Extension").children();
        const critical = parts.length === 3 && parts[1].tag === 0x01 && !(parts[1].value.length === 1 && parts[1].value[0] === 0);
        return [asOid(parts[0]), critical] as [string, boolean];
      });
    } else throw new DerError(`unexpected TSTInfo field 0x${node.tag.toString(16)}`);
    parsed++;
  }
  return out;
}

function parse(data: Uint8Array): Token {
  try {
    const signed = signedData(read(data)).children();
    if (signed.length < 4) throw new DerError("SignedData is too short");
    const encap = signed[2].expect(SEQUENCE, "encapContentInfo").children();
    if (asOid(encap[0].expect(OID, "eContentType")) !== TST_INFO || encap.length !== 2) throw new DerError("the token does not hold a TSTInfo");
    const content = encap[1].children();
    if (content.length !== 1) throw new DerError("the token does not hold a TSTInfo");
    const token: Token = {
      ...tstInfo(content[0].expect(OCTETS, "eContent").value), certs: [], revocation: 0, signerSerial: null,
      signerIssuer: null, signerSki: null, digestOid: "", signedAttrs: new Uint8Array(), attrs: new Map(), sigOid: "",
      signature: new Uint8Array(),
    };
    let rest = signed.slice(3);
    if (rest.length && rest[0].tag === 0xa0) {
      token.certs = rest[0].children().map((cert) => cert.raw);
      rest = rest.slice(1);
    }
    if (rest.length && rest[0].tag === 0xa1) token.revocation = rest[0].children().length;
    const signers = rest[rest.length - 1].expect(SET, "signerInfos").children();
    if (signers.length !== 1) throw new DerError("expected exactly one SignerInfo");
    const items = signers[0].expect(SEQUENCE, "SignerInfo").children();
    if (items.length < 6) throw new DerError("SignerInfo is too short");
    const sid = items[1];
    if (sid.tag === SEQUENCE) {
      const [issuer, serial] = sid.children();
      token.signerIssuer = issuer.raw;
      token.signerSerial = asInt(serial);
    } else if (sid.tag === 0x80) token.signerSki = sid.value;
    else throw new DerError("unknown SignerIdentifier");
    token.digestOid = asOid(items[2].expect(SEQUENCE, "digestAlgorithm").children()[0]);
    if (items[3].tag !== 0xa0) throw new DerError("SignerInfo has no signed attributes");
    token.signedAttrs = retag(items[3], SET);
    for (const attr of items[3].children()) {
      const [oid, values] = attr.expect(SEQUENCE, "Attribute").children();
      token.attrs.set(asOid(oid), values.expect(SET, "AttributeValues").children());
    }
    token.sigOid = asOid(items[4].expect(SEQUENCE, "signatureAlgorithm").children()[0]);
    token.signature = items[5].expect(OCTETS, "signature").value;
    return token;
  } catch (exc) {
    if (exc instanceof DerError) throw exc;
    throw new DerError(`malformed timestamp token: ${(exc as Error).message}`);
  }
}

function digest(name: string, data: Uint8Array): Uint8Array {
  return createHash(name).update(data).digest();
}

function signerCert(token: Token): Cert {
  for (const der of token.certs) {
    const cert = parseCert(der);
    if (token.signerSki !== null) {
      const ski = subjectKeyId(cert);
      if (ski && equalBytes(ski, token.signerSki)) return cert;
    } else if (cert.serial === token.signerSerial && equalBytes(cert.issuer, token.signerIssuer as Uint8Array)) return cert;
  }
  throw new DerError("the token carries no certificate for its signer");
}

function attrsOk(token: Token): boolean {
  const name = HASHES[token.digestOid];
  const kind = token.attrs.get(ATTR_CONTENT_TYPE) ?? [];
  const sum = token.attrs.get(ATTR_MESSAGE_DIGEST) ?? [];
  if (!name || kind.length !== 1 || sum.length !== 1) return false;
  return asOid(kind[0]) === TST_INFO && equalBytes(sum[0].expect(OCTETS, "messageDigest").value, digest(name, token.tstInfo));
}

function essProblem(token: Token, cert: Cert): string | null {
  try {
    const v1 = token.attrs.get(ESS_V1) ?? [];
    const v2 = token.attrs.get(ESS_V2) ?? [];
    if (v1.length + v2.length !== 1) return "signed attributes carry no single ESS signingCertificate(V2) attribute";
    const version = v2.length ? ESS_V2 : ESS_V1;
    const ids = (v2[0] ?? v1[0]).expect(SEQUENCE, "SigningCertificate").children()[0].expect(SEQUENCE, "certs").children();
    if (!ids.length) return "ESS signingCertificate lists no certificate";
    let parts = ids[0].expect(SEQUENCE, "ESSCertID").children();
    let name: string | undefined = "sha1";
    if (version === ESS_V2 && parts[0].tag === SEQUENCE) {
      name = HASHES[asOid(parts[0].children()[0])];
      parts = parts.slice(1);
    } else if (version === ESS_V2) name = "sha256";
    if (!name) return "ESS signingCertificateV2 uses an unsupported hash";
    if (!equalBytes(parts[0].expect(OCTETS, "certHash").value, digest(name, cert.raw))) {
      return "ESS certHash does not match the certificate that signed the token";
    }
    if (parts.length > 1 && asInt(parts[1].expect(SEQUENCE, "IssuerSerial").children()[1]) !== cert.serial) {
      return "ESS issuerSerial names a different certificate";
    }
  } catch (exc) {
    return `ESS signingCertificate is malformed: ${(exc as Error).message}`;
  }
  return null;
}

/**
 * Verify `data` (a TimeStampResp or a bare token) as a timestamp over `bound`.
 * `roots` are always anchors; each `windowed` anchor only for a genTime its window holds.
 */
export function verifyTimestampToken(data: Uint8Array, bound: Uint8Array, roots: Uint8Array[], windowed: [Uint8Array[], Window][] = []): Verdict {
  let token: Token;
  try {
    token = parse(data);
  } catch (exc) {
    return { ok: false, reason: "timestamp.malformed", detail: `not an RFC 3161 token: ${(exc as Error).message}` };
  }
  const name = HASHES[token.hashOid];
  const info = { hashAlgorithm: name ?? token.hashOid, genTime: token.genTime, accuracyUs: token.accuracyUs };
  const no = (reason: string, detail: string): Verdict => ({ ok: false, reason, detail, ...info });
  if (!name) return no("timestamp.unsupported-algorithm", "unsupported imprint hash");
  if (!equalBytes(digest(name, bound), token.imprint)) return no("timestamp.imprint-mismatch", `messageImprint is not the ${name} of the bound bytes`);
  let cert: Cert;
  let pool: Cert[];
  let anchors: Cert[];
  try {
    cert = signerCert(token);
    pool = token.certs.map(parseCert);
  } catch (exc) {
    return no("timestamp.malformed", (exc as Error).message);
  }
  try {
    if (!attrsOk(token)) return no("timestamp.bad-signature", "signed attributes mismatch");
    const hash = HASHES[token.digestOid];
    if (!hash || token.sigOid === PSS) throw new Unsupported("unsupported signature or digest algorithm");
    if (!verifyWith(cert, hash, token.signedAttrs, token.signature)) return no("timestamp.bad-signature", "TSA signature does not verify");
  } catch (exc) {
    if (exc instanceof Unsupported) return no("timestamp.unsupported-algorithm", exc.message);
    return no("timestamp.bad-signature", "TSA signature does not verify");
  }
  const ess = essProblem(token, cert);
  if (ess) return no("timestamp.signing-cert-mismatch", ess);
  let eku: string | null;
  try {
    eku = ekuProblem(cert);
  } catch {
    eku = "TSA certificate lacks timeStamping";
  }
  if (eku) return no("timestamp.missing-eku", eku);
  const critical = token.extensions.find(([, flag]) => flag);
  if (critical) return no("timestamp.critical-extension", `TSTInfo carries critical extension ${critical[0]}, which is not understood`);
  const unknown = unknownCritical(cert);
  if (unknown) return no("timestamp.critical-extension", `TSA certificate has unrecognised critical extension ${unknown}`);
  const slack = token.accuracyUs ?? 0n;
  if (!(cert.notBefore <= token.genTime - slack && token.genTime + slack <= cert.notAfter)) {
    return no("timestamp.outside-validity", "genTime outside cert validity");
  }
  const live = windowed.filter(([, w]) => w.start <= token.genTime && (w.end === null || token.genTime <= w.end)).flatMap(([chain]) => chain);
  if (windowed.length && !roots.length && !live.length) return no("timestamp.tsa-retired", "genTime is outside every TSA validFor window");
  try {
    anchors = [...roots, ...live].map(parseCert);
  } catch (exc) {
    return no("timestamp.malformed", (exc as Error).message);
  }
  if (!anchors.length) return no("timestamp.no-roots", "no TSA root supplied");
  if (!chains(cert, pool, anchors, token.genTime)) return no("timestamp.untrusted-root", "TSA chain reaches no trusted root");
  if (token.revocation) return no("timestamp.revocation-unchecked", "embedded CRL/OCSP data is not read by the TS verifier");
  return { ok: true, reason: "timestamp.verified", detail: `genTime by the TSA (${name})`, ...info };
}
