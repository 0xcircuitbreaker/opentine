/** Types of the bundled TS verifier (`tine-verifier.js`, built by build-verifier.mjs). */

export interface SignatureResult {
  ok: boolean;
  state: "verified" | "verified-tofu" | "unsigned" | "no-key" | "mismatch" | "error";
  algorithm: string | null;
  key_id: string | null;
  signer: string | null;
  signed_at: string | null;
  reason: string;
}

export interface Report {
  schema: string;
  path: string;
  verdict: "pass" | "fail";
  ok: boolean;
  format: string | null;
  root: string | null;
  integrity: { ok: boolean; reason: string };
  signature: SignatureResult | null;
}

/** 0.51: bundles, records and the release this build was made for. */
export const OPENTINE_VERSION: string;

export interface ByteSource {
  readonly size: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

export interface Check {
  name: string;
  state: "pass" | "fail" | "unchecked";
  reason: string;
}

export interface BundleReport {
  schema: string;
  opentine_version: string;
  verdict: "pass" | "fail";
  ok: boolean;
  reason: string | null;
  code: string | null;
  bundle: string | null;
  pack: string | null;
  objects: number;
  pack_reader: "streamed" | "in-memory" | null;
  refs: Record<string, string>;
  signatures: number;
  transparency: number;
  content_unavailable: string[];
  redacted_public: Record<string, unknown> | null;
  checks: Check[];
}

export interface RecordCheck {
  kind: string;
  state: "pass" | "fail" | "unchecked";
  reason: string;
  result: Record<string, unknown> | null;
}

export function blobSource(blob: Blob): ByteSource;
export function bytesSource(data: Uint8Array): ByteSource;
export function isBundle(head: Uint8Array): boolean;
export interface BundleKeys {
  hmacKey?: Uint8Array | null;
  publicKey?: Uint8Array | null;
}
export function verifyBundle(source: ByteSource, keys?: BundleKeys): Promise<BundleReport>;
export function verifyBundleBytes(data: Uint8Array, keys?: BundleKeys): Promise<BundleReport>;
export function recordKinds(): string[];
export function verifyRecordBytes(raw: Uint8Array): RecordCheck;
/** An owner-signed trust bundle (SPEC 8.26), opened by `openTrustBundle`. */
export interface TrustBundle {
  owner: string;
  serial: number;
  issuedAt: string;
  expiresAt: string | null;
  pins: Set<string>;
  logKeys: string[];
  witnessNetwork: unknown;
  admissionPolicies: string[];
  digest: string;
}

export function openTrustBundle(
  note: Uint8Array,
  ownerVkey: string,
  options?: { now?: number; minSerial?: number },
): TrustBundle;

export function keyFingerprint(hexKey: string): string;

export function verifyArtifact(raw: Uint8Array, name?: string, trust?: TrustBundle | null): Promise<Report>;
