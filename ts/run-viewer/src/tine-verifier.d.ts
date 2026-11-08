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

export function verifyArtifact(raw: Uint8Array, name?: string): Promise<Report>;
