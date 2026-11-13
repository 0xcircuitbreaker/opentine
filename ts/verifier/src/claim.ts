/**
 * What the verifier says about an attestation claim it does not know (0.51, FREEZE ruling (b)).
 *
 * A new in-toto `predicateType` or `attestation.claim` schema may ride inside a
 * frozen envelope only once the owner grants it by name (docs/FREEZE.md). Until
 * then the verifier checks the envelope (the signature, unchanged) and reports
 * the claim itself `unchecked`: never `pass` and never `fail`. No predicate is
 * granted in 0.51. The Python reference (`opentine/_claim_status.py`) and the
 * pyz (`opentine/_pyz/_claim.py`) carry the same rule and the same empty list.
 */

import { isObject, type JValue } from "./json.js";

/** Predicates granted under the ruling, by name (FREEZE.md "Granted predicates"). */
export const GRANTED_PREDICATES: ReadonlySet<string> = new Set<string>([]);

export interface ClaimStatus {
  status: "unchecked";
  reason: "claim.unnamed" | "claim.unknown-predicate";
  predicate: string | null;
}

/** The claim's `predicateType` (or `schema`) when it names one. */
export function claimName(claim: JValue | undefined): string | null {
  if (!isObject(claim)) return null;
  for (const key of ["predicateType", "schema"]) {
    const name = claim.get(key);
    if (typeof name === "string" && name.length > 0) return name;
  }
  return null;
}

/** The status of a claim the verifier has no granted checker for. */
export function claimStatus(claim: JValue | undefined): ClaimStatus {
  const name = claimName(claim);
  if (name === null) return { status: "unchecked", reason: "claim.unnamed", predicate: null };
  if (GRANTED_PREDICATES.has(name)) throw new Error(`granted predicate ${name} has no checker`);
  return { status: "unchecked", reason: "claim.unknown-predicate", predicate: name };
}
