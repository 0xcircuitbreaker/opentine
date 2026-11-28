"""k-of-n approval of custody exports and copies (0.91).

Once the owner-pinned trust bundle names any ``custodian`` key, or carries a
``custody`` section (:mod:`opentine._bundle_section`)::

    "custody": {"version": 1, "k": N}      # 2 <= N <= 256; the default N is 2

a weight copy or export (``tine custody record copied|exported --artifact``)
and an interpretability export (``tine interp export``) need ``k`` approvals
from **distinct** custodian keys. Each approval is an attestation (the existing
object kind) whose claim is::

    {"convention": "opentine.custody-approval/1", "operation": "copy" | "export",
     "digest": "sha256:...", "checkpoint": "sha256:..." | null, "requester": FPR,
     "artifact": NAME | null, "destination": TEXT | null, "at": RFC3339}

held under ``custody:quorum:approval:...`` (never released). It is bound to
the exact bytes (``digest``) and to the checkpoint they cover (a weight
artifact's ``created`` digest, an interpretability artifact's checkpoint), so
re-encoded bytes or another checkpoint need approvals of their own. It counts
only when its signer is the key that signed it, is a pinned ``custodian`` key
that is not an ``optimizer`` key, is not the requester, and has not revoked
it: an ``opentine.custody-revocation/1`` attestation ``{"approval": OID,
"at"}`` by the approval's signer or a pinned ``policy`` key. Revocations and
approvals are read from the whole object store, so dropping a hold row
cannot un-revoke. A bundle that cannot be read under a pinned owner requires
a quorum no key can meet (fail closed). Without custodian keys or the section
nothing changes (owner decision D12).
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any

from opentine import _containment_records as records

APPROVAL = "opentine.custody-approval/1"
REVOCATION = "opentine.custody-revocation/1"
HOLD = "custody:quorum:"
OPERATIONS = ("copy", "export")
DEFAULT_K, MAX_K = 2, 256
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class QuorumError(PermissionError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def section_of(doc: Any) -> dict[str, Any] | None:
    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - {"version", "k"}:
        return None
    k = doc.get("k", DEFAULT_K)
    return {"k": k} if type(k) is int and DEFAULT_K <= k <= MAX_K else None


def policy(repo: Any) -> dict[str, Any]:
    """``{"required", "k", "custodians", "error"}``: who may approve, and how many must."""
    from opentine._bundle_section import SectionError, section
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    store = getattr(repo, "path", None)
    try:
        found = section(store, "custody", section_of)
        state = resolve(store)
    except (SectionError, KeyRoleError) as exc:
        return {"required": True, "k": DEFAULT_K, "custodians": set(), "error": str(exc)}
    roles = (state["roles"] or {}) if state["status"] == "pinned" else {}
    named = set(roles.get("custodian", []))
    return {"required": found is not None or bool(named),
            "k": found["k"] if found else DEFAULT_K,
            "custodians": named - set(roles.get("optimizer", [])), "error": None}  # fmt: skip


def _check(operation: str, digest: str, checkpoint: str | None) -> None:
    if operation not in OPERATIONS:
        raise ValueError(f"an operation is one of {', '.join(OPERATIONS)}")
    if not _DIGEST.fullmatch(str(digest)) or (
            checkpoint is not None and not _DIGEST.fullmatch(str(checkpoint))):  # fmt: skip
        raise ValueError("a digest and a checkpoint are sha256:<64 lowercase hex>")


def approve(repo: Any, key: Any, *, operation: str, digest: str, checkpoint: str | None,
            requester: str, artifact: str | None = None, destination: str | None = None,
            now: float | None = None) -> str:  # fmt: skip
    """Sign and hold one approval; refused for a key that could never count."""
    _check(operation, digest, checkpoint)
    signer = records.fingerprint(key)
    found = policy(repo)
    if signer not in found["custodians"]:
        raise QuorumError("custody.approver", f"{signer} is not a pinned custodian key "
                          "(an optimizer key never is)")  # fmt: skip
    if signer == requester:
        raise QuorumError("custody.self-approval", "a requester cannot approve its own request")
    claim = {"convention": APPROVAL, "operation": operation, "digest": digest,
             "checkpoint": checkpoint, "requester": requester, "artifact": artifact,
             "destination": destination,
             "at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    anchor = records.anchor(repo, "custody-approval", f"{operation} {digest}")
    hold = f"{HOLD}approval:{digest[7:]}:{secrets.token_hex(8)}"
    return records.record(repo, anchor, claim, key, hold)


def revoke(repo: Any, approval: str, key: Any, *, now: float | None = None) -> str:
    """Sign and hold a revocation by the approval's signer or a pinned policy key."""
    from opentine._key_roles_pin import granting

    row = records.read(repo, approval)
    if (row["claim"] or {}).get("convention") != APPROVAL:
        raise ValueError(f"{approval} is not a custody approval")
    signer = records.fingerprint(key)
    if signer != row["signer"] and signer not in granting(repo.path, "policy")[0]:
        raise QuorumError("custody.revoker", "only the approver or a pinned policy key revokes")
    claim = {"convention": REVOCATION, "approval": approval,
             "at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    return records.record(repo, row["target"], claim, key, f"{HOLD}revocation:{approval[-64:]}")


def tally(repo: Any, *, operation: str, digest: str, checkpoint: str | None,
          requester: str | None, at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Count the approvals of one request; an approval dated after *at* does not count.

    A revocation counts whenever it is dated: its date and the event's are both
    claimed by their signers, so ordering by them would let a backdated event
    escape a revocation (fail closed; re-approve to cover an earlier copy)."""
    from opentine._key_roles_pin import granting

    _check(operation, digest, checkpoint)
    found = policy(repo)
    rows = records.scan(repo, (APPROVAL, REVOCATION))
    approvals = {r["oid"]: r for r in rows if r["claim"]["convention"] == APPROVAL}
    policy_keys = granting(repo.path, "policy")[0]
    revoked = {r["claim"].get("approval") for r in rows
               if r["claim"]["convention"] == REVOCATION and r["signed"]
               and (r["signer"] in policy_keys
                    or r["signer"] == (approvals.get(r["claim"].get("approval")) or {}).get(
                        "signer"))}  # fmt: skip
    listed, counted = [], set()
    for oid, row in sorted(approvals.items()):
        claim = row["claim"]
        if (
            claim.get("operation"),
            claim.get("digest"),
            claim.get("checkpoint"),
            claim.get("requester"),
        ) != (operation, digest, checkpoint, requester):
            continue
        why = ("not signed by its key" if not row["signed"]
               else "not a pinned custodian key" if row["signer"] not in found["custodians"]
               else "the requester approved itself" if row["signer"] == requester
               else "revoked" if oid in revoked
               else "dated after the event" if at is not None and str(claim.get("at")) > at
               else None)  # fmt: skip
        if why is None:
            counted.add(row["signer"])
        listed.append({"record": oid, "signer": row["signer"], "counted": why is None,
                       "why": why})  # fmt: skip
    ok = not found["required"] or (requester is not None and len(counted) >= found["k"])
    return {"required": found["required"], "k": found["k"], "counted": len(counted),
            "approvals": listed, "ok": ok, "error": found["error"]}  # fmt: skip


def require(repo: Any, **request: Any) -> dict[str, Any]:
    """:func:`tally`, raising :class:`QuorumError` (``custody.quorum``) when it is short."""
    found = tally(repo, **request)
    if not found["ok"]:
        who = request.get("requester") or "no requester"
        raise QuorumError(
            "custody.quorum",
            f"{request['operation']} of {request['digest']} "
            f"by {who} has {found['counted']} of {found['k']} custodian "
            "approvals" + (f" ({found['error']})" if found["error"] else ""),
        )
    return found


__all__ = ["APPROVAL", "HOLD", "OPERATIONS", "REVOCATION", "QuorumError", "approve", "policy",
           "require", "revoke", "section_of", "tally"]  # fmt: skip
