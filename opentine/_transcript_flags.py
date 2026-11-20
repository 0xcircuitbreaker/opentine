"""Behaviour flags (0.74): the ``opentine.transcript-flag/1`` claim convention.

A flag is an **attestation** (an existing object kind) on the first evidence
run, whose claim says which behaviour a labeller saw and where::

    {"convention": "opentine.transcript-flag/1",
     "label": "reward-hacking|test-deletion|sabotage-side-task|<name>",
     "evidence": ["run:sha256:...", ...],      # sorted, at least one
     "cluster": "tc-<16 hex>" | null,          # the cluster it was found in
     "labeller": "<signer fingerprint>",
     "backend": {"name", "digest", "weights_digest"} | null,
     "note": "...", "labelled_at": "YYYY-MM-DDTHH:MM:SSZ"}

Only a ``scorer`` or ``curator`` key of the owner-pinned trust bundle
(:mod:`opentine._key_roles_pin`) may label: an optimizer key, an unpinned role
or an unreadable role policy is refused before anything is written (fail
closed). On reading, a flag is ``verified`` only when its Ed25519 signature
holds, the payload ``signer`` is the key that signed (``used_key_fingerprint``),
the claim's ``labeller`` is that signer and the signer still holds a pinned
``scorer`` or ``curator`` role and not ``optimizer``. Every flag is kept by a
``tine hold`` row whose target starts ``transcript-flag:``, which ``tine hold
release`` refuses, so a loop cannot delete the record that flagged it.
No object kind and no ``tine verify`` code is added (docs/TRANSCRIPT_FLAGS.md).
"""

from __future__ import annotations

import re
from typing import Any

from opentine.repository._holds import TRANSCRIPT_FLAG as HOLD

CONVENTION = "opentine.transcript-flag/1"
STANDARD = ("reward-hacking", "test-deletion", "sabotage-side-task")
LABELLER_ROLES = ("scorer", "curator")
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_CLUSTER = re.compile(r"tc-[0-9a-f]{16}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_FIELDS = ("convention", "label", "evidence", "cluster", "labeller", "backend", "note",
           "labelled_at")  # fmt: skip
MAX_EVIDENCE = 1000


def check_claim(claim: Any) -> list[str]:
    """Problems with *claim* as a flag (none: valid)."""
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return [f"not an {CONVENTION} claim"]
    if set(claim) != set(_FIELDS):
        return ["wrong set of fields"]
    problems = []
    if not isinstance(claim["label"], str) or not _LABEL.fullmatch(claim["label"]):
        problems.append("label is lower-case letters, digits and hyphens")
    evidence = claim["evidence"]
    if (not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE
            or any(not isinstance(e, str) or not _RUN.fullmatch(e) for e in evidence)
            or evidence != sorted(set(evidence))):  # fmt: skip
        problems.append("evidence is a sorted list of distinct run ids")
    if claim["cluster"] is not None and not (
        isinstance(claim["cluster"], str) and _CLUSTER.fullmatch(claim["cluster"])
    ):
        problems.append("cluster is tc-<16 hex> or null")
    if not isinstance(claim["note"], str) or not isinstance(claim["labelled_at"], str):
        problems.append("note and labelled_at are strings")
    return problems


def labeller_state(repo: Any, signer: str) -> tuple[bool, str]:
    """Whether *signer* may label: a pinned scorer or curator key, never an optimizer key."""
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        found = resolve(repo.path)
    except KeyRoleError as exc:
        return False, f"key-role policy: {exc}"
    roles = found["roles"] or {}
    if signer in roles.get("optimizer", []):
        return False, "the signer is an optimizer key"
    if found["status"] != "pinned":
        return False, "the scorer and curator roles are unpinned (no owner-signed trust bundle)"
    if not any(signer in roles.get(role, []) for role in LABELLER_ROLES):
        return False, "the signer is not a pinned scorer or curator key"
    return True, "verified"


def record(repo: Any, claim_in: dict[str, Any], key: Any) -> str:
    """Sign and hold one flag; refuses an unpinned or optimizer labeller. The attestation id."""
    from opentine import _containment_records as records

    signer = records.fingerprint(key)
    ok, why = labeller_state(repo, signer)
    if not ok:
        raise PermissionError(f"refusing to label: {why}")
    claim = {"convention": CONVENTION, **claim_in, "labeller": signer}
    claim["evidence"] = sorted(set(claim["evidence"]))
    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid transcript flag: {problems[0]}")
    for run in claim["evidence"]:
        if not repo.has(run):
            raise KeyError(f"evidence run {run} is not in the repository")
    target = claim["evidence"][0]
    return records.record(repo, target, claim, key, f"{HOLD}{claim['label']}:{target}")


def flags(repo: Any, *, label: str | None = None, run: str | None = None) -> list[dict[str, Any]]:
    """Every held flag (of *label*, naming *run*), with its verification state."""
    from opentine import _containment_records as records

    out = []
    for target, row in records.held(repo, HOLD):
        claim = row["claim"]
        if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
            continue
        if label is not None and claim.get("label") != label:
            continue
        if run is not None and run not in (claim.get("evidence") or []):
            continue
        problems = check_claim(claim)
        if not row["signed"]:
            state = "unverified: the signature does not hold or names another key"
        elif claim.get("labeller") != row["signer"]:
            state = "unverified: the labeller is not the key that signed"
        elif problems:
            state = f"unverified: {problems[0]}"
        else:
            ok, why = labeller_state(repo, row["signer"])
            state = "verified" if ok else f"unverified: {why}"
        out.append({"record": row["oid"], "hold": target, "label": claim.get("label"),
                    "evidence": claim.get("evidence"), "cluster": claim.get("cluster"),
                    "labeller": claim.get("labeller"), "backend": claim.get("backend"),
                    "note": claim.get("note"), "labelled_at": claim.get("labelled_at"),
                    "verification": state})  # fmt: skip
    return out


__all__ = ["CONVENTION", "HOLD", "LABELLER_ROLES", "STANDARD", "check_claim", "flags",
           "labeller_state", "record"]  # fmt: skip
