"""Blind audit games (0.65): the ``opentine.audit-game/1`` claim convention.

A game has three signed records, each an **attestation** (an existing object
kind) on the auditor's ``role=auditor`` run, each held by a ``tine hold`` row
whose target is ``audit-game:GAME`` and that is never released::

    seal:     {"convention", "game", "step": "seal", "commitment", "at"}
    findings: {"convention", "game", "step": "findings", "seal", "findings_digest",
               "verdict": "concern|no-concern", "at"}
    reveal:   {"convention", "game", "step": "reveal", "seal", "findings",
               "target", "objective", "nonce", "at"}

``commitment`` is ``sha256:`` of the canonical JSON of ``{target, objective,
nonce}``: the auditor sees the commitment, not the target. A reveal names the
findings attestation it follows by object id, so a reveal made before a
verdict is detectable offline: ``findings`` is null, names another record, or
the findings were signed after the reveal (``fail:audit-game.reveal-before-verdict``
from ``tine auditor check``). Findings count as the auditor's only when signed by
a key in the ``auditor`` role of the owner-pinned key roles; otherwise they are
reported ``advisory:`` (D12). No object kind and no ``tine verify`` code is added.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

from opentine._utc import rfc3339_utc
from opentine.kernel import canonical_json

CONVENTION = "opentine.audit-game/1"
STEPS = ("seal", "findings", "reveal")
VERDICTS = ("concern", "no-concern")
GAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def now() -> str:
    return rfc3339_utc()


def secret(target: str, objective: str = "", nonce: str | None = None) -> dict[str, str]:
    """What the game owner keeps until the reveal."""
    return {"target": target, "objective": objective, "nonce": nonce or secrets.token_hex(16)}


def commitment(sealed: dict[str, Any]) -> str:
    body = {k: sealed.get(k) for k in ("target", "objective", "nonce")}
    if not all(isinstance(v, str) for v in body.values()) or not body["nonce"]:
        raise ValueError("a sealed secret has string target, objective and nonce")
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def check_claim(claim: Any) -> list[str]:
    """Problems with *claim* as an ``opentine.audit-game/1`` claim (none: valid)."""
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return ["not an opentine.audit-game/1 claim"]
    if claim.get("step") not in STEPS or not GAME_RE.fullmatch(str(claim.get("game", ""))):
        return ["a claim names a game and a step (seal, findings, reveal)"]
    if not isinstance(claim.get("at"), str):
        return ["missing at"]
    step = claim["step"]
    if step == "seal" and not _DIGEST.fullmatch(str(claim.get("commitment", ""))):
        return ["a seal carries a sha256: commitment"]
    digest = str(claim.get("findings_digest", ""))
    if step == "findings" and (
        claim.get("verdict") not in VERDICTS or not _DIGEST.fullmatch(digest)
    ):
        return ["findings carry a verdict and a findings_digest"]
    if step == "reveal":
        try:
            commitment(claim)
        except ValueError as exc:
            return [str(exc)]
    return []


def record(repo: Any, run: str, claim: dict[str, Any], key: Any) -> str:
    """Sign *claim* onto the auditor *run* and hold it; the attestation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest
    from opentine.repository._holds import AUDIT_GAME, hold_row

    problems = check_claim(claim)
    if problems:
        raise ValueError(f"not a valid audit-game record: {problems[0]}")
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    oid = attest(repo, run, claim, signer=signer, key=key, algorithm="ed25519",
                 signed_at=claim["at"])  # fmt: skip
    hold_row(repo, oid, f"{AUDIT_GAME}{claim['game']}")
    return oid


def records(repo: Any, game: str | None = None) -> dict[str, list[dict[str, Any]]]:
    """``{game: [{oid, run, signer, signed, claim}]}`` from the held records."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation
    from opentine.repository._holds import AUDIT_GAME, holds_path, read_holds

    out: dict[str, list[dict[str, Any]]] = {}
    for row in read_holds(holds_path(repo)):
        if not row["target"].startswith(AUDIT_GAME):
            continue
        name = row["target"][len(AUDIT_GAME) :]
        if game is not None and name != game:
            continue
        try:
            payload = repo.get(row["oid"]).payload()
        except Exception:  # noqa: BLE001 - an unreadable record is reported
            payload = {}
        result = verify_attestation(payload, trust_embedded=True) if payload else None
        # The signer field is signed text, not the key: it must name the key that signed.
        used = used_key_fingerprint(payload.get("signature")) if payload else None
        signed = bool(result and result.ok and result.algorithm == "ed25519"
                      and used == payload.get("signer"))  # fmt: skip
        claim = payload.get("claim")
        out.setdefault(name, []).append({
            "oid": row["oid"], "run": payload.get("target_id"), "signer": payload.get("signer"),
            "signed": signed, "claim": claim if isinstance(claim, dict) else None})  # fmt: skip
    return out


def latest(rows: list[dict[str, Any]], step: str) -> dict[str, Any] | None:
    found = [r for r in rows if r["signed"] and (r["claim"] or {}).get("step") == step]
    return max(found, key=lambda r: (r["claim"]["at"], r["oid"])) if found else None


__all__ = ["CONVENTION", "GAME_RE", "STEPS", "VERDICTS", "check_claim", "commitment", "latest",
           "now", "record", "records", "secret"]  # fmt: skip
