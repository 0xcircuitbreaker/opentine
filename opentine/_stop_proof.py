"""Signed stop and continue proofs: claim conventions on existing attestations.

A **fleet stop** is an attestation whose claim follows ``opentine.fleet-stop/1``::

    {"convention": "opentine.fleet-stop/1", "fleet": FLEET, "reason": TEXT,
     "stopped_at": "YYYY-MM-DDTHH:MM:SSZ", "channel": VKEY,
     "checkpoint": {"origin", "size", "root"}}

A **continue proof** is an attestation whose claim follows
``opentine.stop-continue/1``::

    {"convention": "opentine.stop-continue/1", "fleet": FLEET, "run": RUN,
     "seq": N, "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "window_s": T,
     "channel": VKEY, "checkpoint": {"origin", "size", "root"}}

Both are bound to the stop channel's log key (``channel``) and to a checkpoint
of that log the signer saw; both are appended to the channel
(:mod:`opentine._stop_channel`). ``seq`` increases per fleet and run, so a
runner that has accepted proof N refuses N-1 (rollback). Neither adds an object
kind or a ``tine verify`` code.

A proof counts only when it is Ed25519-signed, its ``signer`` is the key that
signed (``used_key_fingerprint``) and that key is a pinned ``stopper`` or
``policy`` key of the owner-signed trust bundle, never an ``optimizer`` key
(:func:`opentine._key_roles_pin.granting`). A stop entry halts whether or not it
verifies (fail safe); a continue proof that does not verify is ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

STOP = "opentine.fleet-stop/1"
CONTINUE = "opentine.stop-continue/1"
AUTHORITY_ROLES = ("stopper", "policy")
MAX_REASON = 1024
MAX_WINDOW_S = 86400


def _control_run(repo: Any, fleet: str, what: str) -> str:
    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet

    run = Run(id=f"fleet-{what}-{fleet}", model_info="opentine/fleet-stop",
              user_prompt=f"{what} fleet {fleet}", policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": f"fleet {fleet}: {what}"})
    return repo.put_run(run).run_id


def sign(repo: Any, claim: dict[str, Any], key: Any, what: str) -> tuple[str, dict[str, Any]]:
    """Store *claim* as an Ed25519-signed attestation; ``(oid, payload)``."""
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest

    signer = key_fingerprint(key.public_key().public_bytes_raw())
    target = _control_run(repo, claim["fleet"], what)
    oid = attest(repo, target, claim, signer=signer, key=key, algorithm="ed25519")
    return oid, repo.get(oid).payload()


def stop_claim(fleet: str, reason: str, at: str, vkey: str, checkpoint: dict) -> dict:
    if not isinstance(reason, str) or len(reason.encode("utf-8")) > MAX_REASON:
        raise ValueError(f"a stop reason is text of at most {MAX_REASON} bytes")
    return {"convention": STOP, "fleet": fleet, "reason": reason, "stopped_at": at,
            "channel": vkey, "checkpoint": checkpoint}  # fmt: skip


def continue_claim(fleet: str, run: str, seq: int, at: str, window_s: int, vkey: str,
                   checkpoint: dict) -> dict:  # fmt: skip
    if not isinstance(run, str) or not run or len(run) > 256:
        raise ValueError("a continue proof names a run id of 1 to 256 characters")
    if type(window_s) is not int or not 1 <= window_s <= MAX_WINDOW_S:
        raise ValueError(f"a freshness window is 1 to {MAX_WINDOW_S} seconds")
    return {"convention": CONTINUE, "fleet": fleet, "run": run, "seq": seq, "issued_at": at,
            "window_s": window_s, "channel": vkey, "checkpoint": checkpoint}  # fmt: skip


def authorities(store: Path | None) -> tuple[set[str], str]:
    """The keys that may sign stops and continues here, and why another may not."""
    from opentine._key_roles_pin import granting

    keys: set[str] = set()
    reasons = []
    for role in AUTHORITY_ROLES:
        held, why = granting(store, role)
        keys |= held
        reasons.append(why)
    return keys, ("the signer is not a pinned stopper or policy key" if keys else
                  "; ".join(reasons))  # fmt: skip


def check(payload: Any, convention: str, keys: set[str], refusal: str) -> str | None:
    """``None`` when *payload* is a valid proof of *convention* by one of *keys*."""
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    claim = payload.get("claim") if isinstance(payload, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != convention:
        return f"not an {convention} claim"
    result = verify_attestation(payload, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return f"signature {result.state}"
    signer = payload.get("signer")
    if used_key_fingerprint(payload.get("signature")) != signer:
        return "the signer field does not name the key that signed"
    if signer not in keys:
        return refusal
    return None


def well_formed_continue(claim: dict[str, Any]) -> bool:
    point = claim.get("checkpoint")
    return (
        isinstance(claim.get("run"), str)
        and type(claim.get("seq")) is int
        and claim["seq"] >= 1
        and type(claim.get("window_s")) is int
        and 1 <= claim["window_s"] <= MAX_WINDOW_S
        and isinstance(claim.get("issued_at"), str)
        and isinstance(claim.get("channel"), str)
        and isinstance(point, dict)
        and type(point.get("size")) is int
        and isinstance(point.get("root"), str)
        and isinstance(point.get("origin"), str)
    )


def parse_at(text: Any) -> int | None:
    """Milliseconds since the epoch for ``YYYY-MM-DDTHH:MM:SSZ``, or ``None``."""
    from datetime import datetime

    if not isinstance(text, str):
        return None
    try:
        return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S%z").timestamp() * 1000)
    except ValueError:
        return None


def rfc3339(ms: int) -> str:
    from opentine._utc import rfc3339_utc

    return rfc3339_utc(ms / 1000)


__all__ = ["AUTHORITY_ROLES", "CONTINUE", "STOP", "authorities", "check", "continue_claim",
           "parse_at", "rfc3339", "sign", "stop_claim", "well_formed_continue"]  # fmt: skip
