"""The DSSE-signed in-toto ``replay/v1`` statement (SPEC 8.8) for the pyz (0.50, family 81).

A port of ``_intoto_replay.verify_envelope`` and ``validate_predicate``: the
envelope's payload type, strict base64, an Ed25519 signature by the pinned key
over the DSSE pre-authentication encoding, then the predicate's shape.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .._ed25519_order import weak_public_key
from . import _ed25519
from ._gitobj import Refused

PAYLOAD_TYPE = "application/vnd.in-toto+json"
REPLAY = "https://opentine.dev/attestation/replay/v1"


def _key(value: dict) -> bytes | None:
    return bytes.fromhex(value["public_key"]) if value.get("public_key") else None


def _predicate_errors(predicate: Any) -> list[str]:
    """``_intoto_replay.validate_predicate``."""
    if not isinstance(predicate, dict):
        return ["predicate is not an object"]
    errors = []
    if predicate.get("mode") not in ("cache", "rerun"):
        errors.append("mode must be cache or rerun")
    replay, result = predicate.get("replay"), predicate.get("result")
    if not isinstance(replay, dict) or not isinstance(replay.get("replay_id"), str):
        errors.append("replay.replay_id must be a string")
    if not isinstance(result, dict):
        return [*errors, "result must be an object"]
    bools = ("reproduced", "identity_ok", "integrity_ok", "ignore_cost_drift")
    errors += [f"result.{k} must be a boolean" for k in bools if type(result.get(k)) is not bool]
    if result.get("slice_ok") not in (True, False, None):
        errors.append("result.slice_ok must be a boolean or null")
    for name in ("structural_drift", "accounting_drift"):
        found = result.get(name)
        if not isinstance(found, list) or not all(isinstance(v, str) for v in found):
            errors.append(f"result.{name} must be a list of strings")
    for name in ("fidelity", "verifier"):
        if not isinstance(predicate.get(name), dict):
            errors.append(f"{name} must be an object")
    if not isinstance(predicate.get("verified_at"), str):
        errors.append("verified_at must be a string")
    return errors


def replay_verify(raw: Any, value: dict, args: dict) -> dict:
    envelope, key = value["envelope"], _key(value)
    if key is None or len(key) != 32 or weak_public_key(key):
        raise Refused("replay.malformed", "the pinned key is not a usable Ed25519 key")
    try:
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            raise Refused("replay.malformed", f"payloadType must be {PAYLOAD_TYPE}")
        body = base64.b64decode(envelope["payload"], validate=True)
        sigs = [base64.b64decode(s["sig"], validate=True) for s in envelope["signatures"]]
    except (KeyError, TypeError, binascii.Error) as exc:
        raise Refused("replay.malformed", "malformed DSSE envelope") from exc
    kind = PAYLOAD_TYPE.encode("utf-8")
    signed = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)
    if not any(_ed25519.verify(key, signed, sig) for sig in sigs):
        raise Refused("replay.bad-signature", "no signature verifies over the payload")
    statement = json.loads(body)
    if not isinstance(statement, dict) or statement.get("predicateType") != REPLAY:
        raise Refused("replay.malformed", f"predicateType is not {REPLAY}")
    errors = _predicate_errors(statement.get("predicate"))
    if errors:
        raise Refused("replay.malformed", "; ".join(errors))
    return statement


__all__ = ["replay_verify"]
