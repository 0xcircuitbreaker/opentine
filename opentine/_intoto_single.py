"""Verify a single-predicate in-toto DSSE envelope (``fleet/v1``, ``replay/v1``).

Each predicate module keeps its public ``verify_envelope``; this is the one
body behind them, so the envelope checks and their error strings cannot drift.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from typing import Any

from opentine.intoto import PAYLOAD_TYPE, pae


def verify_single(
    envelope: Any,
    public_key: Any,
    predicate_type: str,
    validate: Callable[[Any], list[str]],
) -> dict[str, Any]:
    """The statement of a *predicate_type* envelope signed by *public_key*; ``ValueError`` else."""
    from cryptography.exceptions import InvalidSignature

    from opentine._signing_keys import coerce_ed25519_public

    key = coerce_ed25519_public(public_key)
    try:
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            raise ValueError(f"payloadType must be {PAYLOAD_TYPE}")
        body = base64.b64decode(envelope["payload"], validate=True)
        sigs = [base64.b64decode(s["sig"], validate=True) for s in envelope["signatures"]]
    except (KeyError, TypeError, binascii.Error) as exc:
        raise ValueError("malformed DSSE envelope") from exc
    for sig in sigs:
        try:
            key.verify(sig, pae(PAYLOAD_TYPE, body))
            break
        except InvalidSignature:
            continue
    else:
        raise ValueError("no signature verifies over the payload")
    statement = json.loads(body)
    if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
        raise ValueError(f"predicateType is not {predicate_type}")
    errors = validate(statement.get("predicate"))
    if errors:
        raise ValueError("; ".join(errors))
    return statement


__all__ = ["verify_single"]
