"""in-toto ``fleet/v1``: a run's fleet membership as a signed attestation (0.43).

``tine fleet record RUN --attest OUT --attest-key KEY`` writes one DSSE
envelope (``intoto.sign_statement``, Ed25519) around an in-toto Statement v1
whose subject is the run's content digest and whose ``predicateType`` is
:data:`PREDICATE_TYPE`. The predicate is the ``opentine-fleet/1`` record
(``_fleet_record``), the run's agent ref, and -- when the run carries one --
the digests of its ``opentine-delegation/1`` chain, root first. No prompt or
completion text. :func:`verify_envelope` checks signature and shape offline.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from opentine.intoto import PAYLOAD_TYPE, STATEMENT_TYPE, pae

PREDICATE_TYPE = "https://opentine.dev/attestation/fleet/v1"


def build_predicate(run: Any, record: dict[str, Any]) -> dict[str, Any]:
    from opentine import __version__
    from opentine._agent_identity import run_agent_ref
    from opentine._delegation import DelegationError, digest

    chain = run.metadata.get("delegation") if isinstance(run.metadata, dict) else None
    try:
        links = [digest(cert) for cert in chain] if isinstance(chain, list) else []
    except DelegationError:
        links = []
    return {
        "producer": {"id": "https://opentine.dev/tine", "version": __version__},
        "fleet": dict(record),
        "agent_ref": run_agent_ref(run),
        "delegation": links,
    }


def build_statement(run: Any, record: dict[str, Any], digest: str) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": run.id, "digest": {"sha256": digest.rsplit(":", 1)[-1]}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": build_predicate(run, record),
    }


def validate_predicate(predicate: Any) -> list[str]:
    """Every way *predicate* departs from ``fleet/v1``; empty when it conforms."""
    from opentine._fleet_record import validate

    if not isinstance(predicate, dict):
        return ["predicate is not an object"]
    errors = []
    try:
        validate(predicate.get("fleet"))
    except ValueError as exc:
        errors.append(f"fleet: {exc}")
    if not isinstance(predicate.get("agent_ref"), str):
        errors.append("agent_ref must be a string")
    links = predicate.get("delegation")
    if not isinstance(links, list) or not all(isinstance(v, str) for v in links):
        errors.append("delegation must be a list of digests")
    if not isinstance(predicate.get("producer"), dict):
        errors.append("producer must be an object")
    return errors


def verify_envelope(envelope: Any, public_key: Any) -> dict[str, Any]:
    """The statement of a ``fleet/v1`` envelope signed by *public_key*; ``ValueError`` else."""
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
    if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError(f"predicateType is not {PREDICATE_TYPE}")
    errors = validate_predicate(statement.get("predicate"))
    if errors:
        raise ValueError("; ".join(errors))
    return statement


__all__ = [
    "PREDICATE_TYPE",
    "build_predicate",
    "build_statement",
    "validate_predicate",
    "verify_envelope",
]
