"""in-toto ``replay/v1``: a ``tine replay --verify`` verdict as an attestation (0.39).

``tine replay RUN --verify --attest OUT.intoto.jsonl --attest-key KEY`` writes
one DSSE envelope (``intoto.sign_statement``, Ed25519) around an in-toto
Statement v1 whose subject is the *source* run's content digest and whose
``predicateType`` is :data:`PREDICATE_TYPE`. The predicate records what was
compared and what was found -- mode, the two derived ids, slice and integrity
results, drift field names and the fidelity labels -- and never prompt or
completion text. A drifting replay is attested too: the attestation is
evidence of the verdict, whatever it was. :func:`validate_predicate` is the
shape check, and :func:`verify_envelope` checks signature and shape offline.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine.intoto import PAYLOAD_TYPE, STATEMENT_TYPE, pae, sign_statement

PREDICATE_TYPE = "https://opentine.dev/attestation/replay/v1"
MODES = ("cache", "rerun")
_RESULT_BOOLS = ("reproduced", "identity_ok", "integrity_ok", "ignore_cost_drift")


def add_replay_attest_args(parser: Any) -> None:
    parser.add_argument("--attest", metavar="OUT", help="With --verify: write a replay/v1 DSSE")
    parser.add_argument("--attest-key", metavar="KEY", help="Ed25519 key file signing --attest")


def build_predicate(verdict: Any) -> dict[str, Any]:
    from opentine import __version__

    return {
        "verifier": {"id": "https://opentine.dev/tine", "version": __version__},
        "mode": verdict.mode,
        "replay": {
            "replay_id": verdict.replay_id,
            "second_id": verdict.second_id,
            "fork_point": verdict.fork_point,
            "expected_steps": verdict.expected_steps,
            "reused_steps": verdict.reused_steps,
        },
        "result": {
            "reproduced": bool(verdict.reproduced),
            "identity_ok": bool(verdict.identity_ok),
            "integrity_ok": bool(verdict.integrity.ok),
            "slice_ok": verdict.slice_ok,
            "ignore_cost_drift": bool(verdict.ignore_cost_drift),
            "structural_drift": list(verdict.structural),
            "accounting_drift": list(verdict.accounting),
        },
        "fidelity": verdict.fidelity.to_dict(verdict.min_fidelity),
        "verified_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_statement(verdict: Any, run_id: str, digest: str) -> dict[str, Any]:
    hex_digest = digest.rsplit(":", 1)[-1]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": run_id, "digest": {"sha256": hex_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": build_predicate(verdict),
    }


def validate_predicate(predicate: Any) -> list[str]:
    """Every way *predicate* departs from ``replay/v1``; empty when it conforms."""
    if not isinstance(predicate, dict):
        return ["predicate is not an object"]
    errors = []
    if predicate.get("mode") not in MODES:
        errors.append("mode must be cache or rerun")
    replay, result = predicate.get("replay"), predicate.get("result")
    if not isinstance(replay, dict) or not isinstance(replay.get("replay_id"), str):
        errors.append("replay.replay_id must be a string")
    if not isinstance(result, dict):
        return [*errors, "result must be an object"]
    errors += [
        f"result.{k} must be a boolean" for k in _RESULT_BOOLS if type(result.get(k)) is not bool
    ]
    if result.get("slice_ok") not in (True, False, None):
        errors.append("result.slice_ok must be a boolean or null")
    for name in ("structural_drift", "accounting_drift"):
        value = result.get(name)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            errors.append(f"result.{name} must be a list of strings")
    if not isinstance(predicate.get("fidelity"), dict):
        errors.append("fidelity must be an object")
    if not isinstance(predicate.get("verifier"), dict):
        errors.append("verifier must be an object")
    if not isinstance(predicate.get("verified_at"), str):
        errors.append("verified_at must be a string")
    return errors


def verify_envelope(envelope: Any, public_key: Any) -> dict[str, Any]:
    """The statement of a ``replay/v1`` envelope signed by *public_key*; ``ValueError`` else."""
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


def attest(args: Any, verdict: Any, path: str | Path) -> None:
    """``--attest``: write the envelope for *verdict* (a ``_cli_verify_replay.Verdict``)."""
    if not getattr(args, "attest", None):
        return
    from opentine._cli_errors import USAGE, fail
    from opentine._export_write import write_private
    from opentine._signing_keys import SignatureError, ed25519_private_from_file
    from opentine.core import Run

    if not getattr(args, "attest_key", None):
        fail("--attest needs --attest-key: the envelope is signed", USAGE)
    source = Run.verify_integrity(path)
    if not source.ok or not isinstance(source.actual, str):
        fail(f"cannot attest: the source run fails integrity ({source.reason})")
    try:
        key = ed25519_private_from_file(args.attest_key)
        statement = build_statement(verdict, verdict.run_id, source.actual)
        envelope = sign_statement(statement, key)
        line = json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
        write_private(Path(args.attest), line.encode("utf-8"))
    except (OSError, SignatureError, ValueError) as exc:
        fail(f"cannot write --attest: {exc}", cause=exc)


__all__ = [
    "PREDICATE_TYPE",
    "add_replay_attest_args",
    "attest",
    "build_predicate",
    "build_statement",
    "validate_predicate",
    "verify_envelope",
]
