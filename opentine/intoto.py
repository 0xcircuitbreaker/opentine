"""in-toto Statement v1 provenance for a run, in a signed DSSE envelope.

``tine export RUN --format intoto`` writes one envelope per line
(``.intoto.jsonl``): an in-toto ``Statement`` whose single subject is the run's
content address -- the sha256 integrity digest ``tine verify`` prints -- and
whose predicate (``PREDICATE_TYPE``) is content-free provenance: run id,
status, models and providers, step count, fork lineage, token/cost totals and
the opentine version. Prompts, completions, tool inputs and outputs are never
in it; every string is passed through the writer's redaction anyway.

The envelope is DSSE v1: the statement's canonical JSON, base64 in
``payload``, signed with Ed25519 over the pre-authentication encoding
``"DSSEv1" SP len(type) SP type SP len(body) SP body``. The signature's
``keyid`` is the key's ``did:key``, so the envelope names its key in a form
other in-toto tooling understands; it is still only a claim until pinned.

``verify_envelope`` is fail-closed: an envelope passes only when a signature
verifies under a key the caller trusts (``public_key``, a ``pins`` match, or
explicit trust-on-first-use) *and* the statement is well formed; ``check_subject``
then binds it to a run artifact by recomputing that artifact's digest.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from opentine._signing_keys import SignatureError, coerce_ed25519_public, load_ed25519_private
from opentine._signing_pins import key_fingerprint
from opentine.did_key import did_from_public, public_from_did
from opentine.kernel import canonical_json

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://opentine.dev/attestation/run/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_ENVELOPE_BYTES = 1 << 20
_HEX64 = re.compile(r"[0-9a-f]{64}")


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def _text(value: Any, limit: int = 256) -> str:
    from opentine.redaction import redact_value

    return str(redact_value(value if isinstance(value, str) else ""))[:limit]


def _lineage(run: Any) -> dict[str, Any]:
    meta = run.metadata if isinstance(run.metadata, dict) else {}
    out = {name: _text(meta.get(name)) for name in ("forked_from", "fork_point")}
    return {name: value for name, value in out.items() if value}


def build_predicate(run: Any) -> dict[str, Any]:
    """Content-free provenance for *run*: counts, names and digests, never text."""
    from opentine import __version__
    from opentine._agent_identity import run_agent_ref

    steps = list(run.steps)
    models = sorted({_text(s.model_info) for s in steps if s.model_info} - {""})
    providers = sorted({_text(s.provider) for s in steps if s.provider} - {""})
    return {
        "run": {"id": _text(run.id), "status": _text(str(run.status))},
        "model": _text(run.model_info),
        "models": models,
        "providers": providers,
        "step_count": len(steps),
        "lineage": _lineage(run),
        "agent_ref": _text(run_agent_ref(run)),
        "usage": {"total_tokens": int(run.total_tokens), "total_cost_usd": float(run.total_cost)},
        "opentine_version": __version__,
    }


def build_statement(run: Any, digest: str) -> dict[str, Any]:
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError("subject digest must be 64 lowercase hex characters")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": _text(run.id), "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": build_predicate(run),
    }


def sign_statement(statement: dict[str, Any], private_key: Any) -> dict[str, Any]:
    """A DSSE envelope over *statement*, signed by an Ed25519 *private_key*."""
    key = load_ed25519_private(private_key)
    body = canonical_json(statement)
    sig = key.sign(pae(PAYLOAD_TYPE, body))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode("ascii"),
        "signatures": [
            {
                "keyid": did_from_public(key.public_key()),
                "sig": base64.b64encode(sig).decode("ascii"),
            }
        ],
    }


@dataclass
class EnvelopeResult:
    ok: bool
    status: str  # verified | verified-tofu | no-key | mismatch | error
    reason: str
    keyid: str | None = None
    key_fingerprint: str | None = None
    statement: dict[str, Any] | None = field(default=None, repr=False)


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a base64 string")
    return base64.b64decode(value.encode("ascii"), validate=True)


def _statement(body: bytes) -> dict[str, Any]:
    statement = json.loads(body.decode("utf-8"))
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        raise ValueError("payload is not an in-toto Statement v1")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError(f"predicateType is not {PREDICATE_TYPE}")
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        raise ValueError("statement must name exactly one subject")
    digest = subject[0].get("digest")
    if not isinstance(digest, dict) or not _HEX64.fullmatch(str(digest.get("sha256", ""))):
        raise ValueError("subject has no sha256 digest")
    return statement


def _candidates(signatures: list[Any], public_key, pins, trust_embedded):
    """``(signature, key, tofu)`` pairs this caller is willing to check."""
    for entry in signatures:
        if not isinstance(entry, dict) or set(entry) - {"keyid", "sig"}:
            raise ValueError("malformed DSSE signature entry")
        if public_key is not None:
            yield entry, public_key, False
            continue
        embedded = public_from_did(entry.get("keyid"))
        fpr = key_fingerprint(embedded.public_bytes_raw())
        if pins and fpr in pins:
            yield entry, embedded, False
        elif trust_embedded and not pins:
            yield entry, embedded, True


def verify_envelope(
    envelope: Any,
    *,
    public_key: Any | None = None,
    pins: frozenset[str] = frozenset(),
    trust_embedded: bool = False,
) -> EnvelopeResult:
    """Check a DSSE envelope's signature and statement shape, fail-closed."""
    try:
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            raise ValueError(f"payloadType must be {PAYLOAD_TYPE}")
        body = _b64(envelope.get("payload"))
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise ValueError("envelope carries no signatures")
        trusted = coerce_ed25519_public(public_key) if public_key is not None else None
        pairs = list(_candidates(signatures, trusted, pins, trust_embedded))
    except (SignatureError, ValueError, binascii.Error) as exc:
        return EnvelopeResult(False, "error", str(exc))
    if not pairs:
        return EnvelopeResult(False, "no-key", "no signature under a key this caller trusts")
    message = pae(PAYLOAD_TYPE, body)
    for entry, key, tofu in pairs:
        try:
            key.verify(_b64(entry.get("sig")), message)
        except (InvalidSignature, ValueError, binascii.Error):
            continue
        fpr = key_fingerprint(key.public_bytes_raw())
        try:
            statement = _statement(body)
        except (UnicodeDecodeError, ValueError) as exc:
            return EnvelopeResult(False, "error", f"signed payload refused: {exc}")
        status = "verified-tofu" if tofu else "verified"
        return EnvelopeResult(True, status, "ok", did_from_public(key), fpr, statement)
    return EnvelopeResult(False, "mismatch", "no signature verifies over the payload")


def check_subject(statement: dict[str, Any], artifact: str | Path) -> str | None:
    """Why *artifact* is not the statement's subject, or ``None`` when it is."""
    from opentine._graph_serde import verify_integrity

    integrity = verify_integrity(artifact)
    if not integrity.ok:
        return f"run artifact fails integrity: {integrity.reason}"
    if statement["subject"][0]["digest"]["sha256"] != integrity.actual:
        return "subject digest does not match the run artifact"
    return None


def read_envelopes(path: str | Path) -> list[Any]:
    """The envelopes in a ``.intoto.jsonl`` file (one JSON object per line)."""
    with open(path, "rb") as handle:
        raw = handle.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError(f"attestation file exceeds {MAX_ENVELOPE_BYTES} bytes")
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


__all__ = [
    "PAYLOAD_TYPE",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "EnvelopeResult",
    "build_predicate",
    "build_statement",
    "check_subject",
    "pae",
    "read_envelopes",
    "sign_statement",
    "verify_envelope",
]
