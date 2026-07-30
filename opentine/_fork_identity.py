"""Fork-act identity: the recorded basis behind every v2 fork id.

A fork id must never be built by concatenating strings that arrive inside an
untrusted ``.tine`` artifact, because run ids feed ``runs_dir / f"{id}.tine"``
output paths. Everything attacker-influenceable (the source run id, the fork
point, the retained step ids, the claimed integrity digest) enters the id only
as a hash input, so the id is always a 64-hex SHA-256 digest that cannot steer
a write path. A locally drawn 128-bit nonce makes two fork *acts* of the same
point distinct — no fork-time function of content can separate them, because
they diverge only later — while recording the nonce keeps the id verifiable.

Layering: stdlib + ``opentine._canon`` + ``opentine._graph_types`` only, so
``_graph_analysis`` (which already imports ``_graph_types``) can import this
module without a cycle.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

from opentine._canon import _canonical_bytes
from opentine._graph_types import StepKind, step_id

#: Stamped into every recorded fork basis; bump on any change to the derivation.
FORK_IDENTITY_VERSION = 1

_HEX64 = re.compile(r"[0-9a-f]{64}")


def _claimed_digest(metadata: Any) -> str:
    """The 64-hex integrity digest ``metadata`` claims, or ``""``.

    ``metadata`` comes straight out of an untrusted artifact and its
    ``integrity`` block is only shape-checked when a signature is verified, so
    every access here is defensive: any missing or malformed shape is the empty
    claim, never an exception. The digest is what the source *claims*, not a
    verified fact; pair with ``Run.verify_integrity`` for a real binding.
    """
    integrity = metadata.get("integrity") if isinstance(metadata, dict) else None
    digest = integrity.get("digest") if isinstance(integrity, dict) else None
    return digest if isinstance(digest, str) and _HEX64.fullmatch(digest) else ""


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def fork_record(
    *,
    source_id: str,
    fork_point: str,
    retained_ids: Any,
    branch: str,
    intent: dict | None,
    nonce: str | None,
    source_metadata: dict,
) -> dict:
    """The recorded basis of one fork act, ready to hash and to store.

    ``nonce=None`` draws 128 bits from the local CSPRNG (a divergent act, never
    predictable from a shipped artifact); ``nonce=""`` keeps the empty string
    (an idempotent act with a reproducible id, at the caller's request). Every
    attacker-influenceable input is coerced to ``str`` or reduced to a digest
    here, so the record — and therefore the id — is total on hostile artifacts.
    """
    if nonce is None:
        nonce = secrets.token_hex(16)
    retained = sorted(str(step) for step in retained_ids)
    return {
        "branch": str(branch),
        "intent": _digest(intent or {}),
        "nonce": str(nonce),
        "point": str(fork_point),
        "slice": _digest(retained),
        "slice_size": len(retained),
        "source": str(source_id),
        "source_digest": _claimed_digest(source_metadata),
        "version": FORK_IDENTITY_VERSION,
    }


def fork_id(record: dict) -> str:
    """The run id a fork record produces: a typed step id, always 64 hex chars."""
    return step_id(StepKind.model, {"fork": record})


def verify_fork_id(run: Any) -> bool | None:
    """Does ``run.id`` match the fork basis the artifact records?

    ``True``: the id is exactly what ``metadata["fork"]`` re-derives.
    ``False``: a record is present but does not produce the id (edited).
    ``None``: no verdict — no record (explicit ``new_run_id``, pre-0.4.0 fork,
    or a v3 rewrite that dropped it) or a record versioned beyond this build.

    Total on hostile input by construction: the record is untrusted, so a shape
    canonical hashing rejects (over-deep nesting, non-finite floats, non-JSON
    values, cycles) is a ``False`` verdict, never an exception. This is a
    provenance check, not an authorization check: it never gates a write, and
    an artifact author can always make their own artifact self-consistent.
    """
    metadata = getattr(run, "metadata", None)
    if not isinstance(metadata, dict) or "fork" not in metadata:
        return None
    record = metadata["fork"]
    if not isinstance(record, dict):
        return False
    version = record.get("version")
    # `True == 1`, so an explicit isinstance check keeps a bool out of the gate.
    if type(version) is not int or version != FORK_IDENTITY_VERSION:
        return None
    try:
        expected = fork_id(record)
    except Exception:
        return False
    run_id = getattr(run, "id", None)
    return isinstance(run_id, str) and run_id == expected
