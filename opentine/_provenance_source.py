"""Reading a v1/v2 source artifact for ``upgraded_from`` (migrate and verify).

One read: the bytes that are hashed are the bytes that are parsed, verified
and loaded, so a swap between reads cannot pair one file's digest with
another's run. The signature is checked with the existing ``verify_artifact``
(via ``_cli_security.signature_result``, so ``--pubkey``/``--pin``/HMAC flags
mean exactly what they mean to ``tine verify``).
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Any


def read_source(path: Path) -> tuple[str, dict[str, Any]]:
    """``(sha256 hex of the bytes after TINEZ1 unwrap, parsed artifact)``."""
    from opentine._artifact_io import parse_artifact_json, read_artifact_bytes

    unwrapped = read_artifact_bytes(path)
    data = parse_artifact_json(unwrapped)
    if not isinstance(data, dict):
        raise ValueError(".tine artifact root must be an object")
    return hashlib.sha256(unwrapped).hexdigest(), data


def source_format(data: dict[str, Any]) -> str:
    """``tine/2`` for format 2; ``tine/1`` for format 1 and the pre-1 linear layout."""
    return "tine/2" if data.get("format_version") == 2 else "tine/1"


def _basis(args: argparse.Namespace, state: str, fpr: str | None) -> str:
    from opentine._verify_offline import _basis as offline_basis

    if state in ("verified", "verified-tofu"):
        return offline_basis(args, fpr, tofu=state == "verified-tofu")
    if state == "unsigned":
        return "none: the source carries no signature"
    return "none: no key verified the source signature"


def signature_claim(args: argparse.Namespace, path: Path, data: dict[str, Any]) -> dict[str, Any]:
    """The ``upgraded_from.signature`` block: the verdict on the source, right now."""
    from opentine._artifact_io import artifact_signature
    from opentine._cli_security import signature_requested, signature_result
    from opentine.core import Run

    block = artifact_signature(data)
    scheme = block.get("scheme") if isinstance(block, dict) else None
    if signature_requested(args):
        verdict, fpr = signature_result(args, path, data)
    else:
        verdict, fpr = Run.verify_signature(data), None
    state = verdict.state or "error"
    return {
        "key_fingerprint": fpr if state in ("verified", "verified-tofu") else None,
        "scheme": scheme if isinstance(scheme, str) else None,
        "state": state,
        "trust_basis": _basis(args, state, fpr),
    }


def upgrade_record(
    args: argparse.Namespace, path: Path, digest: str, data: dict[str, Any]
) -> dict[str, Any]:
    """The ``upgraded_from`` record for a v1/v2 source already read by ``read_source``."""
    from opentine import _provenance_v4 as provenance
    from opentine._artifact_io import artifact_integrity

    claim = signature_claim(args, path, data)
    integrity = artifact_integrity(data) or {}  # the recorded 3.5 digest, not a recompute
    record = provenance.build(
        source_format(data),
        digest,
        integrity_digest=integrity.get("digest"),
        scheme=claim["scheme"],
        state=claim["state"],
        key_fingerprint=claim["key_fingerprint"],
        trust_basis=claim["trust_basis"],
    )
    return record


__all__ = ["read_source", "signature_claim", "source_format", "upgrade_record"]
