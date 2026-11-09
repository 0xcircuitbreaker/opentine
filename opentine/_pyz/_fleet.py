"""Signed ``opentine-fleet-record/1`` documents for ``tine-verify.pyz`` (SPEC 4.11, 0.48).

A stdlib port of ``opentine._fleet_record.validate``/``verify``; names are
normalised by the vendored ``_agent_identity`` (the same code the reference
runs). Refusals are :class:`Refused` with ``fleet.*`` codes.
"""

from __future__ import annotations

import re
from typing import Any

from .. import _agent_identity as identity
from .. import kernel
from . import _sig
from ._gitobj import Refused

SCHEME = "opentine-fleet/1"
SIGNED_SCHEME = "opentine-fleet-record/1"
DOMAIN = b"opentine.fleet.v1:"
FIELDS = ("fleet_id", "member", "role", "parent")
ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def _no(code: str, message: str) -> Refused:
    return Refused(f"fleet.{code}", message)


def validate(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("scheme") != SCHEME:
        raise _no("malformed", "not an opentine-fleet/1 record")
    if set(record) != {"scheme", *FIELDS}:
        raise _no("malformed", "an opentine-fleet/1 record has exactly scheme and the four fields")
    for name in FIELDS:
        value = record[name]
        if not isinstance(value, str) or value != identity.normalize_name(value):
            raise _no("malformed", f"fleet field {name!r} must be a normalised short string")
    if not ID.fullmatch(record["fleet_id"]):
        raise _no("malformed", "fleet_id must be 1..128 of [A-Za-z0-9_.-]")
    return dict(record)


def verify(document: Any, public_key: bytes | None = None) -> dict[str, Any]:
    """The record, run binding and ``state``; raises :class:`Refused`."""
    if not isinstance(document, dict) or document.get("scheme") != SIGNED_SCHEME:
        raise _no("malformed", f"not an {SIGNED_SCHEME} document")
    record = validate(document.get("record"))
    if not {"run_id", "run_digest"} <= set(document):
        raise _no("malformed", "the document has no run_id or run_digest")
    body = {key: document[key] for key in ("scheme", "record", "run_id", "run_digest")}
    block = document.get("signature")
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        raise _no("bad-signature", "signature error: Ed25519 only")
    raw = block.get("public_key")
    if public_key is not None and raw != public_key.hex():
        raise _no("wrong-key", "signature mismatch: embedded public key is not the trusted key")
    key = public_key or (bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else None)

    def message(header: dict[str, Any]) -> bytes:
        return DOMAIN + kernel.canonical_json({"body": body, "header": header})

    ok, state, reason = _sig.verify_block(
        block, message, ("tine-sig/3",), hmac_key=None, public_key=key
    )
    if not ok:
        raise _no("bad-signature", f"signature {state}: {reason}")
    return {**record, "run_id": document["run_id"], "run_digest": document["run_digest"],
            "state": "verified" if public_key is not None else "verified-tofu"}  # fmt: skip


__all__ = ["Refused", "validate", "verify"]
