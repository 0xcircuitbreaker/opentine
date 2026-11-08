"""``opentine.redacted-copy``: a public copy's link to its private run (0.46, SPEC 4.15).

``tine bundle create --redacted-public`` derives a public copy of one run: every
blob it reaches is re-redacted with the current ruleset, every JSON payload is
redacted again, and each event and the run are rewritten to link the new oids
(:mod:`opentine._redacted_derive`). The copy has its own run oid. Its bundle
carries this signed record, which links the two without exposing the private
objects: exactly these fields plus a ``tine-sig/3`` block over
``opentine.redacted-copy.v1:`` + JCS of ``{body, header}``
(:mod:`opentine._signed_record`):

    {"kind": "opentine.redacted-copy", "copy_version": 1,
     "source_run": "run:sha256:…", "public_run": "run:sha256:…",
     "ruleset": "opentine-redaction/2", "objects": N, "redacted": M,
     "pack": "sha256:<the bundled pack>"}

``objects`` counts the pack's objects and ``redacted`` how many of them differ
from the private object they were derived from. Content addressing makes the
two run oids equal exactly when nothing changed, so ``redacted == 0`` and
``source_run == public_run`` must agree (``redacted-copy.inconsistent``), and
``redacted`` cannot exceed ``objects``. :func:`check` is the reference for the
``redacted-copy.verify`` conformance op (``64-redacted-copy.json``).
"""

from __future__ import annotations

from typing import Any

from opentine._signed_record import (
    DIGEST,
    NAME,
    RUN_OID,
    RecordError,
    check_signature,
    fields,
    is_count,
)
from opentine._signed_record import sign as _sign

KIND = "opentine.redacted-copy"
DOMAIN = b"opentine.redacted-copy.v1:"
FIELDS = ("kind", "copy_version", "source_run", "public_run", "ruleset", "objects",
          "redacted", "pack")  # fmt: skip
CODE = "redacted-copy"
SUBJECT = "redacted copy"


def _malformed(message: str) -> RecordError:
    return RecordError("redacted-copy.malformed", f"redacted copy is malformed: {message}")


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules."""
    out = fields(record, KIND, FIELDS, CODE, SUBJECT)
    if isinstance(out["copy_version"], bool) or out["copy_version"] != 1:
        raise _malformed("copy_version must be 1")
    for name in ("source_run", "public_run"):
        if not isinstance(out[name], str) or not RUN_OID.fullmatch(out[name]):
            raise _malformed(f"{name} must be a run oid")
    if not isinstance(out["ruleset"], str) or not NAME.fullmatch(out["ruleset"]):
        raise _malformed("ruleset must be a name")
    for name in ("objects", "redacted"):
        if not is_count(out[name]):
            raise _malformed(f"{name} must be a count")
    if not isinstance(out["pack"], str) or not DIGEST.fullmatch(out["pack"]):
        raise _malformed("pack must be sha256:<64 hex>")
    return out


def sign(record: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm=algorithm, **header)


def consistent(found: dict[str, Any]) -> None:
    if found["redacted"] > found["objects"]:
        raise RecordError("redacted-copy.inconsistent", "redacted exceeds objects")
    if (found["redacted"] == 0) != (found["source_run"] == found["public_run"]):
        raise RecordError(
            "redacted-copy.inconsistent",
            "the run oids must be equal exactly when no object was redacted",
        )


def check(
    record: Any,
    *,
    hmac_key: bytes | None = None,
    public_key: bytes | None = None,
    pack: str | None = None,
) -> dict[str, Any]:
    """``{source_run, public_run, objects, redacted, state}``; :class:`RecordError` else.

    *pack*, when given, is the ``sha256:`` digest of the pack the record came
    with; a record for another pack is ``redacted-copy.pack-mismatch``.
    """
    found = body(record)
    state = check_signature(
        record,
        found,
        domain=DOMAIN,
        code=CODE,
        subject=SUBJECT,
        hmac_key=hmac_key,
        public_key=public_key,
    )
    consistent(found)
    if pack is not None and pack != found["pack"]:
        raise RecordError("redacted-copy.pack-mismatch", "the record names another pack")
    return {
        "source_run": found["source_run"],
        "public_run": found["public_run"],
        "objects": found["objects"],
        "redacted": found["redacted"],
        "state": state,
    }


__all__ = ["DOMAIN", "FIELDS", "KIND", "body", "check", "consistent", "sign"]
