"""``opentine.tombstone``: the signed record that a blob was purged (0.46, SPEC 4.14).

A purge removes a blob's bytes and keeps its oid: every event and run that
links the blob still hashes the same, and the tombstone says why the bytes are
gone, who removed them and when. A tombstone is exactly these fields plus a
``tine-sig/3`` block over ``opentine.tombstone.v1:`` + JCS of
``{body, header}`` (:mod:`opentine._signed_record`):

    {"kind": "opentine.tombstone", "tombstone_version": 1,
     "oid": "blob:sha256:…", "reason": "…", "actor": "…",
     "purged_at": "YYYY-MM-DDTHH:MM:SSZ"}

``reason`` is free text, redacted like any stored string before it is signed,
1 to 1024 UTF-8 bytes with no control characters. :func:`check` is the
reference for the ``tombstone.verify`` conformance op
(``docs/conformance/vectors/63-tombstone.json``), ported to the pyz
(``opentine._pyz._records``) and the TS verifier (``src/records.ts``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from opentine._signed_record import BLOB_OID, NAME, WHEN, RecordError, check_signature, fields
from opentine._signed_record import sign as _sign

KIND = "opentine.tombstone"
DOMAIN = b"opentine.tombstone.v1:"
FIELDS = ("kind", "tombstone_version", "oid", "reason", "actor", "purged_at")
CODE = "tombstone"
SUBJECT = "tombstone"
MAX_REASON_BYTES = 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _malformed(message: str) -> RecordError:
    return RecordError("tombstone.malformed", f"tombstone is malformed: {message}")


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules."""
    out = fields(record, KIND, FIELDS, CODE, SUBJECT)
    version = out["tombstone_version"]
    if isinstance(version, bool) or version != 1:
        raise _malformed("tombstone_version must be 1")
    if not isinstance(out["oid"], str) or not BLOB_OID.fullmatch(out["oid"]):
        raise _malformed("oid must be a blob oid")
    reason = out["reason"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason.encode("utf-8", "surrogatepass")) > MAX_REASON_BYTES
        or _CONTROL.search(reason)
    ):
        raise _malformed("reason must be 1 to 1024 bytes of text without control characters")
    if not isinstance(out["actor"], str) or not NAME.fullmatch(out["actor"]):
        raise _malformed("actor must be a name")
    if not isinstance(out["purged_at"], str) or not WHEN.fullmatch(out["purged_at"]):
        raise _malformed("purged_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    return out


def build(oid: str, reason: str, actor: str, purged_at: str | None = None) -> dict[str, Any]:
    """An unsigned tombstone body; *reason* is redacted first."""
    from opentine.redaction import redact_blob

    clean = redact_blob(reason.strip().encode("utf-8")).decode("utf-8", "replace")
    when = purged_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "kind": KIND,
        "tombstone_version": 1,
        "oid": oid,
        "reason": clean,
        "actor": actor,
        "purged_at": when,
    }
    return body(record)


def sign(record: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm=algorithm, **header)


def check(
    record: Any, *, hmac_key: bytes | None = None, public_key: bytes | None = None
) -> dict[str, Any]:
    """``{oid, actor, purged_at, state}`` for a good tombstone; :class:`RecordError` else."""
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
    return {
        "oid": found["oid"],
        "actor": found["actor"],
        "purged_at": found["purged_at"],
        "state": state,
    }


def well_formed(record: Any) -> dict[str, Any]:
    """*record* when its fields hold and it carries a signature block; refuse else.

    What a server or an importer checks before storing a tombstone it cannot
    verify (an HMAC key is never shared with it): the shape, never the trust.
    """
    body(record)
    if not isinstance(record.get("signature"), dict):
        raise RecordError("tombstone.unsigned", "the tombstone is unsigned")
    return record


__all__ = ["DOMAIN", "FIELDS", "KIND", "body", "build", "check", "sign", "well_formed"]
