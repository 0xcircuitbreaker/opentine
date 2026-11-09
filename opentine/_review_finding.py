"""``opentine.review-finding``: one reviewer's signed finding on a Review (0.48, SPEC 4.25).

``tine review run`` spawns reviewer harnesses through the fleet; each finding
one of them reports becomes one record: the ``review_id`` and ``finding_id``
it belongs to (the finding row of the Review version that lists it), its
``severity``, the repository-relative ``path`` and 1-based ``line`` it points
at (both optional, a line only with a path), the ``message`` (1 to 1024 bytes
of text), the ``reviewer`` that found it (the fleet member's name), the
reviewer's ``run`` oid when it recorded one, and ``created_at``.

A finding is signed (``tine-sig/3``, Ed25519 only) over
``opentine.review-finding.v1:`` + JCS of ``{body, header}`` by the key that
ran the review. :func:`check` is the reference for the ``review-finding.verify``
conformance op (``vectors/74-review-finding.json``), ported to the pyz
(``opentine._pyz._finding``) and the TS verifier (``src/finding.ts``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from opentine._review_rules import ID, SEVERITIES, text_ok
from opentine._signed_record import NAME, RUN_OID, WHEN, RecordError, check_signature
from opentine._signed_record import fields as _fields
from opentine._signed_record import sign as _sign
from opentine.kernel import ObjectEnvelope, canonical_json

KIND = "opentine.review-finding"
DOMAIN = b"opentine.review-finding.v1:"
CODE = "review-finding"
SUBJECT = "review finding"
FIELDS = ("kind", "finding_version", "review_id", "finding_id", "severity", "path", "line",
          "message", "reviewer", "run", "created_at")  # fmt: skip
MAX_LINE = 2**31 - 1
PATH = re.compile(r"[A-Za-z0-9_.@+-][A-Za-z0-9_.@+/ -]{0,1023}")


def _malformed(message: str) -> RecordError:
    return RecordError(f"{CODE}.malformed", f"review finding is malformed: {message}")


def path_ok(value: Any) -> bool:
    """A repository-relative POSIX path: no leading ``/``, no ``..`` or empty part."""
    if not isinstance(value, str) or not PATH.fullmatch(value):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def digest(record: dict[str, Any]) -> str:
    return ObjectEnvelope.create("blob", canonical_json(record)).oid


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules."""
    out = _fields(record, KIND, FIELDS, CODE, SUBJECT)
    line, path, run = out["line"], out["path"], out["run"]
    checks = (
        (type(out["finding_version"]) is int and out["finding_version"] == 1,
         "finding_version is 1"),
        (isinstance(out["review_id"], str) and bool(ID.fullmatch(out["review_id"]))
         and isinstance(out["finding_id"], str) and bool(ID.fullmatch(out["finding_id"])),
         "review_id and finding_id are ids"),
        (out["severity"] in SEVERITIES, "severity is info, low, medium, high or critical"),
        (path is None or path_ok(path), "path is a repository-relative POSIX path or null"),
        (line is None or (type(line) is int and 1 <= line <= MAX_LINE and path is not None),
         "line counts from 1, with a path, or is null"),
        (text_ok(out["message"], 1024), "message is 1 to 1024 bytes of text"),
        (isinstance(out["reviewer"], str) and bool(NAME.fullmatch(out["reviewer"])),
         "reviewer must be a name"),
        (run is None or (isinstance(run, str) and bool(RUN_OID.fullmatch(run))),
         "run is a run oid or null"),
        (isinstance(out["created_at"], str) and bool(WHEN.fullmatch(out["created_at"])),
         "created_at must be an RFC 3339 UTC time"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise _malformed(message)
    return out


def build(review_id: str, finding_id: str, severity: str, message: str, *, reviewer: str,
          path: str | None = None, line: int | None = None, run: str | None = None,
          created_at: str | None = None) -> dict[str, Any]:  # fmt: skip
    record = {
        "kind": KIND,
        "finding_version": 1,
        "review_id": review_id,
        "finding_id": finding_id,
        "severity": severity,
        "path": path,
        "line": line,
        "message": message,
        "reviewer": reviewer,
        "run": run,
        "created_at": created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return body(record)


def sign(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm="ed25519", **header)


def check(record: Any, *, public_key: bytes | None = None, reviewers: Any = ()) -> dict[str, Any]:
    """``{review_id, finding_id, severity, path, line, digest, signer, state}``; refuse else.

    *reviewers* is the hex keys of the Review's reviewers: a finding signed by
    any other key is ``review-finding.untrusted-signer``. With neither it rests
    on its embedded key (``verified-tofu``).
    """
    found = body(record)
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError(f"{CODE}.wrong-key", "a review finding is signed with an Ed25519 key")
    state = check_signature(
        record, found, domain=DOMAIN, code=CODE, subject=SUBJECT, public_key=public_key
    )
    signer = str(block["public_key"])  # type: ignore[index]
    members = set(reviewers or ())
    if members:
        if signer not in members:
            raise RecordError(
                f"{CODE}.untrusted-signer", "the review finding's signer is not a reviewer"
            )
        state = "verified"
    return {
        "review_id": found["review_id"],
        "finding_id": found["finding_id"],
        "severity": found["severity"],
        "path": found["path"],
        "line": found["line"],
        "digest": digest(record),
        "signer": signer,
        "state": state,
    }


__all__ = [
    "CODE",
    "DOMAIN",
    "FIELDS",
    "KIND",
    "body",
    "build",
    "check",
    "digest",
    "path_ok",
    "sign",
]
