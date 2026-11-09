"""``opentine.mirror-state``: a host's statement about a code slot's sync (0.46.1, SPEC 4.17).

A code mirror (an opentine-web service; ``tine serve`` has none) records what
it last fetched from a project's upstream: for one slot of one manifest
version, the commit each ref pointed at, when, a status (``synced``,
``stale``, ``failed`` or ``paused``) and the reason codes that explain it. It
is signed by the *host service key* (Ed25519, ``tine-sig/3`` over
``opentine.mirror-state.v1:`` + JCS of ``{body, header}``), never by a user's
key: a statement signed by a project owner is refused (``user-signed``).

A verifier can only check who said it, not whether it is true: the upstream
may hold other commits. :func:`check` therefore never reports a pass. Its
``state`` is ``host-statement`` (or ``host-statement-tofu`` with no pinned host
key) and its ``label`` is :data:`LABEL`. The ten project reason codes of
``tine-verify-report/2`` (:data:`REPORT_CODES`, ROADMAP 0.46.0 spells them
``<outcome>:<detail>``) are defined here; a mirror state may carry the seven
``mirror.*`` ones. Reference for ``mirror-state.verify``
(``vectors/66-mirror-state.json``).
"""

from __future__ import annotations

import re
from typing import Any

from opentine._signed_record import WHEN, RecordError, check_signature, fields
from opentine._signed_record import sign as _sign

KIND = "opentine.mirror-state"
DOMAIN = b"opentine.mirror-state.v1:"
FIELDS = (
    "kind",
    "mirror_state_version",
    "tenant",
    "project_id",
    "manifest",
    "slot",
    "object_format",
    "refs",
    "synced_at",
    "status",
    "reasons",
)
CODE = "mirror-state"
SUBJECT = "mirror state"
LABEL = "host statement, not verified by you"
#: code -> tine-verify-report/2 outcome. Never ``pass``: see the module docstring.
REPORT_CODES: dict[str, str] = {
    "project.manifest-signature": "fail",
    "project.manifest-chain": "fail",
    "git-object.mismatch": "fail",
    "mirror.stale": "caveat",
    "mirror.history-truncated": "caveat",
    "mirror.host-statement": "caveat",
    "mirror.upstream-unverifiable": "caveat",
    "mirror.blob-not-mirrored": "unavailable",
    "mirror.upstream-unreachable": "unavailable",
    "mirror.limit-exceeded": "unavailable",
}
MIRROR_CODES = tuple(sorted(code for code in REPORT_CODES if code.startswith("mirror.")))
STATUSES = ("synced", "stale", "failed", "paused")
MAX_REFS = 10_000
_PROJECT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TENANT = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_BLOB = re.compile(r"blob:sha256:[0-9a-f]{64}")
_REF = re.compile(r"refs/(heads|tags)/[A-Za-z0-9._/-]{1,240}")
_HEX = {"sha1": re.compile(r"[0-9a-f]{40}"), "sha256": re.compile(r"[0-9a-f]{64}")}


def _malformed(message: str) -> RecordError:
    return RecordError("mirror-state.malformed", f"mirror state is malformed: {message}")


def _text(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules (not the status rules)."""
    out = fields(record, KIND, FIELDS, CODE, SUBJECT)
    version = out["mirror_state_version"]
    if isinstance(version, bool) or version != 1:
        raise _malformed("mirror_state_version must be 1")
    if not _text(out["tenant"], _TENANT) or not _text(out["project_id"], _PROJECT):
        raise _malformed("tenant and project_id are names")
    if not _text(out["manifest"], _BLOB):
        raise _malformed("manifest is the blob oid of a project manifest version")
    if out["slot"] not in ("primary", "secondary"):
        raise _malformed("slot is primary or secondary")
    hex_oid = _HEX.get(out["object_format"]) if isinstance(out["object_format"], str) else None
    if hex_oid is None:
        raise _malformed("object_format is sha1 or sha256")
    refs = out["refs"]
    if (
        not isinstance(refs, dict)
        or len(refs) > MAX_REFS
        or not all(_text(name, _REF) and ".." not in name for name in refs)
        or not all(_text(oid, hex_oid) for oid in refs.values())
    ):
        raise _malformed("refs maps refs/heads/* and refs/tags/* names to commit ids")
    if not _text(out["synced_at"], WHEN):
        raise _malformed("synced_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    if out["status"] not in STATUSES:
        raise _malformed("status is one of " + ", ".join(STATUSES))
    reasons = out["reasons"]
    if not isinstance(reasons, list) or not all(isinstance(code, str) for code in reasons):
        raise _malformed("reasons is a list of reason codes")
    if reasons != sorted(set(reasons)):
        raise _malformed("reasons are sorted and distinct")
    return out


def consistent(found: dict[str, Any]) -> None:
    """The status rules: known codes, and a status its reasons explain."""
    reasons = set(found["reasons"])
    unknown = sorted(reasons - set(MIRROR_CODES))
    if unknown:
        raise RecordError("mirror-state.unknown-reason", f"unknown mirror reason {unknown[0]}")
    status = found["status"]
    unavailable = {code for code in reasons if REPORT_CODES[code] == "unavailable"}
    if (
        (status == "synced" and (unavailable or "mirror.stale" in reasons))
        or (status == "stale" and "mirror.stale" not in reasons)
        or (status == "failed" and not unavailable)
        or (status == "paused" and "mirror.limit-exceeded" not in reasons)
    ):
        raise RecordError(
            "mirror-state.inconsistent", f"the reasons do not explain status {status}"
        )


def sign(record: dict[str, Any], host_key: Any, **header: Any) -> dict[str, Any]:
    """Sign as the host service (Ed25519 only); a user key must never be passed here."""
    found = body(record)
    consistent(found)
    header.setdefault("key_id", "host")
    return _sign(found, DOMAIN, SUBJECT, host_key, algorithm="ed25519", **header)


def check(record: Any, *, host_key: bytes | None = None, owners: Any = ()) -> dict[str, Any]:
    """What a host said, labelled as such; :class:`RecordError` else. Never a pass."""
    found = body(record)
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError(
            "mirror-state.wrong-key", "a host statement is Ed25519 under the host key"
        )
    state = check_signature(
        record, found, domain=DOMAIN, code=CODE, subject=SUBJECT, public_key=host_key
    )
    if block["public_key"] in set(owners or ()):  # type: ignore[index]
        raise RecordError("mirror-state.user-signed", "signed by a project owner, not the host key")
    consistent(found)
    return {
        "project_id": found["project_id"],
        "slot": found["slot"],
        "manifest": found["manifest"],
        "status": found["status"],
        "refs": len(found["refs"]),
        "reasons": list(found["reasons"]),
        "synced_at": found["synced_at"],
        "state": "host-statement" if state == "verified" else "host-statement-tofu",
        "label": LABEL,
    }


__all__ = [
    "DOMAIN",
    "FIELDS",
    "KIND",
    "LABEL",
    "MIRROR_CODES",
    "REPORT_CODES",
    "STATUSES",
    "body",
    "check",
    "consistent",
    "sign",
]
