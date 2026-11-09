"""Tombstones and redacted-copy records, checked with the standard library (0.46).

An independent port of ``opentine._tombstone.check`` (SPEC 4.14) and
``opentine._redacted_copy.check`` (SPEC 4.15) for ``tine-verify.pyz``: exactly
each kind's fields, a ``tine-sig/3`` block over the kind's domain prefix + JCS
of ``{"body": ..., "header": ...}`` (HMAC-SHA256, or Ed25519 under
``--pubkey`` or, without one, the embedded key: trust on first use). Reason
codes are the conformance suite's ``tombstone.*`` and ``redacted-copy.*``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import kernel
from . import _sig
from ._artifact import check as row

TOMBSTONE = "opentine.tombstone"
COPY = "opentine.redacted-copy"
_KINDS = {
    TOMBSTONE: ("tombstone", "tombstone", b"opentine.tombstone.v1:",
                ("kind", "tombstone_version", "oid", "reason", "actor", "purged_at")),
    COPY: ("redacted-copy", "redacted copy", b"opentine.redacted-copy.v1:",
           ("kind", "copy_version", "source_run", "public_run", "ruleset", "objects",
            "redacted", "pack")),
}  # fmt: skip
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_BLOB = re.compile(r"blob:sha256:[0-9a-f]{64}")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Refused(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _text(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _tombstone_rule(body: dict[str, Any]) -> str | None:
    if not _count(body["tombstone_version"]) or body["tombstone_version"] != 1:
        return "tombstone_version must be 1"
    if not _text(body["oid"], _BLOB):
        return "oid must be a blob oid"
    reason = body["reason"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason.encode("utf-8", "surrogatepass")) > 1024
        or _CONTROL.search(reason)
    ):
        return "reason must be 1 to 1024 bytes of text without control characters"
    if not _text(body["actor"], _NAME):
        return "actor must be a name"
    if not _text(body["purged_at"], _WHEN):
        return "purged_at must be an RFC 3339 UTC time"
    return None


def _copy_rule(body: dict[str, Any]) -> str | None:
    if not _count(body["copy_version"]) or body["copy_version"] != 1:
        return "copy_version must be 1"
    if not (_text(body["source_run"], _RUN) and _text(body["public_run"], _RUN)):
        return "source_run and public_run must be run oids"
    if not _text(body["ruleset"], _NAME):
        return "ruleset must be a name"
    if not (_count(body["objects"]) and _count(body["redacted"])):
        return "objects and redacted must be counts"
    if not _text(body["pack"], _DIGEST):
        return "pack must be sha256:<64 hex>"
    return None


def verify(
    record: Any,
    *,
    hmac_key: bytes | None = None,
    public_key: bytes | None = None,
    pack: str | None = None,
) -> dict[str, Any]:
    """The verified fields of a tombstone or redacted-copy record; :class:`Refused` else."""
    kind = record.get("kind") if isinstance(record, dict) else None
    if kind not in _KINDS:
        raise Refused("tombstone.malformed", "tombstone is malformed: unknown kind")
    code, subject, domain, fields = _KINDS[kind]
    if set(record) - {*fields, "signature"} or set(fields) - set(record):
        raise Refused(f"{code}.malformed", f"{subject} is malformed: wrong set of fields")
    body = {name: record[name] for name in fields}
    problem = (_tombstone_rule if kind == TOMBSTONE else _copy_rule)(body)
    if problem:
        raise Refused(f"{code}.malformed", f"{subject} is malformed: {problem}")
    block = record.get("signature")
    if block is None:
        raise Refused(f"{code}.unsigned", f"the {subject} is unsigned")
    if not isinstance(block, dict):
        raise Refused(f"{code}.bad-signature", f"the {subject} signature is not a block")
    algorithm = block.get("alg")
    if algorithm == "hmac-sha256" and hmac_key is None:
        raise Refused(f"{code}.no-key", f"no key for an hmac-sha256 {subject}")
    if hmac_key is not None and algorithm != "hmac-sha256":
        raise Refused(f"{code}.wrong-key", "not the trusted key's algorithm")
    state = "verified"
    if public_key is not None:
        if algorithm != "ed25519" or block.get("public_key") != bytes(public_key).hex():
            raise Refused(f"{code}.wrong-key", "signed by a key other than the trusted key")
    elif algorithm == "ed25519":
        raw = block.get("public_key")
        public_key = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b"\0" * 32
        state = "verified-tofu"

    def message(header: dict[str, Any]) -> bytes:
        return domain + kernel.canonical_json({"body": body, "header": header})

    ok, found, reason = _sig.verify_block(
        block,
        message,
        ("tine-sig/3",),
        hmac_key=hmac_key if algorithm == "hmac-sha256" else None,
        public_key=public_key if algorithm != "hmac-sha256" else None,
    )
    if not ok:
        raise Refused(
            f"{code}.bad-signature", f"the {subject} signature does not hold ({found}: {reason})"
        )
    if kind == TOMBSTONE:
        return {"oid": body["oid"], "actor": body["actor"], "purged_at": body["purged_at"],
                "state": state}  # fmt: skip
    if body["redacted"] > body["objects"] or (
        (body["redacted"] == 0) != (body["source_run"] == body["public_run"])
    ):
        raise Refused("redacted-copy.inconsistent", "the counts disagree with the run oids")
    if pack is not None and pack != body["pack"]:
        raise Refused("redacted-copy.pack-mismatch", "the record names another pack")
    out = {name: body[name] for name in ("source_run", "public_run", "objects", "redacted")}
    return {**out, "state": state}


def closure(run: str, objects: dict[str, bytes], tombstones: Any) -> dict[str, Any]:
    """A run's closure: a missing blob a tombstone names is content-unavailable (4.14)."""
    if not isinstance(tombstones, list):
        raise Refused("tombstone.malformed", "tombstone is malformed: not a list")
    marked = set()
    for record in tombstones:
        if not isinstance(record, dict) or record.get("kind") != TOMBSTONE:
            raise Refused("tombstone.malformed", "tombstone is malformed: kind")
        fields = _KINDS[TOMBSTONE][3]
        if set(record) - {*fields, "signature"} or set(fields) - set(record):
            raise Refused("tombstone.malformed", "tombstone is malformed: wrong set of fields")
        problem = _tombstone_rule({name: record[name] for name in fields})
        if problem:
            raise Refused("tombstone.malformed", f"tombstone is malformed: {problem}")
        marked.add(record["oid"])
    seen: set[str] = set()
    unavailable: set[str] = set()
    stack = [run]
    while stack:
        oid = stack.pop()
        if oid in seen:
            continue
        seen.add(oid)
        if oid not in objects:
            if oid in marked:
                unavailable.add(oid)
                continue
            raise Refused("tombstone.missing-content", f"{oid} is missing; no tombstone names it")
        envelope = kernel.ObjectEnvelope.decode(objects[oid], oid)
        stack.extend(kernel.validate_links(envelope))
    return {"run": run, "objects": len(seen) - len(unavailable),
            "content_unavailable": sorted(unavailable),
            "state": "content-unavailable" if unavailable else "verified"}  # fmt: skip


def is_record(path: Path) -> bool:
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 1 << 20:
        return False
    try:
        return json.loads(path.read_text("utf-8")).get("kind") in _KINDS
    except (OSError, ValueError, AttributeError, RecursionError):
        return False


def verify_record(path: Path, hmac_key: bytes | None, public_key: bytes | None) -> list:
    """One check for the tombstone or redacted-copy record file at *path*."""
    record = json.loads(path.read_text("utf-8"))
    code = _KINDS[record["kind"]][0]
    try:
        found = verify(record, hmac_key=hmac_key, public_key=public_key)
    except Refused as exc:
        return [row(code, "fail", exc.code, str(exc))]
    return [row(code, "pass", f"{code}.verified", record["kind"], **found)]


def mode(path: Path) -> str:
    return _KINDS[json.loads(path.read_text("utf-8"))["kind"]][0]


__all__ = ["Refused", "closure", "is_record", "mode", "verify", "verify_record"]
