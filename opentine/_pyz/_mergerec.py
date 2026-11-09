"""``opentine.merge`` and ``opentine.merge-approval``, standard library only (0.47).

An independent port of :func:`opentine._merge_record.check` and
:func:`opentine._merge_record.check_approval` (SPEC 4.19) for
``tine-verify.pyz``: exactly each kind's fields, a ``tine-sig/3`` block over
the kind's domain + JCS of ``{"body", "header"}`` (HMAC-SHA256, or Ed25519
under ``--pubkey`` or, without one, the embedded key). With the merged run's
payload, :func:`verify` also checks the record names that run and its parents.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .. import kernel
from . import _sig
from ._artifact import check as row
from ._merge import Refused, run_oid

MERGE = "opentine.merge"
APPROVAL = "opentine.merge-approval"
_KINDS = {
    MERGE: ("merge", "merge record", b"opentine.merge.v1:",
            ("kind", "merge_version", "run", "parents", "target", "fencing", "gates",
             "conflicts", "actor", "merged_at")),
    APPROVAL: ("merge-approval", "merge-approval record", b"opentine.merge-approval.v1:",
               ("kind", "approval_version", "run", "target", "decision", "approver",
                "approved_at")),
}  # fmt: skip
_NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
_WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_RUN = re.compile(r"run:sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _text(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _gates_ok(gates: Any) -> bool:
    return isinstance(gates, list) and len(gates) <= 256 and all(
        isinstance(g, dict) and set(g) == {"gate", "digest"}
        and g["gate"] in ("vsa", "eval", "approval") and _text(g["digest"], _DIGEST)
        for g in gates
    )  # fmt: skip


def _merge_rule(body: dict[str, Any]) -> str | None:
    if not _count(body["merge_version"]) or body["merge_version"] != 1:
        return "merge_version must be 1"
    parents = body["parents"]
    if not _text(body["run"], _RUN) or not isinstance(parents, list) or not 2 <= len(parents) <= 64:
        return "run must be a run oid and parents two or more run oids"
    if not all(_text(p, _RUN) for p in parents) or len(set(parents)) != len(parents):
        return "parents must be unique run oids"
    if body["run"] in parents:
        return "a merge cannot be its own parent"
    if body["target"] is not None and not _text(body["target"], _NAME):
        return "target must be a ref name or null"
    if body["fencing"] is not None and not _count(body["fencing"]):
        return "fencing must be a count or null"
    if not _gates_ok(body["gates"]):
        return "gates must be {gate, digest} rows"
    if not _count(body["conflicts"]) or not _text(body["actor"], _NAME):
        return "conflicts must be a count and actor a name"
    return None if _text(body["merged_at"], _WHEN) else "merged_at must be an RFC 3339 UTC time"


def _approval_rule(body: dict[str, Any]) -> str | None:
    if not _count(body["approval_version"]) or body["approval_version"] != 1:
        return "approval_version must be 1"
    if not _text(body["run"], _RUN):
        return "run must be a run oid"
    if not (_text(body["target"], _NAME) and _text(body["approver"], _NAME)):
        return "target and approver must be names"
    if body["decision"] not in ("approve", "reject"):
        return "decision must be approve or reject"
    return None if _text(body["approved_at"], _WHEN) else "approved_at must be an RFC 3339 time"


def verify(
    record: Any, *, hmac_key: bytes | None = None, public_key: bytes | None = None,
    run: Any = None, kind: str = MERGE,
) -> dict[str, Any]:  # fmt: skip
    """The verified fields of a merge record or approval; :class:`Refused` else."""
    code, subject, domain, fields = _KINDS[kind]
    if not isinstance(record, dict) or record.get("kind") != kind:
        raise Refused(f"{code}.malformed", f"{subject} is malformed: kind is not {kind}")
    if set(record) - {*fields, "signature"} or set(fields) - set(record):
        raise Refused(f"{code}.malformed", f"{subject} is malformed: wrong set of fields")
    body = {name: record[name] for name in fields}
    problem = (_merge_rule if kind == MERGE else _approval_rule)(body)
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
        block, message, ("tine-sig/3",),
        hmac_key=hmac_key if algorithm == "hmac-sha256" else None,
        public_key=public_key if algorithm != "hmac-sha256" else None,
    )  # fmt: skip
    if not ok:
        raise Refused(f"{code}.bad-signature",
                      f"the {subject} signature does not hold ({found}: {reason})")  # fmt: skip
    if kind == APPROVAL:
        keep = ("run", "target", "decision", "approver")
        return {**{name: body[name] for name in keep}, "state": state}
    if run is not None:
        if not isinstance(run, dict) or run_oid(run) != body["run"]:
            raise Refused("merge.run-mismatch", "the merge record names another run")
        if run.get("parents") != body["parents"]:
            raise Refused("merge.run-mismatch", "the merged run has other parents")
    keep = ("run", "parents", "target", "fencing")
    return {**{name: body[name] for name in keep}, "state": state}


def is_record(path: Path) -> bool:
    if path.suffix != ".json" or not path.is_file() or path.stat().st_size > 1 << 20:
        return False
    try:
        return json.loads(path.read_text("utf-8")).get("kind") in _KINDS
    except (OSError, ValueError, AttributeError, RecursionError):
        return False


def verify_record(path: Path, hmac_key: bytes | None, public_key: bytes | None) -> list:
    """One check for the merge attestation or approval file at *path*."""
    record = json.loads(path.read_text("utf-8"))
    code = _KINDS[record["kind"]][0]
    try:
        found = verify(record, hmac_key=hmac_key, public_key=public_key, kind=record["kind"])
    except Refused as exc:
        return [row(code, "fail", exc.code, str(exc))]
    return [row(code, "pass", f"{code}.verified", record["kind"], **found)]


def mode(path: Path) -> str:
    return _KINDS[json.loads(path.read_text("utf-8"))["kind"]][0]


__all__ = ["APPROVAL", "MERGE", "is_record", "mode", "verify", "verify_record"]
