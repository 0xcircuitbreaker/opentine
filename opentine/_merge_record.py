"""``opentine.merge`` (merge/v1) and ``opentine.merge-approval``: signed merge records (0.47).

A **merge attestation** says who landed which merge, onto what, under which
fencing token and after which gates (SPEC 4.19)::

    {"kind": "opentine.merge", "merge_version": 1,
     "run": "run:sha256:…",                     # the merged run
     "parents": ["run:sha256:…", "run:sha256:…"],  # its parents, ours first
     "target": "heads/main" | null, "fencing": N | null,
     "gates": [{"gate": "vsa"|"eval"|"approval", "digest": "sha256:…"}, …],
     "conflicts": N, "actor": "…", "merged_at": "YYYY-MM-DDTHH:MM:SSZ"}

A **merge approval** is one person's signed decision on a candidate run::

    {"kind": "opentine.merge-approval", "approval_version": 1,
     "run": "run:sha256:…", "target": "heads/main",
     "decision": "approve"|"reject", "approver": "…",
     "approved_at": "YYYY-MM-DDTHH:MM:SSZ"}

Both carry a ``tine-sig/3`` block over their own domain + JCS of ``{body,
header}`` (:mod:`opentine._signed_record`). :func:`check` and
:func:`check_approval` answer the ``merge.verify`` and
``merge-approval.verify`` conformance ops (``vectors/68-merge.json``); with the
merged run's payload, :func:`check` also proves the record names that run and
its parents.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from opentine._signed_record import (
    DIGEST,
    NAME,
    RUN_OID,
    WHEN,
    RecordError,
    check_signature,
    fields,
    is_count,
)
from opentine._signed_record import sign as _sign

KIND = "opentine.merge"
DOMAIN = b"opentine.merge.v1:"
FIELDS = ("kind", "merge_version", "run", "parents", "target", "fencing", "gates", "conflicts",
          "actor", "merged_at")  # fmt: skip
APPROVAL_KIND = "opentine.merge-approval"
APPROVAL_DOMAIN = b"opentine.merge-approval.v1:"
APPROVAL_FIELDS = ("kind", "approval_version", "run", "target", "decision", "approver",
                   "approved_at")  # fmt: skip
GATES = ("vsa", "eval", "approval")
MAX_GATES = 256


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bad(code: str, message: str) -> RecordError:
    return RecordError(f"{code}.malformed", f"{code} record is malformed: {message}")


def _run(value: Any) -> bool:
    return isinstance(value, str) and bool(RUN_OID.fullmatch(value))


def body(record: Any) -> dict[str, Any]:
    out = fields(record, KIND, FIELDS, "merge", "merge record")
    if isinstance(out["merge_version"], bool) or out["merge_version"] != 1:
        raise _bad("merge", "merge_version must be 1")
    parents = out["parents"]
    if not _run(out["run"]) or not isinstance(parents, list) or not 2 <= len(parents) <= 64:
        raise _bad("merge", "run must be a run oid and parents two or more run oids")
    if not all(_run(p) for p in parents) or len(set(parents)) != len(parents):
        raise _bad("merge", "parents must be unique run oids")
    if out["run"] in parents:
        raise _bad("merge", "a merge cannot be its own parent")
    if out["target"] is not None and not (isinstance(out["target"], str) and
                                          NAME.fullmatch(out["target"])):  # fmt: skip
        raise _bad("merge", "target must be a ref name or null")
    if out["fencing"] is not None and not is_count(out["fencing"]):
        raise _bad("merge", "fencing must be a count or null")
    gates = out["gates"]
    if not isinstance(gates, list) or len(gates) > MAX_GATES:
        raise _bad("merge", "gates must be a list")
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {"gate", "digest"}:
            raise _bad("merge", "a gate is {gate, digest}")
        if gate["gate"] not in GATES or not isinstance(gate["digest"], str) or not \
                DIGEST.fullmatch(gate["digest"]):  # fmt: skip
            raise _bad("merge", "a gate names vsa, eval or approval and a sha256 digest")
    if not is_count(out["conflicts"]):
        raise _bad("merge", "conflicts must be a count")
    if not isinstance(out["actor"], str) or not NAME.fullmatch(out["actor"]):
        raise _bad("merge", "actor must be a name")
    if not isinstance(out["merged_at"], str) or not WHEN.fullmatch(out["merged_at"]):
        raise _bad("merge", "merged_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    return out


def approval_body(record: Any) -> dict[str, Any]:
    out = fields(record, APPROVAL_KIND, APPROVAL_FIELDS, "merge-approval", "merge-approval record")
    if isinstance(out["approval_version"], bool) or out["approval_version"] != 1:
        raise _bad("merge-approval", "approval_version must be 1")
    if not _run(out["run"]):
        raise _bad("merge-approval", "run must be a run oid")
    for name in ("target", "approver"):
        if not isinstance(out[name], str) or not NAME.fullmatch(out[name]):
            raise _bad("merge-approval", f"{name} must be a name")
    if out["decision"] not in ("approve", "reject"):
        raise _bad("merge-approval", "decision must be approve or reject")
    if not isinstance(out["approved_at"], str) or not WHEN.fullmatch(out["approved_at"]):
        raise _bad("merge-approval", "approved_at must be an RFC 3339 UTC time")
    return out


def build(run: str, parents: list[str], *, actor: str, target: str | None = None,
          fencing: int | None = None, gates: list[dict[str, str]] = (),
          conflicts: int = 0, merged_at: str | None = None) -> dict[str, Any]:  # fmt: skip
    return body({"kind": KIND, "merge_version": 1, "run": run, "parents": list(parents),
                 "target": target, "fencing": fencing, "gates": list(gates),
                 "conflicts": conflicts, "actor": actor,
                 "merged_at": merged_at or now()})  # fmt: skip


def build_approval(run: str, target: str, approver: str, decision: str = "approve",
                   approved_at: str | None = None) -> dict[str, Any]:  # fmt: skip
    return approval_body({"kind": APPROVAL_KIND, "approval_version": 1, "run": run,
                          "target": target, "decision": decision, "approver": approver,
                          "approved_at": approved_at or now()})  # fmt: skip


def sign(record: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, "merge record", key, algorithm=algorithm, **header)


def sign_approval(record: dict[str, Any], key: Any, *, algorithm: str, **header: Any) -> dict:
    found = approval_body(record)
    return _sign(found, APPROVAL_DOMAIN, "merge-approval record", key, algorithm=algorithm,
                 **header)  # fmt: skip


def check(
    record: Any,
    *,
    hmac_key: bytes | None = None,
    public_key: bytes | None = None,
    run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``{run, parents, target, fencing, state}``; :class:`RecordError` else."""
    found = body(record)
    state = check_signature(record, found, domain=DOMAIN, code="merge", subject="merge record",
                            hmac_key=hmac_key, public_key=public_key)  # fmt: skip
    if run is not None:
        from opentine._merge import run_oid

        if not isinstance(run, dict) or run_oid(run) != found["run"]:
            raise RecordError("merge.run-mismatch", "the merge record names another run")
        if run.get("parents") != found["parents"]:
            raise RecordError("merge.run-mismatch", "the merged run has other parents")
    return {"run": found["run"], "parents": found["parents"], "target": found["target"],
            "fencing": found["fencing"], "state": state}  # fmt: skip


def check_approval(
    record: Any, *, hmac_key: bytes | None = None, public_key: bytes | None = None
) -> dict[str, Any]:
    """``{run, target, decision, approver, state}``; :class:`RecordError` else."""
    found = approval_body(record)
    state = check_signature(record, found, domain=APPROVAL_DOMAIN, code="merge-approval",
                            subject="merge-approval record", hmac_key=hmac_key,
                            public_key=public_key)  # fmt: skip
    return {"run": found["run"], "target": found["target"], "decision": found["decision"],
            "approver": found["approver"], "state": state}  # fmt: skip


__all__ = ["APPROVAL_KIND", "DOMAIN", "KIND", "approval_body", "body", "build",
           "build_approval", "check", "check_approval", "sign", "sign_approval"]  # fmt: skip
