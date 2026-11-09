"""Reference ops for SPEC 4.19: run merge and pick, merge attestations and approvals."""

from __future__ import annotations

from typing import Any

from opentine import _merge_record
from opentine._merge import merge_payloads, pick_payloads


def _keys(value: dict) -> dict[str, Any]:
    hmac, public = value.get("hmac_key_hex"), value.get("public_key")
    return {
        "hmac_key": bytes.fromhex(hmac) if hmac else None,
        "public_key": bytes.fromhex(public) if public else None,
    }


def op_merge_compute(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: the merge of two run payloads (and flattened trees) -> its oids."""
    value = inp.value
    plan = merge_payloads(value["ours"], value["theirs"], value.get("trees"))
    return {"run": plan["run_oid"], "event": plan["event_oid"], "tree": plan["tree"],
            "status": plan["status"], "conflicts": plan["conflicts"]}  # fmt: skip


def op_merge_pick(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: events copied onto a run's tips -> the new run and event oids."""
    value = inp.value
    plan = pick_payloads(value["ours"], [(row[0], row[1]) for row in value["picks"]])
    return {"run": plan["run_oid"], "events": [oid for oid, _ in plan["events"]]}


def op_merge_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: verify an opentine.merge attestation (and the merged run when given)."""
    value = inp.value
    return _merge_record.check(value["record"], run=value.get("run"), **_keys(value))


def op_merge_approval_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.19: verify an opentine.merge-approval record."""
    value = inp.value
    return _merge_record.check_approval(value["record"], **_keys(value))


OPS = {
    "merge.compute": op_merge_compute,
    "merge.pick": op_merge_pick,
    "merge.verify": op_merge_verify,
    "merge-approval.verify": op_merge_approval_verify,
}
