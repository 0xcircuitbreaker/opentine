"""Reference ops for SPEC 8.10-8.11: tlog proofs and witness quorums, as verdicts."""

from __future__ import annotations

import base64
from typing import Any

from opentine.repository import _tlog, _tlog_cosign, _tlog_proof


def _classify(exc: Exception) -> str:
    text = str(exc)
    return "rollback" if "rollback" in text else "fork" if "fork" in text else "invalid"


def op_tlog_inclusion(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    try:
        leaf = _tlog.leaf_hash(base64.b64decode(value["entry_b64"], validate=True))
        root = base64.b64decode(value["root_b64"], validate=True)
        proof = _tlog_proof.decode(value["path"])
        _tlog_proof.verify_inclusion(leaf, value["index"], value["size"], proof, root)
    except (KeyError, TypeError, ValueError):
        return {"ok": False}
    return {"ok": True}


def op_tlog_consistency(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    try:
        old = base64.b64decode(value["old_root_b64"], validate=True)
        new = base64.b64decode(value["new_root_b64"], validate=True)
        proof = _tlog_proof.decode(value["proof"])
        _tlog_proof.verify_consistency(value["old_size"], value["new_size"], old, new, proof)
    except (KeyError, TypeError, ValueError) as exc:
        return {"ok": False, "class": _classify(exc)}
    return {"ok": True, "class": "consistent"}


def op_tlog_quorum(inp, args: dict[str, Any]) -> dict[str, Any]:
    value = inp.value
    try:
        note = str(value["checkpoint"]).encode("utf-8")
        found = _tlog_cosign.cosigners(note, list(value["witnesses"]))
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "cosigners": []}
    ok = len(value["witnesses"]) == value["total"] and len(found) >= value["need"]
    return {"ok": ok, "cosigners": sorted(found)}


OPS = {
    "tlog.inclusion": op_tlog_inclusion,
    "tlog.consistency": op_tlog_consistency,
    "tlog.quorum": op_tlog_quorum,
}
