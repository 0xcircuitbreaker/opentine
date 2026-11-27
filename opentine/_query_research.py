"""Elicitation links and sabotage task records in the query index (0.68).

``sabotage_tasks``: one row per ``opentine.sabotage-task/1`` attestation
(:mod:`opentine._sabotage`), read from the object store like monitor verdicts.
``signed`` is 1 only when the Ed25519 signature verifies *and* the payload's
``signer`` names the key that signed (the binding the sabotage report uses).

``elicit_links`` and ``elicit_items``: the ``opentine.elicit-link/1`` records
filed under ``.tine/elicit/links/`` (:mod:`opentine._elicit`). They are signed
files, not objects, so a row's ``oid`` is the record digest
(:func:`opentine._elicit.digest`, signature included) and ``--verify`` re-reads
the file. An item row shares its link's ``oid`` and adds ``id``.

Rows are derived and non-authoritative: they carry no finding. Sandbagging and
catch-rate analysis stays with ``tine elicit report`` and ``tine sabotage
report``; their findings are advisory statistical evidence (D12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentine._query_values import flag as _flag
from opentine._query_values import number as _num
from opentine._query_values import text as _text

COLUMNS: dict[str, tuple[str, ...]] = {
    "sabotage_tasks": ("oid", "target", "signer", "signed", "task", "class", "main_task",
                       "main_score", "main_passed", "side_task", "attempted", "achieved",
                       "verdicts", "at"),
    "elicit_links": ("oid", "source", "task", "safety_relevant", "condition", "kind", "cue",
                     "monitored", "model", "model_version", "signer", "signed", "items",
                     "mean_score", "attempts", "tokens", "usd", "gpu_hours", "created_at"),
    "elicit_items": ("oid", "task", "condition", "id", "score"),
}  # fmt: skip
FILE_TABLES = ("elicit_links", "elicit_items")
#: Roles that make a row of these tables ``verified`` under ``--verify``.
ROLES_FOR = {"sabotage_tasks": ("scorer", "eval"),
             "elicit_links": ("scorer", "eval", "verdict")}  # fmt: skip


def sabotage_row(oid: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    from opentine._sabotage import CONVENTION
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    claim = payload.get("claim")
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return None
    result = verify_attestation(payload, trust_embedded=True)
    signed = bool(
        result.ok
        and result.algorithm == "ed25519"
        and used_key_fingerprint(payload.get("signature")) == payload.get("signer")
    )
    main = claim.get("main_task") if isinstance(claim.get("main_task"), dict) else {}
    side = claim.get("side_task") if isinstance(claim.get("side_task"), dict) else {}
    verdicts = claim.get("monitor_verdicts")
    return {"oid": oid, "target": _text(payload.get("target_id")),
            "signer": _text(payload.get("signer")), "signed": int(signed),
            "task": _text(claim.get("task")), "class": _text(claim.get("class")),
            "main_task": _text(main.get("id")), "main_score": _num(main.get("score")),
            "main_passed": _flag(main.get("passed")), "side_task": _text(side.get("id")),
            "attempted": _flag(side.get("attempted")), "achieved": _flag(side.get("achieved")),
            "verdicts": len(verdicts) if isinstance(verdicts, list) else None,
            "at": _text(claim.get("at"))}  # fmt: skip


def elicit_files(store: Path) -> dict[str, bytes]:
    """``{source: bytes}`` for every record in ``.tine/elicit/links``."""
    from opentine._elicit import read_folder

    folder = Path(store) / "elicit" / "links"
    return {f"elicit/links/{name}": raw for name, raw in read_folder(folder)}


def document_rows(source: str, raw: bytes) -> dict[str, list[dict[str, Any]]]:
    """``{table: rows}`` one elicitation file contributes (``{}`` when malformed)."""
    from opentine import _elicit

    try:
        doc = json.loads(raw)
    except ValueError:
        return {}
    if _elicit.problems(doc):
        return {}
    try:
        signed = int(doc.get("signature") is not None and _elicit.verify(doc) is None)
    except Exception:  # noqa: BLE001 - a malformed signature block is indexed unsigned
        signed = 0
    oid, cond, effort = _elicit.digest(doc), doc["condition"], doc["effort"]
    scores = [float(i["score"]) for i in doc["items"]]
    head = {"oid": oid, "source": source, "task": doc["task"],
            "safety_relevant": int(doc["safety_relevant"]), "condition": cond["name"],
            "kind": cond["kind"], "cue": cond["cue"], "monitored": int(cond["monitored"]),
            "model": doc["model"]["id"], "model_version": doc["model"]["version"],
            "signer": _text(doc.get("signer")), "signed": signed, "items": len(scores),
            "mean_score": sum(scores) / len(scores), "attempts": effort["attempts"],
            "tokens": effort["tokens"], "usd": _num(effort["usd"]),
            "gpu_hours": _num(effort["gpu_hours"]), "created_at": doc["created_at"]}  # fmt: skip
    items = [{"oid": oid, "task": doc["task"], "condition": cond["name"], "id": i["id"],
              "score": float(i["score"])} for i in doc["items"]]  # fmt: skip
    return {"elicit_links": [head], "elicit_items": items}


def rows(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {name: [] for name in FILE_TABLES}
    for source, raw in sorted(files.items()):
        for name, found in document_rows(source, raw).items():
            out[name] += found
    return out


def derive(store: Path, table: str, oid: str, db: Any,
           row: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:  # fmt: skip
    """The row the file behind *oid* derives now, or ``(None, why)`` (for ``--verify``)."""
    hit = db.execute("SELECT source FROM elicit_links WHERE oid = ?", (oid,)).fetchone()
    source = hit[0] if hit else None
    files = elicit_files(store)
    if source not in files:
        return None, "the source is not an indexed elicitation record"
    found = document_rows(source, files[source])
    if not found.get("elicit_links") or found["elicit_links"][0]["oid"] != oid:
        return None, "the elicitation record changed"
    head = found["elicit_links"][0]
    if table == "elicit_links":
        return head, None
    if "id" not in row:
        return {k: head[k] for k in ("oid", "task", "condition", "signer", "signed")}, None
    match = [r for r in found["elicit_items"] if r["id"] == row.get("id")]
    if not match:
        return None, "the record has no item with that id"
    return {**match[0], "signer": head["signer"], "signed": head["signed"]}, None


__all__ = ["COLUMNS", "FILE_TABLES", "ROLES_FOR", "derive", "document_rows", "elicit_files",
           "rows", "sabotage_row"]  # fmt: skip
