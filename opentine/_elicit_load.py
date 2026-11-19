"""Reading an elicitation folder into conditions for ``tine elicit report`` (0.68).

Every record is parsed, checked for shape, re-verified (Ed25519 under its
named signer) and its signer looked up in the owner-pinned key roles
(:func:`opentine._experiment_check.roles`, i.e. ``_key_roles_pin``). A record
that fails any of that is left out of the statistics and reported as a
``fail:elicit.*`` finding; an intact record from a signer without a pinned
``scorer``/``eval``/``verdict`` role is used and reported as
``advisory:elicit.signer-unpinned``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine import _elicit

VERDICT_ROLES = ("scorer", "eval", "verdict")


def finding(level: str, code: str, subject: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:elicit.{code}", "subject": subject,
            "message": message}  # fmt: skip


def _effort_add(total: dict[str, Any], effort: dict[str, Any]) -> None:
    total["attempts"] += effort["attempts"]
    if effort["best_of_n"] is not None:
        total["best_of_n"] = max(total["best_of_n"] or 0, effort["best_of_n"])
    for name in ("tokens", "usd", "gpu_hours"):
        if effort[name] is not None:
            total[name] = (total[name] or 0) + effort[name]


def _accept(name: str, raw: bytes, keys: dict, status: str) -> tuple[dict | None, list]:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, [finding("fail", "malformed", name, f"not JSON: {exc}")]
    bad = _elicit.problems(doc)
    if bad:
        return None, [finding("fail", "malformed", name, bad[0])]
    why = _elicit.verify(doc)
    if why:
        return None, [finding("fail", "bad-signature", name, why)]
    signer = doc["signer"]
    if signer in keys.get("optimizer", []):
        return None, [finding("fail", "key-separation", name,
                              f"signer {signer} holds the optimizer role")]  # fmt: skip
    if not any(signer in keys.get(r, []) for r in VERDICT_ROLES):
        why = ("the key roles are unpinned (no owner-signed trust bundle)" if status != "pinned"
               else "not a pinned scorer/eval/verdict key")  # fmt: skip
        return doc, [finding("advisory", "signer-unpinned", signer, why)]
    return doc, []


def load(files: list[tuple[str, bytes]], pinned: dict[str, Any]) -> dict[str, Any]:
    """``{"records", "conditions", "findings"}`` over a folder's ``(name, bytes)`` pairs.

    ``conditions`` maps a condition name to its metadata, linked tasks, effort
    totals and ``scores``: ``{(task, item): micro-units}``.
    """
    from opentine._eval_stats import micro

    keys, status = pinned.get("roles") or {}, pinned.get("status", "absent")
    found: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], str] = {}
    conditions: dict[str, dict[str, Any]] = {}
    used = 0
    for name, raw in files:
        doc, notes = _accept(name, raw, keys, status)
        found += [n for n in notes if n not in found]
        if doc is None:
            continue
        cond = doc["condition"]
        meta = {k: cond[k] for k in ("kind", "ref", "cue", "monitored")}
        pair = (doc["task"], cond["name"])
        if pair in seen:
            found.append(
                finding(
                    "fail",
                    "duplicate",
                    name,
                    f"task {pair[0]} under {pair[1]} is also in {seen[pair]}",
                )
            )
            continue  # fmt: skip
        row = conditions.setdefault(cond["name"], {
            "name": cond["name"], **meta, "tasks": [], "safety_tasks": [], "scores": {},
            "effort": dict.fromkeys(_elicit.EFFORT, None) | {"attempts": 0}})  # fmt: skip
        if any(row[k] != v for k, v in meta.items()):
            found.append(finding("fail", "malformed", name,
                                 f"condition {cond['name']} is described differently "
                                 "in another record"))  # fmt: skip
            continue
        seen[pair] = name
        used += 1
        row["tasks"].append(doc["task"])
        if doc["safety_relevant"]:
            row["safety_tasks"].append(doc["task"])
        _effort_add(row["effort"], doc["effort"])
        for item in doc["items"]:
            row["scores"][(doc["task"], item["id"])] = micro(item["score"])
    for row in conditions.values():
        row["tasks"].sort()
        row["safety_tasks"].sort()
    return {"records": used, "conditions": conditions, "findings": found}


def suspect(row: dict[str, Any]) -> bool:
    """Eval-cued or monitored: where a sandbagging model would hold back."""
    return row["cue"] == "eval" or row["monitored"]


def control(row: dict[str, Any]) -> bool:
    """Deployment-cued and unmonitored: the model's own other-context performance."""
    return row["cue"] == "deployment" and not row["monitored"]


__all__ = ["VERDICT_ROLES", "control", "finding", "load", "suspect"]
