"""The oversight queue (0.64): ``tine oversight queue`` and ``tine ui --repo``.

The queue is never stored. It is recomputed from the decision annotations the
gate reads (:mod:`opentine._oversight`), the monitor verdicts and taints the
repository holds, the pinned policy (:mod:`opentine._oversight_policy`) and the
label state, and every item's state is :func:`opentine._oversight_gate.tally`
-- the same function ``tine promote`` refuses with -- so the queue cannot say
"approved" where the gate refuses. The same inputs give the same bytes: items
sort by name, decisions by ``(decided_at, id)``, and the body carries a
``digest`` (sha256 of the canonical JSON of the rest) so ``tine ui`` and the
CLI can show they agree.

An item's ``opened_at`` is its first ``request`` decision's ``decided_at`` (else
its first decision's): a timestamp from the records, never from the clock.
"""

from __future__ import annotations

import hashlib
import warnings
from typing import Any

from opentine import _oversight, _oversight_policy
from opentine._oversight_gate import tally
from opentine.kernel import canonical_json

STATES = ("pending", "approved", "rejected", "unrouted")


def _sources(repo: Any) -> list[dict[str, Any]]:
    """Items the repository holds for review: flagged monitor verdicts, taints, budget
    flags (0.69), containment evidence (0.69: held findings and policy records of a
    run whose ``tine containment check`` fails) and custody gaps and refused tagged
    loads (0.72, :mod:`opentine._weight_custody_review`), and behaviour flags and
    similar-to-known-bad runs (0.74, :mod:`opentine._transcript_oversight`), and
    ingest gaps and policy violations (0.77, :mod:`opentine._ingest_oversight`), and failed
    collusion protocols (0.83, :mod:`opentine._collusion_record`), and cumulative-suspicion
    and doom-loop flags (:mod:`opentine._monitor_suspicion`), and halts that were not a
    verified compliant stop (0.91, :mod:`opentine._stop_compliance`)."""
    from opentine import _monitor_verdict
    from opentine.repository._holds import BUDGET_FLAG, TAINT, holds_path, read_holds

    found = []
    for oid in _monitor_verdict.held(repo):
        try:
            claim = repo.get(oid).payload().get("claim") or {}
        except Exception:  # noqa: BLE001 - an unreadable verdict is listed without action
            claim = {}
        found.append({"item": f"monitor:{oid}", "source": "monitor",
                      "action": claim.get("action")})  # fmt: skip
    for row in read_holds(holds_path(repo)):
        if row["target"].startswith(TAINT):
            found.append({"item": f"integrity:{row['oid']}", "source": "integrity"})
        elif row["target"].startswith(BUDGET_FLAG):  # 0.69: a budget violation or limit
            found.append({"item": f"budget:{row['oid']}", "source": "budget"})
    from opentine._collusion_record import items as collusion_items
    from opentine._ingest_oversight import items as ingest_items
    from opentine._monitor_suspicion import items as suspicion_items
    from opentine._stop_compliance import items as stop_items
    from opentine._transcript_oversight import items as transcript_items
    from opentine._weight_custody_review import items as custody_items

    # 0.72: custody gaps and refusals; 0.74: behaviour flags and runs like flagged runs;
    # 0.77: ingest stream gaps and sampling-policy violations
    for name, source in (("containment", _containment), ("custody", custody_items),
                         ("transcript", transcript_items), ("ingest", ingest_items),
                         ("collusion", collusion_items),
                         ("suspicion", suspicion_items), ("stop", stop_items)):  # fmt: skip
        found += _isolated(name, source, repo)
    return found


def _isolated(name: str, source: Any, repo: Any) -> list[dict[str, Any]]:
    """One source's items; a source that fails is warned about, never fatal to the rest."""
    try:
        return list(source(repo))
    except Exception as exc:  # noqa: BLE001 - isolate each source (0.76)
        warnings.warn(f"oversight source {name} failed and lists nothing: {exc}",
                      RuntimeWarning, stacklevel=3)  # fmt: skip
        return []


def _containment(repo: Any) -> list[dict[str, Any]]:
    from opentine import _containment, _containment_detect
    from opentine._containment import HOLD
    from opentine._containment_records import held

    found = [{"item": f"containment:{r['oid']}", "source": "containment"}
             for r in _containment_detect.recorded(repo)]  # fmt: skip
    for run in sorted({target[len(HOLD) :] for target, _ in held(repo, HOLD)}):
        if not _containment.check(repo, run, None)["ok"]:
            found += [{"item": f"containment:{p['oid']}", "source": "containment"}
                      for p in _containment.recorded(repo, run)]  # fmt: skip
    return found


def _bind(repo: Any, info: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[dict, Any]:
    from opentine._promote import STATE, read_state

    record = read_state(repo.path.parent / STATE, info["label"])
    previous, sequence = record["current"], len(record["history"])
    moved = [i for i, h in enumerate(record["history"])
             if h["action"] == "promote" and h["candidate"] == info["candidate"]]  # fmt: skip
    if moved and record["current"] == info["candidate"]:  # promoted: judge it as it was then
        previous, sequence = record["history"][moved[-1]]["previous"], moved[-1]
    bind = {"label": info["label"], "candidate": info["candidate"],
            "previous": previous, "sequence": sequence}  # fmt: skip
    asked = [r["bind"] for r in rows if r["decision"] == "request"]
    return bind, {**info, "metrics": (asked[-1] or {}).get("metrics") if asked else None}


def _opened(rows: list[dict[str, Any]]) -> str | None:
    asked = [r for r in rows if r["decision"] == "request"] or rows
    return asked[0]["decided_at"] if asked else None


def _decision(row: dict[str, Any], uncounted: set[str]) -> dict[str, Any]:
    viewed = row.get("viewed")
    return {"id": row["id"], "decision": row["decision"], "signer": row["signer"],
            "decided_at": row["decided_at"],
            "counted": row["decision"] != "request" and row["id"] not in uncounted,
            "viewed": viewed if isinstance(viewed, dict) else None}  # fmt: skip


def queue(repo: Any, *, from_objects: bool = False) -> dict[str, Any]:
    """``{"policy", "counts", "items", "digest"}``: every routed item and its tally."""
    state = _oversight_policy.load(repo.path)
    policy = state["policy"]
    decided = _oversight.by_objects(repo) if from_objects else _oversight.by_holds(repo)
    infos = {row["item"]: row for row in _sources(repo)}
    for item in decided:
        infos.setdefault(item, _oversight.parse_item(item))
    items = []
    for item in sorted(infos):
        info, rows = infos[item], decided.get(item, [])
        bind = None
        if info["source"] == "promotion":
            bind, info = _bind(repo, info, rows)
        tiers = _oversight_policy.route(policy, info) if policy is not None else []
        if not tiers and not rows:
            continue
        result = tally(state, tiers, rows, bind) if policy is not None else {
            "tiers": [], "state": "unrouted", "rejected_by": [], "uncounted": []}  # fmt: skip
        skip = {u["decision"] for u in result["uncounted"]}
        items.append({"item": item, "source": info["source"], "opened_at": _opened(rows),
                      **result, "decisions": [_decision(r, skip) for r in rows]})  # fmt: skip
    body = {"policy": {"status": state["status"], "why": state["why"],
                       "sha256": policy["sha256"] if policy else None,
                       "floors": state["floors"]},
            "counts": {s: sum(i["state"] == s for i in items) for s in STATES},
            "items": items}  # fmt: skip
    return {**body, "digest": "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()}


__all__ = ["STATES", "queue"]
