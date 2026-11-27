"""The k-of-n oversight gate (0.64): tally decisions and refuse promotions.

The queue view of the same tallies is :mod:`opentine._oversight_queue`.

:func:`tally` judges one item's decisions against the pinned policy. A decision
counts only when it is signed (Ed25519), its signer is in the tier's
``approvers`` *and* holds the pinned ``approver`` role, and the signer holds no
``optimizer``, ``monitor`` or ``scorer`` role. A signer's newest decision
replaces its earlier ones; keys one person holds (``[humans]`` in the policy,
or the same declared ``human``) count once. A promotion decision is bound to
the label's holder and history length; a move since makes it stale.

``promote`` refusals (none when no policy routes the candidate):

* ``promote.oversight-rejected`` -- a counted approver's newest decision is reject;
* ``promote.oversight-key-separation`` -- short of k, and an approval was signed
  by an optimizer, monitor or scorer key (it never counts);
* ``promote.oversight-stale`` -- short of k, and approvals are bound to another
  candidate, holder or sequence;
* ``promote.oversight-insufficient`` -- fewer than k distinct approvers in a
  routed tier, or the policy is unpinned (it grants nothing).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _oversight, _oversight_policy

BIND_KEYS = ("label", "candidate", "previous", "sequence")


def _identity(policy: dict[str, Any], row: dict[str, Any]) -> str:
    person = policy["humans"].get(row["signer"])
    if person is None and isinstance(row.get("human"), str) and row["human"]:
        person = row["human"]
    return f"human:{person}" if person else row["signer"]


def _why_not(row: dict[str, Any], state: dict[str, Any], bind: dict | None) -> str | None:
    held = state["roles"]
    if not row["signed"]:
        return "unsigned"
    if row["signer"] in _oversight_policy.banned(held):
        return "key-separation"
    if bind is not None:
        said = row["bind"] if isinstance(row["bind"], dict) else {}
        if any(said.get(k) != bind.get(k) for k in BIND_KEYS):
            return "stale"
    if state["status"] != "pinned":
        return "policy-unpinned"
    if state["role_status"] != "pinned" or row["signer"] not in held.get("approver", []):
        return "not-an-approver"
    return None


def tally(state: dict[str, Any], tiers: list[str], rows: list[dict[str, Any]],
          bind: dict | None = None) -> dict[str, Any]:  # fmt: skip
    """``{"tiers", "state", "approvers", "rejected_by", "uncounted"}`` for one item."""
    policy = state["policy"]
    latest: dict[str, dict[str, Any]] = {}
    uncounted = []
    for row in rows:
        if row["decision"] == "request":
            continue
        why = _why_not(row, state, bind)
        if why is not None:
            uncounted.append({"decision": row["id"], "signer": row["signer"], "why": why})
            continue
        latest[row["signer"]] = row
    people: dict[str, dict[str, Any]] = {}
    for row in sorted(latest.values(), key=lambda r: rows.index(r)):
        people[_identity(policy, row)] = row  # one person's newest decision
    out_tiers, rejected = [], set()
    for name in tiers:
        tier = policy["tiers"][name]
        voters = {p: r for p, r in people.items() if r["signer"] in tier["approvers"]}
        yes = sorted(p for p, r in voters.items() if r["decision"] == "approve")
        rejected |= {p for p, r in voters.items() if r["decision"] == "reject"}
        out_tiers.append({"tier": name, "k": tier["k"], "n": len(tier["approvers"]),
                          "approvals": len(yes), "approvers": yes})  # fmt: skip
    if not tiers:
        verdict = "unrouted"
    elif rejected:
        verdict = "rejected"
    elif all(t["approvals"] >= t["k"] for t in out_tiers):
        verdict = "approved"
    else:
        verdict = "pending"
    return {"tiers": out_tiers, "state": verdict, "rejected_by": sorted(rejected),
            "uncounted": uncounted}  # fmt: skip


def _store(repo_path: Path | None) -> Any:
    from opentine.repo import Repo

    try:
        return Repo.open(repo_path) if repo_path is not None else None
    except Exception:  # noqa: BLE001 - no repository: no oversight policy
        return None


def promote_refusals(repo_path: Path | None, candidate: str, label: str, *,
                     previous: str | None, sequence: int,
                     evals: Path | None = None) -> list[dict[str, str]]:  # fmt: skip
    """The oversight refusals for moving *label* to *candidate* (none when unrouted)."""
    from opentine._promote_checks import refusal

    repo = _store(repo_path)
    if repo is None:
        return []
    try:
        state = _oversight_policy.load(repo.path)
    except _oversight_policy.OversightError as exc:
        return [refusal("promote.oversight-insufficient", f"oversight policy: {exc}")]
    if state["policy"] is None:
        if _oversight.by_objects(repo):  # held decisions exist: the policy was removed
            return [refusal("promote.oversight-insufficient",
                            "oversight decisions exist; .tine/oversight.toml is gone")]  # fmt: skip
        if state.get("floors"):  # the owner pinned tier floors: the policy must be there
            return [refusal("promote.oversight-insufficient",
                            "floors are pinned; .tine/oversight.toml is gone")]  # fmt: skip
        return []
    info = {"source": "promotion", "label": label,
            "metrics": _oversight_policy.eval_metrics(evals)}  # fmt: skip
    tiers = _oversight_policy.route(state["policy"], info)
    if not tiers:
        return []
    item = _oversight.promotion_item(label, candidate)
    # The gate reads the objects, not the holds file: editing that file hides nothing.
    rows = _oversight.by_objects(repo).get(item, [])
    bind = {"label": label, "candidate": candidate, "previous": previous, "sequence": sequence}
    result = tally(state, tiers, rows, bind)
    if result["state"] == "rejected":
        return [refusal("promote.oversight-rejected",
                        f"{item} rejected by {', '.join(result['rejected_by'])}")]  # fmt: skip
    if result["state"] == "approved":
        return []
    short = "; ".join(f"tier {t['tier']}: {t['approvals']} of {t['k']} distinct approvers"
                      for t in result["tiers"] if t["approvals"] < t["k"])  # fmt: skip
    whys = {u["why"] for u in result["uncounted"]}
    if state["status"] != "pinned":
        return [refusal("promote.oversight-insufficient", f"{short}; {state['why']}")]
    for why, code in (("key-separation", "promote.oversight-key-separation"),
                      ("stale", "promote.oversight-stale")):  # fmt: skip
        if why in whys:
            n = sum(u["why"] == why for u in result["uncounted"])
            return [refusal(code, f"{short}; {n} decision(s) do not count: {why}")]
    return [refusal("promote.oversight-insufficient", short)]


__all__ = ["promote_refusals", "tally"]
