"""Budget status and the next-action decision (0.69).

:func:`status` folds a subject's ledger (:mod:`opentine._budget_ledger`) into
the policy in force, the totals spent and findings; :func:`check` adds the
decision for the *next* action and records flags for oversight.

* Totals count every held ``spend`` entry, signed or not, chained or forked
  (fail safe: a bad entry can hide no spend), folded by
  :func:`opentine._budget_spend.fold`. A run recorded more than once
  counts once, with the largest value of each unit, so the ledger still equals
  the ``tine cost`` export. ``money_usd`` is the
  ``math.fsum`` of the recorded ``cost.total_cost`` values, the number
  ``tine cost`` prints for each run.
* A ``policy`` entry takes effect only when :func:`opentine._budget_policy.judge`
  accepts it; otherwise it is a ``fail:`` finding (an agent raising its own
  limit, a rollback, an unsigned or optimizer-signed policy) and the policy in
  force stays.
* ``wall_clock_s`` is measured from the first accepted policy entry's
  ``at_ms`` to *now_ms*, a caller-supplied clock.
* Decision (owner decision D12): ``deny`` or ``escalate`` (the policy's
  ``on_limit``) only when a limit is reached; every finding is reported, and a
  ``fail:`` finding is routed to the oversight queue, but only an over-budget
  subject has its next action refused.
"""

from __future__ import annotations

from typing import Any

from opentine import _budget_ledger, _budget_policy, _budget_spend
from opentine._budget_policy import LIMITS
from opentine._budget_spend import UNITS


def _finding(level: str, code: str, entry: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:{code}", "entry": entry, "message": message}


def _roles(repo: Any) -> dict[str, Any]:
    from opentine._key_roles import KeyRoleError
    from opentine._key_roles_pin import resolve

    try:
        return resolve(repo.path)
    except KeyRoleError as exc:  # a pinned owner with a bad bundle grants nothing
        return {"roles": None, "status": "unpinned", "source": None, "why": str(exc)}


def _pinned_policy(roles: dict[str, Any]) -> list[str]:
    return (roles.get("roles") or {}).get("policy", []) if roles.get("status") == "pinned" else []


def _signer_findings(row: dict[str, Any], roles: dict[str, Any]) -> list[dict[str, Any]]:
    if not row["signed"]:
        return [_finding("fail", "budget.ledger-unsigned", row["id"],
                         "a ledger entry's signature does not verify")]  # fmt: skip
    held = roles.get("roles") or {}
    if row["signer"] in held.get("optimizer", []):
        return [_finding("fail", "budget.ledger-optimizer-key", row["id"],
                         f"an optimizer key {row['signer']} wrote a ledger entry")]  # fmt: skip
    runners = held.get("runner", []) if roles.get("status") == "pinned" else []
    if runners and row["signer"] not in runners:
        return [_finding("advisory", "budget.ledger-signer", row["id"],
                         f"{row['signer']} is not a pinned runner key")]  # fmt: skip
    return []


def _policy_forked(rows: list[dict[str, Any]]) -> bool:
    """Whether a policy entry is an orphan or shares its parent with another entry."""
    ids = {r["id"] for r in rows}
    children: dict[Any, int] = {}
    for row in rows:
        children[row["previous"]] = children.get(row["previous"], 0) + 1
    return any(r["value"].get("entry") == "policy"
               and (children[r["previous"]] > 1 or (r["previous"] is not None
                                                    and r["previous"] not in ids))
               for r in rows)  # fmt: skip


def status(repo: Any, subject: str, *, now_ms: int) -> dict[str, Any]:
    _budget_policy.subject(subject)
    rows = _budget_ledger.entries(repo, subject)
    roles = _roles(repo)
    findings: list[dict[str, Any]] = []
    policy: dict[str, Any] | None = None
    started: int | None = None
    flagged = set()
    owner_serial = 0
    for oid in _budget_ledger.forks(rows):
        why = "an entry does not continue the ledger's single chain"
        findings.append(_finding("fail", "budget.ledger-fork", oid, why))
    for row in rows:
        value = row["value"]
        findings += _signer_findings(row, roles)
        if value.get("entry") == "policy":
            doc = value.get("policy")
            try:
                code = _budget_policy.judge(doc, policy, roles, owner_serial)
            except _budget_policy.BudgetError:
                code = "budget.policy-unsigned"
            if code is None and doc.get("subject") != subject:
                code = "budget.policy-subject"
            if code is not None:
                findings.append(_finding("fail", code, row["id"],
                                         "a budget policy was refused and the one in force "
                                         "stays"))  # fmt: skip
                continue
            policy = {**_budget_policy.body(doc), "sha256": _budget_policy.digest(doc),
                      "signer": _budget_policy.signer(doc), "entry": row["id"]}  # fmt: skip
            started = int(value.get("at_ms") or 0) if started is None else started
            if policy["signer"] in _pinned_policy(roles):
                owner_serial = max(owner_serial, policy["serial"])
        elif value.get("entry") == "flag" and isinstance(value.get("about"), str):
            flagged.add((value.get("code"), value["about"]))
    totals = _budget_spend.fold(rows)
    totals["wall_clock_s"] = max(0, (now_ms - started) // 1000) if started is not None else 0
    limits = policy["limits"] if policy else {n: None for n in LIMITS}
    over = [n for n in LIMITS if limits[n] is not None and totals[n] >= limits[n]]
    decision = "allow" if not over else policy["on_limit"]  # type: ignore[index]
    if _policy_forked(rows):  # which policy is in force depends on a fork: fail closed
        decision = "deny"
    if policy is None:
        findings.append(_finding("advisory", "budget.no-policy", None,
                                 "no budget policy is in force: nothing is capped"))  # fmt: skip
    remaining = {n: (None if limits[n] is None else max(limits[n] - totals[n], 0))
                 for n in LIMITS}  # fmt: skip
    return {"subject": subject, "roles": roles["status"], "policy": policy, "totals": totals,
            "remaining": remaining, "over": over, "decision": decision,
            "entries": len(rows), "head": rows[-1]["id"] if rows else None,
            "findings": findings,
            "unflagged": [f for f in findings if f["level"] == "fail" and f["entry"]
                          and (f["code"][5:], f["entry"]) not in flagged]}  # fmt: skip


def check(repo: Any, subject: str, *, now_ms: int, key: Any = None) -> dict[str, Any]:
    """:func:`status` plus flags: with *key*, each unflagged ``fail:`` finding and an
    ``escalate`` at the limit are recorded as held ``flag`` entries for oversight."""
    body = status(repo, subject, now_ms=now_ms)
    flags: list[str] = []
    if key is not None:
        for f in body["unflagged"]:
            flags.append(_budget_ledger.append(
                repo, subject, "flag", {"code": f["code"][5:], "detail": f["message"],
                                        "about": f["entry"]}, key, at_ms=now_ms))  # fmt: skip
        about = (body["policy"] or {}).get("entry")
        if body["decision"] == "escalate" and not _escalated(repo, subject, about):
            flags.append(_budget_ledger.append(
                repo, subject, "flag", {"code": "budget.limit-reached",
                                        "detail": "over: " + ", ".join(body["over"]),
                                        "about": about}, key, at_ms=now_ms))  # fmt: skip
    return {**body, "flags": flags}


def _escalated(repo: Any, subject: str, about: Any) -> bool:
    from opentine.repository._holds import BUDGET_FLAG

    for oid in _budget_ledger.held_ids(repo, BUDGET_FLAG, subject):
        row = _budget_ledger.read(repo, oid)
        if row and row["value"].get("code") == "budget.limit-reached" and (
                row["value"].get("about") == about):  # fmt: skip
            return True
    return False


__all__ = ["UNITS", "check", "status"]
