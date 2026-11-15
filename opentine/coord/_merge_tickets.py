"""Merge-approval tickets: queue id, nonce and expiry in local queue state (0.52).

An ``opentine.merge-approval`` (SPEC 4.19) names a run and a target, but not
the queue it is for, and carries no nonce or expiry: its schema is closed.
Carrying them in an ``attestation`` over the approval would add a claim schema
that ``land`` reads to reach a verdict, which the FREEZE.md ruling on claim
schemas allows only once the owner grants it by name (none is granted), so they
live in the queue record instead and a signed form is a 1.x item.

``tine merge-queue approve --queue Q`` **issues** a ticket into queue ``Q``::

    {"nonce": <32 hex>, "approval": "sha256:<JCS digest of the record>",
     "run", "target", "approver", "expires_ms", "spent_fencing": null | N}

When the queue's gates require approvals, :func:`screen` admits only approvals
issued into *this* queue, unexpired and unspent; any other approval in the
evidence rejects the entry (``approval: not issued for ...``, ``... expired``,
``... replayed nonce``). A landing marks the tickets it used spent with its
fencing token, in the same compare-and-swap that lands it, so a nonce is
spent at most once.
"""

from __future__ import annotations

import secrets
from typing import Any

MAX_TICKETS = 4096
MAX_TTL_SECONDS = 30 * 24 * 60 * 60


def issue(repo: Any, queue: str, record: Any, ttl: float) -> dict[str, Any]:
    """Register the signed approval *record* with queue *queue*; the ticket."""
    from opentine._merge_gates import digest
    from opentine._merge_record import check_approval
    from opentine.coord._merge_queue import _update
    from opentine.coord._tasks import LeaseError

    if not isinstance(ttl, int | float) or isinstance(ttl, bool) or not 0 < ttl <= MAX_TTL_SECONDS:
        raise ValueError(f"approval expiry must be 1..{MAX_TTL_SECONDS} seconds")
    key = record.get("signature", {}).get("public_key") if isinstance(record, dict) else None
    found = check_approval(record, public_key=bytes.fromhex(key) if isinstance(key, str) else None)
    ticket: dict[str, Any] = {"nonce": secrets.token_hex(16), "approval": digest(record),
                              "run": found["run"], "target": found["target"],
                              "approver": key, "spent_fencing": None}  # fmt: skip

    def change(value: dict[str, Any], moment: int) -> dict[str, Any]:
        if found["target"] != value["target"]:
            raise LeaseError("target", f"the approval is for {found['target']}, not "
                             f"{value['target']} (queue {queue})")  # fmt: skip
        # Spent tickets are kept past expiry: pruning one would let the same
        # signed approval be issued again under a fresh nonce and replayed.
        live = [t for t in value.get("tickets") or []
                if t["expires_ms"] > moment or t["spent_fencing"] is not None]  # fmt: skip
        if any(t["approval"] == ticket["approval"] for t in live):
            raise LeaseError("exists", f"this approval is already issued into {queue}")
        if len(live) >= MAX_TICKETS:
            raise LeaseError("full", f"merge queue {queue} holds too many live approvals")
        ticket["expires_ms"] = moment + int(ttl * 1000)
        return {**value, "tickets": [*live, ticket]}

    _update(repo, queue, change)
    return ticket


def screen(value: dict[str, Any], evidence: Any, moment: int) -> list[str]:
    """Why the evidence's approvals may not count here (empty: they may)."""
    from opentine._merge_gates import digest

    if not (value.get("gates") or {}).get("approvals"):
        return []
    rows = evidence.get("approvals") if isinstance(evidence, dict) else None
    tickets = {t["approval"]: t for t in value.get("tickets") or []}
    failures = []
    for record in rows if isinstance(rows, list) else []:
        ticket = tickets.get(digest(record))
        if ticket is None:
            failures.append(f"approval: not issued for merge queue {value['queue']}")
        elif ticket["spent_fencing"] is not None:
            failures.append(f"approval: replayed nonce {ticket['nonce']}")
        elif ticket["expires_ms"] <= moment:
            failures.append(f"approval: nonce {ticket['nonce']} expired")
    return failures


def spend(value: dict[str, Any], gates: list[dict[str, str]], fencing: int) -> list[dict]:
    """The queue's tickets with those behind the landing's approval *gates* spent."""
    used = {g["digest"] for g in gates if g["gate"] == "approval"}
    return [{**t, "spent_fencing": fencing} if t["approval"] in used else t
            for t in value.get("tickets") or []]  # fmt: skip


__all__ = ["MAX_TICKETS", "MAX_TTL_SECONDS", "issue", "screen", "spend"]
