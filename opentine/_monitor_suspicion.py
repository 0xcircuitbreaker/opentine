"""Cumulative suspicion and doom-loop flags over a monitor's coverage ledger.

One action just under a threshold is not suspicious; an agent that keeps
probing just under it, or keeps retrying the same refused action, is. This
module reads every verified coverage record (:mod:`opentine._monitor_ledger`)
of the given monitors and streams together, in chain order, and accumulates
per subject:

* ``agent:ID``, ``session:ID`` and ``run:ID`` from the event's subject, so
  splitting work across sessions or runs does not reset an agent's total and
  rotating agent ids does not reset a session's;
* ``stream:S``, the ingest stream itself, which the agent cannot name, so
  rotating every self-claimed id still adds up (doom-loop flags only: a busy
  stream's summed score says nothing);
* ``action:DIGEST``, the same action whatever subject repeats it.

Three advisory flags follow (owner decision D12: they never block):

* ``advisory:monitor.cumulative-suspicion``: the subject's summed score reaches
  ``budget`` (default 3.0);
* ``advisory:monitor.doom-loop-near-threshold``: ``repeats`` (default 3) or
  more scores within ``margin`` (default 0.1) below the threshold;
* ``advisory:monitor.doom-loop-repeated-failure``: the same action digest
  ``repeats`` or more times with an outcome that is not ``allow``.

Each flag names the coverage record in which it was first reached; the
oversight queue (:mod:`opentine._oversight_queue`) opens one
``suspicion:RECORD`` item per such record, so escalation goes through the
existing k-of-n review. The result is a pure function of the held records.
"""

from __future__ import annotations

from typing import Any

from opentine import _monitor_ledger

BUDGET, MARGIN, REPEATS = 3.0, 0.1, 3
CODES = ("cumulative-suspicion", "doom-loop-near-threshold", "doom-loop-repeated-failure")


def _keys(row: dict[str, Any], stream: str) -> list[str]:
    subject = row.get("u") if isinstance(row.get("u"), dict) else {}
    keys = [f"{k}:{subject[k]}" for k in ("agent", "session", "run")
            if isinstance(subject.get(k), str)]  # fmt: skip
    return [*keys, f"stream:{stream}", f"action:{row['d']}"]


def scan(repo: Any, chains: list[tuple[str, str]], keys: set[str], *, budget: float = BUDGET,
         margin: float = MARGIN, repeats: int = REPEATS) -> dict[str, Any]:  # fmt: skip
    """``{"subjects", "flags"}`` over the verified ledgers ``[(monitor, stream)]``, together."""
    rows = [(s, r) for m, s in chains for r in _monitor_ledger.records(repo, m, s)[0]]
    totals: dict[str, dict[str, Any]] = {}
    flags: dict[tuple[str, str], dict[str, Any]] = {}

    def flag(code: str, key: str, record: str, value: Any) -> None:
        flags.setdefault(
            (key, code),
            {
                "level": "advisory",
                "code": f"advisory:monitor.{code}",
                "subject": key,
                "record": record,
                "value": value,
            },
        )

    for stream, record in rows:
        claim = record["claim"]
        if not record["signed"] or record["signer"] not in keys:
            continue
        lines = _monitor_ledger.decode(claim.get("events")) or []
        threshold = float(claim.get("threshold") or 0.0)
        for line in lines:
            score = line.get("s") if isinstance(line.get("s"), (int, float)) else None
            for key in _keys(line, stream):
                total = totals.setdefault(key, {"subject": key, "events": 0, "sum": 0.0,
                                                "near": 0, "failures": 0})  # fmt: skip
                total["events"] += 1
                if score is not None:
                    total["sum"] = round(total["sum"] + float(score), 9)
                    if threshold - margin <= score < threshold:
                        total["near"] += 1
                if line["a"] != "allow":
                    total["failures"] += 1
                if key.startswith(("agent:", "session:", "run:")) and total["sum"] >= budget:
                    flag(CODES[0], key, record["id"], total["sum"])
                if total["near"] >= repeats:
                    flag(CODES[1], key, record["id"], total["near"])
                if key.startswith("action:") and total["failures"] >= repeats:
                    flag(CODES[2], key, record["id"], total["failures"])
    return {"subjects": [totals[k] for k in sorted(totals) if not k.startswith("action:")
                         or totals[k]["failures"]],
            "flags": [flags[k] for k in sorted(flags)]}  # fmt: skip


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]``: one ``suspicion:RECORD`` per record that raised a flag."""
    from opentine._monitor_verdict import monitors

    keys, _ = monitors(repo)
    found = {f["record"] for f in scan(repo, _monitor_ledger.chains(repo), keys)["flags"]}
    return [{"item": f"suspicion:{oid}", "source": "suspicion"} for oid in sorted(found)]


__all__ = ["BUDGET", "CODES", "MARGIN", "REPEATS", "items", "scan"]
