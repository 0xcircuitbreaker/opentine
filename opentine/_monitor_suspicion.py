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
* ``action:DIGEST``, the same action whatever subject repeats it;
* ``shape:DIGEST`` (doom-loop repeated failures only), the normalized action:
  the tool name and argument keys with each value bucketed (a string's first
  word, digits folded; a number's type), recomputed from the captured event,
  so changing one argument per retry still counts as the same action, while
  different tools or commands do not.

Only records signed by a key bound to their monitor
(:mod:`opentine._monitor_binding`) count. A record whose threshold or a score
is NaN, infinite or not a number is never read and is listed in ``invalid``.

Three advisory flags follow (owner decision D12: they never block):

* ``advisory:monitor.cumulative-suspicion``: the subject's summed score reaches
  ``budget`` (default 3.0);
* ``advisory:monitor.doom-loop-near-threshold``: ``repeats`` (default 3) or
  more scores within ``margin`` (default 0.1) below the threshold;
* ``advisory:monitor.doom-loop-repeated-failure``: the same action digest or
  shape ``repeats`` or more times with an outcome that is not ``allow``.

Each flag names the coverage record in which it was first reached; the
oversight queue (:mod:`opentine._oversight_queue`) opens one
``suspicion:RECORD`` item per such record, so escalation goes through the
existing k-of-n review. The result is a pure function of the held records.
"""

from __future__ import annotations

import re
from typing import Any

from opentine import _ingest_batch, _ingest_holds, _monitor_ledger
from opentine._monitor_binding import allowed, finite
from opentine._monitor_runner import _events, _request
from opentine._monitor_verdict import digest

BUDGET, MARGIN, REPEATS = 3.0, 0.1, 3
CODES = ("cumulative-suspicion", "doom-loop-near-threshold", "doom-loop-repeated-failure")


def _bucket(value: Any) -> Any:
    """A value's shape: a string's first word (digits as ``#``), a number's type."""
    if isinstance(value, str):
        word = value.strip().split(maxsplit=1)[0].casefold() if value.strip() else ""
        word = word.rsplit("/", 1)[-1]  # /bin/rm is rm
        return "str:" + re.sub(r"[0-9]+", "#", word)[:32]
    if isinstance(value, dict):
        return {"obj": sorted(str(k) for k in value)}
    return type(value).__name__ if not isinstance(value, list) else "list"


def shape(request: dict[str, Any]) -> str:
    """The normalized action key: tool name and argument keys, values bucketed."""
    args = request.get("arguments")
    body = {k: _bucket(v) for k, v in args.items()} if isinstance(args, dict) else _bucket(args)
    tool = request.get("tool")
    return digest({"tool": tool.casefold() if isinstance(tool, str) else tool, "arguments": body})


def _shapes(repo: Any, claim: dict[str, Any]) -> dict[int, str]:
    """``{index: shape}`` of the batch a record names, for lines scored on its input."""
    batch = _ingest_holds.read(repo, claim.get("batch"), _ingest_batch.CONVENTION) if isinstance(
        claim.get("batch"), str) else None  # fmt: skip
    if batch is None or not batch["signed"]:
        return {}
    return {e["i"]: (digest(_request(str(e.get("k", "event")), e.get("e"))),
                     shape(_request(str(e.get("k", "event")), e.get("e"))))
            for e in _events(batch["claim"])}  # fmt: skip


def _keys(row: dict[str, Any], stream: str, shapes: dict[int, Any]) -> list[str]:
    subject = row.get("u") if isinstance(row.get("u"), dict) else {}
    keys = [f"{k}:{subject[k]}" for k in ("agent", "session", "run")
            if isinstance(subject.get(k), str)]  # fmt: skip
    seen = shapes.get(row["i"])
    alike = [f"shape:{seen[1]}"] if seen and seen[0] == row["d"] else []
    return [*keys, f"stream:{stream}", f"action:{row['d']}", *alike]


def _invalid(claim: dict[str, Any], lines: list[dict[str, Any]]) -> str | None:
    if finite(claim.get("threshold")) is None:
        return "its threshold is not a finite number"
    if any(r.get("s") is not None and finite(r.get("s")) is None for r in lines):
        return "a score is not a finite number"
    return None


def scan(repo: Any, chains: list[tuple[str, str]], keys: set[str], *, budget: float = BUDGET,
         margin: float = MARGIN, repeats: int = REPEATS) -> dict[str, Any]:  # fmt: skip
    """``{"subjects", "flags", "invalid"}`` over the ledgers ``[(monitor, stream)]``, together."""
    bound = {m: allowed(repo, m, keys, gating=False)[0] for m in {m for m, _ in chains}}
    rows = [(m, s, r) for m, s in chains for r in _monitor_ledger.records(repo, m, s)[0]]
    invalid: list[dict[str, Any]] = []
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

    for monitor, stream, record in rows:
        claim = record["claim"]
        if not record["signed"] or record["signer"] not in bound[monitor]:
            continue
        lines = _monitor_ledger.decode(claim.get("events")) or []
        bad = _invalid(claim, lines)
        if bad:  # reported and never read: a NaN threshold must not hide a doom loop or crash
            invalid.append({"record": record["id"], "message": bad})
            continue
        threshold, shapes = finite(claim["threshold"]), _shapes(repo, claim)
        for line in lines:
            score = finite(line.get("s"))
            for key in _keys(line, stream, shapes):
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
                if key.startswith(("action:", "shape:")) and total["failures"] >= repeats:
                    flag(CODES[2], key, record["id"], total["failures"])
    return {"subjects": [totals[k] for k in sorted(totals) if not k.startswith(("action:",
                         "shape:")) or totals[k]["failures"]],
            "flags": [flags[k] for k in sorted(flags)], "invalid": invalid}  # fmt: skip


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]``: one ``suspicion:RECORD`` per record that raised a flag."""
    from opentine._monitor_verdict import monitors

    keys, _ = monitors(repo)
    found = {f["record"] for f in scan(repo, _monitor_ledger.chains(repo), keys)["flags"]}
    return [{"item": f"suspicion:{oid}", "source": "suspicion"} for oid in sorted(found)]


__all__ = ["BUDGET", "CODES", "MARGIN", "REPEATS", "items", "scan", "shape"]
