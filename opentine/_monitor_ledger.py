"""The monitor coverage ledger: ``opentine.monitor-coverage/1`` records.

A monitor that evaluates an ingest stream (:mod:`opentine._monitor_runner`)
writes one coverage record per ingest batch it evaluated. The record is a
signed ``annotation`` (no new object kind) on the stream's anchor blob whose
``value`` follows the convention::

    {"convention": "opentine.monitor-coverage/1",
     "monitor": {"id", "kind", "config_digest"}, "stream": S, "seq": N,
     "previous": RECORD-ID | null, "batch": BATCH-ID, "batch_seq": K,
     "first_index": I, "next_index": J, "evaluated": E,
     "by_action": {"allow": n, "flag": n, "resample": n, "defer": n, "block": n, "error": n},
     "by_category": {"NAME": n}, "threshold": T,
     "latency": {"slo_ms", "p95_ms", "max_ms", "met"},
     "events_sha256": "sha256:...", "events": "<JSON Lines>", "at": RFC3339}

``events`` holds one line per evaluated event, ``{"i": INDEX, "s": SCORE|null,
"a": ACTION, "d": INPUT-DIGEST, "l": LATENCY-MS, "u": {"agent", "session",
"run"}, "c": CATEGORY, "v": SEVERITY}`` (sorted keys; ``c``, ``v`` and ``u``
only when known). Allow verdicts are counted here, as a count plus a digest
list, rather than signed one by one.

Records of one monitor on one stream form a hash chain (``seq``,
``previous``); the newest is held as ``monitor-ledger:MONITOR@STREAM`` and the
chain keeps the rest reachable. ``tine hold release`` refuses the prefix.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from opentine import _ingest_holds
from opentine._monitor_verdict import ACTIONS, digest
from opentine.repository._holds import MONITOR_LEDGER

CONVENTION = "opentine.monitor-coverage/1"
MONITOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
OUTCOMES = (*ACTIONS, "error")
SLO_MS = 30_000
_LINE = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False)  # fmt: skip


class LedgerError(ValueError):
    """A coverage record that cannot be written."""


def monitor_id(value: Any) -> str:
    if not isinstance(value, str) or not MONITOR_ID.fullmatch(value):
        raise LedgerError(f"{value!r} is not a monitor id: [A-Za-z0-9._-], at most 64")
    return value


def config_digest(config: dict[str, Any]) -> str:
    """The digest a coverage record, heartbeat and operating point bind a monitor to."""
    keys = ("mode", "deadline_ms", "fail_closed", "reasoning", "threshold", "action")
    body = {k: config[k] for k in keys}
    body["threshold"] = float(body["threshold"])
    body["monitor"] = config["monitor"].identity
    return digest(body)


def identity(config: dict[str, Any]) -> dict[str, Any]:
    ident = config["monitor"].identity
    return {"id": monitor_id(ident["id"]), "kind": ident["kind"],
            "config_digest": config_digest(config)}  # fmt: skip


def chain_name(monitor: str, stream: str) -> str:
    return f"{monitor_id(monitor)}@{stream}"


def p95(values: list[int]) -> int:
    """The nearest-rank 95th percentile (0 for no values)."""
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, -(-95 * len(ordered) // 100) - 1)]


def encode(rows: list[dict[str, Any]]) -> str:
    return "".join(_LINE.encode(row) + "\n" for row in rows)


def decode(text: Any) -> list[dict[str, Any]] | None:
    """The event lines of a record (``None`` when they are not well formed)."""
    from opentine import _json_shallow

    if not isinstance(text, str):
        return None
    rows = []
    for line in text.splitlines():
        try:
            row = _json_shallow.loads(line.encode("utf-8"))
        except ValueError:
            return None
        if not isinstance(row, dict) or type(row.get("i")) is not int:
            return None
        if row.get("a") not in OUTCOMES or not isinstance(row.get("d"), str):
            return None
        rows.append(row)
    return rows


def head(repo: Any, monitor: str, stream: str) -> str | None:
    return _ingest_holds.head(repo, chain_name(monitor, stream), prefix=MONITOR_LEDGER)


def read(repo: Any, oid: str) -> dict[str, Any] | None:
    return _ingest_holds.read(repo, oid, CONVENTION)


def append(repo: Any, monitor: dict[str, Any], stream: str, batch: dict[str, Any],
           rows: list[dict[str, Any]], key: Any, *, threshold: float,
           at: str) -> dict[str, Any]:  # fmt: skip
    """Sign, store and chain the coverage record of one evaluated *batch*; its summary."""
    from opentine._ingest_policy import anchor

    name = chain_name(monitor["id"], stream)
    previous = head(repo, monitor["id"], stream)
    prior = read(repo, previous) if previous else None
    if previous and prior is None:
        raise LedgerError(f"ledger {name} head {previous} is unreadable")
    by_action = dict.fromkeys(OUTCOMES, 0)
    by_category: dict[str, int] = {}
    for row in rows:
        by_action[row["a"]] += 1
        if row.get("c"):
            by_category[row["c"]] = by_category.get(row["c"], 0) + 1
    latencies = [int(row.get("l", 0)) for row in rows]
    worst = p95(latencies)
    text = encode(rows)
    claim = {"convention": CONVENTION, "monitor": dict(monitor), "stream": stream,
             "seq": prior["claim"]["seq"] + 1 if prior else 0, "previous": previous,
             "batch": batch["id"], "batch_seq": batch["seq"],
             "first_index": batch["first_index"], "next_index": batch["next_index"],
             "evaluated": len(rows), "by_action": by_action, "by_category": by_category,
             "threshold": float(threshold),
             "latency": {"slo_ms": SLO_MS, "p95_ms": worst, "max_ms": max(latencies, default=0),
                         "met": worst <= SLO_MS},
             "events_sha256": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
             "events": text, "at": at}  # fmt: skip
    oid = _ingest_holds.write(repo, anchor(repo, stream), claim, key, previous=previous,
                              signed_at=at, verbatim=("events",))  # fmt: skip
    _ingest_holds.move_head(repo, name, previous, oid, prefix=MONITOR_LEDGER)
    return {"id": oid, **{k: v for k, v in claim.items() if k != "events"}}


def walk(repo: Any, start: str | None, convention: str) -> tuple[list[dict[str, Any]], list[str]]:
    """``(records oldest first, problems)`` along a ``previous`` chain from *start*."""
    found: list[dict[str, Any]] = []
    problems: list[str] = []
    cursor, seen = start, set()
    while cursor is not None:
        if cursor in seen:
            problems.append(f"{cursor}: the chain loops")
            break
        seen.add(cursor)
        row = _ingest_holds.read(repo, cursor, convention)
        if row is None:
            problems.append(f"{cursor}: a record in the chain is missing or unreadable")
            break
        found.append(row)
        cursor = row["claim"].get("previous")
    found.reverse()
    for index, row in enumerate(found):
        if row["claim"].get("seq") != index:
            problems.append(f"{row['id']}: seq {row['claim'].get('seq')} is not {index}")
    return found, problems


def records(repo: Any, monitor: str, stream: str) -> tuple[list[dict[str, Any]], list[str]]:
    return walk(repo, head(repo, monitor, stream), CONVENTION)


def chains(repo: Any) -> list[tuple[str, str]]:
    """Every ``(monitor, stream)`` with a held ledger head."""
    from opentine.repository._holds import holds_path, read_holds

    found = set()
    for row in read_holds(holds_path(repo)):
        if row["target"].startswith(MONITOR_LEDGER):
            monitor, _, stream = row["target"][len(MONITOR_LEDGER) :].partition("@")
            found.add((monitor, stream))
    return sorted(found)


__all__ = ["CONVENTION", "OUTCOMES", "SLO_MS", "LedgerError", "append", "chain_name", "chains",
           "config_digest", "decode", "encode", "head", "identity", "monitor_id", "p95", "read",
           "records", "walk"]  # fmt: skip
