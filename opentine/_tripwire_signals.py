"""The signals a tripwire reads (0.91): ``value(repo, wire, now_ms)``.

Every signal is recomputed from held, signed records; nothing is cached, so a
tripwire reads the same value whoever evaluates it.

* ``suspicion.flags`` and ``suspicion.score``: the cumulative-suspicion and
  doom-loop flags of :mod:`opentine._monitor_suspicion` over every verified
  coverage ledger (a stream scope reads that stream's ledgers only); the score
  is the highest summed score of a matching ``agent:``, ``session:`` or
  ``run:`` subject.
* ``monitor.non-allow`` and ``monitor.events``: the monitor outcomes other than
  ``allow``, and all evaluated events, from the same verified ledgers (per
  subject for an ``agent:``/``session:`` scope, per stream otherwise).
* ``budget.LIMIT``: the spend total of a budget subject
  (:func:`opentine._budget_status.status`), at the injected time ``now_ms``.
* ``ingest.events``: captured events of the signed ingest batches in scope.
* ``decoy.touches``: captured events that contain a registered decoy. Every
  string in an event is compared by its ``sha256:`` digest whole, split at
  whitespace, quotes and brackets, and each such token split again at ``/``,
  ``?``, ``#`` and ``&``; the registry holds only digests, never the decoys.

Each signal returns ``(value, evidence)``, the evidence being the record ids
the value was read from.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_TOKEN = re.compile(r"[\s\"'`=,;|()<>\[\]{}]+")
_PART = re.compile(r"[/?#&]+")


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 64:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k, depth + 1),
                                                      *_strings(v, depth + 1))]  # fmt: skip
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, depth + 1)]
    return []


def digests(event: Any) -> set[str]:
    """The ``sha256:`` digests of every string, token and path part of *event*."""
    pieces: set[str] = set()
    for text in _strings(event):
        pieces.add(text)
        for token in _TOKEN.split(text):
            pieces.add(token)
            pieces.update(_PART.split(token))
    pieces.discard("")
    return {"sha256:" + hashlib.sha256(p.encode("utf-8")).hexdigest() for p in pieces}


def _in_scope(scope: str, stream: str, subject: dict[str, str]) -> bool:
    kind, _, name = scope.partition(":")
    if scope == "*":
        return True
    if kind == "stream":
        return name == stream
    return subject.get(kind) == name


def events(repo: Any, scope: str) -> list[tuple[str, dict[str, Any]]]:
    """``[(batch id, event line)]`` of every captured event in *scope*, stream by stream."""
    from opentine import _ingest_batch, _ingest_holds, _monitor_ledger
    from opentine._monitor_runner import _events, _subject

    out = []
    for stream in _ingest_holds.streams(repo):
        if scope.startswith("stream:") and scope != f"stream:{stream}":
            continue
        rows, _ = _monitor_ledger.walk(repo, _ingest_holds.head(repo, stream),
                                       _ingest_batch.CONVENTION)  # fmt: skip
        for row in rows:
            if not row["signed"]:
                continue
            for line in _events(row["claim"]):
                if _in_scope(scope, stream, _subject(line.get("e"))):
                    out.append((row["id"], line))
    return out


def _suspicion(repo: Any, scope: str) -> dict[str, Any]:
    from opentine import _monitor_ledger, _monitor_suspicion
    from opentine._monitor_verdict import monitors

    keys, _ = monitors(repo)
    chains = [(m, s) for m, s in _monitor_ledger.chains(repo)
              if not scope.startswith("stream:") or scope == f"stream:{s}"]  # fmt: skip
    return _monitor_suspicion.scan(repo, chains, keys)


def _subjects(scan: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    if scope.startswith(("agent:", "session:")):
        return [s for s in scan["subjects"] if s["subject"] == scope]
    return [s for s in scan["subjects"] if s["subject"].startswith("stream:")]


def value(repo: Any, wire: dict[str, Any], now_ms: int) -> tuple[float, list[str]]:
    metric, scope = wire["metric"], wire["scope"]
    if metric.startswith("budget."):
        from opentine._budget_status import status

        subject = scope[len("budget:") :] if scope.startswith("budget:") else scope
        found = status(repo, subject, now_ms=now_ms)
        return float(found["totals"][metric[len("budget."):]]), [found["head"]] * bool(
            found["head"])  # fmt: skip
    if metric in ("ingest.events", "decoy.touches"):
        rows = events(repo, scope)
        if metric == "decoy.touches":
            decoys = set(wire["decoys"])
            rows = [(b, line) for b, line in rows if digests(line.get("e")) & decoys]
        return float(len(rows)), sorted({b for b, _ in rows})
    scan = _suspicion(repo, scope)
    if metric == "suspicion.flags":
        flags = [
            f
            for f in scan["flags"]
            if not scope.startswith(("agent:", "session:")) or f["subject"] == scope
        ]
        return float(len(flags)), sorted({f["record"] for f in flags})
    if metric == "suspicion.score":
        rows = [
            s
            for s in scan["subjects"]
            if s["subject"].startswith(("agent:", "session:", "run:"))
            and (scope in ("*", s["subject"]) or scope.startswith("stream:"))
        ]
        return max((float(s["sum"]) for s in rows), default=0.0), []
    field = "failures" if metric == "monitor.non-allow" else "events"
    return float(sum(s[field] for s in _subjects(scan, scope))), []


def tripped(wire: dict[str, Any], number: float) -> bool:
    limit = wire["threshold"]
    return {">=": number >= limit, ">": number > limit, "<=": number <= limit,
            "<": number < limit}[wire["op"]]  # fmt: skip


__all__ = ["digests", "events", "tripped", "value"]
