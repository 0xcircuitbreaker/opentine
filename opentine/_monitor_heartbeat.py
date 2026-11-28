"""Signed monitor heartbeats: ``opentine.monitor-heartbeat/1`` records.

A monitor proves it is alive by signing a heartbeat every ``interval_s``
seconds (default 60). Each heartbeat is a signed ``annotation`` on the stream's
anchor blob whose ``value`` is::

    {"convention": "opentine.monitor-heartbeat/1",
     "monitor": {"id", "kind", "config_digest"}, "stream": S, "seq": N,
     "previous": HEARTBEAT-ID | null, "interval_s": 60,
     "ingest": {"head": BATCH-ID, "seq": K, "at": RFC3339} | null,
     "ledger": COVERAGE-RECORD-ID | null, "at": RFC3339}

Heartbeats of one monitor on one stream form a hash chain held as
``monitor-heartbeat:MONITOR@STREAM``. Each one is bound to the ingest stream's
head batch when it was signed, so it cannot be backfilled: a heartbeat whose
time is earlier than its bound batch, or that names an old head while newer
batches had already arrived (more than one interval before it), is
``monitor.heartbeat-backfilled``; one whose identity is not its chain's is
``monitor.heartbeat-replayed``; one dated more than an interval after the
time checked is ``monitor.heartbeat-future``. A heartbeat of another config
proves nothing about this one. A monitor is ``stale`` after ``missed``
(default 3) intervals without a heartbeat; :func:`check` reports every such
window, and the last one against an injected ``now``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from opentine import _ingest_holds
from opentine._monitor_ledger import chain_name, walk
from opentine.repository._holds import MONITOR_HEARTBEAT

CONVENTION = "opentine.monitor-heartbeat/1"
INTERVAL_S = 60
MISSED = 3


class HeartbeatError(ValueError):
    """A heartbeat that may not be signed (it would go back in time)."""


def millis(text: Any) -> int | None:
    try:
        return int(datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def head(repo: Any, monitor: str, stream: str) -> str | None:
    return _ingest_holds.head(repo, chain_name(monitor, stream), prefix=MONITOR_HEARTBEAT)


def beat(repo: Any, monitor: dict[str, Any], stream: str, key: Any, *, at_ms: int,
         interval_s: int = INTERVAL_S) -> dict[str, Any]:  # fmt: skip
    """Sign, store and chain one heartbeat bound to the current ingest head."""
    from opentine import _ingest_batch, _monitor_ledger
    from opentine._ingest_policy import anchor
    from opentine._utc import rfc3339_utc

    name = chain_name(monitor["id"], stream)
    previous = head(repo, monitor["id"], stream)
    prior = _ingest_holds.read(repo, previous, CONVENTION) if previous else None
    if previous and prior is None:
        raise HeartbeatError(f"heartbeat chain {name} head {previous} is unreadable")
    at = rfc3339_utc(at_ms / 1000)
    if prior and (millis(prior["claim"].get("at")) or 0) >= at_ms:
        raise HeartbeatError("a heartbeat is newer than the one before it")
    batch_id = _ingest_holds.head(repo, stream)
    bound = None
    if batch_id is not None:
        batch = _ingest_holds.read(repo, batch_id, _ingest_batch.CONVENTION)
        if batch is None:
            raise HeartbeatError(f"stream {stream} head {batch_id} is unreadable")
        if (millis(batch["claim"].get("at")) or 0) > at_ms:
            raise HeartbeatError("a heartbeat may not be older than the batch it is bound to")
        bound = {"head": batch_id, "seq": batch["claim"]["seq"], "at": batch["claim"]["at"]}
    claim = {"convention": CONVENTION, "monitor": dict(monitor), "stream": stream,
             "seq": prior["claim"]["seq"] + 1 if prior else 0, "previous": previous,
             "interval_s": interval_s, "ingest": bound,
             "ledger": _monitor_ledger.head(repo, monitor["id"], stream), "at": at}  # fmt: skip
    oid = _ingest_holds.write(repo, anchor(repo, stream), claim, key, previous=previous,
                              signed_at=at)  # fmt: skip
    _ingest_holds.move_head(repo, name, previous, oid, prefix=MONITOR_HEARTBEAT)
    return {"id": oid, **claim}


def _finding(level: str, code: str, record: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:monitor.{code}", "record": record,
            "message": message}  # fmt: skip


def check(
    repo: Any,
    monitor: dict[str, Any],
    stream: str,
    batches: list[dict[str, Any]],
    *,
    now_ms: int,
    keys: set[str],
    gating: bool,
    missed: int = MISSED,
) -> dict[str, Any]:
    """``{"heartbeats", "first_ms", "last_ms", "stale_windows", "findings"}`` of one chain.

    *batches* is the stream's batch chain (oldest first, each ``{"id", "claim"}``);
    *keys* the pinned monitor fingerprints. Staleness is advisory unless *gating*.
    """
    soft = "fail" if gating else "advisory"
    rows, problems = walk(repo, head(repo, monitor["id"], stream), CONVENTION)
    findings = [_finding("fail", "heartbeat-chain", None, p) for p in problems]
    by_id = {b["id"]: b for b in batches}
    order = {b["id"]: i for i, b in enumerate(batches)}
    windows: list[dict[str, Any]] = []
    first_ms = last_ms = None
    for row in rows:
        claim, oid = row["claim"], row["id"]
        at_ms = millis(claim.get("at"))
        if not row["signed"] or row["signer"] not in keys:
            findings.append(_finding("fail", "heartbeat-unsigned", oid,
                                     "not signed by a pinned monitor key"))  # fmt: skip
            continue
        theirs = claim.get("monitor") if isinstance(claim.get("monitor"), dict) else {}
        mine = theirs.get("id") == monitor["id"] and claim.get("stream") == stream
        if not mine or at_ms is None or row["previous"] != claim.get("previous"):
            findings.append(_finding("fail", "heartbeat-replayed", oid,
                                     "the heartbeat belongs to another monitor, config or "
                                     "stream"))  # fmt: skip
            continue
        if at_ms > now_ms + claim["interval_s"] * 1000:
            findings.append(_finding("fail", "heartbeat-future", oid,
                                     "dated after the time checked: no liveness"))  # fmt: skip
            continue
        if theirs.get("config_digest") != monitor["config_digest"]:
            findings.append(_finding(soft, "config-changed", oid,
                                     "the heartbeat carries another monitor config, so it "
                                     "proves nothing about this one"))  # fmt: skip
            continue
        bound = claim.get("ingest")
        if bound is not None:
            batch = by_id.get(bound.get("head")) if isinstance(bound, dict) else None
            if batch is None or batch["claim"].get("seq") != bound.get("seq"):
                findings.append(_finding("fail", "heartbeat-backfilled", oid,
                                         "bound to a batch the stream does not hold"))  # fmt: skip
                continue
            newer = batches[order[batch["id"]] + 1 :]
            late = [
                b
                for b in newer
                if (millis(b["claim"].get("at")) or 0) + claim["interval_s"] * 1000 <= at_ms
            ]
            if (millis(batch["claim"].get("at")) or 0) > at_ms or late:
                findings.append(_finding("fail", "heartbeat-backfilled", oid,
                                         "signed later than it claims: the stream had moved "
                                         "on"))  # fmt: skip
                continue
        elif (
            batches
            and (millis(batches[0]["claim"].get("at")) or 0) + claim["interval_s"] * 1000 <= at_ms
        ):
            findings.append(
                _finding(
                    "fail",
                    "heartbeat-backfilled",
                    oid,
                    "claims an empty stream that already had batches",
                )
            )
            continue
        if last_ms is not None and at_ms - last_ms > missed * claim["interval_s"] * 1000:
            windows.append({"from": last_ms, "to": at_ms})
        first_ms = at_ms if first_ms is None else first_ms
        last_ms = at_ms
    interval = rows[-1]["claim"].get("interval_s", INTERVAL_S) if rows else INTERVAL_S
    if last_ms is None or now_ms - last_ms > missed * interval * 1000:
        windows.append({"from": last_ms, "to": now_ms})
    for window in windows:
        start = "the start" if window["from"] is None else f"{window['from']} ms"
        findings.append(_finding(soft, "stale", None,
                                 f"no heartbeat from {start} to {window['to']} ms "
                                 f"({missed} missed intervals)"))  # fmt: skip
    return {"heartbeats": len(rows), "first_ms": first_ms, "last_ms": last_ms,
            "stale_windows": windows,
            "findings": findings}  # fmt: skip


__all__ = ["CONVENTION", "INTERVAL_S", "MISSED", "HeartbeatError", "beat", "check", "head",
           "millis"]  # fmt: skip
