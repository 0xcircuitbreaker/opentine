"""The asynchronous monitor runner: a monitor over an ingest stream.

``tine monitor run --config CONFIG --stream S --key KEY`` reads the stream's
batches (:mod:`opentine._ingest_batch`) after the last one its coverage ledger
(:mod:`opentine._monitor_ledger`) records, in order, and scores every captured
event with the configured monitor. For each batch it writes one coverage
record: every evaluated index, its score and outcome (allow included), and the
latency from the batch's ingest time to each verdict against the SLO (p95 at
most 30 s; recorded and advisory). Every outcome that is not ``allow`` is also
an ``opentine.monitor-verdict/1`` attestation, signed and held as the gate's
are, with the monitor's ``category`` and ``severity`` when it names them.

The runner never enforces anything (owner decision D12): it reads events that
already happened. ``--follow`` keeps running, signs a heartbeat every
``interval_s`` seconds (:mod:`opentine._monitor_heartbeat`) and stops when its
stop event is set; the clock, the wait and the deadline runner are injectable,
so tests drive it without sleeping.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from opentine import _ingest_batch, _ingest_holds, _monitor_heartbeat, _monitor_ledger
from opentine._monitor_gate import run_with_deadline
from opentine._monitor_heartbeat import millis
from opentine._monitor_verdict import CONVENTION as VERDICT
from opentine._monitor_verdict import digest
from opentine._monitor_verdict import valid_reply as _valid
from opentine._utc import rfc3339_utc

SUBJECT = ("agent", "session", "run")


def pending(repo: Any, stream: str, monitor: str) -> list[dict[str, Any]]:
    """The stream's batches the monitor's ledger does not record yet, oldest first."""
    done = _monitor_ledger.head(repo, monitor, stream)
    last = _monitor_ledger.read(repo, done) if done else None
    if done and last is None:
        raise _monitor_ledger.LedgerError(f"the ledger head {done} is unreadable")
    seen = last["claim"]["batch_seq"] if last else -1
    rows, _ = _monitor_ledger.walk(repo, _ingest_holds.head(repo, stream),
                                   _ingest_batch.CONVENTION)  # fmt: skip
    return [r for r in rows if r["signed"] and r["claim"].get("seq", -1) > seen]


def _request(kind: str, event: Any) -> dict[str, Any]:
    body = event if isinstance(event, dict) else {"value": event}
    tool = body.get("tool") if isinstance(body.get("tool"), str) else kind
    arguments = body.get("arguments", body)
    reasoning = body.get("reasoning") if isinstance(body.get("reasoning"), str) else None
    return {"tool": tool, "method": "tools/call", "arguments": arguments,
            "reasoning": reasoning}  # fmt: skip


def _subject(event: Any) -> dict[str, str]:
    from opentine.redaction import redact_text

    if not isinstance(event, dict):
        return {}
    return {k: redact_text(event[k])[:128] for k in SUBJECT if isinstance(event.get(k), str)}


class Runner:
    def __init__(self, repo: Any, config: dict[str, Any], stream: str, key: Any, *,
                 clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
                 runner: Callable[..., tuple[bool, Any, Any]] = run_with_deadline,
                 interval_s: int = _monitor_heartbeat.INTERVAL_S) -> None:  # fmt: skip
        from opentine._ingest_policy import stream_name

        self.repo, self.config, self.stream, self.key = repo, config, stream_name(stream), key
        self.monitor = config["monitor"]
        getattr(self.monitor, "bind", lambda _repo: None)(repo)
        self.identity = _monitor_ledger.identity(config)
        self.clock_ms, self.runner, self.interval_s = clock_ms, runner, interval_s
        self.counts = {"batches": 0, "evaluated": 0, "verdicts": 0, "heartbeats": 0}
        self._anchor: str | None = None
        _refuse(repo, key)

    def _score(self, request: dict[str, Any]) -> dict[str, Any] | None:
        deadline = self.config["deadline_ms"] / 1000
        finished, value, error = self.runner(lambda: self.monitor.score(request), deadline)
        return value if finished and error is None and _valid(value) else None

    def _event(self, line: dict[str, Any], batch_ms: int) -> tuple[dict[str, Any], Any]:
        request = _request(str(line.get("k", "event")), line.get("e"))
        reply = self._score(request)
        latency = max(0, self.clock_ms() - batch_ms)
        row: dict[str, Any] = {"i": line["i"], "d": digest(request), "l": latency}
        subject = _subject(line.get("e"))
        if subject:
            row["u"] = subject
        if reply is None:
            return {**row, "s": None, "a": "error"}, request
        score = float(reply["score"])
        over = score >= float(self.config["threshold"])
        row.update(s=score, a=reply.get("action", self.config["action"]) if over else "allow")
        for short, name in (("c", "category"), ("v", "severity")):
            if over and reply.get(name):
                row[short] = reply[name]
        return row, request

    def _verdict(self, row: dict[str, Any], request: dict[str, Any], at: str) -> None:
        from opentine import _monitor_verdict
        from opentine.redaction import redact_text

        claim = {"convention": VERDICT, "monitor": self.monitor.identity,
                 "input_digest": row["d"], "tool": redact_text(request["tool"]),
                 "session": f"ingest:{self.stream}", "score": row["s"],
                 "threshold": float(self.config["threshold"]),
                 "reasoning": {"state": "unavailable", "digest": None}, "action": row["a"],
                 "enforced": False, "mode": "advisory", "decided_by": "monitor",
                 "latency_ms": row["l"], "deadline_ms": self.config["deadline_ms"],
                 "fail_closed": self.config["fail_closed"], "stop": None,
                 "trajectories": [{"role": "original", "digest": row["d"]}],
                 "chosen": "original", "decided_at": at}  # fmt: skip
        for short, name in (("c", "category"), ("v", "severity")):
            if short in row:
                claim[name] = row[short]
        if self._anchor is None:
            from opentine._containment_records import anchor

            self._anchor = anchor(self.repo, "monitor-runner", f"monitor {self.identity['id']}")
        _monitor_verdict.record(self.repo, self._anchor, claim, self.key)
        self.counts["verdicts"] += 1

    def batch(self, batch: dict[str, Any]) -> dict[str, Any]:
        """Evaluate one batch and write its coverage record."""
        claim = batch["claim"]
        batch_ms = millis(claim.get("at")) or 0
        lines = _events(claim)
        rows = []
        for line in lines:
            row, request = self._event(line, batch_ms)
            if row["a"] not in ("allow", "error"):
                self._verdict(row, request, rfc3339_utc(self.clock_ms() / 1000))
            rows.append(row)
        record = _monitor_ledger.append(self.repo, self.identity, self.stream,
                                        {"id": batch["id"], **claim}, rows, self.key,
                                        threshold=self.config["threshold"],
                                        at=rfc3339_utc(self.clock_ms() / 1000))  # fmt: skip
        self.counts["batches"] += 1
        self.counts["evaluated"] += len(rows)
        return record

    def once(self) -> list[dict[str, Any]]:
        """Evaluate every pending batch; the coverage records written."""
        return [self.batch(b) for b in pending(self.repo, self.stream, self.identity["id"])]

    def heartbeat(self) -> dict[str, Any]:
        row = _monitor_heartbeat.beat(
            self.repo,
            self.identity,
            self.stream,
            self.key,
            at_ms=self.clock_ms(),
            interval_s=self.interval_s,
        )
        self.counts["heartbeats"] += 1
        return row

    def follow(self, stop: threading.Event, *, poll_s: float = 1.0,
               wait: Callable[[float], Any] | None = None) -> dict[str, int]:  # fmt: skip
        """Run until *stop* is set: evaluate, and beat once per interval."""
        wait = wait or stop.wait
        last = None
        while not stop.is_set():
            self.once()
            now = self.clock_ms()
            if last is None or now - last >= self.interval_s * 1000:
                self.heartbeat()
                last = now
            wait(poll_s)
        return dict(self.counts)


def _events(claim: dict[str, Any]) -> list[dict[str, Any]]:
    from opentine import _json_shallow

    text = claim.get("events")
    rows = []
    for line in text.splitlines() if isinstance(text, str) else []:
        row = _json_shallow.loads(line.encode("utf-8"))
        if isinstance(row, dict) and type(row.get("i")) is int:
            rows.append(row)
    return rows


def _refuse(repo: Any, key: Any) -> None:
    from opentine._containment_records import fingerprint
    from opentine._key_roles_pin import pinned

    roles = pinned(repo.path) or {}
    if fingerprint(key) in roles.get("optimizer", []):
        raise _monitor_ledger.LedgerError("an optimizer key may not sign monitor coverage")


__all__ = ["Runner", "pending"]
