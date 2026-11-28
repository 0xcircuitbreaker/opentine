"""``tine monitor coverage``: what fraction of captured events a monitor evaluated.

The denominator is the stream's captured events: every index the ingest
batches (:mod:`opentine._ingest_batch`) store. Coverage is therefore of
*captured* actions; an action never ingested stays invisible. The numerator is
the indices the monitor's verified coverage records
(:mod:`opentine._monitor_ledger`) evaluated, so coverage is exact: ``covered``
is ``"E/C"`` and ``percent`` is that fraction to four decimals.

Facts about records are ``fail:`` findings in every profile: a record not
signed by a pinned ``monitor`` key that is not an ``optimizer`` key
(``monitor.coverage-unsigned``), a broken chain (``monitor.coverage-chain``),
or a record that names a batch the stream does not hold, an index the batch
did not capture, or digests and counts that do not match its events
(``monitor.coverage-forged``). Everything else is advisory by default (owner
decision D12) and a ``fail:`` under ``--profile rsi``: uncovered captured
events (``monitor.coverage-gap``), a changed monitor config
(``monitor.config-changed``), a stale or missing heartbeat
(``monitor.stale``, :mod:`opentine._monitor_heartbeat`), a missed verdict
latency SLO (``monitor.latency-slo``), and a monitor whose config digest and
threshold have no validated operating point (``monitor.unvalidated-threshold``,
:mod:`opentine._monitor_validation`). Under ``rsi`` an unvalidated monitor
counts as no coverage at all.
"""

from __future__ import annotations

import hashlib
from typing import Any

from opentine import _ingest_batch, _ingest_holds, _monitor_heartbeat, _monitor_ledger
from opentine._monitor_runner import _events
from opentine._monitor_validation import operating_point

PROFILES = ("default", "rsi")
MAX_GAPS = 100


def _finding(level: str, code: str, record: str | None, message: str) -> dict[str, Any]:
    return {"level": level, "code": f"{level}:monitor.{code}", "record": record,
            "message": message}  # fmt: skip


def _ranges(indices: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for i in indices:
        if out and out[-1][1] == i - 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def _forged(record: dict[str, Any], batch: dict[str, Any] | None, lines: Any) -> str | None:
    claim = record["claim"]
    if batch is None or batch["claim"].get("seq") != claim.get("batch_seq"):
        return "names a batch the stream does not hold"
    if lines is None:
        return "its events are not well formed"
    text = claim.get("events") if isinstance(claim.get("events"), str) else ""
    if "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest() != claim.get("events_sha256"):
        return "events_sha256 does not match its events"
    by_action = dict.fromkeys(_monitor_ledger.OUTCOMES, 0)
    for line in lines:
        by_action[line["a"]] += 1
    if claim.get("evaluated") != len(lines) or claim.get("by_action") != by_action:
        return "its counts do not match its events"
    captured = {e["i"] for e in _events(batch["claim"])}
    indices = [line["i"] for line in lines]
    if len(set(indices)) != len(indices) or not set(indices) <= captured:
        return "evaluates an index the batch did not capture, or one twice"
    return None


def report(repo: Any, stream: str, identity: dict[str, Any], *, now_ms: int,
           profile: str = "default", threshold: float | None = None) -> dict[str, Any]:  # fmt: skip
    """The coverage of one monitor (``{"id", "kind", "config_digest"}``) on *stream*."""
    from opentine._monitor_verdict import monitors

    if profile not in PROFILES:
        raise ValueError(f"profile is one of {', '.join(PROFILES)}")
    gating = profile == "rsi"
    soft = "fail" if gating else "advisory"
    keys, why = monitors(repo)
    batches, problems = _monitor_ledger.walk(repo, _ingest_holds.head(repo, stream),
                                             _ingest_batch.CONVENTION)  # fmt: skip
    findings = [_finding("fail", "coverage-chain", None, f"ingest: {p}") for p in problems]
    captured: dict[int, str] = {}
    for batch in batches:
        captured.update({e["i"]: batch["id"] for e in _events(batch["claim"])})
    by_id = {b["id"]: b for b in batches}
    records, problems = _monitor_ledger.records(repo, identity["id"], stream)
    findings += [_finding("fail", "coverage-chain", None, p) for p in problems]
    evaluated: set[int] = set()
    digests, slo_missed = [], 0
    for record in records:
        claim, oid = record["claim"], record["id"]
        if not record["signed"] or record["signer"] not in keys:
            findings.append(_finding("fail", "coverage-unsigned", oid, why))
            continue
        lines = _monitor_ledger.decode(claim.get("events"))
        bad = _forged(record, by_id.get(claim.get("batch")), lines)
        if bad:
            findings.append(_finding("fail", "coverage-forged", oid, bad))
            continue
        digest = (claim.get("monitor") or {}).get("config_digest")
        if digests and digest != digests[-1]:
            findings.append(_finding(soft, "config-changed", oid,
                                     f"config {digests[-1]} became {digest}"))  # fmt: skip
        digests.append(digest)
        if not (claim.get("latency") or {}).get("met", False):
            slo_missed += 1
        evaluated |= {line["i"] for line in lines or []}
    if digests and digests[-1] != identity["config_digest"]:
        findings.append(_finding(soft, "config-changed", None,
                                 "the ledger was written by another config than the one "
                                 "checked"))  # fmt: skip
    if slo_missed:
        findings.append(_finding(soft, "latency-slo", None,
                                 f"{slo_missed} record(s) missed the p95 verdict latency SLO "
                                 f"of {_monitor_ledger.SLO_MS} ms"))  # fmt: skip
    beats = _monitor_heartbeat.check(repo, identity, stream, batches, now_ms=now_ms, keys=keys,
                                     gating=gating)  # fmt: skip
    findings += beats.pop("findings")
    point, reasons = (None, ["no threshold given"]) if threshold is None else operating_point(
        repo, identity, threshold)  # fmt: skip
    if point is None:
        findings.append(_finding(soft, "unvalidated-threshold", None,
                                 "no validated operating point for this config and threshold"
                                 + (f" ({'; '.join(reasons)})" if reasons else "")))  # fmt: skip
    counted = point is not None or not gating
    covered = len(evaluated & set(captured)) if counted else 0
    missing = sorted(set(captured) - evaluated)
    if missing:
        findings.append(
            _finding(
                soft, "coverage-gap", None, f"{len(missing)} captured event(s) were not evaluated"
            )
        )
    total = len(captured)
    percent = f"{covered * 1_000_000 // total / 10_000:.4f}" if total else None
    return {"stream": stream, "monitor": identity, "captured": total, "evaluated": covered,
            "covered": f"{covered}/{total}", "percent": percent, "counts_as_coverage": counted,
            "operating_point": point["oid"] if point else None, "records": len(records),
            "gaps": _ranges(missing)[:MAX_GAPS], "heartbeats": beats,
            "findings": findings, "profile": profile}  # fmt: skip


__all__ = ["PROFILES", "report"]
