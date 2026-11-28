"""Monitor coverage at promotion (0.90): the candidate's actions were watched.

``tine promote`` reads the monitor coverage ledger (:mod:`opentine._monitor_coverage`)
for the candidate run. The candidate's events are the captured ingest events
whose ``run`` names the candidate (``run:sha256:HEX``, ``sha256:HEX`` or
``HEX``, after NFKC and case folding), in every held ingest stream; the run's
time window runs from the first to the last batch holding one (ingest time,
both ends included). For
each required monitor, every such event must be:

* covered: evaluated (not errored) by a record that verifies, signed by a key
  the trust bundle binds to that monitor (:mod:`opentine._monitor_binding`),
  in a ledger with no unsigned, broken or forged record and no stray heartbeat;
* scored under one monitor config and threshold that has a validated operating
  point (:mod:`opentine._monitor_validation`) for that exact config digest;
* inside a live window: a heartbeat of that config at or before the window's
  start and no stale stretch (three missed intervals) touching it.

Required monitors are the trust bundle's ``monitors.required`` (a pinned rule:
always refused) plus ``required_monitors`` in ``[promote]``. ``monitor_coverage
= "required"`` (on, and not removable, under ``profile = "rsi"``) refuses a gap
with ``promote.monitor-coverage``; ``"advisory"`` (default, owner decision D12)
reports ``advisory:promote.monitor-coverage``. With no required monitor nothing
changes. The time checked is the window's end, never the wall clock.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MODES = ("advisory", "required")
CODE = "promote.monitor-coverage"
_SOFT = ("stale", "coverage-gap", "config-changed", "unvalidated-threshold", "latency-slo",
         "heartbeat-future")  # fmt: skip


def check_policy(policy: dict[str, Any]) -> None:
    """Settle ``monitor_coverage`` and ``required_monitors`` in a ``[promote]`` table."""
    from opentine._monitor_ledger import MONITOR_ID

    rsi = policy.get("profile") == "rsi"
    mode = policy.get("monitor_coverage", "required" if rsi else "advisory")
    if mode not in MODES or (rsi and mode != "required"):
        raise ValueError('monitor_coverage is "advisory" or "required"; the rsi profile '
                         "requires it")  # fmt: skip
    names = policy.get("required_monitors", [])
    if not isinstance(names, list) or not all(isinstance(n, str) and MONITOR_ID.fullmatch(n)
                                              for n in names):  # fmt: skip
        raise ValueError("required_monitors lists monitor ids")
    policy["monitor_coverage"], policy["required_monitors"] = mode, sorted(set(names))


def _norm(value: Any) -> str | None:
    import unicodedata

    if not isinstance(value, str):
        return None
    text = unicodedata.normalize("NFKC", value).strip().casefold()
    return text.removeprefix("run:").removeprefix("sha256:")


def windows(repo: Any, candidate: str) -> dict[str, tuple[set[int], int, int]]:
    """``{stream: (the candidate's captured indices, window start ms, end ms)}``."""
    from opentine import _ingest_batch, _ingest_holds
    from opentine._monitor_heartbeat import millis
    from opentine._monitor_ledger import walk
    from opentine._monitor_runner import _events

    run, out = _norm(candidate), {}
    for stream in _ingest_holds.streams(repo):
        batches, _ = walk(repo, _ingest_holds.head(repo, stream), _ingest_batch.CONVENTION)
        indices: set[int] = set()
        times: list[int] = []
        for batch in batches:
            mine = {e["i"] for e in _events(batch["claim"]) if isinstance(e.get("e"), dict)
                    and _norm(e["e"].get("run")) == run}  # fmt: skip
            if mine:
                indices |= mine
                times.append(millis(batch["claim"].get("at")) or 0)  # unreadable: from 0
        if indices:
            out[stream] = (indices, min(times), max(times))
    return out


def _stale(beats: dict[str, Any], start: int, end: int) -> bool:
    if beats["first_ms"] is None or beats["first_ms"] > start:
        return True  # not known alive when the run's first batch arrived
    for w in beats["stale_windows"]:
        trailing = w["to"] == end and beats["last_ms"] != end
        if (w["from"] is None or w["from"] < end) and (w["to"] > start or trailing):
            return True
    return False


def gaps(repo: Any, monitor: str, stream: str, indices: set[int], start: int,
         end: int) -> list[str]:  # fmt: skip
    """Why *monitor*'s coverage of *indices* on *stream* does not count (empty: it does)."""
    from opentine import _monitor_coverage, _monitor_ledger

    seen: dict[int, set[tuple[str, str, float]]] = {}
    for record in _monitor_ledger.records(repo, monitor, stream)[0]:
        claim = record["claim"]
        ident = claim.get("monitor") if isinstance(claim.get("monitor"), dict) else {}
        for line in _monitor_ledger.decode(claim.get("events")) or []:
            if line["i"] in indices and line["a"] != "error":
                seen.setdefault(line["i"], set()).add((str(ident.get("kind")),
                    str(ident.get("config_digest")), repr(claim.get("threshold"))))  # fmt: skip
    missing = sorted(indices - set(seen))
    if missing:
        return [f"{len(missing)} of the candidate's {len(indices)} captured event(s) on "
                f"{stream} were not evaluated by {monitor}"]  # fmt: skip
    configs = set().union(*seen.values())
    if len(configs) != 1:
        return [f"{monitor} scored the candidate on {stream} under {len(configs)} configs"]
    kind, config, threshold = next(iter(configs))
    ident = {"id": monitor, "kind": kind, "config_digest": config}
    try:
        body = _monitor_coverage.report(repo, stream, ident, now_ms=end, profile="rsi",
                                        threshold=float(threshold))  # fmt: skip
    except (ValueError, KeyError, TypeError) as exc:
        return [f"{monitor} on {stream}: its ledger does not read ({exc})"]
    out = [f"{monitor} on {stream}: {f['code']} {f['message']}" for f in body["findings"]
           if f["level"] == "fail" and f["code"].split(".", 1)[1] not in _SOFT]  # fmt: skip
    if body["operating_point"] is None:
        out.append(f"{monitor} config {config} at threshold {threshold} has no validated "
                   "operating point")  # fmt: skip
    if _stale(body["heartbeats"], start, end):
        out.append(f"{monitor} on {stream} was stale during the candidate's window")
    return out


def findings(policy: dict[str, Any], repo_path: Path | None,
             candidate: str) -> tuple[list, list]:  # fmt: skip
    """``(refusals, advisories)`` of the candidate's monitor coverage."""
    from opentine._monitor_binding import BindingError, required
    from opentine._promote_checks import refusal
    from opentine._promote_judges import _repo

    repo = _repo(repo_path)
    try:
        pinned = set(required(repo)) if repo is not None else set()
    except BindingError as exc:  # a pinned owner's bundle that does not read: fail closed
        return [refusal(CODE, f"the required monitors cannot be read ({exc})")], []
    wanted = pinned | set(policy.get("required_monitors", []))
    if not wanted:
        return [], []
    hard = policy.get("monitor_coverage") == "required"
    if repo is None:  # nothing is pinned without a repository, so only the policy asks
        detail = "no repository to read the monitor coverage ledger from"
        if hard:
            return [refusal(CODE, detail)], []
        return [], [{"code": f"advisory:{CODE}", "detail": detail}]
    found = windows(repo, candidate)
    refusals, advisories = [], []
    for monitor in sorted(wanted):
        problems = [f"no captured ingest event names {candidate}"] if not found else []
        for stream, (indices, start, end) in sorted(found.items()):
            problems += gaps(repo, monitor, stream, indices, start, end)
        for detail in problems:
            if hard or monitor in pinned:
                refusals.append(refusal(CODE, detail))
            else:
                advisories.append({"code": f"advisory:{CODE}", "detail": detail})
    return refusals, advisories


__all__ = ["CODE", "MODES", "check_policy", "findings", "gaps", "windows"]
