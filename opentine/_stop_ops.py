"""Publishing fleet stops and continue proofs to a stop channel, and reading its status.

The issuer side of :mod:`opentine._stop_guard`: ``tine stop issue`` and
``tine stop continue`` sign a claim (:mod:`opentine._stop_proof`) with a pinned
``stopper`` or ``policy`` key, store it as an attestation in the issuer's
repository and append it to the channel log. A key that is not such a key is
refused before anything is written, and an optimizer key never is one. A fleet
stop is also held in the issuer's repository (``fleet-stop:<fleet>``), and there
is no un-stop: a stopped fleet restarts under a new fleet id.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _stop_channel, _stop_proof


def _signer_allowed(repo: Any, key: Any) -> None:
    from opentine._signing_pins import key_fingerprint

    keys, refusal = _stop_proof.authorities(Path(repo.path))
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    if signer not in keys:
        raise ValueError(f"{signer}: {refusal}; stops and continue proofs are signed by a "
                         "pinned stopper or policy key")  # fmt: skip


def _current(channel: Path, fleet: str) -> tuple[str, _stop_channel.Snapshot]:
    from opentine.repository._tlog_note import stored_vkey

    try:
        vkey = stored_vkey(Path(channel))
    except ValueError as exc:
        raise _stop_channel.ChannelError(f"no stop channel at {Path(channel).as_posix()}: "
                                         f"{exc}") from exc  # fmt: skip
    return vkey, _stop_channel.snapshot(channel, fleet, vkey)


def issue_stop(repo: Any, channel: Path, fleet: str, key: Any, *, reason: str,
               now_ms: int) -> dict[str, Any]:  # fmt: skip
    """Sign and publish a fleet stop; the entry's summary."""
    from opentine.repository._holds import FLEET_STOP, hold_row

    _signer_allowed(repo, key)
    vkey, snap = _current(channel, fleet)
    claim = _stop_proof.stop_claim(fleet, reason, _stop_proof.rfc3339(now_ms), vkey,
                                   snap.checkpoint())  # fmt: skip
    oid, payload = _stop_proof.sign(repo, claim, key, "stop")
    hold_row(repo, oid, FLEET_STOP + fleet)  # first: a lost append still leaves the record
    index = _stop_channel.append(channel, fleet, "stop", oid, payload)
    return {"kind": "stop", "attestation": oid, "index": index, "signer": payload["signer"],
            "claim": claim}  # fmt: skip


def issue_continue(repo: Any, channel: Path, fleet: str, runs: list[str], key: Any, *,
                   window_s: int, now_ms: int) -> list[dict[str, Any]]:  # fmt: skip
    """Sign and publish one continue proof per run (refused once the fleet is stopped)."""
    _signer_allowed(repo, key)
    rows = []
    for run in runs:
        vkey, snap = _current(channel, fleet)
        if any(e["kind"] == "stop" for e in snap.entries):
            raise ValueError(f"fleet {fleet} is stopped: no continue proof can be issued")
        seq = 1 + max((e["payload"]["claim"].get("seq", 0) for e in snap.entries
                       if e["kind"] == "continue" and isinstance(e["payload"].get("claim"), dict)
                       and e["payload"]["claim"].get("run") == run
                       and type(e["payload"]["claim"].get("seq")) is int), default=0)  # fmt: skip
        claim = _stop_proof.continue_claim(fleet, run, seq, _stop_proof.rfc3339(now_ms),
                                           window_s, vkey, snap.checkpoint())  # fmt: skip
        oid, payload = _stop_proof.sign(repo, claim, key, "continue")
        index = _stop_channel.append(channel, fleet, "continue", oid, payload)
        rows.append({"kind": "continue", "attestation": oid, "index": index,
                     "signer": payload["signer"], "claim": claim})  # fmt: skip
    return rows


def status(repo: Any, policy: dict[str, Any], run: str | None, now_ms: int) -> dict[str, Any]:
    """What a runner of *run* would decide now, plus the channel's stops and runs."""
    from opentine._stop_guard import Halt, StopGuard

    body: dict[str, Any] = {"fleet": policy["fleet"], "channel": policy["channel"],
                            "window_s": policy["window_s"], "run": run, "ok": False,
                            "code": None, "message": None, "proof": None, "stops": [],
                            "runs": []}  # fmt: skip
    base = Path(repo.path).parent
    channel = Path(policy["channel"])
    channel = channel if channel.is_absolute() else base / channel
    try:
        snap = _stop_channel.snapshot(channel, policy["fleet"], policy["vkey"])
        body["checkpoint"] = snap.checkpoint()
        body["stops"] = [e["attestation"] for e in snap.entries if e["kind"] == "stop"]
        body["runs"] = sorted({e["payload"]["claim"].get("run") for e in snap.entries
                               if e["kind"] == "continue"
                               and isinstance(e["payload"].get("claim"), dict)
                               and isinstance(e["payload"]["claim"].get("run"), str)})  # fmt: skip
    except (_stop_channel.ChannelError, ValueError) as exc:
        body["checkpoint"] = None
        body.update(code="stop.channel-unreachable", message=str(exc))
        return body
    if run is None:
        body.update(ok=not body["stops"], code="stop.stopped" if body["stops"] else None)
        return body
    guard = StopGuard(policy, Path(repo.path), run, base=base, clock_ms=lambda: now_ms)
    try:
        body.update(ok=True, proof=guard.check())
    except Halt as halt:
        body.update(code=halt.code, message=halt.message)
    return body


__all__ = ["issue_continue", "issue_stop", "status"]
