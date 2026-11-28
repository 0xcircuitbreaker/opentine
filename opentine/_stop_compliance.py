"""Stop-compliance records: how a halted run actually stopped, signed by the runner.

After a run halts under a stop policy the runner signs an attestation whose
claim follows ``opentine.stop-compliance/1``::

    {"convention": "opentine.stop-compliance/1", "fleet", "run", "code", "stop",
     "stop_issued_at", "requested_at", "halted_at", "time_to_halt_ms",
     "since_stop_ms", "window_s", "watchdog_s", "residual_processes",
     "residual_method", "forwarded_after_stop", "refused_after_stop",
     "compliant"}

``compliant`` holds when the tree was gone within one watchdog interval of the
halt decision, no process of it was left, no action was forwarded after the
halt, and (for a fleet stop) the halt came within the freshness window of the
stop's own time. The record is held, never released, under
``stop-compliance:<run>``. :func:`items` feeds the ``stop`` source of the
oversight queue: every held record that is not compliant, does not verify, or
is not signed by a pinned ``runner`` key (never an ``optimizer`` key) opens
``stop:<oid>``; the queue fails closed on what it cannot read.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

CONVENTION = "opentine.stop-compliance/1"
SOURCE = "stop"


def claim_for(policy: dict[str, Any], run: str, measured: dict[str, Any],
              stop_issued_at: str | None) -> dict[str, Any]:  # fmt: skip
    from opentine._stop_proof import parse_at, rfc3339

    requested = measured["requested_ms"]
    halted = measured["halted_ms"]
    to_halt = max(0, halted - requested)
    issued = parse_at(stop_issued_at)
    since = None if issued is None else max(0, halted - issued)
    compliant = (
        to_halt <= policy["watchdog_s"] * 1000
        and measured["residual_processes"] == 0
        and measured["forwarded_after_stop"] == 0
        and (since is None or since <= policy["window_s"] * 1000)
    )
    return {"convention": CONVENTION, "fleet": policy["fleet"], "run": run,
            "code": measured["code"], "stop": measured["stop"],
            "stop_issued_at": stop_issued_at, "requested_at": rfc3339(requested),
            "halted_at": rfc3339(halted), "time_to_halt_ms": to_halt, "since_stop_ms": since,
            "window_s": policy["window_s"], "watchdog_s": policy["watchdog_s"],
            "residual_processes": measured["residual_processes"],
            "residual_method": measured["residual_method"],
            "forwarded_after_stop": measured["forwarded_after_stop"],
            "refused_after_stop": measured["refused_after_stop"],
            "compliant": compliant}  # fmt: skip


def stop_time(policy: dict[str, Any], store: Path | None, base: Path | None, stop: Any) -> Any:
    """The ``stopped_at`` of the stop entry *stop* in the channel, if it can be read."""
    from opentine import _stop_channel

    if not isinstance(stop, str):
        return None
    channel = Path(policy["channel"])
    channel = channel if channel.is_absolute() or base is None else base / channel
    try:
        snap = _stop_channel.snapshot(channel, policy["fleet"], policy["vkey"])
    except (_stop_channel.ChannelError, ValueError):
        return None
    for entry in snap.entries:
        claim = entry["payload"].get("claim")
        if entry["attestation"] == stop and isinstance(claim, dict):
            return claim.get("stopped_at") if isinstance(claim.get("stopped_at"), str) else None
    return None


def record(repo: Any, claim: dict[str, Any], key: Any) -> str:
    """Sign *claim* with the runner *key*, store and hold it; the attestation id."""
    from opentine._signing_pins import key_fingerprint
    from opentine.graph import Run, StepKind
    from opentine.policies import PolicySet
    from opentine.repository._attest import attest
    from opentine.repository._holds import STOP_COMPLIANCE, hold_row

    run = Run(id=f"stop-compliance-{claim['fleet']}", model_info="opentine/stop-compliance",
              user_prompt=f"halt of {claim['run']}", policies=PolicySet().to_dict())  # fmt: skip
    run.add_step(StepKind.done, {"text": claim["code"]})
    target = repo.put_run(run).run_id
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    oid = attest(repo, target, claim, signer=signer, key=key, algorithm="ed25519")
    hold_row(repo, oid, STOP_COMPLIANCE + claim["run"])
    return oid


def check(repo: Any, oid: str) -> str | None:
    """``None`` for a compliant record by a pinned runner key; otherwise why not."""
    from opentine._key_roles_pin import granting
    from opentine._signing_pins import used_key_fingerprint
    from opentine.attest_signing import verify_attestation

    try:
        payload = repo.get(oid).payload()
    except Exception:  # noqa: BLE001 - an unreadable record is reported, not raised
        return "the record cannot be read"
    claim = payload.get("claim") if isinstance(payload, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        return f"not an {CONVENTION} claim"
    result = verify_attestation(payload, trust_embedded=True)
    if not result.ok or result.algorithm != "ed25519":
        return f"signature {result.state}"
    if used_key_fingerprint(payload.get("signature")) != payload.get("signer"):
        return "the signer field does not name the key that signed"
    keys, why = granting(Path(repo.path), "runner")
    if payload.get("signer") not in keys:
        return why
    if claim.get("compliant") is not True:
        return (f"non-compliant halt: {claim.get('time_to_halt_ms')} ms to halt, "
                f"{claim.get('residual_processes')} residual process(es), "
                f"{claim.get('forwarded_after_stop')} action(s) after the stop")  # fmt: skip
    return None


def held(repo: Any) -> list[str]:
    from opentine.repository._holds import STOP_COMPLIANCE, holds_path, read_holds

    rows = read_holds(holds_path(repo))
    return sorted({r["oid"] for r in rows if r["target"].startswith(STOP_COMPLIANCE)})


def items(repo: Any) -> list[dict[str, Any]]:
    """``[{"item", "source"}]`` for every held record that is not a verified compliant halt."""
    return [{"item": f"{SOURCE}:{oid}", "source": SOURCE}
            for oid in held(repo) if check(repo, oid) is not None]  # fmt: skip


def report(repo: Any) -> list[dict[str, Any]]:
    rows = []
    for oid in held(repo):
        try:
            claim = repo.get(oid).payload().get("claim") or {}
        except Exception:  # noqa: BLE001 - listed with its problem below
            claim = {}
        problem = check(repo, oid)
        rows.append({"record": oid, "run": claim.get("run"), "code": claim.get("code"),
                     "time_to_halt_ms": claim.get("time_to_halt_ms"),
                     "residual_processes": claim.get("residual_processes"),
                     "compliant": problem is None, "problem": problem})  # fmt: skip
    return rows


__all__ = ["CONVENTION", "SOURCE", "check", "claim_for", "held", "items", "record", "report",
           "stop_time"]  # fmt: skip
