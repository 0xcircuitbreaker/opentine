"""Evaluating tripwires (0.91): ``tine tripwire check``, trips and their stops.

:func:`evaluate` reads the registry (:mod:`opentine._tripwire_registry`) and
each tripwire's signal (:mod:`opentine._tripwire_signals`) at the injected
time ``now_ms``. :func:`record` signs one **trip** per tripwire and registry
version that trips, an attestation (the existing object kind) whose claim is::

    {"convention": "opentine.tripwire-trip/1", "tripwire": WIRE | null,
     "registry": OID | null, "serial": N | null, "value": X | null,
     "evidence": [OID], "action": "flag" | "stop", "stop": OID | null,
     "reason": TEXT, "at": RFC3339}

held under ``tripwire:trip:ID`` (never released) and listed in the oversight
queue as ``tripwire:ATTESTATION``. A ``stop`` action first writes an existing
``opentine.monitor-stop/1`` stop token (:mod:`opentine._monitor_stop`) for the
tripwire's scope (an ``agent:``/``session:`` scope as itself, a stream or
budget scope as ``*``, a ``budget:agent:ID`` scope as ``agent:ID``), and the
trip names it in ``stop``: the gates that honour a stop token honour a trip.

Fail closed: when the pinned rule requires a registry and it is absent,
unpinned or broken, the result is not ok, and :func:`record` writes one trip
with ``tripwire`` null and a ``*`` stop. A trip is signed by a pinned
``monitor``, ``runner`` or ``policy`` key that is not an ``optimizer`` key
(``tripwire.trip-signer``); evaluation without a key reports only.
"""

from __future__ import annotations

import time
from typing import Any

from opentine import _containment_records as records
from opentine import _tripwire_registry as registry
from opentine import _tripwire_signals as signals

CONVENTION = "opentine.tripwire-trip/1"
HOLD = "tripwire:trip:"
SIGNERS = ("monitor", "runner", "policy")
MISSING = "registry"


def evaluate(repo: Any, *, now_ms: int) -> dict[str, Any]:
    state = registry.current(repo)
    rows = []
    for wire in state["tripwires"]:
        try:
            number, evidence = signals.value(repo, wire, now_ms)
            error = None
        except Exception as exc:  # noqa: BLE001 - an unreadable signal trips (fail closed)
            number, evidence, error = None, [], f"{type(exc).__name__}: {exc}"
        hit = error is not None or signals.tripped(wire, number)
        rows.append({**wire, "value": number, "tripped": hit, "evidence": evidence,
                     "error": error})  # fmt: skip
    required = state["rule"]["required"]
    missing = required and state["status"] != "ok"
    findings = list(state["findings"])
    if missing:
        findings.append({"level": "fail", "code": "fail:tripwire.registry-missing",
                         "record": None, "message": f"the pinned rule requires a tripwire "
                         f"registry and it is {state['status']}"})  # fmt: skip
    ok = not findings and not any(r["tripped"] for r in rows)
    return {"registry": {k: state[k] for k in ("status", "head", "serial")},
            "required": required, "missing": missing, "tripwires": rows,
            "findings": findings, "ok": ok}  # fmt: skip


def signers(repo: Any) -> tuple[set[str], str]:
    from opentine._key_roles_pin import granting

    keys: set[str] = set()
    why = ""
    for role in SIGNERS:
        found, why = granting(repo.path, role)
        keys |= found
    return keys, why if not keys else "the signer is not a pinned monitor, runner or policy key"


def trips(repo: Any) -> list[dict[str, Any]]:
    """Every held trip, oldest hold first, with ``counted`` for a pinned signer."""
    allowed, _ = signers(repo)
    out = []
    for target, row in records.held(repo, HOLD):
        claim = row["claim"] or {}
        counted = (row["signed"] and row["signer"] in allowed
                   and claim.get("convention") == CONVENTION)  # fmt: skip
        out.append({**row, "hold": target, "counted": counted})
    return out


def _stop_scope(scope: str) -> str:
    if scope.startswith(("agent:", "session:")):
        return scope
    if scope.startswith("budget:agent:"):
        return scope[len("budget:") :]
    return "*"


def _done(repo: Any, ident: str, head: str | None) -> bool:
    return any(t["counted"] and (t["claim"].get("tripwire") or {}).get("id", MISSING) == ident
               and t["claim"].get("registry") == head for t in trips(repo))  # fmt: skip


def record(repo: Any, result: dict[str, Any], key: Any, *,
           now: float | None = None) -> list[dict[str, Any]]:  # fmt: skip
    """Sign and hold the trips *result* shows that are not recorded yet."""
    from opentine import _monitor_stop

    allowed, why = signers(repo)
    signer = records.fingerprint(key)
    if signer not in allowed:
        raise registry.TripwireError("tripwire.trip-signer", f"{signer}: {why}")
    at = time.time() if now is None else now
    head = result["registry"]["head"]
    todo: list[tuple[dict[str, Any] | None, str]] = []
    if result["missing"]:
        todo.append((None, f"tripwire registry {result['registry']['status']}: fail closed"))
    for row in result["tripwires"]:
        if row["tripped"]:
            detail = (
                row["error"] or f"{row['metric']} = {row['value']} {row['op']} {row['threshold']}"
            )
            todo.append((row, f"tripwire {row['id']}: {detail}"))
    written = []
    for row, reason in todo:
        ident = row["id"] if row else MISSING
        if _done(repo, ident, head):
            continue
        wire = {k: row[k] for k in ("id", "metric", "op", "threshold", "scope", "action",
                                    "decoys")} if row else None  # fmt: skip
        action = wire["action"] if wire else "stop"
        stop = None
        if action == "stop":
            stop = _monitor_stop.stop(repo, _stop_scope(wire["scope"] if wire else "*"), key,
                                      reason=reason[:1024], now=at)  # fmt: skip
        claim = {"convention": CONVENTION, "tripwire": wire, "registry": head,
                 "serial": result["registry"]["serial"], "value": row["value"] if row else None,
                 "evidence": row["evidence"] if row else [], "action": action, "stop": stop,
                 "reason": reason, "at": records.rfc3339(at)}  # fmt: skip
        anchor = records.anchor(repo, "tripwire-trip", reason)
        oid = records.record(repo, anchor, claim, key, HOLD + ident)
        written.append({"record": oid, "tripwire": ident, "action": action, "stop": stop})
    return written


def items(repo: Any) -> list[dict[str, Any]]:
    """``tripwire:TRIP`` oversight items, one per held trip (unsigned ones too)."""
    return [{"item": f"tripwire:{t['oid']}", "source": "tripwire"} for t in trips(repo)]


__all__ = ["CONVENTION", "HOLD", "evaluate", "items", "record", "signers", "trips"]
