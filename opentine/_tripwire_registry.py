"""The tripwire registry (0.91): ``opentine.tripwire-registry/1``, signed and pinned.

A tripwire names a signal, a threshold, a scope and an action. The registry is
a chain of **attestations** (the existing object kind) whose claim is::

    {"convention": "opentine.tripwire-registry/1", "serial": N, "previous": OID | null,
     "tripwires": [{"id", "metric", "op", "threshold", "scope", "action",
                    "decoys": ["sha256:..."]}], "at": RFC3339}

held under ``tripwire:registry:SERIAL`` (never released). Every version
carries the whole list, so adding, editing or removing a tripwire is a new
version whose ``previous`` is the current one. A version counts only when it
is signed by the key that signed it and that key is a pinned ``policy`` key
that is not an ``optimizer`` key (:func:`opentine._key_roles_pin.granting`).

:func:`current` reads every registry claim in the object store, held or not,
so dropping a hold row does not roll the registry back. A version by another
key, a second version with the same serial (a fork), a version that does not
continue the chain, or a head below the pinned ``min_serial`` is a finding,
and the last three leave the registry ``broken``: nothing is evaluated from
it, and under a pinned rule that counts as a missing registry.

The rule is the trust bundle's ``tripwires`` section
(:mod:`opentine._bundle_section`)::

    "tripwires": {"version": 1, "required": true, "min_serial": N}

With ``required`` a registry that is absent, unpinned or broken fails closed
(:mod:`opentine._tripwire_check` issues a stop). Without the section nothing
changes for a repository that registers no tripwires (owner decision D12).
"""

from __future__ import annotations

import math
import re
import time
from typing import Any

from opentine import _containment_records as records

CONVENTION = "opentine.tripwire-registry/1"
HOLD = "tripwire:registry:"
ACTIONS = ("flag", "stop")
OPS = (">=", ">", "<=", "<")
METRICS = ("suspicion.flags", "suspicion.score", "monitor.non-allow", "monitor.events",
           "ingest.events", "decoy.touches")  # fmt: skip
BUDGET_METRIC = re.compile(r"^budget\.(tokens|gpu_hours|wall_clock_s|egress_bytes|money_usd)$")
SCOPE = re.compile(r"^(\*|agent:[A-Za-z0-9._-]{1,64}|(session|stream):[A-Za-z0-9._:-]{1,128}"
                   r"|budget:(loop|agent):[a-z0-9][a-z0-9._-]{0,63})$")  # fmt: skip
ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_WIRES, MAX_DECOYS = 256, 1024
_SECTION = {"version", "required", "min_serial"}


class TripwireError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def section_of(doc: Any) -> dict[str, Any] | None:
    """``{"required", "min_serial"}`` of a bundle ``tripwires`` section; ``None`` if bad."""
    if not isinstance(doc, dict) or doc.get("version") != 1 or set(doc) - _SECTION:
        return None
    required, floor = doc.get("required", False), doc.get("min_serial", 0)
    if type(required) is not bool or type(floor) is not int or floor < 0:
        return None
    return {"required": required, "min_serial": floor}


def rule(repo: Any) -> dict[str, Any]:
    """The pinned rule; an unreadable bundle under a pinned owner requires a registry."""
    from opentine._bundle_section import SectionError, section

    try:
        found = section(getattr(repo, "path", None), "tripwires", section_of)
    except SectionError as exc:
        return {"required": True, "min_serial": 0, "error": str(exc)}
    return {**(found or {"required": False, "min_serial": 0}), "error": None}


def wire(doc: Any) -> dict[str, Any]:
    """One tripwire, normalised; :class:`TripwireError` (``tripwire.invalid``) otherwise."""

    def bad(why: str) -> TripwireError:
        return TripwireError("tripwire.invalid", why)

    keys = {"id", "metric", "op", "threshold", "scope", "action", "decoys"}
    if not isinstance(doc, dict) or set(doc) - keys:
        raise bad(f"a tripwire is an object of {', '.join(sorted(keys))}")
    out = {"id": doc.get("id"), "metric": doc.get("metric"), "op": doc.get("op", ">="),
           "threshold": doc.get("threshold"), "scope": doc.get("scope", "*"),
           "action": doc.get("action", "flag"), "decoys": doc.get("decoys", [])}  # fmt: skip
    if not isinstance(out["id"], str) or not ID.fullmatch(out["id"]):
        raise bad("an id is [a-z0-9._-], 1..64 characters")
    if out["id"] == "registry":
        raise bad("the id registry names the registry itself")
    if out["metric"] not in METRICS and not BUDGET_METRIC.fullmatch(str(out["metric"])):
        raise bad(f"unknown metric {out['metric']!r}: {', '.join(METRICS)} or budget.LIMIT")
    number = out["threshold"]
    if (isinstance(number, bool) or not isinstance(number, (int, float))
            or not math.isfinite(number)):  # fmt: skip
        raise bad("a threshold is a finite number")
    out["threshold"] = float(number)
    if out["op"] not in OPS or out["action"] not in ACTIONS:
        raise bad(f"op is one of {' '.join(OPS)} and action one of {', '.join(ACTIONS)}")
    if not isinstance(out["scope"], str) or not SCOPE.fullmatch(out["scope"]):
        raise bad("a scope is *, agent:ID, session:ID, stream:NAME or budget:loop|agent:NAME")
    budget = str(out["metric"]).startswith("budget.")
    if budget != out["scope"].startswith("budget:") and not (
            budget and out["scope"].startswith("agent:")):  # fmt: skip
        raise bad("a budget metric takes a budget:SUBJECT or agent:ID scope, and only it "
                  "takes budget:")  # fmt: skip
    decoys = out["decoys"]
    if not isinstance(decoys, list) or len(decoys) > MAX_DECOYS or not all(
            isinstance(d, str) and _DIGEST.fullmatch(d) for d in decoys):  # fmt: skip
        raise bad(f"decoys are at most {MAX_DECOYS} sha256:<64 hex> digests")
    if (out["metric"] == "decoy.touches") != bool(decoys):
        raise bad("decoy.touches needs --decoy digests, and only it takes them")
    out["decoys"] = sorted(set(decoys))
    return out


def _wires(claim: dict[str, Any]) -> list[dict[str, Any]] | None:
    rows = claim.get("tripwires")
    try:
        wires = [wire(w) for w in rows] if isinstance(rows, list) else None
    except TripwireError:
        return None
    if wires is None or len(wires) > MAX_WIRES or len({w["id"] for w in wires}) != len(wires):
        return None
    return wires if wires == rows else None


def _finding(code: str, record: str | None, message: str) -> dict[str, Any]:
    return {"level": "fail", "code": f"fail:{code}", "record": record, "message": message}


def current(repo: Any) -> dict[str, Any]:
    """``{"status", "head", "serial", "tripwires", "findings", "rule"}`` of the registry."""
    from opentine._key_roles_pin import granting
    from opentine.repository._holds import holds_path, read_holds

    found = rule(repo)
    allowed, why = granting(repo.path, "policy")
    held = {r["oid"] for r in read_holds(holds_path(repo)) if r["target"].startswith(HOLD)}
    findings, good = [], []
    scanned = records.scan(repo, (CONVENTION,))
    for row in scanned:
        claim = row["claim"]
        if not row["signed"] or row["signer"] not in allowed:
            text = why if row["signed"] else "not signed by its key"
            findings.append(_finding("tripwire.registry-signer", row["oid"], text))
        elif type(claim.get("serial")) is not int or _wires(claim) is None:
            findings.append(_finding("tripwire.registry-invalid", row["oid"], "malformed"))
        else:
            good.append(row)
            if row["oid"] not in held:
                findings.append(_finding("tripwire.registry-unheld", row["oid"],
                                         "a registry version lost its hold row"))  # fmt: skip
    chain, broken = [], False
    for oid in sorted(held - {r["oid"] for r in scanned}):  # deleted: a rollback
        findings.append(_finding("tripwire.registry-missing-version", oid,
                                 "a held registry version is missing from the store"))  # fmt: skip
        broken = True
    by_serial: dict[int, list[dict[str, Any]]] = {}
    for row in good:
        by_serial.setdefault(row["claim"]["serial"], []).append(row)
    for serial in sorted(by_serial):
        rows = by_serial[serial]
        previous = chain[-1]["oid"] if chain else None
        if len(rows) > 1:
            findings += [_finding("tripwire.registry-fork", r["oid"], f"serial {serial} twice")
                         for r in rows]  # fmt: skip
            broken = True
        elif serial != len(chain) + 1 or rows[0]["claim"].get("previous") != previous:
            findings.append(_finding("tripwire.registry-chain", rows[0]["oid"],
                                     "a version that does not continue the chain"))  # fmt: skip
            broken = True
        if broken:
            break
        chain.append(rows[0])
    head = chain[-1] if chain else None
    if head and head["claim"]["serial"] < found["min_serial"]:
        findings.append(_finding("tripwire.registry-rollback", head["oid"],
                                 f"serial {head['claim']['serial']} is below the pinned "
                                 f"min_serial {found['min_serial']}"))  # fmt: skip
        broken = True
    status = "broken" if broken else "ok" if head else "unpinned" if not allowed else "absent"
    if found["error"]:
        status = "broken"
        findings.append(_finding("tripwire.registry-rule", None, found["error"]))
    return {"status": status, "head": head["oid"] if head and not broken else None,
            "serial": head["claim"]["serial"] if head and not broken else None,
            "tripwires": head["claim"]["tripwires"] if head and not broken else [],
            "findings": findings, "rule": found}  # fmt: skip


def write(repo: Any, wires: list[dict[str, Any]], key: Any, *,
          now: float | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign the next version listing *wires*; refused unless the key is a pinned policy key."""
    from opentine._key_roles_pin import granting

    allowed, why = granting(repo.path, "policy")
    signer = records.fingerprint(key)
    if signer not in allowed:
        raise TripwireError("tripwire.registry-signer", f"{signer}: {why}")
    state = current(repo)
    if state["status"] == "broken":
        raise TripwireError("tripwire.registry-broken", "fix the findings of tine tripwire list")
    serial = (state["serial"] or 0) + 1
    claim = {"convention": CONVENTION, "serial": serial, "previous": state["head"],
             "tripwires": sorted((wire(w) for w in wires), key=lambda w: w["id"]),
             "at": records.rfc3339(time.time() if now is None else now)}  # fmt: skip
    if len({w["id"] for w in claim["tripwires"]}) != len(wires) or len(wires) > MAX_WIRES:
        raise TripwireError("tripwire.invalid", f"ids are unique; at most {MAX_WIRES}")
    anchor = records.anchor(repo, "tripwire-registry", "tripwire registry")
    oid = records.record(repo, anchor, claim, key, f"{HOLD}{serial:08d}")
    return {"record": oid, "claim": claim}


__all__ = ["ACTIONS", "CONVENTION", "HOLD", "METRICS", "OPS", "SCOPE", "TripwireError",
           "current", "rule", "section_of", "wire", "write"]  # fmt: skip
