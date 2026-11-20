"""Budget policies for loops and agents (0.69): ``opentine-budget-policy/1``.

A budget policy caps what one loop or agent may spend::

    {"schema": "opentine-budget-policy/1", "subject": "loop:opt", "serial": 3,
     "limits": {"tokens": 200000, "gpu_hours": 2.0, "wall_clock_s": 86400,
                "egress_bytes": 1048576, "money_usd": 25.0},
     "on_limit": "deny" | "escalate", "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
     "signature": {tine-sig/3 Ed25519 block, domain opentine.budget-policy.v1:}}

A limit left out (or ``null``) is not capped. The policy reaches the ledger
as a ``policy`` entry (:mod:`opentine._budget_ledger`); the file itself grants
nothing. Whether a policy may take effect is :func:`judge`: the signer is the
key that signed (``used_key_fingerprint``), never an ``optimizer`` key; a
policy that raises or removes any limit needs a ``policy``-role key from the
owner-pinned trust bundle (:mod:`opentine._key_roles_pin`); its serial must
exceed the one in force (no rollback). Lowering a limit needs no role.
"""

from __future__ import annotations

import math
import re
from typing import Any

from opentine import _signed_doc

SCHEMA = "opentine-budget-policy/1"
DOMAIN = b"opentine.budget-policy.v1:"
LIMITS = ("tokens", "gpu_hours", "wall_clock_s", "egress_bytes", "money_usd")
INTEGER = ("tokens", "wall_clock_s", "egress_bytes")
ON_LIMIT = ("deny", "escalate")
SUBJECT = re.compile(r"^(loop|agent):[a-z0-9][a-z0-9._-]{0,63}$")
_KEYS = {"schema", "subject", "serial", "limits", "on_limit", "issued_at", "signature"}


class BudgetError(ValueError):
    """A budget policy or ledger entry that cannot be used."""


def subject(value: Any) -> str:
    if not isinstance(value, str) or not SUBJECT.fullmatch(value):
        raise BudgetError(f"{value!r} is not a budget subject: loop:NAME or agent:NAME "
                          "(lowercase [a-z0-9._-], at most 64)")  # fmt: skip
    return value


def _limit(name: str, value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BudgetError(f"limit {name} is a number")
    if not math.isfinite(value) or value < 0:
        raise BudgetError(f"limit {name} is a finite number >= 0")
    if name in INTEGER and int(value) != value:
        raise BudgetError(f"limit {name} is a whole number")
    return int(value) if name in INTEGER else float(value)


def body(doc: Any) -> dict[str, Any]:
    """The validated, unsigned body of *doc*."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or set(doc) - _KEYS:
        raise BudgetError(f"not a {SCHEMA} document")
    limits = doc.get("limits")
    if not isinstance(limits, dict) or set(limits) - set(LIMITS):
        raise BudgetError(f"limits is an object of {', '.join(LIMITS)}")
    serial = doc.get("serial")
    if isinstance(serial, bool) or not isinstance(serial, int) or serial < 1:
        raise BudgetError("serial is a whole number >= 1")
    if doc.get("on_limit") not in ON_LIMIT:
        raise BudgetError("on_limit is deny or escalate")
    if not isinstance(doc.get("issued_at"), str):
        raise BudgetError("issued_at is an RFC 3339 time")
    return {"schema": SCHEMA, "subject": subject(doc.get("subject")), "serial": serial,
            "limits": {n: _limit(n, limits.get(n)) for n in LIMITS},
            "on_limit": doc["on_limit"], "issued_at": doc["issued_at"]}  # fmt: skip


def build(subject_: str, limits: dict[str, Any], *, serial: int, on_limit: str,
          issued_at: str) -> dict[str, Any]:  # fmt: skip
    return body({"schema": SCHEMA, "subject": subject_, "serial": serial, "limits": limits,
                 "on_limit": on_limit, "issued_at": issued_at})  # fmt: skip


def sign(doc: dict[str, Any], key: Any) -> dict[str, Any]:
    clean = body(doc)
    return {
        **clean,
        "signature": _signed_doc.sign(DOMAIN, clean, key, signed_at=clean["issued_at"]),
    }


def signer(doc: Any) -> str | None:
    """The fingerprint of the key that signed *doc*, or ``None`` when it does not verify."""
    from opentine._signing_pins import used_key_fingerprint

    try:
        clean = body(doc)
    except BudgetError:
        return None
    block = doc.get("signature")
    if not isinstance(block, dict) or not _signed_doc.verify(DOMAIN, clean, block).ok:
        return None
    return used_key_fingerprint(block)


def digest(doc: dict[str, Any]) -> str:
    import hashlib

    from opentine.kernel import canonical_json

    return "sha256:" + hashlib.sha256(canonical_json(body(doc))).hexdigest()


def raises(old: dict[str, Any] | None, new: dict[str, Any]) -> list[str]:
    """The limits *new* raises or removes relative to *old* (all set ones for a first policy)."""
    if old is None:
        return [n for n in LIMITS if new.get(n) is not None]
    out = []
    for name in LIMITS:
        before, after = old.get(name), new.get(name)
        if before is not None and (after is None or after > before):
            out.append(name)
    return out


def judge(doc: Any, current: dict[str, Any] | None, roles: dict[str, Any],
          owner_serial: int = 0) -> str | None:  # fmt: skip
    """``None`` when *doc* may take effect over *current*; else the violation code.

    *roles* is :func:`opentine._key_roles_pin.resolve`'s answer. A first policy
    needs no role (it only caps what was uncapped) unless it is signed by an
    optimizer key. A pinned ``policy`` key's serial is checked against
    *owner_serial* (the highest serial a pinned policy key put in force), so a
    policy from any other key, however high its serial, cannot lock it out.
    """
    who = signer(doc)
    if who is None:
        return "budget.policy-unsigned"
    held = roles.get("roles") or {}
    if who in held.get("optimizer", []):
        return "budget.policy-optimizer-key"
    clean = body(doc)
    pinned = held.get("policy", []) if roles.get("status") == "pinned" else []
    floor = owner_serial if who in pinned else (current or {}).get("serial", 0)
    if clean["serial"] <= floor:
        return "budget.policy-rollback"
    if current is None or not raises(current["limits"], clean["limits"]):
        return None
    return None if who in pinned else "budget.limit-raise"


__all__ = ["BudgetError", "DOMAIN", "INTEGER", "LIMITS", "ON_LIMIT", "SCHEMA", "body", "build",
           "digest", "judge", "raises", "sign", "signer", "subject"]  # fmt: skip
