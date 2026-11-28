"""Shared helpers for the 0.91 tripwire tests (built on tests.monitor_ledger_helpers)."""

from __future__ import annotations

import hashlib

from tests.key_roles_helpers import pin_roles
from tests.monitor_ledger_helpers import fpr


def pin_rule(repo, tripwires: dict | None = None, custody: dict | None = None) -> None:
    """Re-sign the bundle with the monitor binding of the fixture and the given rules."""
    extra: dict = {"monitors": {"version": 1, "signers": {"rules": [fpr("monitor")]}}}
    if tripwires is not None:
        extra["tripwires"] = tripwires
    if custody is not None:
        extra["custody"] = custody
    pin_roles(repo.path, extra=extra)


def wire(ident: str, **fields) -> dict:
    out = {"id": ident, "metric": "suspicion.flags", "op": ">=", "threshold": 1.0, "scope": "*",
           "action": "flag", "decoys": []}  # fmt: skip
    out.update(fields)
    return out


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = ["digest", "pin_rule", "wire"]
