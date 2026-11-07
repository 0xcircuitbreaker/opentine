"""Key lifecycle (0.41, X23): ``not_before``, ``not_after`` and ``revoked_at``.

A key is named by its fingerprint (``sha256:<hex>`` of the raw Ed25519 public
key), so one rule covers local signing keys, agent keys and the 0.39 proxy key.
Windows come from three places, merged most-restrictive-first:

* ``$XDG_CONFIG_HOME/opentine/key-lifecycle.json`` -- user-scoped, written by
  ``tine key rotate`` and ``tine key revoke``; refused when it is a symlink.
* a *trusted* ``.tine/agents.toml``:
  ``[agents.NAME.lifecycle."sha256:<hex>"] not_after = "2026-01-01T00:00:00Z"``.
* a trust policy's ``key_lifecycle`` table (``{fingerprint: {field: time}}``).

:func:`evaluate` judges a window against the *verified* signing time (the
genTime of a signature-bound RFC 3161 token, 0.39). Without one the verdict is
the explicit ``unverified time`` state, and a revoked key fails closed: the
signer's own ``signed_at`` claim cannot move a signature before a revocation.
"""

from __future__ import annotations

import json
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._agent_keys import _config_home, _raw, trusted
from opentine._canon import atomic_write_text
from opentine._signing_pins import normalize_pin

FILE_NAME = "key-lifecycle.json"
TIMES = ("not_before", "not_after", "revoked_at")
EXTRA = ("successor", "predecessor", "endorsement")
MAX_BYTES = 1 << 20


def parse_time(value: Any, what: str = "time") -> datetime:
    """An RFC 3339 instant with a zone (``Z`` or an offset), as UTC."""
    if not isinstance(value, str):
        raise ValueError(f"{what} must be an RFC 3339 time")
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{what} {value!r} is not an RFC 3339 time") from None
    if when.tzinfo is None:
        raise ValueError(f"{what} {value!r} has no time zone")
    return when.astimezone(UTC)


def stamp(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_entry(fpr: Any, entry: Any) -> tuple[str, dict[str, Any]]:
    """A validated ``(fingerprint, entry)``; ``ValueError`` names the flaw."""
    fpr = normalize_pin(str(fpr))
    if not isinstance(entry, dict) or set(entry) - {*TIMES, *EXTRA}:
        raise ValueError(f"lifecycle of {fpr}: fields are {', '.join((*TIMES, *EXTRA))}")
    for name in TIMES:
        if name in entry:
            parse_time(entry[name], f"{fpr} {name}")
    return fpr, dict(entry)


def check_table(table: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(table, dict):
        raise ValueError("key lifecycle must be a table of fingerprints")
    return dict(check_entry(fpr, entry) for fpr, entry in table.items())


def registry_path() -> Path:
    return _config_home() / FILE_NAME


def load_registry() -> dict[str, dict[str, Any]]:
    path = registry_path()
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; refusing it")
    try:
        raw = path.read_bytes()[: MAX_BYTES + 1]
    except FileNotFoundError:
        return {}
    if len(raw) > MAX_BYTES:
        raise ValueError(f"{FILE_NAME} exceeds {MAX_BYTES} bytes")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{FILE_NAME} is malformed: {exc}") from None
    return check_table((data or {}).get("keys", {}) if isinstance(data, dict) else None)


def save_registry(table: dict[str, dict[str, Any]]) -> None:
    path = registry_path()
    if path.is_symlink():
        raise ValueError(f"{path} is a symlink; refusing it")
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"schema": "tine-key-lifecycle/1", "keys": check_table(table)}
    atomic_write_text(path, json.dumps(document, indent=2, sort_keys=True) + "\n", mode=0o600)


def update_registry(fpr: str, **fields: Any) -> dict[str, Any]:
    """Merge *fields* into the entry for *fpr* and save; returns the new entry."""
    table = load_registry()
    fpr, entry = check_entry(fpr, {**table.get(normalize_pin(fpr), {}), **fields})
    table[fpr] = entry
    save_registry(table)
    return entry


def agent_lifecycle(base: Path | None) -> dict[str, dict[str, Any]]:
    """Lifecycle tables of a *trusted* agents.toml, merged across agents."""
    if base is None or not trusted(base):
        return {}
    try:
        agents = tomllib.loads(_raw(base).decode("utf-8")).get("agents", {})
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, ValueError):
        return {}
    merged: dict[str, dict[str, Any]] = {}
    for entry in agents.values() if isinstance(agents, dict) else ():
        table = entry.get("lifecycle", {}) if isinstance(entry, dict) else {}
        for fpr, window in check_table(table).items():
            merged[fpr] = _strictest(merged.get(fpr), window)
    return merged


def _strictest(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(a or {})
    for name in TIMES:
        values = [parse_time(x[name]) for x in (a, b) if x and name in x]
        if values:
            pick = max(values) if name == "not_before" else min(values)
            out[name] = stamp(pick)
    for name in EXTRA:
        if b and name in b:
            out[name] = b[name]
    return out


def lifecycle_for(fpr: str | None, *sources: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """The merged window for *fpr*, or ``None`` when no source names it."""
    if not fpr:
        return None
    found = [table[fpr] for table in sources if table and fpr in table]
    if not found:
        return None
    merged: dict[str, Any] | None = None
    for window in found:
        merged = _strictest(merged, window)
    return merged


def evaluate(
    window: dict[str, Any], verified: str | None, claimed: str | None = None
) -> tuple[str, str, str]:
    """``(outcome, reason, detail)`` of a signature under *window*.

    *verified* is the verified signing time; *claimed* the signer's own
    ``signed_at``, used only to fail, never to pass.
    """
    revoked = window.get("revoked_at")
    when = parse_time(verified) if verified else None
    basis = "verified signing time" if when else "claimed signing time (unverified)"
    if when is None:
        if revoked:
            detail = f"key revoked at {revoked}; no verified signing time shows it signed earlier"
            return "fail", "lifecycle.revoked-unverified-time", detail
        when = parse_time(claimed) if claimed else None
    if when is not None:
        if revoked and when >= parse_time(revoked):
            return "fail", "lifecycle.revoked", f"{basis} {stamp(when)} >= revoked_at {revoked}"
        if window.get("not_after") and when > parse_time(window["not_after"]):
            detail = f"{basis} {stamp(when)} is after not_after {window['not_after']}"
            return "fail", "lifecycle.expired", detail
        if window.get("not_before") and when < parse_time(window["not_before"]):
            detail = f"{basis} {stamp(when)} is before not_before {window['not_before']}"
            return "fail", "lifecycle.not-yet-valid", detail
    if verified:
        return "pass", "lifecycle.valid", f"verified signing time {verified} is inside the window"
    detail = "unverified time: attach a signature-bound timestamp to check the key's window"
    return "unavailable-offline", "lifecycle.unverified-time", detail


__all__ = [
    "TIMES",
    "agent_lifecycle",
    "check_table",
    "evaluate",
    "lifecycle_for",
    "load_registry",
    "parse_time",
    "registry_path",
    "save_registry",
    "stamp",
    "update_registry",
]
