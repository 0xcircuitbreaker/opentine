"""Storage-only object forms inside a version-3 pack (SPEC 2.8, "Pack v3").

A v3 pack may hold an object in one of three stored forms. All of them are
rebuilt to the object's canonical envelope bytes on read, and the caller checks
those bytes against the object id before returning them, so a stored form can
make an object unreadable but never make it read as different bytes:

* ``FULL`` (0): the canonical envelope itself.
* ``RUN_DELTA`` (1): a run snapshot as its header line plus a delta
  ``{"append","drop","set"}`` against its base, the run stored just before it
  in the same block (so the base costs no bytes and a chain cannot loop). The
  recorder writes one snapshot per append, each listing every event so far, so
  storing the parent plus the newly appended events removes the quadratic part.
* ``EVENT_SLIM`` (2): an event whose fields that hold their default value
  (``EVENT_DEFAULTS``) are left out; a reader puts them back.

Writers choose a form only after rebuilding it and comparing the bytes; any
object whose body is not already in canonical form stays ``FULL``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine.kernel import KernelError, canonical_json, validate_json_shape

FULL, RUN_DELTA, EVENT_SLIM = 0, 1, 2
ENCODINGS = (FULL, RUN_DELTA, EVENT_SLIM)
#: A reader resolves at most this many deltas for one object (writers stay below).
MAX_DELTA_DEPTH = 64
#: A writer starts a fresh full snapshot after this many deltas in a row.
KEYFRAME_INTERVAL = 32
MAX_BODY_TOKENS = 4_000_000
EVENT_DEFAULTS: dict[str, Any] = {
    "actor": "",
    "attributes": {},
    "billing": {},
    "causal_ids": [],
    "cost": 0,
    "duration": 0,
    "parent_ids": [],
    "usage": {},
}
_DELTA_KEYS = frozenset({"append", "drop", "set"})


def split(raw: bytes) -> tuple[bytes, bytes]:
    header, sep, body = raw.partition(b"\n")
    if not sep or len(header) > 256:
        raise KernelError("stored object has no envelope header")
    return header, body


def _parse(body: bytes) -> Any:
    try:
        validate_json_shape(body, max_tokens=MAX_BODY_TOKENS)
        return json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise KernelError("stored object body is not JSON") from exc


def _object(body: bytes) -> dict[str, Any]:
    value = _parse(body)
    if not isinstance(value, dict):
        raise KernelError("stored object body is not a JSON object")
    return value


# --- event slim ------------------------------------------------------------


def slim_event(raw: bytes) -> bytes | None:
    """The ``EVENT_SLIM`` form of *raw*, or ``None`` when it would not round-trip."""
    try:
        header, body = split(raw)
        value = _object(body)
    except KernelError:
        return None
    if any(key not in value for key in EVENT_DEFAULTS):
        return None  # a reader would add a key the original lacks
    kept = {k: v for k, v in value.items() if not _is_default(k, v)}
    if len(kept) == len(value):
        return None
    stored = header + b"\n" + canonical_json(kept)
    return stored if unslim_event(stored) == raw else None


def _is_default(key: str, value: Any) -> bool:
    default = EVENT_DEFAULTS.get(key, _MISSING)
    return default is not _MISSING and type(value) is type(default) and value == default


_MISSING = object()


def unslim_event(stored: bytes) -> bytes:
    header, body = split(stored)
    value = _object(body)
    for key, default in EVENT_DEFAULTS.items():
        if key in value:
            if _is_default(key, value[key]):
                raise KernelError("slim event stores a default it should omit")
        else:
            value[key] = default if not isinstance(default, (dict, list)) else type(default)()
    return header + b"\n" + canonical_json(value)


# --- run delta -------------------------------------------------------------


def run_delta(
    raw: bytes,
    base_raw: bytes,
    target: dict[str, Any] | None = None,
    base: dict[str, Any] | None = None,
) -> bytes | None:
    """*raw* as a delta against *base_raw*, or ``None`` when it would not pay.

    *target* / *base* may pass the bodies already parsed by ``_object`` (a pack
    writer parses each snapshot once, not three times); they are not modified.
    The delta is still kept only if applying it to *base_raw* rebuilds *raw*.
    """
    try:
        header, body = split(raw)
        base_header, base_body = split(base_raw)
        target = _object(body) if target is None else target
        base = _object(base_body) if base is None else base
    except KernelError:
        return None
    if header != base_header:
        return None
    append: dict[str, list] = {}
    changed: dict[str, Any] = {}
    for key, value in target.items():
        old = base.get(key, _MISSING)
        if old is not _MISSING and type(old) is type(value) and old == value:
            continue
        if isinstance(old, list) and isinstance(value, list) and len(value) > len(old):
            if value[: len(old)] == old and old:
                append[key] = value[len(old) :]
                continue
        changed[key] = value
    drop = sorted(key for key in base if key not in target)
    delta = {"append": append, "drop": drop, "set": changed}
    stored = header + b"\n" + canonical_json(delta)
    if len(stored) >= len(raw):
        return None
    try:
        rebuilt = apply_delta(base_raw, parse_delta(stored), base)
    except KernelError:
        return None
    return stored if rebuilt == raw else None


def parse_delta(stored: bytes) -> dict[str, Any]:
    """The delta of a ``RUN_DELTA`` form, its shape fully checked."""
    _, body = split(stored)
    delta = _object(body)
    if set(delta) != _DELTA_KEYS:
        raise KernelError("run delta has the wrong keys")
    append, drop, changed = delta["append"], delta["drop"], delta["set"]
    if not isinstance(append, dict) or not isinstance(changed, dict):
        raise KernelError("run delta is malformed")
    if not isinstance(drop, list) or not all(isinstance(key, str) for key in drop):
        raise KernelError("run delta is malformed")
    if any(not isinstance(tail, list) or not tail for tail in append.values()):
        raise KernelError("run delta appends nothing")
    if set(append) & set(changed) or set(drop) & (set(append) | set(changed)):
        raise KernelError("run delta names one key twice")
    return delta


def apply_delta(base_raw: bytes, delta: dict[str, Any], base: dict | None = None) -> bytes:
    """*base_raw* with *delta* applied; *base* is its body already parsed (kept as is)."""
    header, body = split(base_raw)
    value = _object(body) if base is None else dict(base)
    for key in delta["drop"]:
        if key not in value:
            raise KernelError("run delta drops a key its base lacks")
        del value[key]
    for key, tail in delta["append"].items():
        if not isinstance(value.get(key), list) or not value[key]:
            raise KernelError("run delta appends to a key that is not a list")
        value[key] = value[key] + tail
    value.update(delta["set"])
    return header + b"\n" + canonical_json(value)
