"""Harness telemetry: the publication rule for agent-CLI operator records (Unreleased).

A step that captured an agent CLI's machine-readable stream also captured what
the harness says about the operator's account and machine: rate limits, the
skills and plugins installed, capability flags, socket paths, serving region,
session and request ids. None of it is the run; all of it names the operator.
The ``telemetry`` kind of ``opentine-redaction/2+publish/1`` removes it from a
redacted public copy, harness by harness (:data:`HARNESSES`, documented in
:mod:`opentine._redact_harnesses`):

* a record is the harness's when its kind (``type``, or ``event`` in OpenTine's
  own adapter blobs) is listed under ``types`` and it carries a session id, or
  its kind is listed under ``drop``;
* records whose kind is listed under ``drop`` are removed entirely;
* records matching a ``reduce`` entry keep only the allowlisted keys, and keys
  under ``placeholders`` become a fixed placeholder;
* keys listed under ``strip`` are removed at any depth of any record, except
  inside ``opaque`` keys (a tool's own arguments);
* a string value holding an escaped stream (a tool result) is scrubbed too, and
  a JSON array of records is scrubbed record by record;
* in a JSON blob holding a capture (a step's ``stdout``, an OTel span with a
  ``gen_ai.prompt`` attribute) every string is scrubbed, and OTel
  ``{"key", "value"}`` attributes named by a ``strip`` key are removed;
* a session id inside a path the harness writes (``.claude/projects/<p>/<uuid>/``)
  becomes ``<SESSION>`` (:func:`scrub_session_paths`).

Text is handled as JSON lines (one record per line; lines that are not a JSON
object are kept byte for byte) or as one JSON document. A line is rewritten only
when something was removed, so untouched records keep their exact bytes. The
result is still JSON, so the copy stays valid and verifiable. Each record
dropped and each key removed or replaced counts once as ``telemetry``.
"""

from __future__ import annotations

import json
from typing import Any

from opentine._redact_harnesses import HARNESSES, kind_of, owns


def _clean(record: Any, spec: dict[str, Any], removed: list[int]) -> Any:
    if isinstance(record, list):
        out_list = []
        for item in record:  # a loop: one frame per nesting level
            out_list.append(_clean(item, spec, removed))
        return out_list
    if isinstance(record, str):  # an escaped stream inside a tool result
        if '"' not in record:
            return record
        clean, found = scrub(record)
        removed[0] += found
        return clean
    if not isinstance(record, dict):
        return record
    kind = kind_of(record, spec)
    reduce = spec["reduce"]
    keep = reduce.get((kind, record.get("subtype")), reduce.get((kind, None)))
    out: dict[str, Any] = {}
    for key, value in record.items():
        if key in spec["strip"] or (keep is not None and key not in keep):
            removed[0] += 1
            continue
        if keep is not None and key in spec["placeholders"]:
            if value != spec["placeholders"][key]:
                removed[0] += 1
            out[key] = spec["placeholders"][key]
            continue
        out[key] = value if key in spec["opaque"] else _clean(value, spec, removed)
    return out


def _record(record: Any, removed: list[int]) -> tuple[bool, Any]:
    """``(keep, cleaned)`` for one decoded record (or array of them) under every harness."""
    if isinstance(record, list):  # ``--output-format json --verbose``: an array
        items = []
        for item in record:
            keep, clean = _record(item, removed)
            if keep:
                items.append(clean)
        return True, items
    for spec in HARNESSES.values():
        if not isinstance(record, dict):
            continue
        if kind_of(record, spec) in spec["drop"]:
            removed[0] += 1
            return False, None
        if owns(record, spec):
            record = _clean(record, spec, removed)
    return True, record


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def scrub(text: str) -> tuple[str, int]:
    """*text* without harness telemetry, and how many items were removed."""
    if not any(
        any(marker in text for marker in spec["markers"])
        or any(f'"{kind}"' in text for kind in spec["drop"])
        for spec in HARNESSES.values()
    ):
        return text, 0
    stripped = text.strip()
    if stripped.startswith(("{", "[")) and "\n" in stripped:
        try:  # one (pretty-printed) JSON document
            whole = json.loads(stripped)
        except ValueError:
            whole = None
        if whole is not None:
            removed = [0]
            keep, clean = _record(whole, removed)
            if not removed[0]:
                return text, 0
            return (_dump(clean) if keep else ""), removed[0]
    total, out = 0, []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if not body.lstrip().startswith(("{", "[")):
            out.append(line)
            continue
        try:
            record = json.loads(body)
        except ValueError:
            out.append(line)
            continue
        removed = [0]
        keep, clean = _record(record, removed)
        total += removed[0]
        if not keep:
            continue
        out.append(line if not removed[0] else _dump(clean) + line[len(body) :])
    return ("".join(out), total) if total else (text, 0)


_DROP = object()


def _otel_attribute(value: dict[str, Any]) -> bool:
    return (
        value.keys() == {"key", "value"}
        and isinstance(value["key"], str)
        and any(value["key"] in spec["strip"] for spec in HARNESSES.values())
    )


def _strings(value: Any, removed: list[int]) -> Any:
    if isinstance(value, str):
        clean, found = scrub(value)
        removed[0] += found
        return clean
    if isinstance(value, list):
        items = []
        for item in value:  # a loop: one frame per nesting level
            clean = _strings(item, removed)
            if clean is not _DROP:
                items.append(clean)
        return items
    if isinstance(value, dict):
        out = {}
        if _otel_attribute(value):  # an OTel ``{"key": ..., "value": ...}`` id attribute
            removed[0] += 1
            return _DROP
        for key, item in value.items():
            out[key] = _strings(item, removed)
        return out
    return value


def scrub_nested(text: str) -> tuple[str, int]:
    """A JSON document whose string values hold a captured stream (a step's
    ``stdout`` blob): each such string scrubbed, re-encoded compact with sorted keys."""
    if not any(
        '\\"' + marker.strip('"') + '\\"' in text
        for spec in HARNESSES.values()
        for marker in (*spec["markers"], *(f'"{kind}"' for kind in spec["drop"]))
    ):
        return text, 0
    try:
        value = json.loads(text)
    except ValueError:
        return text, 0
    removed = [0]
    clean = _strings(value, removed)
    if clean is _DROP:
        clean = {}
    if not removed[0]:
        return text, 0
    return json.dumps(clean, ensure_ascii=False, separators=(",", ":"), sort_keys=True), removed[0]


def scrub_session_paths(text: str) -> tuple[str, int]:
    """*text* with each harness's session id inside a path (``SESSION_PATHS``) replaced."""
    total = 0
    for spec in HARNESSES.values():
        pattern = spec.get("session_path")
        if pattern is not None and spec["path_hint"] in text:
            text, found = pattern.subn(r"\1<SESSION>", text)
            total += found
    return text, total


__all__ = ["HARNESSES", "scrub", "scrub_nested", "scrub_session_paths"]
