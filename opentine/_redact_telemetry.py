"""Harness telemetry: the publication rule for agent-CLI operator records (Unreleased).

A step that captured an agent CLI's machine-readable stream also captured what
the harness says about the operator's account and machine: rate limits, the
skills and plugins installed, capability flags, socket paths, serving region,
session and request ids. None of it is the run; all of it names the operator.
The ``telemetry`` kind of ``opentine-redaction/2+publish/1`` removes it from a
redacted public copy, harness by harness (:data:`HARNESSES`):

* a record is the harness's when its ``type`` is listed under ``types`` and it
  carries a ``session_id``, or its ``type`` is listed under ``drop``;
* records whose ``type`` is listed under ``drop`` are removed entirely;
* records matching a ``reduce`` entry keep only the allowlisted keys, and keys
  under ``placeholders`` become a fixed placeholder;
* keys listed under ``strip`` are removed at any depth of any record, except
  inside ``opaque`` keys (a tool's own arguments);
* a string value holding an escaped stream (a tool result) is scrubbed too, and
  a JSON array of records is scrubbed record by record.

Text is handled as JSON lines (one record per line; lines that are not a JSON
object are kept byte for byte) or as one JSON document. A line is rewritten only
when something was removed, so untouched records keep their exact bytes. The
result is still JSON, so the copy stays valid and verifiable. Each record
dropped and each key removed or replaced counts once as ``telemetry``.
"""

from __future__ import annotations

import json
from typing import Any

#: Per-harness patterns. Add a harness by adding an entry; nothing else changes.
HARNESSES: dict[str, dict[str, Any]] = {
    "claude-code-stream-json": {
        "marker": '"session_id"',
        # A record is this harness's when its type is one of these and it carries
        # a session id (or is a type always dropped): other JSON is left untouched.
        "types": frozenset({"system", "assistant", "user", "result", "stream_event"}),
        "drop": frozenset({"rate_limit_event"}),
        "reduce": {
            ("system", "init"): frozenset(
                {"type", "subtype", "model", "tools", "cwd", "permissionMode"}
            ),
        },
        "placeholders": {"cwd": "<CWD>"},
        "strip": frozenset(
            {
                "session_id",
                "sessionId",
                "request_id",
                "requestId",
                "uuid",
                "parent_tool_use_uuid",
                "persistedOutputPath",
            }
        ),
        # A tool's own arguments are the agent's data, never telemetry.
        "opaque": frozenset({"input"}),
    },
    "gemini-cli-stream-json": {
        "marker": '"session_id"',
        "types": frozenset({"init", "message", "tool_use", "tool_result", "result"}),
        "drop": frozenset(),
        "reduce": {("init", None): frozenset({"type", "model"})},
        "placeholders": {},
        "strip": frozenset({"session_id"}),
        "opaque": frozenset({"parameters"}),
    },
    "codex-exec-json": {
        "marker": '"thread_id"',
        "id_key": "thread_id",
        "types": frozenset({"thread.started"}),
        "drop": frozenset(),
        "reduce": {},
        "placeholders": {},
        "strip": frozenset({"thread_id"}),
        "opaque": frozenset(),
    },
}


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
    keep = spec["reduce"].get((record.get("type"), record.get("subtype")))
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
        kind = record.get("type")
        if kind in spec["drop"]:
            removed[0] += 1
            return False, None
        if kind in spec["types"] and spec.get("id_key", "session_id") in record:
            record = _clean(record, spec, removed)
    return True, record


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def scrub(text: str) -> tuple[str, int]:
    """*text* without harness telemetry, and how many items were removed."""
    if not any(
        spec["marker"] in text or any(f'"{kind}"' in text for kind in spec["drop"])
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


def _strings(value: Any, removed: list[int]) -> Any:
    if isinstance(value, str):
        clean, found = scrub(value)
        removed[0] += found
        return clean
    if isinstance(value, list):
        items = []
        for item in value:  # a loop: one frame per nesting level
            items.append(_strings(item, removed))
        return items
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            out[key] = _strings(item, removed)
        return out
    return value


def scrub_nested(text: str) -> tuple[str, int]:
    """A JSON document whose string values hold a captured stream (a step's
    ``stdout`` blob): each such string scrubbed, re-encoded compact with sorted keys."""
    if '\\"session_id\\"' not in text and '\\"rate_limit_event\\"' not in text:
        return text, 0
    try:
        value = json.loads(text)
    except ValueError:
        return text, 0
    removed = [0]
    clean = _strings(value, removed)
    if not removed[0]:
        return text, 0
    return json.dumps(clean, ensure_ascii=False, separators=(",", ":"), sort_keys=True), removed[0]


__all__ = ["HARNESSES", "scrub", "scrub_nested"]
