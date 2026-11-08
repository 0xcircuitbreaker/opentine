"""Git AI v3 notes <-> OpenTine ``opentine-line-attribution/1`` records.

:func:`to_attribution` converts a parsed Git AI note (:mod:`opentine._git_ai_notes`)
into an OpenTine attribution record, credited to ``git-ai:<session or prompt>``
runs with the checkpoint (or prompt) as the step; the note's metadata and its
human attestations are kept under ``git_ai`` so an export writes them back.
Human lines are never credited to an agent. :func:`from_attribution` renders a
v3 note from a record: an imported range keeps its original key, and a native
OpenTine range gets a deterministic ``s_``/``t_`` key derived from its run and
step (Git AI draws trace ids at random; OpenTine keeps exports reproducible).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from opentine._git_ai_notes import (
    HUMAN_KEY,
    PROMPT_KEY,
    REF,
    RUN_PREFIX,
    SESSION_KEY,
    VERSION,
    format_ranges,
    parse_ranges,
    render,
    spans,
)
from opentine._git_link import GitLinkError, git
from opentine._line_attrib import SCHEMA, added_lines, content_hash


def _h(text: str, size: int = 14) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:size]


def _agent(metadata: dict[str, Any], key: str) -> dict[str, Any]:
    match = SESSION_KEY.match(key)
    table, name = ("sessions", match.group(1)) if match else ("prompts", key)
    entry = (metadata.get(table) or {}).get(name) or {}
    agent = entry.get("agent_id") if isinstance(entry, dict) else None
    return agent if isinstance(agent, dict) else {}


def _blob_lines(cwd: Path | str, sha: str, path: str) -> list[str]:
    try:
        return git(cwd, "show", f"{sha}:{path}").splitlines()
    except GitLinkError:
        return []


def to_attribution(cwd: Path | str, sha: str, note: dict[str, Any]) -> dict[str, Any]:
    """The ``opentine-line-attribution/1`` record a parsed Git AI note implies."""
    metadata = note["metadata"]
    files, humans, attributed = [], [], 0
    for path, keys in sorted(note["files"].items()):
        text = _blob_lines(cwd, sha, path)
        ranges = []
        for key, numbers in sorted(keys.items()):
            if HUMAN_KEY.match(key):
                humans.append({"path": path, "key": key, "lines": format_ranges(numbers)})
                continue
            match = SESSION_KEY.match(key)
            run, step = (match.group(1), match.group(2)) if match else (key, key)
            agent = _agent(metadata, key)
            for start, end in spans([n for n in numbers if n <= len(text)]):
                item = {
                    "start_line": start,
                    "end_line": end,
                    "run": RUN_PREFIX + run,
                    "step": step,
                    "content_hash": content_hash(text[start - 1 : end]),
                }
                for field, value in (("tool", agent.get("tool")), ("model", agent.get("model"))):
                    if isinstance(value, str) and value:
                        item[field] = value
                ranges.append(item)
                attributed += end - start + 1
        if ranges:
            files.append({"path": path, "ranges": sorted(ranges, key=lambda r: r["start_line"])})
    added = sum(len(lines) for lines in added_lines(cwd, sha).values())
    source = {
        key: metadata[key]
        for key in ("base_commit_sha", "git_ai_version", "sessions", "humans", "prompts")
        if key in metadata
    }
    return {
        "schema": SCHEMA,
        "files": files,
        "lines_added": added,
        "lines_attributed": attributed,
        "git_ai": {"ref": REF, "schema_version": VERSION, **source, "human_lines": humans},
    }


def from_attribution(sha: str, record: dict[str, Any]) -> str:
    """A v3 note for *sha* from an OpenTine attribution record."""
    source = record.get("git_ai") if isinstance(record.get("git_ai"), dict) else {}
    sessions = dict(source.get("sessions") or {})
    prompts = dict(source.get("prompts") or {})
    files: dict[str, dict[str, list[int]]] = {}
    for entry in record.get("files") or []:
        keys = files.setdefault(str(entry.get("path")), {})
        for item in entry.get("ranges") or []:
            run, step = str(item.get("run") or ""), str(item.get("step") or "")
            short = run[len(RUN_PREFIX) :] if run.startswith(RUN_PREFIX) else ""
            if short.startswith("s_") and step.startswith("t_"):
                key, session = f"{short}::{step}", short
            elif short and PROMPT_KEY.match(short):
                key, session = short, ""
            else:
                session = "s_" + _h("opentine:" + run)
                key = f"{session}::t_{_h(run + chr(0) + step)}"
            if session and session not in sessions:
                sessions[session] = {
                    "agent_id": {
                        "tool": item.get("tool") or "opentine",
                        "id": run,
                        "model": item.get("model") or "unknown",
                    }
                }
            lines = range(int(item["start_line"]), int(item["end_line"]) + 1)
            keys[key] = sorted(set(keys.get(key, [])) | set(lines))
    for human in source.get("human_lines") or []:
        keys = files.setdefault(str(human["path"]), {})
        keys[human["key"]] = sorted(
            set(keys.get(human["key"], [])) | set(parse_ranges(human["lines"]))
        )
    metadata: dict[str, Any] = {
        "schema_version": VERSION,
        "base_commit_sha": source.get("base_commit_sha") or sha,
        "prompts": prompts,
        "sessions": sessions,
    }
    for key in ("git_ai_version", "humans"):
        if key in source:
            metadata[key] = source[key]
    return render(files, metadata)


__all__ = ["from_attribution", "to_attribution"]
