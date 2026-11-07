"""Reading line attribution back: Agent Trace records and ``stats --ai-share``.

:func:`agent_trace` turns a commit's attribution note into one Agent Trace
record (https://agent-trace.dev/, schema
``https://agent-trace.dev/schemas/v1/trace-record.json``): ``vcs`` is the git
commit the note is on, each file is a ``files`` entry, each model one
conversation with contributor ``ai``, and each attributed range keeps its
``content_hash``. The run and step ids ride in ``metadata`` under the vendor
key, as :mod:`opentine._agent_trace` does for a whole-run export.

:func:`ai_share` blames every text file at a revision and counts the lines
whose originating commit's note attributes that line to a run.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._agent_trace import SPEC_VERSION, VENDOR_KEY
from opentine._git_link import GitLinkError, checked_revision, git, resolve_commit
from opentine._line_attrib import read_note
from opentine._version import __version__

MAX_FILES = 5000
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://opentine.com/line-attribution")


def _commit_time(cwd: Path | str, sha: str) -> str:
    seconds = int(git(cwd, "log", "-1", "--format=%ct", sha).strip() or 0)
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def agent_trace(cwd: Path | str, sha: str, record: dict[str, Any]) -> dict[str, Any]:
    """One Agent Trace record for the attribution *record* on commit *sha*."""
    files = []
    steps: list[dict[str, Any]] = []
    for entry in record.get("files") or []:
        conversations: dict[str, dict[str, Any]] = {}
        for item in entry.get("ranges") or []:
            model = str(item.get("model") or "")[:250]
            contributor = {"type": "ai", **({"model_id": model} if model else {})}
            conversation = conversations.setdefault(
                model, {"contributor": contributor, "ranges": []}
            )
            conversation["ranges"].append(
                {key: item[key] for key in ("start_line", "end_line", "content_hash")}
            )
            steps.append({"path": entry["path"], "start_line": item["start_line"],
                          "run": item.get("run"), "step": item.get("step")})  # fmt: skip
        files.append({"path": entry["path"], "conversations": list(conversations.values())})
    return {
        "version": SPEC_VERSION,
        "id": str(uuid.uuid5(_NAMESPACE, sha)),
        "timestamp": _commit_time(cwd, sha),
        "vcs": {"type": "git", "revision": sha},
        "tool": {"name": "opentine", "version": __version__},
        "files": files,
        "metadata": {
            VENDOR_KEY: {
                "attribution_schema": record.get("schema"),
                "signed": isinstance(record.get("signature"), dict),
                "lines_added": record.get("lines_added"),
                "lines_attributed": record.get("lines_attributed"),
                "ranges": steps,
            }
        },
    }


def _attributed(record: dict[str, Any] | None) -> dict[str, dict[int, str]]:
    """``{path: {line: model}}`` an attribution record covers."""
    out: dict[str, dict[int, str]] = {}
    for entry in (record or {}).get("files") or []:
        lines = out.setdefault(str(entry.get("path")), {})
        for item in entry.get("ranges") or []:
            for number in range(int(item["start_line"]), int(item["end_line"]) + 1):
                lines[number] = str(item.get("model") or "unknown")
    return out


def _blame(cwd: Path | str, rev: str, path: str) -> list[tuple[str, str, int]]:
    """``(commit, path in that commit, line number there)`` per line of *path* at *rev*."""
    out = git(cwd, "blame", "--line-porcelain", "--no-textconv", rev, "--", path)
    rows: list[tuple[str, str, int]] = []
    sha, orig, name = "", 0, path
    for raw in out.splitlines():
        if raw.startswith("\t"):
            rows.append((sha, name, orig))
        elif raw.startswith("filename "):
            name = raw[len("filename ") :]
        else:
            parts = raw.split(" ")
            if len(parts) >= 3 and len(parts[0]) >= 40 and parts[1].isdigit():
                sha, orig = parts[0], int(parts[1])
    return rows


def ai_share(cwd: Path | str, rev: str = "HEAD") -> dict[str, Any]:
    """The share of lines at *rev* that attribution notes credit to an agent."""
    sha = resolve_commit(cwd, checked_revision(rev))
    try:
        listed = git(cwd, "grep", "-I", "--name-only", "-z", "-e", "", sha, "--").split("\0")
    except GitLinkError:
        listed = []  # git grep exits 1 when no text file matches
    paths = sorted(item.partition(":")[2] for item in listed if item)[:MAX_FILES]
    notes: dict[str, dict[str, dict[int, str]]] = {}
    total = ai = 0
    by_model: dict[str, int] = {}
    files: list[dict[str, Any]] = []
    for path in paths:
        try:
            rows = _blame(cwd, sha, path)
        except GitLinkError:
            continue
        mine = 0
        for commit, name, line in rows:
            if commit not in notes:
                notes[commit] = _attributed(read_note(cwd, commit))
            model = notes[commit].get(name, {}).get(line)
            if model is not None:
                mine += 1
                by_model[model] = by_model.get(model, 0) + 1
        total += len(rows)
        ai += mine
        files.append({"path": path, "lines": len(rows), "ai_lines": mine})
    return {
        "revision": sha,
        "total_lines": total,
        "ai_lines": ai,
        "ai_share": round(ai / total, 6) if total else 0.0,
        "by_model": dict(sorted(by_model.items())),
        "commits_with_attribution": sum(1 for value in notes.values() if value),
        "files": files,
        "files_clipped": len(listed) > MAX_FILES,
    }


__all__ = ["agent_trace", "ai_share"]
