"""``tine blame``: which run, step, model and tool call wrote a file or a line.

A write action (0.11's action index) says *that* a step wrote a path; the
step's recorded tool input says *what* it wrote -- a Write's ``content``, an
Edit's ``new_string``, the ``+`` lines of an ``apply_patch`` hunk. Blame walks
the writes of a path newest first and reports the first whose inserted text
contains the line asked about. Without a line it lists every writer.

``--git`` starts from ``git blame`` instead: the commit that last changed the
line, then the runs that commit links to (``Tine-Run`` trailers and
``refs/notes/tine``), then the step inside those runs. Everything read comes
from the recorded, already-redacted run, and every walk is bounded.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from opentine._actions import Action
from opentine._actions_db import ActionIndex
from opentine._actions_query import ActionQuery, find
from opentine._git_link import GitLinkError, commit_runs, git
from opentine._git_link_hook import matches

MAX_RUNS_LOADED = 200
MAX_INSERTED_CHARS = 2 * 1024 * 1024
_TEXT_KEYS = ("content", "new_string", "new_str", "file_text", "text", "contents")
_PATCH_KEYS = ("patch", "input", "diff")
_FILE_HEADER = ("*** Update File:", "*** Add File:", "+++ ")


@dataclass
class BlameHit:
    run_id: str
    step_id: str
    seq: int
    tool: str
    model: str
    agent: str
    ts: float
    path: str
    match: str  # "line" (the line is in the inserted text), "file" (wrote the file)
    commit: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _arguments(step: Any) -> Any:
    inputs = step.inputs if isinstance(step.inputs, dict) else {}
    arguments = inputs.get("arguments", inputs.get("input", {}))
    if isinstance(arguments, str):
        try:
            return json.loads(arguments[:MAX_INSERTED_CHARS])
        except ValueError:
            return arguments
    return arguments


def _patch_lines(text: str, target: str) -> list[str]:
    """``+`` lines of a patch, only from sections for *target* when it names files."""
    lines = text[:MAX_INSERTED_CHARS].splitlines()
    sectioned = any(line.startswith(_FILE_HEADER) for line in lines)
    keep, out = not sectioned, []
    for line in lines:
        if line.startswith(_FILE_HEADER):
            named = line.split(":", 1)[-1] if line.startswith("***") else line[4:]
            named = named.strip().removeprefix("b/")
            keep = bool(named) and (target.endswith(named) or named.endswith(target))
            continue
        if keep and line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return out


def inserted_lines(step: Any, target: str) -> set[str]:
    """Stripped lines a write step put into *target* (bounded)."""
    arguments = _arguments(step)
    chunks: list[str] = []
    if isinstance(arguments, dict):
        chunks += [arguments[key] for key in _TEXT_KEYS if isinstance(arguments.get(key), str)]
        edits = arguments.get("edits")
        if isinstance(edits, list):
            for edit in edits[:1000]:
                if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                    chunks.append(edit["new_string"])
        patches = [arguments[key] for key in _PATCH_KEYS if isinstance(arguments.get(key), str)]
    else:
        patches = [arguments] if isinstance(arguments, str) else []
    lines: list[str] = []
    budget = MAX_INSERTED_CHARS
    for chunk in chunks:
        lines += chunk[:budget].splitlines()
        budget -= min(len(chunk), budget)
    for patch in patches:
        lines += _patch_lines(patch, target)
    return {line.strip() for line in lines if line.strip()}


def same_file(written: str, abs_path: Path, given: str) -> bool:
    """Whether a recorded written path names the file at *abs_path* (asked as *given*)."""
    written = written.replace("\\", "/").rstrip("/")
    given = given.replace("\\", "/").removeprefix("./")
    if not written:
        return False
    if os.path.isabs(written) or written.startswith("~"):
        return matches(written, abs_path.parent, abs_path.name)
    clean = written.removeprefix("./")
    return clean == given or abs_path.as_posix().endswith("/" + clean)


def _writers(index: ActionIndex, path: str, abs_path: Path) -> list[Action]:
    leaf = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    found = [
        action
        for action in find(index, ActionQuery(path=leaf, writes=True))
        if any(same_file(written, abs_path, path) for written in action.written)
    ]
    found.sort(key=lambda action: (action.ts, action.seq), reverse=True)
    return found


def _hit(action: Action, path: str, match: str, commit: str = "") -> BlameHit:
    return BlameHit(
        run_id=action.run_id,
        step_id=action.step_id,
        seq=action.seq,
        tool=action.tool,
        model=action.model,
        agent=action.agent,
        ts=action.ts,
        path=path,
        match=match,
        commit=commit,
    )


def blame(
    index: ActionIndex,
    load_run: Callable[[str], Any],
    path: str,
    *,
    line: int | None = None,
    runs: set[str] | None = None,
    commit: str = "",
    line_text: str | None = None,
) -> list[BlameHit]:
    """Writers of *path* (newest first), or the one that wrote line *line*."""
    abs_path = Path(os.path.abspath(path))
    writers = _writers(index, path, abs_path)
    if runs is not None:
        writers = [action for action in writers if action.run_id in runs]
    if line is None:
        return [_hit(action, path, "file", commit) for action in writers]
    wanted = (line_text if line_text is not None else _line_of(abs_path, line)).strip()
    if not wanted:
        return []
    loaded: dict[str, Any] = {}
    for action in writers:
        if action.run_id not in loaded:
            if len(loaded) >= MAX_RUNS_LOADED:
                break
            try:
                loaded[action.run_id] = load_run(action.run_id)
            except Exception:  # noqa: BLE001 - an unreadable run is skipped, not fatal
                loaded[action.run_id] = None
        run = loaded[action.run_id]
        step = run.get_step(action.step_id) if run is not None else None
        if step is not None and wanted in inserted_lines(step, path.replace("\\", "/")):
            return [_hit(action, path, "line", commit)]
    return []


def _line_of(path: Path, line: int) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if number == line:
                    return text
    except OSError:
        return ""
    return ""


def git_line(cwd: Path, path: str, line: int) -> tuple[str, str]:
    """``(commit sha, line text)`` from ``git blame`` for one line of *path*."""
    # Blame the committed HEAD with textconv off: blaming the work tree runs the
    # repository's own filter.*.clean / diff.*.textconv programs.
    try:
        out = git(
            cwd, "blame", "--porcelain", "--no-textconv", "-L", f"{int(line)},{int(line)}",
            "HEAD", "--", path,
        )  # fmt: skip
    except GitLinkError:
        return "", ""
    lines = out.splitlines()
    if not lines:
        return "", ""
    sha = lines[0].split(" ", 1)[0]
    text = next((item[1:] for item in lines if item.startswith("\t")), "")
    return ("" if set(sha) == {"0"} else sha), text


def git_blame(
    index: ActionIndex,
    load_run: Callable[[str], Any],
    cwd: Path,
    path: str,
    line: int,
    to_run_id: Callable[[str], str] = lambda name: name,
) -> tuple[str, list[str], list[BlameHit]]:
    """Commit → linked runs → step for *path*:*line*.

    An uncommitted line has no commit to follow, so it falls back to the plain
    write history. A commit that links no run yields no hit: blame never guesses
    a run the commit does not name.
    """
    sha, text = git_line(cwd, path, line)
    if not sha:
        return "", [], blame(index, load_run, path, line=line, line_text=text)
    linked = [run for run, _source in commit_runs(cwd, sha)]
    runs = {to_run_id(name) for name in linked}
    hits = blame(index, load_run, path, line=line, runs=runs, commit=sha, line_text=text)
    return sha, linked, hits


__all__ = ["BlameHit", "blame", "git_blame", "git_line", "inserted_lines"]
