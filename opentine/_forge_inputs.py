"""What ``tine forge publish`` reads before it posts anything (0.48).

Everything here is local and offline: the project (resolved by the forge's own
repository id, ``forge_repo_id``, against the verified ``opentine.project``
chain), ``tine verify --json`` outputs the CI job already wrote, the bundle the
check links to (verified in full before its digest is taken), the AI share at
the commit and the commit's own attributed ranges (the blame overlay).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from opentine._forge_check import MAX_OVERLAY

MAX_VERIFY_BYTES = 4 << 20
_SAFE_PATH = re.compile(r"[^/\\\0][^\\\0]{0,1023}")
_RUN = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
#: The project slot ``forge`` a publish target resolves against.
SLOT_FORGE = {"github": "github", "gitlab": "gitlab", "forgejo": "forgejo", "entire": "entire"}


def resolve_project(repo_path: str, forge: str, forge_repo_id: str, *, required: bool) -> Any:
    """The ``project_id`` whose verified chain has a slot for this forge repository.

    ``None`` when the run repository holds no project and *required* is false.
    A project with no slot naming ``forge_repo_id`` on *forge* is refused: a
    check is never shown on a repository its project does not link.
    """
    from opentine import _project
    from opentine.repository import Repo, _project_ref

    try:
        repo = Repo.open(repo_path)
    except (OSError, ValueError) as exc:
        if required:
            raise ValueError(f"no run repository at {Path(repo_path).as_posix()}") from exc
        return None
    versions = _project_ref.history(repo)
    if not versions:
        if required:
            raise KeyError("no project here: `tine project init` first")
        return None
    _project.chain(versions)
    head = versions[-1]
    for slot in head["slots"]:
        if slot["forge"] == SLOT_FORGE[forge] and slot.get("forge_repo_id") == forge_repo_id:
            return head["project_id"]
    raise ValueError(
        f"project {head['project_id']} links no {forge} repository with forge_repo_id "
        f"{forge_repo_id}: `tine project link --forge {forge} --forge-repo-id ...` first"
    )


def verify_state(paths: list[str]) -> tuple[str, int]:
    """``(state, runs)`` from ``tine verify --json`` outputs; ``unverified`` without any."""
    if not paths:
        return "unverified", 0
    ok = True
    for path in paths:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_VERIFY_BYTES:
            raise ValueError(f"{Path(path).name} exceeds {MAX_VERIFY_BYTES} bytes")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"{Path(path).name} is not a tine verify --json output") from exc
        good = isinstance(value, dict) and value.get("ok") is True and "error" not in value
        ok = ok and good and "unpinned" not in value
    return ("verified" if ok else "failed"), len(paths)


def bundle_digest(path: str) -> str:
    """The digest of a bundle that verifies completely; refuse to link one that does not."""
    from opentine import _bundle

    return _bundle.verify(_bundle.read_file(path)).digest


def commit_of(code: str, rev: str) -> str:
    from opentine._git_link import checked_revision, resolve_commit

    return resolve_commit(code, checked_revision(rev))


def share(code: str, commit: str) -> tuple[int, int]:
    from opentine._line_attrib_share import ai_share

    report = ai_share(code, commit)
    return int(report["ai_lines"]), int(report["total_lines"])


def overlay(code: str, commit: str) -> list[dict[str, Any]]:
    """The commit's own attributed ranges, at most :data:`MAX_OVERLAY`, by path then line."""
    from opentine._line_attrib import read_note

    rows: list[dict[str, Any]] = []
    for entry in (read_note(code, commit) or {}).get("files") or []:
        path = entry.get("path")
        if not isinstance(path, str) or not _SAFE_PATH.fullmatch(path) or ".." in path.split("/"):
            continue
        for item in entry.get("ranges") or []:
            try:
                start, end = int(item["start_line"]), int(item["end_line"])
            except (KeyError, TypeError, ValueError):
                continue
            run = item.get("run")
            if not 1 <= start <= end:
                continue
            good = isinstance(run, str) and _RUN.fullmatch(run)
            rows.append(
                {"path": path, "start_line": start, "end_line": end, "run": run if good else None}
            )
    rows.sort(key=lambda row: (row["path"], row["start_line"], row["end_line"]))
    return rows[:MAX_OVERLAY]


def runs_of(rows: list[dict[str, Any]]) -> list[str]:
    """The distinct run ids the overlay names, in order."""
    return list(dict.fromkeys(row["run"] for row in rows if row["run"]))


__all__ = [
    "bundle_digest",
    "commit_of",
    "overlay",
    "resolve_project",
    "runs_of",
    "share",
    "verify_state",
]
