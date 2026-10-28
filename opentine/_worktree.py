"""Isolated per-branch working directories: ``tine worktree add/list/remove/prune``.

A worktree is a directory an agent works in for one branch (ref or run). The
repository registers it at ``<.tine>/worktrees/<name>.json`` -- a prune root, so
the run it names is never collected while the worktree exists -- and the
directory carries a ``.tine-worktree`` marker naming the repository and the
worktree. With ``--git`` the directory is also a ``git worktree`` of the
enclosing checkout (detached), so the agent's file edits are isolated too.

Safety:

* a name is one short lowercase component, never a path;
* the target must not be (or resolve into) the repository, must not be a
  symlink, and must be new or an empty directory;
* ``remove`` deletes a directory only when its own marker names *this*
  repository and *this* worktree: a registry entry edited to point at ``$HOME``
  cannot get it deleted, and a non-empty worktree needs ``--force``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

from opentine.repository._paths import atomic_bytes, durable_directory, internal_path, linklike

FORMAT = "opentine-worktree/1"
MARKER = ".tine-worktree"
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_COMMIT = re.compile(r"^(?:HEAD|[0-9a-f]{7,64})$")
MAX_ENTRY = 64 * 1024


def _name(name: str) -> str:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError(f"worktree name must match {NAME.pattern}, got {name!r}")
    return name


def _registry(repo, name: str) -> Path:
    return internal_path(repo.path, "worktrees", f"{_name(name)}.json")


def _target(repo, path: str | Path) -> Path:
    raw = Path(path).expanduser()
    if linklike(raw):
        raise ValueError(f"worktree path is a symlink: {raw}")
    target = raw.parent.resolve() / raw.name if raw.name else raw.resolve()
    tine = repo.path.resolve()
    if target == tine or tine in target.parents or target in tine.parents:
        raise ValueError("a worktree cannot be the repository or contain it")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise ValueError(f"worktree path exists and is not an empty directory: {target}")
    return target


def _read(path: Path) -> dict:
    if linklike(path):
        raise ValueError(f"{path.name} is a symlink")
    with open(path, "rb") as handle:
        raw = handle.read(MAX_ENTRY + 1)
    if len(raw) > MAX_ENTRY:
        raise ValueError(f"{path.name} exceeds its size limit")
    data = json.loads(raw)
    fields = {"format", "git", "name", "path", "ref", "repo", "run", "created"}
    if not isinstance(data, dict) or set(data) != fields or data["format"] != FORMAT:
        raise ValueError(f"{path.name} is not a worktree record")
    if not all(isinstance(data[k], str) for k in ("name", "path", "repo", "ref", "run")):
        raise ValueError(f"{path.name} is malformed")
    _name(data["name"])
    return data


def add(repo, path: str | Path, ref: str, *, name: str | None = None, git: str | None = None):
    from opentine._repo_cli_write import _run_oid

    run = _run_oid(repo, ref)
    target = _target(repo, path)
    name = _name(target.name.casefold() if name is None else name)
    entry_path = _registry(repo, name)
    if entry_path.exists():
        raise ValueError(f"worktree {name!r} already exists")
    if git is not None and not _COMMIT.fullmatch(git):
        raise ValueError("--git takes HEAD or a commit sha")
    entry = {
        "created": str(int(time.time())),
        "format": FORMAT,
        "git": git or "",
        "name": name,
        "path": str(target),
        "ref": ref,
        "repo": str(repo.path.resolve()),
        "run": run,
    }
    created = not target.exists()
    target.mkdir(parents=True, exist_ok=True)
    try:
        if git is not None:
            from opentine._git_link import git as run_git

            run_git(repo.worktree, "worktree", "add", "--detach", "--", str(target), git)
        marker = target / MARKER
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(entry, sort_keys=True).encode())
        durable_directory(entry_path.parent)
        atomic_bytes(entry_path, json.dumps(entry, sort_keys=True).encode())
    except BaseException:
        (target / MARKER).unlink(missing_ok=True)
        if created and not any(target.iterdir()):
            target.rmdir()
        raise
    return entry


def list_worktrees(repo) -> list[dict]:
    rows = []
    directory = internal_path(repo.path, "worktrees")
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            entry = _read(path)
            if entry["name"] != path.stem:
                raise ValueError("name does not match its file")
        except (OSError, ValueError) as exc:
            rows.append({"name": path.stem, "state": "invalid", "detail": str(exc)[:200]})
            continue
        rows.append({**entry, "state": _state(repo, entry)})
    return rows


def _state(repo, entry: dict) -> str:
    target = Path(entry["path"])
    if not target.exists() and not linklike(target):
        return "missing"
    try:
        marker = _read(target / MARKER)
    except (OSError, ValueError):
        return "unmarked"
    same = marker["name"] == entry["name"] and marker["repo"] == str(repo.path.resolve())
    return "ok" if same and not linklike(target) else "foreign"


def remove(repo, name: str, *, force: bool = False) -> dict:
    entry_path = _registry(repo, name)
    entry = _read(entry_path)
    state = _state(repo, entry)
    if state in {"unmarked", "foreign"}:
        raise ValueError(
            f"{entry['path']} is not this worktree (no matching {MARKER}); refusing to delete "
            "it -- `tine worktree prune` drops the registration only"
        )
    target = Path(entry["path"])
    if state == "ok":
        if entry["git"]:
            from opentine._git_link import git as run_git

            (target / MARKER).unlink()
            args = ["worktree", "remove", *(["--force"] if force else []), "--", str(target)]
            run_git(repo.worktree, *args)
        else:
            others = [p for p in target.iterdir() if p.name != MARKER]
            if others and not force:
                raise ValueError(f"{target} has files; pass --force to delete them")
            shutil.rmtree(target)  # never follows symlinks inside the tree
    entry_path.unlink()
    return entry


def prune(repo) -> list[str]:
    """Drop registrations whose directory is gone or no longer this worktree."""
    dropped, git = [], False
    for row in list_worktrees(repo):
        if row["state"] in {"missing", "unmarked", "foreign", "invalid"}:
            internal_path(repo.path, "worktrees", f"{row['name']}.json").unlink(missing_ok=True)
            dropped.append(row["name"])
            git = git or bool(row.get("git"))
    if git:
        from opentine._git_link import GitLinkError
        from opentine._git_link import git as run_git

        try:
            run_git(repo.worktree, "worktree", "prune")
        except GitLinkError:
            pass  # git's own bookkeeping; ours is already consistent
    return dropped


__all__ = ["FORMAT", "MARKER", "add", "list_worktrees", "prune", "remove"]
