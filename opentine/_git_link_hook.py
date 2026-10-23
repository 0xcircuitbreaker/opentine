"""``tine git install-hook`` and the trailers the hook adds to a commit message.

The hook is a ``prepare-commit-msg`` script that asks ``tine git trailers``
which recorded runs wrote the staged files since the last commit, and appends
one ``Tine-Run:`` trailer per run. It never blocks a commit (any failure is
swallowed) and never replaces a hook the user already has: an existing hook
is kept as ``prepare-commit-msg.tine-chained`` and runs first.

``--global`` points ``core.hooksPath`` at a directory of opentine's own, with a
pass-through shim for every other client hook so a repository's own hooks keep
running; when ``core.hooksPath`` is already set globally, the hook is added to
that directory instead and nothing is re-pointed.
"""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

from opentine._actions_query import ActionQuery, find
from opentine._git_link import HOOK_ENV, RUN_ID, GitLinkError, git

HOOK = "prepare-commit-msg"
MARKER = "# opentine:prepare-commit-msg"
CHAINED = ".tine-chained"
MAX_TRAILER_RUNS = 20
MAX_STAGED = 2000
#: Without a previous commit, how far back a write still counts.
FIRST_COMMIT_WINDOW = 7 * 86400
#: Recorded writes stamped further ahead than this are ignored (forged or skewed).
FUTURE_SLACK = 300
#: Git config keys naming where the hook reads runs; set by the user, never by a clone.
REPO_KEY = "tine.repo"
RUNS_KEY = "tine.runsDir"
_CLIENT_HOOKS = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push",
    "post-rewrite", "pre-auto-gc", "push-to-checkout", "reference-transaction",
    "post-index-change", "sendemail-validate", "fsmonitor-watchman", "p4-changelist",
    "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-update",
    "pre-receive", "update", "proc-receive",
)  # fmt: skip


def _script() -> str:
    python = Path(sys.executable).as_posix().replace('"', '\\"')
    return (
        "#!/bin/sh\n"
        f"{MARKER} (managed by `tine git install-hook`; safe to delete)\n"
        f'if [ -x "$0{CHAINED}" ]; then "$0{CHAINED}" "$@" || exit $?; fi\n'
        # Installed globally (core.hooksPath), git no longer runs the repository's
        # own hook of this name: run it here unless it is this very script.
        "common=$(git rev-parse --git-common-dir 2>/dev/null)\n"
        f'own="$common/hooks/{HOOK}"\n'
        f'if [ -n "$common" ] && [ -x "$own" ] && ! grep -q "{MARKER}" "$own" 2>/dev/null; '
        'then "$own" "$@" || exit $?; fi\n'
        # -I: git runs hooks from the worktree, and a cloned repo could ship its
        # own opentine/ package there; isolated mode keeps cwd off sys.path.
        f'"{python}" -I -m opentine.cli git trailers "$@" >/dev/null 2>&1 || true\n'
        "exit 0\n"
    )


def _shim(name: str) -> str:
    # Runs the repository's own hook of this name, as git would without hooksPath.
    return (
        "#!/bin/sh\n"
        f"{MARKER} pass-through shim\n"
        "common=$(git rev-parse --git-common-dir 2>/dev/null) || exit 0\n"
        f'if [ -x "$common/hooks/{name}" ]; then exec "$common/hooks/{name}" "$@"; fi\n'
        "exit 0\n"
    )


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _ours(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return False


def install_into(directory: Path) -> Path:
    """Install the hook into *directory*, chaining any hook already there."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / HOOK
    if target.is_symlink():
        raise GitLinkError(f"{target} is a symlink; remove it or install manually")
    if target.exists() and not _ours(target):
        chained = directory / f"{HOOK}{CHAINED}"
        if chained.exists():
            raise GitLinkError(f"{chained} already exists; refusing to overwrite a user hook")
        target.rename(chained)
    _write_executable(target, _script())
    return target


def _configured_hooks_path(cwd: Path, *scope: str) -> str:
    # Read without the hardened -c (which pins core.hooksPath to the null device).
    try:
        return git(cwd, "config", *scope, "--get", "core.hooksPath", hardened=False).strip()
    except GitLinkError:
        return ""


def install_hook(cwd: Path, *, global_: bool = False) -> Path:
    if global_:
        configured = _configured_hooks_path(cwd, "--global")
        if configured:
            return install_into(Path(os.path.expanduser(configured)))
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        directory = base / "opentine" / "git-hooks"
        hook = install_into(directory)
        for name in _CLIENT_HOOKS:
            shim = directory / name
            if not shim.exists() or _ours(shim):
                _write_executable(shim, _shim(name))
        git(cwd, "config", "--global", "core.hooksPath", directory.as_posix(), hardened=False)
        return hook
    configured = _configured_hooks_path(cwd)
    if configured:
        directory = Path(os.path.expanduser(configured))
        if not directory.is_absolute():
            directory = Path(git(cwd, "rev-parse", "--show-toplevel").strip()) / directory
        return install_into(directory)
    common = Path(git(cwd, "rev-parse", "--git-common-dir").strip())
    if not common.is_absolute():
        common = Path(cwd) / common
    return install_into(common / "hooks")


def staged_paths(cwd: Path) -> list[str]:
    out = git(cwd, "diff", "--cached", "--name-only", "--no-textconv", "-z", keep_env=HOOK_ENV)
    return [name for name in out.split("\0") if name][:MAX_STAGED]


def last_commit_time(cwd: Path) -> float:
    try:
        return float(git(cwd, "log", "-1", "--format=%ct", "HEAD", keep_env=HOOK_ENV).strip())
    except (GitLinkError, ValueError):
        return time.time() - FIRST_COMMIT_WINDOW


def matches(written: str, root: Path, staged: str) -> bool:
    """Whether a recorded written path is the staged file *staged* under *root*."""
    written = written.replace("\\", "/").rstrip("/")
    if not written:
        return False
    if os.path.isabs(written) or written.startswith(("/", "~")):  # rooted (3.13+ Windows)
        target = (root / staged).as_posix()
        return os.path.normcase(os.path.expanduser(written)) == os.path.normcase(target)
    clean = written[2:] if written.startswith("./") else written
    return clean == staged or staged.endswith("/" + clean) and "/" in clean


def runs_for_staged(index, root: Path, staged: list[str], since: float) -> list[str]:
    """Run ids whose recorded writes (at or after *since*) touched a staged path."""
    runs: list[str] = []
    horizon = time.time() + FUTURE_SLACK
    for name in staged:
        leaf = name.rsplit("/", 1)[-1]
        for action in find(index, ActionQuery(path=leaf, writes=True, since=since)):
            if action.ts > horizon or action.run_id in runs:
                continue
            if any(matches(path, root, name) for path in action.written):
                runs.append(action.run_id)
                if len(runs) >= MAX_TRAILER_RUNS:
                    return runs
    return runs


def configured_source(cwd: Path) -> tuple[str, str]:
    """``(repo, runs_dir)`` the user configured for the hook, absolute or empty.

    Never the working tree's own ``.tine/`` or ``.tine_runs/``: a cloned project
    controls those, and would choose the runs credited in the user's commits.
    """
    found = []
    for key in (REPO_KEY, RUNS_KEY):
        try:
            value = git(cwd, "config", "--get", key, keep_env=HOOK_ENV).strip()
        except GitLinkError:
            value = ""
        found.append(value if value and os.path.isabs(os.path.expanduser(value)) else "")
    return found[0], found[1]


def record_source(cwd: Path, *, repo: str = "", runs_dir: str = "", global_: bool = False) -> None:
    """Remember where the hook reads runs (``git config tine.repo`` / ``tine.runsDir``)."""
    scope = ("--global",) if global_ else ()
    for key, value in ((REPO_KEY, repo), (RUNS_KEY, runs_dir)):
        if value:
            absolute = Path(os.path.expanduser(value)).resolve().as_posix()
            git(cwd, "config", *scope, key, absolute, hardened=False)


def add_trailers(cwd: Path, message_file: Path, runs: list[str]) -> None:
    args = ["interpret-trailers", "--in-place", "--if-exists", "addIfDifferent"]
    for run in (run for run in runs if RUN_ID.fullmatch(run)):
        args += ["--trailer", f"Tine-Run: {run}"]
    git(cwd, *args, str(message_file), keep_env=HOOK_ENV)


__all__ = [
    "HOOK",
    "MARKER",
    "add_trailers",
    "configured_source",
    "record_source",
    "install_hook",
    "install_into",
    "last_commit_time",
    "matches",
    "runs_for_staged",
    "staged_paths",
]
