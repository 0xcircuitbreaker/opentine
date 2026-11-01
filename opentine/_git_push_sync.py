"""``tine git install-hook --push``: runs travel with the commits that name them.

The ``pre-push`` hook reads git's pre-push protocol on stdin (one
``<local ref> <local sha> <remote ref> <remote sha>`` line per pushed ref),
walks the commits being pushed, collects their ``Tine-Run:`` trailers and adds
those runs to ``refs/tine/bundle`` on the *same* remote with
:func:`opentine._bundle_git.push_refs`. ``tine bundle fetch REMOTE`` is the pull
side.

A failure to push runs only warns on stderr and never blocks the code push,
unless the hook was installed with ``--strict``. With no trailers it does
nothing. An existing ``pre-push`` hook is chained exactly like the
``prepare-commit-msg`` one (kept as ``pre-push.tine-chained``, run first).
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from opentine._git_link import HOOK_ENV, RUN_ID, git, run_ids
from opentine._git_link_hook import CHAINED, OURS, configured_source

HOOK = "pre-push"
#: Commits walked per pushed ref; a new branch (all-zero remote sha) stops here.
MAX_COMMITS = 1000
MAX_RUNS = 200
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def script(*, strict: bool = False) -> str:
    python = Path(sys.executable).as_posix().replace('"', '\\"')
    flag = " --strict" if strict else ""
    tail = "|| exit 1" if strict else "|| true"
    feed = "printf '%s' \"$input\" | "
    return (
        "#!/bin/sh\n"
        f"{OURS}{HOOK} (managed by `tine git install-hook --push`; safe to delete)\n"
        # Keep stdin (the pushed refs) for every hook in the chain, newline included.
        "input=$(cat; echo x); input=${input%x}\n"
        f'if [ -x "$0{CHAINED}" ]; then {feed}"$0{CHAINED}" "$@" || exit $?; fi\n'
        "common=$(git rev-parse --git-common-dir 2>/dev/null)\n"
        f'own="$common/hooks/{HOOK}"\n'
        f'if [ -n "$common" ] && [ -x "$own" ] && ! grep -q "{OURS}" "$own" 2>/dev/null; '
        f'then {feed}"$own" "$@" || exit $?; fi\n'
        f'{feed}"{python}" -I -m opentine.cli git push-runs{flag} "$@" >/dev/null {tail}\n'
        "exit 0\n"
    )


def pushed_commits(cwd: Path, stdin: str) -> list[str]:
    """Commits being pushed, per git's pre-push protocol, capped per ref."""
    commits: list[str] = []
    for line in stdin.splitlines():
        parts = line.split()
        if len(parts) != 4 or not (_SHA.fullmatch(parts[1]) and _SHA.fullmatch(parts[3])):
            continue
        local, remote = parts[1], parts[3]
        if not local.strip("0"):
            continue  # a branch deletion pushes no commits
        cap = f"--max-count={MAX_COMMITS}"
        try:
            if not remote.strip("0"):
                raise ValueError("new branch")
            out = git(cwd, "rev-list", cap, f"{remote}..{local}", keep_env=HOOK_ENV)
        except Exception:  # noqa: BLE001 - new branch, or a remote sha we lack
            out = git(cwd, "rev-list", cap, local, "--not", "--remotes", keep_env=HOOK_ENV)
        commits += [sha for sha in out.split() if sha not in commits]
    return commits


def trailer_runs_in(cwd: Path, commits: list[str]) -> list[str]:
    runs: list[str] = []
    for sha in commits:
        body = git(cwd, "log", "-1", "--format=%B", sha, keep_env=HOOK_ENV)
        runs += [run for run in run_ids(body) if run not in runs]
    return runs[:MAX_RUNS]


def _ref(oid: str) -> str:
    return f"heads/tine-run/{oid.rsplit(':', 1)[-1][:16]}"


def sync(cwd: Path, remote: str, stdin: str, *, timeout: float = 120.0) -> dict:
    """Push the runs named by trailers in the pushed commits to *remote*'s bundle."""
    runs = trailer_runs_in(cwd, pushed_commits(cwd, stdin))
    if not runs:
        return {"runs": [], "pushed": []}
    from opentine import _bundle_git
    from opentine._git_link_runs import open_catalog
    from opentine.repository import Repo

    repo_path, runs_dir = configured_source(cwd)
    if not repo_path and not (runs_dir and Path(runs_dir).is_dir()):
        raise ValueError("no runs source configured (git config tine.repo or tine.runsDir)")
    catalog = open_catalog(repo_path or None, Path(runs_dir))
    with tempfile.TemporaryDirectory(prefix="tine-push-") as tmp:
        repo = catalog.repo or Repo.init(Path(tmp) / "repo")
        refs: dict[str, str] = {}
        missing: list[str] = []
        for name in runs:
            try:
                run = catalog.load(name)
            except Exception:  # noqa: BLE001 - a trailer for a run not held here
                missing.append(name)
                continue
            if catalog.repo is not None:
                oid = name if name.startswith("run:") else catalog.canonical(name)
            else:
                oid = repo.put_run(run).run_id
            refs[_ref(oid)] = oid
        if not refs:
            raise KeyError(f"none of the trailer runs are held locally: {', '.join(missing)}")
        result = _bundle_git.push_refs(repo, remote, refs, timeout=timeout)
    return {"runs": runs, "missing": missing, **result}


def cmd_push_runs(args: argparse.Namespace) -> None:
    """Called by the pre-push hook; exits non-zero only in strict mode."""
    remote = args.url or args.remote
    try:
        result = sync(Path.cwd(), remote, sys.stdin.read())
    except Exception as exc:  # noqa: BLE001 - a run push never breaks a code push
        level = "error" if args.strict else "warning"
        print(f"tine: {level}: could not push runs to {remote}: {exc}", file=sys.stderr)
        if args.strict:
            raise SystemExit(1) from None
        return
    if result.get("missing"):
        names = ", ".join(n for n in result["missing"] if RUN_ID.fullmatch(n))
        level = "error" if args.strict else "warning"
        print(f"tine: {level}: runs not held locally, not pushed: {names}", file=sys.stderr)
        if args.strict:
            raise SystemExit(1)
    if result.get("pushed"):
        print(f"tine: pushed {len(result['pushed'])} run(s) to {remote}", file=sys.stderr)


def add_push_runs_parser(git_sub) -> None:
    parser = git_sub.add_parser("push-runs", help=argparse.SUPPRESS)
    parser.add_argument("remote")
    parser.add_argument("url", nargs="?", default="")
    parser.add_argument("--strict", action="store_true")


__all__ = ["HOOK", "add_push_runs_parser", "cmd_push_runs", "pushed_commits", "script", "sync"]
