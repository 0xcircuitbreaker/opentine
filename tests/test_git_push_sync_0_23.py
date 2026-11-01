"""0.23 runs travel with the code: ``tine git install-hook --push`` (a pre-push hook)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import opentine
from opentine import _bundle, cli
from opentine._git_push_sync import pushed_commits
from opentine.graph import Run, StepKind
from opentine.repository import Repo

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

WORKTREE = Path(opentine.__file__).resolve().parents[1]
ZERO = "0" * 40


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(WORKTREE)}
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=check
    )


@pytest.fixture
def proj(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("PYTHONPATH", str(WORKTREE))
    _git(tmp_path, "init", "-q", "--bare", "remote")
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for key, value in (("user.name", "T"), ("user.email", "t@example.invalid")):
        _git(root, "config", key, value)
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "remote", "add", "origin", str(tmp_path / "remote"))
    monkeypatch.chdir(root)
    store = Repo.init(tmp_path / "store")
    run = Run(id="runpush1")
    run.add_step(StepKind.done, {"text": "hi"})
    oid = store.put_run(run, ref="heads/main").run_id
    return root, tmp_path / "remote", tmp_path / "store", oid


def _install(root: Path, store: Path, *extra: str) -> Path:
    cli.main(["git", "install-hook", "--push", "--repo", str(store), *extra, "--json"])
    hook = Path(_git(root, "rev-parse", "--git-path", "hooks").stdout.strip())
    hook = (hook if hook.is_absolute() else root / hook) / "pre-push"
    # The hook runs `python -I`; let it import this tree instead of an installed copy.
    hook.write_text(hook.read_text().replace(" -I -m", " -m"))
    return hook


def _commit(root: Path, message: str) -> None:
    (root / "f.txt").write_text(message)
    _git(root, "add", "f.txt")
    _git(root, "commit", "-q", "-m", message)


def _remote_bundle(remote: Path) -> dict:
    if _git(remote, "rev-parse", "-q", "--verify", "refs/tine/bundle", check=False).returncode:
        return {}
    data = subprocess.run(
        ["git", "cat-file", "blob", "refs/tine/bundle:bundle.tine"],
        cwd=remote,
        capture_output=True,
        check=True,
    ).stdout
    return _bundle.verify(data).refs


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="hooks are sh scripts")


@posix_only
def test_git_push_carries_the_trailer_runs_to_the_remote_bundle(proj, capsys):
    root, remote, store, oid = proj
    _install(root, store)
    _commit(root, f"work\n\nTine-Run: {oid}\n")
    done = _git(root, "push", "-q", "origin", "main")
    assert oid in _remote_bundle(remote).values(), done.stderr
    target = Repo.init(root.parent / "friend")
    cli.main(
        ["bundle", "fetch", str(remote), "--as", "origin", "--repo", str(root.parent / "friend")]
    )
    assert target.load_run(oid) is not None
    _commit(root, "second, no trailer")
    _git(root, "push", "-q", "origin", "main")
    assert oid in _remote_bundle(remote).values()  # kept: pushes add, never replace


@posix_only
def test_no_trailers_means_nothing_is_pushed(proj):
    root, remote, store, _ = proj
    _install(root, store)
    _commit(root, "plain commit")
    _git(root, "push", "-q", "origin", "main")
    assert _remote_bundle(remote) == {}


@posix_only
def test_an_unreachable_run_push_warns_but_never_blocks(proj):
    root, remote, store, oid = proj
    _install(root, store)
    _commit(root, f"work\n\nTine-Run: {oid}\n")
    shutil.rmtree(store)  # the runs are gone: the bundle push must fail
    done = _git(root, "push", "origin", "main", check=False)
    assert done.returncode == 0, done.stderr
    assert "tine: warning" in done.stderr
    assert _git(remote, "rev-parse", "main").stdout.strip()


@posix_only
def test_strict_mode_blocks_the_code_push(proj):
    root, remote, store, oid = proj
    _install(root, store, "--strict")
    _commit(root, f"work\n\nTine-Run: {oid}\n")
    shutil.rmtree(store)
    done = _git(root, "push", "origin", "main", check=False)
    assert done.returncode != 0
    assert "tine: error" in done.stderr
    assert _git(remote, "rev-parse", "--verify", "-q", "main", check=False).returncode


@posix_only
def test_an_existing_pre_push_hook_is_chained_and_sees_stdin(proj):
    root, remote, store, oid = proj
    hooks = Path(_git(root, "rev-parse", "--git-path", "hooks").stdout.strip())
    hooks = hooks if hooks.is_absolute() else root / hooks
    hooks.mkdir(parents=True, exist_ok=True)
    mine = hooks / "pre-push"
    mine.write_text('#!/bin/sh\ncat > "$(git rev-parse --show-toplevel)/../chained.txt"\n')
    mine.chmod(0o755)
    _install(root, store)
    assert (hooks / "pre-push.tine-chained").exists()
    _commit(root, f"work\n\nTine-Run: {oid}\n")
    _git(root, "push", "-q", "origin", "main")
    assert "refs/heads/main" in (root.parent / "chained.txt").read_text()
    assert oid in _remote_bundle(remote).values()


def test_the_protocol_reader_skips_deletions_and_bad_lines(proj):
    root, *_ = proj
    _commit(root, "one")
    head = _git(root, "rev-parse", "HEAD").stdout.strip()
    lines = (
        f"refs/heads/main {head} refs/heads/main {ZERO}\nrefs/heads/x {ZERO} refs/heads/x {head}\n"
    )
    assert pushed_commits(root, lines) == [head]
    assert pushed_commits(root, f"refs/heads/main {head} refs/heads/main {head}\n") == []
    assert pushed_commits(root, "garbage\n") == []
