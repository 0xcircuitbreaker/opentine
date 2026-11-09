"""0.46: actions/preserve-notes carries refs/notes/tine through squash and rebase merges."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import _ci_notes

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which("sh")  # a POSIX shell, as the action runner has
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(autouse=True)
def _identity(monkeypatch):
    for kind in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{kind}_NAME", "CI Test")
        monkeypatch.setenv(f"GIT_{kind}_EMAIL", "ci@example.test")


def _git(cwd: Path, *args: str, stdin: str | None = None) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, input=stdin, capture_output=True, text=True,
                          check=True)  # fmt: skip
    return done.stdout.strip()


def _commit(repo: Path, name: str, text: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", f"add {name}")
    return _git(repo, "rev-parse", "HEAD")


def _note(repo: Path, sha: str, text: str) -> None:
    _git(repo, "notes", "--ref=refs/notes/tine", "add", "-m", text, sha)


def _read(repo: Path, sha: str) -> str | None:
    done = subprocess.run(["git", "notes", "--ref=refs/notes/tine", "show", sha], cwd=repo,
                          capture_output=True, text=True)  # fmt: skip
    return done.stdout if done.returncode == 0 else None


@pytest.fixture
def pr(tmp_path: Path):
    """main with one commit, and a two-commit PR branch whose commits carry notes."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    base = _commit(repo, "readme.txt", "hello\n")
    _git(repo, "checkout", "-q", "-b", "feature")
    one = _commit(repo, "a.txt", "a\n")
    two = _commit(repo, "b.txt", "b\n")
    _note(repo, one, "Tine-Run: run:" + "1" * 64)
    _note(repo, two, "Tine-Run: run:" + "2" * 64)
    _git(repo, "checkout", "-q", "main")
    _commit(repo, "other.txt", "moved on\n")  # main moved, so a rebase rewrites ids
    return repo, base, one, two


def test_squash_merge_copies_every_note_onto_the_squash_commit(pr):
    repo, base, one, two = pr
    _git(repo, "merge", "-q", "--squash", "feature")
    _git(repo, "commit", "-q", "-m", "squashed")
    merged = _git(repo, "rev-parse", "HEAD")
    plan = _ci_notes.plan(repo, base, two, merged)
    assert plan == {"mode": "squash", "moves": [[merged, [one, two]]]}
    assert _ci_notes.apply(repo, plan["moves"])[0]["state"] == "written"
    assert _read(repo, merged) == f"Tine-Run: run:{'1' * 64}\nTine-Run: run:{'2' * 64}\n"
    again = _ci_notes.plan(repo, base, two, merged)
    assert _ci_notes.apply(repo, again["moves"])[0]["state"] == "kept"  # idempotent


def test_rebase_merge_moves_each_note_to_its_rewritten_commit(pr):
    repo, base, one, two = pr
    _git(repo, "checkout", "-q", "-b", "landed", "main")
    _git(repo, "cherry-pick", one, two)
    merged = _git(repo, "rev-parse", "HEAD")
    first = _git(repo, "rev-parse", "HEAD~1")
    assert merged != two
    plan = _ci_notes.plan(repo, base, two, merged)
    assert plan["mode"] == "rebase"
    assert plan["moves"] == [[first, [one]], [merged, [two]]]
    _ci_notes.apply(repo, plan["moves"])
    assert _read(repo, first) == f"Tine-Run: run:{'1' * 64}\n"
    assert _read(repo, merged) == f"Tine-Run: run:{'2' * 64}\n"


def test_merge_commits_and_unnoted_prs_are_left_alone(pr):
    repo, base, one, two = pr
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")
    merged = _git(repo, "rev-parse", "HEAD")
    assert _ci_notes.plan(repo, base, two, merged) == {"mode": "merge", "moves": []}
    _git(repo, "notes", "--ref=refs/notes/tine", "remove", one, two)
    _git(repo, "reset", "-q", "--hard", "HEAD~1")
    _git(repo, "merge", "-q", "--squash", "feature")
    _git(repo, "commit", "-q", "-m", "squashed")
    head = _git(repo, "rev-parse", "HEAD")
    assert _ci_notes.plan(repo, base, two, head) == {"mode": "none", "moves": []}


def test_a_different_existing_note_is_never_overwritten(pr):
    repo, base, one, two = pr
    _git(repo, "merge", "-q", "--squash", "feature")
    _git(repo, "commit", "-q", "-m", "squashed")
    merged = _git(repo, "rev-parse", "HEAD")
    _note(repo, merged, "hand written")
    plan = _ci_notes.plan(repo, base, two, merged)
    assert _ci_notes.apply(repo, plan["moves"])[0]["state"] == "conflict"
    assert _read(repo, merged) == "hand written\n"
    with pytest.raises(Exception):
        _ci_notes.plan(repo, "--upload-pack=x", two, merged)


@pytest.mark.skipif(SH is None, reason="no POSIX sh")
def test_the_action_script_carries_and_pushes_to_a_remote(pr, tmp_path: Path):
    repo, base, one, two = pr
    remote = tmp_path / "remote.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    _git(repo, "remote", "add", "origin", remote.as_posix())
    _git(repo, "push", "-q", "origin", "main", "feature", "refs/notes/tine")
    _git(repo, "update-ref", "-d", "refs/notes/tine")  # the CI checkout starts without notes
    _git(repo, "merge", "-q", "--squash", "feature")
    _git(repo, "commit", "-q", "-m", "squashed")
    merged = _git(repo, "rev-parse", "HEAD")
    env = {**os.environ, "BASE": base, "HEAD": two, "MERGED": merged,
           "PYTHON": Path(sys.executable).as_posix(), "PYTHONPATH": ROOT.as_posix()}  # fmt: skip
    script = (ROOT / "actions" / "preserve-notes.sh").as_posix()
    done = subprocess.run([SH, script], cwd=repo, env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["mode"] == "squash"
    remote_note = _git(remote, "notes", "--ref=refs/notes/tine", "show", merged)
    assert remote_note.splitlines() == [f"Tine-Run: run:{'1' * 64}", f"Tine-Run: run:{'2' * 64}"]
    bad = subprocess.run([SH, script], cwd=repo, env={**env, "NOTES_REF": "refs/heads/main"},
                         capture_output=True, text=True)  # fmt: skip
    assert bad.returncode == 2
