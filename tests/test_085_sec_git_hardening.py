"""Security pass: git run on a user's checkout never runs the repo's own commands."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed"),
    pytest.mark.skipif(sys.platform == "win32", reason="the planted hooks are POSIX shell"),
]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _hostile(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n")
    (repo / "f.txt").write_text("one\n")
    (repo / ".gitattributes").write_text("*.txt diff=pwn\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "c")
    (repo / "f.txt").write_text("two\n")
    _git(repo, "config", "core.fsmonitor", f"touch '{repo}/FSMON_RAN'; false #")
    _git(repo, "config", "diff.pwn.textconv", f"sh -c 'touch {repo}/TEXTCONV_RAN; cat \"$0\"'")
    return repo


def _ran(repo: Path) -> list[str]:
    return sorted(p.name for p in repo.iterdir() if p.name.endswith("_RAN"))


def test_code_graph_files_never_runs_a_repo_fsmonitor(tmp_path: Path) -> None:
    from opentine import _code_graph

    repo = _hostile(tmp_path)
    assert "a.py" in _code_graph.files(repo)
    assert _ran(repo) == []


def test_review_context_never_runs_a_repo_fsmonitor_or_textconv(tmp_path: Path) -> None:
    from opentine import _review_run

    repo = _hostile(tmp_path)
    assert "two" in _review_run.context(repo, None, None)
    assert _ran(repo) == []


def test_init_git_top_never_runs_a_repo_fsmonitor(tmp_path: Path) -> None:
    from opentine import _init_auto

    repo = _hostile(tmp_path)
    assert _init_auto._git_top(repo) is not None
    assert _ran(repo) == []
