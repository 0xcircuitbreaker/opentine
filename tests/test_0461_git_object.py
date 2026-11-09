"""0.46.1: the git object check (SPEC 4.18) against objects real git wrote.

Every object of a small repository in each object format (SHA-1 and SHA-256)
must match its id in Python and the pyz, and link exactly what git says it
links; one changed byte is ``git-object.mismatch``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import _git_object
from opentine._pyz import _project as pyz

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is not installed")


def _git(repo: Path, *argv: str, text: bool = True):
    return subprocess.run([GIT, "-C", repo.as_posix(), *argv], check=True,  # type: ignore[list-item]
                          capture_output=True, text=text).stdout  # fmt: skip


def _repo(tmp_path: Path, monkeypatch, object_format: str) -> Path:
    for name, value in (
        ("GIT_AUTHOR_NAME", "t"),
        ("GIT_AUTHOR_EMAIL", "t@example.com"),
        ("GIT_COMMITTER_NAME", "t"),
        ("GIT_COMMITTER_EMAIL", "t@example.com"),
    ):
        monkeypatch.setenv(name, value)  # fmt: skip
    repo = tmp_path / object_format
    subprocess.run([GIT, "init", "-q", f"--object-format={object_format}", repo.as_posix()],  # type: ignore[list-item]
                   check=True, capture_output=True)  # fmt: skip
    (repo / "a.txt").write_text("hello\n", encoding="utf-8")
    (repo / "d").mkdir()
    (repo / "d" / "b.txt").write_text("nested\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "first")
    (repo / "a.txt").write_text("hello again\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "second")
    _git(repo, "tag", "-a", "v1", "-m", "tag")
    return repo


@needs_git
@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("checker", ["python", "pyz"])
def test_every_object_of_a_real_repository_matches_its_id(tmp_path, monkeypatch, object_format,
                                                          checker):  # fmt: skip
    try:
        repo = _repo(tmp_path, monkeypatch, object_format)
    except subprocess.CalledProcessError:
        pytest.skip(f"this git cannot write {object_format} repositories")
    check = _git_object.check if checker == "python" else pyz.git_object_check
    rows = _git(repo, "cat-file", "--batch-all-objects", "--batch-check").splitlines()
    assert len(rows) >= 8
    for row in rows:
        oid, kind, _size = row.split()
        data = _git(repo, "cat-file", kind, oid, text=False)
        found = check(kind, data, oid)
        assert found["object_format"] == object_format and found["state"] == "matches"
        if kind == "commit":
            parents = _git(repo, "rev-list", "--parents", "-n", "1", oid).split()[1:]
            assert found["links"] == [_git(repo, "rev-parse", f"{oid}^{{tree}}").strip(), *parents]
        if kind == "tree":
            listed = [line.split()[2] for line in _git(repo, "ls-tree", oid).splitlines()]
            assert found["links"] == listed
        with pytest.raises(ValueError) as caught:
            check(kind, data + b"x", oid)
        assert caught.value.code == "git-object.mismatch"  # type: ignore[attr-defined]


def test_commit_headers_are_read_in_order():
    import hashlib

    from opentine._git_object import GitObjectError, check

    tree = "a" * 40
    parent = "b" * 40
    for data, ok in (
        (f"tree {tree}\nparent {parent}\nauthor x\n\nm\n".encode(), [tree, parent]),
        (f"tree {tree}\nauthor x\nparent {parent}\n\nm\n".encode(), [tree]),
        (f"junk\ntree {tree}\n\nm\n".encode(), None),
    ):
        oid = hashlib.sha1(b"commit %d\0" % len(data) + data).hexdigest()
        if ok is None:
            with pytest.raises(GitObjectError):
                check("commit", data, oid)
        else:
            assert check("commit", data, oid)["links"] == ok
