"""0.35: rewind refuses control directories and follows no link; canon copies no link mode."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from opentine import Run
from opentine._canon import atomic_write_text
from opentine._rewind import RewindError
from opentine._rewind_write import write_confined
from opentine.cli import main
from opentine.core import StepKind

posix = pytest.mark.skipif(sys.platform == "win32", reason="symlinks and modes are POSIX here")


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "work"
    root.mkdir()
    monkeypatch.chdir(root)
    run = Run(user_prompt="plant hooks")
    for path in (".git/hooks/pre-commit", ".github/workflows/ci.yml", "src/ok.py"):
        run.add_step(
            StepKind.tool,
            inputs={"name": "Write", "arguments": {"file_path": path, "content": "evil\n"}},
            outputs={},
        )
    saved = tmp_path / "r.tine"
    run.save(saved)
    return root, saved


def _rewind(capsys, *argv: str) -> dict:
    try:
        main(["rewind", *argv, "--json"])
    except SystemExit:
        pass
    return json.loads(capsys.readouterr().out)


def test_control_directories_are_refused_by_default(tree, capsys):
    root, saved = tree
    payload = _rewind(capsys, f"{saved}@2", "--root", str(root), "--apply", "--force")
    refused = sorted(row["path"] for row in payload["refused"])
    assert refused == [".git/hooks/pre-commit", ".github/workflows/ci.yml"]
    assert not (root / ".git").exists() and not (root / ".github").exists()
    assert (root / "src/ok.py").read_bytes() == b"evil\n"


def test_the_override_flag_restores_control_directories(tree, capsys):
    root, saved = tree
    payload = _rewind(
        capsys, f"{saved}@2", "--root", str(root), "--apply", "--allow-control-dirs", "--force"
    )
    assert payload["refused"] == []
    assert (root / ".git/hooks/pre-commit").read_bytes() == b"evil\n"


@posix
def test_write_confined_follows_no_swapped_in_directory_link(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "sub").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RewindError):
        write_confined(root, root / "sub" / "f.txt", b"x")
    assert not (outside / "f.txt").exists()


@posix
def test_write_confined_refuses_a_file_link_and_creates_parents(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    (root / "f.txt").symlink_to(victim)
    with pytest.raises(RewindError):
        write_confined(root, root / "f.txt", b"x")
    assert victim.read_bytes() == b"keep"
    write_confined(root, root / "new" / "g.txt", b"y")
    assert (root / "new" / "g.txt").read_bytes() == b"y"


@posix
def test_atomic_write_text_does_not_copy_a_link_targets_mode(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("secret")
    os.chmod(victim, 0o644)
    link = tmp_path / "out.tine"
    link.symlink_to(victim)
    atomic_write_text(link, "new")
    assert not link.is_symlink()
    assert stat.S_IMODE(os.lstat(link).st_mode) != 0o644
    assert victim.read_text() == "secret"
    link.chmod(0o640)
    atomic_write_text(link, "again")
    assert stat.S_IMODE(os.lstat(link).st_mode) == 0o640
