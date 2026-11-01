"""0.22: ``tine rewind RUN[@STEP]`` restores what a run changed, only when recorded."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run
from opentine.cli import main
from opentine.core import StepKind


def _tool(run: Run, name: str, arguments: dict) -> None:
    run.add_step(StepKind.tool, inputs={"name": name, "arguments": arguments}, outputs={})


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "work"
    root.mkdir()
    monkeypatch.chdir(root)
    run = Run(user_prompt="edit things")
    run.add_step(StepKind.think, inputs={"text": "plan"})
    _tool(run, "Write", {"file_path": "a.py", "content": "v1\n"})  # step 1
    _tool(run, "Edit", {"file_path": "a.py", "old_string": "v1", "new_string": "v2"})
    _tool(run, "Bash", {"command": "echo hi > b.txt"})  # step 3
    _tool(run, "Edit", {"file_path": "c.py", "old_string": "old", "new_string": "new"})
    _tool(run, "Write", {"file_path": "../escape.txt", "content": "nope\n"})  # step 5
    saved = tmp_path / "r.tine"
    run.save(saved)
    (root / "a.py").write_text("v2\n")
    (root / "b.txt").write_text("hi\n")
    (root / "c.py").write_text("x new y\n")
    return root, saved


def _rewind(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        main(["rewind", *argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _paths(payload: dict, status: str) -> list[str]:
    return [row["path"] for row in payload[status]]


def test_dry_run_lists_changes_and_writes_nothing(tree, capsys):
    root, saved = tree
    code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root))
    assert code == 0 and payload["command"] == "rewind" and payload["dry_run"] is True
    assert sorted(_paths(payload, "restore")) == ["a.py", "c.py"]
    assert not payload["applied"]
    assert (root / "a.py").read_text() == "v2\n"


def test_apply_restores_recorded_and_undone_edits(tree, capsys):
    root, saved = tree
    code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root), "--apply")
    assert code == 0 and payload["applied"] is True
    assert (root / "a.py").read_text() == "v1\n"
    assert (root / "c.py").read_text() == "x old y\n"
    assert (root / "b.txt").read_text() == "hi\n"
    _code, again = _rewind(capsys, f"{saved}@1", "--root", str(root))
    assert sorted(_paths(again, "unchanged")) == ["a.py", "c.py"]


def test_user_edits_are_a_conflict_unless_forced(tree, capsys):
    root, saved = tree
    (root / "a.py").write_text("mine\n")
    code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root), "--apply")
    assert code == 1 and payload["applied"] is False
    assert _paths(payload, "conflict") == ["a.py"]
    assert (root / "a.py").read_text() == "mine\n"
    assert (root / "c.py").read_text() == "x new y\n"  # nothing written at all
    code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root), "--apply", "--force")
    assert code == 0 and (root / "a.py").read_text() == "v1\n"


def test_unrecoverable_files_are_listed_with_a_reason(tree, capsys):
    root, saved = tree
    _code, payload = _rewind(capsys, str(saved), "--root", str(root))
    reasons = {row["path"]: row["reason"] for row in payload["unrecoverable"]}
    assert "b.txt" in reasons and "without recording" in reasons["b.txt"]
    assert "a.py" in reasons and "not recorded" in reasons["a.py"]  # created whole
    assert _paths(payload, "restore") == ["c.py"]


def test_paths_outside_the_root_are_refused(tree, capsys):
    root, saved = tree
    code, payload = _rewind(capsys, f"{saved}@5", "--root", str(root), "--apply")
    assert code == 0 and len(payload["refused"]) == 1
    assert "outside" in payload["refused"][0]["reason"]
    assert not (root.parent / "escape.txt").exists()


def test_a_symlinked_path_is_refused(tree, capsys, tmp_path):
    root, saved = tree
    (root / "a.py").unlink()
    (root / "a.py").symlink_to(tmp_path / "elsewhere.py")
    _code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root), "--apply")
    assert "a.py" in _paths(payload, "refused")
    assert not (tmp_path / "elsewhere.py").exists()


def test_json_and_human_output_agree(tree, capsys):
    root, saved = tree
    _code, payload = _rewind(capsys, f"{saved}@1", "--root", str(root))
    assert set(payload) >= {"run", "step", "root", "restore", "conflict", "unrecoverable"}
    main(["rewind", f"{saved}@1", "--root", str(root)])
    out = capsys.readouterr().out
    assert "Would restore: a.py" in out and "Cannot recover from the run: b.txt" in out
    assert Path(payload["root"]) == root.resolve()
