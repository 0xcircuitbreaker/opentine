"""0.47 ``tine experts PATH``: agents and humans ranked by attributed lines and verified runs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import cli
from opentine._schemas import validate_output
from opentine._signing_keys import generate_ed25519
from opentine.graph import Run, StepKind

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

AGENT_TEXT = "def agent():\n    return 'written by the agent'\n"


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout


def _as(monkeypatch, name: str) -> None:
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", name)
        monkeypatch.setenv(f"GIT_{role}_EMAIL", f"{name}@example.invalid")


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "commit.gpgsign", "false")
    monkeypatch.chdir(root)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    (root / ".tine_runs").mkdir()
    _as(monkeypatch, "alice")
    (root / "src" / "seed.txt").write_text("seed\n")
    _git(root, "add", "src/seed.txt")
    _git(root, "commit", "-q", "-m", "seed")
    run = Run(id="runexpert1", model_info="claude-opus-5-5")
    target = (root / "src" / "a.py").as_posix()
    run.add_step(StepKind.tool, {"name": "Write", "arguments": {"file_path": target,
                 "content": AGENT_TEXT}}, model_info="claude-opus-5-5")  # fmt: skip
    run.save(root / ".tine_runs" / "runexpert1.tine")
    _as(monkeypatch, "bob")
    (root / "src" / "a.py").write_text(AGENT_TEXT + "# a human line\n")
    _git(root, "add", "src/a.py")
    _git(root, "commit", "-q", "-m", "agent change")
    private, public = generate_ed25519()
    (tmp_path / "k").write_text(private)
    (tmp_path / "k.pub").write_text(public)
    return root


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main([*argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _rows(record: dict) -> list[tuple]:
    return [(e["rank"], e["kind"], e["id"], e["lines"], e["runs"], e["verified_runs"])
            for e in record["experts"]]  # fmt: skip


def test_without_notes_every_line_is_a_humans(repo, capsys):
    code, record = _json(capsys, "experts", "src")
    assert code == 0 and validate_output(record) == []
    assert record["path"] == "src" and record["files"] == 2 and record["total_lines"] == 4
    assert _rows(record) == [(1, "human", "bob@example.invalid", 3, 0, 0),
                             (2, "human", "alice@example.invalid", 1, 0, 0)]  # fmt: skip


def test_signed_notes_rank_the_agent_and_count_its_verified_run(repo, capsys):
    key = (repo.parent / "k").as_posix()
    assert _json(capsys, "git", "attribute", "HEAD", "runexpert1", "--sign-key", key)[0] == 0
    code, record = _json(capsys, "experts", ".")
    assert code == 0 and validate_output(record) == []
    assert _rows(record) == [(1, "agent", "claude-opus-5-5", 2, 1, 1),
                             (2, "human", "alice@example.invalid", 1, 0, 0),
                             (3, "human", "bob@example.invalid", 1, 0, 0)]  # fmt: skip
    assert record["experts"][0]["share"] == 0.5
    other = repo.parent / "other.pub"
    other.write_text(generate_ed25519()[1])
    _, pinned = _json(capsys, "experts", "src/a.py", "--pubkey", other.as_posix(), "--limit", "1")
    assert _rows(pinned) == [(1, "agent", "claude-opus-5-5", 2, 1, 0)]


def test_an_unsigned_note_credits_lines_but_verifies_no_run(repo, capsys):
    assert _json(capsys, "git", "attribute", "HEAD", "runexpert1")[0] == 0
    _, record = _json(capsys, "experts", "src/a.py")
    assert _rows(record)[0] == (1, "agent", "claude-opus-5-5", 2, 1, 0)


def test_a_path_outside_any_repository_is_a_usage_error(repo, capsys):
    code, record = _json(capsys, "experts", os.path.join("..", ".."))
    assert code == 2 and record["error"]["message"].startswith("experts: ")
    assert validate_output(record) == []
