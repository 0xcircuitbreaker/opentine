"""0.42 line attribution: signed notes under refs/notes/tine that survive rewrites.

Real git in temporary repositories: ``commit --amend`` and ``rebase -i`` must
carry the note to the rewritten commit (``notes.rewriteRef``), and the copied
record must still verify against the new commit's lines.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import cli
from opentine._agent_trace import VENDOR_KEY
from opentine._signing_keys import generate_ed25519
from opentine.graph import Run, StepKind

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

AGENT_TEXT = "def agent():\n    return 'written by the agent'\n"


def _git(cwd: Path, *args: str, **env: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=cwd, env={**os.environ, **env}, capture_output=True, text=True,
        check=True,
    )  # fmt: skip
    return done.stdout


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    for key, value in (("user.name", "T"), ("user.email", "t@example.invalid")):
        _git(root, "config", key, value)
    _git(root, "config", "commit.gpgsign", "false")
    monkeypatch.chdir(root)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    (root / ".tine_runs").mkdir()
    (root / "seed.txt").write_text("seed\n")
    _git(root, "add", "seed.txt")
    _git(root, "commit", "-q", "-m", "seed")
    run = Run(id="runattr01", model_info="claude-opus-5-5")
    run.add_step(
        StepKind.tool,
        {"name": "Write", "arguments": {"file_path": str(root / "a.py"), "content": AGENT_TEXT}},
        model_info="claude-opus-5-5",
    )
    run.save(root / ".tine_runs" / "runattr01.tine")
    (root / "a.py").write_text(AGENT_TEXT + "# a human line\n")
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "agent change")
    private, public = generate_ed25519()
    (tmp_path / "k").write_text(private)
    (tmp_path / "k.pub").write_text(public)
    return root


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main([*argv, "--json"] if "--format" not in argv else list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _attribute(repo: Path, capsys) -> dict:
    key = str(repo.parent / "k")
    return _json(capsys, "git", "attribute", "HEAD", "runattr01", "--sign-key", key)[1]


def _verified(repo: Path, capsys) -> dict:
    code, shown = _json(
        capsys, "git", "attribution", "HEAD", "--pubkey", str(repo.parent / "k.pub")
    )
    assert code == 0, shown
    return shown


def test_attribute_signs_lines_and_configures_rewrite_ref(repo, capsys) -> None:
    result = _attribute(repo, capsys)
    assert result["command"] == "git attribute" and result["signed"] is True
    assert (result["lines_added"], result["lines_attributed"]) == (3, 2)
    assert result["rewrite_ref_configured"] is True and result["rewrite_ref_added"] is True
    assert "refs/notes/tine" in _git(repo, "config", "--get-all", "notes.rewriteRef")
    shown = _verified(repo, capsys)
    ranges = shown["attribution"]["files"][0]["ranges"]
    assert [(r["start_line"], r["end_line"], r["run"]) for r in ranges] == [(1, 2, "runattr01")]
    assert shown["verification"]["signature"]["valid"] is True
    assert shown["verification"]["content_matches"] is True
    # The existing commit -> run link reads the same note.
    assert "Tine-Run: runattr01" in _git(repo, "notes", "--ref=refs/notes/tine", "show", "HEAD")


def test_note_survives_commit_amend(repo, capsys) -> None:
    _attribute(repo, capsys)
    before = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "commit", "-q", "--amend", "-m", "agent change, reworded")
    assert _git(repo, "rev-parse", "HEAD").strip() != before
    shown = _verified(repo, capsys)
    assert shown["verification"]["content_matches"] is True


def test_note_survives_interactive_rebase(repo, capsys) -> None:
    _attribute(repo, capsys)
    (repo / "later.txt").write_text("later\n")
    _git(repo, "add", "later.txt")
    _git(repo, "commit", "-q", "-m", "later")
    # Reorder the two commits with rebase -i: both are rewritten.
    # awk, not tac: macOS has no tac.
    script = (
        'awk \'/^pick/ {l[n++] = $0} END {while (n) print l[--n]}\' "$1" > "$1.t" && mv "$1.t" "$1"'
    )
    editor = repo.parent / "editor.sh"
    editor.write_text(f"#!/bin/sh\n{script}\n")
    editor.chmod(0o755)
    _git(repo, "rebase", "-q", "-i", "HEAD~2", GIT_SEQUENCE_EDITOR=str(editor))
    assert _git(repo, "log", "-1", "--format=%s").strip() == "agent change"
    shown = _verified(repo, capsys)
    assert shown["verification"]["content_matches"] is True


def test_tampered_note_fails_verification(repo, capsys) -> None:
    _attribute(repo, capsys)
    note = _git(repo, "notes", "--ref=refs/notes/tine", "show", "HEAD")
    forged = note.replace('"run":"runattr01"', '"run":"runforged"')
    _git(repo, "notes", "--ref=refs/notes/tine", "add", "-f", "-m", forged, "HEAD")
    code, shown = _json(capsys, "git", "attribution", "HEAD", "--verify")
    assert code == 1 and shown["verification"]["signature"]["valid"] is False


def test_agent_trace_output_shape(repo, capsys) -> None:
    _attribute(repo, capsys)
    _, record = _json(capsys, "git", "attribution", "HEAD", "--format", "agent-trace")
    sha = _git(repo, "rev-parse", "HEAD").strip()
    assert set(record) == {"version", "id", "timestamp", "vcs", "tool", "files", "metadata"}
    assert record["version"] == "0.1" and record["vcs"] == {"type": "git", "revision": sha}
    conversation = record["files"][0]["conversations"][0]
    assert record["files"][0]["path"] == "a.py"
    assert conversation["contributor"] == {"type": "ai", "model_id": "claude-opus-5-5"}
    assert set(conversation["ranges"][0]) == {"start_line", "end_line", "content_hash"}
    assert record["metadata"][VENDOR_KEY]["ranges"][0]["run"] == "runattr01"


def test_stats_ai_share(repo, capsys) -> None:
    code, empty = _json(capsys, "stats", "--ai-share")
    assert code == 0 and empty["ai_lines"] == 0 and empty["total_lines"] == 4
    _attribute(repo, capsys)
    _, report = _json(capsys, "stats", "--ai-share")
    assert report["command"] == "stats" and report["mode"] == "ai-share"
    assert (report["ai_lines"], report["total_lines"]) == (2, 4)
    assert report["ai_share"] == 0.5 and report["by_model"] == {"claude-opus-5-5": 2}


def test_attribute_without_runs_refuses(repo, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["git", "attribute", "HEAD"])
    assert exc.value.code == 2
