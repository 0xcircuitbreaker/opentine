"""0.45.x: Git AI Standard v3 notes (``authorship/3.0.0``) and ``tine-ai-share/1``.

Real git in temporary repositories. The identity git needs to write notes is
set through ``GIT_AUTHOR_*``/``GIT_COMMITTER_*`` (CI runners have none).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._git_ai_convert import from_attribution
from opentine._git_ai_notes import GitAiFormatError, format_ranges, parse, parse_ranges, render
from opentine._signing_keys import generate_ed25519

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

IDENTITY = {
    "GIT_AUTHOR_NAME": "Ada", "GIT_AUTHOR_EMAIL": "ada@example.invalid",
    "GIT_COMMITTER_NAME": "Ada", "GIT_COMMITTER_EMAIL": "ada@example.invalid",
}  # fmt: skip
S, T, H = "s_" + "a" * 14, "t_" + "b" * 14, "h_" + "c" * 14
LEGACY = "0123456789abcdef"
AGENT = {"tool": "claude", "id": "conv-1", "model": "claude-opus-5-5"}
META = {
    "schema_version": "authorship/3.0.0",
    "git_ai_version": "1.4.0",
    "base_commit_sha": "0" * 40,
    "prompts": {LEGACY: {"agent_id": {"tool": "cursor", "id": "c2", "model": "gpt-x"},
                         "total_additions": 1, "total_deletions": 0, "accepted_lines": 1,
                         "overriden_lines": 0}},
    "sessions": {S: {"agent_id": AGENT}},
    "humans": {H: {"author": "Ada <ada@example.invalid>"}},
}  # fmt: skip


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args], cwd=cwd,
        env={**os.environ, **IDENTITY}, capture_output=True, text=True, check=True,
    )  # fmt: skip
    return done.stdout


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main([*argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    for name, value in IDENTITY.items():
        monkeypatch.setenv(name, value)
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "seed.txt").write_text("seed\n")
    _git(root, "add", "seed.txt")
    _git(root, "commit", "-q", "-m", "seed")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 7)))
    (root / "my file.txt").write_text("legacy\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "agent change")
    monkeypatch.chdir(root)
    private, public = generate_ed25519()
    (tmp_path / "k").write_text(private)
    (tmp_path / "k.pub").write_text(public)
    return root


def _their_note(root: Path) -> str:
    files = {"src/app.py": {f"{S}::{T}": [1, 2, 3, 5], H: [4]}, "my file.txt": {LEGACY: [1]}}
    text = render(files, META)
    _git(root, "notes", "--ref=refs/notes/ai", "add", "-f", "-m", text.rstrip("\n"), "HEAD")
    return text


def test_ranges_and_note_text_round_trip() -> None:
    assert parse_ranges("1-3,5,7-8") == [1, 2, 3, 5, 7, 8]
    assert format_ranges([8, 1, 2, 3, 5, 7]) == "1-3,5,7-8"
    text = render({"a b.py": {f"{S}::{T}": [1, 2], H: [3]}, "x.py": {"abcdef0": [2]}}, META)
    assert text.splitlines()[:4] == ['"a b.py"', f"  {H} 3", f"  {S}::{T} 1-2", "x.py"]
    parsed = parse(text)
    assert parsed["files"]["a b.py"] == {f"{S}::{T}": [1, 2], H: [3]}
    assert render(parsed["files"], parsed["metadata"]) == text
    assert parse("---\n" + json.dumps(META))["files"] == {}


@pytest.mark.parametrize(
    "text",
    [
        "a.py\n  s_x 1\n---\n{}",
        "a.py\n  " + LEGACY + " 0\n---\n" + json.dumps(META),
        "a.py\n  " + LEGACY + " 3-1\n---\n" + json.dumps(META),
        "  " + LEGACY + " 1\n---\n" + json.dumps(META),
        "a.py\n  " + LEGACY + " 1\n" + json.dumps(META),
        "a.py\n---\n" + json.dumps({**META, "schema_version": "authorship/2.0.0"}),
        "a.py\n---\n" + json.dumps({"schema_version": "authorship/3.0.0"}),
    ],
)
def test_malformed_notes_are_refused(text: str) -> None:
    with pytest.raises(GitAiFormatError):
        parse(text)


def test_import_signs_and_export_round_trips(repo, capsys) -> None:
    original = parse(_their_note(repo))
    key = str(repo.parent / "k")
    code, imported = _json(capsys, "import", str(repo), "--format", "git-ai", "--sign-key", key)
    assert code == 0, imported
    assert _schemas.validate_output(imported) == []
    [row] = imported["commits"]
    assert row["signed"] is True and (row["lines_added"], row["lines_attributed"]) == (7, 5)
    code, shown = _json(capsys, "git", "attribution", "HEAD", "--pubkey", key + ".pub")
    assert code == 0, shown
    assert shown["verification"]["signature"]["valid"] is True
    assert shown["verification"]["content_matches"] is True
    ranges = {(f["path"], r["start_line"], r["end_line"], r["run"], r.get("model"))
              for f in shown["attribution"]["files"] for r in f["ranges"]}  # fmt: skip
    assert ranges == {
        ("src/app.py", 1, 3, f"git-ai:{S}", "claude-opus-5-5"),
        ("src/app.py", 5, 5, f"git-ai:{S}", "claude-opus-5-5"),
        ("my file.txt", 1, 1, f"git-ai:{LEGACY}", "gpt-x"),
    }
    # OpenTine's note is canonical: a second import keeps it.
    again = _json(capsys, "import", str(repo), "--format", "git-ai")[1]
    assert again["commits"][0]["skipped"]
    # Export refuses to replace their note without --force, then writes it back.
    # `tine export` has no JSON of its own: --json wraps it like `--format entire`.
    wrapped = _json(capsys, "export", "HEAD", "--format", "git-ai")[1]
    assert _schemas.validate_output(wrapped) == []
    assert json.loads(wrapped["output"])["commits"][0]["skipped"]
    code, wrapped = _json(capsys, "export", "HEAD", "--format", "git-ai", "--force")
    exported = json.loads(wrapped["output"])
    assert code == 0 and exported["commits"][0]["lines_attributed"] == 5
    back = parse(_git(repo, "notes", "--ref=refs/notes/ai", "show", "HEAD"))
    assert back == original


def test_export_of_native_attribution_imports_back(repo, capsys) -> None:
    sha = _git(repo, "rev-parse", "HEAD").strip()
    record = {"schema": "opentine-line-attribution/1", "lines_added": 7, "lines_attributed": 2,
              "files": [{"path": "src/app.py", "ranges": [{
                  "start_line": 2, "end_line": 3, "content_hash": "x", "run": "runnative01",
                  "step": "st1", "tool": "Write", "model": "m1"}]}]}  # fmt: skip
    text = from_attribution(sha, record)
    assert text == from_attribution(sha, record)  # deterministic keys
    note = parse(text)
    [(key, lines)] = note["files"]["src/app.py"].items()
    assert lines == [2, 3] and key.startswith("s_") and "::t_" in key
    session = note["metadata"]["sessions"][key.split("::")[0]]
    assert session["agent_id"] == {"tool": "Write", "id": "runnative01", "model": "m1"}
    assert note["metadata"]["base_commit_sha"] == sha
    _git(repo, "notes", "--ref=refs/notes/ai", "add", "-f", "-m", text, sha)
    code, imported = _json(capsys, "import", f"{repo}::HEAD~1..HEAD", "--format", "git-ai")
    assert code == 0 and imported["commits"][0]["lines_attributed"] == 2


def test_import_refuses_flags_it_cannot_honour(repo, capsys, tmp_path) -> None:
    with pytest.raises(SystemExit):
        cli.main(["import", str(repo), "--format", "git-ai", "--save", str(tmp_path / "x")])
    with pytest.raises(SystemExit):
        cli.main(["import", "t.json", "--format", "agent-trace", "--sign-key", "k"])


def test_ai_share_outputs_follow_the_published_schema(repo, capsys) -> None:
    _their_note(repo)
    assert _json(capsys, "import", str(repo), "--format", "git-ai")[0] == 0
    code, report = _json(capsys, "stats", "--ai-share")
    assert code == 0 and report["schema"] == "tine-ai-share/1" and report["ai_lines"] == 5
    assert _schemas.detect(report) == "tine-ai-share-1"
    assert _schemas.validate_output(report) == []
    code, line = _json(capsys, "git", "share-line")
    assert code == 0 and line["lines_attributed"] == 5 and line["line"].startswith("tine: 5/7")
    assert _schemas.validate(line) == ("tine-ai-share-1", [])
