"""0.45 blame/why/attach: git-compatible blame, trailer grammar, attach, Agent Trace import.

Real git in temporary repositories. ``tine blame --porcelain`` must equal
``git blame --porcelain`` byte for byte when no line is attributed to an agent.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import cli
from opentine._agent_trace import to_agent_trace
from opentine._git_link import run_ids
from opentine._trailers import Link, TrailerError, format_links, parse
from opentine.graph import Run, StepKind

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

VECTORS = json.loads((Path(__file__).parent / "data" / "trailer_vectors.json").read_text("utf-8"))
AGENT_TEXT = "def agent():\n    return 'written by the agent'\n"
IDENTITY = {
    "GIT_AUTHOR_NAME": "Ada", "GIT_AUTHOR_EMAIL": "ada@example.invalid",
    "GIT_COMMITTER_NAME": "Ada", "GIT_COMMITTER_EMAIL": "ada@example.invalid",
}  # fmt: skip


def _git(cwd: Path, *args: str, **env: str) -> bytes:
    done = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args], cwd=cwd,
        env={**os.environ, **IDENTITY, **env}, capture_output=True, check=True,
    )  # fmt: skip
    return done.stdout


def _blame_bytes(capsys, *argv: str) -> bytes:
    buffer = io.BytesIO()
    out = io.TextIOWrapper(buffer, encoding="utf-8")
    capsys.readouterr()
    old, sys.stdout = sys.stdout, out
    try:
        cli.main(["blame", *argv])
    finally:
        out.flush()
        sys.stdout = old
    return buffer.getvalue()


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main([*argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _fixture(root: Path, number: int) -> list[str]:
    """A repository shaped by *number*: authors, commits, edits, a rename, bytes."""
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    paths = []
    for commit in range(1 + number % 4):
        name = f"f{commit % 2}.txt"
        path = root / name
        old = path.read_bytes() if path.exists() else b""
        lines = old.splitlines(keepends=True)
        lines.insert(min(commit, len(lines)), f"line {number}-{commit} é\n".encode())
        if number % 5 == 0:
            lines.append(b"latin1 \xe9\n")  # not UTF-8: must pass through untouched
        path.write_bytes(b"".join(lines))
        _git(root, "add", name)
        when = f"{1_700_000_000 + commit * 3600} +0100"
        _git(
            root, "commit", "-q", "-m", f"c{commit}", GIT_AUTHOR_DATE=when,
            GIT_COMMITTER_DATE=when, GIT_AUTHOR_NAME=f"A{commit % 3}",
        )  # fmt: skip
        paths.append(name)
    if number % 3 == 0:
        _git(root, "mv", "f0.txt", "renamed.txt")
        _git(root, "commit", "-q", "-m", "rename")
        paths = ["renamed.txt" if p == "f0.txt" else p for p in paths]
    return sorted(set(paths))


@pytest.mark.parametrize("number", range(20))
def test_porcelain_matches_git_byte_for_byte(tmp_path, monkeypatch, capsys, number) -> None:
    root = tmp_path / f"r{number}"
    for path in _fixture(root, number):
        monkeypatch.chdir(root)
        expected = _git(root, "blame", "--porcelain", path)
        assert _blame_bytes(capsys, path, "--porcelain") == expected
        line = _git(root, "blame", "--line-porcelain", path)
        assert _blame_bytes(capsys, path, "--line-porcelain") == line


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_trailer_vectors(case) -> None:
    if "error" in case:
        with pytest.raises(TrailerError, match=case["error"]):
            parse(case["message"])
        return
    links = [link.to_dict() for link in parse(case["message"])]
    assert links == case["links"]
    if case.get("strict_only"):
        return
    # The lenient reader the commit-msg hook uses names the same runs.
    assert run_ids(case["message"]) == list(dict.fromkeys(link["run"] for link in links))


def _note(root: Path, sha: str, ranges: list, path: str = "a.txt") -> None:
    from opentine._line_attrib import PREFIX, SCHEMA

    record = {"schema": SCHEMA, "files": [{"path": path, "ranges": ranges}]}
    body = PREFIX + json.dumps(record)
    _git(root, "notes", "--ref=refs/notes/tine", "add", "-f", "-m", body, sha)


def _one_commit_repo(root: Path, name: str, data: bytes) -> str:
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / name).write_bytes(data)
    _git(root, "add", name)
    _git(root, "commit", "-q", "-m", "A")
    return _git(root, "rev-parse", "HEAD").decode().strip()


def test_porcelain_keeps_each_commits_path_after_a_rename(tmp_path, monkeypatch, capsys) -> None:
    # git names a commit's filename once; a later group of that commit must reuse it.
    root = tmp_path / "rn"
    first = _one_commit_repo(root, "old.txt", b"a1\na2\na3\n")
    _git(root, "mv", "old.txt", "new.txt")
    (root / "new.txt").write_bytes(b"a1\nb2\na3\n")
    _git(root, "add", "new.txt")
    _git(root, "commit", "-q", "-m", "B")
    agent = {"start_line": 3, "end_line": 3, "run": "r-agent", "seq": 0, "model": "m"}
    _note(root, first, [agent], path="old.txt")
    monkeypatch.chdir(root)
    out = _blame_bytes(capsys, "new.txt", "--porcelain")
    assert out.count(b"tine-run r-agent\n") == 1
    headers = b"tine-run r-agent\ntine-step 0\ntine-model m\n"
    assert out.replace(headers, b"") == _git(root, "blame", "--porcelain", "new.txt")


def test_a_hostile_note_cannot_forge_headers_or_exhaust_memory(tmp_path, monkeypatch, capsys):
    root = tmp_path / "evil"
    sha = _one_commit_repo(root, "a.txt", b"x\ny\n")
    _note(root, sha, [
        {"start_line": 1, "end_line": 10**12, "run": "r\nauthor Mallory", "model": "m x"},
        {"start_line": "1", "end_line": None, "run": "bad"},
        "not a range",
    ])  # fmt: skip
    monkeypatch.chdir(root)
    out = _blame_bytes(capsys, "a.txt", "--porcelain")
    assert b"\nauthor Mallory" not in out
    assert out.count(b"tine-run r_author_Mallory\n") == 2
    assert b"tine-model m_x\n" in out


def test_git_log_reports_the_strict_link_set(tmp_path, monkeypatch, capsys) -> None:
    root = tmp_path / "log"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    monkeypatch.chdir(root)
    for name in ("run-with-own-project", "two-projects-rejected"):
        case = next(c for c in VECTORS["cases"] if c["name"] == name)
        _git(root, "commit", "-q", "--allow-empty", "-m", case["message"])
        _code, payload = _json(capsys, "git", "log", "--commit", "HEAD")
        (row,) = payload["links"]
        assert row["links"] == case.get("links", [])
        assert (case.get("error") or "") in row["error"] and bool(row["error"]) == ("error" in case)


def test_agent_trace_import_redacts_the_conversation_url() -> None:
    from opentine.trace._import_agent_trace import agent_trace_events

    secret = "ghp_" + "a1B2" * 9
    conversation = {
        "url": f"https://chat.example.invalid/c?token={secret}",
        "contributor": {"type": "ai", "model_id": "anthropic/claude"},
        "ranges": [{"start_line": 1, "end_line": 2}],
    }
    record = {"id": "t", "files": [{"path": "a.py", "conversations": [conversation]}]}
    events = agent_trace_events(json.dumps(record))
    assert secret not in json.dumps([event.to_dict() for event in events], default=str)


def test_trailer_round_trip() -> None:
    links = [Link("run_20261108_ab12", "web"), Link("run_20261108_cd34", "acme-api")]
    message = "Fix\n\n" + "\n".join(format_links(links, project="acme-api")) + "\n"
    assert "Tine-Project: acme-api" in message
    assert parse(message) == links
    with pytest.raises(TrailerError):
        format_links([Link("run:sha256:short")])


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    monkeypatch.chdir(root)
    monkeypatch.setattr(cli, "RUNS_DIR", Path(".tine_runs"))
    (root / ".tine_runs").mkdir()
    (root / "seed.txt").write_text("seed\n")
    _git(root, "add", "seed.txt")
    _git(root, "commit", "-q", "-m", "seed")
    run = Run(id="runattr45", model_info="claude-opus-5-5")
    run.add_step(StepKind.model, {"prompt": "write a.py"}, model_info="claude-opus-5-5")
    run.add_step(
        StepKind.tool,
        {"name": "Write", "arguments": {"file_path": str(root / "a.py"), "content": AGENT_TEXT}},
        model_info="claude-opus-5-5",
        parent_ids=[run.steps[0].id],
    )
    run.save(root / ".tine_runs" / "runattr45.tine")
    (root / "a.py").write_text(AGENT_TEXT + "# a human line\n")
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "agent change")
    return root


def test_attach_blame_why_and_rewrites(repo, capsys) -> None:
    plain = _git(repo, "blame", "--porcelain", "a.py")
    code, attached = _json(capsys, "attach", "runattr45", "HEAD")
    assert code == 0 and attached["runs"] == ["runattr45"]
    assert attached["lines_attributed"] == 2 and attached["rewrite_ref_configured"] is True
    annotated = _blame_bytes(capsys, "a.py", "--porcelain")
    assert annotated.count(b"tine-run runattr45\n") == 2
    stripped = b"".join(
        line for line in annotated.splitlines(keepends=True) if not line.startswith(b"tine-")
    )
    assert stripped == plain
    record = _json(capsys, "blame", "a.py", "--lines")[1]
    assert record["schema"] == "tine-blame/1" and record["ai_lines"] == 2
    assert [row["ai"] and row["ai"]["run"] for row in record["lines"]] == [
        "runattr45", "runattr45", None,
    ]  # fmt: skip
    why = _json(capsys, "why", "a.py:1")[1]
    assert why["run"] == "runattr45" and why["commit"]
    assert [step["kind"] for step in why["slice"]] == ["model", "tool"]
    human = _json(capsys, "why", "a.py:3")[1]
    assert human["run"] == "" or human["attribution"] is None
    # amend and rebase keep the note (notes.rewriteRef)
    _git(repo, "commit", "-q", "--amend", "-m", "agent change, reworded")
    assert _json(capsys, "blame", "a.py", "--lines")[1]["ai_lines"] == 2
    (repo / "later.txt").write_text("later\n")
    _git(repo, "add", "later.txt")
    _git(repo, "commit", "-q", "-m", "later")
    # awk, not tac: macOS has no tac. Reverses the two picks.
    script = (
        'awk \'/^pick/ {l[n++] = $0} END {while (n) print l[--n]}\' "$1" > "$1.t" && mv "$1.t" "$1"'
    )
    editor = repo.parent / "editor.sh"
    editor.write_text(f"#!/bin/sh\n{script}\n")
    _git(repo, "rebase", "-q", "-i", "HEAD~2", GIT_SEQUENCE_EDITOR=f'sh "{editor.as_posix()}"')
    assert _git(repo, "log", "-1", "--format=%s").strip() == b"agent change, reworded"
    assert _json(capsys, "blame", "a.py", "--lines")[1]["ai_lines"] == 2


def test_install_hook_sets_rewrite_ref_and_share_line(repo, capsys) -> None:
    from opentine._git_share_hook import share_line

    code, installed = _json(capsys, "git", "install-hook", "--ai-share")
    assert code == 0 and installed["rewrite_ref_configured"] is True
    assert any(Path(hook).name == "post-commit" for hook in installed["hooks"])
    assert b"refs/notes/tine" in _git(repo, "config", "--get-all", "notes.rewriteRef")
    assert share_line(repo) == ""  # HEAD links no run yet
    _json(capsys, "attach", "runattr45", "HEAD")
    assert share_line(repo).startswith("tine: 2/3 added line(s) by agents (67%)")


def test_import_agent_trace_round_trip(repo, tmp_path, capsys) -> None:
    from opentine.trace._import_agent_trace import TOOL, agent_trace_events

    record = to_agent_trace(Run.load(repo / ".tine_runs" / "runattr45.tine"), root=repo)
    events = agent_trace_events(json.dumps(record))
    tools = [event for event in events if event.kind == "tool"]
    assert [event.actor for event in tools] == [TOOL]
    assert tools[0].inputs["arguments"]["path"] == "a.py"
    assert tools[0].inputs["arguments"]["ranges"][0]["start_line"] == 1
    source = tmp_path / "trace.json"
    source.write_text(json.dumps(record))
    code, imported = _json(capsys, "import", str(source), "--format", "agent-trace",
                           "--save", str(tmp_path / "out.tine"))  # fmt: skip
    assert code == 0 and imported["events_imported"] == len(events)
    with pytest.raises(ValueError):
        agent_trace_events(b'{"not": "a record"}')
