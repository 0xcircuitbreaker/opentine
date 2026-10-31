"""0.19: ``tine import --format entire`` reads Entire's checkpoint branch.

The fixture branch is built in-test in the layout recorded in
``tests/fixtures/entire/SOURCE.txt`` (entireio/cli @ 54b6a5c).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from opentine import cli
from opentine.core import Run
from opentine.trace import _entire_git
from opentine.trace._import_entire import entire_events

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

CP = "a3b2c4d5e6f7"
CP2 = "0123456789ab"
MODEL = "claude-sonnet-4-5"


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout


def _claude_transcript() -> str:
    base = {"sessionId": "sess-1", "timestamp": "2026-10-30T12:00:00Z"}
    lines = [
        {**base, "type": "user", "uuid": "u1", "message": {"role": "user", "content": "fix"}},
        {
            **base,
            "type": "assistant",
            "uuid": "a1",
            "requestId": "r1",
            "message": {
                "id": "msg_1",
                "model": MODEL,
                "role": "assistant",
                "usage": {"input_tokens": 10, "output_tokens": 5},
                "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}],
            },
        },
        {
            **base,
            "type": "user",
            "uuid": "u2",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}],
            },
        },
    ]
    return "".join(json.dumps(line) + "\n" for line in lines)


def _session_meta(index: int, agent: str, **extra) -> dict:
    return {
        "cli_version": "0.12.3",
        "checkpoint_id": CP,
        "session_id": f"sess-{index}",
        "strategy": "manual-commit",
        "created_at": "2026-10-30T12:00:00Z",
        "branch": "main",
        "checkpoints_count": 1,
        "files_touched": ["src/app.py"],
        "agent": agent,
        "model": MODEL,
        "token_usage": {"input_tokens": 10, "output_tokens": 5, "api_call_count": 1},
        **extra,
    }


def _layout(files: dict[str, str | bytes]) -> dict[str, str | bytes]:
    base = f"{CP[:2]}/{CP[2:]}"
    summary = {
        "checkpoint_id": CP,
        "strategy": "manual-commit",
        "checkpoints_count": 1,
        "files_touched": ["src/app.py"],
        "sessions": [
            {"metadata": f"/{base}/0/metadata.json", "prompt": f"/{base}/0/prompt.txt"},
            {"metadata": f"/{base}/1/metadata.json", "transcript": f"/{base}/1/full.jsonl"},
            {"metadata": "/../../etc/passwd"},
            {"metadata": f"/{CP2[:2]}/{CP2[2:]}/0/metadata.json"},
        ],
    }
    out = {
        f"{base}/metadata.json": json.dumps(summary),
        f"{base}/0/metadata.json": json.dumps(_session_meta(0, "Cursor")),
        f"{base}/0/prompt.txt": "add a button",
        f"{base}/1/metadata.json": json.dumps(_session_meta(1, "Claude Code")),
        f"{base}/1/full.jsonl": _claude_transcript(),
        f"{base}/1/prompt.txt": "fix",
    }
    out.update(files)
    return out


def _make_repo(root: Path, files: dict[str, str | bytes]) -> Path:
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.name", "T")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "commit.gpgsign", "false")
    (root / "README").write_text("x")
    _git(root, "add", "README")
    _git(root, "commit", "-q", "-m", "init")
    _git(root, "checkout", "-q", "--orphan", _entire_git.BRANCH)
    _git(root, "rm", "-rfq", ".")
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body if isinstance(body, bytes) else body.encode())
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "checkpoint")
    _git(root, "checkout", "-q", "main")
    return root


@pytest.fixture
def repo(tmp_path):
    return _make_repo(tmp_path / "proj", _layout({}))


def test_newest_checkpoint_last_session_delegates_to_claude_importer(repo):
    events = entire_events(str(repo))
    assert [event.kind for event in events] == ["human", "model", "tool"]
    assert events[1].model == MODEL
    entire = events[0].attributes["entire"]
    assert entire["checkpoint_id"] == CP
    assert entire["session_index"] == 1
    assert entire["agent"] == "Claude Code"
    assert entire["transcript_format"] == "claude-code-transcript"
    assert entire["files_touched"] == ["src/app.py"]
    assert entire["token_usage"]["input_tokens"] == 10


def test_unsupported_agent_imports_the_prompt_with_a_warning(repo):
    events = entire_events(f"{repo}::a3b/0")
    assert [event.kind for event in events] == ["human"]
    assert events[0].inputs == {"prompt": "add a button"}
    assert events[0].attributes["entire"]["agent"] == "Cursor"
    assert any("Cursor" in w for w in events[0].attributes["opentine.import_warnings"])


def test_traversal_and_foreign_session_paths_are_never_followed(repo):
    summary = json.loads(_git(repo, "show", f"{_entire_git.BRANCH}:a3/b2c4d5e6f7/metadata.json"))
    assert len(summary["sessions"]) == 4
    assert _entire_git.session_dirs(CP, summary) == ["a3/b2c4d5e6f7/0", "a3/b2c4d5e6f7/1"]
    with pytest.raises(ValueError, match="2 session"):
        entire_events(f"{repo}::{CP}/2")


def test_chunked_transcript_is_reassembled(tmp_path):
    whole = _claude_transcript().splitlines(keepends=True)
    base = f"{CP[:2]}/{CP[2:]}/1"
    files = {f"{base}/full.jsonl": whole[0], f"{base}/full.jsonl.001": "".join(whole[1:])}
    repo = _make_repo(tmp_path / "proj", _layout(files))
    assert [event.kind for event in entire_events(str(repo))] == ["human", "model", "tool"]


def test_malformed_and_oversized_input_is_refused(tmp_path, monkeypatch):
    base = f"{CP[:2]}/{CP[2:]}"
    bad = _make_repo(tmp_path / "bad", _layout({f"{base}/metadata.json": "{nope"}))
    with pytest.raises(ValueError, match="not valid JSON"):
        entire_events(str(bad))
    listy = _make_repo(tmp_path / "listy", _layout({f"{base}/1/metadata.json": "[]"}))
    with pytest.raises(ValueError, match="not a JSON object"):
        entire_events(str(listy))
    good = _make_repo(tmp_path / "good", _layout({}))
    monkeypatch.setattr(_entire_git, "MAX_TRANSCRIPT_BYTES", 16)
    with pytest.raises(ValueError, match="limit"):
        entire_events(str(good))


def test_bad_sources_are_refused(tmp_path, repo):
    plain = tmp_path / "plain"
    plain.mkdir()
    _git(plain, "init", "-q")
    with pytest.raises(ValueError, match="entire/checkpoints/v1"):
        entire_events(str(plain))
    with pytest.raises(ValueError, match="matches no checkpoint"):
        entire_events(f"{repo}::ffff")
    with pytest.raises(ValueError, match="not a checkpoint id"):
        entire_events(f"{repo}::..%2f")
    with pytest.raises(ValueError, match="session index"):
        entire_events(f"{repo}::{CP}/../0")
    with pytest.raises(ValueError, match="stream"):
        entire_events(["{}"])


def test_cli_imports_with_auto_detection_and_json(repo, tmp_path, capsys):
    out = tmp_path / "run.tine"
    assert cli.main(["import", str(repo), "--save", str(out), "--json"]) in (0, None)
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "entire" or payload.get("source_format") == "entire"
    run = Run.load(out)
    assert run.metadata["capture"]["source_format"] == "entire"
