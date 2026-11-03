"""0.32: ``tine rewind`` restores from a file's stored original when it can."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run
from opentine._file_originals import KEY, MARKER, Originals, digest, hoist, hoist_events
from opentine.cli import main
from opentine.core import StepKind
from opentine.trace._transcript_claude import claude_transcript_events

ORIGINAL = "line one\nshared\nline three\nshared\n"


def _put(path: Path, text: str) -> None:
    path.write_bytes(text.encode())  # byte-exact: no CRLF translation on Windows


def _get(path: Path) -> str:
    return path.read_bytes().decode()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "work"
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def _edit_run(original: str | None, *, post: str | None = None) -> Run:
    run = Run(user_prompt="edit")
    run.add_step(StepKind.think, inputs={"text": "plan"})
    outputs: dict = {}
    if original is not None:
        outputs[MARKER] = Originals().marker("a.txt", original, post)
        outputs = hoist(run.metadata, outputs)
    # "shared" occurs twice: the old diff-only walk cannot undo a replace_all.
    arguments = {
        "file_path": "a.txt",
        "old_string": "shared",
        "new_string": "S",
        "replace_all": True,
    }
    run.add_step(StepKind.tool, inputs={"name": "Edit", "arguments": arguments}, outputs=outputs)
    return run


def _rewind(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        main(["rewind", *argv, "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _rows(payload: dict) -> dict[str, dict]:
    keys = ("restore", "unchanged", "conflict", "unrecoverable", "refused")
    return {row["path"]: {**row, "status": key} for key in keys for row in payload[key]}


def test_exact_restore_from_stored_original(home, tmp_path, capsys):
    after = ORIGINAL.replace("shared", "S")
    run = _edit_run(ORIGINAL, post=after)
    assert MARKER in run.steps[1].outputs and "content" not in run.steps[1].outputs[MARKER]
    saved = tmp_path / "r.tine"
    run.save(saved)
    _put(home / "a.txt", after)
    code, payload = _rewind(capsys, str(saved), "--root", str(home), "--apply")
    row = _rows(payload)["a.txt"]
    assert code == 0 and row["status"] == "restore" and row["mode"] == "exact"
    assert _get(home / "a.txt") == ORIGINAL


def test_redaction_altered_original_falls_back_safely(home, tmp_path, capsys):
    secret = "AKIAIOSFODNN7EXAMPLE"
    original = f"key = {secret}\nshared\n"
    run = _edit_run(original)
    saved = tmp_path / "r.tine"
    run.save(saved)
    stored = Run.load(saved).metadata[KEY]
    assert secret not in json.dumps(stored)  # the original went through redaction
    _put(home / "a.txt", original.replace("shared", "S"))
    code, payload = _rewind(capsys, str(saved), "--root", str(home), "--apply")
    row = _rows(payload)["a.txt"]
    assert row["mode"] == "skipped" and "redaction" in row["fallback"]
    assert _get(home / "a.txt") == original.replace("shared", "S")  # untouched
    assert "REDACTED" not in _get(home / "a.txt")


def test_old_run_without_originals_still_reconstructs(home, tmp_path, capsys):
    run = Run(user_prompt="edit")
    arguments = {"file_path": "b.txt", "old_string": "old", "new_string": "new"}
    run.add_step(StepKind.tool, inputs={"name": "Edit", "arguments": arguments}, outputs={})
    saved = tmp_path / "r.tine"
    run.save(saved)
    _put(home / "b.txt", "x new y\n")
    code, payload = _rewind(capsys, str(saved), "--root", str(home), "--apply")
    row = _rows(payload)["b.txt"]
    assert code == 0 and row["mode"] == "reconstructed" and "fallback" not in row
    assert _get(home / "b.txt") == "x old y\n"


def test_mismatched_post_digest_is_not_exact(home, tmp_path, capsys):
    run = _edit_run(ORIGINAL, post="something else\n")
    saved = tmp_path / "r.tine"
    run.save(saved)
    _put(home / "a.txt", ORIGINAL.replace("shared", "S"))
    _code, payload = _rewind(capsys, str(saved), "--root", str(home))
    row = _rows(payload)["a.txt"]
    assert row["mode"] == "skipped" and "recorded result" in row["fallback"]


def test_human_output_names_the_mode(home, tmp_path, capsys):
    run = _edit_run(ORIGINAL)
    saved = tmp_path / "r.tine"
    run.save(saved)
    _put(home / "a.txt", ORIGINAL.replace("shared", "S"))
    main(["rewind", str(saved), "--root", str(home)])
    out = " ".join(capsys.readouterr().out.split())
    assert "Would restore: a.txt [exact]" in out


def _claude_lines(path: str) -> list[dict]:
    base = {"sessionId": "s1", "timestamp": "2026-11-01T00:00:00Z"}
    call = {"file_path": path, "old_string": "shared", "new_string": "S", "replace_all": True}
    use = {"type": "tool_use", "id": "t1", "name": "Edit", "input": call}
    result = {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}
    detail = {"filePath": path, "originalFile": ORIGINAL, "oldString": "shared"}
    return [
        {**base, "type": "user", "uuid": "u1", "message": {"role": "user", "content": "go"}},
        {
            **base,
            "type": "assistant",
            "uuid": "a1",
            "message": {"id": "m1", "model": "claude-x", "content": [use], "usage": {}},
        },
        {
            **base,
            "type": "user",
            "uuid": "u2",
            "toolUseResult": detail,
            "message": {"role": "user", "content": [result]},
        },
    ]


def test_claude_transcript_import_stores_original_once(home, tmp_path, capsys):
    target = (home / "a.txt").as_posix()
    events = claude_transcript_events(_claude_lines(target))
    tool = next(event for event in events if event.kind == "tool")
    assert tool.inputs["arguments"]["file_path"] == target
    assert tool.outputs[MARKER]["sha256"] == digest(ORIGINAL)
    stripped, store = hoist_events(events)
    assert store == {digest(ORIGINAL): ORIGINAL}
    assert all("content" not in event.outputs.get(MARKER, {}) for event in stripped)
    source = tmp_path / "session.jsonl"
    source.write_bytes("\n".join(json.dumps(line) for line in _claude_lines(target)).encode())
    saved = tmp_path / "imported.tine"
    main(["import", str(source), "--format", "claude-code-transcript", "--save", str(saved)])
    capsys.readouterr()
    _put(home / "a.txt", ORIGINAL.replace("shared", "S"))
    _code, payload = _rewind(capsys, str(saved), "--root", str(home), "--apply")
    assert _rows(payload)["a.txt"]["mode"] == "exact"
    assert _get(home / "a.txt") == ORIGINAL


def test_gemini_and_stream_recorders_keep_one_original_per_file():
    from opentine.harnesses._claude_stream import ClaudeStream

    originals = Originals()
    display = {"originalContent": ORIGINAL, "newContent": "after\n", "fileName": "a.txt"}
    first = originals.gemini({"file_path": "/w/a.txt"}, display)
    assert first == {
        "path": "/w/a.txt",
        "sha256": digest(ORIGINAL),
        "content": ORIGINAL,
        "post_sha256": digest("after\n"),
    }
    assert "content" not in originals.gemini({"file_path": "/w/a.txt"}, display)  # once
    stream = ClaudeStream(env=dict)
    use = {"type": "tool_use", "id": "t1", "name": "Edit", "input": {"file_path": "/w/b"}}
    stream.step({"type": "assistant", "message": {"id": "m", "content": [use]}})
    result = {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}
    steps = stream.step(
        {
            "type": "user",
            "message": {"content": [result]},
            "tool_use_result": {"filePath": "/w/b", "originalFile": "old\n"},
        }
    )
    assert steps[0].outputs[MARKER]["content"] == "old\n"
