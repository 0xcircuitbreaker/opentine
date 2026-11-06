"""0.38 per-turn capture: the ``opentine-hook/1`` protocol, ``tine enable``/``disable``.

* Every event is one durable step: a SIGKILLed session keeps every step that
  finished before the signal (ROADMAP 0.38 acceptance).
* Capture is off unless the repository's *trusted* config sets ``hooks.capture``.
* ``tine disable`` restores each agent config byte for byte.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from opentine import _hook_turns
from opentine._hook_protocol import PROTOCOL, handle, normalize, run_capture, session_ref


def _repo(tmp_path, monkeypatch, *, capture: bool = True) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "repo"
    repo = Repo.init(root)
    path = Path(repo.path)
    if capture:
        porcelain.save(path, {"remotes": {}, "config": {"hooks.capture": "true"}})
    return root


def _events(root: Path, ref: str) -> tuple[str, list[dict]]:
    from opentine.repo import Repo

    repo = Repo.open(root)
    payload = repo.get(repo.read_ref(ref)).payload()
    return payload["status"], [repo.get(oid).payload() for oid in payload["events"]]


def _send(root, payload, agent="generic") -> dict:
    return handle(json.dumps(payload).encode(), str(root), agent)


def _generic(event, **extra):
    return {"protocol": PROTOCOL, "event": event, "session": "s-1", **extra}


def test_generic_protocol_records_a_session_as_one_run(tmp_path, monkeypatch):
    root = _repo(tmp_path, monkeypatch)
    first = _send(root, _generic("prompt", prompt="fix the bug"))
    assert first["ok"] and first["protocol"] == PROTOCOL and first["steps"] == 1
    tool = {"name": "Bash", "input": {"command": "ls"}, "output": {"stdout": "a"}}
    assert _send(root, _generic("tool", tool=tool))["steps"] == 2
    assert _send(root, _generic("turn_end", message="done"))["steps"] == 3
    status, events = _events(root, first["ref"])
    assert status == "running"  # a turn ending is not the session ending
    end = _send(root, _generic("session_end"))
    status, events = _events(root, end["ref"])
    assert status == "completed" and len(events) == 3
    assert [event["kind"] for event in events] == ["human", "tool", "model"]
    assert events[1]["actor"] == "Bash"


def test_vendor_payloads_normalize_to_the_protocol():
    claude = {"hook_event_name": "PostToolUse", "session_id": "x", "tool_name": "Edit",
              "tool_input": {"file_path": "a"}, "tool_response": {"ok": True}}  # fmt: skip
    event = normalize(claude)
    assert event["event"] == "tool" and event["tool"]["name"] == "Edit"
    assert normalize({"hook_event_name": "AfterTool", "session_id": "x"})["event"] == "tool"
    assert normalize({"hook_event_name": "BeforeAgent", "session_id": "x"})["event"] == "prompt"
    assert normalize({"hook_event_name": "Stop", "session_id": "x"})["event"] == "turn_end"
    assert normalize({"hook_event_name": "Notification", "session_id": "x"}) is None
    assert normalize({"protocol": PROTOCOL, "event": "tool"}) is None  # no session


def test_capture_is_off_unless_the_trusted_config_enables_it(tmp_path, monkeypatch):
    from opentine import _porcelain_config as porcelain

    root = _repo(tmp_path, monkeypatch, capture=False)
    assert _send(root, _generic("prompt", prompt="x"))["reason"] == "capture is not enabled"
    from opentine.repo import Repo

    repo_path = Path(Repo.open(root).path)
    porcelain.save(repo_path, {"remotes": {}, "config": {"hooks.capture": "true"}})
    # The same file without this machine's trust (as a clone ships it): still off.
    Path(porcelain._trust_file()).unlink()
    assert not porcelain.trusted(repo_path)
    assert _send(root, _generic("prompt", prompt="x"))["ok"] is False
    porcelain.trust(repo_path)
    assert _send(root, _generic("prompt", prompt="x"))["ok"] is True


def test_vendor_stdout_is_inert_json_and_bad_input_still_exits_zero(tmp_path, monkeypatch):
    root = _repo(tmp_path, monkeypatch)
    payload = {"hook_event_name": "UserPromptSubmit", "session_id": "v", "prompt": "hi"}
    for agent, expected in (("claude-code", {"suppressOutput": True}), ("gemini", {})):
        out = io.StringIO()
        stream = io.BytesIO(json.dumps(payload).encode())
        assert run_capture(str(root), agent, stream, out) == 0
        assert json.loads(out.getvalue()) == expected
    status, events = _events(root, session_ref("claude-code", "v"))
    assert status == "running" and len(events) == 1
    out = io.StringIO()
    assert run_capture(str(root), None, io.BytesIO(b"{not json"), out) == 0
    assert json.loads(out.getvalue())["ok"] is False


def test_turn_end_callbacks_annotate_the_step_and_cannot_lose_it(tmp_path, monkeypatch):
    root = _repo(tmp_path, monkeypatch)
    seen = []

    def snapshot(context):
        seen.append((context.session, context.cwd, context.recorder.run_id))
        return {"opentine.tree": "t-1"}

    def broken(context):
        raise RuntimeError("boom")

    _hook_turns.register(snapshot)
    _hook_turns.register(broken)
    try:
        result = _send(root, _generic("turn_end", cwd=str(tmp_path)))
    finally:
        _hook_turns.unregister(snapshot)
        _hook_turns.unregister(broken)
    assert result["ok"] and seen and seen[0][:2] == ("s-1", str(tmp_path))
    _, events = _events(root, result["ref"])
    attributes = events[-1]["attributes"]
    assert attributes["opentine.tree"] == "t-1"
    assert attributes["opentine.hook.callback_errors"] == ["broken: RuntimeError"]


_CHILD = textwrap.dedent(
    """
    import json, sys
    from opentine._hook_protocol import PROTOCOL, handle
    root = sys.argv[1]
    for index in range(10_000):
        tool = {"name": "Bash", "input": {"n": index}, "output": {"ok": True}}
        payload = {"protocol": PROTOCOL, "event": "tool", "session": "k", "tool": tool}
        result = handle(json.dumps(payload).encode(), root, "generic")
        assert result["ok"], result
        print(result["steps"], flush=True)
    """
)


@pytest.mark.skipif(os.name == "nt", reason="SIGKILL is POSIX-only")
def test_a_sigkilled_session_keeps_every_completed_step(tmp_path, monkeypatch):
    root = _repo(tmp_path, monkeypatch)
    env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path / "xdg")}
    project = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = project + os.pathsep + env.get("PYTHONPATH", "")
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(root)], stdout=subprocess.PIPE, env=env, text=True
    )
    completed = 0
    try:
        while completed < 5:
            line = child.stdout.readline()
            assert line, "the child stopped before recording 5 steps"
            completed = int(line)
    finally:
        child.send_signal(signal.SIGKILL)
        child.wait()
    assert child.returncode == -signal.SIGKILL
    status, events = _events(root, session_ref("generic", "k"))
    assert status == "running" and len(events) >= completed >= 5


# -- tine enable / disable ---------------------------------------------------------


def _homes(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setenv("GEMINI_CLI_HOME", str(tmp_path / "gem"))
    claude = tmp_path / "claude" / "settings.json"
    claude.parent.mkdir()
    # Odd spacing, key order and no trailing newline: only a byte restore keeps it.
    claude.write_bytes(b'{ "theme":"dark",\r\n  "hooks": {"Stop": [{"hooks": [{"type": '
                       b'"command", "command": "notify-send hi"}]}]}}')  # fmt: skip
    return claude, tmp_path / "codex" / "hooks.json", tmp_path / "gem" / ".gemini" / "settings.json"


def _args(root, **extra):
    values = {"agent": None, "dry_run": False, "repo": str(root)}
    return argparse.Namespace(**{**values, **extra})


def test_enable_dry_run_shows_the_edit_and_writes_nothing(tmp_path, monkeypatch, capsys):
    from opentine._cli_enable import cmd_enable

    root = _repo(tmp_path, monkeypatch, capture=False)
    claude, codex, _ = _homes(tmp_path, monkeypatch)
    before = claude.read_bytes()
    cmd_enable(_args(root, dry_run=True))
    shown = capsys.readouterr().out
    assert "+++ " in shown and "hook capture --agent claude-code" in shown
    assert "PostToolUse" in shown and claude.read_bytes() == before and not codex.exists()


def test_enable_installs_thin_shims_and_disable_restores_bytes(tmp_path, monkeypatch):
    from opentine._cli_enable import cmd_disable, cmd_enable
    from opentine._hook_protocol import enabled
    from opentine.repo import Repo

    root = _repo(tmp_path, monkeypatch, capture=False)
    claude, codex, gemini = _homes(tmp_path, monkeypatch)
    original = claude.read_bytes()
    cmd_enable(_args(root))
    cmd_enable(_args(root))  # twice: still one shim per event
    settings = json.loads(claude.read_text())
    assert settings["theme"] == "dark"
    stop = [h["command"] for g in settings["hooks"]["Stop"] for h in g["hooks"]]
    assert stop[0] == "notify-send hi" and len(stop) == 2
    for event in ("UserPromptSubmit", "PostToolUse", "SessionEnd"):
        assert "hook capture --agent claude-code" in json.dumps(settings["hooks"][event])
    assert "AfterTool" in json.loads(gemini.read_text())["hooks"]
    assert "PostToolUse" in json.loads(codex.read_text())["hooks"]
    assert enabled(Path(Repo.open(root).path))
    cmd_disable(_args(root))
    assert claude.read_bytes() == original  # byte for byte
    assert not codex.exists() and not gemini.exists()  # absent before, absent after


def test_disable_after_a_user_edit_removes_only_the_shims(tmp_path, monkeypatch):
    from opentine._cli_enable import cmd_disable, cmd_enable

    root = _repo(tmp_path, monkeypatch, capture=False)
    claude, _, _ = _homes(tmp_path, monkeypatch)
    cmd_enable(_args(root, agent=["claude-code"]))
    edited = json.loads(claude.read_text())
    edited["model"] = "opus"
    claude.write_text(json.dumps(edited))
    cmd_disable(_args(root, agent=["claude-code"]))
    kept = json.loads(claude.read_text())
    assert kept["model"] == "opus" and "hook capture" not in claude.read_text()
    assert [h["command"] for g in kept["hooks"]["Stop"] for h in g["hooks"]] == ["notify-send hi"]
    # Enable, edit, enable again, disable: the edit is never rolled back.
    cmd_enable(_args(root, agent=["claude-code"]))
    edited = json.loads(claude.read_text())
    edited["model"] = "sonnet"
    claude.write_text(json.dumps(edited))
    cmd_enable(_args(root, agent=["claude-code"]))
    cmd_disable(_args(root, agent=["claude-code"]))
    assert json.loads(claude.read_text())["model"] == "sonnet"
    assert "hook capture" not in claude.read_text()


def test_hook_capture_and_enable_parse_from_the_command_line():
    from opentine.cli import parse

    _, args = parse(["hook", "capture", "--agent", "codex", "--repo", "r"])
    assert args.action == "capture" and args.agent == ["codex"]
    _, args = parse(["enable", "--agent", "gemini", "--dry-run", "--repo", "r"])
    assert args.command == "enable" and args.dry_run and args.agent == ["gemini"]
    _, args = parse(["disable"])
    assert args.command == "disable"
