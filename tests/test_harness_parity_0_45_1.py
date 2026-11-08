"""0.45.x harness parity: Copilot CLI, Factory Droid, Antigravity hooks; Pi sessions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _enable_native as native
from opentine._hook_protocol import PROTOCOL, handle, normalize, session_ref

FIXTURES = Path(__file__).parent / "fixtures"
HOOKS = FIXTURES / "hooks"
PI = FIXTURES / "pi" / "sessions" / "--w-proj--"
SEQUENCES = {
    "copilot": [("prompt.json", None), ("tool.json", None), ("stop.json", None),
                ("session_end.json", None)],
    "droid": [("prompt.json", None), ("tool.json", None), ("stop.json", None),
              ("session_end.json", None)],
    "antigravity": [("PreInvocation.json", "PreInvocation"), ("PostToolUse.json", "PostToolUse"),
                    ("Stop.json", "Stop")],
}  # fmt: skip


def _load(agent: str, name: str) -> dict:
    return json.loads((HOOKS / agent / name).read_text(encoding="utf-8"))


def _repo(tmp_path, monkeypatch) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "repo"
    porcelain.save(Path(Repo.init(root).path),
                   {"remotes": {}, "config": {"hooks.capture": "true"}})  # fmt: skip
    return root


@pytest.mark.parametrize("agent", sorted(SEQUENCES))
def test_fixtures_normalize_to_the_protocol(agent):
    kinds = [normalize(_load(agent, name), hint)["event"] for name, hint in SEQUENCES[agent]]
    expected = ["prompt", "tool", "turn_end", "session_end"][: len(kinds)]
    assert kinds == expected
    tool = normalize(_load(agent, SEQUENCES[agent][1][0]), SEQUENCES[agent][1][1])["tool"]
    assert tool["name"] and tool["input"]
    prompt = normalize(_load(agent, SEQUENCES[agent][0][0]), SEQUENCES[agent][0][1])
    assert prompt["prompt"] == "List the files" and prompt["cwd"] == "/w/proj"


def test_copilot_tool_result_is_kept():
    event = normalize(_load("copilot", "tool.json"))
    assert event["tool"]["output"] == {"type": "success", "text": "a.py\nb.py"}


def test_antigravity_without_event_hint_is_not_a_capture_event():
    assert normalize(_load("antigravity", "Stop.json")) is None


@pytest.mark.parametrize("agent", sorted(SEQUENCES))
def test_fixture_sessions_record_as_one_run(tmp_path, monkeypatch, agent):
    root = _repo(tmp_path, monkeypatch)
    responses = [handle((HOOKS / agent / name).read_bytes(), str(root), agent, hint)
                 for name, hint in SEQUENCES[agent]]  # fmt: skip
    assert all(r["ok"] and r["protocol"] == PROTOCOL for r in responses), responses
    from opentine.repo import Repo

    repo = Repo.open(root)
    session = normalize(_load(agent, SEQUENCES[agent][0][0]), SEQUENCES[agent][0][1])["session"]
    payload = repo.get(repo.read_ref(session_ref(agent, session))).payload()
    kinds = [repo.get(oid).payload()["kind"] for oid in payload["events"]]
    assert kinds == ["human", "tool", "model"]
    assert payload["status"] == ("running" if agent == "antigravity" else "completed")


@pytest.mark.parametrize("agent", native.NATIVE)
def test_native_shims_round_trip_and_keep_user_hooks(tmp_path, agent):
    if agent == "antigravity":
        user = {"mine": {"Stop": [{"type": "command", "command": "echo hi"}]}}
    elif agent == "copilot":
        user = {}
    else:
        user = {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}
    added = native.with_shims(user, agent, tmp_path)
    text = json.dumps(added)
    assert "hook capture --agent" in text and agent in text
    assert native.with_shims(added, agent, tmp_path) == added  # idempotent
    assert native.without_shims(added, agent) == user
    if agent == "antigravity":
        assert added["opentine-capture"]["PreInvocation"][0]["command"].endswith(
            "--event PreInvocation"
        )
    if agent == "copilot":
        assert added["version"] == 1 and set(added["hooks"]) == set(native.EVENTS["copilot"])


def test_enable_and_disable_restore_native_configs(tmp_path, monkeypatch):
    from opentine._cli_enable import _disable_one, _enable_one

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    droid = native.config_path("droid")
    droid.parent.mkdir(parents=True)
    original = b'{"Stop": []}\n'
    droid.write_bytes(original)
    for agent in native.NATIVE:
        _enable_one(agent, tmp_path, False)
        assert "hook capture" in native.config_path(agent).read_text(encoding="utf-8")
    for agent in native.NATIVE:
        _disable_one(agent, False)
    assert droid.read_bytes() == original
    assert not native.config_path("copilot").exists()
    assert not native.config_path("antigravity").exists()


def test_pi_session_imports_with_usage_and_tools():
    from opentine.trace._import_detect import detect_format
    from opentine.trace._transcript_pi import pi_session_events

    path = next(PI.glob("*.jsonl"))
    assert detect_format(path.read_text(encoding="utf-8")) == "pi-session"
    events = pi_session_events(path)
    assert [e.kind for e in events] == ["human", "model", "tool", "model"]
    first = events[1]
    assert first.model == "claude-sonnet-4-5" and first.provider == "anthropic"
    assert first.usage == {"input": 1500, "output": 300, "cache_read": 20000,
                           "cache_write_5m": 4000}  # fmt: skip
    assert first.outputs["tool_calls"][0]["name"] == "bash"
    assert first.outputs["reasoning"] == "Use ls."
    assert events[2].actor == "bash" and events[2].outputs["result"] == "a.py\nb.py"


def test_pi_sessions_are_found_at_the_default_location(tmp_path, monkeypatch):
    from opentine import _cli_import_sessions as sessions

    agent = tmp_path / "agent"
    target = agent / "sessions" / PI.name
    target.mkdir(parents=True)
    source = next(PI.glob("*.jsonl"))
    (target / source.name).write_bytes(source.read_bytes())
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent))
    found = sessions.sessions("pi-session")
    assert [item.path.name for item in found] == [source.name]


def test_doctor_lists_agent_capture(tmp_path, monkeypatch):
    from opentine import _agent_detect

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    for name in ("COPILOT_HOME", "PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
                 "GEMINI_CLI_HOME"):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".pi" / "agent").mkdir(parents=True)
    assert _agent_detect.present() == ["droid (hooks)", "pi (import)"]


def test_copilot_strip_keeps_user_settings_when_only_our_hooks_remain(tmp_path):
    document = native.with_shims({"version": 1, "disableAll": False}, "copilot", tmp_path)
    assert native.without_shims(document, "copilot") == {
        "version": 1,
        "disableAll": False,
        "hooks": {},
    }
    ours_only = native.with_shims({}, "copilot", tmp_path)
    assert native.without_shims(ours_only, "copilot") == {}


def test_copilot_powershell_command_is_invoked_not_echoed(tmp_path):
    document = native.with_shims({}, "copilot", tmp_path)
    entry = document["hooks"]["Stop"][0]
    assert entry["powershell"] == f"& {entry['bash']}"


def test_antigravity_refuses_a_foreign_hook_under_our_key(tmp_path):
    foreign = {native.OWN_KEY: {"enabled": True, "Stop": [{"command": "echo mine"}]}}
    with pytest.raises(ValueError):
        native.with_shims(foreign, "antigravity", tmp_path)
    assert native.without_shims(foreign, "antigravity") == foreign
