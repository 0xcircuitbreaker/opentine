"""0.13 F6: Hermes importer, hook journal/status, Claude Code plugin, read-only MCP,
AdapterSpec SDK. Every fixture is synthetic; HOME and every agent config dir are
temporary, so no real ~/.claude, ~/.codex, ~/.gemini, ~/.hermes or ~/.config is read.
"""

from __future__ import annotations

import io
import json
import sys
from types import SimpleNamespace

import pytest

from opentine import cli
from opentine.repo import Repo
from opentine.trace.schema import TraceEvent


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "HERMES_HOME"):
        monkeypatch.delenv(name, raising=False)
    return home


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "repo")


# -- Hermes trajectories (ShareGPT JSONL, per the Hermes trajectory-format docs) ----

CALL = (
    '<tool_call>\n{"name": "terminal", "arguments": {"command": "wc -l notes.txt"}}\n</tool_call>'
)
RESPONSE = (
    '<tool_response>\n{"tool_call_id": "call_01", "name": "terminal", '
    '"content": "42 notes.txt"}\n</tool_response>'
)


def _trajectory(question="How many lines?", answer="42 lines."):
    return {
        "conversations": [
            {"from": "system", "value": "tool definitions..."},
            {"from": "human", "value": question},
            {"from": "gpt", "value": "<think>\ncount them\n</think>\n" + CALL},
            {"from": "tool", "value": RESPONSE},
            {"from": "gpt", "value": "<think>\n</think>\n" + answer},
        ],
        "timestamp": "2026-01-01T09:00:00.000000",
        "model": "example/model",
        "completed": True,
    }


def _jsonl(path, *records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def test_hermes_trajectory_imports_turns_tools_and_reasoning(tmp_path):
    from opentine.trace._import_hermes import hermes_events

    events = hermes_events(_jsonl(tmp_path / "t.jsonl", _trajectory()))
    kinds = [e.kind for e in events]
    assert kinds == ["human", "model", "tool", "tool", "model"]
    assert events[1].outputs["reasoning"] == "count them" and events[1].model == "example/model"
    assert events[2].inputs["arguments"] == {"command": "wc -l notes.txt"}
    assert events[3].outputs["result"] == "42 notes.txt"
    assert not any(e.usage for e in events)  # trajectories carry no token counts


def test_hermes_picks_the_last_record_or_an_index(tmp_path):
    from opentine.trace._import_hermes import hermes_events

    path = _jsonl(tmp_path / "t.jsonl", _trajectory("first"), _trajectory("second"))
    assert hermes_events(path)[0].inputs["text"] == "second"
    assert hermes_events(f"{path}::0")[0].inputs["text"] == "first"


def test_hermes_hostile_blocks_are_skipped_and_counted(tmp_path):
    from opentine.trace._import_hermes import MAX_CALLS, hermes_events

    record = _trajectory()
    deep = "[" * 100_000 + "]" * 100_000
    many = "".join(f'<tool_call>{{"name": "t{i}"}}</tool_call>' for i in range(MAX_CALLS + 5))
    record["conversations"][2]["value"] = f"<tool_call>{deep}</tool_call>" + many
    events = hermes_events(_jsonl(tmp_path / "t.jsonl", record))
    calls = [e for e in events if e.kind == "tool" and e.span_id.startswith("turn-2.call")]
    assert len(calls) == MAX_CALLS
    assert "skipped" in json.dumps(events[0].attributes)


def test_hermes_is_detected_and_imported_with_an_identity(tmp_path, repo):
    from opentine import _agent_identity as identity

    source = _jsonl(tmp_path / "trajectory_samples.jsonl", _trajectory())
    cli.main(["import", str(source), "--repo", str(repo.path)])
    run = repo.load_run(repo.read_ref("heads/main"))
    assert identity.run_identity(run)["harness"] == "hermes"
    assert run.metadata["capture"]["source_format"] == "hermes-trajectory"


# -- tine hook event / status -------------------------------------------------------


def test_hook_event_reads_stdin_only_and_clamps_ids(repo, monkeypatch):
    from opentine import _hook_journal as journal

    payload = {"hook_event_name": "SubagentStop", "session_id": "s1",
               "agent_id": "../../etc/passwd;rm -rf /", "agent_type": "Explore\n\x00x"}  # fmt: skip
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))
    monkeypatch.setattr(sys, "stdin", stdin)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["hook", "event", "--repo", str(repo.path)])
    assert exit_.value.code == 0
    types = journal.agent_types(repo.path)
    ((agent, kind),) = types.items()  # a stop without a start still names its agent
    assert "/" not in agent and ";" not in agent and " " not in agent
    assert kind == "Explore__x"


@pytest.mark.parametrize(
    "raw", [b"", b"not json", b"[]", b'{"hook_event_name": "PreToolUse", "agent_id": "a"}',
            b'{"hook_event_name": "SubagentStart"}', b"[" * 50_000, b"x" * 300_000],
    ids=lambda raw: f"{len(raw)}b",  # short ids: Windows caps PYTEST_CURRENT_TEST
)  # fmt: skip
def test_hook_event_ignores_anything_else_and_never_fails(repo, raw):
    from opentine import _hook_journal as journal

    assert journal.run_event(str(repo.path), io.BytesIO(raw)) == 0
    assert journal.agent_types(repo.path) == {}


def test_hook_journal_stops_growing_at_its_cap(repo, monkeypatch):
    from opentine import _hook_journal as journal

    monkeypatch.setattr(journal, "MAX_JOURNAL_BYTES", 300)
    record = {"event": "SubagentStart", "session_id": "s", "agent_id": "a", "agent_type": "t"}
    results = [journal.append(repo.path, record) for _ in range(10)]
    assert results[0] and not results[-1]
    assert journal.journal_path(repo.path).stat().st_size <= 300


def test_hook_status_lists_installed_events_without_global(repo, isolated_home, capsys):
    cli.main(["hook", "install", "--global", "--agent", "claude-code", "--repo", str(repo.path)])
    capsys.readouterr()
    cli.main(["hook", "status"])
    out = capsys.readouterr().out
    assert "claude-code" in out and "SessionEnd" in out and "hermes" in out


def test_hermes_hook_install_prints_a_snippet_and_never_writes(repo, isolated_home, capsys):
    cli.main(["hook", "install", "--global", "--agent", "hermes", "--repo", str(repo.path)])
    out = capsys.readouterr().out
    assert "on_session_end" in out and "hermes-trajectory" in out
    assert not (isolated_home / ".hermes").exists()


# -- tine plugin export ------------------------------------------------------------


def test_plugin_export_writes_a_valid_bundle(tmp_path, repo):
    target = tmp_path / "plugin"
    cli.main(["plugin", "export", str(target), "--repo", str(repo.path)])
    manifest = json.loads((target / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == "opentine" and not manifest["name"].startswith("claude")
    hooks = json.loads((target / "hooks" / "hooks.json").read_text())["hooks"]
    assert set(hooks) == {"SessionEnd", "SubagentStart", "SubagentStop"}
    for groups in hooks.values():
        (entry,) = groups[0]["hooks"]
        assert entry["type"] == "command" and entry["command"] == sys.executable
        assert entry["args"][:3] == ["-I", "-m", "opentine.cli"]  # exec form, no shell
    mcp = json.loads((target / ".mcp.json").read_text())["mcpServers"]["opentine"]
    assert mcp["args"][-1] == "--read-only"
    for skill in target.glob("skills/*/SKILL.md"):
        assert skill.read_text().startswith(f"---\nname: {skill.parent.name}\n")
    with pytest.raises(SystemExit):  # not empty, no --force
        cli.main(["plugin", "export", str(target), "--repo", str(repo.path)])


def test_plugin_export_never_writes_into_claude_config(isolated_home, repo, tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        cli.main(["plugin", "export", str(isolated_home / ".claude" / "plugins" / "x"),
                  "--repo", str(repo.path)])  # fmt: skip
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cc"))
    with pytest.raises(SystemExit):
        cli.main(["plugin", "export", str(tmp_path / "cc" / "p"), "--repo", str(repo.path)])
    assert not (isolated_home / ".claude").exists() and not (tmp_path / "cc").exists()


# -- read-only MCP -------------------------------------------------------------------


class _FakeServer:
    def __init__(self):
        self.tools = []

    def tool(self, *args, **kwargs):
        return lambda function: self.tools.append(function.__name__) or function

    def resource(self, *args, **kwargs):
        return lambda function: function


def test_read_only_mcp_registers_only_allowlisted_tools():
    from opentine._mcp_actions import register_actions_and_repository
    from opentine._mcp_readonly import READ_ONLY_TOOLS, ReadOnlyTools

    server = _FakeServer()
    view = ReadOnlyTools(server)

    @view.tool()
    def fork_run():  # a write tool: never registered
        pass

    @view.tool()
    def list_runs():
        pass

    @view.tool()
    def brand_new_tool():  # unknown: left out until reviewed
        pass

    register_actions_and_repository(view, ".tine_runs", ".")
    assert set(server.tools) <= READ_ONLY_TOOLS and "list_runs" in server.tools
    assert {"fork_run", "brand_new_tool"} <= set(view.skipped)


# -- AdapterSpec SDK -----------------------------------------------------------------


def _events(source):
    return [TraceEvent(kind="model", timestamp=1.0, trace_id="t", span_id="s", model="m")]


class _Point:
    def __init__(self, name, target):
        self.name, self.target, self.loaded = name, target, False

    def load(self):
        self.loaded = True
        return self.target


def _points(monkeypatch, *points):
    from opentine.harnesses import _adapter_spec

    monkeypatch.setattr(_adapter_spec.metadata, "entry_points", lambda group: list(points))


def _allow(isolated_home, *names):
    path = isolated_home / ".config" / "opentine" / "adapters.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"allow": list(names)}))


def test_entry_point_adapters_are_not_loaded_unless_allowlisted(monkeypatch, isolated_home):
    from opentine.adapters import AdapterSpec
    from opentine.harnesses._adapter_spec import external_specs

    point = _Point("acme", AdapterSpec("acme", _events, harness="acme"))
    _points(monkeypatch, point)
    specs, skipped = external_specs()
    assert specs == {} and not point.loaded and "not allowlisted" in skipped["acme"]
    _allow(isolated_home, "acme")
    specs, _ = external_specs()
    assert point.loaded and specs["acme"].harness == "acme"


def test_an_allowlisted_adapter_cannot_shadow_a_builtin_or_lie(monkeypatch, isolated_home):
    from opentine.adapters import AdapterSpec
    from opentine.harnesses._adapter_spec import external_specs

    shadow = _Point("atif", AdapterSpec("atif", _events))
    liar = _Point("good", AdapterSpec("other", _events))
    _points(monkeypatch, shadow, liar)
    _allow(isolated_home, "atif", "good")
    specs, skipped = external_specs()
    assert specs == {} and not shadow.loaded and "name mismatch" in skipped["good"]


def test_core_caps_bind_every_adapter(tmp_path, monkeypatch):
    from opentine.adapters import AdapterSpec, run_adapter
    from opentine.harnesses import _adapter_spec

    with pytest.raises(ValueError, match="list of TraceEvent"):
        run_adapter(AdapterSpec("bad", lambda source: [{"kind": "model"}]), ["x"])
    monkeypatch.setattr(_adapter_spec, "MAX_EVENTS", 0)
    with pytest.raises(ValueError, match="exceeded"):
        run_adapter(AdapterSpec("big", _events), ["x"])
    monkeypatch.setattr(_adapter_spec, "MAX_SOURCE_BYTES", 1)
    big = tmp_path / "big.jsonl"
    big.write_text("xx")
    with pytest.raises(ValueError, match="exceeds"):
        run_adapter(AdapterSpec("ok", _events), big)


def test_harnesses_check_runs_fixtures_and_reports(monkeypatch, isolated_home, capsys):
    from opentine.adapters import AdapterSpec

    def broken(source):
        raise RuntimeError("boom")

    _points(monkeypatch, _Point("good", AdapterSpec("good", _events, fixture=("{}",))),
            _Point("bad", AdapterSpec("bad", broken, fixture=("{}",))))  # fmt: skip
    _allow(isolated_home, "good")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["harnesses", "--check"])
    out = capsys.readouterr().out
    assert exit_.value.code == 0 and "hermes-trajectory" in out and "not allowlisted" in out
    _allow(isolated_home, "good", "bad")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["harnesses", "--check", "bad"])
    assert exit_.value.code == 1 and "boom" in capsys.readouterr().out


def test_import_through_an_allowlisted_adapter(tmp_path, repo, monkeypatch, isolated_home):
    from opentine import _agent_identity as identity
    from opentine.adapters import AdapterSpec

    _points(monkeypatch, _Point("acme", AdapterSpec("acme", _events, harness="acme-cli")))
    source = tmp_path / "s.log"
    source.write_text("anything")
    with pytest.raises(SystemExit):  # not allowlisted: refused, never loaded
        cli.main(["import", str(source), "--adapter", "acme", "--repo", str(repo.path)])
    _allow(isolated_home, "acme")
    cli.main(["import", str(source), "--adapter", "acme", "--repo", str(repo.path)])
    run = repo.load_run(repo.read_ref("heads/main"))
    assert identity.run_identity(run)["harness"] == "acme-cli"
