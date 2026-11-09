"""0.36 (A4): MCP tools come from one registry, annotated read or write.

The read-only default exposes no write tool; ``--allow-writes`` exposes exactly
the annotated write set; and every tool generated from the registry returns the
same payload as its ``tine ... --json`` counterpart.
"""

from __future__ import annotations

import inspect
import json

import pytest

from opentine import cli, mcp_server
from opentine._mcp_cli_tools import cli_argv
from opentine._mcp_readonly import ALLOW_WRITES_ENV
from opentine._mcp_registry import CLI_TOOLS, TOOLS
from opentine.core import Run, StepKind
from opentine.parallel._state import State
from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent

#: The 0.35 surface: its names stay, with the same parameters.
LEGACY_14 = {
    "list_runs",
    "show_run",
    "fork_run",
    "diff_runs",
    "find_actions",
    "search_runs",
    "inspect_object",
    "context_slice",
    "semantic_diff",
    "fork_run_v3",
    "resume_run_v3",
    "evaluate_run",
    "attest_run",
    "promote_run",
}
NEW_READ = {"verify_run", "log", "fleet_status", "fanout_status", "cost", "agent_show", "stats",
            "code_graph"}  # fmt: skip


class _FakeServer:
    def __init__(self, name):
        self.tools = {}

    def tool(self, *args, **kwargs):
        return lambda function: self.tools.setdefault(function.__name__, function)

    def resource(self, *args, **kwargs):
        return lambda function: function


@pytest.fixture
def fixture_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "server_class", lambda: _FakeServer)
    monkeypatch.delenv(ALLOW_WRITES_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    (tmp_path / ".tine_runs").mkdir()
    run = Run(id="legacy_run", model_info="mock-model", user_prompt="prompt")
    step = run.add_step(StepKind.model, {"text": "ask"}, {"text": "answer"}, usage={"input": 3})
    run.add_step(StepKind.done, {"text": "done"}, parent_id=step.id)
    run.save(tmp_path / ".tine_runs" / "legacy_run.tine")
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "ok"}))
    (tmp_path / "run.oid").write_text(recorder.finalize())
    member = {"cost": "0.5", "key": "0", "ref": None, "returncode": 0, "run": None}
    member |= {"status": "ok", "vary": {"agent": "coder"}}
    states = ((repo.path / "fanouts", "fan-out"), (tmp_path / ".tine_fleet", "fleet"))
    for directory, kind in states:
        directory.mkdir(parents=True, exist_ok=True)
        State.create(directory, id="0123456789ab", command_digest="0" * 64, budget=None,
                     source={"kind": kind, "name": "n"}, members=[member])  # fmt: skip
    return tmp_path


def _tools(root, *, writes):
    return mcp_server.create_server(root / ".tine_runs", root, read_only=not writes).tools


def test_registry_keeps_the_014_tools_and_adds_the_read_tools():
    assert LEGACY_14 | NEW_READ <= set(TOOLS)
    assert not any(TOOLS[name].writes for name in NEW_READ)


def test_tool_lists_match_the_annotations(fixture_repo):
    read_only = set(_tools(fixture_repo, writes=False))
    writes = set(_tools(fixture_repo, writes=True))
    annotated_writes = {n for n, s in TOOLS.items() if s.writes and not s.operator_only}
    assert read_only == {n for n, s in TOOLS.items() if not s.writes}
    assert not read_only & {n for n, s in TOOLS.items() if s.writes}
    assert writes - read_only == annotated_writes
    assert writes == read_only | annotated_writes


def test_legacy_tool_schemas_are_unchanged(fixture_repo):
    tools = _tools(fixture_repo, writes=True)
    fork = ["run_id", "from_step", "reason"]
    assert list(inspect.signature(tools["fork_run"]).parameters) == fork
    assert list(inspect.signature(tools["diff_runs"]).parameters) == ["run_a", "run_b"]


ARGUMENTS = {
    "verify_run": {"run_id": "legacy_run"},
    "log": {},
    "fleet_status": {},
    "fanout_status": {},
    "cost": {"run_id": "legacy_run"},
    "agent_show": {"target": None},
    "stats": {},
    "code_graph": {"symbol": "main"},
}


@pytest.mark.parametrize("name", sorted(ARGUMENTS))
def test_generated_tool_returns_the_cli_json_payload(fixture_repo, capsys, name):
    tool = _tools(fixture_repo, writes=False)[name]
    arguments = dict(ARGUMENTS[name])
    if "target" in arguments:  # the recorded v3 run
        arguments["target"] = (fixture_repo / "run.oid").read_text()
    payload = tool(**arguments)
    argv = cli_argv(TOOLS[name], fixture_repo, **arguments)
    try:
        cli.main(argv)
    except SystemExit:
        pass
    assert payload == json.loads(capsys.readouterr().out)
    assert payload


def test_every_cli_tool_is_covered_and_option_values_are_refused(fixture_repo):
    assert {spec.name for spec in CLI_TOOLS} == set(ARGUMENTS)
    tool = _tools(fixture_repo, writes=False)["cost"]
    with pytest.raises(ValueError, match="may not start"):
        tool(run_id="--help")
    with pytest.raises(ValueError, match="integer"):
        _tools(fixture_repo, writes=False)["log"](limit=True)
