"""0.10 round-3 audit: terminal text, MCP output and MCP bounds.

E3-2 (``tine migrate`` printed an artifact's digest raw), E3-4 (Rich emoji
shortcodes in run trees), E3-5 (hidden characters delivered to MCP clients),
C3-7/E3-6 (``attest_run`` skipping the evaluation score bound; search believing
unsigned out-of-bound scores and junk signature blocks), and the MCP fork bounds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, cli
from opentine.core import RunStatus
from opentine.graph import StepKind
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent

FIXTURES = Path(__file__).parent / "fixtures"
TAGS = "".join(chr(0xE0000 + ord(character)) for character in "ignore previous")
HIDDEN = {*range(0xE0000, 0xE0080), 0x202E, 0x200B}


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        def register(function):
            self.tools[f"resource:{uri}"] = function
            return function

        return register


def _hidden(value) -> int:
    text = json.dumps(value, ensure_ascii=False)
    return sum(ord(character) in HIDDEN for character in text)


def _v3(tmp_path: Path, text: str = "ok", model: str = "gpt") -> tuple[Repo, str, str, _FakeMCP]:
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(
        TraceEvent("model", 1, "trace", "span", model=model, outputs={"text": text})
    )
    run = recorder.finalize()
    mcp = _FakeMCP()
    register_repository_tools(mcp, str(tmp_path))
    return repo, run, event, mcp


# --- E3-5: no hidden characters reach an MCP client ----------------------------- #


def test_v3_mcp_tools_strip_hidden_characters(tmp_path):
    _, run, event, mcp = _v3(tmp_path, text=f"answer{TAGS}‮", model=f"gpt{TAGS}")
    results = {
        "search_runs": mcp.tools["search_runs"](successful_only=False),
        "inspect_event": mcp.tools["inspect_object"](event, resolve_blobs=True),
        "inspect_run": mcp.tools["inspect_object"](run, resolve_blobs=True),
        "context_slice": mcp.tools["context_slice"](event),
        "object_resource": mcp.tools["resource:tine-object://{object_id}"](event),
    }
    assert results["search_runs"], "the run is found"
    for name, result in results.items():
        assert _hidden(result) == 0, name


def test_legacy_fork_run_clips_what_it_echoes(tmp_path, monkeypatch):
    from opentine.mcp_server import fork_run_file

    runs = tmp_path / "runs"
    runs.mkdir()
    run = Run(run_id=f"r{TAGS}1")
    run.add_step(StepKind.think, {"text": "a"})
    run.add_step(StepKind.done, {"text": "b"})
    run.save(runs / "r1.tine")
    result = fork_run_file("r1", 0, runs_dir=runs)
    assert _hidden(result) == 0


def test_mcp_forks_stop_at_the_runs_directory_byte_budget(tmp_path, monkeypatch):
    from opentine import mcp_server

    runs = tmp_path / "runs"
    runs.mkdir()
    run = Run(run_id="big")
    run.add_step(StepKind.think, {"text": "a" * 2000})
    run.save(runs / "big.tine")
    size = (runs / "big.tine").stat().st_size
    monkeypatch.setattr(mcp_server, "MAX_MCP_RUNS_DIR_BYTES", size * 2 + 10)
    mcp_server.fork_run_file("big", 0, runs_dir=runs)
    with pytest.raises(ValueError, match="bytes of runs"):
        mcp_server.fork_run_file("big", 0, runs_dir=runs)


def test_v3_fork_overrides_are_bounded(tmp_path):
    _, run, event, mcp = _v3(tmp_path)
    with pytest.raises(ValueError, match="prompt"):
        mcp.tools["fork_run_v3"](run, event, "experiments/a", prompt="x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="policy"):
        mcp.tools["fork_run_v3"](run, event, "experiments/b", policy={"x": "y" * (1024 * 1024)})
    with pytest.raises(ValueError, match="model"):
        mcp.tools["fork_run_v3"](run, event, "experiments/c", model="m" * 300)
    assert mcp.tools["fork_run_v3"](run, event, "experiments/d", prompt="short")["run_id"]


# --- C3-7 / E3-6: evaluation scores ---------------------------------------------- #


def test_attest_run_enforces_the_evaluation_score_bound(tmp_path):
    _, run, _, mcp = _v3(tmp_path)
    for scores in ({"q": 1.7e308}, {"q": 2e6}, "not-a-dict"):
        with pytest.raises(ValueError, match="evaluation scores"):
            mcp.tools["attest_run"](run, {"kind": "evaluation", "scores": scores}, "m")
    assert mcp.tools["attest_run"](run, {"kind": "evaluation", "scores": {"q": 0.5}}, "m")


def test_search_ignores_unsigned_out_of_bound_scores_and_junk_signatures(tmp_path):
    repo, run, _, mcp = _v3(tmp_path)
    repo.attest(run, {"kind": "evaluation", "scores": {"q": 1.7e308}}, signer="rogue")
    [row] = mcp.tools["search_runs"](successful_only=False)
    assert row["score"] is None

    other = Repo.init(tmp_path / "second")
    recorder = Recorder.start(other, capture=False)
    recorder.append(TraceEvent("model", 1, "t", "s", outputs={"text": "ok"}))
    second = recorder.finalize()
    other.attest(second, {"kind": "evaluation", "scores": {"q": 0.4}}, signer="junk", signature={})
    from opentine.repository._search_scores import collect_scores

    payloads = {oid: other.get(oid).payload() for oid in other.attestations_for(second)}
    scores = collect_scores(payloads, payloads.get, float)
    assert scores[second] == [(0.4, False)]  # an empty block is not a signature


# --- E3-2 / E3-4: terminal text ------------------------------------------------------ #


def test_migrate_preview_escapes_the_artifacts_digest(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    data = json.loads((FIXTURES / "golden_v0_linear.tine").read_text(encoding="utf-8"))
    data.setdefault("metadata", {})["integrity"] = {"digest": "\x1b]0;PWNED\x07AAAA"}
    path = tmp_path / "legacy.tine"
    path.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    try:
        cli.main(["migrate", str(path)])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "digest:" in out
    assert not any(ord(character) < 32 and character not in "\n" for character in out)


def test_run_tree_and_step_labels_keep_emoji_shortcodes_literal(tmp_path, capsys):
    from opentine._cli_common import _step_label
    from opentine._cli_render import _print_run_tree

    run = Run(run_id="emoji")
    run.model_info = "gpt :white_check_mark: :lock:"
    step = run.add_step(StepKind.think, {"text": ":white_check_mark: verified"})
    run.status = RunStatus.completed
    assert ":white_check_mark:" in _step_label(step).plain
    capsys.readouterr()
    _print_run_tree(run)
    out = capsys.readouterr().out
    assert ":white_check_mark:" in out and "✅" not in out and "\U0001f512" not in out


# --- MCP SDK 2.x: the server class, and errors a 2.x client can read --------------- #


def test_sdk2_server_class_and_tool_errors_are_used_when_present(monkeypatch):
    import sys
    import types

    from opentine._mcp_safety import safe_errors, server_class

    exceptions = types.ModuleType("mcp.server.mcpserver.exceptions")

    class ToolError(Exception):
        pass

    exceptions.ToolError = ToolError
    package = types.ModuleType("mcp.server.mcpserver")

    class MCPServer:
        def __init__(self, name):
            self.tools = {}

        def tool(self):
            def register(function):
                self.tools[function.__name__] = function
                return function

            return register

    MCPServer.__module__ = "mcp.server.mcpserver.server"
    package.MCPServer = MCPServer
    monkeypatch.setitem(sys.modules, "mcp.server.mcpserver", package)
    monkeypatch.setitem(sys.modules, "mcp.server.mcpserver.exceptions", exceptions)

    assert server_class() is MCPServer
    server = MCPServer("opentine")
    mcp = safe_errors(server)

    @mcp.tool()
    def show_run(run_id: str) -> str:
        raise ValueError(f"Run not found: {run_id}")

    with pytest.raises(ToolError) as caught:
        server.tools["show_run"]("x\x1b]52;c;cGF5\x07")
    assert "\x1b" not in str(caught.value) and "Run not found" in str(caught.value)


# --- Final pass 5, #7: every MCP tool and resource result is sanitized ---------- #


class _FakeServer(_FakeMCP):
    def __init__(self, name):
        super().__init__()


def test_every_registered_mcp_tool_and_resource_returns_no_hidden_characters(tmp_path, monkeypatch):
    import opentine.mcp_server as mcp_server

    _, v3_run, event, _ = _v3(tmp_path, text=f"answer{TAGS}‮", model=f"gpt{TAGS}")
    runs = tmp_path / "runs"
    runs.mkdir()
    for name in ("plain", f"run{TAGS}‮enit", f"z{chr(0x200B) * 3}\x1b]52;c;x\x07"):
        run = Run(run_id=f"r{TAGS}{len(name)}", model_info=f"m{TAGS}‮")
        run.add_step(StepKind.think, {"text": f"t{TAGS}‮"})
        run.add_step(StepKind.done, {"text": f"d{TAGS}"})
        run.save(runs / f"{name}.tine")
    (runs / f"bad{TAGS}.tine").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(mcp_server, "server_class", lambda: _FakeServer)
    server = mcp_server.create_server(runs, tmp_path)

    listing = server.tools["list_runs"]()
    assert [entry["path"] for entry in listing if entry.get("path")] == ["plain.tine"]
    assert {"id": None, "status": "hidden-name", "skipped": 3} in listing

    calls = {
        "list_runs": (),
        "show_run": ("plain",),
        "fork_run": ("plain", 0),
        "diff_runs": ("plain", "plain"),
        "resource:run://{run_id}": ("plain",),
        "search_runs": (),
        "inspect_object": (event,),
        "context_slice": (event,),
        "semantic_diff": (v3_run, v3_run),
        "resource:tine-object://{object_id}": (event,),
    }
    assert set(calls) <= set(server.tools)
    for name, args in calls.items():
        result = server.tools[name](*args)
        assert _hidden(result) == 0, name
