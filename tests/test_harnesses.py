"""Tests for external harness adapters."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path
from typing import Any

import pytest

from opentine.cli import _build_parser
from opentine.core import Run, RunStatus, StepKind
from opentine.harnesses import (
    ClaudeCodeHarness,
    CodexCLIHarness,
    CursorHarness,
    GenericHarness,
    HarnessStep,
    HermesHarness,
    KimiCodeHarness,
    OpenClawHarness,
    OpenCodeHarness,
    OpentineHarness,
)
from opentine.mcp_server import (
    diff_runs_text,
    find_run,
    fork_run_file,
    format_run_for_llm,
    list_run_summaries,
)


class DummyHarness:
    name = "dummy"
    model_info = "dummy-model"

    async def execute(self, task: str, context=None, step_callback=None) -> dict[str, Any]:
        assert context == {"repo": "opentine"}
        if step_callback:
            step_callback(
                HarnessStep(
                    kind=StepKind.think,
                    inputs={"text": f"planning {task}"},
                    cost=0.01,
                )
            )
            step_callback(
                HarnessStep(
                    kind=StepKind.tool,
                    inputs={"name": "edit", "arguments": {"path": "auth.py"}},
                    outputs={"result": "patched"},
                    cost=0.02,
                )
            )
        return {"ok": True, "task": task}


def test_opentine_harness_records_external_steps(tmp_path: Path):
    out = tmp_path / "run.tine"
    wrapped = OpentineHarness(DummyHarness())

    run = wrapped.run_sync("refactor auth", context={"repo": "opentine"}, save_path=out)

    assert out.exists()
    assert run.status == RunStatus.completed
    assert run.metadata["harness"] == "dummy"
    assert [step.kind for step in run.steps] == [
        StepKind.model,
        StepKind.think,
        StepKind.tool,
        StepKind.done,
    ]
    assert abs(run.total_cost - 0.03) < 1e-9


def test_opentine_harness_forks_by_index():
    wrapped = OpentineHarness(DummyHarness())
    run = wrapped.run_sync("task", context={"repo": "opentine"})

    forked = wrapped.fork(1, new_run_id="forked")

    assert forked.id == "forked"
    assert len(forked.steps) == 2
    assert forked.metadata["forked_from"] == run.id
    assert forked.metadata["next_harness"] == "dummy"


def test_codex_json_event_parser_extracts_tool_steps():
    harness = CodexCLIHarness()

    step = harness.parse_line(
        '{"type":"tool_call","name":"shell","arguments":{"cmd":"pytest"},'
        '"output":"ok","cost":0.04,"duration":1.2}'
    )

    assert step is not None
    assert step.kind == StepKind.tool
    assert step.inputs["name"] == "shell"
    assert step.outputs["result"] == "ok"
    assert step.cost == 0.04
    assert step.duration == 1.2


def test_agent_cli_harness_command_defaults():
    assert CodexCLIHarness().build_command("task") == [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "task",
    ]
    assert OpenCodeHarness().build_command("task") == ["opencode", "run", "task"]
    assert KimiCodeHarness().build_command("task") == [
        "kimi",
        "--print",
        "--output-format",
        "stream-json",
        "--prompt",
        "task",
    ]
    assert OpenClawHarness().build_command("task") == [
        "openclaw",
        "agent",
        "--local",
        "--json",
        "--message",
        "task",
    ]
    assert HermesHarness().build_command("task") == ["hermes", "chat", "-q", "task"]
    assert GenericHarness(command=("agent", "run")).build_command("task") == [
        "agent",
        "run",
        "task",
    ]
    with pytest.raises(ValueError, match="cannot begin"):
        GenericHarness(command=("agent", "run")).build_command("--unsafe")


def test_agent_cli_harness_parses_structured_and_text_events():
    kimi = KimiCodeHarness()
    step = kimi.parse_line(
        '{"type":"tool_call","name":"read_file","arguments":{"path":"README.md"},'
        '"output":"ok","session_id":"s1"}'
    )
    assert step is not None
    assert step.kind == StepKind.tool
    assert step.inputs["name"] == "read_file"
    assert step.inputs["session_id"] == "s1"

    openclaw = OpenClawHarness()
    step = openclaw.parse_line('{"type":"message","content":"done","sessionId":"abc"}')
    assert step is not None
    assert step.kind == StepKind.think
    assert step.inputs["sessionId"] == "abc"

    hermes = HermesHarness()
    step = hermes.parse_line("Tool terminal: read README.md")
    assert step is not None
    assert step.kind == StepKind.tool
    assert step.inputs["name"] == "read"


def test_login_env_mode_is_allowlisted(monkeypatch):
    monkeypatch.setenv("PATH", "/bin")
    monkeypatch.setenv("HOME", "/tmp/home")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("CUSTOM_CONFIG_DIR", "/tmp/custom")

    isolated = OpenCodeHarness().build_env()
    login = OpenCodeHarness(login_env=True, env_allowlist=("CUSTOM_CONFIG_DIR",)).build_env()

    assert isolated == {}
    assert login["PATH"] == "/bin"
    assert login["HOME"] == "/tmp/home"
    assert login["CUSTOM_CONFIG_DIR"] == "/tmp/custom"
    assert "OPENAI_API_KEY" not in login


def test_mcp_helpers_list_fork_and_diff_runs(tmp_path: Path):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    run = Run(id="original", model_info="dummy")
    run.add_step(StepKind.think, {"text": "plan"})
    run.add_step(StepKind.tool, {"name": "edit", "arguments": {}})
    run.save(runs_dir / "original.tine")

    summaries = list_run_summaries(runs_dir)
    assert summaries[0]["id"] == "original"

    formatted = format_run_for_llm(run)
    assert "Run: original" in formatted
    assert "0. think" in formatted

    forked = fork_run_file("original", 0, runs_dir=runs_dir)
    assert forked["forked_from"] == "original"

    diff = diff_runs_text("original", forked["new_run_id"], runs_dir)
    assert "Diff: original" in diff


def test_mcp_run_lookup_cannot_escape_configured_directory(tmp_path: Path):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    outside = tmp_path / "outside.tine"
    run = Run(id="outside")
    run.add_step(StepKind.done, {"text": "secret outside configured history"})
    run.save(outside)

    with pytest.raises(FileNotFoundError):
        find_run(str(outside), runs_dir)
    with pytest.raises(FileNotFoundError):
        find_run("../outside.tine", runs_dir)

    linked = runs_dir / "linked.tine"
    try:
        linked.symlink_to(outside)
    except OSError:
        return
    with pytest.raises(FileNotFoundError):
        find_run("linked.tine", runs_dir)
    assert list_run_summaries(runs_dir) == []


def test_cli_accepts_harness_flags():
    parser = _build_parser()

    args = parser.parse_args(
        [
            "run",
            "--harness",
            "codex",
            "--harness-command",
            "codex exec",
            "--prompt",
            "fix tests",
        ]
    )

    assert args.command == "run"
    assert args.harness == "codex"
    assert args.prompt == "fix tests"
    assert args.harness_timeout == 3_600
    assert args.harness_max_output == 4_000_000
    assert args.harness_max_events == 10_000
    assert args.harness_max_line_bytes == 1_000_000


def _python_harness(code: str, **limits) -> GenericHarness:
    return GenericHarness(command=(sys.executable, "-c", code), **limits)


def test_process_harness_enforces_output_event_line_and_time_limits():
    with pytest.raises(RuntimeError, match="output exceeds 20 characters"):
        asyncio.run(_python_harness("print('x' * 40)", max_output_chars=20).execute("ignored"))
    with pytest.raises(RuntimeError, match="more than 1 events"):
        asyncio.run(_python_harness("print('one'); print('two')", max_events=1).execute("ignored"))
    with pytest.raises(RuntimeError, match="output line exceeds 64 bytes"):
        asyncio.run(_python_harness("print('x' * 1000)", max_line_bytes=64).execute("ignored"))
    with pytest.raises(TimeoutError, match="0.05-second timeout"):
        asyncio.run(
            _python_harness("import time; time.sleep(60)", timeout_seconds=0.05).execute("ignored")
        )


def test_process_harness_cleans_up_after_callback_failure():
    harness = _python_harness("import time; print('started', flush=True); time.sleep(60)")

    def fail(step):
        if step.inputs.get("text") == "started":
            raise RuntimeError("callback failed")
        return "recorded"

    with pytest.raises(RuntimeError, match="callback failed"):
        asyncio.run(harness.execute("ignored", step_callback=fail))


def test_process_harness_preserves_bounded_output():
    result = asyncio.run(_python_harness("print('hello')").execute("ignored"))
    assert result == {"output": "hello", "returncode": 0}


def test_process_harness_does_not_wait_for_descendant_held_stdout():
    child = "import time; time.sleep(60)"
    parent = (
        "import subprocess,sys,time; time.sleep(.1); "
        f"subprocess.Popen([sys.executable,'-c',{child!r}]); print('done',flush=True)"
    )
    result = asyncio.run(_python_harness(parent, timeout_seconds=2).execute("ignored"))
    assert result == {"output": "done", "returncode": 0}


@pytest.mark.skipif(os.name == "nt", reason="setsid is POSIX-specific")
def test_process_harness_closes_pipe_from_an_escaped_descendant(tmp_path: Path):
    pidfile = tmp_path / "escaped.pid"
    child = f"import os,time; open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(60)"
    parent = (
        "import pathlib,subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True); "
        f"p=pathlib.Path({str(pidfile)!r}); "
        "[(time.sleep(.01)) for _ in range(100) if not p.exists()]; print('done',flush=True)"
    )
    try:
        result = asyncio.run(_python_harness(parent, timeout_seconds=2).execute("ignored"))
        assert result == {"output": "done", "returncode": 0}
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize(
    ("cost", "duration", "name"),
    [(float("nan"), 0, "cost"), (-1, 0, "cost"), (0, float("inf"), "duration")],
)
def test_harness_rejects_invalid_accounting_metrics(cost, duration, name):
    class InvalidMetricHarness:
        name = "invalid"
        model_info = "invalid"

        def execute(self, task, context=None, step_callback=None):
            step_callback(HarnessStep(StepKind.think, cost=cost, duration=duration))
            return {"ok": True}

    wrapped = OpentineHarness(InvalidMetricHarness())
    with pytest.raises(ValueError, match=rf"harness {name} must be finite and non-negative"):
        wrapped.run_sync("task")
    assert wrapped.run is not None and wrapped.run.status == RunStatus.failed


@pytest.mark.parametrize("cost", ["nan", -5, 1e309, True])
def test_external_json_harness_rejects_invalid_cost_before_callback(cost):
    line = json.dumps({"type": "message", "cost": cost})
    with pytest.raises(ValueError, match="harness cost must be finite and non-negative"):
        GenericHarness().parse_line(line)


@pytest.mark.parametrize(
    "harness", [GenericHarness(), CodexCLIHarness(), ClaudeCodeHarness(), CursorHarness()]
)
def test_external_json_harness_treats_null_cost_as_missing(harness):
    step = harness.parse_line('{"type":"message","cost":null,"price":0.25}')
    assert step is not None and step.cost == 0.25
