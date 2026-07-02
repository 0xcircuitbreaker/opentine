"""Tests for external harness adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.cli import _build_parser
from opentine.core import Run, RunStatus, StepKind
from opentine.harnesses import (
    CodexCLIHarness,
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
