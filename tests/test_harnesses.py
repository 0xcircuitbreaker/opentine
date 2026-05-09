"""Tests for external harness adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.cli import _build_parser
from opentine.core import Run, RunStatus, StepKind
from opentine.harnesses import CodexCLIHarness, HarnessStep, OpentineHarness
from opentine.mcp_server import diff_runs_text, fork_run_file, format_run_for_llm, list_run_summaries


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
