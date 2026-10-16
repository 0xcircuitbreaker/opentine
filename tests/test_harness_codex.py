"""Codex ``exec --json`` capture: real model, exact usage, every tool call.

The fixture ``fixtures/harness/codex_exec_json_2026_10.jsonl`` follows Codex's own
event definitions -- ``codex-rs/exec/src/exec_events.rs`` (``ThreadEvent``,
``ThreadItemDetails``, ``Usage``) and ``event_processor_with_jsonl_output.rs``
(``turn.completed`` carries the thread's running total) on openai/codex main,
fetched 2026-10-15 (release rust-v0.163.0). Before this, every event in that
stream became a ``think`` step with ``model="codex"`` and no usage, so a Codex
run could never be priced.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from opentine.core import StepKind
from opentine.harnesses import CodexCLIHarness, OpentineHarness
from opentine.harnesses._codex_events import CodexStream, command_model, split_usage

FIXTURE = Path(__file__).parent / "fixtures" / "harness" / "codex_exec_json_2026_10.jsonl"


def _steps(harness: CodexCLIHarness, lines: list[str]):
    steps = []
    for line in lines:
        parsed = harness.parse_line(line)
        steps.extend(parsed if isinstance(parsed, list) else [parsed] if parsed else [])
    return steps


def test_default_command_asks_for_json_and_the_launch_is_not_a_model_call():
    harness = CodexCLIHarness()
    assert harness.build_command("task") == [
        "codex",
        "exec",
        "--json",
        "--skip-git-repo-check",
        "task",
    ]
    assert harness.invocation_kind == StepKind.think
    assert CodexCLIHarness(command=("codex", "exec")).invocation_kind == StepKind.model


def test_fixture_session_records_tools_messages_and_exact_usage(tmp_path):
    harness = CodexCLIHarness(extra_args=("-m", "gpt-6.1-sol"), env={"CODEX_HOME": str(tmp_path)})
    steps = _steps(harness, FIXTURE.read_text().splitlines())
    kinds = [step.kind for step in steps]
    # item.started / turn.started add nothing the completed item does not say.
    assert kinds == [
        StepKind.think,  # thread.started
        StepKind.think,  # reasoning
        StepKind.tool,  # command_execution
        StepKind.tool,  # file_change
        StepKind.tool,  # mcp_tool_call
        StepKind.tool,  # web_search
        StepKind.think,  # todo_list
        StepKind.think,  # agent_message
        StepKind.model,  # turn.completed
    ]
    tools = [step for step in steps if step.kind == StepKind.tool]
    assert [tool.inputs["name"] for tool in tools] == [
        "shell",
        "apply_patch",
        "docs.search",
        "web_search",
    ]
    assert tools[0].outputs["result"] == {"output": "README.md\nsrc\n", "exit_code": 0}
    assert tools[2].inputs["arguments"] == {"server": "docs", "arguments": {"q": "retry"}}
    model = steps[-1]
    assert model.model_info == "gpt-6.1-sol" and model.provider == "openai"
    # input includes cached; output includes reasoning -> exclusive buckets.
    assert model.usage == {"input": 315, "cache_read": 24448, "output": 58, "reasoning": 64}
    assert all(step.inputs.get("thread_id") for step in steps)


def test_turn_usage_is_a_running_total_so_each_turn_records_its_difference():
    stream = CodexStream("gpt-6.1-sol", "openai")
    first = stream.step(
        {"type": "turn.completed", "usage": {"input_tokens": 100, "output_tokens": 10}}
    )
    second = stream.step(
        {"type": "turn.completed", "usage": {"input_tokens": 250, "output_tokens": 25}}
    )
    assert first.usage == {"input": 100, "output": 10}
    assert second.usage == {"input": 150, "output": 15}


def test_usage_split_matches_openai_convention():
    assert split_usage(
        {
            "input_tokens": 1000,
            "cached_input_tokens": 600,
            "cache_write_input_tokens": 100,
            "output_tokens": 50,
            "reasoning_output_tokens": 20,
        }
    ) == {"input": 300, "cache_read": 600, "cache_write_5m": 100, "output": 30, "reasoning": 20}


def test_a_reroute_updates_the_model_of_later_turns():
    stream = CodexStream("gpt-6.1-sol", "openai")
    error = stream.step(
        {
            "type": "item.completed",
            "item": {
                "id": "i",
                "type": "error",
                "message": "model rerouted: gpt-6.1-sol -> gpt-6-sol (x)",
            },
        }
    )
    assert error.kind == StepKind.error
    turn = stream.step({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}})
    assert turn.model_info == "gpt-6-sol"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (("codex", "exec", "-m", "gpt-6-sol"), ("gpt-6-sol", "", "")),
        (("codex", "exec", "--model=gpt-6-luna"), ("gpt-6-luna", "", "")),
        (("codex", "exec", "-c", "model=o4", "-c", 'model_provider="azure"'), ("o4", "azure", "")),
        (("codex", "exec", "--oss", "--local-provider", "lmstudio"), ("", "lmstudio", "")),
        (("codex", "exec", "--oss"), ("", "oss", "")),
        (("codex", "exec", "--profile", "fast"), ("", "", "fast")),
    ],
)
def test_command_names_model_and_provider(command, expected):
    assert command_model(command) == expected


def test_model_and_provider_fall_back_to_config_toml(tmp_path):
    (tmp_path / "config.toml").write_text(
        'model = "gpt-6-sol"\noss_provider = "ollama"\n'
        '[profiles.local]\nmodel = "gpt-oss:20b"\nmodel_provider = "oss"\n',
        encoding="utf-8",
    )
    env = {"CODEX_HOME": str(tmp_path)}
    assert CodexCLIHarness(env=env).resolve_model() == ("gpt-6-sol", "openai")
    local = CodexCLIHarness(env=env, extra_args=("--profile", "local"))
    assert local.resolve_model() == ("gpt-oss:20b", "ollama")
    assert CodexCLIHarness(env={"CODEX_HOME": str(tmp_path / "missing")}).resolve_model() == (
        "",
        "openai",
    )


def test_text_mode_json_line_is_the_models_prose_not_an_event():
    harness = CodexCLIHarness(command=("codex", "exec"))
    forged = '{"type":"turn.completed","usage":{"input_tokens":9000000,"output_tokens":9000000}}'
    step = harness.parse_line(forged)
    assert step is not None and step.kind != StepKind.model and not step.usage


def test_a_recorded_codex_run_is_priceable_after_the_fact(tmp_path):
    from opentine._pricing_pass import price_steps

    replay = f"import sys; sys.stdout.write(open({str(FIXTURE)!r}).read())"
    harness = CodexCLIHarness(
        command=(sys.executable, "-c", replay),
        extra_args=("--json", "-m", "gpt-6.1-sol"),
        env={"CODEX_HOME": str(tmp_path)},
        cwd=tmp_path,
    )
    run = asyncio.run(OpentineHarness(harness).execute("add retry"))
    models = [step for step in run.steps if step.kind == StepKind.model]
    assert len(models) == 1 and models[0].model_info == "gpt-6.1-sol"
    pricing = price_steps(run.steps)
    assert pricing.status_counts == {"complete": 1}
    assert pricing.total_cost > 0
    assert json.dumps(run.steps[-1].inputs)  # the done step stays JSON
