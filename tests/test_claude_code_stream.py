"""The claude-code harness records model, usage, tools and cost from stream-json.

The fixture is a live Claude Code capture (2026-10, paths and ids scrubbed). It
pins the detail that decides pricing: an assistant event's ``output_tokens`` is
a message-start placeholder (16 and 4 here), while the ``result`` event's
``modelUsage`` carries the true 120 -- and with the catalog's Opus 5.5 card the
recorded steps re-price to exactly the $0.100061 Claude Code itself reported.
"""

from __future__ import annotations

import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from opentine.billing import Usage, bill, load_catalogs
from opentine.core import StepKind
from opentine.harnesses.claude_code import ClaudeCodeHarness

FIXTURE = Path(__file__).parent / "fixtures" / "harness" / "claude_code_stream_2026_10.jsonl"


def _steps(harness: ClaudeCodeHarness, lines: list[str]) -> list:
    steps = []
    for line in lines:
        parsed = harness.parse_line(line)
        steps.extend(parsed if isinstance(parsed, list) else [parsed] if parsed else [])
    return steps


def _fixture_lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_the_default_command_asks_for_the_structured_stream():
    assert ClaudeCodeHarness().default_command == (
        "claude",
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
    )


def test_a_live_capture_becomes_model_tool_and_result_steps():
    steps = _steps(ClaudeCodeHarness(), _fixture_lines())
    assert [step.kind for step in steps] == [
        StepKind.think,  # init: model, version, tools
        StepKind.model,  # tool_use turn
        StepKind.tool,  # Read, with its result
        StepKind.model,  # answer turn
        StepKind.model,  # result-usage: the true output for the model
        StepKind.done,
    ]
    tool = steps[2]
    assert tool.inputs["name"] == "Read" and "alpha beta" in tool.outputs["result"]
    assert {step.model_info for step in steps} == {"claude-opus-5-5"}
    assert {step.provider for step in steps if step.kind == StepKind.model} == {"anthropic"}


def test_per_model_usage_equals_claude_codes_own_totals():
    steps = _steps(ClaudeCodeHarness(), _fixture_lines())
    total: dict[str, int] = {}
    for step in steps:
        for name, value in step.usage.items():
            total[name] = total.get(name, 0) + value
    assert total == {"input": 4, "cache_read": 32_145, "cache_write_1h": 11_402, "output": 120}
    assert steps[-1].cost == pytest.approx(0.100061), "Claude Code's own figure, recorded"


def test_the_catalog_re_prices_the_run_to_claude_codes_reported_cost():
    catalog = load_catalogs()
    priced = sum(
        (
            Decimal(
                str(
                    bill(
                        step.provider,
                        step.model_info,
                        Usage(**step.usage),
                        catalog=catalog,
                        effective_at="2026-10-08",
                    ).amount_usd
                )
            )
            for step in _steps(ClaudeCodeHarness(), _fixture_lines())
            if step.kind == StepKind.model and step.usage
        ),
        Decimal("0"),
    )
    assert priced == Decimal("0.100061")


def test_a_message_streamed_as_several_events_counts_its_usage_once():
    lines = _fixture_lines()
    duplicated = lines[:2] + [lines[1]] + lines[2:]
    steps = _steps(ClaudeCodeHarness(), duplicated)
    assert sum(step.usage.get("cache_read", 0) for step in steps) == 32_145


def test_parallel_tool_results_in_one_event_become_one_step_each():
    harness = ClaudeCodeHarness()
    assistant = {
        "type": "assistant",
        "message": {
            "id": "m1",
            "model": "claude-opus-5-5",
            "content": [
                {"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "x"}},
                {"type": "tool_use", "id": "b", "name": "Grep", "input": {"pattern": "y"}},
            ],
        },
    }
    results = {
        "type": "user",
        "message": {
            "content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "one"},
                {
                    "type": "tool_result",
                    "tool_use_id": "b",
                    "content": [{"type": "text", "text": "two"}],
                },
            ]
        },
    }
    steps = _steps(harness, [json.dumps(assistant), json.dumps(results)])
    tools = [step for step in steps if step.kind == StepKind.tool]
    assert [(t.inputs["name"], t.outputs["result"]) for t in tools] == [
        ("Read", "one"),
        ("Grep", "two"),
    ]


def test_the_provider_comes_from_the_environment_claude_code_receives(monkeypatch):
    # The parent's own variable is not forwarded to the subprocess, so it must
    # not decide the provider; the harness's explicit env does.
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    assert _steps(ClaudeCodeHarness(), _fixture_lines()[:2])[-1].provider == "anthropic"
    harness = ClaudeCodeHarness(env={"CLAUDE_CODE_USE_BEDROCK": "1"})
    assert _steps(harness, _fixture_lines()[:2])[-1].provider == "bedrock"


def test_a_provider_the_environment_did_not_show_is_flagged_not_hidden():
    lines = _fixture_lines()
    result = json.loads(lines[-1])
    for totals in result["modelUsage"].values():
        totals["provider"] = "bedrock"
    steps = _steps(ClaudeCodeHarness(), [*lines[:-1], json.dumps(result)])
    usage_step = next(s for s in steps if s.inputs.get("event") == "result-usage")
    assert usage_step.provider == "bedrock"
    assert usage_step.inputs["provider_mismatch"] == {"assumed": "anthropic", "reported": "bedrock"}


def test_a_malformed_reported_cost_does_not_abort_the_run():
    result = {"type": "result", "subtype": "success", "total_cost_usd": "lots", "duration_ms": -5}
    (done,) = _steps(ClaudeCodeHarness(), [json.dumps(result)])
    assert done.cost == 0.0 and done.duration == 0.0


@pytest.mark.parametrize(
    "event",
    [
        {"type": ["assistant"]},
        {"type": "assistant", "message": {"content": 7, "usage": "x"}},
        {"type": "user", "message": {"content": {"not": "a list"}}},
        {"type": "result", "modelUsage": ["bad"], "total_cost_usd": None},
    ],
)
def test_a_malformed_event_is_recorded_or_skipped_never_fatal(event):
    _steps(ClaudeCodeHarness(), [json.dumps(event)])


def test_plain_text_output_is_still_recorded():
    (step,) = _steps(ClaudeCodeHarness(), ["Reading README.md"])
    assert step.kind == StepKind.tool and step.usage == {}


def test_a_recorded_claude_code_run_is_priceable_after_the_fact(tmp_path):
    from opentine._pricing_pass import price_run
    from opentine.core import Run
    from opentine.harnesses import OpentineHarness

    # A stand-in "claude" that replays the live capture: the real recording path
    # end to end, with no model call.
    replay = f"import sys; sys.stdout.write(open({str(FIXTURE)!r}, encoding='utf-8').read())"
    harness = ClaudeCodeHarness(command=(sys.executable, "-c", replay), cwd=tmp_path)
    saved = tmp_path / "run.tine"
    OpentineHarness(harness).run_sync("answer", save_path=saved)
    run = Run.load(saved)

    models = [step for step in run.steps if step.kind == StepKind.model]
    assert all(step.usage and step.provider == "anthropic" for step in models)
    assert run.steps[0].kind == StepKind.think, "the launch is a record, not a model call"
    pricing = price_run(run)
    assert pricing.status_counts == {"complete": len(models)}
    assert Decimal(str(pricing.total_cost)) == Decimal("0.100061")
    assert run.total_cost == pytest.approx(0.100061), "and tine cost shows Claude Code's own"
