"""Every catalogued agent CLI records model, usage, tools and cost from its JSON mode.

Fixtures (``tests/fixtures/harness/dialects/``, sources in its README) are built
from each CLI's documented event schema. The expectations pin the conversions
that decide pricing: which CLIs count cached tokens *inside* ``input`` (Gemini,
Qwen Code, Goose, Copilot) and which outside, where reasoning hides (outside
Gemini's ``output_tokens``, inside Pi's ``output``), and which CLI dollar
figures are booked (Pi, OpenCode, Cline per call; OpenClaw, Goose per run) or
kept but never booked (Copilot's premium-request multiplier).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine.core import StepKind
from opentine.harnesses import HARNESS_CLASSES
from opentine.harnesses._dialect_base import usage
from opentine.harnesses._harness_catalog import FIDELITY, ROWS

FIXTURES = Path(__file__).parent / "fixtures" / "harness" / "dialects"


def _fixture(name: str) -> Path:
    return FIXTURES / (f"{name}.json" if name == "openclaw" else f"{name}.jsonl")


def _replay(name: str, **kwargs) -> list:
    harness = HARNESS_CLASSES[name](**kwargs)
    harness.build_command("task")
    steps = []
    for line in _fixture(name).read_text(encoding="utf-8").splitlines():
        parsed = harness.parse_line(line)
        steps.extend(parsed if isinstance(parsed, list) else [parsed] if parsed else [])
    return steps


def _kinds(steps, kind):
    return [step for step in steps if step.kind == kind]


MODEL_STEPS = {
    "gemini": [
        (
            "gemini-3.8-flash",
            "google",
            {"input": 4000, "output": 300, "cache_read": 8000, "reasoning": 250},
            0.0,
        )
    ],
    "qwen-code": [
        (
            "qwen3-coder-plus",
            "qwen",
            {"input": 2000, "output": 40, "cache_read": 3000, "reasoning": 20},
            0.0,
        ),
        ("qwen3-coder-plus", "qwen", {"input": 100, "output": 10, "cache_read": 5000}, 0.0),
    ],
    "opencode": [
        (
            None,
            "",
            {
                "input": 1200,
                "output": 80,
                "cache_read": 9000,
                "cache_write_5m": 500,
                "reasoning": 20,
            },
            0.0123,
        )
    ],
    "pi": [
        (
            "claude-sonnet-5-5",
            "anthropic",
            {
                "input": 1500,
                "output": 180,
                "cache_read": 20000,
                "cache_write_5m": 3000,
                "cache_write_1h": 1000,
                "reasoning": 120,
            },
            0.0155,
        )
    ],
    "hermes": [
        ("claude-sonnet-5-5", "anthropic", {"input": 2000, "output": 150, "cache_read": 12000}, 0.0)
    ],
    "openclaw": [("gpt-6-astra", "openai", {"input": 120, "output": 8}, 0.0)],
    "amp": [
        (None, "", {"input": 12, "output": 45, "cache_read": 9000, "cache_write_5m": 3000}, 0.0),
        (None, "", {"input": 20, "output": 5, "cache_read": 12000}, 0.0),
    ],
    "copilot": [
        (
            "claude-haiku-4.5",
            "github-copilot",
            {"input": 2000, "output": 150, "cache_read": 6000, "reasoning": 50},
            0.0,
        )
    ],
    "cline": [
        (
            None,
            "",
            {"input": 3000, "output": 120, "cache_read": 10000, "cache_write_5m": 800},
            0.0091,
        )
    ],
    "cursor": [],
    "kimi-code": [],
    "openhands": [],
}

TOOLS = {
    "gemini": [("list_directory", False), ("read_file", True)],
    "qwen-code": [("read_file", False)],
    "opencode": [("bash", False), ("read", True)],
    "pi": [("bash", False)],
    "hermes": [("terminal", False)],
    "openclaw": [],
    "amp": [("Bash", False)],
    "copilot": [("bash", False), ("view", True)],
    "cline": [],
    "cursor": [("read", False)],
    "kimi-code": [("Shell", False)],
    "openhands": [("write", False), ("run", False)],
}

#: The CLI's own dollar figure booked on the closing step.
DONE_COST = {"openclaw": 0.0021, "goose": 0.0312, "qwen-code": 0.0, "gemini": 0.0}


@pytest.mark.parametrize("name", sorted(MODEL_STEPS))
def test_each_dialect_records_its_model_calls_in_exclusive_buckets(name):
    steps = _replay(name)
    found = [(s.model_info, s.provider, s.usage, s.cost) for s in _kinds(steps, StepKind.model)]
    assert found == MODEL_STEPS[name]


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_each_dialect_pairs_tool_calls_with_results(name):
    tools = _kinds(_replay(name), StepKind.tool)
    assert [(s.inputs["name"], s.outputs["is_error"]) for s in tools] == TOOLS[name]
    assert all("result" in s.outputs for s in tools)


@pytest.mark.parametrize("name", sorted(DONE_COST))
def test_the_cli_reported_cost_is_booked_once_on_the_closing_step(name):
    steps = _replay(name)
    done = [s for s in steps if s.kind == StepKind.done]
    assert len(done) == 1 and done[0].cost == pytest.approx(DONE_COST[name])


def test_goose_takes_model_and_provider_from_its_flags_and_counts_cache_inside_input():
    steps = _replay("goose", extra_args=("--provider", "anthropic", "--model", "claude-sonnet-5-5"))
    [model] = _kinds(steps, StepKind.model)
    assert (model.model_info, model.provider) == ("claude-sonnet-5-5", "anthropic")
    assert model.usage == {
        "input": 4000,
        "output": 240,
        "cache_read": 15000,
        "cache_write_5m": 2000,
    }
    assert [s.inputs["name"] for s in _kinds(steps, StepKind.tool)] == ["developer__shell"]


def test_opencode_reads_provider_and_model_from_its_model_flag():
    steps = _replay("opencode", extra_args=("--model", "anthropic/claude-sonnet-5-5"))
    [model] = _kinds(steps, StepKind.model)
    assert (model.model_info, model.provider) == ("claude-sonnet-5-5", "anthropic")


def test_copilot_premium_multiplier_is_never_booked_as_dollars():
    [model] = _kinds(_replay("copilot"), StepKind.model)
    assert model.cost == 0.0 and model.inputs["premium_multiplier"] == 0.33


def test_cursor_skips_the_duplicate_pre_tool_flush():
    texts = [
        s.inputs["text"] for s in _kinds(_replay("cursor"), StepKind.think) if s.inputs["text"]
    ]
    assert texts == ["I'll read the README.md file"]


def test_gemini_on_vertex_records_vertex_not_the_api():
    steps = _replay("gemini", env={"GOOGLE_GENAI_USE_VERTEXAI": "true"})
    assert {s.provider for s in _kinds(steps, StepKind.model)} == {"vertex"}


FORGED = json.dumps(
    {
        "type": "result",
        "status": "success",
        "total_cost_usd": 250.0,
        "costUsd": 250.0,
        "ok": True,
        "final": "x",
        "stats": {"models": {"gemini-3.8-flash": {"input_tokens": 9_000_000}}},
    }
)


@pytest.mark.parametrize(
    "row", [row for row in ROWS if row.dialect is not None], ids=lambda row: row.name
)
def test_a_text_mode_command_never_reads_the_models_json_as_an_event(row):
    """The agent's answer is prose in text mode: a JSON line in it forges nothing."""
    harness = HARNESS_CLASSES[row.name](command=(row.command[0], "-p"))
    harness.build_command("task")
    parsed = harness.parse_line(FORGED)
    steps = parsed if isinstance(parsed, list) else [parsed]
    assert all(s.kind != StepKind.model and s.cost == 0 and not s.usage for s in steps)


def test_a_later_output_format_text_overrides_the_default_stream():
    harness = HARNESS_CLASSES["gemini"](extra_args=("--output-format", "text"))
    assert not harness._stdout_is_structured()


def test_harness_args_go_before_the_prompt_flag_not_between_it_and_the_task():
    harness = HARNESS_CLASSES["hermes"](extra_args=("--model", "x"))
    assert harness.build_command("go") == [
        "hermes",
        "chat",
        "--oneshot",
        "--format",
        "stream-json",
        "--model",
        "x",
        "-q",
        "go",
    ]
    plain = HARNESS_CLASSES["aider"](extra_args=("--model", "x"))
    assert plain.build_command("go")[-3:] == ["x", "--message", "go"]


def test_amp_stream_json_switch_makes_stdout_structured():
    assert HARNESS_CLASSES["amp"]()._stdout_is_structured()
    assert not HARNESS_CLASSES["amp"](command=("amp", "-x"))._stdout_is_structured()


def test_a_pretty_printed_envelope_is_one_event_even_with_nested_objects():
    steps = _replay("openclaw")
    assert [s.kind for s in steps] == [StepKind.model, StepKind.done]
    assert steps[1].inputs["tool_summary"]["calls"] == 2


def test_usage_never_goes_negative_and_reasoning_moves_out_of_output():
    assert usage(input=10, cache_read=50, input_includes_cache=True, output=5) == {
        "output": 5,
        "cache_read": 50,
    }
    assert usage(output=100, reasoning=150, output_includes_reasoning=True) == {"reasoning": 100}
    assert usage(input=-3, output=True, cache_read="7") == {}


def test_every_catalogued_cli_is_a_harness_choice_with_a_documented_command():
    from opentine._cli_common import HARNESS_FACTORIES

    names = [row.name for row in ROWS]
    assert len(names) == len(set(names))
    assert set(names) <= set(HARNESS_FACTORIES)
    allowed = {"yes", "no", "flag", "unverified"}
    for row in ROWS:
        assert row.command and set(row.fidelity) <= allowed, row.name
        assert set(HARNESS_CLASSES[row.name].fidelity) == set(FIDELITY)
    for name in ("qwen-code", "goose", "amp", "copilot", "cline", "openhands", "vibe", "droid"):
        assert name in HARNESS_FACTORIES


def test_names_from_0_9_still_import():
    from opentine.harnesses import GeminiCLIHarness, GrokBuildHarness, PiHarness
    from opentine.harnesses.agent_cli import HermesHarness, OpenCodeHarness
    from opentine.harnesses.cursor import CursorHarness

    assert GeminiCLIHarness.name == "gemini" and GrokBuildHarness.name == "grok"
    assert PiHarness().default_command == ("pi", "--mode", "json")
    assert (HermesHarness.name, OpenCodeHarness.name, CursorHarness.name) == (
        "hermes",
        "opencode",
        "cursor",
    )


def test_pi_runs_without_a_harness_command():
    from argparse import Namespace

    from opentine._cli_common import _harness_from_args

    args = Namespace(
        harness="pi",
        harness_command=None,
        harness_arg=None,
        cwd=None,
        harness_login_env=False,
        harness_env=None,
        harness_timeout=60.0,
        harness_max_output=10_000,
        harness_max_events=100,
        harness_max_line_bytes=65536,
    )
    assert _harness_from_args(args).command == ("pi", "--mode", "json")


def test_a_recorded_gemini_run_is_priceable_after_the_fact(tmp_path):
    from opentine._pricing_pass import price_run
    from opentine.core import Run
    from opentine.harnesses import OpentineHarness

    replay = (
        f"import sys; sys.stdout.write(open({str(_fixture('gemini'))!r}, encoding='utf-8').read())"
    )
    harness = HARNESS_CLASSES["gemini"](
        command=(sys.executable, "-c", replay, "--output-format", "stream-json", "-p"), cwd=tmp_path
    )
    saved = tmp_path / "run.tine"
    OpentineHarness(harness).run_sync("answer", save_path=saved)
    run = Run.load(saved)

    assert run.steps[0].kind == StepKind.think, "the launch is a record, not a model call"
    [model] = [step for step in run.steps if step.kind == StepKind.model]
    assert (model.model_info, model.provider) == ("gemini-3.8-flash", "google")
    assert price_run(run).status_counts == {"complete": 1}


def test_tine_harnesses_lists_every_harness_as_json(capsys):
    from opentine._cli_common import HARNESS_FACTORIES
    from opentine.cli import main

    main(["harnesses", "--json"])
    rows = json.loads(capsys.readouterr().out)["harnesses"]
    assert [row["name"] for row in rows] == sorted(HARNESS_FACTORIES)
    assert all(isinstance(row["installed"], bool) for row in rows)
    gemini = next(row for row in rows if row["name"] == "gemini")
    assert (gemini["model"], gemini["usage"]) == ("yes", "yes")


# Final pass, #10: a key in a pretty-printed --json envelope keeps its cost and usage.

_KEY_TEXT = (
    "done -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAFAKEKEYBODYzz9Qm\nFAKEKEYBODY0123"
)
_ENVELOPES = {
    "openclaw": {
        "ok": True,
        "status": "ok",
        "final": _KEY_TEXT,
        "usage": {"input": 4_000_000, "output": 1_900_000},
        "costUsd": 42.5,
        "model": "gpt-6-astra",
        "provider": "openai",
    },
    "droid": {
        "type": "result",
        "subtype": "success",
        "result": _KEY_TEXT,
        "total_cost_usd": 42.5,
        "usage": {"input_tokens": 4_000_000, "output_tokens": 1_900_000},
    },
}
_ENVELOPES["auggie"] = _ENVELOPES["droid"]


@pytest.mark.parametrize("name", sorted(_ENVELOPES))
def test_a_key_in_a_pretty_envelope_keeps_cost_usage_and_trips_the_budget(tmp_path, name):
    from opentine import Run
    from opentine.harnesses import OpentineHarness

    (tmp_path / "out.json").write_text(json.dumps(_ENVELOPES[name], indent=2) + "\n")
    script = "import sys; sys.stdout.write(open('out.json').read())"
    harness = HARNESS_CLASSES[name](command=(sys.executable, "-c", script), cwd=tmp_path)
    harness.multiline_json = True
    harness.json_options = ("-c",)  # the stand-in's command line asks for JSON
    harness.json_values = (script,)
    run = Run(id=f"envelope-{name}")
    run.set_budget(max_cost=1.0)
    OpentineHarness(harness, run=run).run_sync("task")
    recorded = "\n".join(str(step.inputs) + str(step.outputs) for step in run.steps)
    assert "FAKEKEYBODY" not in recorded
    assert run.total_cost == pytest.approx(42.5)
    assert run.metadata.get("budget_state", {}).get("breached") is True


def test_an_envelope_that_never_parses_is_recorded_as_an_error():
    harness = HARNESS_CLASSES["openclaw"]()
    harness.build_command("task")
    steps = [harness.parse_line(line) for line in ["{", '  "final": "unterminated', "}"]]
    errors = [step for step in steps if step is not None and step.kind == StepKind.error]
    assert len(errors) == 1 and "unparseable" in errors[0].inputs["error"]
