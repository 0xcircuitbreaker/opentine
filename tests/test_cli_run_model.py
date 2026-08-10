"""`tine run --model provider[:model] --prompt ...` — the no-code first run.

Every test mocks the *model call only*.  Provider-name resolution, the adapter
class, the Agent loop, the save location, and the receipt all run for real;
``MockModel.complete`` from test_core stands in where the network call would be,
so no API key and no socket are involved.  An adapter constructed without a key
never reaches its client, because the call that would build one is replaced.

The last two tests pin the two older run modes — a script and ``--harness`` —
still behaving exactly as they did, since ``--model`` now runs ahead of both.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine.models import model_class
from tests.test_core import MockModel

PROMPT = "What is the answer?"
ANSWER = "The answer is 42."

SCRIPT = (
    "from opentine import Run, RunStatus, StepKind\n"
    "run = Run(id='run_model_script')\n"
    "run.add_step(StepKind.done, {'text': 'ok'})\n"
    "run.status = RunStatus.completed\n"
)


def _invoke(monkeypatch, tmp_path: Path, *args: str) -> None:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def _mock_the_model_call(monkeypatch, provider: str, text: str = ANSWER) -> MockModel:
    """Replace *provider*'s network call with the shared fake, in place."""
    mock = MockModel([{"text": text, "tool_calls": []}])
    monkeypatch.setattr(model_class(provider), "complete", mock.complete)
    return mock


def _saved(tmp_path: Path) -> Run:
    written = list((tmp_path / ".tine_runs").glob("*.tine"))
    assert len(written) == 1, written
    return Run.load(written[0])


class _StubHarness:
    """Stands in for OpentineHarness so the --harness mode runs without a subprocess."""

    def __init__(self, harness, **kwargs):
        pass

    def run_sync(self, task, context=None, save_path=None):
        run = Run(id="run_model_harness")
        run.add_step(StepKind.done, {"text": task})
        run.status = RunStatus.completed
        return run


# --------------------------------------------------------------------------- #
# the happy path
# --------------------------------------------------------------------------- #


def test_a_bundled_adapter_produces_a_saved_run_carrying_prompt_and_output(
    monkeypatch, tmp_path, capsys
):
    mock = _mock_the_model_call(monkeypatch, "anthropic")

    _invoke(monkeypatch, tmp_path, "run", "--model", "anthropic", "--prompt", PROMPT)

    run = _saved(tmp_path)
    assert run.user_prompt == PROMPT
    assert run.status is RunStatus.completed
    assert any(step.inputs.get("text") == ANSWER for step in run.steps), run.steps
    assert mock.seen_messages[0][-1]["content"] == PROMPT
    out = capsys.readouterr().out
    assert "Saved:" in out and f"{run.id}.tine" in out


def test_save_path_is_honoured_exactly_as_in_script_mode(monkeypatch, tmp_path):
    _mock_the_model_call(monkeypatch, "anthropic")
    destination = tmp_path / "out" / "mine.tine"

    _invoke(
        monkeypatch,
        tmp_path,
        "run",
        "--model",
        "anthropic",
        "--prompt",
        PROMPT,
        "--save",
        str(destination),
    )

    assert Run.load(destination).user_prompt == PROMPT
    assert not (tmp_path / ".tine_runs").exists(), "the run was also written to the default slot"


def test_the_provider_name_is_case_insensitive(monkeypatch, tmp_path):
    _mock_the_model_call(monkeypatch, "anthropic")

    _invoke(monkeypatch, tmp_path, "run", "--model", "AnThRoPiC", "--prompt", PROMPT)

    assert _saved(tmp_path).model_info == model_class("anthropic")().name


# --------------------------------------------------------------------------- #
# provider[:model]
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("provider", "model_id"),
    [("anthropic", "claude-haiku-4"), ("kimi", "kimi-k3-turbo"), ("ollama", "llama3.1:8b")],
    ids=lambda value: value,
)
def test_the_part_after_the_colon_sets_the_model_id(monkeypatch, tmp_path, provider, model_id):
    """The split takes the first colon only, so `ollama:llama3.1:8b` survives."""
    _mock_the_model_call(monkeypatch, provider)
    default_name = model_class(provider)().name

    _invoke(monkeypatch, tmp_path, "run", "--model", f"{provider}:{model_id}", "--prompt", PROMPT)

    recorded = _saved(tmp_path).model_info
    assert recorded != default_name
    assert model_id in recorded


def test_without_a_colon_the_adapter_keeps_its_own_default(monkeypatch, tmp_path):
    _mock_the_model_call(monkeypatch, "kimi")

    _invoke(monkeypatch, tmp_path, "run", "--model", "kimi", "--prompt", PROMPT)

    assert _saved(tmp_path).model_info == model_class("kimi")().name


# --------------------------------------------------------------------------- #
# errors: a message, never a traceback
# --------------------------------------------------------------------------- #


def test_an_unknown_provider_names_itself_and_lists_the_valid_ones(monkeypatch, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", "--model", "nope", "--prompt", PROMPT)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert "Unknown provider" in out and "nope" in out
    for provider in ("anthropic", "openai", "google", "ollama", "kimi", "openrouter"):
        assert provider in out, out
    assert not (tmp_path / ".tine_runs").exists()


def test_a_missing_sdk_extra_is_reported_as_the_adapters_pip_hint(monkeypatch, tmp_path, capsys):
    def no_sdk(self):
        raise ImportError("pip install opentine[anthropic]")

    monkeypatch.setattr(model_class("anthropic"), "_get_client", no_sdk)

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", "--model", "anthropic", "--prompt", PROMPT)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert "pip install opentine[anthropic]" in out
    assert "Traceback" not in out


def test_a_provider_rejection_is_one_line_not_a_stack_trace(monkeypatch, tmp_path, capsys):
    """A missing key reaches the CLI as the provider's own error; it must not raise."""

    async def rejected(self, messages, tools=None, system=None, temperature=0.0):
        raise RuntimeError("The api_key client option must be set")

    monkeypatch.setattr(model_class("kimi"), "complete", rejected)

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", "--model", "kimi", "--prompt", PROMPT)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert "api_key client option must be set" in out
    assert "Traceback" not in out


# --------------------------------------------------------------------------- #
# --model is a third mode, exclusive with the other two
# --------------------------------------------------------------------------- #


def test_a_script_and_model_together_are_refused(monkeypatch, tmp_path, capsys):
    script = tmp_path / "agentrun.py"
    script.write_text(SCRIPT, encoding="utf-8")
    _mock_the_model_call(monkeypatch, "anthropic")

    with pytest.raises(SystemExit) as exc:
        _invoke(
            monkeypatch, tmp_path, "run", str(script), "--model", "anthropic", "--prompt", PROMPT
        )

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert "--model" in out and "cannot be combined" in out
    assert not (tmp_path / ".tine_runs").exists()


def test_a_harness_and_model_together_are_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("opentine._cli_execute.OpentineHarness", _StubHarness)
    _mock_the_model_call(monkeypatch, "anthropic")

    with pytest.raises(SystemExit) as exc:
        _invoke(
            monkeypatch,
            tmp_path,
            "run",
            "--harness",
            "generic",
            "--model",
            "anthropic",
            "--prompt",
            PROMPT,
        )

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert "--harness and --model cannot be combined" in out
    assert not (tmp_path / ".tine_runs").exists()


def test_model_without_a_prompt_is_refused(monkeypatch, tmp_path, capsys):
    _mock_the_model_call(monkeypatch, "anthropic")

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", "--model", "anthropic")

    assert exc.value.code == 1
    assert "--prompt is required" in capsys.readouterr().out
    assert not (tmp_path / ".tine_runs").exists()


@pytest.mark.parametrize(
    "extra",
    [
        ["--autosave", "draft.tine"],
        ["--autosave-interval", "3"],
        ["--autosave-seconds", "1.5"],
        ["--cwd", "."],
        ["--harness-command", "agent run"],
        ["--harness-timeout", "5"],
    ],
    ids=lambda extra: extra[0],
)
def test_model_mode_refuses_every_flag_it_cannot_honour(monkeypatch, tmp_path, capsys, extra):
    _mock_the_model_call(monkeypatch, "anthropic")

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, tmp_path, "run", "--model", "anthropic", "--prompt", PROMPT, *extra)

    assert exc.value.code == 1
    out = capsys.readouterr().out.replace("\n", " ")
    assert extra[0] in out and "no effect with --model" in out
    assert not (tmp_path / ".tine_runs").exists()


# --------------------------------------------------------------------------- #
# the two older run modes are untouched
# --------------------------------------------------------------------------- #


def test_script_mode_still_writes_its_run(monkeypatch, tmp_path):
    script = tmp_path / "agentrun.py"
    script.write_text(SCRIPT, encoding="utf-8")

    _invoke(monkeypatch, tmp_path, "run", str(script))

    assert (tmp_path / ".tine_runs" / "run_model_script.tine").is_file()


def test_harness_mode_still_writes_its_run(monkeypatch, tmp_path):
    monkeypatch.setattr("opentine._cli_execute.OpentineHarness", _StubHarness)

    _invoke(
        monkeypatch,
        tmp_path,
        "run",
        "--harness",
        "generic",
        "--harness-command",
        "agent run",
        "--prompt",
        PROMPT,
    )

    saved = Run.load(tmp_path / ".tine_runs" / "run_model_harness.tine")
    assert saved.steps[0].inputs["text"] == PROMPT
