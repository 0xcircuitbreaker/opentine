"""Harness events nested deep enough to break a save, and the autosave cost.

Final pass 4: an event the parser admits (up to 512 levels) was recorded verbatim
inside the run's own structure, so ~505 levels made the whole run unsaveable and
``--autosave`` killed the agent mid-run. And the CLI's harness autosave defaulted
to a checkpoint per output line, re-saving the whole run each time: O(n^2) in
output the agent controls.
"""

from __future__ import annotations

import json
import sys
import time

import pytest

from opentine.autosave import Autosaver
from opentine.core import Run
from opentine.harnesses import ClaudeCodeHarness, GenericHarness, OpentineHarness
from opentine.harnesses._record_depth import RECORD_DEPTH, _recordable


def _nested(depth: int) -> object:
    value: object = "leaf"
    for _ in range(depth):
        value = {"k": value}
    return value


def _printer(tmp_path, lines: list[str], fmt: str = "stream-json") -> tuple[str, ...]:
    """A stand-in CLI; the trailing output-format flag (ignored by ``-c``) makes
    the harness trust its JSON lines as events, as with the real CLI."""
    (tmp_path / "out.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    script = "import sys\nsys.stdout.write(open('out.txt').read()); sys.stdout.flush()\n"
    return (sys.executable, "-c", script, "--output-format", fmt)


def _deep_tool_use(depth: int) -> str:
    return json.dumps(
        {
            "type": "assistant",
            "message": {
                "id": "msg_1",
                "model": "claude-opus-5-5",
                "content": [{"type": "tool_use", "id": "t1", "name": "x", "input": _nested(depth)}],
                "usage": {"input_tokens": 5, "output_tokens": 2},
            },
        }
    )


def test_recordable_keeps_shallow_values_and_flattens_deep_ones():
    shallow = _nested(20)
    assert _recordable(shallow) == shallow
    flat = _recordable(_nested(RECORD_DEPTH + 40))
    for _ in range(RECORD_DEPTH):
        flat = flat["k"]
    assert flat["truncated_depth"] == RECORD_DEPTH
    assert json.loads(flat["json"]) == _nested(40)


@pytest.mark.parametrize("depth", [500, 506, 507, 508])
def test_a_deep_claude_code_event_still_saves(tmp_path, depth):
    harness = ClaudeCodeHarness(command=_printer(tmp_path, [_deep_tool_use(depth)]), cwd=tmp_path)
    run = OpentineHarness(harness).run_sync("task")
    path = run.save(tmp_path / "deep.tine")
    assert len(Run.load(path).steps) == len(run.steps)


def test_a_deep_generic_event_saves_and_autosave_does_not_kill_the_run(tmp_path):
    line = json.dumps({"type": "message", "text": _nested(508)})
    harness = GenericHarness(
        command=_printer(tmp_path, ["before", line, "after"], "json"), cwd=tmp_path
    )
    wrapped = OpentineHarness(harness, autosave_path=tmp_path / "auto.tine", autosave_steps=1)
    run = wrapped.run_sync("task", save_path=tmp_path / "out.tine")
    assert run.status.value == "completed"
    assert Run.load(tmp_path / "out.tine").status.value == "completed"
    assert Run.load(tmp_path / "auto.tine").status.value == "completed"
    recorded = "".join(str(step.inputs) for step in run.steps)
    assert "after" in recorded


def test_growth_gated_autosave_total_work_is_linear(tmp_path):
    # Count the steps written across every checkpoint: a per-step checkpoint
    # writes n(n+1)/2 of them, a 25% growth gate a geometric sum (< 5n).
    def written(n: int) -> int:
        saver = Autosaver(tmp_path / "a.tine", every_n_steps=1, min_growth=0.25)
        total = 0

        class FakeRun:
            steps: list[int] = []

            def save(self, *_a, **_k):
                nonlocal total
                total += len(self.steps)

        run = FakeRun()
        run.steps = []
        for step in range(n):
            run.steps.append(step)
            saver.maybe_save(run)  # type: ignore[arg-type]
        return total

    assert written(400) < 5 * 400
    assert written(1600) < 5 * 1600
    assert written(1600) / written(400) < 6


def test_cli_default_harness_autosave_is_amortized(monkeypatch):
    from opentine import _cli_execute

    captured: dict[str, object] = {}

    class Stub:
        def __init__(self, harness, **kwargs):
            captured.update(kwargs)
            raise SystemExit(0)

    monkeypatch.setattr(_cli_execute, "OpentineHarness", Stub)
    monkeypatch.setattr(_cli_execute, "_harness_from_args", lambda args: None)
    args = type(
        "A",
        (),
        {"prompt": "hi", "script": None, "autosave": "d.tine", "save": None, "cwd": None},
    )()
    with pytest.raises(SystemExit):
        _cli_execute.cmd_run_harness(args)
    assert captured["autosave_growth"] > 0
    assert captured["autosave_seconds"] > 0


def test_many_output_lines_with_default_cli_autosave_stay_fast(tmp_path):
    lines = [f"line {i} " + "x" * 200 for i in range(400)]
    harness = GenericHarness(command=_printer(tmp_path, lines), cwd=tmp_path)
    wrapped = OpentineHarness(
        harness,
        autosave_path=tmp_path / "auto.tine",
        autosave_steps=1,
        autosave_seconds=2.0,
        autosave_growth=0.25,
    )
    started = time.monotonic()
    run = wrapped.run_sync("task")
    assert time.monotonic() - started < 30
    assert Run.load(tmp_path / "auto.tine").steps[-1].id == run.steps[-1].id
