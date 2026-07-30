"""Round-12 audit regressions: shapes ``agent.resume()``/``agent.replay()`` trusted.

One class, one file (``opentine/_runtime_history.py``), four sites. ``validate_run_record``
types a run's *containers* and deliberately leaves their contents open -- transcript is a
``list`` of anything, ``manifest`` is an object whose keys are unconstrained apart from
``model`` -- and ``Run.save`` writes those values back verbatim, so this build both
*accepts* and *writes* every artifact below. Each site then read one of those values as
though it had a shape:

* ``manifest["resume_history"]`` was grown with ``setdefault(..., []).append(...)``. On any
  run with a step, ``Run.fork`` pops the field, so nothing malformed ever survived to the
  append; on a *zero-step* run resume forks nothing, the manifest arrives untouched, and
  ``{"resume": True, "resume_history": 5}`` raised ``AttributeError: 'int' object has no
  attribute 'append'``.
* ``_messages_from_transcript`` called ``item.items()`` on every transcript entry, so a
  transcript of ``[5]`` / ``["abc"]`` / ``[None]`` / ``[[1]]`` raised ``AttributeError``.
* ``_require_complete_tool_batches`` iterated ``message["tool_calls"]`` and called
  ``.get`` on each element: ``5`` -> ``TypeError: 'int' object is not iterable``, ``"a"``
  or ``[5]`` -> ``AttributeError``.
* ``replay(mode="cache")`` resolved its tip as ``refs["main"] or run.steps[-1].id``.
  ``RunBase`` seeds ``refs["main"]`` with ``""`` for an empty graph, so a run with no
  recorded steps fell through to ``steps[-1]`` and raised ``IndexError``.

The two treatments are deliberate and different. A transcript entry that is not a mapping
is not a message, so it is skipped exactly the way the mapping-without-a-``role`` this
loop always skipped is, and it stays in the transcript -- ``_causal_transcript`` had
already settled that rule for ``fork``. A ``tool_calls`` value that cannot be enumerated
is the one case the *safety* check exists to catch, so it refuses with a message instead
of pretending the assistant made no calls and resuming inside an open batch. Neither is
allowed to make a loadable run unusable by accident: every artifact here still loads,
shows, forks and saves, and every well-formed run behaves exactly as before.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from opentine import Run, StepKind
from opentine._artifact_shapes import validate_run_record
from opentine.graph import RunStatus
from opentine.runtime import Agent, _messages_from_transcript

# Values the validator permits wherever it constrains only the container.
NOT_A_LIST = {"int": 5, "str": "abc", "none": None, "true": True, "float": 1.5, "dict": {"a": 1}}
NOT_A_MAPPING = {"int": 5, "str": "abc", "none": None, "true": True, "float": 1.5, "list": [1]}
# Truthy tool_calls values that cannot be read as a batch of calls.
UNREADABLE_CALLS = {
    "int": 5,
    "str": "a",
    "true": True,
    "float": 1.5,
    "dict": {"a": 1},
    "list-of-int": [5],
    "list-of-str": ["x"],
    "list-of-none": [None],
    "list-of-list": [[1]],
}
RAW = (AttributeError, TypeError, IndexError, KeyError)


class _Model:
    """Terminates immediately, and records the message history resume handed it."""

    name = "round12/model"

    def __init__(self):
        self.seen: list[list[dict]] = []

    @property
    def supports_tools(self) -> bool:
        return True

    async def complete(self, messages, **kwargs):
        self.seen.append(json.loads(json.dumps(messages)))
        return {"text": "done", "tool_calls": []}


def _saved(tmp_path, name, *, steps=0, manifest=None, transcript=None, prefix=()):
    """A real .tine written by this build's own writer, then proved validator-legal."""
    run = Run(id=name, model_info="m/1", user_prompt="original")
    run.manifest.update({"kind": "opentine-native", "model": {"name": "m/1"}, "resume": True})
    run.transcript.extend(prefix)
    for index in range(steps):
        inputs = {"text": f"s{index}"}
        step = run.add_step(StepKind.model, inputs, {"result": "r"}, model_info="m/1")
        run.transcript.append({"step_id": step.id, "role": "assistant", "content": f"a{index}"})
    if transcript is not None:
        run.transcript.extend(transcript)
    run.manifest.update(manifest or {})
    run.status = RunStatus.completed
    path = tmp_path / f"{name}.tine"
    run.save(path)
    assert validate_run_record(json.loads(path.read_text()))  # the contract under test
    return path


def _resume(path, *, model=None, prompt="go", **kwargs):
    agent = Agent(model=model or _Model())
    return asyncio.run(agent.resume(Run.load(path), prompt=prompt, **kwargs))


def _replay(path, mode="cache"):
    return asyncio.run(Agent(_Model()).replay(Run.load(path), mode=mode))


# --------------------------------------------------------------------------------------
# (1) manifest.resume_history: a wrong shape is replaced, never appended to, never fatal
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(NOT_A_LIST))
def test_resume_survives_a_non_list_resume_history_on_a_stepless_run(shape, tmp_path):
    """Zero steps means no fork, so nothing launders the manifest before the append."""
    path = _saved(tmp_path, f"rh-{shape}", steps=0, manifest={"resume_history": NOT_A_LIST[shape]})
    resumed = _resume(path)
    assert resumed.status is RunStatus.completed
    assert resumed.manifest["resume_history"] == [{"from_model": "m/1", "model": "round12/model"}]


@pytest.mark.parametrize("shape", sorted(NOT_A_LIST))
def test_a_repaired_resume_history_still_saves_and_reloads(shape, tmp_path):
    path = _saved(tmp_path, f"rhs-{shape}", steps=0, manifest={"resume_history": NOT_A_LIST[shape]})
    out = tmp_path / "resumed.tine"
    _resume(path).save(out)
    assert Run.load(out).manifest["resume_history"][-1]["model"] == "round12/model"


def test_a_well_formed_resume_history_is_appended_to_not_replaced(tmp_path):
    """The reverse failure: the guard must not discard a list that was already fine."""
    prior = [{"from_model": "old/1", "model": "m/1"}]
    path = _saved(tmp_path, "rh-ok", steps=0, manifest={"resume_history": prior})
    assert _resume(path).manifest["resume_history"] == [
        {"from_model": "old/1", "model": "m/1"},
        {"from_model": "m/1", "model": "round12/model"},
    ]


def test_a_stepped_resume_still_starts_a_fresh_history(tmp_path):
    """fork() pops resume_history, so the dominant path was always a fresh list."""
    path = _saved(tmp_path, "rh-step", steps=1, manifest={"resume_history": 5})
    assert _resume(path).manifest["resume_history"] == [
        {"from_model": "m/1", "model": "round12/model"}
    ]


# --------------------------------------------------------------------------------------
# (2) transcript items: a record that is not a message is skipped, not refused, not lost
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(NOT_A_MAPPING))
def test_resume_survives_a_non_mapping_transcript_item(shape, tmp_path):
    item = NOT_A_MAPPING[shape]
    path = _saved(tmp_path, f"tr-{shape}", steps=0, transcript=[item])
    model = _Model()
    resumed = _resume(path, model=model)
    assert resumed.status is RunStatus.completed
    # Skipped as a message...
    assert model.seen[0] == [{"role": "user", "content": "go"}]
    # ...but kept in the transcript, because it is somebody's audit evidence.
    assert resumed.transcript[0] == item


@pytest.mark.parametrize("shape", sorted(NOT_A_MAPPING))
def test_replay_survives_a_non_mapping_transcript_item(shape, tmp_path):
    path = _saved(tmp_path, f"trr-{shape}", steps=1, prefix=[NOT_A_MAPPING[shape]])
    replayed = _replay(path)
    assert replayed.metadata["replay"]["reused_steps"] == 1
    assert replayed.transcript[0] == NOT_A_MAPPING[shape]


@pytest.mark.parametrize("shape", sorted(NOT_A_MAPPING))
def test_a_non_mapping_item_before_the_fork_point_survives_resume(shape, tmp_path):
    """fork's _causal_transcript carries unscoped items forward, so resume must too."""
    path = _saved(tmp_path, f"trf-{shape}", steps=1, prefix=[NOT_A_MAPPING[shape]])
    model = _Model()
    resumed = _resume(path, model=model)
    assert resumed.status is RunStatus.completed
    assert model.seen[0] == [
        {"role": "assistant", "content": "a0"},
        {"role": "user", "content": "go"},
    ]
    assert resumed.transcript[0] == NOT_A_MAPPING[shape]


def test_a_mapping_without_a_role_is_still_skipped_the_same_way(tmp_path):
    """Absence and a non-message record have always been the same case here."""
    assert _messages_from_transcript([{"step_id": "s"}, 5, {"role": "user", "content": "hi"}]) == [
        {"role": "user", "content": "hi"}
    ]


def test_a_well_formed_transcript_is_passed_through_unchanged(tmp_path):
    items = [
        {"step_id": "s0", "role": "user", "content": "hi"},
        {"step_id": "s1", "role": "assistant", "content": "yo", "extra": {"provider": "x"}},
    ]
    assert _messages_from_transcript(items) == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "yo", "extra": {"provider": "x"}},
    ]


# --------------------------------------------------------------------------------------
# (3) assistant.tool_calls: the safety check refuses what it cannot read
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(UNREADABLE_CALLS))
def test_resume_refuses_an_unreadable_tool_call_record(shape, tmp_path):
    entry = {"role": "assistant", "content": "x", "tool_calls": UNREADABLE_CALLS[shape]}
    path = _saved(tmp_path, f"tc-{shape}", steps=0, transcript=[entry])
    model = _Model()
    with pytest.raises(RuntimeError, match="tool-call record that is not a list of objects"):
        _resume(path, model=model)
    assert model.seen == []  # refused before any provider call


@pytest.mark.parametrize("shape", sorted(UNREADABLE_CALLS))
def test_an_unreadable_tool_call_record_still_loads_and_forks(shape, tmp_path):
    """Resume is not allowed to be stricter than the loader in a way that bricks a run."""
    entry = {"role": "assistant", "content": "x", "tool_calls": UNREADABLE_CALLS[shape]}
    path = _saved(tmp_path, f"tcl-{shape}", steps=1, prefix=[entry])
    loaded = Run.load(path)
    assert loaded.transcript[0] == entry
    forked = loaded.fork(loaded.refs["main"], new_run_id="child")
    forked.save(tmp_path / "child.tine")
    assert Run.load(tmp_path / "child.tine").transcript[0] == entry


@pytest.mark.parametrize("value", [[], 0, "", None, False])
def test_a_falsy_tool_calls_value_is_still_not_a_batch(value, tmp_path):
    """Unchanged behaviour: only a *truthy* value was ever read as a batch."""
    entry = {"role": "assistant", "content": "x", "tool_calls": value}
    path = _saved(tmp_path, f"tcf-{json.dumps(value)}", steps=0, transcript=[entry])
    assert _resume(path).status is RunStatus.completed


def test_a_complete_tool_batch_still_resumes(tmp_path):
    transcript = [
        {"role": "assistant", "content": "x", "tool_calls": [{"id": "c1", "name": "t"}]},
        {"role": "tool", "content": "r", "tool_call_id": "c1", "name": "t"},
    ]
    path = _saved(tmp_path, "tc-ok", steps=0, transcript=transcript)
    model = _Model()
    assert _resume(path, model=model).status is RunStatus.completed
    assert model.seen[0][:2] == transcript


def test_an_incomplete_tool_batch_is_refused_with_the_same_message_as_before(tmp_path):
    entry = {"role": "assistant", "content": "x", "tool_calls": [{"id": "c1", "name": "t"}]}
    path = _saved(tmp_path, "tc-partial", steps=0, transcript=[entry])
    with pytest.raises(RuntimeError, match="ends inside a tool-call batch"):
        _resume(path)


def test_an_unmatched_tool_result_is_refused_with_the_same_message_as_before(tmp_path):
    transcript = [
        {"role": "assistant", "content": "x", "tool_calls": [{"id": "c1", "name": "t"}]},
        {"role": "tool", "content": "r", "tool_call_id": "other"},
    ]
    path = _saved(tmp_path, "tc-unmatched", steps=0, transcript=transcript)
    with pytest.raises(RuntimeError, match="unmatched tool result"):
        _resume(path)


# --------------------------------------------------------------------------------------
# (4) replay: a run with no recorded steps has no tip to reuse
# --------------------------------------------------------------------------------------


def test_cache_replay_of_a_stepless_run_refuses_instead_of_indexerror(tmp_path):
    path = _saved(tmp_path, "empty", steps=0)
    assert json.loads(path.read_text())["refs"]["main"] == ""  # what RunBase seeds
    with pytest.raises(RuntimeError, match="no recorded steps"):
        _replay(path)


def test_rerun_replay_of_a_stepless_run_still_works(tmp_path):
    """The refusal names this mode, so it has to keep working."""
    path = _saved(tmp_path, "empty-rerun", steps=0)
    replayed = _replay(path, mode="rerun")
    assert replayed.status is RunStatus.completed
    assert replayed.id == "empty-rerun-rerun"


def test_resume_of_a_stepless_run_still_works(tmp_path):
    """Resume has always handled the empty graph; the replay guard must not change that."""
    assert _resume(_saved(tmp_path, "empty-resume", steps=0)).status is RunStatus.completed


@pytest.mark.parametrize("main", ["", "seeded"])
def test_cache_replay_of_a_stepped_run_is_unchanged(main, tmp_path):
    """An empty refs.main on a run that has steps still falls back to the tip, as before."""
    path = _saved(tmp_path, f"tip-{main or 'blank'}", steps=2)
    if not main:
        data = json.loads(path.read_text())
        data["refs"]["main"] = ""
        assert validate_run_record(data)
        path.write_text(json.dumps(data))
    replayed = _replay(path)
    assert replayed.metadata["replay"]["reused_steps"] == 2
    assert replayed.metadata["replay"]["mode"] == "cache"


# --------------------------------------------------------------------------------------
# class sweep: no position in this file may produce a raw interpreter error
# --------------------------------------------------------------------------------------


def _positions():
    for name, value in sorted(NOT_A_LIST.items()):
        yield f"resume_history/{name}", {"manifest": {"resume_history": value}}
    for name, value in sorted(NOT_A_MAPPING.items()):
        yield f"transcript-item/{name}", {"transcript": [value]}
    for name, value in sorted(UNREADABLE_CALLS.items()):
        yield (
            f"tool_calls/{name}",
            {"transcript": [{"role": "assistant", "content": "x", "tool_calls": value}]},
        )
    for name, value in sorted(NOT_A_MAPPING.items()):
        yield (
            f"tool_call_id/{name}",
            {
                "transcript": [
                    {"role": "assistant", "content": "x", "tool_calls": [{"id": "c1"}]},
                    {"role": "tool", "content": "r", "tool_call_id": value},
                ]
            },
        )
    for name, value in sorted(NOT_A_MAPPING.items()):
        yield (
            f"call-id/{name}",
            {"transcript": [{"role": "assistant", "content": "x", "tool_calls": [{"id": value}]}]},
        )
    yield "stepless", {}


CASES = dict(_positions())


@pytest.mark.parametrize("case", sorted(CASES))
@pytest.mark.parametrize("steps", [0, 1])
def test_no_position_raises_a_raw_interpreter_error(case, steps, tmp_path):
    """Every shape at every position: a typed refusal or correct behaviour, never a crash."""
    kwargs = CASES[case]
    path = _saved(
        tmp_path,
        f"sweep-{case.replace('/', '-')}-{steps}",
        steps=steps,
        manifest=kwargs.get("manifest"),
        prefix=kwargs.get("transcript", ()),
    )
    assert Run.load(path).id.startswith("sweep-")  # loadable, so resume owes a clean answer
    for call in (lambda: _resume(path), lambda: _replay(path), lambda: _replay(path, "rerun")):
        try:
            call()
        except RuntimeError:
            pass
        except RAW as exc:  # pragma: no cover - the regression this file exists for
            pytest.fail(f"{case}/steps={steps} raised {type(exc).__name__}: {exc}")
