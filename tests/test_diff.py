"""Field-level diff coverage."""

from __future__ import annotations

from opentine import Run, StepKind


def _linear(run_id: str, texts) -> Run:
    run = Run(id=run_id)
    for t in texts:
        run.add_step(StepKind.done, {"text": t})
    return run


def test_changed_pair_has_field_deltas():
    a = Run(id="a")
    root = a.add_step(StepKind.think, {"text": "root"})
    a.add_step(StepKind.done, {"text": "answer A"}, parent_id=root.id)

    b = a.fork(root.id, new_run_id="b")
    b.add_step(StepKind.done, {"text": "answer B"})

    diff = a.diff(b)
    assert diff.only_a == [] and diff.only_b == []
    assert len(diff.changed) == 1
    change = diff.changed[0]
    inputs_delta = next(d for d in change.fields if d.name == "inputs")
    assert "text" in inputs_delta.changed_keys
    assert inputs_delta.before["text"] == "answer A"
    assert inputs_delta.after["text"] == "answer B"


def test_same_id_cost_drift_surfaces():
    # Two runs whose single step has identical content (same id) but a different
    # cost — replay drift that the content hash alone would hide.
    a = Run(id="a")
    a.add_step(StepKind.done, {"text": "x"}, cost=1.0, usage={"input": 10, "output": 2})
    b = Run(id="b")
    b.add_step(StepKind.done, {"text": "x"}, cost=2.0, usage={"input": 10, "output": 9})
    assert a.steps[0].id == b.steps[0].id  # same content addressing

    diff = a.diff(b)
    assert diff.only_a == [] and diff.only_b == []
    assert len(diff.changed) == 1
    names = {d.name for d in diff.changed[0].fields}
    assert "cost" in names
    assert "usage" in names


def test_identical_runs_have_no_changes():
    a = _linear("a", ["one", "two"])
    b = _linear("b", ["one", "two"])
    diff = a.diff(b)
    assert diff.changed == []
    assert diff.only_a == [] and diff.only_b == []


def test_append_is_only_b_not_changed():
    a = _linear("a", ["one"])
    b = a.fork(a.steps[0].id, new_run_id="b")
    b.add_step(StepKind.done, {"text": "two"})  # new tail at a fresh position
    diff = a.diff(b)
    assert [s.inputs["text"] for s in diff.only_b] == ["two"]
    assert diff.changed == []


def test_different_kind_same_position_is_only_not_changed():
    a = Run(id="a")
    root = a.add_step(StepKind.think, {"text": "root"})
    a.add_step(StepKind.tool, {"name": "search"}, parent_id=root.id)

    b = a.fork(root.id, new_run_id="b")
    b.add_step(StepKind.done, {"text": "answer"})  # same position, different kind

    diff = a.diff(b)
    assert diff.changed == []  # different kinds are different work
    assert any(s.kind == StepKind.tool for s in diff.only_a)
    assert any(s.kind == StepKind.done for s in diff.only_b)


def test_diff_on_500_step_runs_is_bounded():
    # guard against accidental quadratic blowup in position-keying
    a = _linear("a", [str(i) for i in range(500)])
    b = _linear("b", [str(i) for i in range(500)])
    diff = a.diff(b)
    assert diff.changed == [] and diff.only_a == [] and diff.only_b == []
