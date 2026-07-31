"""Golden fixture coverage for the current .tine v1 format."""

from __future__ import annotations

import json
from pathlib import Path

from opentine import Run, StepKind

FIXTURES = Path(__file__).parent / "fixtures"


def test_golden_v1_load_save_fork_and_diff(tmp_path):
    fixture = FIXTURES / "golden_v1.tine"
    original_data = json.loads(fixture.read_text(encoding="utf-8"))

    integrity = Run.verify_integrity(fixture)
    assert integrity.ok
    assert integrity.algorithm == "sha256"

    run = Run.load(fixture)
    assert run.id == "golden-v1"
    assert run.model_info == "mock-golden"
    assert [step.kind for step in run.steps] == [StepKind.think, StepKind.tool, StepKind.done]
    assert run.refs["main"] == run.steps[-1].id

    resaved = tmp_path / "resaved.tine"
    run.save(resaved)
    assert Run.verify_integrity(resaved).ok
    # Re-saving a loaded v1 artifact upgrades it to v2 in place, preserving run
    # identity, graph order, and content-addressed step ids, while recording a
    # migration breadcrumb. (v1 still verifies under v1: asserted above.)
    resaved_data = json.loads(resaved.read_text(encoding="utf-8"))
    assert resaved_data["format_version"] == 2
    assert resaved_data["run_id"] == original_data["run_id"]
    assert resaved_data["graph"]["order"] == original_data["graph"]["order"]
    assert set(resaved_data["graph"]["steps"]) == set(original_data["graph"]["steps"])
    assert resaved_data["metadata"]["migration"][-1]["to"] == 2

    forked = run.fork(run.steps[1].id, new_run_id="golden-fork")
    forked.add_step(StepKind.done, {"text": "forked result"})
    diff = run.diff(forked)

    assert len(forked.steps) == 3
    assert diff.common_ancestor == run.steps[1].id
    # The original `done` step and the forked `done` step share a lineage
    # position + kind but differ in content, so they pair as a field-level change
    # rather than only_a/only_b.
    assert diff.only_a == [] and diff.only_b == []
    assert len(diff.changed) == 1
    change = diff.changed[0]
    assert change.step_a.id == run.steps[2].id
    assert change.step_b.id == forked.steps[-1].id
    assert change.step_a.inputs.get("text") == "done"
    assert change.step_b.inputs.get("text") == "forked result"
    assert any(d.name == "inputs" and "text" in d.changed_keys for d in change.fields)


def test_v2_and_v3_canonicalizations_order_keys_differently_and_must_stay_that_way():
    """v2 artifacts (``_canon``) and v3 objects (``kernel``) canonicalize
    independently, with DIFFERENT key orderings: v2 sorts by Unicode code point
    (``json.dumps(sort_keys=True)``, ASCII-escaped); v3 sorts by UTF-16BE bytes
    with ``ensure_ascii`` off. The two disagree for non-BMP keys, whose surrogate
    code units (0xD800..) sort below BMP characters in U+E000..U+FFFF.

    This divergence is load-bearing: every stored v2 integrity digest/signature
    and every v3 object id was written under its own ordering, so "unifying" the
    two canonicalizations would silently invalidate all of them and break the
    backwards-compat gate. Pin both against a discriminating input so any such
    change fails loudly here rather than as unreadable historical data."""
    from opentine._canon import _canonical_bytes
    from opentine.kernel import canonical_json

    # U+E000 (BMP) vs U+10000 (non-BMP; UTF-16 surrogate pair D800 DC00).
    keys = {"": 1, "\U00010000": 2}
    # v2: code-point order puts U+E000 first; non-ASCII is \\u-escaped.
    assert _canonical_bytes(keys) == b'{"\\ue000":1,"\\ud800\\udc00":2}'
    # v3: UTF-16BE order puts U+10000 first; emitted as raw UTF-8.
    assert canonical_json(keys) == '{"\U00010000":2,"":1}'.encode("utf-8")
    # They genuinely disagree — the guard exists to keep it that way.
    assert _canonical_bytes(keys) != canonical_json(keys)
