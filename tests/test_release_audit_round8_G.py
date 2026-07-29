"""Regressions for the v0.3.0 second-round audit (group G).

Each test pins a defect that shipped-quality code had already passed review for,
so the assertions describe the *user-visible* failure rather than the mechanism.
"""

from __future__ import annotations

import json

import pytest

from opentine import Run, StepKind
from opentine.repository import Repo
from opentine.tools import fs
from opentine.trace import Recorder, jsonl_events, native_events
from opentine.trace.schema import TraceEvent


def _event(**overrides):
    base = {"kind": "model", "timestamp": 1.0, "trace_id": "t", "span_id": "s"}
    base.update(overrides)
    return TraceEvent(**base)


def test_metric_rejected_by_the_event_store_is_rejected_at_schema_construction():
    # The schema validated the original Python value while the store validated
    # the json_safe-transformed one with stricter rules, so events constructed
    # fine and then crashed recorder append/import with a KernelError.
    for message, overrides in (
        ("trace usage", {"usage": {"custom_counter": 10**20}}),
        ("trace cost", {"cost": "1e999999999"}),
        ("trace cost", {"billing": {"known_subtotal_usd": "1e999999999"}}),
        ("trace cost", {"cost": 10**300}),
        ("trace duration", {"duration": 10**300}),
        ("trace timestamp", {"timestamp": 10**300}),
    ):
        with pytest.raises(ValueError, match=message):
            _event(**overrides)


def test_schema_accepted_metrics_always_append(tmp_path):
    # The flip side of the gate: everything the schema lets through must reach
    # the store without a KernelError, including the edge shapes near it.
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    survivors = (
        _event(span_id="a", timestamp=-10.0),
        _event(span_id="b", cost="0.25", duration=10**20),
        _event(span_id="c", usage={"input": 10, "custom_ratio": 1e300}),
        _event(span_id="d", billing={"known_subtotal_usd": "0.125"}),
    )
    for event in survivors:
        assert recorder.append(event).startswith("event:")


def test_jsonl_import_discards_unsafe_usage_dimension_instead_of_crashing(tmp_path):
    # safe_usage kept non-token ints above 2**53-1 despite its discard-with-
    # warning contract, and the whole import then died inside repo.put.
    events = jsonl_events(
        [
            json.dumps({"span_id": "a", "usage": {"input": 10, "internal_seq": 10**20}}),
            json.dumps({"span_id": "b", "parent_span_id": "a"}),
        ]
    )
    assert events[0].usage == {"input": 10}
    warnings = events[0].attributes["opentine.import_warnings"]
    assert any("internal_seq" in warning for warning in warnings)
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    assert len(recorder.import_events(events)) == 2


def test_fs_read_and_edit_agree_on_crlf_files(tmp_path):
    # read() translated CRLF to LF while edit() matched raw bytes, so any
    # multi-line `old` copied verbatim from read() output could never match
    # and CRLF files were structurally uneditable across lines.
    for name, newline in (("crlf.txt", b"\r\n"), ("lf.txt", b"\n")):
        path = tmp_path / name
        path.write_bytes(newline.join((b"alpha", b"beta", b"gamma", b"")))
        shown = fs.read(str(path), sandbox=str(tmp_path))
        old = shown.split("gamma")[0]  # "alpha<eol>beta<eol>" exactly as read() showed it
        fs.edit(str(path), old, old.replace("beta", "BETA"), sandbox=str(tmp_path))
        assert path.read_bytes() == newline.join((b"alpha", b"BETA", b"gamma", b""))


def test_native_events_preserves_both_parents_of_a_legacy_merge_step(tmp_path):
    # native_events kept only parent_ids[-1] per step, silently reshaping the
    # DAG of any legacy run that used the supported fork/merge workflow.
    run = Run(id="merge-run")
    a = run.add_step(StepKind.model, {})
    b = run.add_step(StepKind.model, {}, parent_ids=[])
    merge = run.add_step(StepKind.model, {}, parent_ids=[a.id, b.id])

    events = native_events(run)
    carried = {events[-1].parent_span_id, *events[-1].causal_span_ids}
    assert carried == set(merge.parent_ids)

    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    event_ids = recorder.import_events(events)
    payload = repo.get(event_ids[-1]).payload()
    dag_edges = {*(payload.get("parent_ids") or []), *(payload.get("causal_ids") or [])}
    assert dag_edges == {event_ids[0], event_ids[1]}

    loaded = repo.load_run(recorder.run_id)
    step = loaded.graph.steps[event_ids[-1]]
    round_trip = {*step.parent_ids, *loaded._v3_causal_ids[event_ids[-1]]}
    assert round_trip == dag_edges
