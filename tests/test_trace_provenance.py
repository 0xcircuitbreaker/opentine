"""Trace identity and dependency provenance regression tests."""

from __future__ import annotations

import pytest

from opentine.repository import Repo
from opentine.trace import Recorder, TraceEvent


def event(
    trace: str,
    span: str,
    *,
    parent: str | None = None,
    causal: tuple[str, ...] = (),
) -> TraceEvent:
    return TraceEvent(
        "model",
        1,
        trace,
        span,
        parent_span_id=parent,
        causal_span_ids=causal,
    )


def test_same_span_id_in_different_traces_does_not_cross_link(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    first = recorder.append(event("trace-a", "root"))
    second = recorder.append(event("trace-b", "root"), chain_if_parentless=False)
    child = recorder.append(event("trace-b", "child", parent="root"))
    effect = recorder.append(event("trace-a", "effect", causal=("root",)))

    assert repo.get(child).payload()["parent_ids"] == [second]
    assert repo.get(child).payload()["parent_ids"] != [first]
    assert repo.get(effect).payload()["causal_ids"] == [first]
    assert repo.get(effect).payload()["causal_ids"] != [second]


def test_import_resolves_same_span_ids_only_within_their_trace(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    ids = recorder.import_events(
        [
            event("trace-a", "root"),
            event("trace-b", "child", parent="root"),
            event("trace-b", "root"),
            event("trace-a", "child", parent="root"),
        ]
    )

    assert repo.get(ids[1]).payload()["parent_ids"] == [ids[2]]
    assert repo.get(ids[3]).payload()["parent_ids"] == [ids[0]]


@pytest.mark.parametrize("batched", [False, True])
def test_duplicate_span_id_within_trace_is_rejected(tmp_path, batched):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(event("trace", "duplicate"))

    with pytest.raises(ValueError, match="duplicate span ID within trace"):
        if batched:
            recorder.import_events([event("trace", "duplicate")])
        else:
            recorder.append(event("trace", "duplicate"))


def test_duplicate_span_id_inside_batch_is_rejected_atomically(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    original = recorder.run_id
    with pytest.raises(ValueError, match="duplicate span ID within trace"):
        recorder.import_events([event("trace", "same"), event("trace", "same")])
    assert recorder.run_id == original
    assert recorder.payload["events"] == []


@pytest.mark.parametrize(
    "events",
    [
        [event("trace", "a", parent="b"), event("trace", "b", parent="a")],
        [
            event("trace", "a", causal=("b",)),
            event("trace", "b", causal=("a",)),
        ],
        [event("trace", "self", parent="self")],
    ],
)
def test_dependency_cycles_are_rejected_without_linearization(tmp_path, events):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    original = recorder.run_id
    with pytest.raises(ValueError, match="dependency cycle"):
        recorder.import_events(events)
    assert recorder.run_id == original
    assert recorder.payload["events"] == []


@pytest.mark.parametrize(
    "candidate",
    [event("trace", "self", parent="self"), event("trace", "self", causal=("self",))],
)
def test_live_append_rejects_self_dependencies_before_writing(tmp_path, candidate):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    original = recorder.run_id
    with pytest.raises(ValueError, match="dependency cycle"):
        recorder.append(candidate)
    assert recorder.run_id == original
    assert recorder.payload["events"] == []


def test_resume_preserves_trace_qualified_span_resolution(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    first = recorder.append(event("trace-a", "root"))
    second = recorder.append(event("trace-b", "root"), chain_if_parentless=False)

    resumed = Recorder.resume(repo, recorder.run_id, ref="heads/main")
    child = resumed.append(event("trace-a", "child", parent="root"))
    assert repo.get(child).payload()["parent_ids"] == [first]
    assert repo.get(child).payload()["parent_ids"] != [second]

    with pytest.raises(ValueError, match="duplicate span ID within trace"):
        resumed.append(event("trace-b", "root"))


def test_unresolved_links_are_retained_and_partial_import_remains_usable(tmp_path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    ids = recorder.import_events(
        [
            event(
                "trace",
                "partial",
                parent="outside-parent",
                causal=("outside-cause", "outside-cause"),
            ),
            event("trace", "independent"),
        ]
    )

    payload = repo.get(ids[0]).payload()
    assert payload["parent_ids"] == []
    assert payload["causal_ids"] == []
    assert payload["unresolved_span_refs"] == {
        "causal": ["outside-cause"],
        "parent": ["outside-parent"],
    }
    assert set(recorder.payload["roots"]) == set(ids)
    assert repo.fsck().ok
