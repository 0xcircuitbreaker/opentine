"""Round-9 release-audit regressions: shallow boundary on the fork/resume surface.

Round 8 guarded the graph *read* APIs (log, context_slice, semantic_diff,
load_run) against depth-limited clones but left the run-continuation surface
open: Repo.fork/ops.fork_run walked parent_ids/causal_ids with a bare
repo.get and leaked a raw KeyError, and so did Recorder.resume's span-map
rebuild and graph_tips. Full materializations now refuse with the same typed
KernelError remedy load_run uses; traversal-shaped reads stop cleanly.
"""

from __future__ import annotations

import pytest

from opentine.kernel import KernelError
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.repository._run_graph import graph_tips
from opentine.repository.pack import create_pack, install_pack, reachable
from opentine.trace import Recorder, TraceEvent
from opentine.trace._record_event import span_key


def _shallow_clone(tmp_path, depth: int):
    """A depth-limited clone exactly as fetch --depth produces one (round-8 harness)."""
    src = Repo.init(tmp_path / "src")
    blob = src.put("blob", b"payload text")
    first = src.put(
        "event",
        {"cost": 1.0, "input_blob": blob, "kind": "model", "parent_ids": [],
         "span_id": "s1", "trace_id": "t"},
    )  # fmt: skip
    second = src.put(
        "event",
        {"cost": 2.0, "kind": "model", "parent_ids": [first], "span_id": "s2", "trace_id": "t"},
    )
    third = src.put(
        "event",
        {"cost": 3.0, "kind": "model", "parent_ids": [second], "span_id": "s3", "trace_id": "t"},
    )
    run = src.put(
        "run",
        {"events": [first, second, third], "roots": [first],
         "status": "completed", "tips": [third]},
    )  # fmt: skip
    src.update_ref("heads/main", run)
    dst = Repo.init(tmp_path / "dst")
    install_pack(dst, create_pack(src, reachable(src, [run], depth=depth)))
    dst.update_ref("heads/main", run)
    return src, dst, run, (first, second, third)


class _FakeMCP:
    def __init__(self):
        self.tools = {}
        self.resources = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        def register(function):
            self.resources[uri] = function
            return function

        return register


@pytest.mark.parametrize("depth", [0, 1])
def test_fork_on_a_shallow_clone_names_the_remedy(tmp_path, depth):
    # The fork closure walked parent_ids/causal_ids with a bare repo.get, so
    # the first cut ancestor surfaced as KeyError('event:sha256:...') naming
    # an object the caller never mentioned, while fsck reported ok.
    _, dst, run, (first, _, third) = _shallow_clone(tmp_path, depth)
    assert dst.fsck().ok
    for from_event in (third, first):
        with pytest.raises(KernelError, match="forking run .* deepen the fetch"):
            dst.fork(run, from_event, ref="heads/experiment")


def test_a_refused_fork_writes_no_objects_and_no_refs(tmp_path):
    _, dst, run, (_, _, third) = _shallow_clone(tmp_path, depth=1)
    refs_before = dst.list_refs()
    oids_before = set(dst.iter_oids())
    with pytest.raises(KernelError, match="deepen the fetch"):
        dst.fork(run, third, ref="heads/experiment")
    assert dst.list_refs() == refs_before
    assert set(dst.iter_oids()) == oids_before


def test_fork_still_succeeds_when_the_closure_is_inside_the_boundary(tmp_path):
    # The guard must refuse crossings, not shallow repositories: a run whose
    # ancestry is fully present forks fine on the same depth-limited clone.
    _, dst, _, _ = _shallow_clone(tmp_path, depth=1)
    event = dst.put("event", {"cost": 1.0, "kind": "model", "parent_ids": []})
    run = dst.put(
        "run", {"events": [event], "roots": [event], "status": "completed", "tips": [event]}
    )
    forked = dst.fork(run, event, ref="heads/local-fork")
    assert dst.get(forked).payload()["events"] == [event]


def test_deepening_the_fetch_restores_fork_and_resume(tmp_path):
    src, dst, run, (_, _, third) = _shallow_clone(tmp_path, depth=1)
    with pytest.raises(KernelError, match="deepen the fetch"):
        dst.fork(run, third, ref="heads/experiment")
    dst.import_pack(src.pack())
    forked = dst.fork(run, third, ref="heads/experiment")
    assert dst.read_ref("heads/experiment") == forked
    assert Recorder.resume(dst, "heads/main").run_id == run


@pytest.mark.parametrize("depth", [0, 1])
def test_recorder_resume_on_a_shallow_clone_names_the_remedy(tmp_path, depth):
    # resume rebuilt its span map with a bare repo.get over every recorded
    # event, so both run-continuation entry points crashed with KeyError.
    _, dst, _, _ = _shallow_clone(tmp_path, depth)
    with pytest.raises(KernelError, match="resuming run .* deepen the fetch"):
        Recorder.resume(dst, "heads/main")


def test_recorder_fork_gets_the_typed_refusal(tmp_path):
    _, dst, run, (_, _, third) = _shallow_clone(tmp_path, depth=1)
    recorder = Recorder(dst, run, "heads/main")
    with pytest.raises(KernelError, match="forking run .* deepen the fetch"):
        recorder.fork(third, ref="heads/experiment")


def test_recorder_span_map_refuses_cut_events_but_accepts_present_ones(tmp_path):
    _, dst, run, (_, second, third) = _shallow_clone(tmp_path, depth=1)
    with pytest.raises(KernelError, match="recording into run .* deepen the fetch"):
        Recorder(dst, run, "heads/main", {span_key("t", "s2"): second})
    # A span map naming only present events still constructs, and appending
    # into the shallow clone keeps working (the tolerant write surface).
    recorder = Recorder(dst, run, "heads/main", {span_key("t", "s3"): third})
    appended = recorder.append(TraceEvent("model", 4.0, "t", "s4", outputs={"text": "ok"}))
    assert dst.get(appended).payload()["parent_ids"] == [third]
    assert dst.fsck().ok


def test_graph_tips_stops_at_the_shallow_fetch_boundary(tmp_path):
    src, dst, _, events = _shallow_clone(tmp_path, depth=1)
    _, _, third = events
    assert graph_tips(src, list(events)) == [third]  # full repo unchanged
    assert graph_tips(dst, list(events)) == [third]  # cut events contribute nothing
    _, zero, _, zero_events = _shallow_clone(tmp_path / "zero", depth=0)
    assert graph_tips(zero, list(zero_events)) == []


def test_mcp_fork_and_resume_tools_surface_the_remedy(tmp_path):
    # fork_run_v3/resume_run_v3 hand tool errors straight to a model client;
    # they now carry the actionable message instead of an oid-only KeyError.
    _, dst, run, (_, _, third) = _shallow_clone(tmp_path, depth=1)
    mcp = _FakeMCP()
    register_repository_tools(mcp, str(tmp_path / "dst"))
    with pytest.raises(KernelError, match="deepen the fetch"):
        mcp.tools["fork_run_v3"](run, third, "experiments/x")
    with pytest.raises(KernelError, match="deepen the fetch"):
        mcp.tools["resume_run_v3"](run, "experiments/x")
