"""Round-8 audit regressions, group D: fork must tolerate what load tolerates.

Both defects were writer/reader asymmetries in reverse: the artifact saves,
loads, shows, and verifies cleanly, then ``run.fork()`` raises AttributeError
deep inside slicing helpers -- surfacing as raw tracebacks from ``tine fork``,
``tine replay --mode cache``, and the MCP fork_run tool.
"""

from __future__ import annotations

from opentine import Run, StepKind
from opentine.mcp_server import fork_run_file


def _run_with(run_id: str) -> Run:
    run = Run(id=run_id, model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    return run


def test_fork_survives_a_non_dict_transcript_item(tmp_path):
    # A bare string in the transcript saves and loads fine; fork used to crash
    # on item.get("step_id"). It must ride along like any unscoped human turn.
    run = _run_with("transcript-note")
    run.transcript.append("a bare string turn")
    path = tmp_path / "transcript_str.tine"
    run.save(path)

    loaded = Run.load(path)
    assert "a bare string turn" in loaded.transcript

    forked = loaded.fork(loaded.steps[0].id)
    assert "a bare string turn" in forked.transcript


def test_fork_attaches_a_non_dict_turn_to_the_next_retained_event(tmp_path):
    # Mixed transcripts keep their causal slice: the stray string is pending
    # context for the next content-addressed event, exactly like an unscoped dict.
    run = _run_with("transcript-mixed")
    fork_point = run.steps[0].id
    run.transcript = [
        "context before the event",
        {"role": "assistant", "content": "kept", "step_id": fork_point},
        {"role": "user", "content": "after the fork point", "step_id": "unretained"},
    ]
    path = tmp_path / "transcript_mixed.tine"
    run.save(path)

    forked = Run.load(path).fork(fork_point)
    assert forked.transcript == [
        "context before the event",
        {"role": "assistant", "content": "kept", "step_id": fork_point},
    ]


def test_fork_survives_pricing_catalogs_that_are_not_a_list(tmp_path):
    # validate_run_record does not constrain manifest.pricing.catalogs, so a
    # hand-edited dict there loads cleanly; the snapshot lookup then iterated
    # the dict's string keys and crashed on str.get. Fork now finds no
    # snapshot in a malformed shape instead of crashing.
    run = _run_with("pricing-bad")
    run.manifest["pricing"] = {
        "invocations": [],
        "catalogs": {"cid": "not-a-list"},
        "catalog_provenance": "stale",
    }
    path = tmp_path / "pricing_bad.tine"
    run.save(path)

    loaded = Run.load(path)
    forked = loaded.fork(loaded.steps[0].id)
    pricing = forked.manifest["pricing"]
    assert pricing["invocations"] == []
    # No snapshot can be resolved from a malformed catalogs shape.
    assert "catalog_provenance" not in pricing


def test_mcp_fork_run_handles_both_tolerated_shapes(tmp_path):
    # The same crashes escaped mcp_server.fork_run_file as internal errors.
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()

    noted = _run_with("mcp-transcript-note")
    noted.transcript.append("a bare string turn")
    noted.save(runs_dir / "mcp-transcript-note.tine")

    priced = _run_with("mcp-pricing-bad")
    priced.manifest["pricing"] = {"invocations": [], "catalogs": {"cid": "not-a-list"}}
    priced.save(runs_dir / "mcp-pricing-bad.tine")

    for run_id in ("mcp-transcript-note", "mcp-pricing-bad"):
        result = fork_run_file(run_id, 0, runs_dir=runs_dir)
        assert result["forked_from"] == run_id
        assert Run.load(result["path"]).status.value == "running"
