"""Round-8 audit regressions: write-side validation (group B).

Both defects share the round-7 shape: the writer accepted what every later read
rejected, so a run persisted cleanly, fsck stayed green, and the data was gone.
What the reader rejects, the writer must reject too — at write time, with an
actionable error.
"""

from __future__ import annotations

import pytest

from opentine import Run, StepKind
from opentine.kernel import parse_oid
from opentine.repository import Repo
from opentine.repository._annotations import write_run_annotation
from opentine.trace._record_event import put_trace_event
from opentine.trace.schema import TraceEvent

WIDE = {"rows": [{"i": i} for i in range(60_000)]}  # ~240k structural tokens


def _poison_annotation_head(repo, run_id, value):
    """Write a malformed annotation head the way a pre-fix build did."""
    oid = repo.put(
        "annotation",
        {
            "compatibility": "run-metadata-v1",
            "previous_id": None,
            "target_id": run_id,
            "value": value,
        },
        redact=False,
    )
    name = f"annotations/{parse_oid(run_id)[1]}"
    repo.update_ref(name, oid, expected_old=repo.read_ref(name))


def test_run_tags_and_metadata_rejected_at_read_are_also_rejected_at_write(tmp_path):
    # run.tags / run.metadata are plain attributes, so a non-string tag passed
    # put_run, then every load_run raised "run annotation tags are malformed"
    # while fsck reported the repository healthy.
    repo = Repo.init(tmp_path)
    tagged = Run(id="bad-tag")
    tagged.add_step(StepKind.think, {"a": 1})
    tagged.tags.append(5)
    before = repo.fsck().objects
    with pytest.raises(ValueError, match="run tags must all be strings"):
        repo.put_run(tagged)

    typed = Run(id="bad-metadata")
    typed.add_step(StepKind.think, {"a": 1})
    typed.metadata = "oops"
    with pytest.raises(ValueError, match="run metadata must be a JSON object"):
        repo.put_run(typed)

    # preflight caught both before anything reached disk
    after = repo.fsck()
    assert after.ok and after.objects == before


def test_poisoned_annotation_head_can_be_superseded_by_a_clean_write(tmp_path):
    # The dedupe read called _value() on the existing head, so a repo poisoned by
    # an older build rejected the corrected annotation too: repair through the
    # API was impossible and the run stayed permanently unloadable.
    repo = Repo.init(tmp_path)
    run = Run(id="poisoned")
    run.add_step(StepKind.think, {"a": 1})
    run_id = repo.put_run(run).run_id
    _poison_annotation_head(repo, run_id, {"metadata": {}, "tags": [5]})
    with pytest.raises(ValueError, match="tags are malformed"):
        repo.load_run(run_id)

    assert write_run_annotation(repo, run_id, {"k": "v"}, ["ok"])
    repaired = repo.load_run(run_id)
    assert repaired.tags == ["ok"] and repaired.metadata == {"k": "v"}


def test_reput_of_the_same_run_repairs_a_poisoned_annotation(tmp_path):
    # Re-saving the run with fixed tags mints the same content-addressed run id,
    # so repair had to go through the same annotation head that raised.
    repo = Repo.init(tmp_path)
    run = Run(id="poisoned-reput")
    run.add_step(StepKind.think, {"a": 1})
    run_id = repo.put_run(run).run_id
    _poison_annotation_head(repo, run_id, {"metadata": "oops", "tags": []})
    with pytest.raises(ValueError, match="value is malformed"):
        repo.load_run(run_id)

    run.tags = ["fixed"]
    assert repo.put_run(run).run_id == run_id
    assert repo.load_run(run_id).tags == ["fixed"]


def test_a_step_wide_enough_to_save_is_still_narrow_enough_to_load(tmp_path):
    # json_blob stored raw bytes with no structural check while blob_json bounds
    # every read, so a wide tool output saved cleanly and then failed every later
    # Run.load with "compatibility JSON blob is malformed".
    repo = Repo.init(tmp_path)
    wide = Run(id="wide")
    wide.add_step(StepKind.tool, {"query": "list"}, WIDE)
    with pytest.raises(ValueError, match="structural limit"):
        wide.save(tmp_path)

    check = repo.fsck()
    assert check.ok and check.refs == 0  # rejected save left no bricked head

    ordinary = Run(id="ordinary")
    ordinary.add_step(StepKind.tool, {"query": "list"}, {"rows": [{"i": i} for i in range(1000)]})
    ordinary.save(tmp_path)
    assert len(Run.load(tmp_path).steps) == 1


def test_trace_event_blobs_enforce_the_loader_cap_at_write(tmp_path):
    # The trace recorder shares the blob writer, so an imported span with a wide
    # payload bricked load_run the same way.
    repo = Repo.init(tmp_path)
    event = TraceEvent(kind="tool", timestamp=0.0, trace_id="t", span_id="s", outputs=WIDE)
    with pytest.raises(ValueError, match="structural limit"):
        put_trace_event(repo, event, {})
