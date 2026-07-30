"""Round-9 audit regressions: blob/artifact writer-reader symmetry (group blobguard).

Round 8 aligned the writer with the reader one rule at a time, and every round
found the next unaligned rule. These tests pin the whole contract instead:
every rule ``blob_json`` or the ``.tine`` reader enforces has a write-side
counterpart, and the structural budget is one formula imported by both sides,
so a run that saves is a run that loads — and a run that loads is a run that
can be written into a v3 repository.
"""

from __future__ import annotations

import pytest

from opentine import Run, RunStatus, StepKind, _artifact_io
from opentine._artifact_io import assert_loadable, compact_token_budget
from opentine._blob_guard import guarded_blob_body
from opentine.kernel import KernelError, validate_json_shape
from opentine.repository import Repo
from opentine.repository._run_blobs import blob_json, put_transcript
from opentine.trace.recorder import Recorder


def _structural_tokens(body: bytes) -> int:
    """Smallest budget validate_json_shape accepts == the body's token count."""
    low, high = 0, len(body)
    while low < high:
        mid = (low + high) // 2
        try:
            validate_json_shape(body, max_tokens=mid)
            high = mid
        except KernelError:
            low = mid + 1
    return low


# --- rule: blobs must be canonical *objects*, at write as well as read -------


def test_non_dict_step_outputs_are_refused_before_anything_is_written(tmp_path):
    # add_step's hint says dict but nothing enforced it: a list output was
    # canonicalized, stored, and heads/main advanced to a run every later
    # load_run refused, with fsck green.
    repo = Repo.init(tmp_path)
    run = Run(id="listy")
    run.add_step(StepKind.tool, {"query": "list"}, ["row-a", "row-b"])
    with pytest.raises(ValueError, match="must be an object.*got list"):
        repo.put_run(run, ref="heads/main")
    check = repo.fsck()
    assert check.ok and check.objects == 0 and check.refs == 0
    assert repo.read_ref("heads/main") is None


def test_non_dict_run_attachments_are_refused_with_the_shape_named(tmp_path):
    repo = Repo.init(tmp_path)
    for field, value, shape in (
        ("cache", ["not", "a", "dict"], "list"),
        ("policies", "nope", "str"),
        ("manifest", None, "NoneType"),
    ):
        run = Run(id=f"bad-{field}")
        run.add_step(StepKind.think, {"a": 1})
        setattr(run, field, value)
        with pytest.raises(ValueError, match=f"must be an object.*got {shape}"):
            repo.put_run(run)
    check = repo.fsck()
    assert check.ok and check.objects == 0


def test_recorder_manifest_blobs_require_objects(tmp_path):
    # The trace surface shares guarded_blob_body; a non-dict manifest bricked
    # every later read of the recorded run the same way.
    repo = Repo.init(tmp_path)
    with pytest.raises(ValueError, match="must be an object.*got list"):
        Recorder.start(repo, code=["not", "a", "manifest"], capture=False)
    assert repo.read_ref("heads/main") is None


def test_blob_reader_still_requires_canonical_objects(tmp_path):
    # The write guard mirrors the reader; the reader's own rule is unchanged
    # for blobs written out-of-band.
    repo = Repo.init(tmp_path)
    oid = repo.put("blob", b'["not","an","object"]', redact=False)
    with pytest.raises(ValueError, match="must be a canonical object"):
        blob_json(repo, oid)


# --- rule: the v2 writer applies every record rule the v2 reader applies -----


def test_v2_save_applies_the_reader_record_rules(tmp_path):
    # The same class on the .tine path: Run.save persisted a list-valued step
    # output or a non-string tag verbatim, and Run.load then refused the file
    # with exactly the messages asserted here.
    listy = Run(id="listy")
    listy.add_step(StepKind.tool, {"query": "list"}, ["row-a", "row-b"])
    target = tmp_path / "listy.tine"
    with pytest.raises(ValueError, match="outputs must be an object"):
        listy.save(target)
    assert not target.exists()

    tagged = Run(id="tagged")
    tagged.add_step(StepKind.think, {"a": 1})
    tagged.tags.append(5)
    with pytest.raises(ValueError, match="tags must be a list of strings"):
        tagged.save(tmp_path / "tagged.tine")

    versioned = Run(id="versioned")
    versioned.add_step(StepKind.think, {"a": 1})
    versioned.format_version = 99
    with pytest.raises(ValueError, match="format_version"):
        versioned.save(tmp_path / "versioned.tine")


# --- rule: one structural budget, shared by blob writer and blob reader ------


def test_blob_budget_is_one_formula_imported_by_both_sides():
    import opentine._blob_guard as blob_guard
    import opentine.repository._run_blobs as run_blobs

    # Round 10 moved the reader half into _blob_guard beside the writer, because
    # the budget was not the only rule that could drift: the reader parsed
    # without the kernel's parse_int hook. Both halves now call one formula from
    # one module, which is what this test was pinning -- _run_blobs no longer
    # imports the budget at all, it delegates the whole read.
    assert run_blobs.blob_json.__globals__["guarded_blob_parse"] is blob_guard.guarded_blob_parse
    assert blob_guard.compact_token_budget is _artifact_io.compact_token_budget
    # Shares the artifact reader's floor and absolute ceiling; compact canonical
    # JSON is never denser than one structural token per byte, so bytes are the
    # density bound in between.
    assert compact_token_budget(0) == _artifact_io._MIN_STRUCTURAL_TOKENS
    assert compact_token_budget(588_900) == 588_900  # the migrate-v3 band
    assert compact_token_budget(10**9) == _artifact_io._MAX_STRUCTURAL_TOKENS


def test_blob_write_and_read_budgets_agree_exactly_at_the_bound(tmp_path, monkeypatch):
    # Round 8 pinned the writer at 200k while the reader scaled; this pins the
    # symmetry itself: at budget == tokens both sides accept, at budget ==
    # tokens - 1 both sides refuse the very same bytes.
    repo = Repo.init(tmp_path)
    value = {"rows": [[0, 1] for _ in range(1_000)]}
    body = guarded_blob_body(value)
    oid = repo.put("blob", body, redact=False)
    tokens = _structural_tokens(body)

    monkeypatch.setattr(_artifact_io, "_MIN_STRUCTURAL_TOKENS", tokens)
    monkeypatch.setattr(_artifact_io, "_MAX_STRUCTURAL_TOKENS", tokens)
    assert guarded_blob_body(value) == body
    assert blob_json(repo, oid)["rows"][0] == [0, 1]

    monkeypatch.setattr(_artifact_io, "_MIN_STRUCTURAL_TOKENS", tokens - 1)
    monkeypatch.setattr(_artifact_io, "_MAX_STRUCTURAL_TOKENS", tokens - 1)
    with pytest.raises(ValueError, match="structural limit"):
        guarded_blob_body(value)
    with pytest.raises(ValueError, match="malformed"):
        blob_json(repo, oid)


def test_healthy_v2_artifact_with_wide_tool_result_migrates_and_round_trips(tmp_path):
    # The release-gate repro: a ~590 KB structured tool result (50k small
    # objects, ~200k structural tokens) saves, loads and verifies as .tine but
    # was refused by put_run/migrate-v3 under the fixed 200k write cap.
    run = Run(id="wide", model_info="m")
    run.add_step(StepKind.tool, {"q": "scan"}, {"rows": [{"i": i} for i in range(50_000)]})
    run.status = RunStatus.completed
    artifact = run.save(tmp_path / "wide.tine")
    assert Run.verify_integrity(artifact).ok

    repo = Repo.init(tmp_path / "repo")
    result = repo.migrate_v2(artifact, ref="heads/main")
    loaded = repo.load_run(result.run_id)
    assert len(loaded.steps[0].outputs["rows"]) == 50_000
    assert repo.fsck().ok


# --- rule: the reader's 256 MiB byte bound applies at save --------------------


def test_oversized_artifact_is_refused_at_save_not_after(tmp_path, monkeypatch):
    # assert_loadable never applied MAX_TINE_ARTIFACT_BYTES, which
    # read_artifact_bytes enforces twice: an oversized run saved cleanly and
    # then no load/verify/migrate would touch it. Scaled stand-in for the
    # 256 MiB bound (the readers pick the constant up at call time too).
    monkeypatch.setattr(_artifact_io, "MAX_TINE_ARTIFACT_BYTES", 200_000)
    target = tmp_path / "checkpoint.tine"
    run = Run(id="big")
    run.add_step(StepKind.think, {"a": 1})
    run.save(target)
    checkpoint = target.read_bytes()

    run.add_step(StepKind.tool, {"q": "read"}, {"stdout": "x" * 250_000})
    with pytest.raises(ValueError, match="size limit"):
        run.save(target)
    # the refusal precedes the write, so the previous checkpoint survives
    assert target.read_bytes() == checkpoint
    assert len(Run.load(target).steps) == 1


def test_size_gate_counts_platform_newline_growth(tmp_path, monkeypatch):
    # atomic_write_text writes text-mode, so every newline becomes os.linesep;
    # a file that fits by len(encoded) on Linux can exceed the reader's stat
    # bound on Windows. The gate must budget the translated size.
    run = Run(id="nl")
    run.add_step(StepKind.think, {"a": 1})
    probe = run.save(tmp_path / "probe.tine")
    text = probe.read_text()
    assert "\n" in text

    monkeypatch.setattr(_artifact_io, "MAX_TINE_ARTIFACT_BYTES", len(text.encode()))
    assert_loadable(text)  # exactly at the limit where linesep == "\n"
    monkeypatch.setattr(_artifact_io.os, "linesep", "\r\n")
    with pytest.raises(ValueError, match="size limit"):
        assert_loadable(text)


# --- rule: what loads can be written — transcript turns ----------------------


def test_tolerated_transcript_turns_survive_the_v3_round_trip(tmp_path):
    # Round 8 taught Run.load and Run.fork to tolerate non-dict transcript
    # items, but put_transcript still refused them, so the run that loaded and
    # forked could not enter a v3 repository (migrate-v3 exit 1).
    run = Run(id="transcripty")
    run.add_step(StepKind.think, {"a": 1})
    run.transcript.append("a bare string turn")
    artifact = run.save(tmp_path / "tr.tine")

    repo = Repo.init(tmp_path / "repo")
    result = repo.migrate_v2(artifact)
    assert "a bare string turn" in repo.load_run(result.run_id).transcript

    direct = repo.put_run(run)
    assert "a bare string turn" in repo.load_run(direct.run_id).transcript

    # dict turns keep their step-id discipline
    with pytest.raises(ValueError, match="unknown step"):
        put_transcript(repo, [{"step_id": "nope"}], {})
