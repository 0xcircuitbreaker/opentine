"""Round-10 audit regressions, group pricing: guard the pricing *containers*.

Round 9 (f203121) taught ``_slice_pricing`` not to trust the manifest *values*
it probes for membership, but the containers it iterates stayed unchecked:
``for item in pricing.get("invocations") or []`` rescues only falsey shapes, so
any truthy non-iterable (``5``, ``1.5``, ``True``) raised
``TypeError: '<type>' object is not iterable`` at the first statement of the
function. ``validate_run_record`` does not constrain ``manifest.pricing``, so
such an artifact loads, shows, verifies, costs and diffs cleanly and then
crashes ``run.fork()``, ``tine fork``, ``tine replay --mode cache`` and MCP
``fork_run_file`` with a raw traceback and rc=1.

The container now degrades the way its already-guarded siblings do: a shape
``_slice_pricing`` cannot filter is preserved exactly as loaded, and no
invocation-derived field is rewritten from it — deriving ``complete`` from an
unreadable container would launder a ``complete: false`` manifest into
``complete: true`` across a fork and silence the strict_cost refusal on the
child run.
"""

from __future__ import annotations

import json
import sys

import pytest

from opentine import Run, StepKind, cli
from opentine.mcp_server import fork_run_file
from opentine.repository import Repo

# Shapes that used to abort every fork entry point with a raw TypeError.
NON_ITERABLE = {"int": 5, "float": 1.5, "true": True}
# Shapes that survived by being silently replaced with [] (data destroyed).
EMPTIED = {"str": "abc", "dict": {"a": 1}, "none": None, "zero": 0, "emptystr": ""}
UNREADABLE = {**NON_ITERABLE, **EMPTIED}


def _priced_run(run_id: str, invocations: object) -> Run:
    run = Run(id=run_id, model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = {
        "complete": False,
        "catalog_id": "cid",
        "catalog_hash": "h",
        "catalog_provenance": ["p"],
        "invocations": invocations,
        "rate_cards": {run.steps[0].id: "rc", "dropped-step": "rc2"},
        "catalogs": [{"catalog_id": "cid", "catalog_hash": "h"}],
    }
    return run


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


@pytest.mark.parametrize("shape", sorted(UNREADABLE))
def test_fork_and_cached_replay_survive_a_non_list_invocations_container(
    shape, monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    value = UNREADABLE[shape]
    source = tmp_path / f"{shape}.tine"
    run = _priced_run(f"run-{shape}", value)
    run.save(source)

    loaded = Run.load(source)
    assert loaded.manifest["pricing"]["invocations"] == value
    forked = loaded.fork(loaded.steps[0].id)
    assert forked.metadata["forked_from"] == run.id

    fork_out = tmp_path / f"{shape}-fork.tine"
    replay_out = tmp_path / f"{shape}-replay.tine"
    _invoke(monkeypatch, "fork", str(source), "--from-step", "0", "--save", str(fork_out))
    _invoke(monkeypatch, "replay", str(source), "--mode", "cache", "--save", str(replay_out))
    assert Run.load(fork_out).metadata["forked_from"] == run.id
    assert Run.load(replay_out).metadata["replay"]["source_run"] == run.id
    # The child artifact is a valid, verifiable artifact of its own.
    assert Run.verify_integrity(fork_out).ok
    assert Run.load(fork_out).cost_breakdown().total_cost == 0.0


@pytest.mark.parametrize("shape", sorted(UNREADABLE))
def test_mcp_fork_run_survives_a_non_list_invocations_container(shape, tmp_path):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    run_id = f"mcp-{shape}"
    _priced_run(run_id, UNREADABLE[shape]).save(runs_dir / f"{run_id}.tine")

    result = fork_run_file(run_id, 0, runs_dir=runs_dir)
    assert result["forked_from"] == run_id
    assert Run.load(result["path"]).status.value == "running"


@pytest.mark.parametrize("shape", sorted(UNREADABLE))
def test_unreadable_container_is_preserved_and_derives_nothing(shape, tmp_path):
    value = UNREADABLE[shape]
    run = _priced_run(f"keep-{shape}", value)
    step = run.steps[0].id
    path = tmp_path / f"{shape}.tine"
    run.save(path)

    pricing = Run.load(path).fork(step).manifest["pricing"]
    # Preserved verbatim, exactly like the guarded rate_cards/catalogs siblings.
    assert pricing["invocations"] == value
    # No claim is derived from a container this function cannot read.
    assert pricing["complete"] is False
    assert pricing["catalog_id"] == "cid"
    assert pricing["catalog_hash"] == "h"
    assert pricing["catalog_provenance"] == ["p"]
    assert pricing["catalogs"] == [{"catalog_id": "cid", "catalog_hash": "h"}]
    # rate_cards is keyed by step id, so it is still sliced to retained steps.
    assert pricing["rate_cards"] == {step: "rc"}


@pytest.mark.parametrize("shape", sorted(UNREADABLE))
def test_unreadable_container_cannot_launder_incomplete_pricing(shape, tmp_path):
    # Before the fix a str/dict/None container was replaced with [], and
    # all([]) is True: forking upgraded "complete": false to true on data the
    # slicer never read. strict_cost budgets refuse only on an explicit False.
    run = _priced_run(f"launder-{shape}", UNREADABLE[shape])
    path = tmp_path / f"{shape}.tine"
    run.save(path)

    forked = Run.load(path).fork(run.steps[0].id)
    assert forked.manifest["pricing"].get("complete") is False


def test_empty_invocations_list_still_derives_completeness(tmp_path):
    # Contrast: an empty *list* is readable evidence that nothing is pending,
    # so the pre-existing derivation is kept for it.
    run = Run(id="empty-list", model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = {"complete": False, "invocations": []}
    path = tmp_path / "empty.tine"
    run.save(path)

    pricing = Run.load(path).fork(run.steps[0].id).manifest["pricing"]
    assert pricing == {"complete": True, "invocations": []}


@pytest.mark.parametrize("invocations", [{}, {"invocations": None}], ids=["absent", "null"])
def test_rate_cards_are_sliced_even_without_a_readable_invocations_key(invocations, tmp_path):
    # rate_cards is keyed by step id and is independent of invocations, so it
    # must be sliced whatever invocations turns out to be. Gating the whole
    # function on ``"invocations" in pricing`` left a dropped step's card in the
    # child, and the repository then refuses that child. Two manifests that mean
    # the same thing -- {"rate_cards": X} and the same plus "invocations": null
    # -- forked to different results, and only one of the two was storable.
    run = Run(id=f"cards-{len(invocations)}", model_info="m")
    kept = run.add_step(StepKind.think, {"text": "a"}).id
    dropped = run.add_step(StepKind.done, {"text": "b"}).id
    run.manifest["pricing"] = {"rate_cards": {kept: "rc1", dropped: "rc2"}, **invocations}
    path = tmp_path / "cards.tine"
    run.save(path)

    forked = Run.load(path).fork(kept)
    assert forked.manifest["pricing"]["rate_cards"] == {kept: "rc1"}
    child = tmp_path / "cards-child.tine"
    forked.save(child)
    # The child is storable: no pricing entry references a step it dropped.
    repo = Repo.init(tmp_path / "repo")
    assert repo.put_run(Run.load(child)).run_id
    assert repo.fsck().ok


def test_fork_still_slices_well_formed_pricing_after_the_container_guard(tmp_path):
    # Behavior guard: the list path keeps the exact pre-round-10 semantics.
    run = Run(id="healthy", model_info="m")
    first = run.add_step(StepKind.think, {"text": "a"})
    second = run.add_step(StepKind.done, {"text": "b"})
    run.manifest["pricing"] = {
        "complete": False,
        "invocations": [
            {"step_id": first.id, "catalog_id": "cid", "catalog_hash": "h", "status": "complete"},
            {"step_id": second.id, "catalog_id": "old", "catalog_hash": "h0", "status": "partial"},
        ],
        "catalogs": [
            {"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["ok"]},
            {"catalog_id": "old", "catalog_hash": "h0"},
        ],
        "rate_cards": {first.id: "rc1", second.id: "rc2"},
    }
    path = tmp_path / "healthy.tine"
    run.save(path)

    pricing = Run.load(path).fork(first.id).manifest["pricing"]
    assert [item["step_id"] for item in pricing["invocations"]] == [first.id]
    assert pricing["complete"] is True
    assert pricing["rate_cards"] == {first.id: "rc1"}
    assert pricing["catalogs"] == [
        {"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["ok"]}
    ]
    assert pricing["catalog_id"] == "cid"
    assert pricing["catalog_hash"] == "h"
    assert pricing["catalog_provenance"] == ["ok"]


# Every container position in the pricing tree, crossed with every JSON shape:
# the class this round is closing is "guard added one level too shallow", so the
# sweep asserts containers and items together instead of one repro shape.
CONTAINER_PATHS = ("pricing", "invocations", "rate_cards", "catalogs")
SHAPES = (5, 1.5, True, False, "s", None, [1], {"k": 1}, [], {}, 0, "")


@pytest.mark.parametrize("path_name", CONTAINER_PATHS)
@pytest.mark.parametrize("shape", SHAPES, ids=lambda value: f"{type(value).__name__}-{value!r}")
def test_no_pricing_container_shape_can_crash_fork(path_name, shape, tmp_path):
    run = _priced_run("sweep", [{"step_id": "unmatched", "status": "complete"}])
    if path_name == "pricing":
        run.manifest["pricing"] = shape
    else:
        run.manifest["pricing"][path_name] = shape
    before = json.dumps(run.manifest["pricing"], sort_keys=True, default=str)
    artifact = tmp_path / "sweep.tine"
    run.save(artifact)

    loaded = Run.load(artifact)
    forked = loaded.fork(loaded.steps[0].id)
    # The source object is never mutated by slicing its copy.
    assert json.dumps(loaded.manifest["pricing"], sort_keys=True, default=str) == before
    assert forked.metadata["fork_point"] == loaded.steps[0].id
