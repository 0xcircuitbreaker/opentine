"""Round-9 audit regressions, group pricing: fork must tolerate what load tolerates.

``validate_run_record`` does not constrain ``manifest.pricing``, yet
``_slice_pricing`` probed set membership with raw manifest values at four
sites: ``step_id in retained``, the referenced-catalog set build, the
catalogs membership test, and ``status in {...}``. A list or dict in any of
the five unconstrained field positions (``invocations[*].step_id``,
``invocations[*].catalog_id``, ``invocations[*].catalog_hash``,
``catalogs[*].catalog_id``, ``catalogs[*].catalog_hash``) — or in
``invocations[*].status``, the fourth crash site — loaded, showed, verified
and costed cleanly, then crashed ``run.fork``, ``tine fork``,
``tine replay --mode cache``, MCP ``fork_run_file`` and v3 ``repo.fork``
with a raw ``TypeError: unhashable type``.
"""

from __future__ import annotations

import sys

import pytest

from opentine import Run, StepKind, cli
from opentine.mcp_server import fork_run_file
from opentine.repository import Repo

# Builders keyed by malformed field position; each receives the real step id.
MALFORMED_PRICING = {
    "invocation-step-id-list": lambda step: {
        "invocations": [{"step_id": ["oops"], "status": "complete"}],
    },
    "invocation-step-id-dict": lambda step: {
        "invocations": [{"step_id": {"oops": 1}, "status": "complete"}],
    },
    "invocation-catalog-id-list": lambda step: {
        "invocations": [{"step_id": step, "catalog_id": ["oops"], "status": "complete"}],
    },
    "invocation-catalog-hash-dict": lambda step: {
        "invocations": [{"step_id": step, "catalog_hash": {"oops": 1}, "status": "complete"}],
    },
    "catalogs-entry-catalog-id-list": lambda step: {
        "invocations": [{"step_id": step, "catalog_id": "cid", "status": "complete"}],
        "catalogs": [{"catalog_id": ["oops"], "catalog_hash": None}],
    },
    "catalogs-entry-catalog-hash-dict": lambda step: {
        "invocations": [{"step_id": step, "catalog_id": "cid", "status": "complete"}],
        "catalogs": [{"catalog_id": "cid", "catalog_hash": {"oops": 1}}],
    },
    # The fourth crash site: status probed against a set literal.
    "invocation-status-list": lambda step: {
        "invocations": [{"step_id": step, "status": ["complete"]}],
    },
}


def _priced_run(run_id: str, build_pricing) -> Run:
    run = Run(id=run_id, model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    run.manifest["pricing"] = build_pricing(run.steps[0].id)
    return run


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


@pytest.mark.parametrize("shape", sorted(MALFORMED_PRICING))
def test_fork_and_cached_replay_survive_unhashable_pricing_values(shape, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    source = tmp_path / f"{shape}.tine"
    run = _priced_run(f"run-{shape}", MALFORMED_PRICING[shape])
    run.save(source)

    loaded = Run.load(source)
    forked = loaded.fork(loaded.steps[0].id)
    assert forked.metadata["forked_from"] == run.id

    fork_out = tmp_path / f"{shape}-fork.tine"
    replay_out = tmp_path / f"{shape}-replay.tine"
    _invoke(monkeypatch, "fork", str(source), "--from-step", "0", "--save", str(fork_out))
    _invoke(monkeypatch, "replay", str(source), "--mode", "cache", "--save", str(replay_out))
    assert Run.load(fork_out).metadata["forked_from"] == run.id
    assert Run.load(replay_out).metadata["replay"]["source_run"] == run.id


@pytest.mark.parametrize("shape", sorted(MALFORMED_PRICING))
def test_mcp_fork_run_survives_unhashable_pricing_values(shape, tmp_path):
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    run_id = f"mcp-{shape}"
    _priced_run(run_id, MALFORMED_PRICING[shape]).save(runs_dir / f"{run_id}.tine")

    result = fork_run_file(run_id, 0, runs_dir=runs_dir)
    assert result["forked_from"] == run_id
    assert Run.load(result["path"]).status.value == "running"


@pytest.mark.parametrize(
    "shape",
    [
        "invocation-catalog-id-list",
        "invocation-catalog-hash-dict",
        "catalogs-entry-catalog-id-list",
        "catalogs-entry-catalog-hash-dict",
        "invocation-status-list",
    ],
)
def test_v3_repo_fork_survives_unhashable_pricing_values(shape, tmp_path):
    # put_run_manifest already rejects non-str step_id with a clean ValueError;
    # every other malformed position reaches _slice_pricing via run_origin and
    # fork_payload, where it used to raise TypeError deep inside the slice.
    repo = Repo.init(tmp_path)
    run = _priced_run(f"repo-{shape}", MALFORMED_PRICING[shape])
    stored = repo.put_run(run, ref="heads/main")

    forked = repo.fork(stored.run_id, stored.event_map[run.steps[0].id])
    assert repo.get(forked).payload()["forked_from"] == stored.run_id
    assert repo.fsck().ok


def test_v3_repo_put_run_still_rejects_non_string_step_references(tmp_path):
    repo = Repo.init(tmp_path)
    run = _priced_run("repo-step-id-list", MALFORMED_PRICING["invocation-step-id-list"])
    with pytest.raises(ValueError, match="step references must be strings"):
        repo.put_run(run, ref="heads/main")


def test_malformed_values_degrade_the_lookup_not_the_data(tmp_path):
    # A malformed step_id can never match a retained step, so its invocation
    # is sliced away; a malformed status is simply not complete; a catalogs
    # entry with a malformed key matches no referenced snapshot; and valid
    # siblings keep working (snapshot retained, provenance propagated).
    run = Run(id="mixed", model_info="m")
    run.add_step(StepKind.done, {"text": "d"})
    step = run.steps[0].id
    run.manifest["pricing"] = {
        "invocations": [
            {"step_id": ["oops"], "catalog_id": "cid", "status": "complete"},
            {"step_id": step, "catalog_id": "cid", "catalog_hash": "h", "status": ["nope"]},
        ],
        "catalogs": [
            {"catalog_id": ["oops"], "catalog_hash": "h", "catalog_provenance": ["bad"]},
            {"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["good"]},
        ],
    }
    path = tmp_path / "mixed.tine"
    run.save(path)

    loaded = Run.load(path)
    pricing = loaded.fork(step).manifest["pricing"]
    assert [item["step_id"] for item in pricing["invocations"]] == [step]
    assert pricing["complete"] is False
    assert pricing["catalogs"] == [
        {"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["good"]}
    ]
    assert pricing["catalog_provenance"] == ["good"]
    # The malformed invocation values that survive slicing are preserved as-is.
    assert pricing["catalog_id"] == "cid"
    assert pricing["catalog_hash"] == "h"


def test_fork_still_slices_well_formed_pricing(tmp_path):
    # Behavior guard: valid manifests keep the exact pre-fix slicing semantics.
    run = Run(id="healthy", model_info="m")
    first = run.add_step(StepKind.think, {"text": "a"})
    second = run.add_step(StepKind.done, {"text": "b"})
    run.manifest["pricing"] = {
        "invocations": [
            {"step_id": first.id, "catalog_id": "cid", "catalog_hash": "h", "status": "complete"},
            {"step_id": second.id, "catalog_id": "cid", "catalog_hash": "h", "status": "pending"},
        ],
        "catalogs": [{"catalog_id": "cid", "catalog_hash": "h", "catalog_provenance": ["ok"]}],
        "rate_cards": {first.id: "rc1", second.id: "rc2"},
    }
    path = tmp_path / "healthy.tine"
    run.save(path)

    loaded = Run.load(path)
    pricing = loaded.fork(first.id).manifest["pricing"]
    assert [item["step_id"] for item in pricing["invocations"]] == [first.id]
    assert pricing["complete"] is True
    assert pricing["rate_cards"] == {first.id: "rc1"}
    assert pricing["catalog_id"] == "cid"
    assert pricing["catalog_hash"] == "h"
    assert pricing["catalog_provenance"] == ["ok"]
