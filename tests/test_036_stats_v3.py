"""``tine stats`` over a v3 repository counts the store, not the legacy index.

Before 0.36.0 ``stats`` read only ``.tine_runs``, so on a v3 repository it
reported zero runs (or the numbers of unrelated legacy files nearby). The
ground truth here is computed independently: run costs from the ``Run`` objects
the test wrote, object counts and bytes from ``iter_oids`` and ``raw``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine.repository import Repo


def _run(name: str, costs: list[float], model: str) -> Run:
    run = Run(id=f"v3_{name}", model_info=model, user_prompt=f"prompt {name}", created_at=1.0e9)
    parent = None
    for index, cost in enumerate(costs):
        step = run.add_step(
            StepKind.think, {"text": f"{name}-{index}"}, parent_id=parent, cost=cost
        )
        parent = step.id
    run.status = RunStatus.completed
    return run


def _invoke(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> tuple[Repo, list[Run]]:
    monkeypatch.chdir(tmp_path)
    store = Repo.init(tmp_path / "repo")
    runs = [_run("a", [0.25, 0.5], "m1"), _run("b", [1.0, 0.125, 0.0625], "m2")]
    for index, run in enumerate(runs):
        store.put_run(run, ref=f"tags/r{index}")
    # A legacy artifact beside it must not leak into the repository's numbers.
    legacy = tmp_path / ".tine_runs"
    legacy.mkdir()
    _run("legacy", [9.0], "m9").save(legacy / "legacy.tine")
    return store, runs


def _truth(store: Repo, runs: list[Run]) -> dict:
    oids = store.iter_oids()
    blobs = [oid for oid in oids if oid.startswith("blob:")]
    return {
        "runs": sum(1 for oid in oids if oid.startswith("run:")),
        "events": sum(1 for oid in oids if oid.startswith("event:")),
        "blobs": len(blobs),
        "objects": len(oids),
        "bytes": sum(len(store.raw(oid)) for oid in oids),
        "blob_bytes": sum(len(store.raw(oid)) for oid in blobs),
        "cost": sum(step.cost for run in runs for step in run.steps),
        "steps": sum(len(run.steps) for run in runs),
    }


def test_stats_repo_matches_ground_truth(repo, capsys):
    store, runs = repo
    truth = _truth(store, runs)
    code, out = _invoke(capsys, "stats", "--json", "--repo", str(store.path))
    assert code == 0, out
    payload = json.loads(out)
    assert payload["scope"] == "v3-repository"
    assert truth["runs"] == 2 and payload["totals"]["runs"] == truth["runs"]
    assert payload["totals"]["steps_total"] == truth["steps"]
    assert payload["totals"]["cost_total"] == pytest.approx(truth["cost"])
    assert payload["totals"]["models"] == ["m1", "m2"]
    for key in ("events", "blobs", "objects", "bytes", "blob_bytes"):
        assert payload["store"][key] == truth[key], key
    assert payload["unreadable"] == 0


def test_stats_inside_a_repo_counts_the_repo(repo, capsys, monkeypatch):
    store, _ = repo
    monkeypatch.chdir(store.path.parent)
    code, out = _invoke(capsys, "stats", "--json", "--group-by", "model")
    assert code == 0, out
    payload = json.loads(out)
    assert payload["totals"]["runs"] == 2
    assert [group["key"] for group in payload["groups"]] == ["m2", "m1"]


def test_legacy_dir_keeps_legacy_behaviour(repo, capsys):
    code, out = _invoke(capsys, "stats", "--json")
    assert code == 0, out
    payload = json.loads(out)
    assert payload["scope"] == "legacy-index"
    assert payload["totals"]["runs"] == 1
    assert payload["totals"]["cost_total"] == pytest.approx(9.0)


def test_legacy_only_flags_are_refused_over_a_repo(repo, capsys):
    store, _ = repo
    code, _ = _invoke(capsys, "stats", "--repo", str(store.path), "--deep")
    assert code == 1
