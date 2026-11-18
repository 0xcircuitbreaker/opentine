"""0.54 CI plan: full matrix on main, slim matrix on pull requests, sharded Windows."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _plan():
    spec = importlib.util.spec_from_file_location("ci_plan", ROOT / "scripts" / "ci_plan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cells(event, changed=None):
    return json.loads(_plan().plan(event, changed)["matrix"])["include"]


def test_main_nightly_and_dispatch_runs_get_the_full_3_by_4_matrix():
    for event in ("push", "schedule", "workflow_dispatch"):
        cells = _cells(event)
        pairs = {(c["os"], c["python-version"]) for c in cells}
        assert len(pairs) == 12, event
        assert _plan().plan(event, ["docs/README.md"])["python"] == "true"


def test_every_windows_cell_is_sharded_and_the_shards_cover_it_once():
    plan = _plan()
    for event in ("push", "pull_request"):
        windows = [c for c in _cells(event) if c["os"] == "windows-latest"]
        assert windows
        for python in {c["python-version"] for c in windows}:
            shards = sorted(c["shard"] for c in windows if c["python-version"] == python)
            assert shards == list(range(1, plan.WINDOWS_SHARDS + 1))
            assert plan.WINDOWS_SHARDS > 1
        others = [c for c in _cells(event) if c["os"] != "windows-latest"]
        assert all(c["shards"] == 1 and c["shard"] == 1 for c in others)


def test_a_pull_request_gets_the_slim_matrix():
    pairs = {(c["os"], c["python-version"]) for c in _cells("pull_request", ["opentine/x.py"])}
    assert pairs == set(_plan().PR_CELLS)
    assert {os for os, _ in pairs} == {"ubuntu-latest", "windows-latest", "macos-latest"}


def test_docs_only_pull_requests_skip_the_matrix_and_ts_only_ones_run_one_cell():
    plan = _plan()
    assert plan.plan("pull_request", ["docs/CI-RUNNERS.md", "README.md"])["python"] == "false"
    ts = plan.plan("pull_request", ["ts/verifier/src/codec.ts", "docs/SPEC.md"])
    assert ts["python"] == "true"
    assert [(c["os"], c["python-version"]) for c in json.loads(ts["matrix"])["include"]] == [
        ("ubuntu-latest", "3.14")
    ]
    for code in (["opentine/cli.py"], ["docs/schemas/x.json"], ["tests/notes.md"], []):
        assert plan.plan("pull_request", code)["python"] == "true", code
        assert len(json.loads(plan.plan("pull_request", code)["matrix"])["include"]) > 1


def test_an_unreadable_changed_file_list_plans_everything(tmp_path):
    plan = _plan()
    assert plan.read_changed(str(tmp_path / "missing.txt")) is None
    assert plan.plan("pull_request", plan.read_changed(None))["python"] == "true"


def test_the_plan_writes_github_output(tmp_path, monkeypatch):
    out = tmp_path / "out.txt"
    changed = tmp_path / "changed.txt"
    changed.write_text("docs/A.md\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert _plan().main(["--event", "pull_request", "--changed", str(changed)]) == 0
    assert "python=false\n" in out.read_text("utf-8")


def test_ci_hoists_the_once_only_checks_into_prep_and_the_matrix_needs_it():
    jobs = yaml.safe_load(CI.read_text("utf-8"))["jobs"]
    prep = "\n".join(str(step.get("run", "")) for step in jobs["prep"]["steps"])
    for needle in (
        "ruff check",
        "ruff format --check",
        "check_architecture.py",
        "check_copy.py",
        "uv build",
        "check_release_inventory.py",
        "twine check",
        "wheel_smoke.py",
    ):
        assert needle in prep, needle
    test = jobs["test"]
    assert set(test["needs"]) == {"prep", "plan"}
    runs = "\n".join(str(step.get("run", "")) for step in test["steps"])
    assert "ruff" not in runs and "uv build" not in runs
    assert "-n auto --dist loadgroup" in runs and "-p no:xdist" in runs
    assert re.search(r"--splits \"\$SHARDS\" --group \"\$SHARD\"", runs)
    assert "check_release_inventory.py" in str(jobs["package-os"]["steps"])
    aggregate = jobs["python-tests"]
    assert aggregate["if"] == "always()" and "test" in aggregate["needs"]


def test_the_durations_file_covers_the_suite_and_the_serial_marker_is_registered():
    durations = json.loads((ROOT / "tests" / "test_durations.json").read_text("utf-8"))
    assert len(durations) > 1000
    assert all(isinstance(v, (int, float)) and v >= 0 for v in durations.values())
    pyproject = (ROOT / "pyproject.toml").read_text("utf-8")
    assert '"serial: ' in pyproject and "pytest-xdist" in pyproject and "pytest-split" in pyproject


def test_the_durations_file_holds_no_credential_shaped_test_ids():
    spec = importlib.util.spec_from_file_location("scrub", ROOT / "scripts" / "scrub_durations.py")
    scrub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scrub)
    data = json.loads((ROOT / "tests" / "test_durations.json").read_text("utf-8"))
    assert data and not [k for k in data if scrub.credential_shaped(k)]
