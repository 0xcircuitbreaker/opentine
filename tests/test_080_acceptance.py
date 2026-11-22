"""0.80 acceptance, end to end: the single entry point runs the loop and verifies its output.

The example's own ``main`` runs the stub loop with ``--verify``: every object
and signed record the run wrote is checked by the Python verifier and a freshly
built pyz (and the TS verifier when it is built). The seeded hack is caught,
recorded and never promoted; a tampered record makes the check fail; CI, the
nightly soak and the 1.0 re-evaluation are wired. Counts and recorded outcomes
only, never a duration.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _example():
    spec = importlib.util.spec_from_file_location(
        "self_improving_loop_080", ROOT / "examples" / "self_improving_loop.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    work = tmp_path_factory.mktemp("acceptance") / "run"
    code = _example().main([work.as_posix(), "--steps", "3", "--verify"])
    return work, code, json.loads((work / "report.json").read_bytes())


def test_the_entry_point_runs_and_every_produced_object_verifies(run, capsys):
    work, code, report = run
    assert code == 0
    assert len(report["steps"]) == 3
    assert report["final"]["fsck_ok"] is True
    assert (work / "repo" / ".tine" / "objects").is_dir()


def test_the_seeded_hack_is_caught_recorded_and_never_promoted(run):
    work, _code, report = run
    hack = report["steps"][1]
    assert hack["seeded"] == "reward-hack"
    assert hack["integrity"]["tainted"] is True
    assert hack["admission"]["decision"] == "deny"
    assert hack["promote"]["promoted"] is False
    state = json.loads((work / "promotion" / "state" / "prod.json").read_bytes())
    assert all(h["candidate"] != hack["run"] for h in state["history"])
    assert hack["run"] in report["final"]["curated"]["excluded"]


def test_a_tampered_record_fails_the_verification(run, capsys):
    work, _code, _report = run
    policy = work / "policy" / "budget.json"
    original = policy.read_bytes()
    try:
        policy.write_bytes(original.replace(b'"money_usd": 10.0', b'"money_usd": 99.0'))
        assert policy.read_bytes() != original
        assert _example().verify(work, require_ts=False) == 1
        assert "policy does not verify: file:budget.json" in capsys.readouterr().err
    finally:
        policy.write_bytes(original)


def test_ci_runs_the_loop_and_requires_all_three_verifiers():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  reference-loop:\n", 1)[1].split("\n  fips:\n", 1)[0]
    assert "examples/self_improving_loop.py" in job
    assert "--verify --require-ts" in job
    assert "npm run build" in job


def test_the_soak_and_the_1_0_re_evaluation_are_in_place():
    soak = (ROOT / ".github" / "workflows" / "nightly-soak.yml").read_text(encoding="utf-8")
    assert "schedule:" in soak
    roadmap = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
    section = roadmap.split("### 1.0 re-evaluation (0.80)", 1)[1]
    assert "| # | Criterion | Evidence | Status at 0.80 | Audit status |" in section
    assert "go/no-go on declaring the 1.0 track is the owner's decision" in section
    guide = (ROOT / "docs" / "REFERENCE-LOOP.md").read_text(encoding="utf-8")
    assert guide.startswith("# Running a self-improving loop with OpenTine")
