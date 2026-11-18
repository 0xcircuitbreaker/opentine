"""0.54 runner policy: no job a pull request can reach may land on a self-hosted runner.

Every workflow under .github/workflows is parsed; every job's ``runs-on`` is
evaluated (tests/_gha_expr.py) for every pull-request event the workflow listens
to, with the home-runner switch on and off and every matrix OS. Each resolved
label must be a GitHub-hosted one. Home runners are opt-in: with the repository
variable USE_HOME_RUNNERS unset, every job of every event resolves hosted too.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path

import pytest
import yaml

from tests import _gha_expr

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
HOSTED = re.compile(r"(ubuntu|windows|macos)-(latest|\d+(\.\d+)?)(-arm)?")
HOME = "opentine-home"
PR_EVENTS = ("pull_request", "pull_request_target")
HOSTED_OSES = ("ubuntu-latest", "windows-latest", "macos-latest")


def _workflows() -> dict[str, dict]:
    return {p.name: yaml.safe_load(p.read_text("utf-8")) for p in sorted(WORKFLOWS.glob("*.yml"))}


def _events(workflow: dict) -> set[str]:
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    return set(on if isinstance(on, (list, dict)) else [])


def _matrix_oses(job: dict) -> tuple[str, ...]:
    matrix = (job.get("strategy") or {}).get("matrix")
    if isinstance(matrix, dict) and isinstance(matrix.get("os"), list):
        extra = [row["os"] for row in matrix.get("include", []) if "os" in row]
        return tuple(matrix["os"]) + tuple(extra)
    return HOSTED_OSES  # dynamic matrix (fromJSON): the plan only emits hosted OSes


def _context(event: str, ref: str, switch: str, os_name: str) -> dict:
    return {
        "github.event_name": event,
        "github.ref": ref,
        "github.repository": "owner/opentine",
        "github.event.pull_request.head.repo.full_name": "fork/opentine",
        "github.event.pull_request.head.repo.fork": True,
        "vars.USE_HOME_RUNNERS": switch,
        "matrix.os": os_name,
    }


def _labels(runs_on, context) -> list[str]:
    if isinstance(runs_on, dict):  # {group: ..., labels: ...}
        assert "group" not in runs_on, "runner groups are self-hosted"
        runs_on = runs_on.get("labels")
    values = runs_on if isinstance(runs_on, list) else [runs_on]
    out: list[str] = []
    for value in values:
        resolved = _gha_expr.resolve(str(value), context)
        out.extend(resolved if isinstance(resolved, list) else [str(resolved)])
    return out


def _resolutions(job: dict, events, refs, switches):
    for event, ref, switch, os_name in itertools.product(events, refs, switches, _matrix_oses(job)):
        yield (
            (event, ref, switch, os_name),
            _labels(job["runs-on"], _context(event, ref, switch, os_name)),
        )


def _jobs():
    for name, workflow in _workflows().items():
        for job_id, job in (workflow.get("jobs") or {}).items():
            yield name, workflow, job_id, job


def test_no_job_reachable_from_a_pull_request_can_resolve_to_a_self_hosted_runner():
    checked = 0
    for name, workflow, job_id, job in _jobs():
        events = _events(workflow) & set(PR_EVENTS)
        if not events:
            continue
        assert "runs-on" in job, f"{name}:{job_id} calls a reusable workflow; check it here"
        refs = ("refs/pull/1/merge", "refs/heads/main")
        for case, labels in _resolutions(job, sorted(events), refs, ("true", "", "false")):
            bad = [label for label in labels if not HOSTED.fullmatch(label)]
            assert not bad, f"{name}:{job_id} resolves to {bad} for {case}"
            checked += 1
    assert checked > 50


def test_home_runners_are_off_unless_the_switch_is_the_string_true():
    for name, workflow, job_id, job in _jobs():
        if "runs-on" not in job:
            continue
        events = sorted(_events(workflow) | {"push", "workflow_dispatch", "schedule"})
        for case, labels in _resolutions(job, events, ("refs/heads/main",), ("", "false", "1")):
            assert all(HOSTED.fullmatch(label) for label in labels), (name, job_id, case)


def test_home_runners_serve_only_push_to_main_and_workflow_dispatch():
    homed = set()
    for name, _workflow, job_id, job in _jobs():
        if "runs-on" not in job:
            continue
        refs = ("refs/heads/main", "refs/heads/feature")
        events = ("push", "workflow_dispatch", "schedule", "pull_request")
        for (event, ref, _s, _os), labels in _resolutions(job, events, refs, ("true",)):
            if HOME in labels:
                homed.add((name, job_id))
                assert event == "workflow_dispatch" or (event, ref) == (
                    "push",
                    "refs/heads/main",
                ), (name, job_id, event, ref)
            else:
                assert all(HOSTED.fullmatch(label) for label in labels), (name, job_id, labels)
    assert ("ci.yml", "test") in homed and ("ci.yml", "prep") in homed


@pytest.mark.parametrize("workflow", ["publish.yml", "bench.yml", "codeql.yml", "scorecard.yml"])
def test_release_bench_and_scanning_workflows_never_use_home_runners(workflow):
    text = (WORKFLOWS / workflow).read_text("utf-8")
    assert HOME not in text and "self-hosted" not in text and "USE_HOME_RUNNERS" not in text


def test_the_bench_gate_stays_on_hosted_ubuntu_24_04():
    bench = _workflows()["bench.yml"]["jobs"]["bench"]
    assert bench["runs-on"] == "ubuntu-24.04"


def test_the_policy_check_catches_an_unguarded_expression():
    job = {
        "runs-on": "${{ vars.USE_HOME_RUNNERS == 'true' && 'opentine-home' || 'ubuntu-latest' }}"
    }
    labels = [
        lab for _c, lab in _resolutions(job, ["pull_request"], ["refs/pull/1/merge"], ["true"])
    ]
    assert ["opentine-home"] in labels
    with pytest.raises(ValueError):
        _gha_expr.evaluate("contains(github.ref, 'main')", {"github.ref": "x"})
