"""0.51: the standing 1.0 gates produce evidence per commit.

The compression bench runs on every push to main, the nightly streak honours
committed flake waivers, the gate jobs run on every push to main, and
``scripts/check_release_gates.py`` reads them for one SHA. Every check here is
offline: the API answers come from recorded responses.
"""

from __future__ import annotations

import importlib.util
import json
import re
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA = "0123456789abcdef0123456789abcdef01234567"
REPO = "o/r"


def _script(name: str):
    spec = importlib.util.spec_from_file_location(f"_s051_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jobs(name: str) -> dict[str, str]:
    text = (WORKFLOWS / name).read_text("utf-8").split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", text, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def _on(name: str) -> str:
    return (WORKFLOWS / name).read_text("utf-8").split("\non:\n", 1)[1].split("\n\n", 1)[0]


# --- workflows ----------------------------------------------------------------- #


def test_the_bench_gate_runs_on_every_push_to_main_pinned_and_keeps_its_report():
    on = _on("bench.yml")
    assert re.search(r"^  push:\n    branches: \[main\]\n", on, re.M), on
    assert "schedule:" in on and "pull_request:" in on
    text = (WORKFLOWS / "bench.yml").read_text("utf-8")
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in text
    bench = _jobs("bench.yml")["bench"]
    assert "runs-on: ubuntu-24.04" in bench and 'OMP_NUM_THREADS: "1"' in bench
    assert "timeout-minutes:" in bench and "ref: v0.40.0" in bench
    assert "scripts/bench/gate.py --base bench-040.json" in bench and "bench-gate.md" in bench
    assert "actions/upload-artifact" in bench and "if: always()" in bench
    # A push run compares with 0.40 only (main against itself would be noise).
    assert "github.event_name == 'pull_request' || inputs.compare == true" in bench


def test_the_gate_jobs_run_on_every_push_to_main_and_audit_kit_drops_the_network():
    on = _on("ci.yml")
    assert re.search(r"^  push:\n    branches: \[main\]$", on, re.M), on
    jobs = _jobs("ci.yml")
    gates = _script("check_release_gates").JOB_GATES
    for job in ("parity", "peer-compat-034", "leave-service", "audit-kit"):
        body = jobs[job]
        assert not re.search(r"^    if:", body, re.M), job  # never skipped on push
        assert re.search(r"^    timeout-minutes: \d+", body, re.M), job
    for name, (workflow, prefix) in gates.items():
        names = re.findall(r"^    name: (.+)$", "".join(_jobs(workflow).values()), re.M)
        assert any(n.startswith(prefix) for n in names), name
    kit = jobs["audit-kit"]
    assert "ubuntu-latest" in kit
    assert re.search(r"if: runner.os == 'Linux'\n\s+run: sudo unshare --net -- ", kit)


def test_the_nightly_summary_records_the_streak_with_read_only_permissions():
    summary = _jobs("nightly-stress.yml")["summary"]
    assert "actions: read" in summary and "contents: read" in summary
    assert "write" not in summary.split("permissions:", 1)[1].split("steps:", 1)[0]
    assert "scripts/stress_streak.py" in summary and "nightly-streak.json" in summary


# --- waivers ------------------------------------------------------------------- #


def _run(day: str, conclusion: str = "success") -> dict:
    stamp = f"{day}T03:20:00Z"
    return {"event": "schedule", "status": "completed", "conclusion": conclusion,
            "created_at": stamp, "run_started_at": stamp, "html_url": f"u/{day}",
            "head_sha": SHA}  # fmt: skip


def _waiver(**over) -> dict:
    rec = {"night": "2026-11-05", "recorded": "2026-11-06", "owner": "CircuitBreaker",
           "cause": "macOS runner image lost its disk",
           "evidence": "https://example.invalid/1"}  # fmt: skip
    rec.update(over)
    return rec


def test_a_waived_infrastructure_night_bridges_but_does_not_count():
    mod = _script("stress_streak")
    runs = [_run(f"2026-11-{d:02d}", "failure" if d == 5 else "success") for d in range(1, 10)]
    assert mod.streak(runs)["streak"] == 4
    waivers = mod.load_waivers({"waivers": [_waiver()]})
    got = mod.streak(runs, date(2026, 11, 9), waivers)
    assert got["streak"] == 8 and got["waived"] == ["2026-11-05"] and got["since"] == "2026-11-01"
    missing = [r for r in runs if not r["created_at"].startswith("2026-11-05")]
    assert mod.streak(missing, None, waivers)["streak"] == 8  # a waived missing night too


@pytest.mark.parametrize(
    "bad",
    [
        {"recorded": ""},  # undated
        {"owner": " "},  # unowned
        {"cause": None},  # no proven cause
        {"evidence": ""},
        {"recorded": "2026-11-04"},  # waived before the night happened
        {"night": "not-a-date"},
    ],
)
def test_undated_unowned_or_unproven_waivers_are_refused(bad, tmp_path, capsys):
    mod = _script("stress_streak")
    rec = _waiver(**bad)
    with pytest.raises(ValueError):
        mod.load_waivers({"waivers": [rec]})
    page, waivers = tmp_path / "runs.json", tmp_path / "w.json"
    page.write_text(json.dumps([_run("2026-11-01")]))
    waivers.write_text(json.dumps({"waivers": [rec]}))
    argv = ["--runs-file", str(page), "--waivers", str(waivers), "--today", "2026-11-01"]
    assert mod.main(argv) == 2
    assert "error" in json.loads(capsys.readouterr().out)


def test_duplicate_or_shapeless_waiver_files_are_refused():
    mod = _script("stress_streak")
    with pytest.raises(ValueError):
        mod.load_waivers({"waivers": [_waiver(), _waiver()]})
    with pytest.raises(ValueError):
        mod.load_waivers([_waiver()])


def test_the_committed_streak_and_waiver_files_are_plain_valid_data(tmp_path):
    mod = _script("stress_streak")
    waivers = json.loads((ROOT / "docs" / "bench" / "stress-waivers.json").read_text("utf-8"))
    mod.load_waivers(waivers)  # every committed waiver is dated, owned and proven
    streak = json.loads((ROOT / "docs" / "bench" / "nightly-streak.json").read_text("utf-8"))
    assert streak["workflow"] == "nightly-stress.yml" and isinstance(streak["streak"], int)
    assert "kind" not in streak and "kind" not in waivers  # data, not an object kind
    page, out = tmp_path / "runs.json", tmp_path / "streak.json"
    page.write_text(json.dumps([_run("2026-11-01")]))
    assert mod.main(["--runs-file", str(page), "--today", "2026-11-01", "--need", "1",
                     "--write", str(out)]) == 0  # fmt: skip
    assert json.loads(out.read_text("utf-8"))["streak"] == 1
    assert set(json.loads(out.read_text("utf-8"))) == set(streak)


# --- the release-gate checklist -------------------------------------------------- #


def _recorded(*, red: str | None = None, pending: str | None = None, nights: int = 30) -> dict:
    gates = _script("check_release_gates").JOB_GATES
    responses: dict = {}
    jobs_by_run: dict[int, list] = {}
    for i, (name, (workflow, prefix)) in enumerate(gates.items()):
        run_id = 100 + (0 if workflow == "ci.yml" else 1)
        runs_path = f"repos/{REPO}/actions/workflows/{workflow}/runs?head_sha={SHA}&per_page=100"
        responses[runs_path] = {"workflow_runs": [{"id": run_id, "head_sha": SHA, "run_attempt": 1,
                                                   "html_url": f"u/{run_id}"}]}  # fmt: skip
        legs = 3 if name in ("audit-kit", "leave-service") else 1
        for leg in range(legs):
            conclusion = "failure" if name == red and leg == legs - 1 else "success"
            status = "in_progress" if name == pending else "completed"
            jobs_by_run.setdefault(run_id, []).append(
                {
                    "id": i * 10 + leg,
                    "name": f"{prefix} (leg {leg})" if legs > 1 else prefix,
                    "status": status,
                    "conclusion": None if name == pending else conclusion,
                }  # fmt: skip
            )
    for run_id, jobs in jobs_by_run.items():
        responses[f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100"] = {"jobs": jobs}
    streak_path = (
        f"repos/{REPO}/actions/workflows/nightly-stress.yml/runs"
        "?event=schedule&branch=main&per_page=100"
    )
    days = [date.fromordinal(date(2026, 11, 13).toordinal() - k) for k in range(nights)]
    responses[streak_path] = {"workflow_runs": [_run(d.isoformat()) for d in days]}
    return responses


def _check(responses: dict) -> dict:
    mod = _script("check_release_gates")
    return mod.check(mod.recorded_api(responses), REPO, SHA, 30, date(2026, 11, 13))


def test_every_gate_green_for_the_commit():
    got = _check(_recorded())
    assert got["all_green"] is True
    assert set(got["gates"]) == {"parity", "peer-compat", "audit-kit", "leave-service", "bench",
                                 "nightly-streak"}  # fmt: skip
    assert got["gates"]["audit-kit"]["jobs"] == 3 and got["gates"]["nightly-streak"]["streak"] == 30


def test_a_red_leg_a_pending_job_a_missing_run_or_a_short_streak_is_not_green():
    red = _check(_recorded(red="leave-service"))
    assert not red["all_green"] and red["gates"]["leave-service"]["status"] == "red"
    assert red["gates"]["leave-service"]["failed"] == ["Leave the hosted service (leg 2)"]
    pending = _check(_recorded(pending="bench"))
    assert pending["gates"]["bench"]["status"] == "pending" and not pending["all_green"]
    short = _check(_recorded(nights=12))
    assert short["gates"]["nightly-streak"] == {"status": "red", "streak": 12, "need": 30,
                                                "waived": []}  # fmt: skip
    responses = _recorded()
    responses[f"repos/{REPO}/actions/workflows/bench.yml/runs?head_sha={SHA}&per_page=100"] = {
        "workflow_runs": []
    }
    assert _check(responses)["gates"]["bench"]["status"] == "missing"


def test_the_cli_reads_recorded_responses_and_skips_without_gh(tmp_path, capsys, monkeypatch):
    mod = _script("check_release_gates")
    saved = tmp_path / "api.json"
    saved.write_text(json.dumps(_recorded()))
    argv = [SHA, "--repo", REPO, "--recorded", str(saved), "--today", "2026-11-13"]
    assert mod.main(argv) == 0 and json.loads(capsys.readouterr().out)["all_green"]
    saved.write_text(json.dumps(_recorded(red="parity")))
    assert mod.main(argv) == 1 and not json.loads(capsys.readouterr().out)["all_green"]
    saved.write_text("{}")
    assert mod.main(argv) == 2 and "error" in json.loads(capsys.readouterr().out)
    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    assert mod.main([SHA]) == 0
    skipped = json.loads(capsys.readouterr().out)
    assert skipped["skipped"] is True and "gh" in skipped["reason"]
    assert mod.main([SHA, "--require"]) == 3


def test_releasing_documents_the_gates_and_the_waiver_policy():
    text = (ROOT / "docs" / "RELEASING.md").read_text("utf-8")
    assert "scripts/check_release_gates.py" in text and "stress-waivers.json" in text
    for needle in ("dated", "owner", "infrastructure", "refuse"):
        assert needle in text, needle
