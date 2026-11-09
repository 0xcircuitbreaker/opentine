"""0.50: the nightly stress workflow, its summary and green streak, the 0.34 peer
compatibility check and the published deprecation policy (1.0 criteria 3, 5, 7).

The checks run offline: the 0.34 reader is ``git archive v0.34.0 opentine`` on
this interpreter's ``sys.path`` (CI's ``peer-compat-034`` job installs the
published wheel instead), and the streak is computed from saved API pages.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _script(name: str):
    spec = importlib.util.spec_from_file_location(f"_s_{name}", ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _jobs(name: str) -> dict[str, str]:
    """Each top-level job of a workflow -> its text (jobs are 2-space keys)."""
    text = (WORKFLOWS / name).read_text("utf-8").split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", text, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


# --- the nightly stress workflow ---------------------------------------------- #


def test_the_nightly_workflow_is_scheduled_and_runs_every_stress_suite():
    text = (WORKFLOWS / "nightly-stress.yml").read_text("utf-8")
    assert "schedule:" in text and "cron:" in text
    jobs = _jobs("nightly-stress.yml")
    assert set(jobs) == {"stress", "coord-scale", "fuzz", "summary"}
    for name, body in jobs.items():
        assert re.search(r"^    timeout-minutes: \d+", body, re.M), name
    stress = jobs["stress"]
    for needle in (
        "tests/stress",
        "tests/test_036_ref_retry.py",
        "test_047_merge_queue.py::test_kill_9_workers_never_double_merge",
        "OPENTINE_STRESS_MQ_ENTRIES",
        "OPENTINE_STRESS_PRUNE_ROUNDS",
        "--junitxml",
    ):
        assert needle in stress, needle
    assert "windows-latest" in stress and "macos-latest" in stress
    assert "scripts/coord_scale.py --tasks 1000 --workers 50" in jobs["coord-scale"]
    assert "scripts/fuzz_otlp.py --hours" in jobs["fuzz"]
    summary = jobs["summary"]
    assert "needs: [stress, coord-scale, fuzz]" in summary and "if: always()" in summary
    assert "scripts/nightly_summary.py" in summary and "name: nightly-summary" in summary


def test_every_stress_knob_the_workflow_sets_is_read_by_a_test():
    env = set(re.findall(r"(OPENTINE_STRESS_[A-Z_]+):", _jobs("nightly-stress.yml")["stress"]))
    sources = "".join(p.read_text("utf-8") for p in (ROOT / "tests").rglob("*.py"))
    assert env and all(f'"{name}"' in sources for name in env), env


def test_the_summary_is_green_only_when_every_job_and_file_is(tmp_path):
    summary = _script("nightly_summary")
    results = tmp_path / "results"
    (results / "a").mkdir(parents=True)
    (results / "a" / "s.xml").write_text(
        '<testsuites><testsuite tests="5" failures="0" errors="0" skipped="1"/></testsuites>'
    )
    report = {"lost": 0, "duplicated": 0, "stale_accepted": 0, "tasks": 1000}
    (results / "coord-scale.json").write_text(json.dumps(report))
    needs = {"stress": {"result": "success"}, "coord-scale": {"result": "success"}}
    green = summary.summarise(results, needs)
    assert green["ok"] and green["files"]["a/s.xml"]["tests"] == 5
    assert "green" in summary.markdown(green)
    assert not summary.summarise(results, {**needs, "fuzz": {"result": "failure"}})["ok"]
    (results / "coord-scale.json").write_text(json.dumps({**report, "lost": 1}))
    assert not summary.summarise(results, needs)["ok"]
    (results / "coord-scale.json").write_text(json.dumps(report))
    (results / "a" / "s.xml").write_text('<testsuite tests="5" failures="1" errors="0"/>')
    assert not summary.summarise(results, needs)["ok"]
    assert not summary.summarise(tmp_path / "missing", {})["ok"]  # nothing ran: not green
    out, md = tmp_path / "s.json", tmp_path / "s.md"
    assert summary.main([str(tmp_path / "missing"), "--out", str(out), "--markdown", str(md)]) == 1
    assert json.loads(out.read_text())["ok"] is False and "RED" in md.read_text()


def _run(day: str, conclusion: str = "success", event: str = "schedule", hour: int = 3) -> dict:
    stamp = f"{day}T{hour:02d}:17:00Z"
    return {"event": event, "status": "completed", "conclusion": conclusion,
            "created_at": stamp, "run_started_at": stamp, "html_url": f"u/{day}"}  # fmt: skip


def test_the_streak_counts_consecutive_green_scheduled_days():
    streak = _script("stress_streak").streak
    runs = [_run(f"2026-11-{d:02d}") for d in range(1, 10)]
    assert streak(runs)["streak"] == 9 and streak(runs)["since"] == "2026-11-01"
    red = [*runs, _run("2026-11-05", "failure", hour=4)]  # the night's latest run failed
    got = streak(red)
    assert got["streak"] == 4 and got["broken_by"]["day"] == "2026-11-05"
    rerun = [*red, _run("2026-11-05", "success", hour=5)]  # a later green run that day
    assert streak(rerun)["streak"] == 9
    gap = [r for r in runs if not r["created_at"].startswith("2026-11-07")]
    got = streak(gap)
    assert got["streak"] == 2 and got["broken_by"]["reason"] == "no finished scheduled run"
    manual = [*gap, _run("2026-11-07", event="workflow_dispatch")]
    assert streak(manual)["streak"] == 2  # a manual run never fills a night
    assert streak([])["streak"] == 0


def test_the_streak_script_reads_a_saved_page_and_exits_on_the_criterion(tmp_path, capsys):
    script = _script("stress_streak")
    page = tmp_path / "runs.json"
    page.write_text(json.dumps({"workflow_runs": [_run(f"2026-11-{d:02d}") for d in range(1, 4)]}))
    assert script.main(["--runs-file", str(page), "--need", "3"]) == 0
    assert json.loads(capsys.readouterr().out)["met"] is True
    assert script.main(["--runs-file", str(page)]) == 1  # 30 days are needed
    assert json.loads(capsys.readouterr().out) == {
        "branch": "main", "broken_by": {"day": "2026-10-31",
        "reason": "before the first recorded run"}, "met": False, "need": 30,
        "since": "2026-11-01", "streak": 3, "through": "2026-11-03",
        "workflow": "nightly-stress.yml"}  # fmt: skip
    assert script.main(["--runs-file", str(tmp_path / "nope.json")]) == 2


# --- the 0.34 peer compatibility job ------------------------------------------ #


def test_ci_runs_the_034_peer_compatibility_job():
    job = _jobs("ci.yml")["peer-compat-034"]
    assert re.search(r"^    timeout-minutes: \d+", job, re.M)
    assert '"opentine[zstd]==0.34.0"' in job
    assert "scripts/peer_compat_034.py --old-python" in job


def test_the_judge_fails_new_failures_and_pinned_gaps_that_start_passing():
    peer = _script("peer_compat_034")
    ok = {"ok": True, "detail": 1}
    gap = {"ok": False, "detail": "v5"}
    checks = {"load_run": ok, "fsck": {"ok": True, "detail": []}, "artifact_default": gap}
    base = {"version": "0.34.0", "checks": checks}
    assert peer.judge(base)["ok"]
    assert not peer.judge({**base, "version": "0.49.0"})["ok"]
    passing = {**base, "checks": {**base["checks"], "artifact_default": ok}}
    assert "unpin" in peer.judge(passing)["failures"][0]
    broken = {**base, "checks": {**base["checks"], "load_run": {"ok": False, "detail": "x"}}}
    assert peer.judge(broken)["failures"] == ["load_run: x"]
    fsck = {"ok": True, "detail": ["ref file 'prompts/r/head': bad", "pack p: malformed"]}
    judged = peer.judge({**base, "checks": {**base["checks"], "fsck": fsck}})
    assert judged["failures"] == ["fsck: ['pack p: malformed']"]
    assert "registry_refs" in judged["known_gaps"]
    assert not peer.judge({"error": "boom"})["ok"]


def _v034(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    try:
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", "v0.34.0", "opentine"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.34.0 is not available in this checkout")
    dest = tmp_path / "v034"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest


@pytest.mark.filterwarnings("ignore::Warning")
def test_034_reads_and_fetches_what_this_tree_writes_and_serves(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("OPENTINE_FORMAT", raising=False)
    old = _v034(tmp_path)
    out = tmp_path / "report.json"
    code = _script("peer_compat_034").main(["--old-path", str(old), "--out", str(out)])
    report = json.loads(out.read_text("utf-8"))
    assert code == 0, report["failures"]
    assert report["version"] == "0.34.0"
    checks = report["checks"]
    for name in ("get_every_object", "load_run", "artifact_legacy", "import_pack", "http_fetch"):
        assert checks[name]["ok"], (name, checks[name])
    assert set(report["known_gaps"]) <= {"artifact_default", "registry_refs"}


# --- the deprecation policy --------------------------------------------------- #


def test_the_deprecation_policy_is_published_and_linked():
    policy = (ROOT / "docs" / "DEPRECATION.md").read_text("utf-8")
    for needle in ("readable for ever", "two minor releases", "caps", "exit code",
                   "--json", "MUST", "0.34 peer compatibility", "Compatibility"):  # fmt: skip
        assert needle in policy, needle
    assert "](DEPRECATION.md)" in (ROOT / "docs" / "SPEC.md").read_text("utf-8")
    assert "](docs/DEPRECATION.md)" in (ROOT / "README.md").read_text("utf-8")
