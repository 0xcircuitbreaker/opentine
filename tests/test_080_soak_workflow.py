"""0.80 nightly soak: the workflow's shape, and the summary it writes."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "nightly-soak.yml"


def _text() -> str:
    return WORKFLOW.read_bytes().decode("utf-8")


def _job(name: str) -> str:
    text = _text()
    start = text.index(f"\n  {name}:\n")
    rest = text[start + 1 :]
    end = re.search(r"\n  [a-z-]+:\n", rest[1:])
    return rest if end is None else rest[: end.start() + 1]


def test_it_runs_nightly_and_on_demand_with_read_only_permissions():
    text = _text()
    assert re.search(r"on:\n  schedule:\n    - cron: \"[0-9]+ [0-9]+ \* \* \*\"\n", text)
    assert "  workflow_dispatch:\n" in text
    assert "permissions:\n  contents: read\n" in text
    assert "write" not in re.sub(r"#.*", "", text).replace("--write", "")


def test_every_action_is_pinned_to_a_commit_and_checkout_keeps_no_token():
    uses = re.findall(r"uses: (\S+)", _text())
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses)
    checkouts = _text().count("actions/checkout@")
    assert _text().count("persist-credentials: false") == checkouts


def test_suite_parity_fuzz_and_bench_feed_one_summary():
    for job, needle in [("suite", "pytest -n auto"), ("parity", "check_parity.py --require-ts"),
                        ("parity", "verify_everywhere.py"), ("fuzz", "scripts/fuzz.py"),
                        ("bench", "run_bench.py")]:  # fmt: skip
        assert needle in _job(job), (job, needle)
    summary = _job("summary")
    assert "needs: [suite, parity, fuzz, bench]" in summary and "if: always()" in summary
    assert "scripts/nightly_summary.py" in summary and '--title "Nightly soak"' in summary
    assert "--iterations 200000" in _job("fuzz")  # ten times the per-PR 20,000
    for job in ("suite", "parity", "fuzz", "bench"):
        assert "upload-artifact@" in _job(job) and "name: soak-" in _job(job)


def test_the_summary_is_titled_and_red_on_a_red_night(tmp_path):
    results = tmp_path / "results"
    (results / "soak-parity").mkdir(parents=True)
    report = {"ok": False, "problems": ["ts disagrees: x"]}
    (results / "soak-parity" / "verify-everywhere.json").write_bytes(json.dumps(report).encode())
    md = tmp_path / "summary.md"
    needs = json.dumps({"parity": {"result": "success"}})
    done = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "nightly_summary.py"), str(results),
         "--needs", needs, "--markdown", str(md), "--title", "Nightly soak"],
        capture_output=True, check=False, timeout=120)  # fmt: skip
    assert done.returncode == 1
    assert md.read_bytes().decode("utf-8").startswith("## Nightly soak: RED")


def test_the_roadmap_re_evaluates_all_seven_criteria_and_leaves_the_call_to_the_owner():
    text = (ROOT / "docs" / "ROADMAP.md").read_bytes().decode("utf-8")
    section = text.split("### 1.0 re-evaluation (0.80)", 1)[1].split("\n### ", 1)[0]
    assert "| # | Criterion | Evidence | Status at 0.80 | Audit status |" in section
    rows = [line for line in section.splitlines() if re.match(r"\| [1-7] \|", line)]
    assert [row.split("|")[1].strip() for row in rows] == [str(n) for n in range(1, 8)]
    assert all(row.count("|") == 6 for row in rows)
    assert "go/no-go on declaring the 1.0 track is the owner's decision" in section
    assert "nightly-soak.yml" in section and "verify_everywhere.py" in section


def test_a_failing_check_piped_into_tee_still_fails_its_step():
    # GitHub's implicit shell is ``bash -e`` without pipefail, so ``check | tee``
    # would be green whatever the check said. Only an explicit ``shell: bash``
    # (``bash --noprofile --norc -eo pipefail``) makes the pipe carry the failure.
    text = _text()
    piped = [m for m in re.findall(r"run: \|\n((?:          .*\n)+)", text) if " | " in m]
    assert piped
    assert "defaults:\n  run:\n    shell: bash\n" in text
