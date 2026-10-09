"""End-to-end: the neutral runner, against the reference PROTOCOL.md adapter.

``run_conformance.py`` is the file a third party actually executes, and
``scripts/conformance_adapter.py`` is the worked example they port. Neither is
exercised by the two self-gates -- those call the ops directly -- so a broken
protocol layer would ship green. This module runs the real thing.

It shells only ``[sys.executable, ...]``, which the binary-dependency meta-test
in ``test_release_audit_round11_misc.py`` does not treat as an external binary,
so it needs no entry in ``BINARY_DEPENDENT_TEST_MODULES``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "docs" / "conformance" / "run_conformance.py"
ADAPTER = ROOT / "scripts" / "conformance_adapter.py"


def _run(*extra: str, report: Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(RUNNER),
        "--adapter",
        f"{sys.executable} {ADAPTER}",
        "--capability",
        "zlib",
        "--capability",
        "ed25519",
        "--capability",
        "wtf8",
        *extra,
    ]
    if report is not None:
        command += ["--report", str(report)]
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, timeout=900)


@pytest.fixture(scope="module")
def level_two(tmp_path_factory) -> dict:
    report = tmp_path_factory.mktemp("conformance") / "report.json"
    result = _run("--level", "2", "--name", "opentine", "--language", "python", report=report)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(report.read_text("utf-8"))


def test_the_reference_adapter_scores_a_clean_level_2_run(level_two: dict) -> None:
    totals = level_two["totals"]
    assert totals["fail"] == 0, "the reference implementation failed its own suite"
    assert totals["repaired"] == 0, "the reference implementation silently repaired an input"
    assert totals["unsupported"] == 0, "an op in MANIFEST.ops has no adapter"
    assert totals["pass"] > 400


def test_every_twin_pair_passes_as_a_pair(level_two: dict) -> None:
    """A blanket rejecter scores 100% on negatives and 0% here, which is the point."""
    pairs = level_two["pairs"]
    assert pairs["total"] >= 90
    assert pairs["passed"] == pairs["total"]


def test_level_2_reason_agreement_is_total(level_two: dict) -> None:
    agreement = level_two["reason_agreement"]
    assert agreement["total"] >= 180
    assert agreement["agreed"] == agreement["total"]


def test_the_report_matches_its_own_schema(level_two: dict) -> None:
    schema = json.loads((ROOT / "docs" / "conformance" / "report.schema.json").read_text("utf-8"))
    for field in schema["required"]:
        assert field in level_two, field
    statuses = set(schema["properties"]["results"]["items"]["properties"]["status"]["enum"])
    assert {row["status"] for row in level_two["results"]} <= statuses
    for row in level_two["results"]:
        for field in schema["properties"]["results"]["items"]["required"]:
            assert field in row, (row["id"], field)


def test_an_implementation_that_refuses_everything_scores_zero_on_pairs(tmp_path: Path) -> None:
    """The suite must not be passable by a blanket rejecter -- better than a third
    of its cases are negatives, and a program that answers 'no' to all of them
    would score well on any single-column scorecard."""
    stub = tmp_path / "always_reject.py"
    stub.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    request = json.loads(line)\n"
        "    sys.stdout.write(json.dumps(\n"
        "        {'id': request['id'], 'ok': False, 'reason': 'nope'}) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    report = tmp_path / "reject.json"
    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--adapter",
            f"{sys.executable} {stub}",
            "--capability",
            "zlib",
            "--capability",
            "ed25519",
            "--capability",
            "wtf8",
            "--profile",
            "reader",
            "--report",
            str(report),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=900,
    )
    assert result.returncode == 1
    data = json.loads(report.read_text("utf-8"))
    assert data["totals"]["fail"] > 100
    # Not exactly zero: a handful of twins are reject/reject (both canonicalizers
    # refuse NaN, say), and a rejecter gets those for free. The score still
    # collapses, which is the property the pairs column exists to expose.
    assert data["pairs"]["passed"] * 10 < data["pairs"]["total"], data["pairs"]


def test_an_implementation_that_repairs_is_reported_as_repaired(tmp_path: Path) -> None:
    """The status that matters: accepting an input the format requires be refused,
    and returning the exact answer the repair produces."""
    stub = tmp_path / "repairing.py"
    stub.write_text(
        "import json, sys\n"
        "FORBIDDEN = json.load(open(sys.argv[1]))\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    request = json.loads(line)\n"
        "    answer = FORBIDDEN.get(request['id'])\n"
        "    if answer is None:\n"
        "        out = {'id': request['id'], 'ok': False, 'unsupported': True}\n"
        "    else:\n"
        "        out = {'id': request['id'], 'ok': True, 'output': answer}\n"
        "    sys.stdout.write(json.dumps(out) + '\\n')\n"
        "    sys.stdout.flush()\n",
        encoding="utf-8",
    )
    suite = ROOT / "docs" / "conformance"
    forbidden = {
        record["id"]: record["forbidden"]
        for path in sorted((suite / "vectors").glob("*.json"))
        for record in json.loads(path.read_text("utf-8"))["cases"]
        if record.get("forbidden")
    }
    payload = tmp_path / "forbidden.json"
    payload.write_text(json.dumps(forbidden), encoding="utf-8")
    report = tmp_path / "repaired.json"
    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--adapter",
            f"{sys.executable} {stub} {payload}",
            "--capability",
            "zlib",
            "--capability",
            "ed25519",
            "--capability",
            "wtf8",
            "--report",
            str(report),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=900,
    )
    assert result.returncode == 1
    data = json.loads(report.read_text("utf-8"))
    assert data["totals"]["repaired"] >= 14, data["totals"]
    assert "REPAIRED" in result.stdout
