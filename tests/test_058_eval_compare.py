"""0.58: ``tine eval compare --ci``: deterministic statistics, an export, an attestation.

The standalone ``scripts/eval_compare_reproduce.py`` (no opentine import)
reproduces ``stats`` exactly from the export; the attestation is an existing
``attestation`` whose claim follows ``opentine.eval-compare/1`` and is
reported ``unchecked`` by the claim helper.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import _claim_status, _eval_stats, _schemas, cli
from opentine.attest_signing import verify_attestation
from tests.promote_helpers import EVALER, RUN_A, RUN_B, make_eval, write_key

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
SCRIPT = ROOT / "scripts" / "eval_compare_reproduce.py"


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = capsys.readouterr().out
    document = json.loads(out) if out.strip().startswith("{") else {}
    if document:
        assert _schemas.validate_output(document) == [], document
    return code, document


@pytest.fixture
def evals(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    a = make_eval(tmp_path / "a", RUN_A, lambda i: i % 2 == 0)  # 50%
    b = make_eval(tmp_path / "b", RUN_B, lambda i: i % 10 != 0)  # 90%
    return tmp_path, a, b


@pytest.mark.parametrize("method", ["paired-bootstrap", "permutation"])
def test_compare_is_deterministic_and_reproduced_from_the_export(evals, capsys, method):
    base, a, b = evals
    export = base / f"{method}.json"
    argv = ("eval", "compare", a.as_posix(), b.as_posix(), "--ci", method, "--seed", "11",
            "--resamples", "400", "--json")  # fmt: skip
    code, first = _tine(capsys, *argv, "--export", export.as_posix())
    assert code == 0, first
    _, second = _tine(capsys, *argv)
    assert first["stats"] == second["stats"]
    stats = first["stats"]
    assert stats["n"] == 40 and stats["metrics"]["pass_rate"]["delta"] == "0.400000"
    assert stats["metrics"]["pass_rate"]["improvement"] is True
    assert stats["regressions"] == []
    done = subprocess.run([sys.executable, "-I", SCRIPT.as_posix(), export.as_posix()],
                          capture_output=True, timeout=300)  # fmt: skip
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == stats
    assert done.stdout.decode() == json.dumps(stats, sort_keys=True) + "\n"


def test_a_regression_is_named_and_exit_code_flags_it(evals, capsys):
    _, a, b = evals
    code, row = _tine(
        capsys,
        "eval",
        "compare",
        b.as_posix(),
        a.as_posix(),
        "--ci",
        "paired-bootstrap",
        "--resamples",
        "300",
        "--exit-code",
        "--json",
    )
    assert code == 1
    metric = row["stats"]["metrics"]["pass_rate"]
    assert metric["regression"] is True and float(metric["ci"][1]) < 0
    assert "pass_rate" in row["stats"]["regressions"]


def test_a_different_seed_changes_only_the_resampled_numbers(evals):
    from opentine._eval_run import read_verdicts

    _, a, b = evals
    one, two = (
        _eval_stats.compute(_eval_stats.export(read_verdicts(a), read_verdicts(b),
                            method="paired-bootstrap", alpha="0.05", seed=s, resamples=300))
        for s in (1, 2)
    )  # fmt: skip
    assert one["metrics"]["score"]["delta"] == two["metrics"]["score"]["delta"]
    assert (one["seed"], two["seed"]) == (1, 2)


def test_the_comparison_is_attested_with_an_unchecked_claim(evals, capsys):
    base, a, b = evals
    signer = write_key(base / "k.key", EVALER)
    out = base / "compare.attestation.json"
    code, row = _tine(capsys, "eval", "compare", a.as_posix(), b.as_posix(), "--ci",
                      "permutation", "--resamples", "200", "--attest", signer.as_posix(),
                      "--out", out.as_posix(), "--signed-at", "2026-11-01T12:00:00Z",
                      "--json")  # fmt: skip
    assert code == 0 and row["attestation"] == out.as_posix()
    document = json.loads(out.read_text("utf-8"))
    assert document["claim"]["schema"] == "opentine.eval-compare/1"
    assert document["claim"]["stats"] == row["stats"]
    assert document["target_id"] == row["b"]["eval"]
    assert verify_attestation(document, trust_embedded=True).ok
    status = _claim_status.claim_status(document["claim"])
    assert status["status"] == "unchecked"
    document["claim"]["stats"]["n"] = 41
    assert not verify_attestation(document, trust_embedded=True).ok


@pytest.mark.parametrize("alpha", ["0", "1", "x", "-0.1"])
def test_bad_alpha_is_refused(alpha):
    with pytest.raises(ValueError):
        _eval_stats.check("paired-bootstrap", alpha, 0, 1000)


def test_the_human_table_names_each_metric(evals, capsys):
    _, a, b = evals
    code, _ = _tine(capsys, "eval", "compare", a.as_posix(), b.as_posix(), "--ci",
                    "paired-bootstrap", "--resamples", "200")  # fmt: skip
    assert code == 0
