"""0.86: eval plans, epochs and reducers, coverage, clusters, power and correction."""

from __future__ import annotations

import json
import random
from fractions import Fraction
from pathlib import Path

import pytest

from opentine import _eval_plan as plans
from opentine import _eval_reduce as reduce
from opentine import _schemas, cli
from opentine._eval_coverage import read as read_coverage
from tests.plan_helpers import SECRET, items, plan_fields, run, write_plan
from tests.promote_helpers import EVALER, PROMOTER, RUN_A, RUN_B, fingerprint, key

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _rows(passing: dict[str, list[bool]]) -> list[dict]:
    return [{"item": item if len(bits) == 1 else f"{item}@e{e}",
             "score": "1" if bit else "0", "passed": bit}
            for item, bits in passing.items() for e, bit in enumerate(bits)]  # fmt: skip


def test_reducers_turn_epochs_into_one_value_per_item():
    rows = _rows({"a": [True, False, True], "b": [True, True, True], "c": [False, False, False]})
    got = {r: reduce.reduced(rows, 3, "pass_rate", r) for r in ("mean", "pass@k", "pass^k")}
    assert {k: v["a"] for k, v in got.items()} == {"mean": Fraction(2, 3), "pass@k": 1,
                                                   "pass^k": 0}  # fmt: skip
    assert got["pass^k"] == {"a": 0, "b": 1, "c": 0}
    short = reduce.reduced(rows[:-1], 3, "pass_rate", "mean")  # c lost an epoch: not paired
    assert set(short) == {"a", "b"}


def test_clusters_set_the_effective_n_and_widen_the_interval():
    rows = items(40, families=4)
    clusters = {r["id"]: r["metadata"]["family"] for r in rows}
    base = [{"item": r["id"], "score": "0", "passed": False} for r in rows]
    cand = [{"item": r["id"], "score": str(int(i % 4 == 0)), "passed": i % 4 == 0}
            for i, r in enumerate(rows)]  # one family moved, three did not  # fmt: skip
    flat = reduce.analyse(base, cand, plan_fields(rows), seed=1, alpha="0.05", clusters=None)
    pooled = reduce.analyse(base, cand, plan_fields(rows, cluster_key="family"), seed=1,
                            alpha="0.05", clusters=clusters)  # fmt: skip
    assert (flat["effective_n"], pooled["effective_n"]) == (40, 4)
    assert flat["passed"] is True and pooled["passed"] is False
    assert pooled["se"] > flat["se"] and pooled["power_at_mde"] < flat["power_at_mde"]


def test_correction_divides_alpha_by_the_candidate_count():
    assert reduce.corrected_alpha("0.05", "bonferroni", 10, 3) == "0.005"
    assert [reduce.corrected_alpha("0.05", "holm", 4, r) for r in (1, 2, 3, 4)] == [
        "0.0125", "0.01666666666666666666666666667", "0.025", "0.05"]  # fmt: skip


def test_null_candidates_are_not_promoted_familywise():
    rng = random.Random("opentine-0.86-null")
    rows = items(30)
    plan = plan_fields(rows, max_candidates=50, resamples=2000)
    alpha = reduce.corrected_alpha("0.05", "holm", 50, 1)
    raw = corrected = 0
    for n in range(50):  # 50 null variants: every pass bit is a coin flip on both sides
        base, cand = ([{"item": r["id"], "score": "0", "passed": rng.random() < 0.5}
                       for r in rows] for _ in range(2))  # fmt: skip
        raw += reduce.analyse(base, cand, plan, seed=n, alpha="0.05", clusters=None)["passed"]
        corrected += reduce.analyse(base, cand, plan, seed=n, alpha=alpha, clusters=None)["passed"]
    assert raw >= 1 and corrected == 0  # selection on noise wins uncorrected only


def test_a_bootstrap_too_coarse_for_the_corrected_alpha_fails_closed():
    rows = items(30)
    base = [{"item": r["id"], "score": "0", "passed": False} for r in rows]
    cand = [{"item": r["id"], "score": "1", "passed": True} for r in rows]
    row = reduce.analyse(base, cand, plan_fields(rows, resamples=100), seed=1,
                         alpha="0.001", clusters=None)  # fmt: skip
    assert (row["resolved"], row["passed"]) == (False, False)


def test_the_seed_is_fixed_by_the_plan_not_by_the_caller():
    sha = "ab" * 32
    seed = plans.derive_seed(SECRET, sha)
    assert seed == plans.derive_seed(SECRET, sha) and 0 <= seed < 2**53
    assert seed != plans.derive_seed(SECRET, "cd" * 32)
    assert plans.commitment(SECRET) != plans.commitment("11" * 32)


def test_a_reveal_must_open_the_commitment_under_the_plan_signer(tmp_path):
    rows = items()
    plan, reveal = write_plan(tmp_path, rows)
    opened = plans.opened_plan(plans.load(plan))
    assert plans.opened_reveal(plans.load(reveal), opened) == plans.derive_seed(
        SECRET, opened["sha256"])  # fmt: skip
    forged = plans.make_reveal(key(PROMOTER), plans.load(plan), SECRET, "2026-11-01T13:00:00Z")
    with pytest.raises(plans.PlanError) as caught:
        plans.opened_reveal(forged, opened)
    assert caught.value.code == "promote.seed-not-committed"
    with pytest.raises(plans.PlanError):
        plans.make_reveal(key(EVALER), plans.load(plan), "22" * 32, "2026-11-01T13:00:00Z")
    tampered = plans.load(plan)
    tampered["claim"]["max_candidates"] = 1000
    with pytest.raises(plans.PlanError) as caught:
        plans.opened_plan(tampered)
    assert caught.value.code == "promote.plan-invalid"


def test_coverage_records_skipped_and_errored_items_signed(tmp_path):
    rows = items(10)
    folder = run(tmp_path / "e", rows, RUN_B, lambda i, e: True, missing={"main-003"})
    claim = read_coverage(folder, {fingerprint(EVALER)})
    assert (claim["planned"], claim["scored"], claim["skipped"]) == (10, 9, ["main-003"])
    assert read_coverage(folder, {fingerprint(PROMOTER)}) is None  # another signer: not trusted
    epochs = run(tmp_path / "x", rows, RUN_A, lambda i, e: e == 0, epochs=3)
    claim = read_coverage(epochs, {fingerprint(EVALER)})
    assert (claim["epochs"], claim["planned"], claim["scored"]) == (3, 30, 30)


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


def test_the_cli_plans_runs_epochs_under_the_plan_and_reveals(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = [{**row, "metadata": {"family": f"f{n % 3}"}} for n, row in enumerate(items(6))]
    Path("d.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in data).encode())
    Path("k.key").write_bytes(EVALER.encode())
    code, row = _tine(capsys, "eval", "plan", "d.jsonl", "--key", "k.key", "--out", "p.json",
                      "--secret-out", "p.secret", "--max-candidates", "4", "--epochs", "2",
                      "--reducer", "pass^k", "--cluster-key", "family", "--at",
                      "2026-11-01T11:00:00Z", "--json")  # fmt: skip
    assert code == 0 and row["plan"]["reducer"] == "pass^k"
    again, _ = _tine(capsys, "eval", "plan", "d.jsonl", "--key", "k.key", "--out", "q.json",
                     "--secret-out", "p.secret", "--max-candidates", "4", "--json")  # fmt: skip
    assert again != 0  # a secret is never overwritten
    outs = [{"id": r["id"], "epoch": e, "output": "yes", "run": RUN_B} for r in data
            for e in range(2) if (r["id"], e) != ("main-001", 1)]  # fmt: skip
    Path("o.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in outs).encode())
    code, row = _tine(capsys, "eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key",
                      "--out", "ev", "--outputs", "o.jsonl", "--plan", "p.json",
                      "--continue-on-error", "--json")  # fmt: skip
    assert code == 0 and row["coverage"] == {"planned": 12, "scored": 11, "skipped": 1,
                                             "errored": 0}  # fmt: skip
    claim = read_coverage(Path("ev"), {fingerprint(EVALER)})
    assert claim["plan_sha256"] == plans.file_sha256(plans.load(Path("p.json")))
    assert claim["clusters"]["main-004"] == "f1" and claim["skipped"] == ["main-001@e1"]
    code, _ = _tine(capsys, "eval", "run", "d.jsonl", "--scorer", "exact", "--key", "k.key",
                    "--out", "ev2", "--outputs", "o.jsonl", "--plan", "p.json",
                    "--epochs", "3")  # fmt: skip
    assert code != 0  # epochs must match the plan
    code, row = _tine(capsys, "eval", "reveal", "p.json", "--secret", "p.secret", "--key",
                      "k.key", "--out", "r.json", "--json")  # fmt: skip
    assert code == 0 and row["seed"] == plans.derive_seed(
        Path("p.secret").read_bytes().decode().strip(), row["plan_sha256"])  # fmt: skip


def test_an_isolated_scorer_error_is_recorded_as_errored(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("sc.py").write_bytes(
        b"def score(output, item):\n"
        b"    if item['id'] == 'main-002':\n"
        b"        raise RuntimeError('cannot score')\n"
        b"    return output == item['expected']\n"
    )  # fmt: skip
    data = [{**row, "output": "yes", "run": RUN_B} for row in items(4)]
    Path("d.jsonl").write_bytes("".join(json.dumps(r) + "\n" for r in data).encode())
    Path("k.key").write_bytes(EVALER.encode())
    argv = ("eval", "run", "d.jsonl", "--scorer", "python:sc.py:score", "--isolate", "--key",
            "k.key", "--json")  # fmt: skip
    code, _ = _tine(capsys, *argv, "--out", "strict")
    assert code != 0  # without --continue-on-error an error still aborts
    code, row = _tine(capsys, *argv, "--out", "ev", "--continue-on-error")
    assert code == 0 and row["coverage"]["errored"] == 1 and row["items"] == 3
    assert read_coverage(Path("ev"), {fingerprint(EVALER)})["errored"] == ["main-002"]
