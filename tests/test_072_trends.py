"""``tine trends`` (0.72): capability trends over lineage generations from signed records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._cli_trends import export_bytes
from opentine._trends import compute
from opentine.kernel import canonical_json
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse fixture
from tests.promote_helpers import AT, RUN_C, key
from tests.trends_helpers import build, write_lengths

ARGS = ["--resamples", "200"]


def run(argv: list[str]) -> int:
    try:
        cli.main(argv)
    except SystemExit as exc:
        return exc.code or 0
    return 0


def trends(root: Path, capsys, *extra: str) -> dict:
    assert run(["trends", "--repo", root.as_posix(), "--json", *ARGS, *extra]) == 0
    out = json.loads(capsys.readouterr().out)
    _schemas.validate(out, "tine-cli-trends-1")
    return out


@pytest.fixture
def lineage(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    return build(tmp_path)


def by_variant(row: dict) -> dict[str, dict]:
    return {v["variant"]: v for v in row["variants"]}


def test_generations_metrics_and_regressions(lineage, capsys) -> None:
    root, v = lineage
    row = trends(root, capsys)
    assert row["schema"] == "tine-cli-trends/1" and row["signers"] == "pinned"
    assert row["lengths"]["status"] == "trusted"
    rows = by_variant(row)
    assert [rows[v[n]]["generation"] for n in ("root", "child", "worse")] == [0, 1, 2]
    assert [g["generation"] for g in row["generations"]] == [0, 1, 2]
    root_row, child, worse = (rows[v[n]] for n in ("root", "child", "worse"))
    assert root_row["n"] == child["n"] == 80
    assert child["pass_rate"]["mean"] > root_row["pass_rate"]["mean"]
    low, high = child["pass_rate"]["ci"]
    assert low <= child["pass_rate"]["mean"] <= high
    # the horizon moves with capability: child > root > worse
    hours = [float(rows[v[n]]["horizon"]["minutes"]) for n in ("worse", "root", "child")]
    assert hours == sorted(hours)
    assert row["regressions"] == [{"variant": v["worse"], "parent": v["child"],
                                   "metrics": ["score", "pass_rate"]}]  # fmt: skip
    assert child["vs_parents"][0]["regressions"] == []
    assert root_row["cost_per_success"] is None  # no signed spend recorded


def test_fail_on_regression_exits_1(lineage, capsys) -> None:
    root, _ = lineage
    assert run(["trends", "--repo", root.as_posix(), "--fail-on-regression", *ARGS]) == 1
    assert "REGRESSION" in capsys.readouterr().out


def test_tainted_input_is_flagged_and_not_best(lineage, capsys) -> None:
    from opentine._integrity_run import taint
    from tests.lineage_helpers import RECORDER

    root, v = lineage
    row = {"run": RUN_C, "findings": [{"level": "fail", "code": "fail:protected-surface-modified"}],
           "protected_sha256": "0" * 64}  # fmt: skip
    taint(root, key(RECORDER), row, AT)
    out = trends(root, capsys)
    assert by_variant(out)[v["worse"]]["flags"] == ["lineage.score-tainted"]
    assert out["flags"] == ["lineage.score-tainted"]
    gen = out["generations"][2]
    assert gen["flagged"] == 1 and gen["best"] is None


def test_quarantined_input_is_flagged(lineage, capsys, monkeypatch) -> None:
    from opentine import _memory_quarantine

    root, v = lineage

    def served(_root, _files, variants):
        return [{"code": "lineage.memory-quarantined", "variant": x, "detail": "d"}
                for x in variants if x == v["child"]]  # fmt: skip

    monkeypatch.setattr(_memory_quarantine, "lineage_findings", served)
    out = trends(root, capsys)
    assert by_variant(out)[v["child"]]["flags"] == ["lineage.memory-quarantined"]


def test_unsigned_eval_is_withheld_and_record_excluded(lineage, capsys) -> None:
    root, v = lineage
    evals = sorted((root / ".tine" / "lineage" / "evals").glob("*.jsonl"))
    raw = evals[0].read_bytes().replace(b'"score": "1"', b'"score": "0"', 1)
    evals[0].write_bytes(raw)
    forged = root / ".tine" / "lineage" / "variants" / f"{v['root'][7:]}.json"
    out = trends(root, capsys)
    withheld = [r for r in out["variants"] if "lineage.evidence-missing" in r["flags"]]
    assert len(withheld) == 1 and withheld[0]["n"] == 0
    assert withheld[0]["score"] == {"mean": None, "ci": None}
    forged.write_bytes(forged.read_bytes().replace(b'"selector": ""', b'"selector": "x"'))
    out = trends(root, capsys)
    assert {"variant": v["root"], "code": "lineage.record-invalid"} in out["excluded"]
    assert v["root"] not in by_variant(out)
    assert by_variant(out)[v["child"]]["generation"] == 0  # its parent no longer counts
    assert "lineage.parent-missing" in by_variant(out)[v["child"]]["flags"]


@pytest.mark.parametrize("case", ["missing", "unpinned", "optimizer", "edited"])
def test_task_lengths_fail_closed(tmp_path, capsys, case) -> None:
    from tests.lineage_helpers import RECORDER

    root, v = build(tmp_path, pin=case != "unpinned")
    path = root / ".tine" / "trends" / "task-lengths.json"
    if case == "missing":
        path.unlink()
    elif case == "optimizer":
        write_lengths(root, signer=RECORDER)
    elif case == "edited":
        path.write_bytes(path.read_bytes().replace(b'"240"', b'"2400"'))
    out = trends(root, capsys)
    status = {"missing": "missing", "unpinned": "roles-unpinned", "optimizer": "signer-untrusted",
              "edited": "invalid"}[case]  # fmt: skip
    assert out["lengths"]["status"] == status
    for row in out["variants"]:
        assert row["horizon"]["minutes"] is None and row["horizon"]["n"] == 0
        assert row["horizon"]["reason"] == "fewer-than-two-lengths"


def test_export_recomputes_byte_for_byte(lineage, capsys, tmp_path) -> None:
    root, _ = lineage
    path = tmp_path / "trends.json"
    out = trends(root, capsys, "--export", path.as_posix())
    data = json.loads(path.read_bytes())
    _schemas.validate(data, "opentine-trends-1")
    reported = data.pop("reported")
    again = compute(data)
    assert canonical_json(again) == canonical_json(reported)
    assert {k: out[k] for k in reported} == reported
    assert export_bytes({**data, "reported": reported}) == path.read_bytes()
    second = tmp_path / "again.json"
    trends(root, capsys, "--export", second.as_posix())
    assert second.read_bytes() == path.read_bytes()  # deterministic given the seed


def test_seed_changes_intervals_not_means(lineage, capsys) -> None:
    root, v = lineage
    a = by_variant(trends(root, capsys))[v["child"]]
    b = by_variant(trends(root, capsys, "--seed", "7"))[v["child"]]
    assert a["score"]["mean"] == b["score"]["mean"]
    assert a["horizon"]["minutes"] == b["horizon"]["minutes"]


def test_refuses_bad_parameters(lineage, capsys) -> None:
    root, _ = lineage
    for extra in (["--seed", str(2**53)], ["--alpha", "1"], ["--resamples", "5"]):
        assert run(["trends", "--repo", root.as_posix(), *extra]) != 0
    capsys.readouterr()


def test_sign_lengths_cli(tmp_path, capsys) -> None:
    from opentine._trends_lengths import verify
    from tests.trends_helpers import DATASET

    (tmp_path / "k").write_bytes(DATASET.encode())
    (tmp_path / "l.json").write_bytes(b'{"a": "1.5", "b": "30"}')
    out = tmp_path / "signed.json"
    assert run(["trends", "--sign-lengths", (tmp_path / "l.json").as_posix(), "--key",
                (tmp_path / "k").as_posix(), "--task-lengths", out.as_posix(), "--at", AT,
                "--json"]) == 0  # fmt: skip
    printed = json.loads(capsys.readouterr().out)
    _schemas.validate(printed, "tine-cli-trends-1")
    assert printed["items"] == 2
    _schemas.validate(json.loads(out.read_bytes()), "opentine-trends-task-lengths-1")
    assert verify(json.loads(out.read_bytes()))["lengths"] == {"a": "1.5", "b": "30"}


def test_browser_recompute_matches(lineage, capsys, tmp_path) -> None:
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    root, _ = lineage
    path = tmp_path / "trends.json"
    trends(root, capsys, "--export", path.as_posix())
    script = Path(__file__).resolve().parents[1] / "opentine" / "data" / "trends" / "recompute.mjs"
    done = subprocess.run([node, script.as_posix(), path.as_posix()], capture_output=True,
                          timeout=120, check=True)  # fmt: skip
    reported = json.loads(path.read_bytes())["reported"]
    assert done.stdout == canonical_json(reported) + b"\n"
