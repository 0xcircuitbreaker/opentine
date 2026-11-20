"""Red-team holes in ``tine trends`` (0.72), one test each.

A self-improving loop holding only its optimizer key tries to look more capable
or to hide a regression; each test is an attack that must not change the report
in the loop's favour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas, cli
from opentine._trends import compute
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import AT, RUN_A, RUN_C, fingerprint, key
from tests.trends_helpers import build, items, make_eval, roles_toml, write_lengths

ARGS = ["--resamples", "200"]
RUNNER = "7a" * 32


def tine(argv: list[str]) -> int:
    try:
        cli.main(argv)
    except SystemExit as exc:
        return exc.code or 0
    return 0


def trends(root: Path, capsys, *extra: str) -> dict:
    assert tine(["trends", "--repo", root.as_posix(), "--json", *ARGS, *extra]) == 0
    out = json.loads(capsys.readouterr().out)
    _schemas.validate(out, "tine-cli-trends-1")
    return out


def rows(out: dict) -> dict[str, dict]:
    return {r["variant"]: r for r in out["variants"]}


def gate(root: Path, capsys) -> int:
    code = tine(["trends", "--repo", root.as_posix(), "--fail-on-regression", *ARGS])
    capsys.readouterr()
    return code


def test_unpinned_eval_signers_withhold_every_metric(tmp_path, capsys) -> None:
    root, v = build(tmp_path, pin=False)
    out = trends(root, capsys)
    assert out["signers"] == "unpinned"
    for name in ("child", "worse"):
        row = rows(out)[v[name]]
        assert row["n"] == 0 and "lineage.signer-untrusted" in row["flags"]
    assert out["regressions"] == [] and out["unchecked"]
    assert gate(root, capsys) == 1


def test_dropping_a_regressed_variants_evidence_fails_the_gate(tmp_path, capsys) -> None:
    root, v = build(tmp_path)
    record = root / ".tine" / "lineage" / "variants" / f"{v['worse'][7:]}.json"
    cited = json.loads(record.read_bytes())["claim"]["evals"][0]["eval"]
    (root / ".tine" / "lineage" / "evals" / f"{cited[7:]}.jsonl").unlink()
    out = trends(root, capsys)
    assert out["regressions"] == []
    assert {"variant": v["worse"], "code": "lineage.evidence-missing"} in out["unchecked"]
    assert gate(root, capsys) == 1


def test_a_run_recorded_again_under_new_parents_is_flagged(tmp_path, capsys) -> None:
    from opentine._lineage import record
    from tests.lineage_helpers import RECORDER, art

    root, v = build(tmp_path)
    folder = make_eval(tmp_path / "again", RUN_C, "2026-11-01T12:00:09Z")
    store = root / ".tine" / "lineage"
    rerooted = record(key(RECORDER), run=RUN_C, artifacts=art(103), store=store, parents=[],
                      evals=[folder], at=AT)["variant"]  # fmt: skip
    out = trends(root, capsys)
    for variant in (rerooted, v["worse"]):
        assert "trends.run-relabelled" in rows(out)[variant]["flags"]
    assert {"variant": rerooted, "code": "trends.run-relabelled"} in out["unchecked"]


def test_a_recorded_variant_cannot_be_re_rooted(tmp_path, capsys) -> None:
    from opentine._lineage import record
    from tests.lineage_helpers import RECORDER, art

    root, v = build(tmp_path)
    folder = make_eval(tmp_path / "again", RUN_C, "2026-11-01T12:00:09Z")
    store = root / ".tine" / "lineage"
    with pytest.raises(ValueError, match="append-only"):
        record(key(RECORDER), run=RUN_C, artifacts=art(102), store=store, parents=[],
               evals=[folder], at=AT)  # fmt: skip
    assert rows(trends(root, capsys))[v["worse"]]["generation"] == 2


def test_lengths_for_another_dataset_give_no_horizon(tmp_path, capsys) -> None:
    root, _ = build(tmp_path)
    write_lengths(root, bound="sha256:" + "ab" * 32)
    out = trends(root, capsys)
    assert out["lengths"]["status"] == "trusted"
    for row in out["variants"]:
        assert row["horizon"]["minutes"] is None and row["horizon"]["n"] == 0


def test_the_order_of_cited_evals_cannot_pick_the_better_run(tmp_path, capsys) -> None:
    from opentine._eval_run import run_eval
    from opentine._eval_scorers import parse
    from opentine._lineage import record
    from tests.lineage_helpers import RECORDER, art
    from tests.promote_helpers import EVALER

    root, _ = build(tmp_path)
    folders = []
    for n, answer in enumerate(("no", "yes")):
        outputs = {i["id"]: {"output": answer, "run": RUN_A} for i in items()}
        run_eval(items(), parse("exact"), key(EVALER), tmp_path / f"e{n}", outputs=outputs,
                 created_at=f"2026-11-02T12:00:0{n}Z")  # fmt: skip
        folders.append(tmp_path / f"e{n}")
    store = root / ".tine" / "lineage"
    one = record(key(RECORDER), run=RUN_A, artifacts=art(200), store=store, parents=[],
                 evals=folders, at=AT)["variant"]  # fmt: skip
    two = record(key(RECORDER), run=RUN_A, artifacts=art(201), store=store, parents=[],
                 evals=folders[::-1], at=AT)["variant"]  # fmt: skip
    out = rows(trends(root, capsys))
    assert out[one]["score"]["mean"] == out[two]["score"]["mean"] == "0.000000"


@pytest.mark.parametrize("signer,total,counted", [
    ("runner", 3.0, True), ("optimizer", 3.0, False), ("runner", -3.0, False),
    ("runner", "3", False), ("runner", True, False)])  # fmt: skip
def test_cost_counts_only_sane_spend_from_a_pinned_runner(tmp_path, capsys, signer, total,
                                                          counted) -> None:  # fmt: skip
    from opentine import _budget_ledger
    from opentine.repository import Repo
    from tests.lineage_helpers import RECORDER

    root, v = build(tmp_path)
    repo = Repo.open(root)
    store = Path(repo.path)
    toml = roles_toml() + f'runner = ["{fingerprint(RUNNER)}"]\n'
    (store / "key-roles.toml").write_bytes(toml.encode("utf-8"))
    pin_roles(store)
    signing = key(RUNNER if signer == "runner" else RECORDER)
    _budget_ledger.append(repo, "loop:opt", "spend", {"run": RUN_A, "cost": {"total_cost": total}},
                          signing, at_ms=1_800_000_000_000)  # fmt: skip
    got = rows(trends(root, capsys))[v["root"]]["cost_per_success"]
    assert (got is not None) is counted


def test_an_export_seed_a_browser_cannot_read_exactly_is_refused(tmp_path, capsys) -> None:
    root, _ = build(tmp_path)
    path = tmp_path / "t.json"
    trends(root, capsys, "--export", path.as_posix())
    data = json.loads(path.read_bytes())
    data.pop("reported")
    with pytest.raises(ValueError, match="2\\^53"):
        compute({**data, "seed": 2**53 + 1})
