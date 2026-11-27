"""0.86 acceptance, end to end: a pre-registered plan through to a signed promotion.

Under ``profile = "rsi"`` a candidate promotes only with a committed plan, a
revealed seed, pinned scorer signers and a lineage record; epochs reduce by the
planned reducer, clusters set the effective n, the alpha is corrected over the
committed candidate count, and the decision signs all of it. Holdout queries
past the budget are counted and refuse the promotion under rsi.
"""

from __future__ import annotations

import json

import pytest

from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.plan_helpers import items, plan_sha, run, write_plan
from tests.promote_helpers import AT, EVALER, PROMOTER, RUN_A, RUN_B, fingerprint, key
from tests.test_086_promote_plan import Room, _codes, _plan_args

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
EPOCHS = (lambda i, e: i % 2 == 0, lambda i, e: i % 10 != 0 or e == 0)


@pytest.fixture
def rsi_room(tmp_path, monkeypatch):
    from opentine._lineage import record
    from tests.key_roles_helpers import pin_roles
    from tests.regions_helpers import pin_regions, policy_role

    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    monkeypatch.delenv("OPENTINE_TRUST_OWNER", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_BUNDLE", raising=False)
    room = Room(tmp_path)
    room.rows = items(40, families=20)
    store = room.repo / ".tine"
    (store / "key-roles.toml").write_bytes(
        (f'version = 1\n[roles]\nscorer = ["{fingerprint(EVALER)}"]\n' + policy_role()).encode()
    )
    pin_roles(store)
    pin_regions(room.repo)  # 0.87: rsi requires a signed region pin
    record(key(PROMOTER), run=RUN_B, artifacts={"code_tree": "sha256:" + "1" * 64},
           store=store / "lineage", parents=["sha256:" + "9" * 64], at=AT)  # fmt: skip
    return room


@pytest.mark.parametrize("correction", ["holm", "bonferroni"])
def test_a_planned_candidate_promotes_with_its_analysis_signed(rsi_room, capsys, correction):
    room = rsi_room
    plan, reveal = write_plan(room.base, room.rows, epochs=3, reducer="pass^k",
                              cluster_key="family", max_candidates=3, correction=correction,
                              resamples=2000)  # fmt: skip
    shape = {"epochs": 3, "cluster_key": "family"}
    base = run(room.base / "base", room.rows, RUN_A, EPOCHS[0], **shape)
    cand = run(room.base / "cand", room.rows, RUN_B, EPOCHS[1], plan=plan, **shape)
    args = ["--baseline-evals", base.as_posix(), "--evals", cand.as_posix()]
    code, row = room.promote(capsys, *args, profile="rsi")
    assert code == 1 and "promote.plan-missing" in _codes(row)
    code, row = room.promote(capsys, *args, *_plan_args(plan, reveal), profile="rsi")
    assert code == 0, row.get("refusals")
    signed = json.loads((room.base / "out" / "decision.json").read_bytes())["claim"]["plan"]
    assert signed["plan_sha256"] == plan_sha(plan) and signed["correction"] == correction
    assert signed["candidates"] == 3 and signed["step"] == 1
    assert signed["corrected_alpha"] == "0.01666666666666666666666666667"  # 0.05 / 3
    assert signed["coverage"] == {"planned": 120, "scored": 120, "skipped": [], "errored": []}
    analysis = signed["analysis"]
    assert analysis["effective_n"] == 20 and analysis["passed"] is True
    assert {"se", "power_at_mde"} <= set(analysis)


def test_a_reveal_signed_before_the_verdicts_is_refused(rsi_room, capsys):
    from opentine import _eval_plan as plans
    from tests.plan_helpers import SECRET

    room = rsi_room
    plan, _ = write_plan(room.base, room.rows)
    early = room.base / "early.json"
    plans.dump(early, plans.make_reveal(key(EVALER), plans.load(plan), SECRET,
                                        "2026-11-01T11:30:00Z"))  # fmt: skip
    code, row = room.promote(capsys, *room.pair(plan=plan), *_plan_args(plan, early),
                             profile="rsi")  # fmt: skip
    assert code == 1 and "promote.seed-not-committed" in _codes(row)


@pytest.mark.usefixtures("isolated_trust_config")
def test_holdout_queries_over_budget_are_counted_and_refuse_under_rsi(tmp_path, capsys):
    from opentine._holdout_query import check_policy, counts, promote_findings
    from tests.holdout_helpers import EVAL, ITEMS, Hold, tine

    hold = Hold(tmp_path)
    assert hold.seal(capsys, "h1", "--max-queries", "2", unseals=3, items=6)[0] == 0
    assert hold.unseal(capsys)[0] == 0
    outs = tmp_path / "outs.jsonl"
    rows = [{"id": i["id"], "output": i["expected"], "run": "run-x"} for i in ITEMS]
    outs.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    for n, node in enumerate(("gen-a", "gen-b", "gen-c")):  # one query per self-chosen name
        code, _ = tine(capsys, "eval", "run", (hold.base / "out" / "released.jsonl").as_posix(),
                       "--outputs", outs.as_posix(), "--scorer", "exact", "--key",
                       hold.keys[EVAL], "--out", (tmp_path / f"e{n}").as_posix(), "--repo",
                       hold.root.as_posix(), "--created-at", f"2026-11-27T10:00:0{n}Z",
                       "--lineage", node, "--json")  # fmt: skip
        assert code == 0
    state = counts(hold.folder(), hold.root)
    assert state["total"] == 3 and state["over_budget"] == ["*"]
    rsi = {"profile": "rsi"}
    check_policy(rsi)
    refused, _ = promote_findings([hold.folder()], hold.root, rsi)
    assert {r["code"] for r in refused} == {"promote.holdout-query-budget"}
