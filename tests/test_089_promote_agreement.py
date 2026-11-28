"""0.89: ``tine promote`` and a judged candidate -- the judge-agreement floor.

Advisory by default (D12); refused under ``judge_agreement = "required"`` (and the
rsi profile) when no queue revealed the judge, or the judge misses the floor.
"""

from __future__ import annotations

import pytest

from opentine import _judge_provenance as jp
from opentine._eval_run import run_eval
from opentine._eval_scorers import Scorer
from opentine._promote_agreement import check_policy, findings, judges
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import ADMIN, pin, provenance
from tests.promote_helpers import AT, EVALER, RUN_A, RUN_B, key, make_eval, policy, write_key
from tests.test_058_promote import Room, _codes, _tine
from tests.test_089_judge_agreement import _reveal, labelled, truth

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


JUDGE_RUN = "run:sha256:" + "d" * 64


def _judged(out, doc: dict, run: str, passing, n: int = 40):
    """An eval of *n* items scored by the judge *doc* pins; item i passes when ``passing(i)``."""
    items = [{"id": f"main-{i:03d}", "input": f"main {i}", "expected": "yes"} for i in range(n)]
    outputs = {row["id"]: {"output": "yes", "run": run} for row in items}

    def score(item, output):
        return (1.0 if passing(int(item["id"][-3:])) else 0.0), JUDGE_RUN

    scorer = Scorer(id="llm-judge", version=jp.pin(doc), config={"provenance": doc}, func=score)
    run_eval(items, scorer, key(EVALER), out, outputs=outputs, created_at=AT)
    return out


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "config").as_posix())
    room = Room(tmp_path)
    room.repo = tmp_path / "repo"
    room.repo.mkdir()
    pin(room.repo)
    return room


def _promote(room, capsys, **rule):
    import json

    doc = json.loads(provenance(room.base / "jp.json").read_bytes())
    base = _judged(room.base / "base", doc, RUN_A, lambda i: i % 2 == 0)
    cand = _judged(room.base / "cand", doc, RUN_B, lambda i: i % 10 != 0)
    pol = policy(room.base, require_holdout=False, **rule)
    signed = room.base / "policy.att.json"
    code, row = _tine(capsys, "promote", pol.as_posix(), "--sign-policy", "--key",
                      write_key(room.base / "admin.key", ADMIN).as_posix(), "--out",
                      signed.as_posix(), "--json")  # fmt: skip
    assert code == 0, row
    return room.promote(capsys, RUN_B, "--baseline-evals", base.as_posix(), "--evals",
                        cand.as_posix(), "--approval", room.approve(capsys, RUN_B).as_posix(),
                        "--spent", "1", "--repo", room.repo.as_posix(),
                        "--policy-attestation", signed.as_posix(), pol=pol)  # fmt: skip


def test_a_judged_candidate_without_agreement_is_advisory_by_default(room, capsys):
    code, row = _promote(room, capsys)
    assert code == 0, row.get("refusals")
    assert "advisory:promote.judge-agreement" in {a["code"] for a in row["advisories"]}


def test_a_required_rule_refuses_a_judge_no_queue_revealed(room, capsys):
    code, row = _promote(room, capsys, judge_agreement="required")
    assert code == 1 and _codes(row) == {"promote.judge-agreement"}


def test_a_required_rule_passes_a_judge_humans_agree_with(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, row = _promote(room, capsys, judge_agreement="required")
    assert code == 0, row.get("refusals")
    assert "advisory:promote.judge-agreement" not in {a["code"] for a in row["advisories"]}


def test_a_required_rule_refuses_a_judge_below_the_floor(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": "good"} for s in shas])  # always "good"
    code, row = _promote(room, capsys, judge_agreement="required")
    assert code == 1 and _codes(row) == {"promote.judge-agreement"}


def test_a_tampered_queue_fails_closed(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    log = room.repo / ".tine" / "labels" / "q" / "log.jsonl"
    lines = log.read_bytes().split(b"\n")
    lines[-3] = lines[-3].replace(b'"label":"bad"', b'"label":"good"')
    log.write_bytes(b"\n".join(lines))
    code, row = _promote(room, capsys, judge_agreement="required")
    assert code == 1 and "does not verify" in row["refusals"][0]["detail"]


def test_the_rsi_profile_requires_judge_agreement():
    rule = {"profile": "rsi"}
    check_policy(rule)
    assert rule["judge_agreement"] == "required" and rule["agreement_floor"] == "0.6"
    with pytest.raises(ValueError):
        check_policy({"profile": "rsi", "judge_agreement": "advisory"})
    with pytest.raises(ValueError):
        check_policy({"agreement_floor": "2"})


def test_a_candidate_without_a_judge_is_not_affected(tmp_path):
    folder = make_eval(tmp_path / "plain", RUN_B, lambda i: True)
    assert judges(folder) == []
    assert findings({"judge_agreement": "required"}, tmp_path, folder) == ([], [])
