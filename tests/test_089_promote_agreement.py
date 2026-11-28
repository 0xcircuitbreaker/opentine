"""0.89: ``tine promote`` and a judged candidate -- the one judge assurance gate.

Advisory by default (D12); refused under ``judge_assurance = "required"`` (and the
rsi profile) when the judge is unvalidated, no queue revealed its signed outcomes,
its recomputed agreement misses the floor, or it is not independent of the candidate.
"""

from __future__ import annotations

import json

import pytest

from opentine import _judge_provenance as jp
from opentine import _lineage
from opentine._eval_run import run_eval
from opentine._eval_scorers import Scorer
from opentine._promote_judges import check_policy, findings
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import ADMIN, SC, outputs, pin, provenance
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
    from opentine.repository import Repo

    room.repo = tmp_path / "repo"
    Repo.init(room.repo)
    pin(room.repo)
    _lineage.record(key("3d" * 32), run=RUN_B, artifacts={"prompt": "sha256:" + "0" * 64},
                    store=room.repo / ".tine" / "lineage", parents=[], at=AT)  # fmt: skip
    return room


def validate(room, capsys, fooled: int = 0):
    """Sign a validation of the judge: four adversarial cases, *fooled* of them wrong."""
    from opentine._label_queue import digest

    cases = [{"id": f"adv-{i}", "input": f"trick {i}", "expected": "bad"} for i in range(4)]
    path = room.base / "adv.jsonl"
    path.write_bytes(b"".join(json.dumps(c).encode() + b"\n" for c in cases))
    signed = outputs(room.base / "adv-out.jsonl", [
        {"item_sha256": digest(c), "label": "good" if i < fooled else "bad"}
        for i, c in enumerate(cases)])  # fmt: skip
    return _tine(capsys, "judge", "validate", "--queue", "q", "--judge",
                 provenance(room.base / "jp.json").as_posix(), "--adversarial", path.as_posix(),
                 "--adversarial-outcomes", signed.as_posix(), "--key",
                 write_key(room.base / "sc.key", SC).as_posix(), "--resamples", "200",
                 "--repo", room.repo.as_posix(), "--json")  # fmt: skip


def _promote(room, capsys, **rule):
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


REQUIRED = {"judge_assurance": "required"}


def _good(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, row = validate(room, capsys)
    assert code == 0, row
    return shas


def test_a_judged_candidate_without_assurance_is_advisory_by_default(room, capsys):
    code, row = _promote(room, capsys)
    assert code == 0, row.get("refusals")
    told = {a["code"] for a in row["advisories"]}
    assert {"advisory:promote.judge-agreement", "advisory:judge.unvalidated"} <= told


def test_a_required_rule_refuses_a_judge_no_queue_revealed(room, capsys):
    code, row = _promote(room, capsys, **REQUIRED)
    assert code == 1 and _codes(row) == {"promote.judge-agreement", "promote.judge-unvalidated"}


def test_a_required_rule_passes_a_validated_judge_humans_agree_with(room, capsys):
    _good(room, capsys)
    code, row = _promote(room, capsys, **REQUIRED)
    assert code == 0, row.get("refusals")
    assert not {a["code"] for a in row["advisories"]} & {"advisory:promote.judge-agreement",
                                                       "advisory:judge.unvalidated"}  # fmt: skip


def test_agreement_without_a_validation_record_is_refused(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, row = _promote(room, capsys, **REQUIRED)
    assert code == 1 and _codes(row) == {"promote.judge-unvalidated"}


def test_a_fooled_judge_cannot_be_validated(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    code, row = validate(room, capsys, fooled=1)
    assert code == 1 and "judge.validation-failed" in row["error"]["message"]


def test_a_required_rule_refuses_a_judge_below_the_floor(room, capsys):
    shas = labelled(room.repo)
    _reveal(room.repo, [{"item_sha256": s, "label": "good"} for s in shas])  # always "good"
    code, row = validate(room, capsys)
    assert code == 1 and "floor" in row["error"]["message"]
    code, row = _promote(room, capsys, **REQUIRED)
    assert code == 1 and _codes(row) == {"promote.judge-agreement", "promote.judge-unvalidated"}


def test_a_stricter_policy_floor_is_recomputed_not_read_from_the_record(room, capsys):
    _good(room, capsys)
    log = room.repo / ".tine" / "labels" / "q"
    assert log.is_dir()
    code, row = _promote(room, capsys, **REQUIRED, agreement_min_items=1000)
    assert code == 1 and _codes(row) == {"promote.judge-agreement"}


def test_a_tampered_queue_fails_closed(room, capsys):
    _good(room, capsys)
    log = room.repo / ".tine" / "labels" / "q" / "log.jsonl"
    lines = log.read_bytes().split(b"\n")
    lines[-3] = lines[-3].replace(b'"label":"bad"', b'"label":"good"')
    log.write_bytes(b"\n".join(lines))
    code, row = _promote(room, capsys, **REQUIRED)
    assert code == 1 and "does not verify" in row["refusals"][0]["detail"]


def test_the_rsi_profile_requires_judge_assurance():
    rule = {"profile": "rsi"}
    check_policy(rule)
    assert rule["judge_assurance"] == "required" and rule["agreement_floor"] == "0.6"
    with pytest.raises(ValueError):
        check_policy({"profile": "rsi", "judge_assurance": "advisory"})
    for bad in ({"agreement_floor": "2"}, {"agreement_floor": True},
                {"agreement_min_coverage": "1.5"}, {"agreement_min_items": -1}):  # fmt: skip
        with pytest.raises(ValueError):
            check_policy(bad)


def test_a_candidate_without_a_judge_is_not_affected(tmp_path):
    folder = make_eval(tmp_path / "plain", RUN_B, lambda i: True)
    assert findings(dict(REQUIRED), tmp_path, RUN_B, None, {"evals": folder}) == ([], [])
