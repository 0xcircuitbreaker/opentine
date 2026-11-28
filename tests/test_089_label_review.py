"""0.89 review: holes a loop could use against label queues and the agreement gate."""

from __future__ import annotations

import json

import pytest

from opentine import _label_ops as ops
from opentine._eval_run import run_eval
from opentine._eval_scorers import Scorer
from opentine._label_queue import LabelError
from opentine._label_report import settings
from opentine._promote_judges import check_policy, findings
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import ADMIN, AT, R1, RUBRIC, items, write_items
from tests.promote_helpers import EVALER, fingerprint, key

RUN = "run:sha256:" + "e" * 64


def _pin_both(repo):
    """ADMIN holds policy and reviewer, so it could assign items to itself."""
    from tests.key_roles_helpers import pin_roles

    store = repo / ".tine"
    store.mkdir(parents=True, exist_ok=True)
    both = fingerprint(ADMIN)
    text = (f'version = 1\n[roles]\npolicy = ["{both}"]\n'
            f'reviewer = ["{both}", "{fingerprint(R1)}"]\n')  # fmt: skip
    (store / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(store)


def test_the_assigning_key_cannot_assign_an_item_to_itself(tmp_path):
    _pin_both(tmp_path)
    rubric = tmp_path / "rubric.json"
    rubric.write_bytes(json.dumps(RUBRIC).encode())
    ops.init(tmp_path, "q", rubric, key(ADMIN), AT)
    rows = write_items(tmp_path / "items.jsonl", items(2))
    with pytest.raises(LabelError) as caught:
        ops.assign(tmp_path, "q", rows, [fingerprint(ADMIN)], key(ADMIN), AT)
    assert caught.value.code == "labels.self-assign"
    ops.assign(tmp_path, "q", rows, [fingerprint(R1)], key(ADMIN), AT)  # another reviewer is fine


@pytest.mark.parametrize("value", ["1e999999999", "nan", "inf", "1/2", " 0.6", "-0", "0x1"])
def test_agreement_numbers_are_plain_decimals(value):
    with pytest.raises(ValueError):
        settings(floor=value)
    with pytest.raises(ValueError):
        check_policy({"judge_assurance": "required", "agreement_floor": value})


def test_a_judge_verdict_without_a_provenance_pin_is_refused_when_required(tmp_path):
    """An llm-judge whose scorer_version is not a ``jp1+sha256:`` pin cannot dodge the gate."""
    rows = [{"id": f"m-{i}", "input": "x", "expected": "yes"} for i in range(3)]
    outputs = {r["id"]: {"output": "yes", "run": "run:sha256:" + "a" * 64} for r in rows}
    scorer = Scorer(id="llm-judge", version="renamed-judge-v2", config={},
                    func=lambda item, out: (1.0, "run:sha256:" + "d" * 64))  # fmt: skip
    run_eval(rows, scorer, key(EVALER), tmp_path / "ev", outputs=outputs, created_at=AT)
    required = {"judge_assurance": "required"}
    check_policy(required)
    refused, _ = findings(required, tmp_path, RUN, None, {"evals": tmp_path / "ev"})
    assert [r["code"] for r in refused] == ["promote.judge-unvalidated"]
    advisory = {}
    check_policy(advisory)
    refused, advised = findings(advisory, tmp_path, RUN, None, {"evals": tmp_path / "ev"})
    assert refused == [] and [a["code"] for a in advised] == ["advisory:judge.unvalidated"]


def test_a_reveal_cannot_carry_plain_judge_labels(tmp_path):
    """Judge outcomes are bound to the judge: an unsigned outputs file is refused."""
    from tests.label_helpers import pin, provenance, queue

    pin(tmp_path)
    shas = queue(tmp_path, n=2)
    path = tmp_path / "plain.jsonl"
    path.write_bytes(b"".join(json.dumps({"item_sha256": s, "label": "good"}).encode() + b"\n"
                              for s in shas))  # fmt: skip
    with pytest.raises(LabelError, match="judge.outcome-unsigned"):
        ops.reveal(tmp_path, "q", provenance(tmp_path / "j.json"), path, key(ADMIN), AT)
