"""0.89: a judge's agreement with the human consensus; abstentions and errors are not scores."""

from __future__ import annotations

import pytest

from opentine import _label_ops as ops
from opentine._judge_outcomes import parse
from opentine._label_queue import LabelError, folder, read
from opentine._label_report import report, settings
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import (  # noqa: F401
    ADMIN,
    AT,
    OPT,
    R1,
    R2,
    R3,
    SC,
    judge_doc,
    make_repo,
    outputs,
    provenance,
    queue,
)
from tests.promote_helpers import key

N = 24


def truth(i: int) -> str:
    return "good" if i % 2 == 0 else "bad"


def labelled(repo, n: int = N) -> list[str]:
    """Three reviewers label *n* items; R3 disagrees on every sixth one."""
    shas = queue(repo, n=n, reviewers=(R1, R2, R3))
    state = read(repo, "q")
    for i, sha in enumerate(shas):
        for who in (R1, R2):
            ops.submit(repo, "q", sha, truth(i), key(who), AT, state)
        flip = "bad" if truth(i) == "good" else "good"
        ops.submit(repo, "q", sha, flip if i % 6 == 0 else truth(i), key(R3), AT, state)
    return shas


def _reveal(repo, rows, prompt="Judge it") -> str:
    found = ops.reveal(repo, "q", provenance(repo / f"judge-{prompt}.json", prompt),
                       outputs(repo / f"out-{prompt}.jsonl", rows, prompt), key(ADMIN),
                       AT)  # fmt: skip
    return found["judge"]


def _opts(**kw):
    return settings(resamples=200, **kw)


def test_a_judge_that_agrees_with_the_consensus_passes(repo):
    shas = labelled(repo)
    _reveal(repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    found = report(repo, "q", _opts())
    judge = found["judges"][0]
    assert judge["judge_vs_consensus"]["value"] == "1.000000" and judge["floor_ok"]
    assert judge["compared"] == N and judge["coverage"] == "1.000000"
    assert found["human"]["reviewers"] == 3 and found["human"]["primary"] == "krippendorff"


def test_a_judge_humans_disagree_with_fails_the_floor(repo):
    shas = labelled(repo)
    _reveal(repo, [{"item_sha256": s, "label": "good" if i % 3 == 0 else "bad"}
                   for i, s in enumerate(shas)])  # fmt: skip
    judge = report(repo, "q", _opts())["judges"][0]
    assert not judge["floor_ok"] and judge["reasons"]


def test_abstentions_are_not_scores_and_lower_coverage(repo):
    shas = labelled(repo)
    rows = [{"item_sha256": s, "abstain": True} if i % 2 else {"item_sha256": s, "label": truth(i)}
            for i, s in enumerate(shas)]  # fmt: skip
    _reveal(repo, rows)
    judge = report(repo, "q", _opts())["judges"][0]
    assert judge["abstained"] == N // 2 and judge["compared"] == N // 2
    assert judge["coverage"] == "0.500000" and not judge["floor_ok"]
    # Only "good" items were answered: kappa is undefined, never a pass.
    assert judge["judge_vs_consensus"]["value"] is None


def _pin(prompt="Judge it"):
    from opentine._judge_provenance import pin

    return pin(judge_doc(prompt))


def test_unparsable_off_rubric_and_unsigned_outputs_are_errors_never_zero(repo):
    sha = "a" * 64
    signed = outputs(repo / "s.jsonl", [{"item_sha256": sha, "label": "maybe"}]).read_bytes()
    plain = b'{"item_sha256": "%s", "label": "good"}\n' % ("c" * 64).encode()
    raw = b"not json\n" + signed + plain
    found, errors = parse(raw, _pin(), repo / ".tine", ["good", "bad"])
    assert found == {} and errors == 3


def test_an_item_answered_twice_counts_as_errors(repo):
    raw = outputs(repo / "s.jsonl", [{"item_sha256": "b" * 64, "label": "good"}]).read_bytes()
    assert parse(raw * 2, _pin(), repo / ".tine", ["good", "bad"]) == ({}, 2)


@pytest.mark.parametrize("case", ["plain", "optimizer", "other-judge"])
def test_a_reveal_takes_only_outcomes_signed_for_that_judge(repo, case):
    """Judge outcomes are bound to the judge: a plain file, a non-scorer key or another pin."""
    shas = labelled(repo, n=4)
    rows = [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)]
    path = repo / "out.jsonl"
    if case == "plain":
        path.write_bytes(b"".join(b'{"item_sha256": "%s", "label": "good"}\n' % s.encode()
                                  for s in shas))  # fmt: skip
    else:
        outputs(path, rows, "Other judge" if case == "other-judge" else "Judge it",
                signer=OPT if case == "optimizer" else SC)  # fmt: skip
    with pytest.raises(LabelError, match="labels.bad-input"):
        ops.reveal(repo, "q", provenance(repo / "judge.json"), path, key(ADMIN), AT)


def test_agreeing_humans_cannot_carry_a_random_judge_over_the_floor(repo):
    import random

    rng = random.Random(7)
    shas = labelled(repo, n=40)
    _reveal(repo, [{"item_sha256": s, "label": rng.choice(["good", "bad"])} for s in shas])
    judge = report(repo, "q", _opts())["judges"][0]
    assert not judge["floor_ok"] and judge["multi_rater"]["value"] is not None


def test_a_point_estimate_above_the_floor_with_a_low_bound_fails(repo):
    shas = labelled(repo)
    flip = {1, 2, 4, 6}
    _reveal(repo, [{"item_sha256": s, "label": ("bad" if truth(i) == "good" else "good")
                    if i in flip else truth(i)} for i, s in enumerate(shas)])  # fmt: skip
    judge = report(repo, "q", _opts())["judges"][0]
    assert float(judge["judge_vs_consensus"]["value"]) > 0.6 and not judge["floor_ok"]
    assert float(judge["judge_vs_consensus"]["lower"]) < 0.6


def test_labels_given_after_the_reveal_do_not_count(repo):
    shas = queue(repo, n=4, reviewers=(R1, R2))
    state = read(repo, "q")
    for who in (R1, R2):
        ops.submit(repo, "q", shas[0], "good", key(who), AT, state)
    _reveal(repo, [{"item_sha256": s, "label": "good"} for s in shas])
    state = read(repo, "q")
    for who in (R1, R2):
        ops.submit(repo, "q", shas[1], "good", key(who), AT, state)
    judge = report(repo, "q", _opts(min_items=0))["judges"][0]
    assert judge["consensus_items"] == 1
    assert report(repo, "q", _opts())["human"]["items"] == 2


def test_altered_judge_outputs_make_the_report_fail(repo):
    shas = labelled(repo, n=4)
    _reveal(repo, [{"item_sha256": s, "label": "good"} for s in shas])
    path = next((folder(repo, "q") / "judge").iterdir())
    path.write_bytes(path.read_bytes().replace(b"good", b"bad", 1))
    with pytest.raises(LabelError, match="labels.chain"):
        report(repo, "q", _opts())


def test_two_reviewers_use_cohen_and_ties_are_left_out(repo):
    shas = queue(repo, n=4, reviewers=(R1, R2))
    state = read(repo, "q")
    for i, sha in enumerate(shas):
        ops.submit(repo, "q", sha, truth(i), key(R1), AT, state)
        ops.submit(repo, "q", sha, truth(i) if i else "bad", key(R2), AT, state)
    _reveal(repo, [{"item_sha256": s, "label": truth(i)} for i, s in enumerate(shas)])
    found = report(repo, "q", _opts(min_items=0))
    assert found["human"]["primary"] == "cohen" and found["human"]["cohen"]["value"] is not None
    assert found["judges"][0]["ties"] == 1 and found["judges"][0]["consensus_items"] == 3


def test_settings_are_checked():
    with pytest.raises(ValueError):
        settings(floor="1.5")
    with pytest.raises(ValueError):
        settings(alpha="0")
