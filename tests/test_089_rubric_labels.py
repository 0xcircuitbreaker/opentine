"""0.89: human rubric labels are signed by pinned reviewers, bound to rubric and item, held."""

from __future__ import annotations

import pytest

from opentine import _rubric_labels, _schemas
from opentine.repository._holds import HoldError, release
from tests.judge_helpers import (  # noqa: F401
    BOTH,
    OPTIMIZER,
    OTHER,
    REV1,
    REV2,
    common,
    judge_room,
    label,
    write_jsonl,
)  # fmt: skip
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.query_helpers import tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _labels(room: dict) -> dict:
    rubric = _rubric_labels.rubric_digest((room["base"] / "rubric.md").read_bytes())
    from opentine._eval_dataset import item_digest

    items = {i["id"]: item_digest(i) for i in room["items"]}
    return _rubric_labels.labels(room["repo"], rubric, items)


def test_a_pinned_reviewer_label_counts_and_is_held(room, capsys):
    code, out = label(capsys, room, "i1", "pass", REV1)
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    claim = out["claim"]
    assert claim["reviewer"].startswith("sha256:") and claim["item"] == "i1"
    found = _labels(room)
    assert found["labels"] == {"i1": {claim["reviewer"]: "pass"}}
    with pytest.raises(HoldError):
        release(room["repo"], "rubric-label:" + claim["rubric"])


@pytest.mark.parametrize("seed", [OPTIMIZER, OTHER, BOTH])
def test_optimizer_unpinned_and_dual_role_keys_cannot_label(room, capsys, seed):
    code, out = label(capsys, room, "i1", "pass", seed)
    assert code == 1 and "judge.label-signer" in out["error"]["message"]
    assert _labels(room)["labels"] == {}


def test_a_label_does_not_carry_over_to_an_edited_item_or_another_rubric(room, capsys):
    assert label(capsys, room, "i2", "fail", REV1)[0] == 0
    edited = [dict(i, expected="y") if i["id"] == "i2" else i for i in room["items"]]
    write_jsonl(room["base"] / "items.jsonl", edited)
    found = _labels({**room, "items": edited})
    assert found["labels"] == {} and "another version" in found["ignored"][0]["reason"]
    (room["base"] / "rubric.md").write_bytes(b"a different rubric\n")
    assert _labels({**room, "items": edited})["ignored"] == []  # not even read: other hold


def test_two_labels_from_one_reviewer_conflict_and_neither_counts(room, capsys):
    assert label(capsys, room, "i3", "pass", REV1)[0] == 0
    assert label(capsys, room, "i3", "fail", REV1)[0] == 0
    assert label(capsys, room, "i3", "pass", REV2)[0] == 0
    found = _labels(room)
    assert len(found["labels"]["i3"]) == 1 and found["conflicts"][0]["labels"] == ["fail", "pass"]


def test_a_forged_claim_with_another_reviewer_is_refused(room):
    from opentine import _containment_records
    from tests.promote_helpers import fingerprint, key

    claim = {"convention": _rubric_labels.CONVENTION, "rubric": "sha256:" + "0" * 64,
             "item": "i1", "item_digest": "sha256:" + "1" * 64, "label": "pass",
             "reviewer": fingerprint(REV1), "at": "2026-12-01T10:00:00Z"}  # fmt: skip
    with pytest.raises(_rubric_labels.LabelError, match="judge.label-signer"):
        _rubric_labels.record(room["repo"], claim, key(OTHER))
    # signed directly by another key, bypassing the check: read back as not counting
    _containment_records.record(room["repo"], _containment_records.anchor(room["repo"], "x", "y"),
                                claim, key(OTHER), "rubric-label:" + claim["rubric"])  # fmt: skip
    found = _rubric_labels.labels(room["repo"], claim["rubric"], {"i1": claim["item_digest"]})
    assert found["labels"] == {} and found["ignored"][0]["reason"] == (
        "not signed by its reviewer key"
    )


def test_the_queue_assigns_reproducibly_and_shows_pending(room, capsys):
    code, out = tine(capsys, "judge", "queue", *common(room), "--per-item", "1")
    assert code == 0, out
    _schemas.validate(out, "tine-cli-judge-1")
    assert out["pinned"] and len(out["reviewers"]) == 2  # the dual-role key is not a reviewer
    assigned = [i for row in out["reviewers"].values() for i in row["assigned"]]
    assert sorted(assigned) == sorted(i["id"] for i in room["items"])
    again = tine(capsys, "judge", "queue", *common(room), "--per-item", "1")[1]
    assert again == out
    reviewer, row = next(iter(out["reviewers"].items()))
    seed = REV1 if _fp(REV1) == reviewer else REV2
    other = REV2 if seed == REV1 else REV1
    assert label(capsys, room, row["assigned"][0], "pass", seed)[0] == 0
    assert label(capsys, room, row["assigned"][0], "pass", other)[0] == 0
    after = tine(capsys, "judge", "queue", *common(room), "--per-item", "1")[1]
    assert row["assigned"][0] not in after["reviewers"][reviewer]["pending"]
    assert after["unassigned_labels"] == [{"item": row["assigned"][0], "reviewer": _fp(other)}]


def _fp(seed: str) -> str:
    from tests.promote_helpers import fingerprint

    return fingerprint(seed)
