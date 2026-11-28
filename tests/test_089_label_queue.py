"""0.89: rubric label queues -- signed, bound, hash-chained -- against an adversary."""

from __future__ import annotations

import json

import pytest

from opentine import _label_ops as ops
from opentine._label_queue import LABEL, LabelError, folder, read
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import ADMIN, AT, OPT, R1, R2, R3, make_repo, pin, queue  # noqa: F401
from tests.promote_helpers import fingerprint, key


def _log(repo, name="q") -> list[bytes]:
    return (folder(repo, name) / "log.jsonl").read_bytes().split(b"\n")[:-1]


def _write(repo, lines, name="q") -> None:
    (folder(repo, name) / "log.jsonl").write_bytes(b"".join(x + b"\n" for x in lines))


def test_a_label_binds_reviewer_rubric_and_item(repo):
    shas = queue(repo)
    row = ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    assert row["reviewer"] == fingerprint(R1)
    state = read(repo, "q")
    doc = json.loads(_log(repo)[-1])
    assert doc["claim"]["schema"] == LABEL and doc["signer"] == fingerprint(R1)
    assert doc["claim"]["rubric_sha256"] == state["rubric_sha256"]
    assert doc["claim"]["item_sha256"] == shas[0]
    assert state["labels"][fingerprint(R1), shas[0]]["label"] == "good"


def test_the_rubric_is_pinned_by_digest(repo):
    queue(repo)
    lines = _log(repo)
    doc = json.loads(lines[0])
    doc["claim"]["rubric"]["labels"] = ["good", "great"]
    _write(repo, [json.dumps(doc).encode(), *lines[1:]])
    with pytest.raises(LabelError):
        read(repo, "q")


def test_an_optimizer_key_cannot_label_even_when_named_a_reviewer(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    pin(root, extra_reviewers=(OPT,))
    shas = queue(root, reviewers=(R1, OPT))
    with pytest.raises(LabelError) as caught:
        ops.submit(root, "q", shas[0], "good", key(OPT), AT)
    assert caught.value.code == "labels.signer"


def test_an_unpinned_key_cannot_label_or_assign(repo):
    shas = queue(repo)
    stranger = "6f" * 32
    with pytest.raises(LabelError, match="labels.signer"):
        ops.submit(repo, "q", shas[0], "good", key(stranger), AT)
    with pytest.raises(LabelError, match="labels.signer"):
        ops.reassign(repo, "q", shas[0], fingerprint(R1), fingerprint(R3), "x", key(R1), AT)


def test_a_forged_label_line_is_refused_on_read(repo):
    shas = queue(repo)
    ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    lines = _log(repo)
    doc = json.loads(lines[-1])
    doc["claim"]["label"] = "bad"  # edited after signing
    _write(repo, [*lines[:-1], json.dumps(doc).encode()])
    with pytest.raises(LabelError, match="labels.bad-signature"):
        read(repo, "q")


def test_a_label_naming_another_reviewer_is_refused(repo):
    from opentine._label_queue import append

    shas = queue(repo)
    rubric = read(repo, "q")["rubric_sha256"]
    claim = {"schema": LABEL, "item_sha256": shas[0], "label": "good",
             "reviewer": fingerprint(R2), "rubric_sha256": rubric}  # fmt: skip
    with pytest.raises(LabelError, match="labels.signer"):
        append(repo, "q", key(R1), claim, AT)


def test_a_replayed_label_is_refused(repo):
    shas = queue(repo)
    ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    lines = _log(repo)
    _write(repo, [*lines, lines[-1]])  # the same signed line again
    with pytest.raises(LabelError, match="labels.chain"):
        read(repo, "q")


def test_a_label_replayed_from_another_queue_is_refused(repo):
    shas = queue(repo)
    queue(repo, name="other")
    ops.submit(repo, "other", shas[0], "bad", key(R1), AT)
    stolen = _log(repo, "other")[-1]
    _write(repo, [*_log(repo), stolen])
    with pytest.raises(LabelError, match="labels.chain"):
        read(repo, "q")


def test_a_duplicate_label_is_refused(repo):
    shas = queue(repo)
    ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    with pytest.raises(LabelError, match="labels.duplicate"):
        ops.submit(repo, "q", shas[0], "bad", key(R1), AT)
    assert len(read(repo, "q")["labels"]) == 1


def test_an_unassigned_reviewer_cannot_label(repo):
    shas = queue(repo, reviewers=(R1,))
    with pytest.raises(LabelError, match="labels.unassigned"):
        ops.submit(repo, "q", shas[0], "good", key(R2), AT)


def test_a_label_outside_the_rubric_is_refused(repo):
    shas = queue(repo)
    with pytest.raises(LabelError, match="labels.bad-label"):
        ops.submit(repo, "q", shas[0], "fine", key(R1), AT)


def test_reassignment_is_logged_and_moves_the_item(repo):
    shas = queue(repo, reviewers=(R1,))
    ops.reassign(repo, "q", shas[0], fingerprint(R1), fingerprint(R3), "on leave", key(ADMIN), AT)
    with pytest.raises(LabelError, match="labels.unassigned"):
        ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    ops.submit(repo, "q", shas[0], "good", key(R3), AT)
    doc = json.loads(_log(repo)[-2])
    assert doc["claim"]["from"] == fingerprint(R1) and doc["claim"]["reason"] == "on leave"


def test_a_labelled_item_cannot_be_reassigned_away(repo):
    shas = queue(repo, reviewers=(R1,))
    ops.submit(repo, "q", shas[0], "good", key(R1), AT)
    with pytest.raises(LabelError, match="labels.labelled"):
        ops.reassign(repo, "q", shas[0], fingerprint(R1), fingerprint(R3), "x", key(ADMIN), AT)


def test_next_lists_pending_items_without_any_judge_output(repo):
    from tests.label_helpers import outputs, provenance

    shas = queue(repo)
    ops.reveal(repo, "q", provenance(repo / "judge.json"),
               outputs(repo / "out.jsonl", [{"item_sha256": shas[0], "label": "good"}]),
               key(ADMIN), AT)  # fmt: skip
    ops.submit(repo, "q", shas[1], "good", key(R1), AT)
    row = ops.pending(repo, "q", fingerprint(R1))
    assert [r["item_sha256"] for r in row["pending"]] == sorted(set(shas) - {shas[1]})
    assert "judge" not in json.dumps(row) and all(r["item"] for r in row["pending"])


def test_a_missing_queue_fails_closed(repo):
    with pytest.raises(LabelError, match="labels.missing"):
        read(repo, "q")


def test_without_a_pinned_bundle_no_one_may_start_a_queue(tmp_path):
    root = tmp_path / "bare"
    root.mkdir()
    with pytest.raises(LabelError, match="labels.signer"):
        queue(root)


def test_queue_names_are_checked(repo):
    with pytest.raises(LabelError, match="labels.bad-name"):
        folder(repo, "../x")
