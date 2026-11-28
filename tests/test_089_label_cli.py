"""0.89: ``tine label`` end to end; every ``--json`` output validates against its schema."""

from __future__ import annotations

import json

import pytest

from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.label_helpers import (
    ADMIN,
    OPT,
    R1,
    R2,
    RUBRIC,
    items,
    outputs,
    pin,
    provenance,
    write_items,
)
from tests.promote_helpers import fingerprint, write_key
from tests.test_058_promote import _tine

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


@pytest.fixture
def room(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    pin(repo)
    keys = {s: write_key(tmp_path / f"{s[:2]}.key", s).as_posix() for s in (ADMIN, R1, R2, OPT)}
    (tmp_path / "rubric.json").write_bytes(json.dumps(RUBRIC).encode())
    return tmp_path, repo, keys


def _label(capsys, repo, *argv):
    return _tine(capsys, "label", *argv, "--repo", repo.as_posix(), "--json")


def test_the_label_flow_through_the_cli(room, capsys):
    base, repo, keys = room
    code, row = _label(capsys, repo, "init", "q", "--rubric", (base / "rubric.json").as_posix(),
                       "--key", keys[ADMIN])  # fmt: skip
    assert code == 0 and row["rubric"]["labels"] == ["good", "bad"]
    path = write_items(base / "items.jsonl", items(3))
    reviewers = ["--reviewer", fingerprint(R1), "--reviewer", fingerprint(R2)]
    code, row = _label(capsys, repo, "assign", "q", "--items", path.as_posix(), *reviewers,
                       "--key", keys[ADMIN])  # fmt: skip
    assert code == 0 and row["assigned"] == 6
    code, row = _label(capsys, repo, "next", "q", "--reviewer", fingerprint(R1))
    shas = [r["item_sha256"] for r in row["pending"]]
    assert code == 0 and len(shas) == 3
    for sha in shas:
        for who in (R1, R2):
            code, row = _label(capsys, repo, "submit", "q", "--item", sha, "--label", "good",
                               "--key", keys[who])  # fmt: skip
            assert code == 0, row
    code, row = _label(capsys, repo, "submit", "q", "--item", shas[0], "--label", "bad",
                       "--key", keys[R1])  # fmt: skip
    assert code == 1  # a duplicate label
    code, row = _label(capsys, repo, "submit", "q", "--item", shas[0], "--label", "bad",
                       "--key", keys[OPT])  # fmt: skip
    assert code == 1  # the optimizer is no reviewer
    judge = provenance(base / "judge.json")
    out = outputs(base / "out.jsonl", [{"item_sha256": s, "abstain": True} for s in shas])
    code, row = _label(capsys, repo, "reveal", "q", "--judge", judge.as_posix(), "--outputs",
                       out.as_posix(), "--key", keys[ADMIN])  # fmt: skip
    assert code == 0 and row["judge"].startswith("jp1+sha256:")
    code, row = _label(capsys, repo, "reassign", "q", "--item", shas[0], "--from",
                       fingerprint(R1), "--to", fingerprint(OPT), "--reason", "x",
                       "--key", keys[ADMIN])  # fmt: skip
    assert code == 1  # R1 already labelled it
    agree = ["judge", "agreement", "--queue", "q", "--resamples", "50", "--repo",
             repo.as_posix(), "--json"]  # fmt: skip
    code, row = _tine(capsys, *agree)
    assert code == 0 and not row["ok"] and row["advisory"]  # one category only, undefined
    assert row["human"]["krippendorff"]["value"] is None
    judge = row["judges"][0]
    assert judge["abstained"] == 3 and judge["judge_vs_consensus"]["value"] is None
    code, row = _tine(capsys, *agree, "--strict")
    assert code == 1
    code, row = _tine(capsys, "label", "agree", "q", "--repo", repo.as_posix())
    assert code == 2  # one home for agreement: tine judge agreement
