"""0.69 acceptance, end to end: two loops branch from one base, each changes its own
history, and ``tine merge-history`` lands the union as ref updates plus one signed,
held ``opentine.history-merge/1`` record that verifies under pinned roles, from
either side, and shows in the query index. A ref moved onto a held object, or a
dropped hold, is a conflict and nothing moves; an optimizer key cannot apply.
Every assertion counts rows or compares values; nothing is timed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas
from opentine.repository import Repo
from opentine.repository._holds import holds_path, read_holds
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import fingerprint, write_key
from tests.query_helpers import add_run, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
AT = "2026-12-01T10:00:00Z"
POLICY, OPTIMIZER = "69" * 32, "7c" * 32


@pytest.fixture
def lab(tmp_path: Path, monkeypatch) -> dict:
    for name in ("OPENTINE_OUTPUT", "OPENTINE_FORMAT"):
        monkeypatch.delenv(name, raising=False)
    repo = Repo.init(tmp_path / "r")
    runs = {name: add_run(repo, name, cost=0.1) for name in ("main", "a", "b", "bad")}
    repo.update_ref("heads/main", runs["main"])
    write_key(tmp_path / "policy.key", POLICY)
    write_key(tmp_path / "optimizer.key", OPTIMIZER)
    text = (f'version = 1\n[roles]\npolicy = ["{fingerprint(POLICY)}"]\n'
            f'optimizer = ["{fingerprint(OPTIMIZER)}"]\n')  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    return {"base": tmp_path, "repo": repo, "runs": runs}


def _mh(capsys, lab: dict, *argv: str) -> tuple[int, dict]:
    code, out = tine(capsys, "merge-history", argv[0], "--repo", (lab["base"] / "r").as_posix(),
                     *argv[1:], "--json")  # fmt: skip
    _schemas.validate(out, "tine-cli-merge-history-1")
    return code, out


def _write(lab: dict, name: str, snap: dict) -> str:
    path = lab["base"] / name
    path.write_bytes(json.dumps(snap, sort_keys=True).encode("utf-8"))
    return path.as_posix()


def _branch(capsys, lab: dict) -> tuple[str, str, dict]:
    """Base snapshot, then loop B's side: a new ref and a new stop hold."""
    base = _mh(capsys, lab, "snapshot")[1]["snapshot"]
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/loop-b"] = lab["runs"]["b"]
    theirs["holds"].append(["loop-stop:loop-b", lab["runs"]["bad"]])
    return _write(lab, "base.json", base), _write(lab, "theirs.json", theirs), base


def _apply(capsys, lab: dict, base: str, theirs: str, who: str) -> tuple[int, dict]:
    return _mh(capsys, lab, "apply", "--base", base, "--theirs", theirs, "--key",
               (lab["base"] / f"{who}.key").as_posix(), "--target", "heads/loop-b",
               "--at", AT)  # fmt: skip


def test_two_loops_merge_into_one_signed_held_queryable_history(lab, capsys) -> None:
    base, theirs, _ = _branch(capsys, lab)
    lab["repo"].update_ref("heads/loop-a", lab["runs"]["a"])  # loop A, on this side
    code, out = _apply(capsys, lab, base, theirs, "policy")
    assert code == 0 and out["applied"] and out["conflicts"] == []
    repo = lab["repo"]
    assert repo.read_ref("heads/loop-a") == lab["runs"]["a"]
    assert repo.read_ref("heads/loop-b") == lab["runs"]["b"]
    targets = {(r["target"], r["oid"]) for r in read_holds(holds_path(repo))}
    assert ("loop-stop:loop-b", lab["runs"]["bad"]) in targets
    assert any(t.startswith("history-merge:") and o == out["record"] for t, o in targets)

    ours = _write(lab, "ours.json", out["ours"])
    for a, b in ((ours, theirs), (theirs, ours)):
        code, check = _mh(capsys, lab, "verify", out["record"], "--base", base, "--ours", a,
                          "--theirs", b)  # fmt: skip
        assert code == 0 and check["ok"] and check["signers"] == "pinned"
        assert check["signer_trusted"] and check["merged"] == out["digests"]["merged"]

    claim = repo.get(out["record"]).payload()["claim"]  # an attestation, no new object kind
    assert claim["convention"] == "opentine.history-merge/1"
    code, body = tine(
        capsys, "query", "index", "--rebuild", "--repo", (lab["base"] / "r").as_posix()
    )
    assert code == 0 and body["counts"]["history_merges"] == 1
    code, rows = tine(capsys, "query", "SELECT * FROM history_merges", "--repo",
                      (lab["base"] / "r").as_posix(), "--verify", "--strict")  # fmt: skip
    _schemas.validate(rows, "tine-cli-query-1")
    assert code == 0 and rows["verification"]["counts"] == {"verified": 1, "unverified": 0,
                                                            "failed": 0}  # fmt: skip
    (row,) = rows["rows"]
    assert (row["oid"], row["ref"], row["conflicts"], row["signed"]) == (
        out["record"], "heads/loop-b", 0, 1)  # fmt: skip
    assert row["merged"] == out["digests"]["merged"]


def test_the_optimizer_key_cannot_apply_a_merge(lab, capsys) -> None:
    base, theirs, _ = _branch(capsys, lab)
    code, _ = _apply(capsys, lab, base, theirs, "optimizer")
    assert code != 0
    assert lab["repo"].read_ref("heads/loop-b") is None
    assert not [r for r in read_holds(holds_path(lab["repo"]))
                if r["target"].startswith("history-merge:")]  # fmt: skip


def test_a_ref_onto_a_stopped_run_or_a_dropped_hold_is_a_conflict(lab, capsys) -> None:
    from opentine.repository import _holds

    lab["repo"].update_ref("heads/bad", lab["runs"]["bad"])
    _holds.add(lab["repo"], "heads/bad")
    base = _mh(capsys, lab, "snapshot")[1]["snapshot"]
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/main"] = lab["runs"]["bad"]
    taint = ["integrity-taint:t1", lab["runs"]["bad"]]
    theirs["holds"].append(taint)
    files = _write(lab, "base.json", base), _write(lab, "theirs.json", theirs)
    code, out = _apply(capsys, lab, *files, "policy")
    assert code == 1 and not out["applied"]
    assert "held-target" in {c["kind"] for c in out["conflicts"]}
    assert lab["repo"].read_ref("heads/main") == lab["runs"]["main"]

    dropped = {**base, "holds": []}
    code, out = _mh(capsys, lab, "plan", "--base", files[0], "--theirs",
                    _write(lab, "dropped.json", dropped))  # fmt: skip
    assert code == 1 and [c["kind"] for c in out["conflicts"]] == ["hold-weakened"]
