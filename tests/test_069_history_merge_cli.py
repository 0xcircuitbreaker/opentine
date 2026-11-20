"""0.69: ``tine merge-history`` end to end: plan, apply, verify, queue, holds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _schemas
from opentine.coord import _merge_queue
from opentine.repository import Repo
from opentine.repository._holds import HoldError, holds_path, read_holds, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import fingerprint, write_key
from tests.query_helpers import add_run, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
AT = "2026-12-01T10:00:00Z"


@pytest.fixture
def room(tmp_path: Path) -> dict:
    repo = Repo.init(tmp_path / "r")
    runs = {name: add_run(repo, name, cost=0.1) for name in ("main", "a", "b")}
    repo.update_ref("heads/main", runs["main"])
    write_key(tmp_path / "k.key", "69" * 32)
    return {"base": tmp_path, "repo": repo, "runs": runs}


def _run(capsys, room: dict, *argv: str) -> tuple[int, dict]:
    code, out = tine(capsys, "merge-history", argv[0], "--repo", (room["base"] / "r").as_posix(),
                     *argv[1:], "--json")  # fmt: skip
    _schemas.validate(out, "tine-cli-merge-history-1")
    return code, out


def _write(room: dict, name: str, snap: dict) -> str:
    path = room["base"] / name
    path.write_bytes(json.dumps(snap).encode("utf-8"))
    return path.as_posix()


def _snap(capsys, room: dict) -> dict:
    code, out = _run(capsys, room, "snapshot")
    assert code == 0
    return out["snapshot"]


def test_apply_lands_the_other_side_with_a_held_record_that_verifies(room, capsys) -> None:
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/release"] = room["runs"]["b"]
    theirs["holds"].append(["loop-stop:l1", room["runs"]["a"]])
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, out = _run(capsys, room, "plan", "--base", files[0], "--theirs", files[1])
    assert code == 0 and out["conflicts"] == []
    code, out = _run(capsys, room, "apply", "--base", files[0], "--theirs", files[1],
                     "--key", (room["base"] / "k.key").as_posix(), "--target", "heads/release",
                     "--at", AT)  # fmt: skip
    assert code == 0 and out["refs_moved"] == ["heads/release"]
    assert room["repo"].read_ref("heads/release") == room["runs"]["b"]
    ours = _write(room, "ours.json", out["ours"])
    code, check = _run(capsys, room, "verify", out["record"], "--base", files[0],
                       "--ours", ours, "--theirs", files[1])  # fmt: skip
    assert code == 0 and check["ok"] and check["merged"] == out["digests"]["merged"]
    swapped = _run(capsys, room, "verify", out["record"], "--base", files[0],
                   "--ours", files[1], "--theirs", ours)[1]  # fmt: skip
    assert swapped["ok"]  # the record does not depend on which side is "ours"
    rows = read_holds(holds_path(room["repo"]))
    record_hold = [r for r in rows if r["target"].startswith("history-merge:")]
    assert record_hold and record_hold[0]["oid"] == out["record"]
    with pytest.raises(HoldError):
        release(room["repo"], record_hold[0]["target"])
    after = _snap(capsys, room)  # the merged history, plus the hold on its own record
    after["holds"] = [h for h in after["holds"] if not h[0].startswith("history-merge:")]
    assert after == out["merged"]


def test_a_conflict_is_reported_and_nothing_moves(room, capsys) -> None:
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/main"] = room["runs"]["b"]
    room["repo"].update_ref("heads/main", room["runs"]["a"])
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, out = _run(capsys, room, "apply", "--base", files[0], "--theirs", files[1],
                     "--key", (room["base"] / "k.key").as_posix(), "--subject",
                     room["runs"]["a"])  # fmt: skip
    assert code == 1 and not out["applied"]
    assert [c["kind"] for c in out["conflicts"]] == ["ref-diverged"]
    assert room["repo"].read_ref("heads/main") == room["runs"]["a"]


def test_a_dropped_hold_on_the_other_side_is_a_conflict(room, capsys) -> None:
    from opentine.repository import _holds

    _holds.add(room["repo"], room["runs"]["a"])
    base = _snap(capsys, room)
    theirs = {**base, "holds": []}
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, out = _run(capsys, room, "plan", "--base", files[0], "--theirs", files[1])
    assert code == 1 and [c["kind"] for c in out["conflicts"]] == ["hold-weakened"]
    assert out["merged"]["holds"] == base["holds"]


def test_a_queue_owned_target_is_enqueued_not_moved(room, capsys) -> None:
    _merge_queue.init(room["repo"], "q1", "heads/main")
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/main"] = room["runs"]["b"]
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    code, out = _run(capsys, room, "apply", "--base", files[0], "--theirs", files[1],
                     "--key", (room["base"] / "k.key").as_posix(), "--target", "heads/main",
                     "--at", AT)  # fmt: skip
    assert code == 0 and out["refs_moved"] == []
    assert out["queued"] == [{"ref": "heads/main", "run": room["runs"]["b"], "queue": "q1"}]
    assert room["repo"].read_ref("heads/main") == room["runs"]["main"]
    entries = _merge_queue.get(room["repo"], "q1")["entries"]
    assert [e["run"] for e in entries] == [room["runs"]["b"]]


def test_an_edited_record_does_not_verify(room, capsys) -> None:
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/release"] = room["runs"]["b"]
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    out = _run(
        capsys,
        room,
        "apply",
        "--base",
        files[0],
        "--theirs",
        files[1],
        "--key",
        (room["base"] / "k.key").as_posix(),
        "--target",
        "heads/release",
        "--at",
        AT,
    )[1]
    record = room["repo"].get(out["record"]).payload()
    record["claim"]["conflicts"] = [{"kind": "lineage-id", "key": "x", "base": None,
                                     "sides": ["a", "b"]}]  # fmt: skip
    path = _write(room, "record.json", record)
    ours = _write(room, "ours.json", out["ours"])
    code, check = _run(capsys, room, "verify", path, "--base", files[0], "--ours", ours,
                       "--theirs", files[1])  # fmt: skip
    assert code == 1 and not check["ok"] and not check["conflicts_match"]


@pytest.mark.parametrize(("role", "ok"), [("policy", True), ("optimizer", False)])
def test_pinned_roles_decide_who_may_sign_a_merge(room, capsys, role: str, ok: bool) -> None:
    base = _snap(capsys, room)
    theirs = json.loads(json.dumps(base))
    theirs["refs"]["heads/release"] = room["runs"]["b"]
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    out = _run(
        capsys,
        room,
        "apply",
        "--base",
        files[0],
        "--theirs",
        files[1],
        "--key",
        (room["base"] / "k.key").as_posix(),
        "--target",
        "heads/release",
        "--at",
        AT,
    )[1]
    ours = _write(room, "ours.json", out["ours"])
    argv = ("verify", out["record"], "--base", files[0], "--ours", ours, "--theirs", files[1])
    assert _run(capsys, room, *argv)[1]["signers"] == "unpinned"
    text = f'version = 1\n[roles]\n{role} = ["{fingerprint("69" * 32)}"]\n'
    (room["repo"].path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(room["repo"].path)
    code, check = _run(capsys, room, *argv)
    assert check["signers"] == "pinned" and check["signer_trusted"] is ok
    assert check["ok"] is ok and code == (0 if ok else 1)


def _other_side(room: dict, base: dict) -> tuple[dict, Path, Path]:
    import hashlib

    from opentine import _lineage
    from opentine.kernel import canonical_json
    from tests.promote_helpers import key

    lineage, state = room["base"] / "their-lineage", room["base"] / "their-state"
    found = _lineage.record(key("69" * 32), run=room["runs"]["b"], store=lineage,
                            artifacts={"code_tree": "sha256:" + "1" * 64}, at=AT)  # fmt: skip
    row = {"action": "promote", "candidate": room["runs"]["b"], "at": AT, "previous": None}
    state.mkdir()
    label = {"label": "prod", "current": room["runs"]["b"], "history": [row]}
    (state / "prod.json").write_bytes(json.dumps(label).encode("utf-8"))
    theirs = json.loads(json.dumps(base))
    raw = Path(found["record"]).read_bytes()
    theirs["lineage"][found["variant"]] = hashlib.sha256(raw).hexdigest()
    theirs["labels"]["prod"] = {
        "current": room["runs"]["b"],
        "history": [hashlib.sha256(canonical_json(row)).hexdigest()],
    }
    return theirs, state, lineage


def test_labels_and_lineage_records_come_from_the_other_side_checked(room, capsys) -> None:
    base = _snap(capsys, room)
    theirs, state, lineage = _other_side(room, base)
    files = [_write(room, "base.json", base), _write(room, "theirs.json", theirs)]
    argv = (
        "apply",
        "--base",
        files[0],
        "--theirs",
        files[1],
        "--key",
        (room["base"] / "k.key").as_posix(),
        "--subject",
        room["runs"]["b"],
        "--at",
        AT,
    )
    repo = (room["base"] / "r").as_posix()
    code, _ = tine(capsys, "merge-history", *argv, "--repo", repo)
    assert code == 1  # no --theirs-lineage: the record cannot be checked, nothing lands
    record = next((lineage / "variants").glob("*.json"))
    good = record.read_bytes()
    record.write_bytes(good + b"\n")
    code, _ = tine(capsys, "merge-history", *argv, "--repo", repo, "--theirs-state",
                   state.as_posix(), "--theirs-lineage", lineage.as_posix())  # fmt: skip
    assert code == 1  # a record that does not hash to the snapshot is refused
    record.write_bytes(good)
    code, out = _run(capsys, room, *argv, "--theirs-state", state.as_posix(),
                     "--theirs-lineage", lineage.as_posix())  # fmt: skip
    assert code == 0 and out["labels_moved"] == ["prod"] and len(out["lineage_added"]) == 1
    after = _snap(capsys, room)
    assert after["labels"] == out["merged"]["labels"]
    assert after["lineage"] == out["merged"]["lineage"]
