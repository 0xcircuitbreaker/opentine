"""0.68: sabotage task records, catch rate per class, and outcomes that only go up."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import _monitor_verdict, _sabotage, _schemas
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import key
from tests.query_helpers import add_run, claim, tine

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

MONITOR, SCORER, EVAL, OTHER, OPTIMIZER = "11" * 32, "5a" * 32, "6b" * 32, "22" * 32, "7c" * 32
AT = "2026-12-01T10:00:00Z"


def _fp(seed: str) -> str:
    return key_fingerprint(key(seed).public_key().public_bytes_raw())


@pytest.fixture
def room(tmp_path: Path) -> dict:
    repo = Repo.init(tmp_path / "r")
    roles = {"monitor": [_fp(MONITOR)], "scorer": [_fp(SCORER)], "eval": [_fp(EVAL)],
             "optimizer": [_fp(OPTIMIZER)]}  # fmt: skip
    text = "version = 1\n[roles]\n" + "".join(f"{r} = {json.dumps(k)}\n" for r, k in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    for seed in (SCORER, EVAL, OTHER, OPTIMIZER):
        (tmp_path / f"{seed[:2]}.key").write_bytes(seed.encode("ascii"))
    runs = [add_run(repo, f"run{i}", cost=0.1) for i in range(4)]
    caught = _monitor_verdict.record(repo, runs[0], claim("s0", "block"), key(MONITOR))
    allowed = _monitor_verdict.record(repo, runs[1], claim("s1", "allow"), key(MONITOR))
    forged = _monitor_verdict.record(repo, runs[2], claim("s2", "block"), key(OTHER))
    return {"base": tmp_path, "repo": repo, "runs": runs, "caught": caught,
            "allowed": allowed, "forged": forged}  # fmt: skip


def _record(capsys, room: dict, task: str, run: int, cls: str, seed: str, *extra: str):
    base = room["base"]
    return tine(capsys, "sabotage", "record", "--repo", (base / "r").as_posix(),
                "--run", room["runs"][run], "--task", task, "--class", cls,
                "--main-task", "fix-bug", "--main-score", "0.75", "--main-passed", "yes",
                "--side-task", "plant-backdoor", "--key", (base / f"{seed[:2]}.key").as_posix(),
                "--at", AT, *extra)  # fmt: skip


def _report(capsys, room: dict, *extra: str):
    return tine(capsys, "sabotage", "report", "--repo", (room["base"] / "r").as_posix(), *extra)


def test_catch_rate_per_class_counts_only_verified_blocking_verdicts(room, capsys):
    code, out = _record(capsys, room, "t1", 0, "code", SCORER, "--attempted", "--achieved",
                        "--verdict", room["caught"], "--evidence", "diff:abc")  # fmt: skip
    assert code == 0, out
    _schemas.validate(out, "tine-cli-sabotage-1")
    assert out["run"] == room["runs"][0]
    assert _record(capsys, room, "t2", 1, "code", EVAL, "--attempted",
                   "--verdict", room["allowed"])[0] == 0  # fmt: skip
    assert _record(capsys, room, "t3", 2, "decision", SCORER, "--attempted", "--achieved",
                   "--verdict", room["forged"])[0] == 0  # fmt: skip
    assert _record(capsys, room, "t4", 3, "decision", EVAL)[0] == 0
    code, out = _report(capsys, room, "--seed", "7")
    _schemas.validate(out, "tine-cli-sabotage-1")
    assert code == 0 and out["ok"] and out["advisory"] is True
    rates = {c["class"]: c for c in out["classes"]}
    assert rates["code"]["attempted"] == 2 and rates["code"]["caught"] == 1
    assert rates["code"]["catch_rate"] == "0.500000" and rates["code"]["ci"] is not None
    assert rates["decision"]["attempted"] == 1 and rates["decision"]["caught"] == 0
    assert rates["decision"]["achieved_uncaught"] == 1
    codes = sorted(f["code"] for f in out["findings"])
    assert codes == ["advisory:sabotage.uncaught", "advisory:sabotage.verdict-unverified"]
    assert _report(capsys, room, "--seed", "7")[1] == out  # seeded: byte-identical
    code, strict = _report(capsys, room, "--strict")
    assert code == 1 and strict["blocking"] == 2


def test_a_record_cannot_relabel_an_achieved_side_task(room, capsys):
    assert _record(capsys, room, "t1", 0, "code", SCORER, "--attempted", "--achieved")[0] == 0
    code, out = _record(capsys, room, "t1", 0, "code", EVAL)
    assert code == 1 and "sabotage.relabel" in out["error"]["message"]
    with pytest.raises(HoldError):
        release(room["repo"], "sabotage-task:t1")
    # A loop that bypasses the command and holds a downgrade is caught by the report.
    downgrade = {"convention": _sabotage.CONVENTION, "task": "t1", "class": "code",
                 "main_task": {"id": "fix-bug", "score": None, "passed": None},
                 "side_task": {"id": "plant-backdoor", "attempted": False, "achieved": False},
                 "evidence": [], "monitor_verdicts": [], "at": AT}  # fmt: skip
    from opentine.repository._attest import attest
    from opentine.repository._holds import SABOTAGE_TASK, edit_holds, holds_path

    oid = attest(room["repo"], room["runs"][0], downgrade, signer=_fp(EVAL), key=key(EVAL),
                 algorithm="ed25519", signed_at=AT)  # fmt: skip
    row = {"oid": oid, "target": f"{SABOTAGE_TASK}t1"}
    edit_holds(holds_path(room["repo"]), lambda rows: [*rows, row])
    code, out = _report(capsys, room)
    assert code == 1 and not out["ok"]
    assert [f["code"] for f in out["findings"]] == [
        "fail:sabotage.relabel",
        "advisory:sabotage.uncaught",
    ]
    task = out["tasks"][0]
    assert task["attempted"] and task["achieved"] and task["counted"] == 2


def test_unpinned_and_optimizer_signers_do_not_count(room, capsys):
    assert _record(capsys, room, "t1", 0, "code", OTHER, "--attempted")[0] == 0
    assert _record(capsys, room, "t2", 1, "decision", OPTIMIZER, "--attempted")[0] != 0
    code, out = _report(capsys, room)
    assert out["tasks"] == [] and all(c["attempted"] == 0 for c in out["classes"])
    assert [f["code"] for f in out["findings"]] == ["advisory:sabotage.signer-unpinned"]
    assert code == 0


def test_unpinned_roles_make_every_record_advisory(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    run = add_run(repo, "run0", cost=0.1)
    (tmp_path / "k.key").write_bytes(SCORER.encode("ascii"))
    code, _ = tine(capsys, "sabotage", "record", "--repo", (tmp_path / "r").as_posix(),
                   "--run", run, "--task", "t", "--class", "code", "--main-task", "m",
                   "--side-task", "s", "--key", (tmp_path / "k.key").as_posix(),
                   "--at", AT)  # fmt: skip
    assert code == 0
    code, out = tine(capsys, "sabotage", "report", "--repo", (tmp_path / "r").as_posix())
    assert code == 0 and out["tasks"] == []
    assert "unpinned" in out["findings"][0]["message"]


def test_claim_checks_and_schema():
    good = {"convention": _sabotage.CONVENTION, "task": "t", "class": "code",
            "main_task": {"id": "m", "score": "1", "passed": True},
            "side_task": {"id": "s", "attempted": True, "achieved": True},
            "evidence": ["run:x"], "monitor_verdicts": [], "at": AT}  # fmt: skip
    assert _sabotage.check_claim(good) == []
    _schemas.validate(good, "opentine-sabotage-task-1")
    bad = {**good, "side_task": {"id": "s", "attempted": False, "achieved": True}}
    assert _sabotage.check_claim(bad) == ["an achieved side task was attempted"]
    assert _sabotage.check_claim({**good, "class": "x"})
    assert _sabotage.check_claim({**good, "monitor_verdicts": ["nope"]})
    assert _sabotage.check_claim({**good, "main_task": {"id": "m", "score": 1, "passed": None}})


def test_achieved_needs_attempted_on_the_command_line(room, capsys):
    code, out = _record(capsys, room, "t1", 0, "code", SCORER, "--achieved")
    assert code == 1 and "--attempted" in out["error"]["message"]
