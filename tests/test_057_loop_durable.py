"""0.57: a loop stop survives its coord record, names its stopper, fences its namespace.

Every clock is injected (``now=``); nothing sleeps.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine._ref_delete import delete_ref
from opentine._signing_pins import key_fingerprint
from opentine.coord import _loop_stop, _tasks
from opentine.coord._store import swap
from opentine.coord._tasks import LeaseError
from opentine.repository import Repo, _holds
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

TTL = 30.0
T0 = 1_800_000_000_000


def _key(seed: int = 7) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _fpr(seed: int) -> str:
    return key_fingerprint(_key(seed).public_key().public_bytes_raw())


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _refused(repo, task: str, now: int = T0) -> None:
    with pytest.raises(LeaseError) as caught:
        _tasks.claim(repo, task, "m0", TTL, now=now)
    assert caught.value.code == "stopped"


def test_deleting_or_rewriting_the_loop_record_does_not_un_stop(repo):
    _tasks.add(repo, "g0", now=T0, loop="opt")
    record = _loop_stop.stop(repo, "opt", _key(), reason="halt", now=T0)
    ref = "coord/loops/opt"
    delete_ref(repo.path, ref, repo.read_ref(ref))
    assert repo.read_ref(ref) is None
    state = _loop_stop.loop_state(repo, "opt")
    assert state["status"] == "stopped" and state["stop"] == record["stop"]
    assert state["verification"] == "verified"
    _refused(repo, "g0")
    # A fresh, running record in its place changes nothing either.
    assert swap(repo, ref, "loop", {"loop": "opt", "status": "running"}, None) is not None
    _refused(repo, "g0", T0 + 1)
    assert _loop_stop.stop(repo, "opt", _key(9), now=T0 + 2)["stop"] == record["stop"]


def test_the_hold_that_keeps_a_stop_cannot_be_released(repo):
    record = _loop_stop.stop(repo, "opt", _key(), now=T0)
    for target in (record["stop"], "loop-stop:opt"):
        with pytest.raises(_holds.HoldError, match="never released"):
            _holds.release(repo, target)
    assert record["stop"] in _holds.held(repo)


def test_an_unreadable_holds_file_fences_a_loop_generation(repo):
    _tasks.add(repo, "g0", now=T0, loop="opt")
    _holds.holds_path(repo).write_bytes(b"not json")
    _refused(repo, "g0")
    assert _loop_stop.loop_state(repo, "opt")["verification"].startswith("unverified")


def _roles(repo, **roles) -> None:
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode())
    pin_roles(repo.path)  # 0.59: roles grant only from an owner-signed trust bundle


def test_a_stop_from_a_key_outside_the_stopper_role_fences_but_is_unverified(repo):
    _roles(repo, stopper=[_fpr(9)])
    _tasks.add(repo, "g0", now=T0, loop="opt")
    _loop_stop.stop(repo, "opt", _key(7), now=T0)
    state = _loop_stop.loop_state(repo, "opt")
    assert state["verification"] == "unverified: the signer is not a stopper key"
    _refused(repo, "g0")
    _loop_stop.stop(repo, "next", _key(9), now=T0)
    assert _loop_stop.loop_state(repo, "next")["verification"] == "verified"


def test_a_task_in_a_stopped_loops_namespace_is_fenced_without_loop(repo):
    _tasks.add(repo, "opt.gen-1", now=T0)  # added before the stop, without loop=
    _tasks.add(repo, "optimum", now=T0)  # not in the namespace: only "opt." prefixes are
    _loop_stop.stop(repo, "opt", _key(), now=T0)
    _refused(repo, "opt.gen-1")
    assert _tasks.claim(repo, "optimum", "m0", TTL, now=T0)["fencing"] == 1
    for kwargs in ({}, {"loop": "opt"}):
        with pytest.raises(LeaseError) as caught:
            _tasks.add(repo, "opt.gen-2" if not kwargs else "g9", now=T0, **kwargs)
        assert caught.value.code == "stopped"


def test_deleting_the_record_and_the_holds_file_does_not_un_stop(repo):
    _tasks.add(repo, "g0", now=T0, loop="opt")
    record = _loop_stop.stop(repo, "opt", _key(), reason="halt", now=T0)
    ref = "coord/loops/opt"
    delete_ref(repo.path, ref, repo.read_ref(ref))
    _holds.holds_path(repo).unlink()
    state = _loop_stop.loop_state(repo, "opt")
    assert state["status"] == "stopped" and state["stop"] == record["stop"]
    _refused(repo, "g0")
