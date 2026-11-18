"""0.58: ``tine loop stop`` -- a signed stop that coord lease fencing honours.

Every clock is injected (``now=``): no sleeps, no wall-clock thresholds. A
"fleet" is a set of members whose clocks are skewed from each other by more
than a lease period, the case a time-based fence would get wrong.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import cli
from opentine.coord import _loop_stop, _tasks
from opentine.coord._tasks import LeaseError
from opentine.repository import Repo

TTL = 30.0
SPAN = int(TTL * 1000)
T0 = 1_800_000_000_000
#: Member clocks, skewed by up to two lease periods either way.
SKEWS = (-2 * SPAN, -SPAN - 1, 0, SPAN + 1, 2 * SPAN)


def _key(seed: int = 7) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _generations(repo, loop: str, count: int) -> list[str]:
    names = [f"{loop}.gen-{n}" for n in range(count)]
    for name in names:
        _tasks.add(repo, name, now=T0, loop=loop)
    return names


def test_a_loop_task_records_its_loop_and_others_keep_their_bytes(repo):
    plain = _tasks.add(repo, "plain", now=T0)
    assert "loop" not in plain
    assert _tasks.add(repo, "g0", now=T0, loop="opt")["loop"] == "opt"
    with pytest.raises(ValueError, match="invalid loop id"):
        _tasks.add(repo, "g1", now=T0, loop="Bad Loop")


def test_the_stop_is_a_signed_attestation_with_the_claim_convention(repo):
    record = _loop_stop.stop(repo, "opt", _key(), reason="regression", now=T0)
    assert record["status"] == "stopped" and record["stop"].startswith("attestation:")
    payload = repo.get(record["stop"]).payload()
    stamp = "2027-01-15T08:00:00Z"
    assert payload["claim"] == {"convention": "opentine.loop-stop/1", "loop": "opt",
                                "reason": "regression", "stopped_at": stamp}  # fmt: skip
    assert payload["target_id"].startswith("run:") and payload["signer"] == record["signer"]
    state = _loop_stop.loop_state(repo, "opt")
    assert state["status"] == "stopped" and state["verification"] == "verified"
    assert _loop_stop.loop_state(repo, "other") == {"loop": "other", "status": "running"}
    # The first stop stands: stopping again changes nothing.
    assert _loop_stop.stop(repo, "opt", _key(9), reason="again", now=T0 + 5) == record
    assert repo.fsck().ok


def test_skewed_members_run_normally_before_a_stop(repo):
    (gen0,) = _generations(repo, "opt", 1)
    won = _tasks.claim(repo, gen0, "m0", TTL, now=T0)
    assert _tasks.heartbeat(repo, gen0, "m0", won["fencing"], TTL, now=T0 + 10)["status"]


def test_after_a_stop_every_skewed_member_is_refused_the_next_generation(repo):
    gen0, gen1 = _generations(repo, "opt", 2)
    _tasks.claim(repo, gen0, "m0", TTL, now=T0)
    _loop_stop.stop(repo, "opt", _key(), now=T0 + 1)
    for index, skew in enumerate(SKEWS):
        moment = T0 + 2 + skew
        with pytest.raises(LeaseError) as caught:
            _tasks.claim(repo, gen1, f"m{index}", TTL, now=moment)
        assert caught.value.code == "stopped" and "verified" in str(caught.value)
        # A member whose clock runs ahead sees gen0's lease as expired; still refused.
        with pytest.raises(LeaseError) as caught:
            _tasks.claim(repo, gen0, f"m{index}", TTL, now=moment)
        assert caught.value.code == "stopped"
    assert _tasks.get(repo, gen1)["status"] == "open"


def test_the_running_generation_cannot_outlive_one_lease_period(repo):
    (gen0,) = _generations(repo, "opt", 1)
    holder = _tasks.claim(repo, gen0, "m0", TTL, now=T0)
    _loop_stop.stop(repo, "opt", _key(), now=T0 + 1)
    for skew in SKEWS:
        with pytest.raises(LeaseError) as caught:
            _tasks.heartbeat(repo, gen0, "m0", holder["fencing"], TTL, now=T0 + 2 + skew)
        assert caught.value.code == "stopped"
    # Its lease is not extended: it ends at the expiry it held before the stop.
    assert _tasks.get(repo, gen0)["lease_expires_ms"] == T0 + SPAN
    # It may still close its own work.
    assert _tasks.done(repo, gen0, "m0", holder["fencing"], now=T0 + 3)["status"] == "done"


def test_a_stop_of_another_loop_or_a_plain_task_is_not_fenced(repo):
    _tasks.add(repo, "plain", now=T0)
    (gen0,) = _generations(repo, "keep", 1)
    _loop_stop.stop(repo, "opt", _key(), now=T0)
    assert _tasks.claim(repo, "plain", "m0", TTL, now=T0)["fencing"] == 1
    assert _tasks.claim(repo, gen0, "m0", TTL, now=T0)["fencing"] == 1


def test_a_stop_record_that_does_not_verify_still_refuses(repo):
    (gen0,) = _generations(repo, "opt", 1)
    other = _loop_stop.stop(repo, "else", _key(), now=T0)
    from opentine.coord._store import swap

    forged = {"loop": "opt", "status": "stopped", "stop": other["stop"], "updated_ms": T0}
    assert swap(repo, "coord/loops/opt", "loop", forged, None) is not None
    assert _loop_stop.loop_state(repo, "opt")["verification"].startswith("unverified")
    with pytest.raises(LeaseError, match="unverified") as caught:
        _tasks.claim(repo, gen0, "m0", TTL, now=T0)
    assert caught.value.code == "stopped"


def test_a_later_record_version_cannot_un_stop_or_replace_the_first_stop(repo):
    (gen0,) = _generations(repo, "opt", 1)
    record = _loop_stop.stop(repo, "opt", _key(), now=T0)
    other = _loop_stop.stop(repo, "else", _key(), now=T0)
    from opentine.coord._store import read, swap

    oid, value = read(repo, "coord/loops/opt", "loop")
    oid = swap(repo, "coord/loops/opt", "loop", {**value, "stop": other["stop"]}, oid)
    swap(repo, "coord/loops/opt", "loop", {"loop": "opt", "status": "running"}, oid)
    state = _loop_stop.loop_state(repo, "opt")
    assert state["status"] == "stopped" and state["stop"] == record["stop"]
    assert state["verification"] == "verified"
    with pytest.raises(LeaseError) as caught:
        _tasks.claim(repo, gen0, "m0", TTL, now=T0 + 10 * TTL * 1000)
    assert caught.value.code == "stopped"
    assert _loop_stop.stop(repo, "opt", _key(9), now=T0)["stop"] == record["stop"]


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0
    return code, json.loads(capsys.readouterr().out.strip().splitlines()[-1])


@pytest.mark.filterwarnings("ignore::Warning")  # a plaintext-hex test key
def test_the_cli_stops_a_loop_and_task_claim_is_refused(repo, tmp_path, capsys):
    key = tmp_path / "op.key"
    key.write_bytes((bytes([7]) * 32).hex().encode())
    path = str(repo.path.parent)
    code, out = _cli(capsys, "task", "add", "opt.gen-1", "--loop", "opt", "--repo", path, "--json")
    assert code == 0 and out["task"]["loop"] == "opt"
    code, out = _cli(capsys, "loop", "status", "opt", "--repo", path, "--json")
    assert code == 0 and out["loop"]["status"] == "running"
    code, out = _cli(capsys, "loop", "stop", "opt", "--ed25519-key-file", str(key),
                     "--reason", "regression", "--repo", path, "--json")  # fmt: skip
    assert code == 0 and out["command"] == "loop stop" and out["loop"]["status"] == "stopped"
    assert out["loop"]["verification"] == "verified"
    code, out = _cli(capsys, "task", "claim", "opt.gen-1", "--holder", "m0", "--repo", path,
                     "--json")  # fmt: skip
    assert code == 1 and out["error"]["code"] == "stopped"


def test_loop_stop_needs_an_ed25519_key(repo, capsys):
    path = str(repo.path.parent)
    code, out = _cli(capsys, "loop", "stop", "opt", "--repo", path, "--json")
    assert code != 0 and "ed25519" in json.dumps(out).lower()
