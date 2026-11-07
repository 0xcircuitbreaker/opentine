"""0.43 ``opentine-coord/1`` tasks and leases (``tine task``).

A claim is one compare-and-swap move of ``coord/tasks/<id>``: racing processes
produce exactly one winner, an expired lease is re-claimed with a higher fencing
token, and a stale holder is refused on heartbeat and done.
"""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from opentine import cli
from opentine.coord import _tasks
from opentine.coord._tasks import LeaseError
from opentine.repo import Repo


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


@pytest.fixture
def repo(tmp_path) -> Repo:
    return Repo.init(tmp_path / "repo")


def test_claim_heartbeat_done_and_the_history_chain(repo):
    _tasks.add(repo, "build", "Build it", now=1)
    lease = _tasks.claim(repo, "build", "alice", ttl=10, now=1000)
    assert (lease["status"], lease["holder"], lease["fencing"]) == ("claimed", "alice", 1)
    assert lease["lease_expires_ms"] == 11_000
    beat = _tasks.heartbeat(repo, "build", "alice", 1, ttl=10, now=5000)
    assert beat["lease_expires_ms"] == 15_000 and beat["fencing"] == 1
    closed = _tasks.done(repo, "build", "alice", 1, now=6000)
    assert closed["status"] == "done" and closed["lease_expires_ms"] is None
    statuses = [row["status"] for row in _tasks.task_history(repo, "build")]
    assert statuses == ["done", "claimed", "claimed", "open"]
    with pytest.raises(LeaseError) as caught:
        _tasks.claim(repo, "build", "bob", now=7000)
    assert caught.value.code == "done"
    assert repo.fsck().ok


def test_a_live_lease_is_held_and_an_expired_one_is_reclaimed_with_a_higher_token(repo):
    _tasks.add(repo, "t")
    _tasks.claim(repo, "t", "alice", ttl=1, now=1000)
    with pytest.raises(LeaseError) as caught:
        _tasks.claim(repo, "t", "bob", now=1999)
    assert caught.value.code == "held"
    second = _tasks.claim(repo, "t", "bob", ttl=1, now=2000)
    assert second["holder"] == "bob" and second["fencing"] == 2


@pytest.mark.parametrize("operation", ["heartbeat", "done"])
def test_a_stale_holder_is_refused(repo, operation):
    _tasks.add(repo, "t")
    _tasks.claim(repo, "t", "alice", ttl=1, now=1000)
    _tasks.claim(repo, "t", "bob", ttl=60, now=3000)
    call = getattr(_tasks, operation)
    with pytest.raises(LeaseError) as caught:
        call(repo, "t", "alice", 1, now=3001)
    assert caught.value.code == "stale"
    with pytest.raises(LeaseError):  # the right holder with an old token is stale too
        call(repo, "t", "bob", 1, now=3001)
    assert _tasks.get(repo, "t")["holder"] == "bob"


def test_an_expired_but_unclaimed_lease_cannot_be_heartbeaten(repo):
    _tasks.add(repo, "t")
    _tasks.claim(repo, "t", "alice", ttl=1, now=1000)
    with pytest.raises(LeaseError) as caught:
        _tasks.heartbeat(repo, "t", "alice", 1, now=2000)
    assert caught.value.code == "stale"


def test_adding_twice_and_bad_ids_are_refused(repo):
    _tasks.add(repo, "t")
    with pytest.raises(LeaseError):
        _tasks.add(repo, "t")
    for bad in ("", "Upper", "a/b", "../x", "x" * 65):
        with pytest.raises(ValueError):
            _tasks.add(repo, bad)


def _race(path: str, holder: str, start, results) -> None:
    from opentine.coord import _tasks
    from opentine.repo import Repo

    repo = Repo.open(path)
    start.wait()
    wins = 0
    for index in range(5):
        try:
            _tasks.claim(repo, f"job-{index}", holder, ttl=600)
            wins += 1
        except _tasks.LeaseError as exc:
            assert exc.code in ("held", "contended"), exc
    results.put((holder, wins))


def test_processes_racing_a_claim_produce_exactly_one_winner(tmp_path):
    root = tmp_path / "repo"
    repo = Repo.init(root)
    for index in range(5):
        _tasks.add(repo, f"job-{index}")
    context = multiprocessing.get_context("spawn")
    start, results = context.Barrier(6), context.Queue()
    workers = [
        context.Process(target=_race, args=(str(root), f"agent-{n}", start, results))
        for n in range(6)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
        assert worker.exitcode == 0
    wins = dict(results.get(timeout=10) for _ in workers)
    assert sum(wins.values()) == 5  # each task: exactly one winner, never two
    for index in range(5):
        value = _tasks.get(repo, f"job-{index}")
        assert value["fencing"] == 1 and value["holder"] in wins
        history = _tasks.task_history(repo, f"job-{index}")
        assert [row["fencing"] for row in history] == [1, 0]  # no lost or double claim
    assert repo.fsck().ok


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def test_the_task_cli_round_trip_with_json(tmp_path, capsys):
    root = str(Path(Repo.init(tmp_path / "repo").path).parent)
    code, out = _tine(
        capsys, "task", "add", "lint", "--title", "Run lint", "--repo", root, "--json"
    )
    assert code == 0 and out == {"command": "task add", "task": out["task"]}
    code, out = _tine(capsys, "task", "claim", "lint", "--holder", "a", "--repo", root, "--json")
    assert code == 0 and out["task"]["fencing"] == 1
    code, out = _tine(capsys, "task", "claim", "lint", "--holder", "b", "--repo", root, "--json")
    assert code == 1 and out["error"]["code"] == "held"
    argv = ("--holder", "a", "--fencing", "1", "--repo", root, "--json")
    assert _tine(capsys, "task", "heartbeat", "lint", *argv)[0] == 0
    code, out = _tine(capsys, "task", "done", "lint", *argv)
    assert code == 0 and out["task"]["status"] == "done"
    code, out = _tine(capsys, "task", "list", "--repo", root, "--json")
    assert [row["task"] for row in out["tasks"]] == ["lint"]
