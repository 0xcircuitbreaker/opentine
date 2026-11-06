"""0.36.0 F1: contended ref writers wait instead of failing; opt-in rebase retry."""

from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import time

import pytest

from opentine import Repo
from opentine.repository import _ref_retry
from opentine.repository._ref_retry import RefCasMismatch, RefLockContended, backoff
from opentine.repository._reflog import read_reflog

WRITERS = 16
UPDATES = 20

_WORKER = textwrap.dedent(
    """
    import sys
    from opentine import Repo

    repo = Repo.open(sys.argv[1])
    who = sys.argv[2]
    for i in range(int(sys.argv[3])):
        def rebase(current, i=i):
            body = f"{current}|{who}:{i}".encode("ascii")
            return repo.put("blob", body)
        repo.update_ref_rebase("tags/shared", rebase, actor=f"w{who}")
    """
)


def _chain_length(repo: Repo, oid: str | None) -> int:
    count = 0
    while oid is not None and oid != "None":
        count += 1
        oid = repo.get(oid).body.decode("ascii").rsplit("|", 1)[0]
    return count


@pytest.mark.stress
def test_sixteen_processes_lose_no_shared_ref_update(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    started = time.monotonic()
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER, str(repo.path), str(n), str(UPDATES)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for n in range(WRITERS)
    ]
    failures = []
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        if proc.returncode:
            failures.append(err.decode(errors="replace")[-2000:])
    assert failures == []
    assert time.monotonic() - started < 120
    rows = read_reflog(repo.path, "tags/shared")
    assert len(rows) == WRITERS * UPDATES
    assert _chain_length(repo, repo.read_ref("tags/shared")) == WRITERS * UPDATES


def test_a_briefly_held_lock_is_waited_for(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    first = repo.put("blob", b"one")
    lock = repo.path / "refs" / "tags" / "t.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("", encoding="ascii")  # unknown owner: never broken, only waited for
    timer = threading.Timer(0.3, lock.unlink)
    timer.start()
    try:
        repo.update_ref("tags/t", first, expected_old=None)
    finally:
        timer.join()
    assert repo.read_ref("tags/t") == first


def test_a_lock_that_stays_held_fails_after_the_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(_ref_retry, "LOCK_WAIT_SECONDS", 0.2)
    repo = Repo.init(tmp_path / "repo")
    lock = repo.path / "refs" / "tags" / "t.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("", encoding="ascii")
    started = time.monotonic()
    with pytest.raises(RefLockContended, match="delete that file"):
        repo.update_ref("tags/t", repo.put("blob", b"x"), expected_old=None)
    assert 0.2 <= time.monotonic() - started < 5
    assert lock.exists()


def test_a_cas_mismatch_is_never_retried_by_update_ref(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    a, b = repo.put("blob", b"a"), repo.put("blob", b"b")
    repo.update_ref("tags/t", a, expected_old=None)
    with pytest.raises(RefCasMismatch):
        repo.update_ref("tags/t", b, expected_old=None)
    assert repo.read_ref("tags/t") == a
    with pytest.raises(RefCasMismatch):
        repo.update_refs([("tags/t", b, None)])


def test_rebase_rereads_after_a_concurrent_move(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    a, b, c = (repo.put("blob", x) for x in (b"a", b"b", b"c"))
    repo.update_ref("tags/t", a, expected_old=None)
    seen = []

    def rebase(current):
        seen.append(current)
        if len(seen) == 1:  # someone else moves the ref after our read
            repo.update_ref("tags/t", b, expected_old=a)
        return c

    assert repo.update_ref_rebase("tags/t", rebase) == c
    assert seen == [a, b]
    assert repo.read_ref("tags/t") == c


def test_rebase_keeps_retrying_when_the_lock_outlasts_one_wait(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "repo")
    a, c = (repo.put("blob", x) for x in (b"a", b"c"))
    repo.update_ref("tags/t", a, expected_old=None)
    real, calls = repo.update_ref, []

    def contended(*args, **kwargs):
        calls.append(1)
        if len(calls) < 3:  # update_ref's own lock wait ran out, twice
            raise RefLockContended("ref 'tags/t' is locked by a concurrent writer")
        return real(*args, **kwargs)

    monkeypatch.setattr(repo, "update_ref", contended)
    assert repo.update_ref_rebase("tags/t", lambda current: c) == c
    assert len(calls) == 3 and real.__self__.read_ref("tags/t") == c


def test_backoff_is_bounded_and_jittered():
    delays = list(backoff(0.05))
    assert delays and all(0 < d <= 0.05 for d in delays)
    assert sum(delays) <= 0.06
