"""A lock file is never visible without its owner stamp.

A writer SIGKILLed between creating a lock and stamping it used to leave an
empty lock: unreadable, so never provably dead, so the ref wedged for good.
"""

from __future__ import annotations

import errno
import os
import threading
from pathlib import Path

import pytest

from opentine.repository import _lockfile


def _fields(path):
    return path.read_bytes().decode("ascii").split()


def test_a_new_lock_is_stamped_and_leaves_no_temporary_file(tmp_path):
    lock = tmp_path / "main.lock"
    os.close(_lockfile.acquire(lock))
    assert len(_fields(lock)) == 5 and int(_fields(lock)[0]) == os.getpid()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["main.lock"]


def test_a_held_lock_refuses_and_leaves_no_temporary_file(tmp_path):
    lock = tmp_path / "main.lock"
    os.close(_lockfile.acquire(lock))
    before = lock.read_bytes()
    with pytest.raises(FileExistsError):
        _lockfile.acquire(lock)  # our own pid is alive
    assert lock.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["main.lock"]


def test_the_lock_never_exists_before_its_stamp(tmp_path, monkeypatch):
    lock = tmp_path / "main.lock"
    real_link = os.link

    def link(src, dst):
        assert not lock.exists(), "lock visible before it was stamped"
        assert len(Path(src).read_bytes().split()) == 5  # stamped before it is linked
        return real_link(src, dst)

    monkeypatch.setattr(_lockfile.os, "link", link)
    os.close(_lockfile.acquire(lock))
    assert len(_fields(lock)) == 5


def test_without_hard_links_it_falls_back_to_exclusive_create(tmp_path, monkeypatch):
    def no_link(src, dst):
        raise OSError(errno.EPERM, "hard links not supported")

    monkeypatch.setattr(_lockfile.os, "link", no_link)
    lock = tmp_path / "main.lock"
    os.close(_lockfile.acquire(lock))
    assert len(_fields(lock)) == 5
    assert sorted(p.name for p in tmp_path.iterdir()) == ["main.lock"]
    with pytest.raises(FileExistsError):
        _lockfile.acquire(lock)


def test_a_dead_owners_lock_is_still_broken(tmp_path):
    lock = tmp_path / "main.lock"
    stamp = _lockfile.stamp().decode().split()
    stamp[0] = str(2**22 + 12345)  # a pid that is not running
    lock.write_text(" ".join(stamp) + "\n")
    if _lockfile.pid_alive(int(stamp[0])):
        pytest.skip("that pid happens to be alive here")
    os.close(_lockfile.acquire(lock))
    assert int(_fields(lock)[0]) == os.getpid()


def test_a_failed_reopen_after_the_link_removes_the_lock(tmp_path, monkeypatch):
    lock = tmp_path / "main.lock"
    real_open = _lockfile._winretry.open_fd
    calls = []

    def open_fd(path, flags, mode=0o777):
        calls.append(path)
        if len(calls) == 2:
            raise OSError(24, "Too many open files")
        return real_open(path, flags, mode)

    monkeypatch.setattr(_lockfile._winretry, "open_fd", open_fd)
    with pytest.raises(OSError):
        _lockfile.acquire(lock)
    assert list(tmp_path.iterdir()) == []


def test_a_crash_before_the_link_leaves_no_lock(tmp_path, monkeypatch):
    lock = tmp_path / "main.lock"

    def killed(src, dst):
        raise KeyboardInterrupt  # stands in for a kill after the stamp is written

    monkeypatch.setattr(_lockfile.os, "link", killed)
    with pytest.raises(KeyboardInterrupt):
        _lockfile.acquire(lock)
    assert not lock.exists()
    monkeypatch.undo()
    os.close(_lockfile.acquire(lock))
    assert len(_fields(lock)) == 5


def test_an_unsupported_link_on_a_held_lock_still_refuses(tmp_path, monkeypatch):
    lock = tmp_path / "main.lock"
    os.close(_lockfile.acquire(lock))
    before = lock.read_bytes()

    def no_link(src, dst):
        raise OSError(errno.EPERM, "hard links not supported")

    monkeypatch.setattr(_lockfile.os, "link", no_link)
    with pytest.raises(FileExistsError):
        _lockfile.acquire(lock)
    assert lock.read_bytes() == before


def test_another_link_error_is_raised_not_masked(tmp_path, monkeypatch):
    def broken(src, dst):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(_lockfile.os, "link", broken)
    with pytest.raises(OSError) as info:
        _lockfile.acquire(tmp_path / "main.lock")
    assert info.value.errno == errno.EIO
    assert list(tmp_path.iterdir()) == []


def test_threads_of_one_process_get_distinct_temporary_names(tmp_path, monkeypatch):
    # A coarse clock gave two threads the same temp name on Windows; one thread
    # then deleted the other's stamp file before it was linked.
    monkeypatch.setattr(_lockfile.time, "monotonic_ns", lambda: 0)
    lock = tmp_path / "main.lock"
    errors, held = [], []
    gate = threading.Barrier(8)

    def contend():
        gate.wait()
        for _ in range(200):
            try:
                fd = _lockfile.acquire(lock)
            except FileExistsError:
                continue
            except BaseException as exc:  # pragma: no cover - the bug
                errors.append(exc)
                return
            held.append(1)
            os.close(fd)
            _lockfile._winretry.unlink(lock)

    threads = [threading.Thread(target=contend) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and held
    assert list(tmp_path.iterdir()) == []


def test_a_temp_name_that_cannot_be_removed_never_costs_the_lock(tmp_path, monkeypatch):
    # Windows: once linked, a contender holding the lock open blocks deleting the
    # temp name. acquire must still return the lock it took, not raise.
    real_unlink = _lockfile._winretry.unlink

    def unlink(path):
        if ".new-" in str(path):
            raise PermissionError(13, "sharing violation")
        return real_unlink(path)

    monkeypatch.setattr(_lockfile._winretry, "unlink", unlink)
    lock = tmp_path / "main.lock"
    os.close(_lockfile.acquire(lock))
    assert len(_fields(lock)) == 5 and int(_fields(lock)[0]) == os.getpid()
