"""0.35 stale-lock hardening: boot/namespace-scoped stamps and a race-safe break."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from opentine.repository import _lockfile


@pytest.fixture
def dead_pid(monkeypatch):
    monkeypatch.setattr(_lockfile, "pid_alive", lambda pid: pid != 424242)


def _five(boot: str, ns: str) -> bytes:
    return f"424242 {_lockfile._host()} 0 {boot} {ns}\n".encode()


def _live() -> bytes:
    return f"{os.getpid()} {_lockfile._host()} 0\n".encode()


def test_a_new_stamp_carries_boot_id_and_pid_namespace():
    fields = _lockfile.stamp().decode().split()
    assert len(fields) == 5
    assert fields[3] == _lockfile._boot_id() and fields[4] == _lockfile._pid_ns()


def test_a_dead_lock_from_this_boot_and_namespace_is_broken(tmp_path: Path, dead_pid):
    if "-" in (_lockfile._boot_id(), _lockfile._pid_ns()):
        pytest.skip("no /proc boot id or pid namespace here")
    lock = tmp_path / "x.lock"
    lock.write_bytes(_five(_lockfile._boot_id(), _lockfile._pid_ns()))
    os.close(_lockfile.acquire(lock))
    assert lock.read_bytes().split()[0] == str(os.getpid()).encode()


@pytest.mark.parametrize("which", ["boot", "ns", "unknown"])
def test_a_lock_from_another_boot_or_pid_namespace_is_never_broken(tmp_path: Path, dead_pid, which):
    boot, ns = _lockfile._boot_id(), _lockfile._pid_ns()
    content = {
        "boot": _five("other-boot", ns),
        "ns": _five(boot, "1"),
        "unknown": _five("-", "-"),
    }[which]
    lock = tmp_path / "x.lock"
    lock.write_bytes(content)
    assert not _lockfile.provably_dead(lock)
    with pytest.raises(FileExistsError):
        _lockfile.acquire(lock)
    assert lock.read_bytes() == content


def test_a_legacy_three_field_stamp_is_still_judged_as_before(tmp_path: Path, dead_pid):
    lock = tmp_path / "x.lock"
    lock.write_bytes(f"424242 {_lockfile._host()} 0\n".encode())
    assert _lockfile.provably_dead(lock)


def test_a_lock_replaced_after_it_was_judged_dead_is_not_moved(tmp_path: Path, dead_pid):
    lock = tmp_path / "x.lock"
    lock.write_bytes(b"424242 0\n")
    identity = _lockfile._dead_identity(lock)
    assert identity is not None
    keep = tmp_path / "keep"
    os.rename(lock, keep)  # hold the old inode so it cannot be reused
    lock.write_bytes(_live())  # a live writer took the lock meanwhile
    _lockfile._break(lock, identity)
    assert lock.read_bytes() == _live()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep", "x.lock"]


def test_a_failed_link_back_keeps_the_moved_lock_and_fails(tmp_path: Path, dead_pid, monkeypatch):
    lock = tmp_path / "x.lock"
    lock.write_bytes(b"424242 0\n")
    identity = _lockfile._dead_identity(lock)
    assert identity is not None
    real_rename = os.rename
    held = tmp_path / "held"

    def swap_then_rename(src, dst):
        real_rename(src, held)  # a live lock replaced the dead one just now
        Path(src).write_bytes(_live())
        real_rename(src, dst)
        Path(src).write_bytes(b"another live owner\n")  # link-back will collide

    monkeypatch.setattr(_lockfile.os, "rename", swap_then_rename)
    monkeypatch.setattr(_lockfile, "_same", lambda path, ident: True)
    with pytest.raises(FileExistsError, match="could not be restored"):
        _lockfile._break(lock, identity)
    aside = [p for p in tmp_path.iterdir() if "stale" in p.name]
    assert len(aside) == 1 and aside[0].read_bytes() == _live()


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_off_linux_a_dead_lock_without_proc_fields_is_still_broken(
    tmp_path: Path, dead_pid, monkeypatch, platform
):
    monkeypatch.setattr(_lockfile.sys, "platform", platform)
    monkeypatch.setattr(_lockfile, "_boot_id", lambda: "-")
    monkeypatch.setattr(_lockfile, "_pid_ns", lambda: "-")
    lock = tmp_path / "x.lock"
    lock.write_bytes(f"424242 {_lockfile._host()} 1 - -\n".encode())
    assert _lockfile.provably_dead(lock)


def test_on_linux_unknown_proc_fields_never_prove_death(tmp_path: Path, dead_pid, monkeypatch):
    monkeypatch.setattr(_lockfile.sys, "platform", "linux")
    monkeypatch.setattr(_lockfile, "_boot_id", lambda: "-")
    monkeypatch.setattr(_lockfile, "_pid_ns", lambda: "-")
    lock = tmp_path / "x.lock"
    lock.write_bytes(f"424242 {_lockfile._host()} 1 - -\n".encode())
    assert not _lockfile.provably_dead(lock)
