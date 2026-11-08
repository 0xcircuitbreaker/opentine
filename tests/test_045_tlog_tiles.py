"""0.45: O(log n) appends to opentine-log/1 and a failed audit append failing the write."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from opentine.remote import _audit_tlog
from opentine.repository import _tlog, _tlog_append, _tlog_note
from tests.test_remote_0_12 import _remote

LOG = "example.com/log"


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("n", [1, 255, 256, 257, 600])
def test_incremental_tiles_match_the_full_tile_writer_byte_for_byte(tmp_path, n):
    entries = [f"e{i}".encode() for i in range(n)]
    full, fast = tmp_path / "full", tmp_path / "fast"
    _tlog.write_tiles(full, entries, 0)
    for size, entry in enumerate(entries):
        _tlog_append.write_append(fast, size, entry)
    written, expected = _files(fast), _files(full)
    # every tile the full writer names is identical; older partial tiles (``.p/<W>``
    # for a smaller W) also remain, as tlog-tiles allows
    assert {name: written[name] for name in expected} == expected


def test_append_chains_on_the_tail_and_the_log_verifies(tmp_path):
    root = tmp_path / "log"
    seen = []
    for i in range(300):
        _tlog_note.append(root, LOG, lambda tail, i=i: seen.append(tail) or f"x{i}".encode())
    assert seen[0] == [] and seen[1] == [b"x0"] and seen[299] == [b"x298"]
    assert _tlog_note.verify_log(root, LOG)[-1] == b"x299"


def test_append_refuses_tiles_the_checkpoint_does_not_sign(tmp_path):
    root = tmp_path / "log"
    for i in range(3):
        _tlog_note.append(root, LOG, lambda _t, i=i: f"x{i}".encode())
    (root / _tlog.tile_path(0, 0, 3)).write_bytes(b"\0" * 96)
    with pytest.raises(_tlog.LogError, match="checkpoint root"):
        _tlog_note.append(root, LOG, lambda _t: b"y")


def seed_log(root: Path, n: int) -> None:
    """A signed log of ``n`` entries written in one pass (benchmark set-up)."""
    entries = [f"e{i}".encode() for i in range(n)]
    _tlog.write_tiles(root, entries, 0)
    key = _tlog_note._signer(root, LOG)
    tree = _tlog.merkle_root([_tlog.leaf_hash(e) for e in entries])
    (root / "checkpoint").write_bytes(_tlog_note.sign_checkpoint(key, LOG, n, tree))


def test_append_cost_does_not_grow_with_the_log(tmp_path):
    """Scaled-down benchmark; scripts/bench_tlog_append.py runs the 1M-entry gate."""
    root = tmp_path / "log"
    seed_log(root, 70_000)
    times = []
    for i in range(40):
        start = time.perf_counter()
        _tlog_note.append(root, LOG, lambda _t, i=i: f"n{i}".encode())
        times.append(time.perf_counter() - start)
    times.sort()
    assert times[int(len(times) * 0.95)] < 0.25  # generous: CI disks and fsync vary
    assert len(_tlog_note.verify_log(root, LOG)) == 70_040


def test_a_failed_audit_append_is_retried_then_fails_the_write(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    calls = []

    def broken(*_a, **_k):
        calls.append(1)
        raise OSError("disk full")

    monkeypatch.setattr(_tlog_note, "append", broken)
    monkeypatch.setattr(_audit_tlog.time, "sleep", lambda _s: None)
    with pytest.raises(_audit_tlog.PublishError, match="disk full"):
        _audit_tlog.publish(service.audit, {"action": "x"}, "00")
    assert len(calls) == _audit_tlog.PUBLISH_ATTEMPTS
    calls.clear()
    failures = [OSError("locked")]

    def once(*_a, **_k):
        calls.append(1)
        if failures:
            raise failures.pop()
        return 0

    monkeypatch.setattr(_tlog_note, "append", once)
    _audit_tlog.publish(service.audit, {"action": "x"}, "00")
    assert len(calls) == 2
