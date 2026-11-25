"""Recording a long run: bounded I/O per event, and never a dangling run.

0.74.0 timed out on Windows recording ``MAX_RECORDED_EVENTS`` marks. Two costs
grew with the event count. Every repeat of an already-stored blob went through
``install_verified`` asking ``FileIO.read`` for ``MAX_OBJECT_BYTES`` (~256 MiB,
which Windows commits). And a store without packs (version 1, as the test suite
creates with ``OPENTINE_COMPRESS=0``, or ``OPENTINE_RUN_PACK=0``) wrote each new
object loose with a file fsync *and* a directory fsync. Counted for the whole
``on_chain_end`` of a 3000-event run, before -> after:

* loose store: 6279 -> 3279 fsyncs (2.03 -> 1.06 per event; the marginal
  cost per event drops from ~2 to ~1: one file sync, directories once each);
* pack store (the default): 16 -> 16 fsyncs, the same for every N;
* reads asking for >= 1 MiB: 5998 (loose) / 3000 (pack) -> 0.

Everything here counts calls; nothing reads a clock.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest

from opentine.integrations.langchain import OpenTineCallbackHandler
from opentine.repository import Repo, _paths, _write_batch
from opentine.repository import store as store_module

CHAIN = uuid.UUID(int=1)
PACK_FSYNCS = 16  # the whole on_chain_end of a pack store, for any event count


class Crash(BaseException):
    """A process death: nothing in the recorder may catch it."""


def _record(tmp_path, marks: int) -> tuple[Repo, OpenTineCallbackHandler]:
    repo = Repo.init(tmp_path)
    handler = OpenTineCallbackHandler(repo, capture=False)
    handler.on_chain_start({"name": "agent"}, {"q": 1}, run_id=CHAIN)
    action = SimpleNamespace(tool="moons", tool_input={"planet": "mars"}, log="thinking")
    for _ in range(marks):
        handler.on_agent_action(action, run_id=CHAIN)
    return repo, handler


def _end(handler) -> None:
    handler.on_chain_end({"output": "done"}, run_id=CHAIN)


@pytest.fixture
def io_counts(monkeypatch):
    counts = {"fsync": 0, "big_reads": 0, "verified_existing": 0}
    real_fsync, real_fdopen, real_install = os.fsync, os.fdopen, _paths.install_verified

    def fsync(fd):
        counts["fsync"] += 1
        return real_fsync(fd)

    class Reads:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            self._handle.__enter__()
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._handle, name)

        def read(self, size=-1):
            if size is None or size < 0 or size >= 1 << 20:
                counts["big_reads"] += 1
            return self._handle.read(size)

    def fdopen(fd, mode="r", *args, **kwargs):
        handle = real_fdopen(fd, mode, *args, **kwargs)
        return Reads(handle) if "r" in mode and "b" in mode else handle

    def install(*args, **kwargs):
        written = real_install(*args, **kwargs)
        counts["verified_existing"] += not written
        return written

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(_paths.os, "fdopen", fdopen)
    monkeypatch.setattr("opentine.repository._storage.install_verified", install)
    return counts


def _end_counted(tmp_path, marks: int, counts: dict) -> dict:
    repo, handler = _record(tmp_path, marks)
    for key in counts:
        counts[key] = 0
    _end(handler)
    result = dict(counts)
    payload = repo.get(handler.run_id).payload()
    assert payload["status"] == "completed" and len(payload["events"]) == marks + 1
    return result


def test_pack_store_fsyncs_do_not_grow_with_the_event_count(tmp_path, io_counts, monkeypatch):
    """Pack store: at most 16 fsyncs for 40 events and for 400, before and after.

    The exact count can be one lower when two new objects land in the same
    fresh directory (its sync is shared); it never grows with the event count.
    """
    monkeypatch.setenv("OPENTINE_COMPRESS", "1")  # a version-2 store writes run packs
    small = _end_counted(tmp_path / "small", 40, io_counts)
    large = _end_counted(tmp_path / "large", 400, io_counts)
    assert 0 < small["fsync"] <= PACK_FSYNCS
    assert 0 < large["fsync"] <= PACK_FSYNCS
    assert small["big_reads"] == large["big_reads"] == 0  # before: one per event


def test_loose_store_pays_one_fsync_per_new_object(tmp_path, io_counts):
    """Loose store: each extra event cost ~2 fsyncs (file + directory); now ~1.

    Measured for 400 -> 800 events: before +~800 fsyncs per 400 events, after
    +~400 (the 256 object directories are each synced once per flush).
    """
    small = _end_counted(tmp_path / "small", 400, io_counts)
    large = _end_counted(tmp_path / "large", 800, io_counts)
    assert small["big_reads"] == large["big_reads"] == 0  # before: two per event
    assert large["fsync"] - small["fsync"] <= 1.2 * 400
    assert large["fsync"] <= 1.2 * 800 + 300


def test_a_repeated_blob_is_verified_once_per_batch(tmp_path, io_counts):
    """Before: every event re-read and re-verified the shared input blob."""
    counts = _end_counted(tmp_path, 400, io_counts)
    assert counts["verified_existing"] <= 4


def test_an_oversized_existing_object_is_refused_without_reading_it(tmp_path):
    target = tmp_path / "obj"
    target.write_bytes(b"x" * 100)
    with pytest.raises(_paths.KernelError, match="does not match"):
        _paths.install_verified(target, b"x" * 10, "object")
    target.write_bytes(b"x" * 10)
    assert _paths.install_verified(target, b"x" * 10, "object") is False


def _assert_no_dangling_run(path, marks: int) -> None:
    """Every ref names the run as it was before the end (no events yet) or whole."""
    repo = Repo.open(path)
    assert repo.fsck().ok
    runs = 0
    for oid in repo.list_refs().values():
        payload = repo.get(oid).payload()
        if "events" not in payload:
            continue
        runs += 1
        assert len(payload["events"]) in (0, marks + 1)
        for event in payload["events"]:
            repo.get(event)  # every event a ref reaches is durable and readable
    assert runs


#: (store, the batch step that makes the run's objects durable)
_STORES = [
    pytest.param("1", "publish_pack", id="pack"),
    pytest.param("0", "_fsync_dir", id="loose"),
]


@pytest.mark.parametrize(("compress", "durable_step"), _STORES)
def test_a_crash_before_the_objects_are_durable_leaves_no_dangling_run(
    tmp_path, monkeypatch, compress, durable_step
):
    monkeypatch.setenv("OPENTINE_COMPRESS", compress)
    _, handler = _record(tmp_path, 50)

    def crash(*args, **kwargs):
        raise Crash

    with monkeypatch.context() as patch:
        patch.setattr(_write_batch, durable_step, crash)
        with pytest.raises(Crash):
            _end(handler)
    _assert_no_dangling_run(tmp_path, 50)


@pytest.mark.parametrize(("compress", "durable_step"), _STORES)
def test_a_crash_between_the_objects_and_the_ref_leaves_no_dangling_run(
    tmp_path, monkeypatch, compress, durable_step
):
    monkeypatch.setenv("OPENTINE_COMPRESS", compress)
    _, handler = _record(tmp_path, 50)
    order: list[str] = []
    real_step = getattr(_write_batch, durable_step)

    def step(*args, **kwargs):
        order.append("objects")
        return real_step(*args, **kwargs)

    def commit(*args, **kwargs):
        order.append("ref")
        raise Crash

    with monkeypatch.context() as patch:
        patch.setattr(_write_batch, durable_step, step)
        patch.setattr(store_module, "commit_ref", commit)
        with pytest.raises(Crash):
            _end(handler)
    assert order[0] == "objects" and order[-1] == "ref"  # durable before any ref moves
    _assert_no_dangling_run(tmp_path, 50)
