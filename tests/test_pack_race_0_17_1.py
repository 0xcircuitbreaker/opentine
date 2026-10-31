"""0.17.1: a reader racing a gc never reports a stored object missing.

The recorder in ``test_autopack_and_prune_racing_a_live_recorder_lose_nothing``
died on Windows with ``missing linked object`` for an object it had stored
itself. A gc in another process had packed that object and was deleting its
loose copy. On Windows a file or directory being deleted while any handle is
open on it is *delete-pending*: inspecting it fails with an access error, not
"not found". ``internal_path`` turned that ``OSError`` into a ``KernelError``,
and ``object_exists`` took any ``KernelError`` from the loose check to mean
"absent" -- without looking in the pack the gc had already published.

These tests reproduce the Windows behaviour on any OS by making the gc's freshly
deleted paths raise ``PermissionError`` when inspected, exactly in the window
between the gc publishing its pack and the deletion completing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from opentine import Recorder, TraceEvent
from opentine.repository import Repo, _gc, _packs
from opentine.repository._gc import gc


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    monkeypatch.setattr("opentine.repository._storage._pause", lambda attempt: None)


def _recorded(tmp_path, steps=3) -> tuple[Repo, str]:
    repo = Repo.init(tmp_path / "r", compression="zlib")
    rec = Recorder.start(repo, ref="heads/live", prompt="live", capture=False)
    for index in range(steps):
        rec.append(
            TraceEvent(
                kind="tool",
                timestamp=index + 1.0,
                trace_id="t",
                span_id=f"s{index}",
                actor="a",
                inputs={"i": index},
                outputs={"text": f"live {index} " * 80},
            )
        )
    return repo, rec.run_id


def _deny(path):
    raise PermissionError(13, "delete pending", str(path))


def test_link_check_during_a_concurrent_loose_delete_sees_the_pack(tmp_path, monkeypatch):
    repo, run = _recorded(tmp_path)
    reader = Repo.open(repo.path)  # the recorder's side
    real_lstat, real_remove = Path.lstat, _gc._remove_loose
    checked = []

    def remove(owner, oid):
        path = owner._object_path(oid)
        real_remove(owner, oid)
        # The pack is published; the loose entry (and the emptied fan-out
        # directory) is delete-pending while another handle is still open.
        pending = {path, path.parent}
        with monkeypatch.context() as patch:
            patch.setattr(Path, "lstat", lambda p: _deny(p) if p in pending else real_lstat(p))
            assert reader.has(oid), oid
            assert reader.raw(oid) == owner.raw(oid)
            if oid.startswith(("run:", "event:")):
                reader.get(oid)  # validate_links: every linked object exists
        checked.append(oid)

    monkeypatch.setattr(_gc, "_remove_loose", remove)
    gc(repo, min_age=0)
    assert any(oid.startswith("blob:") for oid in checked)
    assert any(oid.startswith("event:") for oid in checked)
    assert len(Repo.open(repo.path).get(run).payload()["events"]) == 3


def test_reading_a_pack_another_process_merged_away_retries(tmp_path, monkeypatch):
    repo, run = _recorded(tmp_path)
    gc(repo, min_age=0)
    stale = _packs.pack_set(repo.path)
    stale.refresh()
    oid = next(o for o in stale.where if o.startswith("event:"))
    expected = repo.raw(oid)
    # Another process merges every pack into a new one; this one's view is stale.
    _packs._CACHE[str(repo.path)] = _packs.PackSet(repo.path)
    repo.put("blob", b"more")
    gc(repo, min_age=0, repack=True)
    _packs._CACHE[str(repo.path)] = stale
    real_read = _packs._read_file

    def read_file(path, *args, **kwargs):
        if not Path(path).exists():
            _deny(path)  # Windows: opening a delete-pending pack is an access error
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(_packs, "_read_file", read_file)
    stale._recent.clear()
    assert repo.raw(oid) == expected
    assert repo.has(oid) and repo.get(run)


def test_a_transient_pack_listing_error_is_not_absence(tmp_path, monkeypatch):
    repo, run = _recorded(tmp_path)
    gc(repo, min_age=0)
    packs = _packs.pack_set(repo.path)
    packs.fingerprint = None
    real_scan, failures = _packs.PackSet._scan, [1]

    def scan(self):
        if failures:
            failures.pop()
            _deny(self.root / "packs")
        return real_scan(self)

    monkeypatch.setattr(_packs.PackSet, "_scan", scan)
    assert repo.has(run)
    assert not failures
