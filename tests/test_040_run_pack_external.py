"""0.40: one pack and one fsync per run (P2), and external blob pointers."""

from __future__ import annotations

import hashlib
import json
import os
import socket
from pathlib import Path

import pytest

from opentine import Run, StepKind
from opentine.kernel import ObjectEnvelope
from opentine.repository import Repo, _external, _paths, _write_batch
from opentine.repository import store as store_module
from opentine.repository._config import rewrite_config
from opentine.repository._objects import iter_object_oids
from opentine.trace.recorder import Recorder
from opentine.trace.schema import TraceEvent


@pytest.fixture(autouse=True)
def _no_autopack(monkeypatch):
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "0")
    monkeypatch.delenv("OPENTINE_RUN_PACK", raising=False)


def _run(steps: int = 12) -> Run:
    run = Run(id="p2", model_info="mock/p2", system_prompt="sys", user_prompt="go")
    for index in range(steps):
        run.add_step(StepKind("tool"), {"path": f"f{index}.py"}, {"text": f"body {index}\n" * 9})
    return run


def _loose(repo: Repo) -> list[str]:
    root = repo.path / "objects"
    return [p.name for p in root.rglob("*") if p.is_file()]


def _packs(repo: Repo) -> list[str]:
    return sorted(p.name for p in (repo.path / "packs").glob("*.tpk"))


class _Counter:
    def __init__(self, monkeypatch):
        self.files = self.dirs = 0
        real_file, real_dir = _paths.full_fsync, _write_batch._fsync_dir

        def count_file(fd):
            self.files += 1
            real_file(fd)

        def count_dir(path):
            self.dirs += 1
            real_dir(path)

        for module in (_paths, _write_batch):
            monkeypatch.setattr(module, "full_fsync", count_file)
        monkeypatch.setattr(_paths, "_fsync_dir", count_dir)
        monkeypatch.setattr(_write_batch, "_fsync_dir", count_dir)


def test_a_put_run_lands_in_one_pack_with_one_sync_per_pack_file(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    published: list[str] = []
    real_publish = _write_batch.publish_pack
    monkeypatch.setattr(
        _write_batch,
        "publish_pack",
        lambda *a: (published.append(a[1]), real_publish(*a))[1],
    )
    counter = _Counter(monkeypatch)
    result = repo.put_run(_run(), ref=None)
    assert len(published) == 1 and _packs(repo) == [f"{published[0]}.tpk"]
    assert _loose(repo) == []  # nothing of the run was written loose
    # One fsync for the pack body, one for its index, one directory sync --
    # whatever the run's object count (a loose run paid two per object).
    assert (counter.files, counter.dirs) == (2, 1)
    objects = list(iter_object_oids(repo.path))
    assert len(objects) > 20 and result.run_id in objects
    assert repo.load_run(result.run_id).steps[3].outputs == {"text": "body 3\n" * 9}
    assert repo.fsck().ok


def test_the_ref_moves_only_after_the_pack_is_published(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    order: list[str] = []
    real_publish, real_commit = _write_batch.publish_pack, store_module.commit_ref
    monkeypatch.setattr(
        _write_batch, "publish_pack", lambda *a: (order.append("pack"), real_publish(*a))[1]
    )
    monkeypatch.setattr(
        store_module, "commit_ref", lambda *a, **k: (order.append("ref"), real_commit(*a, **k))[1]
    )
    repo.put_run(_run(), ref="heads/main")
    assert order[:2] == ["pack", "ref"]


def test_a_crash_between_pack_and_ref_leaves_a_consistent_repository(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    first = repo.put_run(_run(2), ref="heads/main").run_id

    class Crash(BaseException):
        pass

    def crash(*_a, **_k):
        raise Crash

    monkeypatch.setattr(store_module, "commit_ref", crash)
    with pytest.raises(Crash):
        repo.put_run(_run(), ref="heads/main")
    monkeypatch.undo()
    reopened = Repo.open(repo.path)
    assert reopened.read_ref("heads/main") == first  # the ref never moved
    assert len(_packs(reopened)) == 2  # the orphan pack is all that is left
    assert not [p for p in (repo.path / "packs").iterdir() if p.name.startswith(".")]
    report = reopened.fsck()
    assert report.ok, report
    reopened.load_run("heads/main")


def test_a_failed_run_writes_nothing(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")

    def boom(*_a, **_k):
        raise RuntimeError("annotation failed")

    monkeypatch.setattr("opentine.repository.runs.write_run_annotation", boom)
    monkeypatch.setattr(_write_batch, "flush", lambda repo: None)
    with pytest.raises(RuntimeError):
        repo.put_run(_run(), ref="heads/main")
    assert _packs(repo) == [] and _loose(repo) == []


def test_recorder_import_is_one_pack_and_appends_stay_loose(tmp_path):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    recorder = Recorder.start(repo, prompt="p", system="s", capture=False)
    before = set(_packs(repo))
    events = [
        TraceEvent("tool", 1.0 + i, "t", f"s{i}", inputs={"i": i}, outputs={"o": "x" * i})
        for i in range(10)
    ]
    recorder.import_events(events)
    assert len(set(_packs(repo)) - before) == 1
    recorder.append(TraceEvent("tool", 50.0, "t", "late", inputs={}, outputs={}))
    assert len(set(_packs(repo)) - before) == 1
    assert Repo.open(repo.path).fsck().ok


def test_opting_out_keeps_loose_writes(tmp_path, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    rewrite_config(repo.path, lambda config: config.update(run_pack=False) or True)
    repo.put_run(_run(3), ref="heads/main")
    assert _packs(repo) == [] and _loose(repo)


# -- external blob pointers -------------------------------------------------


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "bucket"
    directory.mkdir()
    return directory


def _allow(repo: Repo, *prefixes: str) -> None:
    rewrite_config(repo.path, lambda c: c.update(external_blobs={"allow": list(prefixes)}) or True)


def _point(repo: Repo, store: Path, content: bytes, name: str = "a.bin"):
    target = store / name
    target.write_bytes(content)
    return _external.add(repo.path, target.as_uri(), target)


def test_an_external_pointer_resolves_to_the_same_blob_id(tmp_path, store):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    content = os.urandom(5000)
    pointer = _point(repo, store, content)
    assert pointer.oid == ObjectEnvelope.create("blob", content).oid  # oid is unchanged
    assert pointer.sha256 == hashlib.sha256(content).hexdigest() and pointer.size == 5000
    assert not repo.has(pointer.oid)
    # A run may link it while it is still only a pointer.
    assert repo._link_exists(pointer.oid)
    _allow(repo, store.as_uri() + "/")
    raw = _external.resolve(repo, pointer.oid)
    assert ObjectEnvelope.decode(raw, pointer.oid).body == content
    assert repo.has(pointer.oid) and _external.status(repo) == {pointer.oid: "resolved"}


def test_size_and_hash_mismatches_are_refused(tmp_path, store):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _allow(repo, store.as_uri() + "/")
    pointer = _point(repo, store, b"original content")
    (store / "a.bin").write_bytes(b"original content plus more")
    with pytest.raises(_external.ExternalError, match="larger"):
        _external.resolve(repo, pointer.oid)
    (store / "a.bin").write_bytes(b"short")
    with pytest.raises(_external.ExternalError, match="size"):
        _external.resolve(repo, pointer.oid)
    (store / "a.bin").write_bytes(b"ORIGINAL CONTENT")
    with pytest.raises(_external.ExternalError, match="sha256"):
        _external.resolve(repo, pointer.oid)
    assert not repo.has(pointer.oid)
    # A forged pointer (right sha256 and size, wrong blob) fails the id check.
    forged = json.loads(_external._path(repo.path, pointer.oid).read_bytes())
    other = b"0" * len(b"ORIGINAL CONTENT")
    (store / "a.bin").write_bytes(other)
    forged["sha256"] = hashlib.sha256(other).hexdigest()
    _external._path(repo.path, pointer.oid).write_text(json.dumps(forged))
    with pytest.raises(_external.ExternalError, match="blob id"):
        _external.resolve(repo, pointer.oid)


def test_only_allowed_locations_are_read(tmp_path, store):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    pointer = _point(repo, store, b"secret")
    with pytest.raises(_external.ExternalError, match="allowed"):
        _external.resolve(repo, pointer.oid)  # nothing configured: nothing fetched
    other = tmp_path / "other"
    other.mkdir()
    _allow(repo, other.as_uri() + "/")
    with pytest.raises(_external.ExternalError, match="allowed"):
        _external.resolve(repo, pointer.oid)
    for bad in ("ftp://h/x", "https://user:pw@h/x", "https://h/a/../x", "gopher://h/"):
        with pytest.raises(_external.ExternalError):
            _external.add(repo.path, bad, b"x")


def test_offline_status_never_touches_the_network(tmp_path, store, monkeypatch):
    repo = Repo.init(tmp_path / "r", compression="zlib")
    _allow(repo, "https://artifacts.example/")
    pointer = _external.add(repo.path, "https://artifacts.example/big.bin", b"big" * 100)

    def no_network(*_a, **_k):
        raise AssertionError("offline verification opened a connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(_external, "_download", no_network)
    assert _external.status(repo) == {pointer.oid: "unresolved"}
    assert repo.fsck().ok
