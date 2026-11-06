"""0.37: packed-refs (P4), autopack by count and bytes (P1), the lazy pack index
(P7) and tip negotiation (P5)."""

from __future__ import annotations

import json
import os

import pytest

from opentine import Run, StepKind
from opentine._ref_delete import delete_ref
from opentine.kernel import KernelError
from opentine.repository import Repo, _config, _gc_refs, _packed_refs
from opentine.repository._gc import gc
from opentine.repository._paths import internal_path


def _run(store: Repo, label: str, ref: str | None = None) -> str:
    run = Run(id=f"r{label}", model_info="m")
    run.add_step(StepKind.model, {"text": label}, {"text": "ok"})
    return store.put_run(run, ref=ref).run_id


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "0")
    return Repo.init(tmp_path)


def _loose(repo: Repo, name: str):
    return internal_path(repo.path, "refs", *name.split("/"))


def _config_of(repo: Repo) -> dict:
    return json.loads(internal_path(repo.path, "config.json").read_text())


# -- P4 packed-refs ---------------------------------------------------------


def test_gc_leaves_loose_refs_alone_until_the_repository_opts_in(repo):
    a = _run(repo, "a", "heads/main")
    gc(repo)
    assert _loose(repo, "heads/main").is_file()
    assert not internal_path(repo.path, "packed-refs").exists()
    assert repo.list_refs() == {"heads/main": a}


def test_opted_in_gc_packs_refs_and_reads_fall_back_to_them(repo):
    a, b = _run(repo, "a", "heads/main"), _run(repo, "b", "tags/v1")
    _gc_refs.enable(repo)
    result = gc(repo)
    assert result.refs_packed == 2
    assert not _loose(repo, "heads/main").exists() and not _loose(repo, "tags/v1").exists()
    raw = internal_path(repo.path, "packed-refs").read_bytes()
    assert raw == _packed_refs.HEADER + f"{a} heads/main\n{b} tags/v1\n".encode()
    assert repo.read_ref("heads/main") == a and repo.list_refs() == {"heads/main": a, "tags/v1": b}
    # A write lands loose and shadows the packed value; CAS sees the packed one.
    c = _run(repo, "c")
    repo.update_ref("heads/main", c, expected_old=a)
    assert repo.read_ref("heads/main") == c and repo.list_refs()["heads/main"] == c
    repo.update_refs([("tags/v1", c, b)])
    assert repo.list_refs() == {"heads/main": c, "tags/v1": c}
    assert repo.fsck().ok


def test_delete_removes_the_packed_value_too(repo):
    a = _run(repo, "a", "heads/topic")
    _gc_refs.enable(repo)
    gc(repo)
    delete_ref(repo.path, "heads/topic", a)
    assert repo.read_ref("heads/topic") is None and "heads/topic" not in repo.list_refs()
    # Shadowed (loose and packed): the delete must not resurrect the packed value.
    b = _run(repo, "b", "heads/x")
    gc(repo)
    repo.update_ref("heads/x", a, expected_old=b)
    delete_ref(repo.path, "heads/x", a)
    assert repo.read_ref("heads/x") is None


def test_gc_keeps_a_ref_that_moved_after_the_snapshot(repo, monkeypatch):
    a, b = _run(repo, "a", "heads/main"), _run(repo, "b")
    _gc_refs.enable(repo)
    real = _packed_refs.write_packed

    def racing(base, refs):  # a writer moves the ref right after gc's snapshot
        real(base, refs)
        monkeypatch.setattr(_gc_refs, "write_packed", real)
        repo.update_ref("heads/main", b, expected_old=a)

    monkeypatch.setattr(_gc_refs, "write_packed", racing)
    assert _gc_refs.pack_refs(repo.path) == 0
    assert _loose(repo, "heads/main").is_file() and repo.read_ref("heads/main") == b


def test_a_ref_held_open_on_windows_stays_loose(repo, monkeypatch):
    from opentine.repository import _winretry

    a = _run(repo, "a", "heads/main")
    _gc_refs.enable(repo)
    real = _winretry.unlink

    def held(path):  # a reader holds the ref open: its removal is a sharing violation
        if not str(path).endswith(".lock"):
            raise PermissionError(13, "in use", str(path))
        real(path)

    monkeypatch.setattr(_winretry, "unlink", held)
    assert _gc_refs.pack_refs(repo.path) == 0
    monkeypatch.setattr(_winretry, "unlink", real)
    assert _loose(repo, "heads/main").is_file() and repo.list_refs() == {"heads/main": a}
    assert not list(internal_path(repo.path, "refs", "heads").glob("*.lock"))
    assert _gc_refs.pack_refs(repo.path) == 1


def test_opting_in_gates_older_readers_and_unpack_restores_them(repo):
    a = _run(repo, "a", "heads/main")
    _gc_refs.enable(repo)
    config = _config_of(repo)
    assert config["refs"] == "packed" and config["min_reader"] == _packed_refs.MIN_READER
    assert "format" not in config and config["objects"] == 4
    gc(repo)
    # What a 0.36 reader (READER_VERSION 0.26.0) does with this descriptor: refuse.
    path = internal_path(repo.path, "config.json")
    old = _config.READER_VERSION
    try:
        _config.READER_VERSION = (0, 26, 0)
        with pytest.raises(ValueError, match="needs opentine 0.37.0"):
            _config.read_config(path)
    finally:
        _config.READER_VERSION = old
    assert _gc_refs.disable(repo) == 1
    assert _loose(repo, "heads/main").read_text() == a + "\n"
    assert not internal_path(repo.path, "packed-refs").exists()
    assert "refs" not in _config_of(repo) and _config_of(repo)["min_reader"] == "0.26.0"


def test_a_malformed_packed_refs_is_refused_and_reported(repo):
    a = _run(repo, "a", "heads/main")
    _gc_refs.enable(repo)
    gc(repo)
    path = internal_path(repo.path, "packed-refs")
    for bad in (
        b"garbage\n",
        _packed_refs.HEADER + f"{a} heads/z\n{a} heads/a\n".encode(),  # unsorted
        _packed_refs.HEADER + f"{a} ../escape\n".encode(),
        _packed_refs.HEADER + b"run:sha256:00 heads/main\n",
    ):
        path.write_bytes(bad)
        with pytest.raises(KernelError):
            repo.list_refs()
    path.write_bytes(_packed_refs.HEADER + f"{a} heads/main\n".encode())
    assert repo.read_ref("heads/main") == a


def test_list_refs_opens_no_ref_file_once_refs_are_packed(repo, monkeypatch):
    from opentine.repository import _ref_store

    a = _run(repo, "a")
    repo.update_refs([(f"tags/t{i:03}", a, None) for i in range(50)])
    _gc_refs.enable(repo)
    gc(repo)
    reads: list[str] = []
    real = _ref_store.read_loose_oid
    monkeypatch.setattr(_ref_store, "read_loose_oid", lambda b, n: reads.append(n) or real(b, n))
    _packed_refs._CACHE.clear()
    assert len(repo.list_refs()) == 50 and reads == []


# -- P7 lazy, mapped pack index ---------------------------------------------


def _packed_repo(tmp_path, runs: int = 6) -> tuple[Repo, list[str]]:
    store = Repo.init(tmp_path / "p", compression="zlib")
    for index in range(runs):
        _run(store, f"p{index}", f"heads/p{index}")
    gc(store, upgrade=True)
    return store, store.iter_oids()


@pytest.mark.parametrize("mapped", [True, False])  # False: the Windows path (no mmap)
def test_a_cold_lookup_never_loads_every_index_entry(tmp_path, monkeypatch, mapped):
    from opentine.repository import _pack_lookup, _packs

    monkeypatch.setattr(_pack_lookup, "USE_MMAP", mapped)
    store, oids = _packed_repo(tmp_path)
    _packs._CACHE.clear()
    cold = Repo.open(store.path)
    probes: list[str] = []
    real = Repo._object_path
    monkeypatch.setattr(Repo, "_object_path", lambda self, o: probes.append(o) or real(self, o))
    assert all(cold.has(oid) for oid in oids)
    assert probes == []  # has() asked the pack index first: no loose path walk
    assert cold.raw(oids[0]) and cold.load_run("heads/p0").steps
    packs = _packs.pack_set(cold.path)
    assert packs._where is None and packs._v3 is None  # no oid -> place dict was built
    index = next(iter(packs.indexes.values()))
    assert isinstance(index, _pack_lookup.MappedIndex)
    assert isinstance(index.data, bytes) is not mapped
    whole = index.entries()
    assert len(whole) == len(oids)
    assert all(index.find(oid) == place for oid, place in whole.items())
    assert index.find("blob:sha256:" + "0" * 64) is None and index.find("nope") is None
    assert not cold.has("event:sha256:" + "f" * 64)


def test_a_crafted_index_entry_is_refused_at_lookup(tmp_path):
    import hashlib

    from opentine.repository import _pack_lookup
    from opentine.repository import _pack_v3_index as v3index

    store, _ = _packed_repo(tmp_path, runs=1)
    packs = store.path / "packs"
    digest = next(p.name[:64] for p in packs.iterdir() if p.suffix == ".tidx")
    data = bytearray((packs / f"{digest}.tidx").read_bytes())
    _, _, count, _ = v3index._HEAD.unpack_from(data)
    first = v3index._HEAD.size + count * v3index._BLOCK.size
    row = list(v3index._ENTRY.unpack_from(data, first))
    row[3] = 10**6  # start far past its block's end
    v3index._ENTRY.pack_into(data, first, *row)
    data[-32:] = hashlib.sha256(data[:-32]).digest()  # a consistent, crafted index
    index = _pack_lookup.MappedIndex(bytes(data), digest, (packs / f"{digest}.tpk").stat().st_size)
    oid = f"{v3index.KINDS[row[0]]}:sha256:{row[1].hex()}"
    with pytest.raises(KernelError, match="does not fit its block"):
        index.find(oid)
    with pytest.raises(KernelError):
        index.entries()


def test_version_1_pack_indexes_are_still_read(tmp_path):
    from opentine.repository import _pack_lookup, _packs

    store, oids = _packed_repo(tmp_path)
    gc(store, downgrade=True)
    _packs._CACHE.clear()
    cold = Repo.open(store.path)
    assert all(cold.has(oid) and cold.raw(oid) for oid in oids)
    indexes = _packs.pack_set(cold.path).indexes.values()
    assert {type(index) for index in indexes} == {_pack_lookup.LegacyIndex}


# -- P1 autopack by bytes ---------------------------------------------------


def test_autopack_triggers_on_cold_loose_bytes(tmp_path, monkeypatch):
    import time

    from opentine.repository import _autopack
    from opentine.repository._gc_tidy import loose_entries

    monkeypatch.setenv("OPENTINE_AUTO_PACK", "1000")  # far more objects than written
    monkeypatch.delenv("OPENTINE_AUTO_PACK_BYTES", raising=False)
    store = Repo.init(tmp_path / "a", compression="zlib")
    for _ in range(3):
        store.put("blob", os.urandom(64 * 1024), redact=False)
    stamp = time.time() - 600
    for _, path, _ in loose_entries(store.path):
        os.utime(path, (stamp, stamp))
    assert _autopack.maybe_autopack(store) is None  # under the 16 MiB default
    monkeypatch.setenv("OPENTINE_AUTO_PACK_BYTES", str(64 * 1024))
    assert _autopack.maybe_autopack(store) is not None
    assert not list(loose_entries(store.path))


def test_autopack_byte_threshold_is_configurable(tmp_path, monkeypatch):
    from opentine.repository import _autopack
    from opentine.repository._config import rewrite_config

    monkeypatch.delenv("OPENTINE_AUTO_PACK_BYTES", raising=False)
    store = Repo.init(tmp_path / "c", compression="zlib")
    assert _autopack.byte_threshold(store) == _autopack.DEFAULT_BYTES
    rewrite_config(store.path, lambda c: c.update(auto_pack={"bytes": 4096}) or True)
    assert _autopack.byte_threshold(store) == 4096
    small = os.stat(internal_path(store.path, "config.json"))
    assert _autopack.disk_bytes(small) >= min(small.st_size, 512)


# -- P5 tip negotiation -----------------------------------------------------


def _remote(tmp_path, monkeypatch, *, tips: bool):
    import httpx

    from opentine.remote import (
        FilesystemObjectStore,
        Identity,
        LocalKeyProvider,
        RemoteApp,
        RemoteService,
        RoleAuthorizationPolicy,
        SQLiteBackend,
        StaticTokenIdentityProvider,
    )
    from opentine.repository import client as repository_client

    identities = StaticTokenIdentityProvider({"t": Identity("w", "acme", ("writer",))})
    service = RemoteService(
        FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32)),
        SQLiteBackend(tmp_path / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
    )
    caps = service.capabilities()
    if not tips:  # what a 0.36 server advertises
        caps.pop("negotiation")
    monkeypatch.setattr(service, "capabilities", lambda: dict(caps))
    app = RemoteApp(service, tmp_path / "state")
    sent: list[dict] = []
    original = app._json

    def recording(environ, *allowed):
        if not tips:
            allowed = tuple(key for key in allowed if key != "tips")  # 0.36 refuses it
        data = original(environ, *allowed)
        sent.append(data)
        return data

    app._json = recording

    def client(base, token, **kwargs):
        transport = httpx.WSGITransport(app=app)
        auth = {"Authorization": "Bearer t"}
        return httpx.Client(base_url="http://remote", transport=transport, headers=auth)

    monkeypatch.setattr(repository_client, "_client", client)
    return service, service.authenticate({"Authorization": "Bearer t"}), sent


@pytest.mark.parametrize("tips", [True, False])
def test_fetch_negotiates_on_tips_and_falls_back_to_haves(tmp_path, monkeypatch, tips):
    from opentine.repository import client as repository_client
    from opentine.repository._annotations import write_run_annotation

    service, writer, sent = _remote(tmp_path, monkeypatch, tips=tips)
    origin = Repo.init(tmp_path / "origin")
    a = _run(origin, "a", "heads/main")
    service.install_pack(writer, "acme", origin.pack())
    service.update_ref(writer, "acme", "heads/main", a, None)
    local = Repo.init(tmp_path / "local")
    _run(local, "local-only", "heads/mine")
    repository_client.fetch(local, "https://remote", tenant="acme", token="t")
    assert local.has(a)
    note = write_run_annotation(origin, a, {"label": "good"}, [])
    service.install_pack(writer, "acme", origin.pack())
    sent.clear()
    result = repository_client.fetch(
        local, "https://remote", tenant="acme", token="t", wants=[note]
    )
    request = next(item for item in sent if "wants" in item)
    if tips:
        assert request["haves"] == [] and a in request["tips"]
        assert set(request["tips"]) <= set(local.list_refs().values())
        assert result.objects == 1  # the annotation alone: a's history stayed put
    else:
        assert "tips" not in request and a in request["haves"]
    assert local.has(note) and local.fsck().ok


def test_the_server_walk_stops_at_the_clients_tips(tmp_path):
    from opentine.repository.pack import negotiate

    store = Repo.init(tmp_path / "s")
    a = _run(store, "a", "heads/main")
    b = _run(store, "b", "heads/other")
    everything = negotiate(store, [a, b], [])
    stopped = negotiate(store, [a, b], [], tips=[a])
    assert a in everything and a not in stopped
    assert set(stopped) == set(negotiate(store, [b], [])) - {a}
    assert set(stopped) < set(everything)
    with pytest.raises(KernelError, match="invalid typed object id"):
        negotiate(store, [a], [], tips=["not-an-oid"])
    with pytest.raises(KernelError, match="too many tips"):
        negotiate(store, [a], [], tips=[a] * 5000)
