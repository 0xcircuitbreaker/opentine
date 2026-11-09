"""0.49 review: reused chunks keep the newest retention; store parity with the filesystem."""

from __future__ import annotations

import datetime
import os

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote._fastcdc import ChunkParams
from opentine.remote._worm import COMPLIANCE, GOVERNANCE, RetentionLocked, WormPolicy
from opentine.remote._worm_store import WormObjectStore
from opentine.remote.security import LocalKeyProvider
from tests._worm_fakes import FakeBlobClient

KEYS = LocalKeyProvider(b"k" * 32)
SMALL = ChunkParams(64, 256, 1024)


def _blob(data: bytes) -> tuple[str, bytes]:
    envelope = ObjectEnvelope.create("blob", data)
    return envelope.oid, envelope.encode()


def _store(client, policy, **kw):
    return WormObjectStore(
        client, KEYS, policy, prefix="p", chunk_threshold=4096, chunk_params=SMALL, **kw
    )


def test_a_reused_chunk_is_relocked_for_the_newer_object():
    client = FakeBlobClient()
    base = os.urandom(20_000)
    first, raw1 = _blob(base)
    _store(client, WormPolicy(GOVERNANCE, 1)).put("acme", first, raw1)
    chunk_keys = [k for k in client.blobs if "/chunks/" in k]
    for key in chunk_keys:  # the first object's retention has run out
        client.expire(key)
    second, raw2 = _blob(base + b"tail")
    store = _store(client, WormPolicy(COMPLIANCE, 30))
    store.put("acme", second, raw2)
    soon = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=29)
    used = {store._chunk_key("acme", d) for d, _ in store.manifest("acme", second).chunks}
    reused = [k for k in chunk_keys if k in used]
    assert reused
    for key in reused:
        state = client.locks[key]
        assert state.mode == COMPLIANCE and state.until > soon
        with pytest.raises(RetentionLocked):
            client.delete(key)


def test_tombstones_are_read_from_the_state_root(tmp_path):
    from opentine.remote import _tombstone_store

    store = _store(FakeBlobClient(), None, holds_root=tmp_path)
    oid, _ = _blob(b"gone")
    assert store.root == tmp_path and not store.tombstoned("acme", oid)
    path = _tombstone_store._path(tmp_path, "acme", oid)
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    assert store.tombstoned("acme", oid)


def test_deleting_a_missing_object_is_file_not_found():
    store = _store(FakeBlobClient(), None)
    with pytest.raises(FileNotFoundError):
        store.delete("acme", _blob(b"never")[0])


def test_uncompressed_tenants_are_honoured():
    client = FakeBlobClient()
    store = _store(client, None, uncompressed_tenants=frozenset({"acme"}))
    oid, raw = _blob(b"a" * 2000)
    store.put("acme", oid, raw)
    assert client.blobs[store._key("acme", oid)].startswith(b"TINEAES3")
    assert store.get("acme", oid) == raw
