"""0.49: FastCDC chunking as a stored form, with lazy fetch from the object store."""

from __future__ import annotations

import random

import pytest

from opentine.kernel import KernelError, ObjectEnvelope
from opentine.remote import _fastcdc
from opentine.remote._chunk_manifest import MARKER, Manifest
from opentine.remote._fastcdc import CHUNK_THRESHOLD, ChunkParams, boundaries, chunks
from opentine.remote._worm_store import CHUNK, WormObjectStore
from opentine.remote.security import LocalKeyProvider
from tests._worm_fakes import FakeBlobClient

KEYS = LocalKeyProvider(b"k" * 32)
SMALL = ChunkParams(64, 256, 1024)


def _data(n: int, seed: int = 7) -> bytes:
    return random.Random(seed).randbytes(n)


def _store(client=None):
    client = client or FakeBlobClient()
    return client, WormObjectStore(client, KEYS, chunk_threshold=4096, chunk_params=SMALL)


def test_threshold_and_gear_table():
    assert CHUNK_THRESHOLD == 8 * 1024 * 1024
    assert len(set(_fastcdc._GEAR)) == 256  # one generator, not 256 equal values


def test_chunks_are_bounded_join_back_and_are_deterministic():
    data = _data(50_000)
    pieces = list(chunks(data, SMALL))
    assert b"".join(pieces) == data and len(pieces) > 20
    assert all(64 < len(p) <= 1024 for p in pieces[:-1])
    assert list(boundaries(data, SMALL)) == list(boundaries(bytearray(data), SMALL))
    assert list(chunks(b"", SMALL)) == [] and list(chunks(b"ab", SMALL)) == [b"ab"]


def test_boundaries_resynchronise_after_an_insert():
    data = _data(60_000)
    before = set(chunks(data, SMALL))
    edited = data[:100] + b"INSERTED" + data[100:]
    after = list(chunks(edited, SMALL))
    shared = sum(1 for piece in after if piece in before)
    assert shared >= len(after) - 3  # only the chunks near the edit change


def test_params_are_validated():
    for bad in ((64, 300, 1024), (0, 256, 1024), (512, 256, 1024), (64, 256, 128)):
        with pytest.raises(ValueError):
            ChunkParams(*bad)


def test_manifest_round_trip_and_rejects_damage():
    manifest = Manifest.of([b"a" * 10, b"b" * 5])
    assert Manifest.decode(manifest.encode()) == manifest and manifest.total == 15
    assert [s[2] for s in manifest.span(9, 2)] == [0, 10] and len(manifest.span(0, 3)) == 1
    raw = manifest.encode()
    for bad in (raw[:-1], b"XXXXXXXX" + raw[8:], raw[:8] + (99).to_bytes(8, "big") + raw[16:]):
        with pytest.raises(ValueError):
            Manifest.decode(bad)


def test_large_payload_is_chunked_oid_unchanged_and_deduplicated():
    client, store = _store()
    envelope = ObjectEnvelope.create("blob", _data(40_000))
    oid, raw = envelope.oid, envelope.encode()
    store.put("acme", oid, raw)
    assert client.blobs[store._key("acme", oid)].startswith(MARKER)
    manifest = store.manifest("acme", oid)
    assert manifest is not None and manifest.total == len(raw)
    assert store.get("acme", oid) == raw and store.size("acme", oid) == len(raw)
    assert ObjectEnvelope.decode(store.get("acme", oid), oid).oid == oid
    first = {k for k in client.blobs if "/chunks/" in k}
    grown = ObjectEnvelope.create("blob", envelope.body + b"one more line\n")
    store.put("acme", grown.oid, grown.encode())
    added = {k for k in client.blobs if "/chunks/" in k} - first
    assert len(added) <= 2  # a grown transcript stores only its new tail
    assert sorted(store.list("acme")) == sorted([oid, grown.oid])


def test_lazy_fetch_reads_only_the_chunks_in_range():
    client, store = _store()
    envelope = ObjectEnvelope.create("blob", _data(40_000))
    oid, raw = envelope.oid, envelope.encode()
    store.put("acme", oid, raw)
    total = len(store.manifest("acme", oid).chunks)
    client.gets.clear()
    assert store.read_range("acme", oid, 20_000, 100) == raw[20_000:20_100]
    fetched = [k for k in client.gets if "/chunks/" in k]
    assert 1 <= len(fetched) <= 2 < total
    client.gets.clear()
    stream = store.stream("acme", oid)
    first = next(stream)
    assert raw.startswith(first) and len([k for k in client.gets if "/chunks/" in k]) == 1
    assert store.read_range("acme", oid, len(raw) - 5, 50) == raw[-5:]


def test_a_damaged_chunk_is_caught_and_the_whole_object_is_rehashed():
    client, store = _store()
    envelope = ObjectEnvelope.create("blob", _data(30_000))
    oid, raw = envelope.oid, envelope.encode()
    store.put("acme", oid, raw)
    digest = store.manifest("acme", oid).chunks[3][0]
    other = _data(500, seed=9)
    sealed = KEYS.seal(CHUNK, "acme", digest, other)  # validly sealed, wrong bytes
    client.blobs[store._chunk_key("acme", digest)] = sealed
    with pytest.raises(ValueError, match="digest"):
        store.get("acme", oid)
    # a manifest that lists a different (self-consistent) chunk still fails the oid
    client2, store2 = _store()
    store2.put("acme", oid, raw)
    bogus = Manifest.of([b"x" * len(raw)])
    good = store2._chunk_key("acme", bogus.chunks[0][0])
    client2.blobs[good] = KEYS.seal(CHUNK, "acme", bogus.chunks[0][0], b"x" * len(raw))
    client2.blobs[store2._key("acme", oid)] = MARKER + KEYS.seal(
        "object", "acme", oid, bogus.encode()
    )
    with pytest.raises((KernelError, ValueError)):
        store2.get("acme", oid)
