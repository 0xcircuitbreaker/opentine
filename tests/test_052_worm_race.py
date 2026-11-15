"""0.52: a delete racing an upload that reuses its chunks never loses one, and
``tine gc --sweep-expired`` removes only expired orphan chunks.

The race runs over seeded interleavings of the S3 test double (every client
call is one scheduling point); ``OPENTINE_STRESS_WORM_RACE_SEEDS`` raises the
number of seeds in the nightly job.
"""

from __future__ import annotations

import base64
import json
import os
import random

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote._fastcdc import ChunkParams
from opentine.remote._worm import GOVERNANCE, WormPolicy
from opentine.remote._worm_store import WormObjectStore
from opentine.remote.security import LocalKeyProvider
from tests._lockstep import Lockstep, Stepped
from tests._worm_fakes import FakeBlobClient

KEYS = LocalKeyProvider(b"k" * 32)
SMALL = ChunkParams(64, 256, 1024)
SEEDS = int(os.environ.get("OPENTINE_STRESS_WORM_RACE_SEEDS", "60"))


def _blob(data: bytes) -> tuple[str, bytes]:
    envelope = ObjectEnvelope.create("blob", data)
    return envelope.oid, envelope.encode()


def _store(client, policy=None) -> WormObjectStore:
    store = WormObjectStore(client, KEYS, policy, prefix="p", chunk_threshold=4096,
                            chunk_params=SMALL)  # fmt: skip
    store.fence_poll = 0  # every poll is a scheduling point already
    return store


def _chunks(client) -> set[str]:
    return {k for k in client.blobs if "/chunks/" in k}


@pytest.mark.parametrize("policy", [None, WormPolicy(GOVERNANCE, 1)], ids=["none", "governance"])
def test_a_delete_never_loses_a_chunk_a_concurrent_upload_reuses(policy):
    base = random.Random(7).randbytes(12_000)
    first, raw1 = _blob(base)
    second, raw2 = _blob(base + b"a different tail")
    for seed in range(SEEDS):
        fake = FakeBlobClient()
        _store(fake, policy).put("acme", first, raw1)
        for key in list(fake.blobs):  # the first object's retention has run out
            if policy is not None:
                fake.expire(key)
        step = Lockstep(seed)
        store = _store(Stepped(fake, step), policy)
        step.run({"delete": lambda s=store: s.delete("acme", first),
                  "upload": lambda s=store: s.put("acme", second, raw2)})  # fmt: skip
        assert step.errors == {}, (seed, step.errors)
        check = _store(fake, policy)
        assert check.get("acme", second) == raw2, seed  # every chunk is still there
        assert not check.has("acme", first)
        assert not [k for k in fake.blobs if "/chunk-fences/" in k], seed
        used = check.chunks_in_use("acme")
        assert {k.rsplit("/", 1)[1] for k in _chunks(fake)} == used, seed  # nothing leaked


def test_an_upload_waits_for_a_fence_and_then_restores_the_chunk():
    fake = FakeBlobClient()
    store = _store(fake)
    oid, raw = _blob(random.Random(1).randbytes(9_000))
    pieces = []

    def fenced_keys(prefix, keys=fake.keys):  # a reaper deletes the chunk mid-wait
        found = list(keys(prefix))
        if "/chunk-fences/" in prefix and not pieces:
            pieces.append(prefix)
            digest = prefix.rstrip("/").rsplit("/", 1)[1]
            fake.blobs.pop(f"p/acme/chunks/{digest}", None)
            return iter([prefix + "reaper"])
        return iter(found)

    store.put("acme", oid, raw)
    fake.keys = fenced_keys
    second, raw2 = _blob(random.Random(1).randbytes(9_000) + b"!")
    store.put("acme", second, raw2)
    assert pieces and store.get("acme", second) == raw2 and store.get("acme", oid) == raw


def test_a_stale_fence_does_not_block_uploads():
    fake = FakeBlobClient()
    store = _store(fake)
    oid, raw = _blob(random.Random(2).randbytes(9_000))
    store.put("acme", oid, raw)
    digest = next(iter(_chunks(fake))).rsplit("/", 1)[1]
    fake.blobs[f"p/acme/chunk-fences/{digest}/old"] = b"1000.0"  # a crashed reaper's
    store.fence_wait = 0
    second, raw2 = _blob(random.Random(2).randbytes(9_000) + b"!")
    store.put("acme", second, raw2)
    assert store.get("acme", second) == raw2


def test_a_live_fence_that_outlasts_the_wait_refuses_the_upload(monkeypatch):
    import time

    fake = FakeBlobClient()
    store = _store(fake)
    oid, raw = _blob(random.Random(3).randbytes(9_000))
    store.put("acme", oid, raw)
    digest = sorted(_chunks(fake))[0].rsplit("/", 1)[1]
    fake.blobs[f"p/acme/chunk-fences/{digest}/live"] = f"{time.time():.3f}".encode()
    store.fence_wait = -1
    second, raw2 = _blob(random.Random(3).randbytes(9_000) + b"!")
    with pytest.raises(OSError, match="being deleted"):
        store.put("acme", second, raw2)


def _seeded(fake, policy, count: int, seed: int) -> list[tuple[str, bytes]]:
    store = _store(fake, policy)
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        oid, raw = _blob(rng.randbytes(rng.randrange(5_000, 15_000)))
        store.put("acme", oid, raw)
        out.append((oid, raw))
    return out


def test_sweep_expired_removes_every_expired_orphan_and_nothing_live():
    fake = FakeBlobClient()
    policy = WormPolicy(GOVERNANCE, 1)
    objects = _seeded(fake, policy, 12, 5)
    small, raw_small = _blob(b"whole")
    _store(fake, policy).put("acme", small, raw_small)
    doomed, live = objects[:6], objects[6:]
    for key in list(fake.blobs):  # time passes for every key ...
        fake.expire(key)
    store = _store(fake, policy)
    for oid, _ in doomed:
        store.delete("acme", oid)
    # ... but the deletes above already reaped what they could; leave orphans to sweep
    orphans_before = _chunks(fake) - {f"p/acme/chunks/{d}" for d in store.chunks_in_use("acme")}
    leftovers = [random.Random(9).randbytes(40) for _ in range(5)]
    for i, payload in enumerate(leftovers):  # crashed uploads' chunks: no record names them
        fake.put(f"p/acme/chunks/{i:064x}", payload, mode=None, until=None, legal_hold=False)
    retained = f"p/acme/chunks/{'f' * 64}"
    fake.put(retained, b"r", mode=GOVERNANCE, until=policy.until(), legal_hold=False)
    live_before = {k: fake.blobs[k] for k in fake.blobs if "/chunks/" not in k}
    live_chunks = {f"p/acme/chunks/{d}" for d in store.chunks_in_use("acme")}
    report = store.sweep_expired("acme")
    assert report["swept"] == len(orphans_before) + len(leftovers)  # 100% of expired orphans
    assert report["retained"] == 1 and retained in fake.blobs
    assert _chunks(fake) == live_chunks | {retained}
    assert {k: fake.blobs[k] for k in fake.blobs if "/chunks/" not in k} == live_before
    for oid, raw in live:
        assert store.get("acme", oid) == raw
    assert store.get("acme", small) == raw_small
    assert store.sweep_expired("acme")["swept"] == 0


def test_records_written_before_0_52_still_protect_their_chunks():
    fake = FakeBlobClient()
    (oid, raw), = _seeded(fake, None, 1, 6)  # fmt: skip
    record = next(k for k in fake.blobs if "/chunked/" in k)
    fake.blobs[record] = b""  # what 0.49-0.51 wrote
    store = _store(fake)
    assert store.sweep_expired("acme")["swept"] == 0
    assert store.get("acme", oid) == raw


def test_gc_sweep_expired_cli(monkeypatch, capsys, tmp_path):
    from opentine import _schemas, cli
    from opentine.remote import _worm_config

    fake = FakeBlobClient()
    (oid, raw), = _seeded(fake, None, 1, 8)  # fmt: skip
    fake.put(f"p/acme/chunks/{'0' * 64}", b"x", mode=None, until=None, legal_hold=False)
    real = _worm_config.object_store_from_env
    monkeypatch.setattr(_worm_config, "object_store_from_env",
                        lambda state, keys, **kw: real(state, keys, client=fake, **kw))  # fmt: skip
    monkeypatch.setenv("TINE_REMOTE_OBJECT_STORE", "s3://bucket/p")
    monkeypatch.setenv("TINE_KMS_KEY", base64.b64encode(b"k" * 32).decode())
    code = 0
    try:
        cli.main(["gc", "--sweep-expired", "--state", str(tmp_path), "--json"])
    except SystemExit as exc:
        code = int(exc.code or 0)
    document = json.loads(capsys.readouterr().out)
    assert code == 0 and _schemas.validate_output(document) == []
    assert document["swept"] == 1 and document["tenants"][0]["tenant"] == "acme"
    assert f"p/acme/chunks/{'0' * 64}" not in fake.blobs
