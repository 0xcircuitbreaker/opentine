"""0.77: object-store-native packs for ``tine serve`` (S3 via moto, and the filesystem).

The live S3 case runs only when ``TINE_TEST_S3_BUCKET`` names a bucket the
ambient AWS credentials can write (docs/INGEST.md); it is skipped otherwise.
No test here reaches the network: S3 is moto's in-process fake.
"""

from __future__ import annotations

import importlib.util
import os
import uuid

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.kernel import ObjectEnvelope
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._pack_blobs import (
    MIN_PART_BYTES,
    DigestMismatch,
    FilesystemPackBlobs,
    S3PackBlobs,
    multipart_etag,
)
from opentine.remote._packed_store import PackedObjectStore
from opentine.repository import Repo

KEYS = LocalKeyProvider(b"k" * 32)
HAS_MOTO = importlib.util.find_spec("moto") is not None and importlib.util.find_spec("boto3")


def _blobs(n: int, tag: bytes = b"") -> list[tuple[str, bytes]]:
    out = []
    for i in range(n):
        env = ObjectEnvelope.create("blob", tag + b"object %d" % i)
        out.append((env.oid, env.encode()))
    return out


@pytest.fixture
def s3(monkeypatch):
    if not HAS_MOTO:
        pytest.skip("moto[s3] is not installed")
    from moto import mock_aws

    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        import boto3

        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="tine-packs")
        yield client


@pytest.fixture(params=["file", "s3"])
def blobs(request, tmp_path):
    if request.param == "file":
        return FilesystemPackBlobs(tmp_path / "packs")
    client = request.getfixturevalue("s3")
    return S3PackBlobs("tine-packs", client, prefix="pre")


def test_a_batch_is_one_pack_readable_after_restart(blobs, tmp_path):
    store = PackedObjectStore(blobs, KEYS, holds_root=tmp_path / "state")
    items = _blobs(20)
    digest = store.put_many("acme", items)
    names = sorted(blobs.names("acme/packs/"))
    assert names == [f"acme/packs/{digest}.tidx", f"acme/packs/{digest}.tpk"]
    fresh = PackedObjectStore(blobs, KEYS)  # another server process: reads the listing
    assert fresh.list("acme") == sorted(oid for oid, _ in items)
    assert all(fresh.get("acme", oid) == raw for oid, raw in items)
    assert fresh.put_many("acme", items) is None  # nothing new, nothing written
    assert fresh.fsck("acme") == {"tenant": "acme", "packs": 1, "objects": 20, "bad": []}


def test_names_are_never_overwritten(blobs):
    assert blobs.put("acme/x", b"first") is True
    assert blobs.put("acme/x", b"second") is False
    assert blobs.get("acme/x") == b"first"


def test_listing_race_index_without_body_is_skipped_then_found(blobs, tmp_path):
    store = PackedObjectStore(blobs, KEYS)
    writer = PackedObjectStore(blobs, KEYS)
    (oid, raw), = _blobs(1)  # fmt: skip
    digest = writer.put_many("acme", [(oid, raw)])
    body = blobs.get(f"acme/packs/{digest}.tpk")
    blobs.delete(f"acme/packs/{digest}.tpk")  # as if the listing saw the index first
    assert not store.has("acme", oid)
    assert store.fsck("acme")["bad"] == [f"pack {digest}: index without a readable body"]
    blobs.put(f"acme/packs/{digest}.tpk", body)
    assert store.get("acme", oid) == raw


def test_a_swapped_body_fails_closed(blobs):
    store = PackedObjectStore(blobs, KEYS)
    one = store.put_many("acme", _blobs(2, b"a"))
    two = store.put_many("acme", _blobs(2, b"b"))
    other = blobs.get(f"acme/packs/{two}.tpk")
    blobs.delete(f"acme/packs/{one}.tpk")
    blobs.put(f"acme/packs/{one}.tpk", other)
    reader = PackedObjectStore(blobs, KEYS)
    with pytest.raises(Exception):  # noqa: B017 - the AEAD context or the digest refuses it
        reader.get("acme", _blobs(1, b"a")[0][0])
    assert len(reader.fsck("acme")["bad"]) == 2


def test_delete_rewrites_the_pack_and_honours_holds(blobs, tmp_path):
    state = tmp_path / "state"
    store = PackedObjectStore(blobs, KEYS, holds_root=state)
    items = _blobs(3)
    store.put_many("acme", items)
    (state / ".holds").mkdir(parents=True)
    held = {"format": "tine-holds/1", "holds": [{"oid": items[0][0], "target": "keep"}]}
    import json

    (state / ".holds" / "acme").write_bytes(json.dumps(held).encode())
    with pytest.raises(PermissionError):
        store.delete("acme", items[0][0])
    store.delete("acme", items[1][0])
    reader = PackedObjectStore(blobs, KEYS)
    assert reader.list("acme") == sorted([items[0][0], items[2][0]])
    assert reader.fsck("acme")["bad"] == []


def test_s3_upload_refuses_a_part_altered_in_transit(s3):
    class Tamper:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def upload_part(self, **kw):
            if kw["PartNumber"] == 2:
                kw["Body"] = b"X" + kw["Body"][1:]
            return self.inner.upload_part(**kw)

    part = MIN_PART_BYTES
    data = bytes(range(256)) * (2 * part // 256) + b"tail"  # three parts, the last short
    blobs = S3PackBlobs("tine-packs", Tamper(s3), part_bytes=part)
    with pytest.raises(DigestMismatch):
        blobs.put("acme/y", data)
    assert not blobs.exists("acme/y")  # the bad upload does not stay under the name
    honest = S3PackBlobs("tine-packs", s3, part_bytes=part)
    assert honest.put("acme/y", data) and honest.get("acme/y") == data
    assert honest.put("acme/y", data[:-1]) is False  # never overwritten, multipart too
    assert multipart_etag([b"abcd", b"efgh", b"ij"]).endswith('-3"')


def test_server_push_lands_as_one_pack_and_fetches(s3, tmp_path, monkeypatch):
    monkeypatch.setenv("TINE_REMOTE_PACK_STORE", "s3://tine-packs/srv")
    monkeypatch.delenv("TINE_REMOTE_OBJECT_STORE", raising=False)
    identities = StaticTokenIdentityProvider({"t": Identity("alice", "acme", ("writer",))})
    app = server.reference_app(tmp_path / "srv", identities=identities, keys=KEYS)
    assert isinstance(app.service.objects, PackedObjectStore)
    local = Repo.init(tmp_path / "repo")
    run = Run(id="alpha", metadata={"label": "alpha"})
    run.add_step(StepKind.done, {"text": "alpha"})
    run_id = local.put_run(run).run_id
    writer = app.service.authenticate({"authorization": "Bearer t"})
    _, count = app.service.install_pack(writer, "acme", local.pack())
    tidx = [n for n in app.service.objects.blobs.names("acme/packs/") if n.endswith(".tidx")]
    assert count > 1 and len(tidx) == 1  # one durability point for the whole push
    data = app.service.fetch_pack(writer, "acme", [run_id], [])
    clone = Repo.init(tmp_path / "clone")
    from opentine.repository.pack import install_pack

    install_pack(clone, data)
    assert clone.get(run_id).oid == run_id
    assert app.service.objects.fsck("acme")["bad"] == []


def test_both_store_settings_are_refused(tmp_path):
    from opentine.remote._worm_config import object_store_from_env

    env = {"TINE_REMOTE_PACK_STORE": "file:///x", "TINE_REMOTE_OBJECT_STORE": "s3://b"}
    with pytest.raises(ValueError, match="not both"):
        object_store_from_env(tmp_path, KEYS, env=env)
    with pytest.raises(ValueError, match="TINE_REMOTE_PACK_STORE"):
        object_store_from_env(tmp_path, KEYS, env={"TINE_REMOTE_PACK_STORE": "gs://x"})
    env = {"TINE_REMOTE_PACK_STORE": (tmp_path / "p").as_uri()}
    store = object_store_from_env(tmp_path, KEYS, env=env)
    assert isinstance(store, PackedObjectStore) and store.blobs.root == tmp_path / "p"


@pytest.mark.skipif(not os.environ.get("TINE_TEST_S3_BUCKET"), reason="TINE_TEST_S3_BUCKET unset")
def test_live_s3_bucket_round_trip():  # pragma: no cover - owner-run against real S3
    blobs = S3PackBlobs(os.environ["TINE_TEST_S3_BUCKET"], prefix=f"opentine-test-{uuid.uuid4()}")
    store = PackedObjectStore(blobs, KEYS)
    items = _blobs(5)
    store.put_many("acme", items)
    try:
        assert PackedObjectStore(blobs, KEYS).list("acme") == sorted(o for o, _ in items)
        assert PackedObjectStore(blobs, KEYS).fsck("acme")["bad"] == []
    finally:
        for name in list(blobs.names("")):
            blobs.delete(name)
