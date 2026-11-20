"""0.49: the WORM store against real S3 Object Lock / Azure immutable-blob services.

Each target runs only when it is reachable; otherwise it is skipped with the
reason. None of them run in the default offline suite.

* moto (``pip install 'moto[s3]'``): in-process S3 with Object Lock.
* MinIO: ``TINE_TEST_MINIO_ENDPOINT=http://127.0.0.1:9000`` plus
  ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY``; a lock-enabled bucket is
  created per run (``docs/STORAGE.md`` has the ``docker run`` line).
* AWS: ``TINE_TEST_S3_BUCKET`` names an existing bucket with Object Lock on.
* Azurite/Azure: ``TINE_TEST_AZURE_CONNECTION`` and ``TINE_TEST_AZURE_CONTAINER``
  name a container with version-level immutability (needs azure-storage-blob).
"""

from __future__ import annotations

import importlib.util
import os
import random
import uuid

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote._fastcdc import ChunkParams
from opentine.remote._worm import GOVERNANCE, RetentionLocked, WormPolicy
from opentine.remote._worm_store import WormObjectStore
from opentine.remote.security import LocalKeyProvider

KEYS = LocalKeyProvider(b"k" * 32)


def _scenario(client, tmp_path) -> None:
    store = WormObjectStore(
        client,
        KEYS,
        WormPolicy(GOVERNANCE, 1),
        prefix=f"opentine-test-{uuid.uuid4().hex[:8]}",
        holds_root=tmp_path,
        chunk_threshold=4096,
        chunk_params=ChunkParams(64, 256, 1024),
    )
    small = ObjectEnvelope.create("blob", b"retained")
    large = ObjectEnvelope.create("blob", random.Random(3).randbytes(20_000))
    for envelope in (small, large):
        store.put("acme", envelope.oid, envelope.encode())
        assert store.get("acme", envelope.oid) == envelope.encode()
    assert store.manifest("acme", large.oid) is not None
    raw = large.encode()
    assert store.read_range("acme", large.oid, 9_000, 64) == raw[9_000:9_064]
    for envelope in (small, large):
        with pytest.raises(RetentionLocked):
            store.delete("acme", envelope.oid)
        assert store.has("acme", envelope.oid)
    key = store._key("acme", small.oid)
    store.client.set_legal_hold(key, True)
    assert store.client.retention(key).legal_hold
    store.client.set_legal_hold(key, False)


def _race(client, rounds: int = 8) -> None:
    """0.52: a delete racing an upload that reuses its chunks (real threads, no
    retention so nothing blocks the delete) never loses a chunk."""
    import threading

    prefix = f"opentine-race-{uuid.uuid4().hex[:8]}"
    store = WormObjectStore(client, KEYS, None, prefix=prefix, chunk_threshold=4096,
                            chunk_params=ChunkParams(64, 256, 1024))  # fmt: skip
    for round_ in range(rounds):
        base = random.Random(round_).randbytes(20_000)
        first = ObjectEnvelope.create("blob", base)
        second = ObjectEnvelope.create("blob", base + b"tail")
        store.put("acme", first.oid, first.encode())
        errors: list[BaseException] = []

        def run(call, *args):
            try:
                call(*args)
            except BaseException as exc:  # a thread's failure must fail the test, not vanish
                errors.append(exc)

        put = (store.put, "acme", second.oid, second.encode())
        jobs = [threading.Thread(target=run, args=(store.delete, "acme", first.oid)),
                threading.Thread(target=run, args=put)]  # fmt: skip
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
        assert not errors, errors
        assert store.get("acme", second.oid) == second.encode()
        store.delete("acme", second.oid)
    assert store.sweep_expired("acme")["swept"] == 0


def _moto_client():
    if importlib.util.find_spec("moto") is None or importlib.util.find_spec("boto3") is None:
        pytest.skip("moto[s3] is not installed (pip install 'moto[s3]')")
    import boto3
    from moto import mock_aws

    return mock_aws, boto3


def _atomic_requests(client):
    """Make each in-process moto request atomic, as every real S3 request is.

    moto's ``ListObjectsV2`` iterates the bucket's live key dict, so a delete on
    another thread mid-listing raises a bare ``KeyError`` from inside moto (which
    the store then reads as a missing object). Real S3 never fails a listing that
    way. Serializing whole requests keeps the race between the store's *calls*
    (what ``_race`` tests) while removing the emulator's own thread-unsafety.
    """
    import threading

    lock, call = threading.Lock(), client._make_api_call

    def locked(*args, **kwargs):
        with lock:
            return call(*args, **kwargs)

    client._make_api_call = locked
    return client


def test_moto_object_lock(tmp_path, monkeypatch):
    mock_aws, boto3 = _moto_client()
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    from opentine.remote._worm_s3 import S3BlobClient

    with mock_aws():
        s3 = _atomic_requests(boto3.client("s3", region_name="us-east-1"))
        s3.create_bucket(Bucket="locked", ObjectLockEnabledForBucket=True)
        _scenario(S3BlobClient("locked", client=s3), tmp_path)
        _race(S3BlobClient("locked", client=s3))


def test_minio_object_lock(tmp_path):
    endpoint = os.environ.get("TINE_TEST_MINIO_ENDPOINT")
    if not endpoint:
        pytest.skip("TINE_TEST_MINIO_ENDPOINT is not set (no MinIO to test against)")
    if importlib.util.find_spec("boto3") is None:
        pytest.skip("boto3 is not installed")
    import boto3

    from opentine.remote._worm_s3 import S3BlobClient

    s3 = boto3.client("s3", endpoint_url=endpoint)
    bucket = f"opentine-{uuid.uuid4().hex[:12]}"
    s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    _scenario(S3BlobClient(bucket, client=s3), tmp_path)
    _race(S3BlobClient(bucket, client=s3))


def test_aws_object_lock(tmp_path):
    bucket = os.environ.get("TINE_TEST_S3_BUCKET")
    if not bucket:
        pytest.skip("TINE_TEST_S3_BUCKET is not set (no AWS bucket with Object Lock)")
    from opentine.remote._worm_s3 import S3BlobClient

    _scenario(S3BlobClient(bucket), tmp_path)


def test_azure_immutable_blobs(tmp_path):
    connection = os.environ.get("TINE_TEST_AZURE_CONNECTION")
    container = os.environ.get("TINE_TEST_AZURE_CONTAINER")
    if not connection or not container:
        pytest.skip("TINE_TEST_AZURE_CONNECTION/CONTAINER are not set (no Azurite or Azure)")
    if importlib.util.find_spec("azure.storage.blob") is None:
        pytest.skip("azure-storage-blob is not installed")
    from opentine.remote._worm_azure import AzureBlobClient

    _scenario(AzureBlobClient.from_connection_string(connection, container), tmp_path)
