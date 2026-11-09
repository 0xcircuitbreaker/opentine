"""0.49: S3 Object Lock / Azure immutable object store, against an in-memory fake."""

from __future__ import annotations

import json
import os

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote._chunk_manifest import MARKER
from opentine.remote._fastcdc import ChunkParams
from opentine.remote._worm import COMPLIANCE, GOVERNANCE, RetentionLocked, WormPolicy
from opentine.remote._worm_config import object_store_from_env, parse_location, policy_from_env
from opentine.remote._worm_store import WormObjectStore
from opentine.remote.security import LocalKeyProvider
from opentine.repository._holds import HoldError
from tests._worm_fakes import FakeBlobClient

KEYS = LocalKeyProvider(b"k" * 32)
SMALL = ChunkParams(64, 256, 1024)


def _blob(data: bytes) -> tuple[str, bytes]:
    envelope = ObjectEnvelope.create("blob", data)
    return envelope.oid, envelope.encode()


def _store(policy=None, **kw):
    client = FakeBlobClient()
    kw.setdefault("chunk_threshold", 4096)
    kw.setdefault("chunk_params", SMALL)
    return client, WormObjectStore(client, KEYS, policy, prefix="opentine", **kw)


def _hold(root, tenant, oid):
    path = root / ".holds" / tenant
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [{"oid": oid, "target": oid}]
    path.write_text(json.dumps({"format": "tine-holds/1", "holds": rows}), encoding="utf-8")


def test_policy_validation():
    assert WormPolicy().until() is None
    assert WormPolicy(COMPLIANCE, 7).until() is not None
    for bad in (("forever", 1), (GOVERNANCE, 0), (None, 3), (GOVERNANCE, -1)):
        with pytest.raises(ValueError):
            WormPolicy(*bad)


def test_small_object_round_trip_is_sealed_and_retained():
    client, store = _store(WormPolicy(GOVERNANCE, 30))
    oid, raw = _blob(b"hello")
    store.put("acme", oid, raw)
    store.put("acme", oid, raw)  # idempotent
    assert store.has("acme", oid) and store.get("acme", oid) == raw
    key = store._key("acme", oid)
    assert key.startswith("opentine/acme/objects/blob/")
    assert b"hello" not in client.blobs[key]
    assert client.locks[key].mode == GOVERNANCE and client.locks[key].locked()
    assert store.list("acme") == [oid] and store.manifest("acme", oid) is None


def test_delete_refused_inside_retention_then_allowed_after():
    client, store = _store(WormPolicy(COMPLIANCE, 1))
    oid, raw = _blob(b"keep me")
    store.put("acme", oid, raw)
    with pytest.raises(RetentionLocked, match="compliance"):
        store.delete("acme", oid)
    assert isinstance(RetentionLocked("x"), PermissionError)
    with pytest.raises(RetentionLocked):
        client.shorten(store._key("acme", oid))  # compliance cannot be shortened
    client.expire(store._key("acme", oid))
    store.delete("acme", oid)
    assert not store.has("acme", oid)


def test_governance_can_be_shortened_by_an_operator_but_not_by_delete():
    client, store = _store(WormPolicy(GOVERNANCE, 1))
    oid, raw = _blob(b"gov")
    store.put("acme", oid, raw)
    with pytest.raises(RetentionLocked):
        store.delete("acme", oid)
    client.shorten(store._key("acme", oid))
    store.delete("acme", oid)


def test_the_cloud_refuses_even_when_the_store_check_passes():
    class Stale(FakeBlobClient):
        def delete(self, key):  # retention() reads stale metadata; the cloud still knows
            raise RetentionLocked(f"{key} is locked")

    client = Stale()
    store = WormObjectStore(client, KEYS, WormPolicy())
    oid, raw = _blob(b"x")
    store.put("acme", oid, raw)
    with pytest.raises(RetentionLocked):
        store.delete("acme", oid)
    assert store.has("acme", oid)


def test_opentine_holds_map_to_legal_holds(tmp_path):
    client, store = _store(holds_root=tmp_path)
    oid, raw = _blob(os.urandom(9000))  # chunked: the hold reaches every chunk
    other, other_raw = _blob(b"free")
    store.put("acme", oid, raw)
    store.put("acme", other, other_raw)
    _hold(tmp_path, "acme", oid)
    assert store.held("acme") == {oid}
    with pytest.raises(RetentionLocked, match="held"):
        store.delete("acme", oid)
    result = store.sync_holds("acme")
    assert result == {"held": [oid], "released": []}
    chunk_keys = [k for k in client.blobs if "/chunks/" in k]
    assert chunk_keys and all(client.locks[k].legal_hold for k in chunk_keys)
    assert client.locks[store._key("acme", oid)].legal_hold
    (tmp_path / ".holds" / "acme").unlink()
    with pytest.raises(RetentionLocked, match="legal hold"):
        store.delete("acme", oid)  # the cloud's hold still stands
    assert store.sync_holds("acme", release=True)["released"] == [oid]
    store.delete("acme", oid)
    assert not any("/chunks/" in k for k in client.blobs)
    store.delete("acme", other)


def test_unreadable_holds_file_refuses_deletes(tmp_path):
    _client, store = _store(holds_root=tmp_path)
    oid, raw = _blob(b"y")
    store.put("acme", oid, raw)
    (tmp_path / ".holds").mkdir()
    (tmp_path / ".holds" / "acme").write_text("not json", encoding="utf-8")
    with pytest.raises(HoldError):  # fail closed, as on the filesystem store
        store.delete("acme", oid)


def test_retention_hook_is_consulted():
    class Hook:
        def retain_until(self, tenant, oid):
            return "2999-01-01T00:00:00Z"

        def before_delete(self, tenant, oid):
            raise PermissionError("policy keeps it")

    _client, store = _store(retention=Hook())
    oid, raw = _blob(b"z")
    store.put("acme", oid, raw)
    with pytest.raises(PermissionError, match="policy"):
        store.delete("acme", oid)


def test_collision_and_bad_tenant_are_refused():
    _client, store = _store()
    oid, raw = _blob(b"a")
    with pytest.raises(ValueError):
        store.put("acme", oid, _blob(b"b")[1])
    with pytest.raises(ValueError):
        store.put("../x", oid, raw)


def test_store_url_and_policy_parsing(tmp_path):
    assert parse_location("s3://bucket/a/b/") == ("s3", "bucket", "a/b")
    assert parse_location("azblob://box") == ("azblob", "box", "")
    for bad in ("bucket", "gs://x", "s3://"):
        with pytest.raises(ValueError):
            parse_location(bad)
    env = {"TINE_REMOTE_RETENTION_MODE": "Compliance", "TINE_REMOTE_RETENTION_DAYS": "30"}
    assert policy_from_env(env) == WormPolicy(COMPLIANCE, 30)
    with pytest.raises(ValueError):
        policy_from_env({"TINE_REMOTE_RETENTION_DAYS": "a week"})
    assert object_store_from_env(tmp_path, KEYS, env={}) is None
    env["TINE_REMOTE_OBJECT_STORE"] = "s3://bucket/pre"
    store = object_store_from_env(tmp_path, KEYS, env=env, client=FakeBlobClient())
    assert store.prefix == "pre/" and store.policy.mode == COMPLIANCE
    assert store.holds_root == tmp_path / "objects"
    with pytest.raises(ValueError, match="AZURE"):
        object_store_from_env(tmp_path, KEYS, env={"TINE_REMOTE_OBJECT_STORE": "azblob://c"})


def test_marker_never_collides_with_a_sealed_object():
    _client, store = _store()
    oid, raw = _blob(b"q")
    store.put("acme", oid, raw)
    assert not store._stored("acme", oid).startswith(MARKER)
