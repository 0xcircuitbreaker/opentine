"""0.12 remote: v4 negotiation with old/new peers, TINEAES4 at rest, ff-only heads."""

from __future__ import annotations

import io
import os
import sqlite3
from pathlib import Path

import httpx
import pytest
from cryptography.exceptions import InvalidTag

from opentine import Run
from opentine.graph import StepKind
from opentine.remote import _sealed
from opentine.remote._admin_reseal import reseal
from opentine.remote._ref_policy import descends
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import Identity
from opentine.remote.security import (
    LocalKeyProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.service import RemoteService
from opentine.repository import Repo, _pack4
from opentine.repository import client as repository_client

KEY = b"k" * 32
OID = "blob:sha256:" + "0" * 64
URL = "https://remote.example/v1/tenants/acme"


def _run(name: str, steps: int = 4) -> Run:
    run = Run(id=name)
    for index in range(steps):
        run.add_step(StepKind.think, {"text": f"{name} {index} " + "words " * 30})
    return run


def _remote(tmp_path: Path, monkeypatch, *, legacy: bool = False, **service_kwargs):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(KEY))
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("writer", "acme", ("writer",)),
            "admin-token": Identity("admin", "acme", ("admin",)),
        }
    )
    service = RemoteService(
        objects,
        SQLiteBackend(tmp_path / "remote.sqlite3"),
        identities,
        RoleAuthorizationPolicy(),
        **service_kwargs,
    )
    if legacy:  # a 0.11 server: advertises v3 only, refuses unknown fetch keys
        caps = service.capabilities()
        for key in ("pack_formats", "pack_codecs", "heads_fast_forward"):
            caps.pop(key)
        monkeypatch.setattr(service, "capabilities", lambda: caps)
    app = RemoteApp(service, tmp_path / "state")
    seen: list[httpx.Request] = []

    def handler_app(environ, start_response):
        if legacy and environ["PATH_INFO"].endswith("/fetch"):
            body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
            assert b"pack_formats" not in body, "offered v4 to a v3-only server"
            environ["wsgi.input"] = io.BytesIO(body)
        return app(environ, start_response)

    transport = httpx.WSGITransport(app=handler_app)
    token = {"value": "writer-token"}

    def session(*_args, **_kwargs):
        return httpx.Client(
            transport=transport,
            base_url="https://remote.example",
            headers={"authorization": f"Bearer {token['value']}"},
            event_hooks={"request": [seen.append]},
        )

    monkeypatch.setattr(repository_client, "_client", session)
    return service, token, seen


# --- negotiation ------------------------------------------------------------ #


def test_new_client_and_server_round_trip_in_v4(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    run_id = origin.put_run(_run("a"), ref="heads/main").run_id
    repository_client.push(origin, URL, ref="heads/main")
    caps = service.capabilities()
    assert caps["pack_formats"][0] == "TINEPACK4" and caps["pack_format"] == "TINEPACK3"
    clone = Repo.init(tmp_path / "clone")
    repository_client.fetch(clone, URL)
    assert clone.has(run_id) and clone.fsck().ok


def test_server_answers_v4_only_when_asked(tmp_path, monkeypatch):
    service, _, _ = _remote(tmp_path, monkeypatch)
    origin = Repo.init(tmp_path / "origin")
    origin.put_run(_run("a"), ref="heads/main")
    repository_client.push(origin, URL, ref="heads/main")
    client = repository_client._client("https://remote.example", "writer-token")
    prefix = repository_client._prefix("acme")
    want = service.list_refs(service.authenticate({"authorization": "Bearer writer-token"}), "acme")
    body = {"depth": None, "haves": [], "object_types": [], "wants": list(want.values())}
    old = client.post(prefix + "/fetch", json=body)  # a 0.11 client's request
    assert old.content.startswith(b"TINEPACK3\0")
    new = client.post(
        prefix + "/fetch", json={**body, "pack_formats": ["TINEPACK4"], "pack_codecs": ["zlib"]}
    )
    assert new.content.startswith(_pack4.MAGIC4)
    assert new.headers[_pack4.FORMAT_HEADER] == "TINEPACK4"


def test_new_client_against_a_v3_only_server_both_ways(tmp_path, monkeypatch):
    _remote(tmp_path, monkeypatch, legacy=True)
    origin = Repo.init(tmp_path / "origin")
    run_id = origin.put_run(_run("a"), ref="heads/main").run_id
    monkeypatch.setattr(
        _pack4, "build", lambda *a, **k: pytest.fail("built v4 for a v3-only server")
    )
    repository_client.push(origin, URL, ref="heads/main")
    clone = Repo.init(tmp_path / "clone")
    repository_client.fetch(clone, URL)
    assert clone.has(run_id)


# --- TINEAES4 --------------------------------------------------------------- #


def test_objects_are_compressed_then_sealed_and_bound_to_their_slot(tmp_path):
    keys = LocalKeyProvider(KEY)
    store = FilesystemObjectStore(tmp_path / "objects", keys)
    local = Repo.init(tmp_path / "local")
    oid = local.put("blob", b"secret " * 500, redact=False)
    store.put("acme", oid, local.raw(oid))
    sealed = store._path("acme", oid).read_bytes()
    assert sealed.startswith(b"TINEAES4") and b"secret" not in sealed
    assert len(sealed) < len(local.raw(oid))
    assert store.get("acme", oid) == local.raw(oid)
    for purpose, tenant, context in (
        ("upload-frame", "acme", oid),
        ("object", "other", oid),
        ("object", "acme", OID),
    ):
        with pytest.raises(InvalidTag):
            keys.unseal(purpose, tenant, context, sealed)


@pytest.mark.parametrize("offset", [8, 9, 16])  # codec byte, size high/low bytes
def test_relabelling_the_codec_or_size_is_refused(tmp_path, offset):
    keys = LocalKeyProvider(KEY)
    sealed = bytearray(_sealed.seal_object(keys, "acme", OID, b"x" * 4000, "zlib"))
    sealed[offset] ^= 0x01
    with pytest.raises((InvalidTag, ValueError)):
        keys.unseal("object", "acme", OID, bytes(sealed))


def test_a_declared_size_over_the_limit_is_refused_before_decrypting():
    sealed = bytearray(_sealed.seal_object(LocalKeyProvider(KEY), "acme", OID, b"x", "zlib"))
    sealed[9:17] = (2**40).to_bytes(8, "big")
    with pytest.raises(ValueError, match="declares more"):
        _sealed.unseal_compressed_with(KEY, "object", "acme", OID, bytes(sealed), limit=1024)


def test_legacy_ciphertexts_still_open_and_tenants_can_opt_out(tmp_path):
    keys = LocalKeyProvider(KEY)
    store = FilesystemObjectStore(tmp_path / "o", keys, uncompressed_tenants={"plain"})
    local = Repo.init(tmp_path / "local")
    oid = local.put("blob", b"payload " * 50, redact=False)
    raw = local.raw(oid)
    store.put("plain", oid, raw)
    assert store._path("plain", oid).read_bytes().startswith(b"TINEAES3")
    for legacy in (keys.encrypt("acme", raw), keys.seal("object", "acme", oid, raw)):
        path = store._path("acme", oid)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(legacy)
        assert store.get("acme", oid) == raw


def test_storage_codec_switch(monkeypatch):
    monkeypatch.setenv(_sealed.CODEC_ENV, "off")
    assert _sealed.storage_codec() is None
    monkeypatch.setenv(_sealed.CODEC_ENV, "zlib")
    assert _sealed.storage_codec() == "zlib"
    monkeypatch.setenv(_sealed.CODEC_ENV, "lzma")
    with pytest.raises(ValueError):
        _sealed.storage_codec()


def test_kms_style_provider_without_seal_compressed_stays_on_aes3():
    class Unbound:
        def encrypt(self, tenant, data):
            return LocalKeyProvider(KEY).encrypt(tenant, data)

    sealed = _sealed.seal_object(Unbound(), "acme", OID, b"x" * 100, "zlib")
    assert not sealed.startswith(b"TINEAES4")


def test_reseal_rolls_a_tenant_back_to_aes3_and_forward(tmp_path):
    store = FilesystemObjectStore(tmp_path / "o", LocalKeyProvider(KEY))
    local = Repo.init(tmp_path / "local")
    oids = [local.put("blob", os.urandom(8) * 40, redact=False) for _ in range(3)]
    for oid in oids:
        store.put("acme", oid, local.raw(oid))
    assert reseal(store, "acme", "aes3", dry_run=True).rewritten == 3
    assert reseal(store, "acme", "aes3").rewritten == 3
    assert all(store._path("acme", o).read_bytes().startswith(b"TINEAES3") for o in oids)
    assert reseal(store, "acme", "aes3").unchanged == 3
    assert reseal(store, "acme", "aes4").rewritten == 3
    assert all(store.get("acme", o) == local.raw(o) for o in oids)


# --- fast-forward-only heads ------------------------------------------------ #


def _ff_setup(tmp_path, monkeypatch, enabled=True):
    service, token, _ = _remote(tmp_path, monkeypatch, fast_forward_heads=enabled)
    origin = Repo.init(tmp_path / "origin")
    first = origin.put_run(_run("first"), ref="heads/main").run_id
    repository_client.push(origin, URL, ref="heads/main")
    return service, token, origin, first


def test_heads_move_freely_by_default(tmp_path, monkeypatch):
    service, _, origin, _ = _ff_setup(tmp_path, monkeypatch, enabled=False)
    assert service.capabilities()["heads_fast_forward"] is False
    second = origin.put_run(_run("second"), ref="heads/main").run_id
    repository_client.push(origin, URL, ref="heads/main")
    admin = service.authenticate({"authorization": "Bearer admin-token"})
    assert service.list_refs(admin, "acme")["heads/main"] == second


def test_a_descendant_fast_forwards(tmp_path, monkeypatch):
    service, _, origin, first = _ff_setup(tmp_path, monkeypatch)
    tip = origin.get(first).payload()["tips"][0]
    fork = origin.fork(first, tip, ref="heads/main")
    repository_client.push(origin, URL, ref="heads/main")
    admin = service.authenticate({"authorization": "Bearer admin-token"})
    assert service.list_refs(admin, "acme")["heads/main"] == fork


def test_an_unrelated_run_is_refused_then_forced_by_an_admin(tmp_path, monkeypatch):
    service, token, origin, first = _ff_setup(tmp_path, monkeypatch)
    other = origin.put_run(_run("other"), ref="heads/main").run_id
    url = URL
    with pytest.raises(Exception):
        repository_client.push(origin, url, ref="heads/main")
    with pytest.raises(Exception):  # a writer cannot force
        repository_client.push(origin, url, ref="heads/main", force=True)
    token["value"] = "admin-token"
    repository_client.push(origin, url, ref="heads/main", force=True)
    admin = service.authenticate({"authorization": "Bearer admin-token"})
    assert service.list_refs(admin, "acme")["heads/main"] == other
    with sqlite3.connect(tmp_path / "remote.sqlite3") as db:
        outcomes = {row[0] for row in db.execute("SELECT outcome FROM audit")}
    assert "non-fast-forward" in outcomes and "forced" in outcomes


def test_descent_check_is_bounded():
    class Chain:
        def get(self, oid):
            class Envelope:
                object_type = "run"

                def payload(self):
                    number = int(oid.rsplit("-", 1)[1])
                    tips = ["event-x"] if number == 0 else []
                    return {"tips": tips, "events": [], "forked_from": f"run-{number + 1}"}

            return Envelope()

    assert not descends(Chain(), "run-0", "run-1", budget=50)
