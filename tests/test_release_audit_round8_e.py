"""Round-8 release-audit regressions, group E: remote pack ingest write order."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentine.kernel import ObjectEnvelope, validate_links
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.remote._pack_ingest import verified_write_order
from opentine.remote._tenant_repo import TenantRepo
from opentine.repository import Repo
from opentine.repository.pack import inspect_pack


def _service(tmp_path: Path) -> tuple[RemoteService, FilesystemObjectStore, Identity]:
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "acme", ("writer",))}
    )
    service = RemoteService(objects, index, identities, RoleAuthorizationPolicy())
    return service, objects, service.authenticate({"authorization": "Bearer writer-token"})


def _linked_pack(tmp_path: Path) -> tuple[bytes, tuple[str, str, str]]:
    """Event <- run <- annotation: manifest (sorted-oid) order cites before it defines."""
    local = Repo.init(tmp_path / "local")
    event = local.put("event", {"causal_ids": [], "parent_ids": []})
    run = local.put("run", {"events": [event], "manifests": {}, "roots": [event], "tips": [event]})
    annotation = local.put("annotation", {"target_id": run, "value": {"note": "review"}})
    return local.pack(), (event, run, annotation)


def test_interrupted_remote_install_never_leaves_a_link_broken_object(tmp_path):
    # install_pack wrote objects in manifest (sorted-oid) order, so an ENOSPC after
    # the first durable write stored the annotation while its target run never
    # arrived; TenantRepo.get / fetch_pack then failed that object with "missing
    # linked object" until a client re-pushed the full closure.
    pack, oids = _linked_pack(tmp_path)
    for fault_after in range(1, len(oids)):
        service, objects, writer = _service(tmp_path / f"srv{fault_after}")
        original_put = objects.put
        durable: list[str] = []

        def failing_put(tenant, oid, raw, _put=original_put, _durable=durable, _n=fault_after):
            if len(_durable) >= _n:
                raise OSError(28, "No space left on device")
            _put(tenant, oid, raw)
            _durable.append(oid)

        objects.put = failing_put
        with pytest.raises(OSError):
            service.install_pack(writer, "acme", pack)
        objects.put = original_put
        assert durable  # the interruption landed after at least one durable write

        # Every prefix of the write sequence must be link-closed: each durable
        # object stays fully readable by the server's own semantic paths.
        repo = TenantRepo("acme", objects)
        for oid in durable:
            validate_links(repo.get(oid), repo.has)

        # A retried push converges and heals the tenant store completely.
        _, count = service.install_pack(writer, "acme", pack)
        assert count == len(oids)
        for oid in oids:
            repo.get(oid)
        assert service.fetch_pack(writer, "acme", [oids[-1]], [])


def test_remote_install_writes_dependencies_before_dependents(tmp_path):
    pack, _ = _linked_pack(tmp_path)
    _, objects, _ = _service(tmp_path / "srv")
    _, packed, shallow = inspect_pack(pack)
    # The manifest itself is sorted-oid order — the citing annotation comes first.
    assert [oid.split(":", 1)[0] for oid, _ in packed] == ["annotation", "event", "run"]
    order = verified_write_order("acme", objects, packed, shallow)
    assert sorted(oid for oid, _ in order) == sorted(oid for oid, _ in packed)
    packed_ids = {oid for oid, _ in packed}
    written: set[str] = set()
    for oid, raw in order:
        internal = set(validate_links(ObjectEnvelope.decode(raw, oid))) & packed_ids
        assert internal <= written, f"{oid} written before a target it links"
        written.add(oid)


def test_relocated_ingest_validation_still_rejects_bad_packs(tmp_path):
    # The link/shallow checks moved from service.py into _pack_ingest; they must
    # keep refusing packs before any object write happens.
    pack, oids = _linked_pack(tmp_path)
    run = oids[1]
    _, objects, _ = _service(tmp_path / "srv")
    _, packed, _ = inspect_pack(pack)
    without_run = [(oid, raw) for oid, raw in packed if oid != run]
    with pytest.raises(ValueError, match="unresolved link"):
        verified_write_order("acme", objects, without_run, [])
    objects.put("acme", run, dict(packed)[run])
    with pytest.raises(ValueError, match="shallow boundaries"):
        verified_write_order("acme", objects, without_run, [])
