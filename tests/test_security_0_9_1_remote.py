"""0.9.1 remote availability fixes: listing binding, association budget, install guard.

Each was a way for one writer -- or one ordinary push -- to take the remote away
from everyone else in a tenant (A-1, A-2) or on the server (A-3).
"""

from __future__ import annotations

import io
import sqlite3
from pathlib import Path

import pytest

from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
    _association_budget,
    _tenant_repo,
)
from opentine.repository import Repo

EMPTY_RUN = {"events": [], "manifests": {}, "roots": [], "tips": []}


def _service(tmp_path: Path, index=None):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    backend = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("writer", "acme", ("writer",)),
            "reader-token": Identity("reader", "acme", ("reader",)),
        }
    )
    service = RemoteService(
        objects, index(backend) if index else backend, identities, RoleAuthorizationPolicy()
    )
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    reader = service.authenticate({"authorization": "Bearer reader-token"})
    return service, backend, writer, reader


class ProtocolOnlyIndex:
    """An IndexBackend with only the protocol methods: no install-time bindings."""

    def __init__(self, backend: SQLiteBackend):
        self._backend = backend

    def __getattr__(self, name):
        if name in {"recorded_targets", "association_counts"}:
            raise AttributeError(name)
        return getattr(self._backend, name)


def _annotated_run(tmp_path: Path, size: int) -> tuple[Repo, str, str]:
    local = Repo.init(tmp_path / "local")
    run = local.put("run", EMPTY_RUN)
    note = local.put(
        "annotation",
        {"previous_id": None, "target_id": run, "value": {"tags": ["x" * size]}},
    )
    return local, run, note


# --- A-1: one large annotation no longer fails the whole ref listing ----------- #


def test_large_annotation_ref_lists_through_its_install_time_binding(tmp_path, monkeypatch):
    service, _, writer, reader = _service(tmp_path)
    local, run, note = _annotated_run(tmp_path, 4096)
    service.install_pack(writer, "acme", local.pack())
    # Far below this annotation: the old listing decoded it and refused.
    monkeypatch.setattr(_tenant_repo, "MAX_REF_ANNOTATION_BYTES", 64)
    monkeypatch.setattr(_tenant_repo, "MAX_REF_ANNOTATION_TOTAL_BYTES", 64)
    name = f"annotations/{run.rsplit(':', 1)[1]}"
    assert service.update_ref(writer, "acme", "heads/main", run, None)
    assert service.update_ref(writer, "acme", name, note, None)
    assert service.list_refs(reader, "acme") == {"heads/main": run, name: note}


def test_recorded_binding_still_refuses_a_misnamed_annotation_ref(tmp_path):
    service, backend, writer, reader = _service(tmp_path)
    local, run, note = _annotated_run(tmp_path, 8)
    other = local.put("run", {**EMPTY_RUN, "status": "completed"})
    service.install_pack(writer, "acme", local.pack())
    wrong = f"annotations/{other.rsplit(':', 1)[1]}"
    with pytest.raises(ValueError, match="match its target run"):
        service.update_ref(writer, "acme", wrong, note, None)
    with sqlite3.connect(backend.path) as database:  # planted past update_ref
        database.execute("INSERT INTO refs(tenant,name,oid) VALUES('acme',?,?)", (wrong, note))
    with pytest.raises(ValueError, match="match its target run"):
        service.list_refs(reader, "acme")


def test_without_bindings_a_write_cannot_leave_an_unlistable_tenant(tmp_path, monkeypatch):
    service, _, writer, reader = _service(tmp_path, ProtocolOnlyIndex)
    local, run, note = _annotated_run(tmp_path, 4096)
    service.install_pack(writer, "acme", local.pack())
    assert service.update_ref(writer, "acme", "heads/main", run, None)
    monkeypatch.setattr(_tenant_repo, "MAX_REF_ANNOTATION_BYTES", 1024)
    name = f"annotations/{run.rsplit(':', 1)[1]}"
    # The listing's own decode budget, enforced at the write it would have failed on.
    with pytest.raises(ValueError, match="byte limit"):
        service.update_ref(writer, "acme", name, note, None)
    assert service.list_refs(reader, "acme") == {"heads/main": run}


# --- A-2: uploads cannot make an existing run unfetchable ---------------------- #


@pytest.mark.parametrize("index", [None, ProtocolOnlyIndex], ids=["sqlite", "protocol-only"])
def test_association_budget_is_enforced_at_install(tmp_path, monkeypatch, index):
    monkeypatch.setattr(_association_budget, "MAX_ASSOCIATIONS_PER_TARGET", 3)
    service, _, writer, reader = _service(tmp_path, index)
    local = Repo.init(tmp_path / "local")
    run = local.put("run", EMPTY_RUN)
    service.install_pack(writer, "acme", local.pack())
    first = [local.attest(run, {"n": n}, signer="ci") for n in range(3)]
    service.install_pack(writer, "acme", local.pack(first))
    # Re-sending what the server already holds is not new associations.
    service.install_pack(writer, "acme", local.pack(first))

    extra = local.attest(run, {"n": 3}, signer="mallory")
    with pytest.raises(ValueError, match="more than 3 associated"):
        service.install_pack(writer, "acme", local.pack([extra]))
    assert not service.objects.has("acme", extra)

    pack = service.fetch_pack(reader, "acme", [run], [])
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(pack)
    assert set(clone.attestations_for(run)) == set(first)


def test_association_budget_counts_annotations_and_attestations_together(tmp_path, monkeypatch):
    monkeypatch.setattr(_association_budget, "MAX_ASSOCIATIONS_PER_TARGET", 2)
    service, _, writer, _ = _service(tmp_path)
    local, run, note = _annotated_run(tmp_path, 8)
    attestation = local.attest(run, {"ok": True}, signer="ci")
    service.install_pack(writer, "acme", local.pack([run, note, attestation]))
    with pytest.raises(ValueError, match="more than 2 associated"):
        service.install_pack(writer, "acme", local.pack([local.attest(run, {}, signer="x")]))


# --- A-3: a slow upload body does not hold the server-wide install guard ------- #


class _GuardProbe(io.BytesIO):
    def __init__(self, data: bytes, app: RemoteApp):
        super().__init__(data)
        self.app = app
        self.free_slots: list[int] = []

    def read(self, *args):
        self.free_slots.append(self.app._install_guard._value)
        return super().read(*args)


def test_direct_pack_body_is_read_before_taking_the_install_guard(tmp_path):
    service, _, _, _ = _service(tmp_path)
    app = RemoteApp(service, tmp_path / "state")
    local = Repo.init(tmp_path / "local")
    local.put("run", EMPTY_RUN)
    data = local.pack()
    body = _GuardProbe(data, app)
    statuses: list[str] = []
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/tenants/acme/packs",
        "CONTENT_TYPE": "application/vnd.opentine.pack",
        "CONTENT_LENGTH": str(len(data)),
        "HTTP_AUTHORIZATION": "Bearer writer-token",
        "wsgi.input": body,
    }
    app(environ, lambda status, headers: statuses.append(status))
    assert statuses == ["201 Created"]
    assert body.free_slots == [2]  # both slots free while the client trickles bytes
