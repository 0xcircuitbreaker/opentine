"""Final adversarial checks for remote storage and audit reporting."""

from __future__ import annotations

import hashlib
import io
import json
import os

import pytest

from opentine.kernel import ObjectEnvelope
from opentine.remote import backend as backend_module
from opentine.remote._uploads import UploadRegistry
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import Identity
from opentine.remote.security import (
    AuthenticationError,
    LocalKeyProvider,
    OIDCIdentityProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.service import RemoteService


def test_audit_verification_status_is_bound_to_the_returned_head():
    class RacingAudit:
        def __init__(self):
            self.head = "a" * 64
            self.expected = None

        def append(self, event):
            raise AssertionError("verification must remain read-only")

        def audit_head(self):
            return self.head

        def audit_status(self, *, expected_head=None):
            self.expected = expected_head
            self.head = "b" * 64
            return "verified" if expected_head == self.head else "invalid"

        def audit_warnings(self):
            return []

        def verify_audit_chain(self):
            return True

    audit = RacingAudit()
    service = RemoteService(object(), object(), object(), RoleAuthorizationPolicy(), audit=audit)
    result = service.verify_audit_chain(Identity("admin", "acme", ("admin",)), "acme")

    assert audit.expected == "a" * 64
    assert result == {
        "head": "a" * 64,
        "ok": False,
        "status": "invalid",
        "warnings": [],
    }


def test_oidc_rejects_non_utf8_actor_before_authorization():
    provider = OIDCIdentityProvider(
        lambda _: {"sub": "actor\ud800", "tenant": "acme", "roles": ["writer"]}
    )
    with pytest.raises(AuthenticationError, match="invalid text"):
        provider.authenticate({"authorization": "Bearer signed-token"})
    with pytest.raises(ValueError, match="valid UTF-8"):
        Identity("actor\ud800", "acme", ("writer",))
    with pytest.raises(AuthenticationError, match="invalid text"):
        OIDCIdentityProvider(
            lambda _: {"sub": "x" * 4_097, "tenant": "acme", "roles": ["writer"]}
        ).authenticate({"authorization": "Bearer signed-token"})


def test_ref_listing_uses_typed_ids_without_walking_run_graphs():
    envelope = ObjectEnvelope.create(
        "run", {"events": [], "manifests": {}, "roots": [], "tips": []}
    )

    class Store:
        reads = 0

        def has(self, tenant, oid):
            return tenant == "acme" and oid == envelope.oid

        def get(self, tenant, oid):
            self.reads += 1
            return envelope.encode()

    class Index:
        def list_refs(self, tenant):
            return {f"tags/repeated-{index}": envelope.oid for index in range(1_000)}

        def append(self, event):
            pass

    store = Store()
    service = RemoteService(store, Index(), object(), RoleAuthorizationPolicy())
    refs = service.list_refs(Identity("reader", "acme"), "acme")
    assert len(refs) == 1_000
    assert store.reads == 0


def test_ref_listing_cost_is_linear_for_distinct_runs_with_shared_events():
    event = ObjectEnvelope.create("event", {"causal_ids": [], "parent_ids": []})
    runs = [
        ObjectEnvelope.create(
            "run",
            {"events": [event.oid], "manifests": {}, "roots": [event.oid], "tips": [event.oid]},
        )
        for _ in range(50)
    ]
    # Make the content addresses distinct without expanding the shared event graph.
    runs = [
        ObjectEnvelope.create("run", {**run.payload(), "created_at": index})
        for index, run in enumerate(runs)
    ]

    class Store:
        reads = 0

        def has(self, tenant, oid):
            return tenant == "acme" and (oid == event.oid or any(run.oid == oid for run in runs))

        def get(self, tenant, oid):
            self.reads += 1
            return next(run.encode() for run in runs if run.oid == oid)

    class Index:
        def list_refs(self, tenant):
            return {f"heads/run-{index}": run.oid for index, run in enumerate(runs)}

        def append(self, event):
            pass

    store = Store()
    service = RemoteService(store, Index(), object(), RoleAuthorizationPolicy())
    assert len(service.list_refs(Identity("reader", "acme"), "acme")) == 50
    assert store.reads == 0


def test_ref_cas_rejects_unbounded_expected_oid_before_audit_mutation():
    envelope = ObjectEnvelope.create(
        "run", {"events": [], "manifests": {}, "roots": [], "tips": []}
    )

    class Store:
        def has(self, tenant, oid):
            return oid == envelope.oid

        def get(self, tenant, oid):
            return envelope.encode()

    class Index:
        events = []

        def append(self, event):
            self.events.append(event)

    index = Index()
    service = RemoteService(Store(), index, object(), RoleAuthorizationPolicy())
    identity = Identity("writer", "acme", ("writer",))

    with pytest.raises(ValueError, match="invalid typed object id"):
        service.update_ref(identity, "acme", "heads/main", envelope.oid, "x" * 1_000_000)
    assert index.events == []


def _request(app, method, path, body=b"", **headers):
    state = {}

    def start_response(status, response_headers):
        state["status"] = status
        state["headers"] = dict(response_headers)

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": headers.pop("content_type", "application/json"),
        "HTTP_AUTHORIZATION": "Bearer writer-token",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    environ.update({f"HTTP_{key.upper()}": value for key, value in headers.items()})
    payload = b"".join(app(environ, start_response))
    return state["status"], payload


def test_completed_invalid_resumable_pack_is_removed(tmp_path):
    key = LocalKeyProvider(b"k" * 32)
    objects = FilesystemObjectStore(tmp_path / "objects", key)
    index = SQLiteBackend(tmp_path / "metadata.sqlite3", audit_key=b"a" * 32)
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "acme", ("writer",))}
    )
    service = RemoteService(objects, index, identities, RoleAuthorizationPolicy())
    app = RemoteApp(service, tmp_path / "state")
    invalid_pack = b"checksum-valid but structurally invalid pack"
    declaration = json.dumps(
        {"sha256": hashlib.sha256(invalid_pack).hexdigest(), "size": len(invalid_pack)}
    ).encode()

    status, body = _request(app, "POST", "/v1/tenants/acme/packs", declaration)
    upload_id = json.loads(body)["upload_id"]
    assert status == "201 Created"
    status, _ = _request(
        app,
        "PATCH",
        f"/v1/tenants/acme/packs/{upload_id}",
        invalid_pack,
        content_type="application/octet-stream",
        upload_offset="0",
    )

    assert status == "400 Bad Request"
    assert not list(app.uploads.rglob(f"{upload_id}.*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX link behavior differs on Windows")
def test_upload_staging_rejects_symlinked_directories_and_hardlinked_files(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "uploads"
    linked_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="real directory"):
        UploadRegistry(linked_root, LocalKeyProvider(b"u" * 32), ttl_seconds=60, max_pending=4)

    registry = UploadRegistry(
        tmp_path / "private", LocalKeyProvider(b"u" * 32), ttl_seconds=60, max_pending=4
    )
    part, _ = registry.create(
        "acme", "a" * 32, {"sha256": hashlib.sha256(b"x").hexdigest(), "size": 1}
    )
    os.link(part, tmp_path / "part-link")
    with pytest.raises(ValueError, match="regular file"):
        registry.paths("acme", "a" * 32)


def test_ref_capacity_cannot_make_ref_discovery_permanently_unusable(tmp_path, monkeypatch):
    monkeypatch.setattr(backend_module, "MAX_CONTROL_RESULTS", 2)
    backend = SQLiteBackend(tmp_path / "refs.sqlite3", audit_key=b"a" * 32)
    first = "run:sha256:" + "1" * 64
    second = "run:sha256:" + "2" * 64
    replacement = "run:sha256:" + "3" * 64

    assert backend.update_ref("acme", "heads/one", first, None)
    assert backend.update_ref("acme", "heads/two", second, None)
    with pytest.raises(ValueError, match="ref count"):
        backend.update_ref("acme", "heads/three", replacement, None)
    assert backend.update_ref("acme", "heads/one", replacement, first)
    assert backend.list_refs("acme") == {
        "heads/one": replacement,
        "heads/two": second,
    }
