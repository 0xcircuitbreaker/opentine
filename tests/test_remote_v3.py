"""Security and protocol gates for the minimal self-hosted v3 remote."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
from pathlib import Path

import pytest

from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    OIDCIdentityProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.remote._upload_crypto import append_frames, read_frames
from opentine.repository import Repo


def _service(tmp_path: Path):
    key = LocalKeyProvider(b"k" * 32)
    objects = FilesystemObjectStore(tmp_path / "objects", key)
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {
            "reader-token": Identity("reader", "acme", ("reader",)),
            "writer-token": Identity("writer", "acme", ("writer",)),
            "other-token": Identity("other", "other", ("admin",)),
        }
    )
    return RemoteService(objects, index, identities, RoleAuthorizationPolicy()), objects, index


def test_auth_rbac_namespace_encryption_cas_and_append_only_audit(tmp_path: Path):
    service, objects, index = _service(tmp_path)
    writer = service.authenticate({"Authorization": "Bearer writer-token"})
    reader = service.authenticate({"authorization": "Bearer reader-token"})
    other = service.authenticate({"authorization": "Bearer other-token"})

    local = Repo.init(tmp_path / "local")
    oid = local.put("blob", b"remote secret payload", redact=False)
    run = local.put("run", {"events": [], "manifests": {}, "roots": [], "tips": []})
    pack_id, count = service.install_pack(writer, "acme", local.pack())
    assert pack_id.startswith("sha256:") and count == 2
    assert service.update_ref(writer, "acme", "heads/main", run, None) is True
    assert service.update_ref(writer, "acme", "heads/main", run, None) is False
    with pytest.raises(ValueError, match="invalid ref"):
        service.update_ref(writer, "acme", "heads/../escape", oid, None)
    with pytest.raises(ValueError, match="heads refs require run"):
        service.update_ref(writer, "acme", "heads/blob", oid, None)
    assert service.list_refs(reader, "acme") == {"heads/main": run}

    encrypted = objects._path("acme", oid).read_bytes()
    assert encrypted.startswith(b"TINEAES2")
    assert b"remote secret payload" not in encrypted
    assert objects.get("acme", oid) == local.raw(oid)

    with pytest.raises(PermissionError):
        service.install_pack(reader, "acme", local.pack())
    with pytest.raises(PermissionError):
        service.list_refs(other, "acme")
    assert not objects.has("other", oid)

    for unsafe in ("Acme", "acme.", "con", "COM1", "nul.objects"):
        with pytest.raises(ValueError, match="invalid tenant"):
            objects.has(unsafe, oid) or objects.list(unsafe)

    with sqlite3.connect(index.path) as database:
        assert database.execute("SELECT count(*) FROM audit").fetchone()[0] >= 4
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            database.execute("DELETE FROM audit")


def test_oidc_retention_and_admission_extension_seams(tmp_path: Path):
    oidc = OIDCIdentityProvider(lambda token: {"sub": token, "tenant": "acme", "roles": ["writer"]})
    identity = oidc.authenticate({"authorization": "Bearer subject-1"})
    assert identity == Identity(
        "subject-1",
        "acme",
        ("writer",),
        {"sub": "subject-1", "tenant": "acme", "roles": ["writer"]},
    )

    class Retention:
        def retain_until(self, tenant, oid):
            return "2099-01-01"

        def before_delete(self, tenant, oid):
            raise PermissionError("retained")

    store = FilesystemObjectStore(tmp_path / "retained", LocalKeyProvider(b"r" * 32), Retention())
    local = Repo.init(tmp_path / "retention-source")
    oid = local.put("blob", b"keep", redact=False)
    store.put("acme", oid, local.raw(oid))
    with pytest.raises(PermissionError, match="retained"):
        store.delete("acme", oid)
    assert store.has("acme", oid)

    class DenyAdmission:
        def admit(self, identity, operation, facts):
            raise RuntimeError(f"denied {operation}")

    service, objects, index = _service(tmp_path / "denied")
    denied = RemoteService(
        objects,
        index,
        service.identities,
        RoleAuthorizationPolicy(),
        admission=DenyAdmission(),
    )
    writer = denied.authenticate({"authorization": "Bearer writer-token"})
    with pytest.raises(RuntimeError, match="denied upload"):
        denied.install_pack(writer, "acme", local.pack())


def _wsgi(app, method: str, path: str, body: bytes, **headers):
    state = {}

    def start_response(status, response_headers):
        state["status"] = status
        state["headers"] = response_headers

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": headers.pop("content_type", "application/json"),
        "HTTP_AUTHORIZATION": "Bearer writer-token",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    environ.update(
        {f"HTTP_{key.upper().replace('-', '_')}": value for key, value in headers.items()}
    )
    response = b"".join(app(environ, start_response))
    return state["status"], response


def test_resumable_pack_upload_round_trip(tmp_path: Path):
    service, objects, _ = _service(tmp_path / "remote")
    app = RemoteApp(service, tmp_path / "state")
    local = Repo.init(tmp_path / "local-upload")
    oid = local.put("blob", b"resumable", redact=False)
    pack = local.pack()
    declaration = json.dumps(
        {"sha256": hashlib.sha256(pack).hexdigest(), "size": len(pack)}
    ).encode()
    status, body = _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    assert status == "201 Created"
    upload_id = json.loads(body)["upload_id"]
    midpoint = len(pack) // 2
    path = f"/v1/tenants/acme/packs/{upload_id}"
    status, body = _wsgi(
        app,
        "PATCH",
        path,
        pack[:midpoint],
        content_type="application/octet-stream",
        upload_offset="0",
    )
    assert status == "200 OK" and json.loads(body)["offset"] == midpoint
    staged = app.uploads / "acme" / f"{upload_id}.part"
    assert pack[:midpoint] not in staged.read_bytes()
    assert b"TINEAES2" in staged.read_bytes()
    recovered = pack[midpoint : midpoint + 5]
    append_frames(staged, objects.keys, "acme", midpoint, recovered, len(pack))
    with staged.open("ab") as handle:
        handle.write(b"\x00\x01")
    app = RemoteApp(service, tmp_path / "state")
    status, body = _wsgi(app, "HEAD", path, b"")
    resumed = midpoint + len(recovered)
    assert status == "200 OK" and json.loads(body)["offset"] == resumed
    status, body = _wsgi(
        app,
        "PATCH",
        path,
        pack[resumed:],
        content_type="application/octet-stream",
        upload_offset=str(resumed),
    )
    assert status == "201 Created" and json.loads(body)["objects"] == 1
    assert objects.has("acme", oid)


def test_encrypted_upload_rejects_oversized_decrypted_frame(tmp_path: Path):
    class BrokenKeys:
        def encrypt(self, tenant, plaintext):
            return b"ciphertext"

        def decrypt(self, tenant, ciphertext):
            return b"x" * (1024 * 1024 + 9)

    path = tmp_path / "upload.part"
    path.touch()
    append_frames(path, BrokenKeys(), "acme", 0, b"x", 1)
    with pytest.raises(ValueError, match="frame is invalid"):
        read_frames(path, BrokenKeys(), "acme", 1, repair_tail=False)

    class ExpandingKeys(BrokenKeys):
        def encrypt(self, tenant, plaintext):
            return b"x" * (len(plaintext) + 4097)

    second = tmp_path / "expanded.part"
    second.touch()
    with pytest.raises(ValueError, match="invalid ciphertext"):
        append_frames(second, ExpandingKeys(), "acme", 0, b"x", 1)
