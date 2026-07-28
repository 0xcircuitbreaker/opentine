"""Release-gate regressions for the fourth v0.3.0 security review."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import stat
import time
from pathlib import Path

import httpx
import pytest

import opentine.tools.search as search_tool
from opentine._canon import _redact
from opentine.redaction import redact_blob
from opentine.remote import _audit_backend
from opentine.remote.app import RemoteApp
from opentine.remote.backend import FilesystemObjectStore, SQLiteBackend
from opentine.remote.interfaces import AuditEvent, Identity
from opentine.remote.security import (
    KMSKeyProvider,
    LocalKeyProvider,
    RoleAuthorizationPolicy,
    StaticTokenIdentityProvider,
)
from opentine.remote.server import reference_app
from opentine.remote.service import RemoteService
from opentine.repository.client import _upload_result


def _identities(role: str = "admin") -> StaticTokenIdentityProvider:
    return StaticTokenIdentityProvider({"token": Identity("alice", "acme", (role,))})


def _service(root: Path, *, admission=None) -> RemoteService:
    index = SQLiteBackend(root / "metadata.sqlite3")
    return RemoteService(
        FilesystemObjectStore(root / "objects", LocalKeyProvider(b"k" * 32)),
        index,
        _identities(),
        RoleAuthorizationPolicy(),
        admission=admission,
    )


def _wsgi(app: RemoteApp, method: str, path: str, body: bytes = b"", **headers):
    status: list[str] = []
    environ = {
        "CONTENT_LENGTH": str(headers.pop("content_length", len(body))),
        "CONTENT_TYPE": headers.pop("content_type", "application/json"),
        "HTTP_AUTHORIZATION": "Bearer token",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    environ.update({"HTTP_" + key.upper(): value for key, value in headers.items()})
    response = app(environ, lambda value, _headers: status.append(value))
    return status[0], b"".join(response)


def test_m1_kms_remote_requires_external_audit_key(tmp_path: Path):
    def passthrough(_tenant, value):
        return value

    keys = KMSKeyProvider(passthrough, passthrough)
    with pytest.raises(RuntimeError, match="audit-key derivation"):
        reference_app(tmp_path / "missing", identities=_identities(), keys=keys)
    assert not list(tmp_path.rglob("*.audit-key"))

    derived = KMSKeyProvider(passthrough, passthrough, lambda: b"a" * 32)
    reference_app(tmp_path / "configured", identities=_identities(), keys=derived)
    assert not list((tmp_path / "configured").rglob("*.audit-key"))


def test_m3_committed_audit_row_forward_heals_anchor(monkeypatch, tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=b"a" * 32)
    original = _audit_backend.write_anchor

    def interrupted(*_args):
        raise OSError("simulated checkpoint interruption")

    monkeypatch.setattr(_audit_backend, "write_anchor", interrupted)
    with pytest.raises(OSError, match="checkpoint"):
        backend.append(AuditEvent("e1", "1", "acme", "alice", "read", "ok", {}))
    with sqlite3.connect(path) as database:
        assert database.execute("SELECT count(*) FROM audit").fetchone()[0] == 1

    monkeypatch.setattr(_audit_backend, "write_anchor", original)
    recovered = SQLiteBackend(path, audit_key=b"a" * 32)
    assert recovered.verify_audit_chain()


def test_m3_arbitrary_anchor_mismatch_needs_exact_recovery_head(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=b"a" * 32)
    backend.append(AuditEvent("e1", "1", "acme", "alice", "read", "ok", {}))
    trusted_head = backend.audit_head()
    Path(str(path) + ".audit-head").unlink()
    with pytest.raises(RuntimeError, match="explicit recovery"):
        SQLiteBackend(path, audit_key=b"a" * 32, migrate_legacy_audit=True)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        SQLiteBackend(path, audit_key=b"a" * 32, reanchor_audit_head="bad")
    recovered = SQLiteBackend(path, audit_key=b"a" * 32, reanchor_audit_head=trusted_head)
    assert recovered.verify_audit_chain()


def test_m4_transient_disconnect_preserves_resumable_upload(tmp_path: Path):
    app = RemoteApp(_service(tmp_path / "remote"), tmp_path / "state")
    data = b"eventual-pack"
    declaration = json.dumps(
        {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    ).encode()
    status, body = _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    assert status == "201 Created"
    upload_id = json.loads(body)["upload_id"]
    path = f"/v1/tenants/acme/packs/{upload_id}"
    status, _ = _wsgi(
        app,
        "PATCH",
        path,
        b"part",
        content_length=8,
        content_type="application/octet-stream",
        upload_offset="0",
    )
    assert status == "400 Bad Request"
    status, body = _wsgi(app, "HEAD", path)
    assert status == "200 OK" and json.loads(body)["offset"] == 0


def test_m5_assignment_redaction_is_linear_and_headers_fail_closed():
    adversarial = (b"a-b_c-d_" * 1500) + b"secretz"
    private_key_prefixes = b"-----BEGIN PRIVATE KEY-----x" * 3000
    started = time.monotonic()
    assert redact_blob(adversarial) == adversarial
    assert redact_blob(private_key_prefixes) == b"[REDACTED PRIVATE KEY]"
    assert time.monotonic() - started < 1.5
    prose = "authorization: this header controls access"
    assert _redact(prose).endswith("[REDACTED]")
    assert redact_blob(prose.encode()).endswith(b"[REDACTED]")
    assert _redact("authorization: Basic dXNlcjpwYXNz").endswith("[REDACTED]")
    assert _redact("authorization: this secret phrase").endswith("[REDACTED]")
    assert redact_blob(b"authorization: this secret phrase").endswith(b"[REDACTED]")


def test_l6_audit_verify_is_read_only_and_reports_status(tmp_path: Path):
    service = _service(tmp_path / "remote")
    admin = service.authenticate({"authorization": "Bearer token"})
    service.list_refs(admin, "acme")
    index = service.index
    before = index.audit_head()
    with sqlite3.connect(index.path) as database:
        count = database.execute("SELECT count(*) FROM audit").fetchone()[0]
    first = service.verify_audit_chain(admin, "acme")
    second = service.verify_audit_chain(admin, "acme")
    with sqlite3.connect(index.path) as database:
        after_count = database.execute("SELECT count(*) FROM audit").fetchone()[0]
    assert first == second == {"head": before, "ok": True, "status": "verified", "warnings": []}
    assert after_count == count and index.audit_head() == before

    class InvalidAudit:
        def append(self, *_args):
            return None

        def audit_head(self):
            return "0" * 64

        def audit_warnings(self):
            return []

        def verify_audit_chain(self):
            return False

    invalid = RemoteService(
        service.objects,
        service.index,
        service.identities,
        service.authorization,
        audit=InvalidAudit(),
    )
    assert invalid.verify_audit_chain(admin, "acme")["status"] == "invalid"


def test_info_existing_audit_key_permissions_are_restricted(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    SQLiteBackend(path)
    key_path = Path(str(path) + ".audit-key")
    key_path.chmod(0o644)
    SQLiteBackend(path)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_info_invalid_upload_results_are_rejected():
    good = {"objects": 2, "pack_id": "sha256:" + "a" * 64}
    assert _upload_result(good) == (2, good["pack_id"])
    for bad in (
        {"objects": True, "pack_id": good["pack_id"]},
        {"objects": -1, "pack_id": good["pack_id"]},
        {"objects": 1, "pack_id": "not-a-pack"},
        {"objects": 1},
    ):
        with pytest.raises(ValueError, match="invalid"):
            _upload_result(bad)
    with pytest.raises(ValueError, match="does not match"):
        _upload_result(good, expected_objects=3, expected_pack=good["pack_id"])
    with pytest.raises(ValueError, match="does not match"):
        _upload_result(good, expected_objects=2, expected_pack="sha256:" + "b" * 64)


def test_info_pending_limit_precedes_admission(tmp_path: Path):
    class Admission:
        calls = 0

        def admit(self, _identity, _operation, _facts):
            self.calls += 1

    admission = Admission()
    app = RemoteApp(
        _service(tmp_path / "remote", admission=admission),
        tmp_path / "state",
        max_pending_uploads=1,
    )
    declaration = json.dumps({"sha256": "0" * 64, "size": 1}).encode()
    assert _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)[0] == "201 Created"
    assert _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)[0] == "400 Bad Request"
    assert admission.calls == 1


@pytest.mark.asyncio
async def test_independent_search_responses_are_streamed_and_bounded(monkeypatch):
    oversized = b"x" * 65
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=oversized, request=request)
    )

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=transport, **kwargs)

    monkeypatch.setattr(search_tool.httpx, "AsyncClient", Client)
    monkeypatch.setattr(search_tool, "MAX_SEARCH_RESPONSE_BYTES", 64)
    with pytest.raises(ValueError, match="maximum size"):
        await search_tool._duckduckgo("bounded", 1)


def test_duckduckgo_html_parser_is_single_pass_and_output_bounded():
    from opentine.tools._html import duckduckgo_results

    adversarial = 'class="result__snippet">' * 8_000
    assert duckduckgo_results(adversarial, 5) == []
    html = (
        '<a data-extra="1" href="https://example.test" class="other result__a">'
        "A <b>useful</b> &amp; safe title</a>"
        '<div class="result__snippet">A <em>short</em> snippet</div>'
    )
    assert duckduckgo_results(html, 5) == [
        ("https://example.test", "A useful & safe title", "A short snippet")
    ]
    huge = '<a class="result__a" href="/' + "u" * 10_000 + '">' + "x" * 10_000 + "</a>"
    [(url, title, _)] = duckduckgo_results(huge, 1)
    assert len(url) == 4_096
    assert len(title) == 2_048
