"""Final remote-layer release regressions."""

from __future__ import annotations

import base64
import io
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from opentine.remote._oidc import JWTVerifier, OIDCError, _document
from opentine.remote._uploads import UploadRegistry
from opentine.remote.app import RemoteApp
from opentine.remote.backend import SQLiteBackend
from opentine.remote.interfaces import AuditEvent
from opentine.remote.security import LocalKeyProvider, OIDCIdentityProvider


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _verifier() -> JWTVerifier:
    return JWTVerifier(
        {"keys": [{"kid": "key-1", "kty": "RSA"}]},
        issuer="https://issuer.example",
        audience="opentine",
    )


@pytest.mark.parametrize(
    "header",
    (
        b'{"alg":[],"kid":"key-1"}',
        b'{"alg":"RS256","kid":{}}',
        b'{"alg":"","kid":"key-1"}',
        b'{"alg":"RS256","kid":""}',
    ),
)
def test_malformed_jwt_alg_and_kid_types_fail_as_oidc_errors(header: bytes):
    token = f"{_b64(header)}.{_b64(b'{}')}.{_b64(b'x')}"
    with pytest.raises(OIDCError):
        _verifier()(token)


def test_json_integer_guard_is_wrapped_and_wsgi_returns_401(tmp_path):
    oversized = b'{"alg":' + b"1" * 5_000 + b',"kid":"key-1"}'
    token = f"{_b64(oversized)}.{_b64(b'{}')}.{_b64(b'x')}"
    with pytest.raises(OIDCError, match="malformed JWT header"):
        _verifier()(token)
    with pytest.raises(OIDCError, match="malformed OIDC discovery"):
        _document(b'{"value":' + b"1" * 5_000 + b"}", "discovery")

    class Service:
        objects = object()

        @staticmethod
        def capabilities():
            return {}

        def authenticate(self, headers):
            provider = OIDCIdentityProvider(_verifier())
            return provider.authenticate(headers)

    app = RemoteApp(Service(), tmp_path, staging_keys=LocalKeyProvider(b"k" * 32))
    state = {}

    def start_response(status, _headers):
        state["status"] = status

    environ = {
        "CONTENT_LENGTH": "0",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "PATH_INFO": "/v1/tenants/acme/refs",
        "REQUEST_METHOD": "GET",
        "wsgi.input": io.BytesIO(),
    }
    assert b"authentication failed" in b"".join(app(environ, start_response))
    assert state["status"] == "401 Unauthorized"


def test_upload_creation_is_atomic_and_reserves_capacity_per_tenant(tmp_path):
    registry = UploadRegistry(
        tmp_path / "uploads",
        LocalKeyProvider(b"u" * 32),
        ttl_seconds=60,
        max_pending=4,
    )
    barrier = Barrier(8)

    def create(index: int) -> str:
        barrier.wait()
        try:
            registry.create("acme", f"{index:032x}", {"sha256": "0" * 64, "size": 1})
        except ValueError as exc:
            return str(exc)
        return "created"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(create, range(8)))
    assert results.count("created") == 3
    assert results.count("tenant has too many pending uploads") == 5
    registry.create("beta", "f" * 32, {"sha256": "0" * 64, "size": 1})
    assert len(list((tmp_path / "uploads").glob("*/*.json"))) == 4

    with pytest.raises(ValueError, match="preserve global upload capacity"):
        UploadRegistry(
            tmp_path / "other",
            LocalKeyProvider(b"u" * 32),
            ttl_seconds=60,
            max_pending=4,
            max_pending_per_tenant=4,
        )


def test_audit_append_authenticates_tail_without_rescanning_history(tmp_path, monkeypatch):
    path = tmp_path / "audit.sqlite3"
    backend = SQLiteBackend(path, audit_key=b"a" * 32)
    backend.append(AuditEvent("first", "1", "acme", "alice", "read", "ok", {}))
    original = backend._verified_head_from
    scans = 0

    def counted(database):
        nonlocal scans
        scans += 1
        return original(database)

    monkeypatch.setattr(backend, "_verified_head_from", counted)
    for index in range(50):
        backend.append(AuditEvent(f"event-{index}", str(index), "acme", "alice", "read", "ok", {}))
    assert scans == 0
    assert backend.verify_audit_chain()
    assert scans > 0
    assert SQLiteBackend(path, audit_key=b"a" * 32).verify_audit_chain()
