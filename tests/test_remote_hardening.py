"""Regression tests for remote-layer audit follow-ups (M4 audit chain, M5 OIDC, M6 limits)."""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from opentine.remote.backend import SQLiteBackend
from opentine.remote.interfaces import AuditEvent
from opentine.remote.security import LocalKeyProvider

crypto = pytest.importorskip("cryptography")


# --- M4: HMAC-chained audit log with an authenticated external head -------------------


@pytest.mark.parametrize("leeway", [True, float("nan"), float("inf")])
def test_oidc_rejects_nonfinite_or_boolean_leeway(leeway):
    from opentine.remote._oidc import JWTVerifier, OIDCError

    with pytest.raises(OIDCError):
        JWTVerifier(
            {"keys": [{"kid": "key"}]},
            issuer="https://idp",
            audience="opentine",
            leeway=leeway,
        )


def _seed_audit(tmp_path: Path) -> SQLiteBackend:
    db = SQLiteBackend(tmp_path / "meta.sqlite3")
    for i in range(4):
        db.append(
            AuditEvent(f"e{i}", f"2026-07-14T00:00:0{i}", "t1", "alice", "fetch", "ok", {"n": i})
        )
    return db


def test_m4_audit_chain_is_valid_when_untampered(tmp_path: Path):
    db = _seed_audit(tmp_path)
    assert db.verify_audit_chain() is True
    assert db.verify_audit_chain(expected_head=db.audit_head()) is True


def test_m4_audit_chain_detects_interior_tampering(tmp_path: Path):
    db = _seed_audit(tmp_path)
    con = sqlite3.connect(db.path)
    con.execute("DROP TRIGGER audit_no_update")  # even bypassing the soft trigger...
    con.execute("UPDATE audit SET details='{\"n\":999}' WHERE event_id='e1'")
    con.commit()
    con.close()
    assert db.verify_audit_chain() is False  # ...the chain still catches it


def test_m4_audit_chain_detects_truncation_against_checkpoint(tmp_path: Path):
    db = _seed_audit(tmp_path)
    head = db.audit_head()
    con = sqlite3.connect(db.path)
    con.execute("DROP TRIGGER audit_no_delete")
    con.execute("DELETE FROM audit WHERE event_id='e3'")  # drop the last row
    con.commit()
    con.close()
    # The authenticated sidecar anchor makes end truncation fail by default.
    assert db.verify_audit_chain() is False
    assert db.verify_audit_chain(expected_head=head) is False


def test_m4_concurrent_appends_form_one_valid_chain(tmp_path: Path):
    db = SQLiteBackend(tmp_path / "meta.sqlite3")
    barrier = threading.Barrier(8)
    errors = []

    def append(index: int) -> None:
        try:
            barrier.wait()
            db.append(AuditEvent(f"e{index}", str(index), "t1", "a", "read", "ok", {"n": index}))
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=append, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with sqlite3.connect(db.path) as database:
        count = database.execute("SELECT count(*) FROM audit").fetchone()[0]
    assert not errors and count == 8
    assert db.verify_audit_chain()


def test_m4_existing_unchained_audit_rows_are_migrated(tmp_path: Path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as database:
        database.execute(
            "CREATE TABLE audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
            "event_id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, tenant TEXT NOT NULL, "
            "actor TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, "
            "details TEXT NOT NULL)"
        )
        database.execute(
            "INSERT INTO audit(event_id,timestamp,tenant,actor,action,outcome,details) "
            "VALUES(?,?,?,?,?,?,?)",
            ("old", "1", "t1", "a", "read", "ok", '{"n":1}'),
        )
    with pytest.raises(RuntimeError, match="explicit migration"):
        SQLiteBackend(path)
    db = SQLiteBackend(path, migrate_legacy_audit=True)
    assert db.audit_status() == "legacy-unverified"
    assert db.verify_audit_chain() is False
    db.append(AuditEvent("new", "2", "t1", "a", "read", "ok", {}))
    assert db.audit_status() == "legacy-unverified"


# --- M5: real OIDC/JWT verification ----------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_bytes(value: int, size: int | None = None) -> bytes:
    size = size or (value.bit_length() + 7) // 8
    return value.to_bytes(size, "big")


def _rs256(payload: dict, key, kid: str = "r1") -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = _b64(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = key.sign(f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{_b64(sig)}"


def _es256(payload: dict, key, kid: str = "e1") -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    header = _b64(json.dumps({"alg": "ES256", "kid": kid}).encode())
    body = _b64(json.dumps(payload).encode())
    der = key.sign(f"{header}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return f"{header}.{body}.{_b64(_int_bytes(r, 32) + _int_bytes(s, 32))}"


def test_m5_oidc_verifier_accepts_valid_and_rejects_bad(tmp_path: Path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    from opentine.remote._oidc import JWTVerifier, OIDCError
    from opentine.remote.security import OIDCIdentityProvider

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "r1",
                "n": _b64(_int_bytes(numbers.n)),
                "e": _b64(_int_bytes(numbers.e)),
            }
        ]
    }
    now = time.time()
    verifier = JWTVerifier(jwks, issuer="https://idp", audience="tine", now=lambda: now)

    valid = _rs256(
        {
            "iss": "https://idp",
            "aud": "tine",
            "sub": "u1",
            "exp": now + 300,
            "tenant": "t1",
            "roles": ["writer"],
        },
        key,
    )
    assert verifier(valid)["sub"] == "u1"

    for payload in (
        {"iss": "https://idp", "aud": "tine", "sub": "u", "exp": now - 100},  # expired
        {"iss": "https://idp", "aud": "other", "sub": "u", "exp": now + 300},  # wrong aud
        {"iss": "https://evil", "aud": "tine", "sub": "u", "exp": now + 300},  # wrong iss
    ):
        with pytest.raises(OIDCError):
            verifier(_rs256(payload, key))

    tampered = valid[:-6] + ("AAAAAA" if valid[-6:] != "AAAAAA" else "BBBBBB")
    with pytest.raises(OIDCError):
        verifier(tampered)

    # The identity provider maps verified claims into a tenant-scoped Identity.
    provider = OIDCIdentityProvider.from_jwks(jwks, issuer="https://idp", audience="tine")
    provider.verifier = verifier
    identity = provider.authenticate({"authorization": f"Bearer {valid}"})
    assert identity.tenant == "t1" and "writer" in identity.roles
    provider.verifier = lambda token: {
        "sub": "u",
        "tenant": "t1",
        "roles": {"admin": True},
    }
    with pytest.raises(PermissionError, match="roles claim"):
        provider.authenticate({"authorization": "Bearer signed"})
    provider.verifier = lambda token: {"sub": "u", "tenant": "t1", "roles": []}
    assert provider.authenticate({"authorization": "Bearer signed"}).roles == ()


def test_m5_es256_and_algorithm_confusion_guards():
    from cryptography.hazmat.primitives.asymmetric import ec

    from opentine.remote._oidc import JWTVerifier, OIDCError

    now = time.time()
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {
        "alg": "ES256",
        "crv": "P-256",
        "kid": "e1",
        "kty": "EC",
        "use": "sig",
        "x": _b64(_int_bytes(numbers.x, 32)),
        "y": _b64(_int_bytes(numbers.y, 32)),
    }
    verifier = JWTVerifier({"keys": [jwk]}, issuer="https://idp", audience="tine", now=lambda: now)
    claims = {"iss": "https://idp", "aud": "tine", "sub": "u", "exp": now + 300}
    assert verifier(_es256(claims, key))["sub"] == "u"
    confused_header = _b64(json.dumps({"alg": "RS256", "kid": "e1"}).encode())
    confused_body = _b64(json.dumps(claims).encode())
    confused = f"{confused_header}.{confused_body}.{_b64(b'x' * 64)}"
    with pytest.raises(OIDCError, match="algorithm"):
        verifier(confused)
    with pytest.raises(OIDCError, match="unique"):
        JWTVerifier({"keys": [jwk, jwk]}, issuer="https://idp", audience="tine")


def test_local_encryption_derives_tenant_keys_and_reads_legacy_ciphertext():
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    provider = LocalKeyProvider(b"k" * 32)
    first = provider.encrypt("tenant-a", b"same")
    second = provider.encrypt("tenant-b", b"same")
    assert first.startswith(b"TINEAES2") and second.startswith(b"TINEAES2")
    assert provider.decrypt("tenant-a", first) == b"same"
    with pytest.raises(InvalidTag):
        provider.decrypt("tenant-b", first)
    nonce = b"n" * 12
    legacy = b"TINEAES1" + nonce + AESGCM(b"k" * 32).encrypt(nonce, b"old", b"tenant-a")
    assert provider.decrypt("tenant-a", legacy) == b"old"


# --- M6: server limits -----------------------------------------------------------------


def test_m6_server_has_conservative_defaults():
    import inspect

    from opentine.remote.app import RemoteApp
    from opentine.remote.server import ThreadingWSGIServer, TimeoutRequestHandler

    assert TimeoutRequestHandler.timeout == 30 and ThreadingWSGIServer.max_workers == 16
    assert ThreadingWSGIServer.request_deadline == 60
    # Single requests are small; resumable uploads retain a separately bounded total.
    default = inspect.signature(RemoteApp.__init__).parameters["max_request_bytes"].default
    upload = inspect.signature(RemoteApp.__init__).parameters["max_upload_bytes"].default
    assert default == 16 * 1024 * 1024 and upload == 256 * 1024 * 1024


def test_m6_absolute_request_deadline_interrupts_active_connection():
    import threading
    import time

    from opentine.remote.server import ThreadingWSGIServer

    class BlockingServer(ThreadingWSGIServer):
        request_deadline = 0.05

        def finish_request(self, request, client_address):
            request.closed.wait(timeout=1)

        def handle_error(self, request, client_address):
            pass

        def shutdown_request(self, request):
            request.close()

    class Request:
        closed = threading.Event()

        def shutdown(self, how):
            self.closed.set()

        def close(self):
            self.closed.set()

    server = object.__new__(BlockingServer)
    server._request_slots = threading.BoundedSemaphore(1)
    server._request_slots.acquire()
    accepted = Request()
    worker = threading.Thread(target=server.process_request_thread, args=(accepted, ("local", 0)))
    started = time.monotonic()
    worker.start()
    try:
        worker.join(timeout=0.5)
        assert not worker.is_alive() and time.monotonic() - started < 0.3
    finally:
        accepted.close()


def test_m6_tls_handshake_is_deferred_to_bounded_worker(monkeypatch):
    from wsgiref.simple_server import WSGIServer

    from opentine.remote.server import ThreadingWSGIServer

    class Raw:
        closed = False

        def close(self):
            self.closed = True

    class Context:
        def wrap_socket(self, request, **kwargs):
            assert kwargs == {"server_side": True, "do_handshake_on_connect": False}
            return ("wrapped", request)

    raw = Raw()
    monkeypatch.setattr(WSGIServer, "get_request", lambda self: (raw, ("client", 1)))
    server = object.__new__(ThreadingWSGIServer)
    server.ssl_context = Context()
    request, address = server.get_request()
    assert request == ("wrapped", raw) and address == ("client", 1)
    assert raw.closed is False
