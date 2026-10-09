"""0.9.2 production hardening of the reference remote (slice-A audit hardening list).

Each test names the item it pins; each fails on the code before the change.
"""

from __future__ import annotations

import base64
import io
import json
import select
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from opentine import Run
from opentine._cli_parser import _build_parser
from opentine.graph import StepKind
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    JWTVerifier,
    LocalKeyProvider,
    OIDCError,
    OIDCIdentityProvider,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
    _object_list,
    backend,
    server,
    service,
)
from opentine.remote._admin import RemoteAdmin
from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler
from opentine.remote._upload_crypto import append_frames, read_frames
from opentine.remote.security import AuthenticationError
from opentine.repository import Repo

KEY = b"k" * 32
ISSUER = "https://idp.example"


def _reference(tmp_path: Path, **options):
    root = tmp_path / "remote-root"
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("alice", "acme", ("writer",)),
            "other-token": Identity("bob", "acme", ("writer",)),
            "admin-token": Identity("root", "acme", ("admin",)),
        }
    )
    app = server.reference_app(root, identities=identities, keys=LocalKeyProvider(KEY), **options)
    remote = app.service

    def who(token: str) -> Identity:
        return remote.authenticate({"authorization": f"Bearer {token}"})

    return app, remote, who


def _push(remote, writer, local: Repo, label: str, ref: str | None) -> str:
    run = Run(id=label, metadata={"label": label})
    run.add_step(StepKind.done, {"text": f"{label} output"})
    stored = local.put_run(run)
    remote.install_pack(writer, "acme", local.pack())
    if ref:
        assert remote.update_ref(writer, "acme", ref, stored.run_id, None)
    return stored.run_id


def _call(app, method: str, path: str, body: bytes = b"", token="writer-token", **headers):
    state: dict = {}

    def start_response(status, response_headers):
        state["status"] = status

    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": headers.pop("content_type", "application/json"),
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
    }
    environ.update({f"HTTP_{k.upper().replace('-', '_')}": v for k, v in headers.items()})
    body = b"".join(app(environ, start_response))
    return state["status"], body


def _audit_rows(index, action: str) -> list[tuple]:
    with sqlite3.connect(index.path) as database:
        return database.execute(
            "SELECT tenant,actor,outcome,details FROM audit WHERE action=? ORDER BY sequence",
            (action,),
        ).fetchall()


class _Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


# --- 1. purge sees a tenant beyond the request-path listing cap -------------------- #


def test_purge_works_on_a_tenant_larger_than_the_listing_cap(tmp_path, monkeypatch):
    app, remote, who = _reference(tmp_path)
    writer = who("writer-token")
    local = Repo.init(tmp_path / "local")
    kept = _push(remote, writer, local, "kept", "heads/main")
    gone = _push(remote, writer, local, "gone", "heads/gone")
    monkeypatch.setattr(_object_list, "MAX_OBJECT_LIST", 3)
    with pytest.raises(ValueError):
        remote.objects.list("acme")  # the bounded request-path listing refuses this tenant
    admin = RemoteAdmin.open(app.state, keys=LocalKeyProvider(KEY))
    assert admin.delete_ref("acme", "heads/gone", expected=gone)
    result = admin.purge("acme", grace_seconds=0)
    assert gone in result.removed
    assert remote.objects.has("acme", kept) and not remote.objects.has("acme", gone)


# --- 2. association installs serialize across processes ---------------------------- #

_HOLD_LOCK = """
import sys, time
from pathlib import Path
from opentine.remote._audit import audit_file_lock
with audit_file_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    time.sleep(float(sys.argv[2]))
"""


def test_association_installs_serialize_across_processes(tmp_path):
    app, remote, who = _reference(tmp_path)
    writer = who("writer-token")
    local = Repo.init(tmp_path / "local")
    run = _push(remote, writer, local, "signed", "heads/main")
    local.attest(run, {"ok": True}, signer="ci")
    plain = Repo.init(tmp_path / "plain")
    plain.put("blob", b"no associations here", redact=False)
    lock = f"{remote.index.path}.association-lock"
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLD_LOCK, lock, "3"], stdout=subprocess.PIPE, text=True
    )
    try:
        assert holder.stdout.readline().strip() == "locked"
        started = time.monotonic()
        remote.install_pack(writer, "acme", plain.pack())  # no associations: never waits
        assert time.monotonic() - started < 1.5
        started = time.monotonic()
        remote.install_pack(writer, "acme", local.pack())  # an attestation: waits its turn
        waited = time.monotonic() - started
    finally:
        holder.wait(timeout=30)
        holder.stdout.close()
    assert waited >= 0.5


# --- 3. slow or crowding clients cannot hold every worker --------------------------- #


def _hello(environ, start_response):
    start_response("200 OK", [("Content-Length", "2")])
    return [b"ok"]


def _serve(header_timeout: float = 10, **limits):
    handler = type("_H", (TimeoutRequestHandler,), {"timeout": 5, "header_timeout": header_timeout})
    server_class = type("_S", (ThreadingWSGIServer,), limits)
    running = make_server("127.0.0.1", 0, _hello, server_class=server_class, handler_class=handler)
    threading.Thread(target=running.serve_forever, daemon=True).start()
    return running


def _stop(running) -> None:
    running.shutdown()
    running.server_close()


def _closed_within(connection: socket.socket, seconds: float) -> bool:
    """Trickle a byte every 100 ms (a per-read timeout never fires) until closed."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            readable, _, _ = select.select([connection], [], [], 0.1)
            if readable and connection.recv(1) == b"":
                return True
            connection.sendall(b"a")
        except OSError:
            return True
    return False


def test_a_trickled_request_is_closed_at_the_header_deadline():
    running = _serve(header_timeout=0.5)
    try:
        with socket.create_connection(running.server_address, timeout=5) as connection:
            connection.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
            assert _closed_within(connection, 3)
    finally:
        _stop(running)


def _busy_reply(running) -> bytes:
    with socket.create_connection(running.server_address, timeout=2) as connection:
        return connection.recv(200)


def test_a_full_server_answers_503_instead_of_blocking_its_accept_loop():
    running = _serve(max_workers=1, max_per_peer=4)
    idle = socket.create_connection(running.server_address)  # holds the only slot
    try:
        time.sleep(0.2)
        assert _busy_reply(running).startswith(b"HTTP/1.1 503")
    finally:
        idle.close()
        _stop(running)


def test_one_peer_cannot_hold_every_worker():
    running = _serve(max_workers=4, max_per_peer=1)
    idle = socket.create_connection(running.server_address)
    try:
        time.sleep(0.2)
        assert _busy_reply(running).startswith(b"HTTP/1.1 503")  # three slots still free
    finally:
        idle.close()
        _stop(running)


def test_request_logs_never_name_an_upload_id(capsys):
    handler = object.__new__(TimeoutRequestHandler)
    upload = "ab" * 16
    handler.command = "PATCH"
    handler.path = f"/v1/tenants/acme/packs/{upload}?sig=1"
    handler.requestline = f"PATCH {handler.path} HTTP/1.1"
    handler.client_address = ("127.0.0.1", 1)
    handler.log_request(200, 5)
    logged = capsys.readouterr().err
    assert upload not in logged and "sig=1" not in logged
    assert "/packs/<upload>" in logged


# --- 4. refusals are audited ----------------------------------------------------------- #


def test_an_oidc_tenant_claim_that_is_no_tenant_is_refused_at_authentication():
    claims = {"sub": "u1", "tenant": "Acme Corp", "roles": ["reader"]}
    provider = OIDCIdentityProvider(lambda token: dict(claims))
    with pytest.raises(AuthenticationError, match="tenant"):
        provider.authenticate({"authorization": "Bearer anything"})


def test_a_denial_for_an_invalid_tenant_claim_is_still_audited(tmp_path):
    app, remote, who = _reference(tmp_path)
    stranger = Identity("mallory", "Acme Corp", ("reader",))
    with pytest.raises(PermissionError):
        remote._authorize(stranger, "read_ref", "acme")
    assert _audit_rows(remote.index, "read_ref")[-1][:3] == ("acme", "mallory", "denied")


def test_unauthenticated_requests_are_audited_without_flooding_the_log(tmp_path):
    app, remote, who = _reference(tmp_path)
    clock = _Clock()
    app._failures.clock = clock
    for _ in range(3):
        status, _ = _call(app, "GET", "/v1/tenants/acme/refs", token="not-a-real-token")
        assert status.startswith("401")
    rows = _audit_rows(remote.index, "authenticate")
    assert [(row[0], row[1], row[2], json.loads(row[3])["count"]) for row in rows] == [
        ("acme", "anonymous", "denied", 1)
    ]
    clock.value += 61
    _call(app, "GET", "/v1/tenants/NOT A TENANT/refs", token="not-a-real-token")
    later = [
        (row[0], json.loads(row[3])["count"]) for row in _audit_rows(remote.index, "authenticate")
    ]
    assert sorted(later[1:]) == [("_server", 1), ("acme", 2)]
    assert "not-a-real-token" not in json.dumps(later)


def test_failures_after_authorization_are_audited(tmp_path):
    class Refuse:
        def admit(self, identity, operation, facts):
            if operation == "upload":
                raise PermissionError("over quota")

    app, remote, who = _reference(tmp_path, admission=Refuse())
    missing = json.dumps({"new": "run:sha256:" + "1" * 64}).encode()
    status, _ = _call(app, "PUT", "/v1/tenants/acme/refs/heads/main", missing)
    assert status.startswith("404")
    error = _audit_rows(remote.index, "update_ref")[-1]
    assert error[:3] == ("acme", "alice", "error") and json.loads(error[3])["error"] == "KeyError"
    local = Repo.init(tmp_path / "local")
    local.put("blob", b"refused", redact=False)
    status, _ = _call(
        app, "POST", "/v1/tenants/acme/packs", local.pack(),
        content_type="application/vnd.opentine.pack",
    )  # fmt: skip
    assert status.startswith("403")
    assert _audit_rows(remote.index, "upload")[-1][:3] == ("acme", "alice", "denied")


# --- 5. promotions and tag moves need admin by default ----------------------------- #


def test_promotions_and_tag_moves_need_the_admin_role(tmp_path):
    app, remote, who = _reference(tmp_path)
    writer, admin = who("writer-token"), who("admin-token")
    local = Repo.init(tmp_path / "local")
    first = _push(remote, writer, local, "first", "heads/main")
    second = _push(remote, writer, local, "second", None)
    with pytest.raises(PermissionError):
        remote.update_ref(writer, "acme", "promotions/prod", first, None)
    assert _audit_rows(remote.index, "promote")[-1][1:3] == ("alice", "denied")
    assert remote.update_ref(admin, "acme", "promotions/prod", first, None)
    assert remote.update_ref(writer, "acme", "tags/v1", first, None)  # creating stays a writer's
    with pytest.raises(PermissionError):
        remote.update_ref(writer, "acme", "tags/v1", second, first)
    assert remote.update_ref(admin, "acme", "tags/v1", second, first)
    relaxed = RoleAuthorizationPolicy(writer_promotes=True)
    assert relaxed.authorize(writer, "promote", "acme") and relaxed.authorize(
        writer, "retag", "acme"
    )
    assert not RoleAuthorizationPolicy().authorize(writer, "promote", "acme")


# --- 6. plaintext development mode stays on loopback -------------------------------- #


def test_insecure_dev_serves_loopback_only_unless_told_otherwise(tmp_path, monkeypatch):
    monkeypatch.setenv("TINE_REMOTE_TOKEN", "t" * 32)
    monkeypatch.setenv("TINE_KMS_KEY", base64.b64encode(KEY).decode())

    def bound(*args, **kwargs):
        raise RuntimeError("bound")

    monkeypatch.setattr(server, "make_server", bound)
    base = ["serve", "--root", str(tmp_path / "remote"), "--port", "0", "--insecure-dev"]
    with pytest.raises(SystemExit, match="loopback only"):
        server.cmd_serve(_build_parser().parse_args([*base, "--host", "0.0.0.0"]), None)
    for host in (["--host", "127.0.0.1"], ["--host", "0.0.0.0", "--insecure-dev-any-host"]):
        with pytest.raises(RuntimeError, match="bound"):
            server.cmd_serve(_build_parser().parse_args([*base, *host]), None)


# --- 7. an upload belongs to the identity that declared it ------------------------- #


def test_another_writer_cannot_touch_someone_elses_upload(tmp_path):
    import hashlib

    app, remote, who = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    local.put("blob", b"resumable", redact=False)
    pack = local.pack()
    declaration = json.dumps({"sha256": hashlib.sha256(pack).hexdigest(), "size": len(pack)})
    status, body = _call(app, "POST", "/v1/tenants/acme/packs", declaration.encode())
    upload = json.loads(body)["upload_id"]
    path = f"/v1/tenants/acme/packs/{upload}"
    octets = {"content_type": "application/octet-stream", "upload_offset": "0"}
    assert _call(app, "PATCH", path, pack, token="other-token", **octets)[0].startswith("403")
    assert _call(app, "HEAD", path, token="other-token")[0].startswith("403")
    assert _audit_rows(remote.index, "upload")[-1][1:3] == ("bob", "denied")
    assert _call(app, "PATCH", path, pack, **octets)[0] == "201 Created"


# --- 8. audit verification: tenant-safe report, bounded cost ------------------------ #


def test_audit_report_names_no_server_wide_head_and_walks_the_chain_rarely(tmp_path, monkeypatch):
    app, remote, who = _reference(tmp_path)
    admin = who("admin-token")
    remote.list_refs(admin, "acme")
    assert remote.verify_audit_chain(admin, "acme") == {
        "ok": True,
        "status": "verified",
        "warnings": [],
    }
    starts: list[int] = []
    walk = SQLiteBackend._verify_rows

    def counted(self, database, after, previous):
        starts.append(after)
        return walk(self, database, after, previous)

    monkeypatch.setattr(SQLiteBackend, "_verify_rows", counted)
    for _ in range(5):
        remote.list_refs(admin, "acme")
        assert remote.verify_audit_chain(admin, "acme")["ok"]
    assert starts and 0 not in starts  # only rows appended since the last check
    remote.list_refs(admin, "acme")
    with sqlite3.connect(remote.index.path) as database:  # a row the next check covers
        database.execute("DROP TRIGGER audit_no_update")
        database.execute(
            "UPDATE audit SET details='{}' WHERE sequence=(SELECT max(sequence) FROM audit)"
        )
    assert remote.verify_audit_chain(admin, "acme")["status"] == "invalid"


def test_a_full_walk_still_runs_and_catches_interior_tampering(tmp_path, monkeypatch):
    app, remote, who = _reference(tmp_path)
    admin = who("admin-token")
    remote.list_refs(admin, "acme")
    assert remote.verify_audit_chain(admin, "acme")["ok"]
    with sqlite3.connect(remote.index.path) as database:
        database.execute("DROP TRIGGER audit_no_update")
        database.execute(
            "UPDATE audit SET details='{}' WHERE sequence=(SELECT min(sequence) FROM audit)"
        )
    monkeypatch.setattr(remote.index, "full_verify_interval", 0.0)
    assert remote.verify_audit_chain(admin, "acme")["status"] == "invalid"


# --- 9. ciphertexts are bound to their slot ------------------------------------------ #


def test_object_ciphertexts_open_only_in_their_own_slot(tmp_path):
    keys = LocalKeyProvider(KEY)
    objects = FilesystemObjectStore(tmp_path / "objects", keys)
    local = Repo.init(tmp_path / "local")
    first, second = (local.put("blob", text, redact=False) for text in (b"alpha", b"beta"))
    for oid in (first, second):
        objects.put("acme", oid, local.raw(oid))
    sealed = objects._path("acme", first).read_bytes()
    assert sealed.startswith(b"TINEAES3")
    assert keys.unseal("object", "acme", first, sealed) == local.raw(first)
    with pytest.raises(InvalidTag):
        keys.unseal("object", "acme", second, sealed)  # another object's slot
    with pytest.raises(InvalidTag):
        keys.unseal("upload-frame", "acme", first, sealed)  # another purpose
    # Written before 0.9.2: tenant-bound only, and still readable.
    objects._path("acme", second).write_bytes(keys.encrypt("acme", local.raw(second)))
    assert objects.get("acme", second) == local.raw(second)


def test_upload_frames_cannot_move_between_uploads(tmp_path):
    keys = LocalKeyProvider(KEY)
    spools = [tmp_path / f"{name * 32}.part" for name in ("a", "b")]
    for spool in spools:
        spool.touch()
        append_frames(spool, keys, "acme", 0, b"x" * 10, 10)
    assert read_frames(spools[1], keys, "acme", 10, repair_tail=False)[0] == b"x" * 10
    spools[1].write_bytes(spools[0].read_bytes())
    with pytest.raises(InvalidTag):
        read_frames(spools[1], keys, "acme", 10, repair_tail=False)


# --- 10. search pages instead of failing ---------------------------------------------- #


def test_search_returns_a_truncated_page_instead_of_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "MAX_CONTROL_RESULTS", 3)
    monkeypatch.setattr(service, "MAX_CONTROL_RESULTS", 3, raising=False)
    app, remote, who = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    for index in range(5):
        local.put("blob", f"blob {index}".encode(), redact=False)
    remote.install_pack(who("writer-token"), "acme", local.pack())
    query = json.dumps({"type": "blob"}).encode()
    status, body = _call(app, "POST", "/v1/tenants/acme/search", query)
    assert status == "200 OK"
    page = json.loads(body)
    assert len(page["objects"]) == 3 and page["truncated"] is True
    assert json.loads(_call(app, "POST", "/v1/tenants/acme/search", query)[1]) == page


# --- 11. access tokens issued to a listed client --------------------------------------- #


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _signed(key, claims: dict) -> str:
    header = {"alg": "ES256", "kid": "k1"}
    payload = {"iss": ISSUER, "aud": "tine", "sub": "u1", "exp": time.time() + 300, **claims}
    signing = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    r, s = utils.decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def test_an_access_token_for_a_listed_client_is_accepted():
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "k1"}
    jwk.update(x=_b64(numbers.x.to_bytes(32, "big")), y=_b64(numbers.y.to_bytes(32, "big")))
    jwks = {"keys": [jwk]}
    token = _signed(key, {"azp": "cli-client"})
    with pytest.raises(OIDCError, match="authorized party"):
        JWTVerifier(jwks, issuer=ISSUER, audience="tine")(token)
    listed = JWTVerifier(jwks, issuer=ISSUER, audience="tine", authorized_parties=("cli-client",))
    assert listed(token)["azp"] == "cli-client"
    with pytest.raises(OIDCError, match="authorized party"):
        listed(_signed(key, {"aud": ["tine", "other"]}))  # several audiences: azp required
    with pytest.raises(OIDCError, match="authorized party"):
        listed(_signed(key, {"azp": "someone-else"}))


# --- 12. negotiation is behind a bounded slot ---------------------------------------- #


def test_negotiation_waits_for_a_bounded_slot_then_answers_busy(tmp_path):
    app, remote, who = _reference(tmp_path)
    app.guard_wait_seconds = 0.05
    request = json.dumps({"wants": [], "haves": []}).encode()
    for _ in range(2):
        app._walk_guard.acquire()
    try:
        status, body = _call(app, "POST", "/v1/tenants/acme/negotiate", request)
    finally:
        for _ in range(2):
            app._walk_guard.release()
    assert status.startswith("503") and json.loads(body) == {"error": "server is busy"}
    assert _call(app, "POST", "/v1/tenants/acme/negotiate", request)[0] == "200 OK"
