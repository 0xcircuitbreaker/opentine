"""Adversarial regression coverage for the second v0.3.0 audit."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sqlite3
from pathlib import Path

import httpx
import pytest

import opentine.billing.catalog as catalog_module
from opentine import Recorder, Repo
from opentine._canon import _redact
from opentine.billing.catalog import CatalogError, PricingCatalog
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, object_id, validate_links
from opentine.policies import NetworkPolicy
from opentine.redaction import redact_blob
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.remote.interfaces import AuditEvent
from opentine.repository._http import MAX_CONTROL_BYTES, request_json
from opentine.repository.client import _upload
from opentine.repository.pack import MAGIC, MAX_PACK_OBJECTS, create_pack, inspect_pack, negotiate
from opentine.repository.search import search
from opentine.tools.web import _get as web_get
from opentine.trace.importers import framework_events, jsonl_events, otel_genai_events
from opentine.trace.schema import TraceEvent

FIXTURES = Path(__file__).parent / "fixtures"


def _service(tmp_path: Path) -> RemoteService:
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "acme", ("writer",))}
    )
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "metadata.sqlite3")
    return RemoteService(objects, index, identities, RoleAuthorizationPolicy())


def _wsgi(app: RemoteApp, method: str, path: str, body: bytes = b"", **headers):
    state = {}

    def start_response(status, response_headers):
        state["status"] = status

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


def test_h1_all_control_plane_json_is_streamed_and_bounded(monkeypatch):
    body = b'{"padding":"' + b"x" * MAX_CONTROL_BYTES + b'"}'
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    session = httpx.Client(base_url="https://remote.example", transport=transport)
    with pytest.raises(ValueError, match="control response exceeds"):
        request_json(session, "GET", "/v1/capabilities")
    session.close()

    import opentine.repository.client as client_module

    session = httpx.Client(base_url="https://remote.example", transport=transport)
    monkeypatch.setattr(client_module.httpx, "Client", lambda **kwargs: session)
    with pytest.raises(ValueError, match="control response exceeds"):
        client_module.capabilities("https://remote.example")


@pytest.mark.asyncio
async def test_independent_web_fetch_is_bounded_during_streaming(monkeypatch):
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"x" * 65, request=request)
    )

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=transport, **kwargs)

    monkeypatch.setattr("opentine.tools.web.httpx.AsyncClient", Client)
    monkeypatch.setattr("opentine.tools.web._check_url", lambda url, policy: None)
    with pytest.raises(ValueError, match="max_body_bytes"):
        await web_get("https://remote.example", NetworkPolicy(max_body_bytes=64))


def test_m1_audit_is_keyed_anchored_and_legacy_migration_is_loud(tmp_path: Path):
    path = tmp_path / "audit.sqlite3"
    key = b"audit-secret-outside-the-database"
    db = SQLiteBackend(path, audit_key=key)
    db.append(AuditEvent("e1", "1", "acme", "alice", "read", "ok", {"n": 1}))
    assert db.verify_audit_chain()
    assert Path(str(path) + ".audit-head").is_file()

    with sqlite3.connect(path) as con:
        con.execute("DROP TRIGGER audit_no_update")
        con.execute("UPDATE audit SET details='{}',row_hash=? WHERE event_id='e1'", ("0" * 64,))
    assert db.verify_audit_chain() is False
    with pytest.raises(RuntimeError, match="audit chain verification failed"):
        SQLiteBackend(path, audit_key=key)

    legacy = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy) as con:
        con.execute(
            "CREATE TABLE audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
            "event_id TEXT UNIQUE NOT NULL,timestamp TEXT NOT NULL,tenant TEXT NOT NULL,"
            "actor TEXT NOT NULL,action TEXT NOT NULL,outcome TEXT NOT NULL,details TEXT NOT NULL)"
        )
        con.execute(
            "INSERT INTO audit(event_id,timestamp,tenant,actor,action,outcome,details) "
            "VALUES('old','1','acme','a','read','ok','{}')"
        )
    with pytest.raises(RuntimeError, match="explicit migration"):
        SQLiteBackend(legacy, audit_key=key)
    migrated = SQLiteBackend(legacy, audit_key=key, migrate_legacy_audit=True)
    assert migrated.verify_audit_chain()
    assert migrated.audit_warnings() == ["legacy audit rows were migrated without authenticity"]


def test_m2_upload_locks_are_bounded_and_terminal_errors_are_reaped(tmp_path: Path):
    app = RemoteApp(
        _service(tmp_path / "remote"),
        tmp_path / "state",
        upload_ttl_seconds=0.01,
        max_pending_uploads=8,
    )
    for upload_id in ("not-valid!", *(f"{index:032x}" for index in range(16))):
        status, _ = _wsgi(app, "HEAD", f"/v1/tenants/acme/packs/{upload_id}")
        assert status in {"400 Bad Request", "404 Not Found"}
        assert app._uploads.lock_count() == 0

    declaration = json.dumps({"sha256": hashlib.sha256(b"yes").hexdigest(), "size": 3}).encode()
    status, body = _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    upload_id = json.loads(body)["upload_id"]
    status, _ = _wsgi(
        app,
        "PATCH",
        f"/v1/tenants/acme/packs/{upload_id}",
        b"bad",
        content_type="application/octet-stream",
        upload_offset="0",
    )
    assert status == "400 Bad Request"
    assert not list(app.uploads.rglob(f"{upload_id}.*"))
    assert app._uploads.lock_count() == 0

    status, body = _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    stale = json.loads(body)["upload_id"]
    for path in app.uploads.rglob(f"{stale}.*"):
        os.utime(path, (0, 0))
    _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    assert not list(app.uploads.rglob(f"{stale}.*"))

    orphan = app.uploads / "acme" / ("f" * 32 + ".part")
    orphan.write_bytes(b"orphan")
    os.utime(orphan, (0, 0))
    _wsgi(app, "POST", "/v1/tenants/acme/packs", declaration)
    assert not orphan.exists()

    invalid_size = json.dumps({"sha256": "0" * 64, "size": 1.5}).encode()
    status, _ = _wsgi(app, "POST", "/v1/tenants/acme/packs", invalid_size)
    assert status == "400 Bad Request"


def test_m3_remote_offset_must_advance_and_upload_loop_is_bounded():
    patches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal patches
        if request.method == "POST":
            return httpx.Response(201, json={"offset": 0, "upload_id": "a" * 32})
        patches += 1
        return httpx.Response(409, json={"offset": 0})

    with httpx.Client(
        base_url="https://remote.example", transport=httpx.MockTransport(handler)
    ) as session:
        with pytest.raises(ValueError, match="did not advance"):
            _upload(session, "/packs", b"payload", chunk_size=2)
    assert patches == 1

    transport = httpx.MockTransport(
        lambda request: httpx.Response(201, json={"offset": 0.5, "upload_id": "a" * 32})
    )
    with httpx.Client(base_url="https://remote.example", transport=transport) as session:
        with pytest.raises(ValueError, match="invalid upload offset"):
            _upload(session, "/packs", b"payload", chunk_size=2)


def test_m4_redaction_handles_header_arrays_pairs_and_preserves_prose():
    samples = (
        b'["Authorization: Basic dXNlcjpwYXNz"]',
        b'[["Cookie","sid=secret"]]',
        b'[["x-api-key","opaque-secret"]]',
        b'{"name":"Authorization","value":"Basic dXNlcjpwYXNz"}',
        b'{"value":"sid=secret","name":"Cookie"}',
        b'{"headers":["X-Api-Key: opaque-secret"]}',
    )
    for sample in samples:
        redacted = redact_blob(sample)
        assert not any(
            secret in redacted for secret in (b"dXNlcjpwYXNz", b"sid=secret", b"opaque-secret")
        )
    assert _redact(
        [
            "Authorization: Basic abc",
            ["Cookie", "sid=secret"],
            ["x-api-key", "value"],
            {"name": "Authorization", "value": "Basic abc"},
            {"Name": "X-Api-Key", "Value": "opaque-secret"},
        ]
    ) == [
        "Authorization: [REDACTED]",
        ["Cookie", "[REDACTED]"],
        ["x-api-key", "[REDACTED]"],
        {"name": "Authorization", "value": "[REDACTED]"},
        {"Name": "X-Api-Key", "Value": "[REDACTED]"},
    ]
    assert redact_blob(b"api_key: how do I rotate it") == b"api_key: how do I rotate it"


def test_m5_m6_trace_imports_stringify_bigints_and_skip_bad_jsonl(tmp_path: Path):
    large = 1_234_567_890_123_456_789
    events = jsonl_events(
        [
            json.dumps({"id": "one", "attributes": {"snowflake": large}}),
            '{"truncated":',
            json.dumps({"id": "two", "usage": {"input": large}}),
        ]
    )
    assert len(events) == 2
    assert events[0].attributes["snowflake"] == str(large)
    assert events[1].usage["input"] == str(large)

    framework = framework_events([{"metadata": {"discord_message_id": large}}], "langchain")
    otel = otel_genai_events(
        [
            {
                "traceId": "t",
                "spanId": "s",
                "startTimeUnixNano": "1700000000000000000",
                "attributes": [
                    {
                        "key": "gen_ai.usage.input_tokens",
                        "value": {"intValue": str(large)},
                    }
                ],
            }
        ]
    )
    assert framework[0].attributes["discord_message_id"] == str(large)
    assert otel[0].usage["input"] == str(large)

    overflow = otel_genai_events(
        [{"traceId": "t", "spanId": "overflow", "endTimeUnixNano": "1" * 1000}]
    )
    assert overflow[0].duration == 0

    repo = Repo.init(tmp_path / "repo")
    recorder = Recorder.start(repo, capture=False)
    recorder.import_events([*events, *framework, *otel])
    assert repo.fsck().ok


def test_l1_huge_integer_literal_is_wrapped_as_kernel_error():
    body = b"1" * 5000
    header = b'{"encoding":"json","schema":1,"type":"annotation"}'
    oid = object_id("annotation", 1, body)
    with pytest.raises(KernelError, match="integer literal is too large"):
        ObjectEnvelope.decode(header + b"\n" + body, oid)


def test_independent_pack_audit_rejects_boolean_version_and_invalid_wants(tmp_path: Path):
    body = canonical_json({"objects": [], "shallow": [], "version": True})
    import zlib

    packed = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body)
    with pytest.raises(KernelError, match="unsupported pack"):
        inspect_pack(packed)
    repo = Repo.init(tmp_path / "invalid-wants")
    with pytest.raises(KernelError, match="invalid typed object id"):
        negotiate(repo, ["not-an-object"], [])


def test_l2_v2_migration_uses_the_verified_read(monkeypatch, tmp_path: Path):
    import opentine.repository.runs as runs_module

    source = tmp_path / "source.tine"
    original = (FIXTURES / "golden_v2.tine").read_bytes()
    source.write_bytes(original)
    expected_created = json.loads(original)["created_at"]
    real_read = runs_module._read_v2
    swapped = False

    def read_and_swap(path: Path) -> bytes:
        nonlocal swapped
        raw = real_read(path)
        if path == source and not swapped:
            swapped = True
            changed = json.loads(raw)
            changed["created_at"] = expected_created + 999
            path.write_text(json.dumps(changed), encoding="utf-8")
        return raw

    monkeypatch.setattr(runs_module, "_read_v2", read_and_swap)
    repo = Repo.init(tmp_path / "repo")
    result = repo.migrate_v2(source)
    payload = repo.get(result.run_id).payload()
    assert repo.get(payload["legacy_blob"]).body == original
    assert repo.load_run(result.run_id).created_at == expected_created


def test_l3_ref_write_error_does_not_double_close_transferred_fd(monkeypatch, tmp_path: Path):
    import opentine.repository.store as store_module

    repo = Repo.init(tmp_path)
    old = repo.put("blob", b"old", redact=False)
    new = repo.put("blob", b"new", redact=False)
    repo.update_ref("heads/main", old)
    real_close = store_module.os.close
    opened: list[int] = []
    closes: list[int] = []

    class BrokenFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def write(self, value):
            raise OSError("simulated write failure")

    def broken_fdopen(fd, *args, **kwargs):
        opened.append(fd)
        return BrokenFile()

    monkeypatch.setattr(store_module.os, "fdopen", broken_fdopen)
    monkeypatch.setattr(store_module.os, "close", closes.append)
    with pytest.raises(OSError, match="simulated"):
        repo.update_ref("heads/main", new, expected_old=old)
    assert closes == []
    real_close(opened[0])


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def test_l4_oidc_rejects_signed_but_unsupported_critical_headers():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from opentine.remote._oidc import JWTVerifier, OIDCError

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def integer(value: int) -> str:
        return _b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    verifier = JWTVerifier(
        {"keys": [{"kid": "k", "kty": "RSA", "n": integer(numbers.n), "e": integer(numbers.e)}]},
        issuer="https://issuer.example",
        audience="opentine",
        now=lambda: 100,
    )
    payload = _b64(
        json.dumps({"iss": "https://issuer.example", "aud": "opentine", "exp": 200}).encode()
    )
    for extra in ({"crit": ["custom"], "custom": True}, {"b64": True}):
        header = _b64(json.dumps({"alg": "RS256", "kid": "k", **extra}).encode())
        signature = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
        with pytest.raises(OIDCError, match="critical"):
            verifier(f"{header}.{payload}.{_b64(signature)}")


def test_independent_kernel_audit_rejects_wrong_link_container_types():
    malformed = (
        ("event", {"causal_ids": [], "parent_ids": 1}),
        ("run", {"events": 1, "manifests": {}, "roots": [], "tips": []}),
        ("attestation", {"evidence_ids": 1}),
        ("event", {"causal_ids": [], "parent_ids": 0}),
        ("run", {"events": [], "manifests": 0, "roots": [], "tips": []}),
    )
    for object_type, payload in malformed:
        with pytest.raises(KernelError):
            validate_links(ObjectEnvelope.create(object_type, payload))


def test_independent_kernel_wraps_recursive_values_and_surrogate_keys():
    recursive: list[object] = []
    recursive.append(recursive)
    for value in (recursive, {"\ud800": "value"}):
        with pytest.raises(KernelError):
            canonical_json(value)


def test_independent_fsck_handles_deep_event_graph_without_recursion(tmp_path: Path):
    repo = Repo.init(tmp_path)
    parent = None
    for index in range(1200):
        parent = repo.put(
            "event",
            {
                "causal_ids": [],
                "kind": "model",
                "parent_ids": [parent] if parent else [],
                "span_id": str(index),
            },
        )
    assert repo.fsck().ok


def test_independent_pack_creation_rejects_excessive_object_lists_before_encoding(
    tmp_path: Path,
):
    repo = Repo.init(tmp_path)
    oid = repo.put("blob", b"small", redact=False)
    with pytest.raises(KernelError, match="excessive"):
        create_pack(repo, [oid] * (MAX_PACK_OBJECTS + 1))


def test_independent_ref_validation_excludes_lockfile_aliases(tmp_path: Path):
    repo = Repo.init(tmp_path)
    oid = repo.put("blob", b"value", redact=False)
    for name in ("heads/main.lock", "heads/./main", "heads//main"):
        with pytest.raises(ValueError, match="invalid ref"):
            repo.update_ref(name, oid)


def test_independent_repository_config_is_bounded_and_versioned(tmp_path: Path):
    repo = Repo.init(tmp_path)
    repo.path.joinpath("config.json").write_text('{"format":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="incompatible"):
        Repo.open(tmp_path)


def test_independent_audit_verification_reports_tampering_without_appending(tmp_path: Path):
    index = SQLiteBackend(tmp_path / "audit.sqlite3")
    identities = StaticTokenIdentityProvider({"admin-token": Identity("admin", "acme", ("admin",))})
    service = RemoteService(
        FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"z" * 32)),
        index,
        identities,
        RoleAuthorizationPolicy(),
    )
    admin = service.authenticate({"authorization": "Bearer admin-token"})
    service.list_refs(admin, "acme")
    with sqlite3.connect(index.path) as con:
        con.execute("DROP TRIGGER audit_no_update")
        con.execute("UPDATE audit SET details='{}'")
    result = service.verify_audit_chain(admin, "acme")
    assert result["ok"] is False


def test_independent_trace_sanitizer_handles_cyclic_framework_metadata(tmp_path: Path):
    metadata: dict[str, object] = {}
    metadata["self"] = metadata
    event = framework_events([{"metadata": metadata}], "langchain")[0]
    assert event.attributes["self"] == {"self": "[CIRCULAR]"}
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(event)
    assert repo.fsck().ok

    odd = jsonl_events(
        [json.dumps({"id": "odd", "kind": {"unexpected": True}, "parent_id": ["bad"]})]
    )[0]
    huge_time = framework_events([{"timestamp": 10**400}], "langchain")[0]
    assert isinstance(odd.kind, str) and odd.parent_span_id == "['bad']"
    assert huge_time.timestamp == 0.0
    recorder.append(odd)
    assert repo.fsck().ok


def test_independent_trace_import_preserves_out_of_order_parents_and_multiple_roots(
    tmp_path: Path,
):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    events = [
        TraceEvent("model", 2, "trace", "child", "parent"),
        TraceEvent("model", 1, "trace", "parent"),
        TraceEvent("human", 3, "trace", "independent"),
    ]
    ids = recorder.import_events(events)
    child = repo.get(ids[0]).payload()
    run = recorder.payload
    assert child["parent_ids"] == [ids[1]]
    assert set(run["roots"]) == {ids[1], ids[2]}
    assert repo.fsck().ok


def test_independent_fork_retains_causal_ancestors(tmp_path: Path):
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    ids = recorder.import_events(
        [
            TraceEvent("tool", 1, "trace", "cause"),
            TraceEvent("model", 2, "trace", "effect", causal_span_ids=("cause",)),
        ]
    )
    run = recorder.finalize()
    fork = repo.fork(run, ids[1])
    assert set(repo.get(fork).payload()["events"]) == set(ids)


def test_independent_search_skips_corrupt_run_paths(tmp_path: Path):
    repo = Repo.init(tmp_path)
    corrupt = repo.path / "objects" / "run" / "aa" / ("z" * 62)
    corrupt.parent.mkdir(parents=True)
    corrupt.write_bytes(b"not an object")
    assert search(repo) == []


def test_independent_catalog_and_audit_sidecars_are_bounded(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(catalog_module, "MAX_CATALOG_BYTES", 8)
    catalog = tmp_path / "catalog.json"
    catalog.write_bytes(b"{" + b" " * 8 + b"}")
    with pytest.raises(CatalogError, match="maximum size"):
        PricingCatalog.load(catalog)

    audit = tmp_path / "audit.sqlite3"
    SQLiteBackend(audit)
    Path(str(audit) + ".audit-key").write_bytes(b"k" * 65)
    with pytest.raises(RuntimeError, match="sidecar exceeds"):
        SQLiteBackend(audit)
