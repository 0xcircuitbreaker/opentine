"""0.9.2 remote hardening: JWT type, JWKS rotation, history fetches, admin, ref capacity.

Follow-ups deferred from the 0.9.1 audit fixes. Each test names the way the
server misbehaved before.
"""

from __future__ import annotations

import base64
import json
import math
import os
import sqlite3
import threading
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from opentine import Run, cli
from opentine.graph import StepKind
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
    _admin,
    _admin_graph,
    _association_budget,
    _install_fence,
    _ref_backend,
)
from opentine.remote._admin import RemoteAdmin
from opentine.remote._oidc import JWTVerifier, OIDCError
from opentine.remote.server import reference_app
from opentine.repository import Repo
from opentine.repository import client as repository_client
from opentine.repository import pack as pack_module
from opentine.repository._http import MAX_CONTROL_BYTES

ISSUER = "https://idp.example"
EMPTY_RUN = {"events": [], "manifests": {}, "roots": [], "tips": []}


# --- JWT helpers ---------------------------------------------------------------- #


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _token(key, kid: str, *, typ=None, claims: dict | None = None) -> str:
    header = {"alg": "ES256", "kid": kid}
    if typ is not None:
        header["typ"] = typ
    payload = {"iss": ISSUER, "aud": "tine", "sub": "u1", "exp": time.time() + 300}
    payload.update(claims or {})
    signing = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    r, s = utils.decode_dss_signature(key.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class _IdP:
    """A discovery endpoint whose JWKS the test rotates; counts JWKS fetches."""

    def __init__(self, *keys: tuple[ec.EllipticCurvePrivateKey, str]):
        self.keys = list(keys)
        self.jwks_fetches = 0
        self.fail = False
        self.gate: threading.Event | None = None

    def __call__(self, url: str) -> bytes:
        if url.endswith("/.well-known/openid-configuration"):
            return json.dumps({"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks"}).encode()
        self.jwks_fetches += 1
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail:
            raise httpx.ConnectError("issuer unreachable")
        return json.dumps({"keys": [_jwk(key, kid) for key, kid in self.keys]}).encode()


class _Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


def _discovered(idp: _IdP, clock: _Clock, **kwargs) -> JWTVerifier:
    return JWTVerifier.from_discovery(ISSUER, "tine", idp, clock=clock, **kwargs)


# --- 1. JWT typ ------------------------------------------------------------------ #


@pytest.mark.parametrize("typ", [None, "JWT", "jwt", "at+jwt", "AT+JWT", "application/at+jwt"])
def test_access_and_id_token_types_are_accepted(typ):
    key = ec.generate_private_key(ec.SECP256R1())
    verifier = JWTVerifier({"keys": [_jwk(key, "k1")]}, issuer=ISSUER, audience="tine")
    assert verifier(_token(key, "k1", typ=typ))["sub"] == "u1"


@pytest.mark.parametrize(
    "typ", ["dpop+jwt", "logout+jwt", "secevent+jwt", "application/jwk+json", "", 1, ["JWT"]]
)
def test_other_jwt_types_signed_by_the_issuer_are_not_bearer_tokens(typ):
    key = ec.generate_private_key(ec.SECP256R1())
    verifier = JWTVerifier({"keys": [_jwk(key, "k1")]}, issuer=ISSUER, audience="tine")
    with pytest.raises(OIDCError, match="JWT type"):
        verifier(_token(key, "k1", typ=typ))


# --- 2. JWKS refresh and rotation ------------------------------------------------- #


def test_a_key_rotated_in_is_fetched_on_its_first_token():
    old, new = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    idp, clock = _IdP((old, "k1")), _Clock()
    verifier = _discovered(idp, clock)
    idp.keys.append((new, "k2"))
    clock.value += 61
    # Before 0.9.2 the JWKS was fetched once at startup: k2 failed until a restart.
    assert verifier(_token(new, "k2"))["sub"] == "u1"
    assert idp.jwks_fetches == 2


def test_unknown_kid_refetches_are_rate_limited():
    key = ec.generate_private_key(ec.SECP256R1())
    idp, clock = _IdP((key, "k1")), _Clock()
    verifier = _discovered(idp, clock, refresh_interval=60)
    clock.value += 61
    for attempt in range(20):
        with pytest.raises(OIDCError, match="no JWKS key"):
            verifier(_token(key, f"made-up-{attempt}"))
    assert idp.jwks_fetches == 2  # startup + one refetch, not one per token
    clock.value += 61
    with pytest.raises(OIDCError):
        verifier(_token(key, "made-up-again"))
    assert idp.jwks_fetches == 3


def test_a_key_rotated_out_stops_verifying_after_the_maximum_age():
    leaked, current = (
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP256R1()),
    )
    idp, clock = _IdP((leaked, "k1")), _Clock()
    verifier = _discovered(idp, clock, max_key_age=3600)
    idp.keys = [(current, "k2")]  # the issuer revokes k1
    clock.value += 600
    assert verifier(_token(leaked, "k1"))["sub"] == "u1"  # cached, within max age
    clock.value += 3600
    # Before 0.9.2 a revoked key verified for as long as the server ran.
    with pytest.raises(OIDCError, match="no JWKS key"):
        verifier(_token(leaked, "k1"))
    assert verifier(_token(current, "k2"))["sub"] == "u1"


def test_a_failed_refetch_keeps_keys_until_the_maximum_age_then_fails_closed():
    key = ec.generate_private_key(ec.SECP256R1())
    idp, clock = _IdP((key, "k1")), _Clock()
    verifier = _discovered(idp, clock, max_key_age=3600)
    idp.fail = True
    clock.value += 120
    with pytest.raises(OIDCError, match="no JWKS key"):
        verifier(_token(key, "unknown"))  # triggers a refetch that fails
    assert verifier(_token(key, "k1"))["sub"] == "u1"  # old keys still served
    clock.value += 3600
    with pytest.raises(OIDCError, match="maximum age"):
        verifier(_token(key, "k1"))
    idp.fail = False
    clock.value += 61
    assert verifier(_token(key, "k1"))["sub"] == "u1"  # recovers on the next refetch


def test_a_malformed_refetched_jwks_is_a_failed_refetch():
    key = ec.generate_private_key(ec.SECP256R1())
    idp, clock = _IdP((key, "k1")), _Clock()
    verifier = _discovered(idp, clock)
    idp.keys = []  # an empty key set is refused, not installed
    clock.value += 3601
    with pytest.raises(OIDCError, match="maximum age"):
        verifier(_token(key, "k1"))


def test_a_static_jwks_is_the_operators_pin_and_never_expires():
    key = ec.generate_private_key(ec.SECP256R1())
    clock = _Clock()
    verifier = JWTVerifier({"keys": [_jwk(key, "k1")]}, issuer=ISSUER, audience="tine", clock=clock)
    clock.value += 10 * 365 * 86400
    assert verifier(_token(key, "k1"))["sub"] == "u1"


def test_concurrent_unknown_kids_share_one_refetch():
    key = ec.generate_private_key(ec.SECP256R1())
    idp, clock = _IdP((key, "k1")), _Clock()
    verifier = _discovered(idp, clock)
    clock.value += 61
    idp.gate = threading.Event()
    errors: list[Exception] = []

    def attempt(index: int) -> None:
        try:
            verifier(_token(key, f"unknown-{index}"))
        except OIDCError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attempt, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    idp.gate.set()
    for thread in threads:
        thread.join(10)
    assert len(errors) == 8
    assert idp.jwks_fetches == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"refresh_interval": 0},
        {"max_key_age": float("inf")},
        {"refresh_interval": 120, "max_key_age": 60},
        {"refresh_interval": True},
    ],
)
def test_refresh_settings_are_validated(kwargs):
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(OIDCError, match="refresh interval"):
        JWTVerifier({"keys": [_jwk(key, "k1")]}, issuer=ISSUER, audience="tine", **kwargs)


# --- 4. Associations can no longer make a history unfetchable --------------------- #


def _service(tmp_path: Path):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    backend = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider(
        {
            "writer-token": Identity("writer", "acme", ("writer",)),
            "reader-token": Identity("reader", "acme", ("reader",)),
        }
    )
    service = RemoteService(objects, backend, identities, RoleAuthorizationPolicy())
    writer = service.authenticate({"authorization": "Bearer writer-token"})
    reader = service.authenticate({"authorization": "Bearer reader-token"})
    return service, backend, writer, reader


def _flooded_history(tmp_path: Path, monkeypatch, runs: int = 3, attestations: int = 6):
    """Scaled down: a 20-object pack budget, three runs of one annotation + six attestations.

    Structure is 3 objects; associations are 21, so the third run's do not fit.
    At full scale this is ten runs each at the 1000-association cap.
    """
    monkeypatch.setattr(_association_budget, "MAX_ASSOCIATIONS_PER_TARGET", 10)
    service, backend, writer, reader = _service(tmp_path / "remote")
    local = Repo.init(tmp_path / "local")
    run_ids, notes = [], {}
    for index in range(runs):
        run = local.put("run", {**EMPTY_RUN, "label": f"run-{index}"})
        notes[run] = local.put(
            "annotation", {"previous_id": None, "target_id": run, "value": {"tags": ["t"]}}
        )
        for number in range(attestations):
            local.attest(run, {"n": number}, signer="mallory")
        run_ids.append(run)
    service.install_pack(writer, "acme", local.pack())
    monkeypatch.setattr(pack_module, "MAX_PACK_OBJECTS", 20)
    return service, writer, reader, local, run_ids, notes


def test_a_flooded_history_still_fetches_with_the_overflow_reported(tmp_path, monkeypatch):
    service, _, reader, _, runs, notes = _flooded_history(tmp_path, monkeypatch)
    omitted: list[str] = []
    # Before 0.9.2 this raised: the third run's association lookup exceeded the budget.
    pack = service.fetch_pack(reader, "acme", runs, [], omitted=omitted)
    assert omitted == [runs[2]]
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(pack)
    assert all(clone.has(run) for run in runs)
    # The run left short keeps its metadata: annotations go before attestations.
    assert all(clone.has(note) for note in notes.values())
    assert len(clone.attestations_for(runs[0])) == 6
    assert not clone.attestations_for(runs[2])


def test_a_large_run_cannot_be_bricked_by_attestations(tmp_path, monkeypatch):
    monkeypatch.setattr(pack_module, "MAX_PACK_OBJECTS", 20)
    local = Repo.init(tmp_path / "local")
    source = Run(id="big")
    for index in range(8):
        source.add_step(StepKind.done, {"text": f"step {index}"})
    run = local.put_run(source).run_id
    structure = len(pack_module.reachable(local, [run], include_associated=False))
    for number in range(20 - structure + 1):
        local.attest(run, {"n": number}, signer="mallory")
    omitted: list[str] = []
    found = pack_module.reachable(local, [run], omitted=omitted)
    assert omitted == [run]
    assert len(found) <= 20
    assert not any(oid.startswith("attestation:") for oid in found)


def test_associations_that_fit_are_all_included_and_nothing_is_reported(tmp_path, monkeypatch):
    service, _, reader, _, runs, _ = _flooded_history(tmp_path, monkeypatch, runs=2)
    omitted: list[str] = []
    pack = service.fetch_pack(reader, "acme", runs, [], omitted=omitted)
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(pack)
    assert omitted == []
    assert all(len(clone.attestations_for(run)) == 6 for run in runs)


def test_the_fetch_audit_and_response_header_report_the_omission(tmp_path, monkeypatch):
    service, _, _, _, runs, _ = _flooded_history(tmp_path, monkeypatch)
    app = RemoteApp(service, tmp_path / "state")
    headers: list[tuple[str, str]] = []
    body = json.dumps({"wants": runs, "haves": []}).encode()
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/tenants/acme/fetch",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_AUTHORIZATION": "Bearer reader-token",
        "wsgi.input": __import__("io").BytesIO(body),
    }
    app(environ, lambda status, response_headers: headers.extend(response_headers))
    assert ("Opentine-Associations-Omitted", "1") in headers
    with service.index._connect() as database:
        details = database.execute(
            "SELECT details FROM audit WHERE action='fetch' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0]
    assert json.loads(details)["associations_omitted"] == 1


def test_the_client_reports_omitted_associations_and_old_servers_report_none(tmp_path, monkeypatch):
    service, _, _, _, runs, _ = _flooded_history(tmp_path, monkeypatch)
    app = RemoteApp(service, tmp_path / "state")
    transport = httpx.WSGITransport(app=app)

    def session(*_args, **_kwargs):
        return httpx.Client(
            transport=transport,
            base_url="https://remote.example",
            headers={"authorization": "Bearer reader-token"},
        )

    monkeypatch.setattr(repository_client, "_client", session)
    clone = Repo.init(tmp_path / "clone")
    result = repository_client.fetch(clone, "https://remote.example", tenant="acme", wants=runs)
    assert result.associations_omitted == 1
    assert repository_client._omitted({}) == 0  # a pre-0.9.2 server sends no header
    assert repository_client._omitted({"opentine-associations-omitted": "lots"}) == 0


# --- 3. Offline admin: delete refs and objects, purge ----------------------------- #


KEY = b"k" * 32


def _reference(tmp_path: Path, retention=None):
    """A ``tine serve --root`` layout, the service on it, and the operator's admin."""
    root = tmp_path / "remote-root"
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("writer", "acme", ("writer",))}
    )
    app = reference_app(root, identities=identities, keys=LocalKeyProvider(KEY))
    if retention is not None:
        app.service.objects.retention = retention
    writer = app.service.authenticate({"authorization": "Bearer writer-token"})
    admin = RemoteAdmin.open(root, keys=LocalKeyProvider(KEY))
    admin.objects.retention = retention
    return root, app, app.service, writer, admin


def _push_run(service, writer, local: Repo, label: str, ref: str | None, attestations=0):
    source = Run(id=label, metadata={"label": label})
    source.add_step(StepKind.done, {"text": f"{label} output"})
    stored = local.put_run(source)
    signed = [local.attest(stored.run_id, {"n": n}, signer="ci") for n in range(attestations)]
    service.install_pack(writer, "acme", local.pack())
    if ref:
        assert service.update_ref(writer, "acme", ref, stored.run_id, None)
    return stored, signed


def _audit_actions(index) -> list[tuple[str, str, str]]:
    with index._connect() as database:
        return database.execute(
            "SELECT actor,action,outcome FROM audit WHERE action LIKE 'admin_%' ORDER BY sequence"
        ).fetchall()


def _fetch(service, writer, oid: str, tmp_path: Path, name: str) -> Repo:
    clone = Repo.init(tmp_path / name)
    clone.import_pack(service.fetch_pack(writer, "acme", [oid], []))
    return clone


def test_delete_ref_is_compare_and_swap_and_audited(tmp_path):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    first, _ = _push_run(service, writer, local, "first", "heads/main")
    other = "run:sha256:" + "0" * 64
    assert admin.delete_ref("acme", "heads/main", expected=other) is False
    assert admin.delete_ref("acme", "heads/main", expected=first.run_id) is True
    assert admin.delete_ref("acme", "heads/main") is False  # already gone
    assert "heads/main" not in service.index.list_refs("acme")
    actions = _audit_actions(service.index)
    assert [row[1:] for row in actions] == [
        ("admin_delete_ref", "conflict"),
        ("admin_delete_ref", "ok"),
        ("admin_delete_ref", "conflict"),
    ]
    assert all(actor.startswith("operator") for actor, _, _ in actions)
    assert service.index.verify_audit_chain()


def test_delete_ref_recovers_a_tenant_whose_listing_is_refused(tmp_path):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    stored, _ = _push_run(service, writer, local, "first", "heads/main")
    wrong = "annotations/" + "f" * 64  # names a run this annotation does not target
    with sqlite3.connect(service.index.path) as database:  # planted past update_ref
        database.execute(
            "INSERT INTO refs(tenant,name,oid) VALUES('acme',?,?)", (wrong, stored.annotation_id)
        )
    with pytest.raises(ValueError):
        service.list_refs(writer, "acme")  # every fetch, clone and push starts here
    assert admin.refs("acme")[wrong] == stored.annotation_id
    assert admin.delete_ref("acme", wrong, expected=stored.annotation_id)
    assert service.list_refs(writer, "acme") == {"heads/main": stored.run_id}


def test_purge_removes_what_no_ref_reaches_and_keeps_what_one_does(tmp_path):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    kept, kept_signed = _push_run(service, writer, local, "kept", "heads/main", attestations=2)
    gone, gone_signed = _push_run(service, writer, local, "gone", "heads/gone", attestations=2)
    gone_objects = set(pack_module.reachable(local, [gone.run_id])) - set(
        pack_module.reachable(local, [kept.run_id])
    )
    assert admin.delete_ref("acme", "heads/gone", expected=gone.run_id)

    preview = admin.purge("acme", grace_seconds=0, dry_run=True)
    assert set(preview.removed) == gone_objects
    assert all(service.objects.has("acme", oid) for oid in gone_objects)

    result = admin.purge("acme", grace_seconds=0)
    assert set(result.removed) == gone_objects
    assert not any(service.objects.has("acme", oid) for oid in gone_objects)
    assert not service.index.associated_objects("acme", gone.run_id, 10)
    clone = _fetch(service, writer, kept.run_id, tmp_path, "clone")
    assert set(clone.attestations_for(kept.run_id)) == set(kept_signed)
    assert clone.load_run(kept.run_id).metadata["label"] == "kept"
    assert [row[1:] for row in _audit_actions(service.index)][-3:] == [
        ("admin_purge", "dry-run"),
        ("admin_purge", "started"),
        ("admin_purge", "ok"),
    ]


def test_purge_grace_window_keeps_a_push_waiting_for_its_ref(tmp_path):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    pending, _ = _push_run(service, writer, local, "pending", None)  # installed, no ref yet
    result = admin.purge("acme", grace_seconds=3600)
    assert result.removed == () and result.deferred > 0
    assert service.update_ref(writer, "acme", "heads/main", pending.run_id, None)

    orphan, _ = _push_run(service, writer, Repo.init(tmp_path / "other"), "orphan", None)
    old = time.time() - 7200
    for oid in service.objects.list("acme"):
        os.utime(service.objects._path("acme", oid), (old, old))
    result = admin.purge("acme", grace_seconds=3600)
    assert orphan.run_id in result.removed
    assert service.objects.has("acme", pending.run_id)


def test_purge_keeps_an_object_a_ref_gains_while_it_runs(tmp_path, monkeypatch):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    late, _ = _push_run(service, writer, local, "late", None)
    original = _admin_graph.ObjectGraph.live
    calls: list[int] = []

    def push_after_the_snapshot(graph, roots, excluded=frozenset()):
        if not calls:  # purge has read the refs and is about to pick candidates
            assert service.update_ref(writer, "acme", "heads/late", late.run_id, None)
        calls.append(1)
        return original(graph, roots, excluded)

    monkeypatch.setattr(_admin_graph.ObjectGraph, "live", push_after_the_snapshot)
    result = admin.purge("acme", grace_seconds=0)
    assert late.run_id not in result.removed  # the batch re-read the refs
    assert result.deferred == 0
    _fetch(service, writer, late.run_id, tmp_path, "clone")


def _orphaned_and_aged(tmp_path: Path):
    """A pushed run whose ref the operator deleted, every object past the grace window."""
    root, app, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    orphan, _ = _push_run(service, writer, local, "orphan", "heads/orphan")
    assert admin.delete_ref("acme", "heads/orphan", expected=orphan.run_id)
    old = time.time() - 7200
    for oid in service.objects.list("acme"):
        os.utime(service.objects._path("acme", oid), (old, old))
    return service, writer, admin, local, orphan


def _purge_mid_install(service, admin, monkeypatch) -> None:
    """Run a whole purge right after the install's first object write."""
    original = service.objects.put
    calls: list[str] = []

    def put(tenant, oid, raw):
        original(tenant, oid, raw)  # already stored: skipped, as for any re-push
        if not calls:
            calls.append(oid)
            admin.purge("acme", grace_seconds=3600)

    monkeypatch.setattr(service.objects, "put", put)


def test_a_purge_landing_inside_an_install_cannot_break_the_pushed_run(tmp_path, monkeypatch):
    service, writer, admin, local, orphan = _orphaned_and_aged(tmp_path)
    _purge_mid_install(service, admin, monkeypatch)
    service.install_pack(writer, "acme", local.pack())  # the run is pushed again
    assert service.update_ref(writer, "acme", "heads/main", orphan.run_id, None)
    wanted = pack_module.reachable(local, [orphan.run_id])
    assert all(service.objects.has("acme", oid) for oid in wanted)
    clone = _fetch(service, writer, orphan.run_id, tmp_path, "clone")
    assert clone.load_run(orphan.run_id).metadata["label"] == "orphan"


def test_without_the_install_fence_that_purge_breaks_the_run(tmp_path, monkeypatch):
    # Negative control: the scenario above is a real race, and the fence closes it.
    service, writer, admin, local, orphan = _orphaned_and_aged(tmp_path)
    _purge_mid_install(service, admin, monkeypatch)
    monkeypatch.setattr(_install_fence, "fence_install", lambda *args: None)
    service.install_pack(writer, "acme", local.pack())  # reports success
    wanted = pack_module.reachable(local, [orphan.run_id])
    assert not all(service.objects.has("acme", oid) for oid in wanted)


@pytest.mark.parametrize("age_check", [True, False], ids=["in-lock-age", "scan-age-only"])
def test_purge_keeps_what_an_install_fenced_after_its_scan(tmp_path, monkeypatch, age_check):
    service, writer, admin, local, orphan = _orphaned_and_aged(tmp_path)
    scanned = _admin.scan

    def install_after_the_scan(*args):
        graph = scanned(*args)
        service.install_pack(writer, "acme", local.pack())  # fenced: every object refreshed
        return graph

    monkeypatch.setattr(_admin, "scan", install_after_the_scan)
    if not age_check:  # negative control: the age read at scan time alone
        monkeypatch.setattr(RemoteAdmin, "_age", lambda self, tenant, oid, now: math.inf)
    result = admin.purge("acme", grace_seconds=3600)
    if not age_check:
        assert orphan.run_id in result.removed
        return
    assert result.removed == ()
    assert service.update_ref(writer, "acme", "heads/main", orphan.run_id, None)
    _fetch(service, writer, orphan.run_id, tmp_path, "clone")


def test_delete_objects_clears_an_attestation_flood_but_never_a_linked_object(tmp_path):
    _, _, service, writer, admin = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    stored, flood = _push_run(service, writer, local, "victim", "heads/main", attestations=5)
    listed = admin.associations("acme", stored.run_id)
    assert {row["oid"] for row in listed} == {stored.annotation_id, *flood}

    preview = admin.delete_objects("acme", flood, dry_run=True)
    assert set(preview.removed) == set(flood)
    assert all(service.objects.has("acme", oid) for oid in flood)
    result = admin.delete_objects("acme", flood)
    assert set(result.removed) == set(flood)
    clone = _fetch(service, writer, stored.run_id, tmp_path, "clone")
    assert not clone.attestations_for(stored.run_id)
    assert clone.load_run(stored.run_id).metadata["label"] == "victim"

    with pytest.raises(ValueError, match="a ref names"):
        admin.delete_objects("acme", [stored.run_id])
    event = next(oid for oid in local.iter_oids() if oid.startswith("event:"))
    with pytest.raises(ValueError, match="still linked"):
        admin.delete_objects("acme", [event])
    with pytest.raises(KeyError):
        admin.delete_objects("acme", ["blob:sha256:" + "0" * 64])
    outcomes = [row[1:] for row in _audit_actions(service.index)]
    assert ("admin_delete_objects", "refused") in outcomes
    assert service.objects.has("acme", stored.run_id) and service.objects.has("acme", event)


def test_a_retention_veto_is_reported_and_the_object_kept(tmp_path):
    class Retention:
        def retain_until(self, tenant, oid):
            return "2099-01-01"

        def before_delete(self, tenant, oid):
            raise PermissionError("retained")

    _, _, service, writer, admin = _reference(tmp_path, Retention())
    local = Repo.init(tmp_path / "local")
    stored, _ = _push_run(service, writer, local, "held", None)
    result = admin.purge("acme", grace_seconds=0)
    assert result.removed == () and stored.run_id in result.retained
    assert service.objects.has("acme", stored.run_id)


def test_no_admin_operation_is_reachable_over_http(tmp_path):
    _, app, _, _, _ = _reference(tmp_path)
    for method, path in (
        ("DELETE", "/v1/tenants/acme/refs/heads/main"),
        ("POST", "/v1/tenants/acme/purge"),
        ("POST", "/v1/tenants/acme/admin/purge"),
    ):
        statuses: list[str] = []
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "HTTP_AUTHORIZATION": "Bearer writer-token",
            "wsgi.input": __import__("io").BytesIO(b""),
        }
        app(environ, lambda status, headers: statuses.append(status))
        assert statuses == ["404 Not Found"]


def test_tine_serve_admin_actions_run_offline(tmp_path, monkeypatch, capsys):
    root, _, service, writer, _ = _reference(tmp_path)
    local = Repo.init(tmp_path / "local")
    stored, _ = _push_run(service, writer, local, "cli", "heads/main")
    monkeypatch.setenv("TINE_KMS_KEY", base64.b64encode(KEY).decode())
    monkeypatch.delenv("TINE_REMOTE_TOKEN", raising=False)  # no server is started

    cli.main(["serve", "--root", str(root), "--tenant", "acme", "refs"])
    assert json.loads(capsys.readouterr().out)["refs"]["heads/main"] == stored.run_id
    cli.main(["serve", "purge", "--root", str(root), "--tenant", "acme", "--dry-run"])
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    with pytest.raises(SystemExit) as refused:
        cli.main(
            ["serve", "--root", str(root), "--tenant", "acme", "delete-ref", "heads/main",
             "--expect", "run:sha256:" + "0" * 64]
        )  # fmt: skip
    assert refused.value.code == 1
    assert json.loads(capsys.readouterr().out)["deleted"] is False
    cli.main(["serve", "--root", str(root), "--tenant", "acme", "delete-ref", "heads/main"])
    assert json.loads(capsys.readouterr().out)["deleted"] is True
    with pytest.raises(SystemExit):
        cli.main(["serve", "--root", str(tmp_path / "nowhere"), "refs"])


# --- 5. A tenant is no longer capped at a thousand refs ---------------------------- #


def test_a_tenant_holds_well_over_a_thousand_annotated_runs(tmp_path):
    backend = SQLiteBackend(tmp_path / "refs.sqlite3", audit_key=b"a" * 32)
    rows = [
        (f"annotations/{index:064x}", "annotation:sha256:" + f"{index:064x}")
        for index in range(1500)
    ]
    with sqlite3.connect(backend.path) as database:
        database.executemany("INSERT INTO refs(tenant,name,oid) VALUES('acme',?,?)", rows)
    # Before 0.9.2 the 1001st ref -- about the thousandth pushed run -- was refused.
    assert backend.update_ref("acme", "heads/main", "run:sha256:" + "1" * 64, None)
    assert len(backend.list_refs("acme")) == 1501


def test_the_ref_listing_stays_readable_by_every_client(tmp_path, monkeypatch):
    # The byte bound plus JSON framing fits the 1 MiB clients accept for any names.
    worst = {}
    remaining = _ref_backend.MAX_REF_LISTING_BYTES
    oid = "attestation:sha256:" + "a" * 64
    index = 0
    while remaining >= 6 + len(oid) + 1:
        name = f"tags/{index:x}".ljust(min(512, remaining - 6 - len(oid)), "x")
        worst[name] = oid
        remaining -= len(name) + len(oid) + 6
        index += 1
    body = json.dumps({"refs": worst}, sort_keys=True, separators=(",", ":")).encode()
    assert len(body) <= MAX_CONTROL_BYTES

    monkeypatch.setattr(_ref_backend, "MAX_REF_LISTING_BYTES", 400)
    backend = SQLiteBackend(tmp_path / "bytes.sqlite3", audit_key=b"a" * 32)
    run = "run:sha256:" + "1" * 64
    assert backend.update_ref("acme", "heads/" + "a" * 200, run, None)
    with pytest.raises(ValueError, match="byte limit"):
        backend.update_ref("acme", "heads/" + "b" * 200, run, None)
    # Moving an existing ref is measured as a replacement, not an addition.
    assert backend.update_ref("acme", "heads/" + "a" * 200, "run:sha256:" + "2" * 64, run)


def test_the_ref_count_bound_still_holds(tmp_path, monkeypatch):
    monkeypatch.setattr(_ref_backend, "MAX_TENANT_REFS", 2)
    backend = SQLiteBackend(tmp_path / "count.sqlite3", audit_key=b"a" * 32)
    run = "run:sha256:" + "1" * 64
    assert backend.update_ref("acme", "heads/one", run, None)
    assert backend.update_ref("acme", "heads/two", run, None)
    with pytest.raises(ValueError, match="ref count"):
        backend.update_ref("acme", "heads/three", run, None)


# --- 4b. Two concurrent installs cannot overshoot a target's association budget ---- #


def test_concurrent_installs_cannot_overshoot_the_association_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(_association_budget, "MAX_ASSOCIATIONS_PER_TARGET", 3)
    service, _, writer, reader = _service(tmp_path / "remote")
    local = Repo.init(tmp_path / "local")
    run = local.put("run", EMPTY_RUN)
    service.install_pack(writer, "acme", local.pack([run]))
    packs = [
        local.pack([local.attest(run, {"batch": batch, "n": n}, signer="x") for n in range(2)])
        for batch in range(2)
    ]
    real = _association_budget.check_association_budget

    def slow_check(*args):
        real(*args)
        time.sleep(0.2)  # both installs would be past the check before either records

    monkeypatch.setattr(_association_budget, "check_association_budget", slow_check)
    outcomes: list[str] = []

    def install(data: bytes) -> None:
        try:
            service.install_pack(writer, "acme", data)
            outcomes.append("ok")
        except ValueError:
            outcomes.append("refused")

    threads = [threading.Thread(target=install, args=(data,)) for data in packs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    # Before 0.9.2 both passed against a count of zero: four associations, cap three.
    assert sorted(outcomes) == ["ok", "refused"]
    assert len(service.index.associated_objects("acme", run, 10)) == 2
