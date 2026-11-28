"""0.90 role-scoped ``tine serve`` tokens: ingest-only, verdict-only and approve-only."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _review, _schemas, cli
from opentine.remote._token_store import TokenStore
from tests._auth_helpers import call, local_run, make_app, push

T = "/v1/tenants/acme"


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path / "remote")


def role_token(app, role, refs, agent="", tenant="acme", ttl=3600):
    return app.tokens.mint(tenant, "write", refs, ttl=ttl, role=role, agent=agent)


def _upload(app, tmp_path, label, token):
    run_id, pack = local_run(tmp_path, label)
    status = call(app, "POST", T + "/packs", raw=pack, token=token,
                  content_type="application/vnd.opentine.pack")[0]  # fmt: skip
    return run_id, status


def _put_ref(app, name, oid, token, old=None):
    body = {"new": oid, "expected_old": old}
    return call(app, "PUT", f"{T}/refs/{quote(name, safe='')}", body, token)[0]


def _routes(oid):
    q = quote(oid, safe="")
    return [
        ("GET", T + "/refs", None), ("GET", T + "/list/refs", None),
        ("GET", T + "/list/runs", None), ("POST", T + "/search", {}),
        ("POST", T + "/fetch", {"wants": [oid]}), ("POST", T + "/negotiate", {"wants": [oid]}),
        ("GET", f"{T}/objects/{q}", None), ("GET", T + "/events", None),
        ("GET", T + "/webhooks", None), ("GET", T + "/shares", None),
        ("POST", T + "/shares", {"run": oid}), ("GET", T + "/tokens", None),
        ("POST", T + "/tokens", {"access": "read", "refs": ["*"]}),
        ("GET", T + "/usage", None), ("GET", T + "/audit/verify", None),
        ("GET", T + "/admin/stats", None), ("PUT", f"{T}/tombstones/{q}", {}),
        ("POST", T + "/coord/tasks", {"task": "t1"}), ("PUT", T + "/project", {}),
        ("PUT", T + "/reviews/r1", {"expected_old": None, "version": {}}),
        ("POST", T + "/reviews/r1/decisions", {"decision": {}}),
        ("POST", T + "/import", {}),
    ]  # fmt: skip


def test_mint_rules_for_roles(tmp_path):
    store = TokenStore(tmp_path / "auth.sqlite3")
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], role="ingest")  # names its namespaces
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], role="verdict")
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], role="approve")  # needs an agent id
    with pytest.raises(ValueError):
        store.mint("acme", "read", ["heads/ci/"], role="ingest")  # roles are write tokens
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["heads/ci/"], role="admin")
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], agent="a")  # an agent without a role
    with pytest.raises(ValueError):
        store.mint("acme", "write", ["*"], role="approve", agent="x\n")
    _, record = store.mint("acme", "write", ["*"], role="approve", agent="agent-1")
    assert (record["role"], record["agent"]) == ("approve", "agent-1")
    assert "role" not in store.mint("acme", "read", ["*"])[1]


def test_a_root_minted_before_roles_gains_the_columns(tmp_path):
    path = tmp_path / "auth.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        db.executescript(
            "CREATE TABLE tokens (id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest BLOB NOT NULL,"
            " tenant TEXT NOT NULL, access TEXT NOT NULL, refs TEXT NOT NULL, label TEXT NOT NULL,"
            " subject TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, revoked REAL);"
        )
    store = TokenStore(path)
    secret, record = store.mint("acme", "write", ["heads/in/"], role="ingest")
    assert store.identity(secret).claims["opentine_scope"]["role"] == "ingest"


def test_an_ingest_token_writes_inside_its_namespace_and_reads_nothing(app, tmp_path):
    secret, _ = role_token(app, "ingest", ["heads/in/"], agent="collector")
    run_id, status = _upload(app, tmp_path, "ingested", secret)
    assert status == 201
    assert _put_ref(app, "heads/in/one", run_id, secret) == 200
    assert _put_ref(app, "heads/main", run_id, secret) in (403, 404)
    assert _put_ref(app, "heads/inx", run_id, secret) in (403, 404)  # prefix confusion
    txn = {"updates": [{"name": "heads/in/two", "new": run_id, "expected_old": None},
                       {"name": "heads/main", "new": run_id, "expected_old": None}]}  # fmt: skip
    assert call(app, "POST", T + "/ref-txn", txn, secret)[0] in (403, 404)
    assert set(app.service.index.list_refs("acme")) == {"heads/in/one"}
    for method, path, body in _routes(run_id):
        status = call(app, method, path, body, secret)[0]
        assert status in (403, 404), (method, path, status)
    assert call(app, "GET", "/v1/capabilities", token=secret)[0] == 200


def test_a_verdict_token_reads_and_writes_only_inside_its_namespaces(app, tmp_path):
    judged = push(app, tmp_path, "judged", "heads/agents/a")
    hidden = push(app, tmp_path, "hidden", "heads/main")
    secret, _ = role_token(app, "verdict", ["heads/agents/", "heads/monitors/"], agent="mon-1")
    status, _, body = call(app, "GET", T + "/refs", token=secret)
    assert status == 200 and json.loads(body)["refs"] == {"heads/agents/a": judged}
    assert call(app, "POST", T + "/fetch", {"wants": [judged]}, secret)[0] == 200
    assert call(app, "POST", T + "/fetch", {"wants": [hidden]}, secret)[0] == 404
    verdict, status = _upload(app, tmp_path, "verdict", secret)
    assert status == 201
    assert _put_ref(app, "heads/monitors/mon-1/v1", verdict, secret) == 200
    assert _put_ref(app, "heads/main", verdict, secret, old=hidden) in (403, 404)
    allowed = {("GET", T + "/refs"), ("POST", T + "/fetch"), ("POST", T + "/negotiate")}
    for method, path, body in _routes(judged):
        if (method, path) in allowed:
            continue
        status = call(app, method, path, body, secret)[0]
        assert status in (403, 404), (method, path, status)


def _key():
    key = Ed25519PrivateKey.generate()
    return key, key.public_key().public_bytes_raw().hex()


def _review_of(app, run_id, key, pub, review_id="rv"):
    version = _review.sign(
        _review.build(review_id, title="t", reviewers=[pub],
                      repos=[{"name": "acme", "project": None}],
                      subjects=[{"repo": "acme", "type": "run", "id": run_id}], gates=["ship"]),
        key,
    )  # fmt: skip
    put = {"expected_old": None, "version": version}
    assert call(app, "PUT", f"{T}/reviews/{review_id}", put)[0] == 200
    return version


def _decide(app, version, key, token, decision="approve"):
    record = _review.sign_gate(_review.build_gate(version, "ship", decision), key)
    path = f"{T}/reviews/{version['review_id']}/decisions"
    return call(app, "POST", path, {"decision": record}, token)


def test_an_approve_token_decides_but_never_writes_and_never_self_approves(app, tmp_path):
    key, pub = _key()
    approver, _ = role_token(app, "approve", ["*"], agent="agent-7")
    ingest, _ = role_token(app, "ingest", ["heads/agent-7/"], agent="agent-7")
    own, status = _upload(app, tmp_path, "own", ingest)
    assert status == 201 and _put_ref(app, "heads/agent-7/x", own, ingest) == 200
    other = push(app, tmp_path, "other", "heads/main")
    mine = _review_of(app, own, key, pub, "mine")
    theirs = _review_of(app, other, key, pub, "theirs")
    refused = _decide(app, mine, key, approver)
    assert refused[0] == 403 and json.loads(refused[2])["code"] == "token.self-approval"
    assert _decide(app, mine, key, approver, "reject")[0] == 201  # rejecting is no conflict
    assert _decide(app, theirs, key, approver)[0] == 201
    assert call(app, "GET", f"{T}/reviews/theirs", token=approver)[0] == 200
    assert _put_ref(app, "heads/main", own, approver, old=other) in (403, 404)
    put = {"expected_old": _review.digest(theirs), "version": theirs}
    assert call(app, "PUT", f"{T}/reviews/theirs", put, approver)[0] in (403, 404)
    _, status = _upload(app, tmp_path, "sneak", approver)
    assert status in (403, 404)
    writes = {"POST", "PUT", "DELETE"}
    for method, path, body in _routes(other):
        if method in writes and not path.endswith(("/decisions", "/fetch", "/negotiate")):
            status = call(app, method, path, body, approver)[0]
            assert status in (403, 404), (method, path, status)
    for path in ("/webhooks", "/tokens", "/shares", "/audit/verify", "/admin/stats"):
        assert call(app, "GET", T + path, token=approver)[0] in (403, 404), path


def test_a_run_the_tenant_does_not_hold_cannot_be_self_checked(app, tmp_path):
    key, pub = _key()
    approver, _ = role_token(app, "approve", ["*"], agent="agent-9")
    absent, _pack = local_run(tmp_path, "absent")
    version = _review_of(app, absent, key, pub)
    refused = _decide(app, version, key, approver)
    assert refused[0] == 403 and "not held" in json.loads(refused[2])["error"]
    plain, _ = app.tokens.mint("acme", "write", ["*"])  # a non-role token: unchanged
    assert _decide(app, version, key, plain)[0] == 201


def test_other_roles_cannot_decide_and_revocation_and_ttl_apply_on_replay(tmp_path):
    clock = [1_000_000.0]
    app = make_app(tmp_path / "remote")
    app.tokens.now = lambda: clock[0]
    key, pub = _key()
    other = push(app, tmp_path, "other", "heads/main")
    version = _review_of(app, other, key, pub)
    for name in ("ingest", "verdict"):
        secret, _ = role_token(app, name, ["heads/"], agent="x")
        assert _decide(app, version, key, secret)[0] in (403, 404)
    approver, record = role_token(app, "approve", ["*"], agent="agent-2", ttl=60)
    assert call(app, "GET", f"{T}/reviews", token=approver)[0] == 200
    app.tokens.revoke(record["id"])
    assert _decide(app, version, key, approver)[0] == 401  # replay after revocation
    assert call(app, "GET", f"{T}/reviews", token=approver)[0] == 401
    ingest, _ = role_token(app, "ingest", ["heads/in/"], ttl=60)
    clock[0] += 61
    assert _upload(app, tmp_path, "late", ingest)[1] == 401


def test_namespace_confusion_across_tenants_and_prefixes(app, tmp_path):
    secret, _ = role_token(app, "ingest", ["heads/in/"])
    run_id, _ = _upload(app, tmp_path, "x", secret)
    for name in ("heads/in", "heads/in/../main", "heads/IN/x", "refs/heads/inx"):
        assert _put_ref(app, name, run_id, secret) in (400, 403, 404), name
    other = call(app, "PUT", "/v1/tenants/other/refs/heads%2Fin%2Fx", {"new": run_id}, secret)
    assert other[0] in (403, 404)
    assert set(app.service.index.list_refs("acme")) <= {"heads/in/x"}


def test_the_scope_is_in_every_audit_row_of_a_token(app, tmp_path):
    secret, record = role_token(app, "ingest", ["heads/in/"], agent="collector")
    run_id, _ = _upload(app, tmp_path, "audited", secret)
    assert _put_ref(app, "heads/in/a", run_id, secret) == 200
    assert _put_ref(app, "heads/main", run_id, secret) in (403, 404)
    with closing(sqlite3.connect(tmp_path / "remote" / "metadata.sqlite3")) as db:
        rows = db.execute("SELECT actor, action, outcome, details FROM audit").fetchall()
    mine = [(a, o, json.loads(d)) for actor, a, o, d in rows if actor == f"token:{record['id']}"]
    assert {(a, o) for a, o, _ in mine} >= {("upload", "ok"), ("update_ref", "ok")}
    assert any(o == "denied" for _, o, _ in mine)
    for _, _, details in mine:
        assert details["token_scope"]["role"] == "ingest"
        assert details["token_scope"]["token"] == record["id"]


def test_capabilities_http_mint_and_the_cli(app, tmp_path, monkeypatch, capsys):
    assert app.service.capabilities()["scoped_tokens"]["roles"] == ["ingest", "verdict", "approve"]
    body = {"access": "write", "refs": ["*"], "role": "approve", "agent": "a1"}
    minted = call(app, "POST", T + "/tokens", body)
    assert minted[0] == 201 and json.loads(minted[2])["role"] == "approve"
    bad = call(app, "POST", T + "/tokens", {**body, "role": "root"})
    assert bad[0] == 400
    monkeypatch.chdir(tmp_path)
    cli.main(["serve", "token", "mint", "--root", "r", "--tenant", "acme", "--role", "verdict",
              "--ref", "heads/monitors/", "--agent", "m1", "--json"])  # fmt: skip
    out = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(out) == []
    assert out["tokens"][0]["role"] == "verdict" and out["tokens"][0]["access"] == "write"
