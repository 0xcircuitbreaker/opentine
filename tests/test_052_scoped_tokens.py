"""0.52 caps.scoped_tokens: per tenant, read|write, per ref namespace; hashed; revocable."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from opentine import _schemas, cli
from opentine.remote._token_store import TokenStore, parse_ttl
from tests._auth_helpers import call, make_app, mint, push


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path / "remote")


def test_only_the_digest_is_stored_and_a_wrong_secret_is_refused(app, tmp_path):
    secret = mint(app, "read", ["*"])
    raw = (tmp_path / "remote" / "auth.sqlite3").read_bytes()
    assert secret.rsplit("_", 1)[-1].encode() not in raw
    assert secret.split("_", 3)[3].encode() not in raw
    assert call(app, "GET", "/v1/tenants/acme/refs", token=secret)[0] == 200
    forged = secret[:-4] + ("AAAA" if not secret.endswith("AAAA") else "BBBB")
    assert call(app, "GET", "/v1/tenants/acme/refs", token=forged)[0] == 401
    ci_spelling = secret.replace("tine_pat_", "tine_ci_")
    assert call(app, "GET", "/v1/tenants/acme/refs", token=ci_spelling)[0] == 401


def test_expiry_and_revocation_apply_on_the_next_request(tmp_path):
    clock = [1_000_000.0]
    store = TokenStore(tmp_path / "auth.sqlite3", now=lambda: clock[0])
    secret, record = store.mint("acme", "read", ["*"], ttl=60)
    assert store.identity(secret).tenant == "acme"
    clock[0] += 61
    with pytest.raises(PermissionError):
        store.identity(secret)
    assert store.get(record["id"])["state"] == "expired"
    secret, record = store.mint("acme", "read", ["*"], ttl=60)
    assert store.revoke(record["id"])["state"] == "revoked"
    assert store.revoke(record["id"])["state"] == "revoked"  # idempotent
    with pytest.raises(PermissionError):
        store.identity(secret)
    with pytest.raises(KeyError):
        store.revoke(record["id"], tenant="other")  # another tenant's token: as if absent


def test_mint_refuses_bad_scopes_and_lifetimes(tmp_path):
    store = TokenStore(tmp_path / "auth.sqlite3")
    for refs in ([], ["*", "heads/main"], ["heads/*"], ["../x"], "heads/main"):
        with pytest.raises(ValueError):
            store.mint("acme", "read", refs)
    with pytest.raises(ValueError):
        store.mint("acme", "admin", ["*"])
    with pytest.raises(ValueError):
        store.mint("acme", "read", ["*"], ttl=400 * 86400)
    with pytest.raises(ValueError):
        store.mint("acme", "read", ["*"], ttl=7200, kind="ci")
    assert store.mint("acme", "read", ["refs/heads/ci/"])[1]["refs"] == ["heads/ci/"]
    assert parse_ttl("15m") == 900
    with pytest.raises(ValueError):
        parse_ttl("forever")


def test_a_namespace_limited_reader_sees_and_fetches_only_its_namespace(app, tmp_path):
    inside = push(app, tmp_path, "inside", "heads/ci/build")
    outside = push(app, tmp_path, "outside", "heads/main")
    token = mint(app, "read", ["heads/ci/"])
    status, _, body = call(app, "GET", "/v1/tenants/acme/refs", token=token)
    assert status == 200 and json.loads(body)["refs"] == {"heads/ci/build": inside}
    assert call(app, "POST", "/v1/tenants/acme/fetch", {"wants": [inside]}, token)[0] == 200
    refused = call(app, "POST", "/v1/tenants/acme/fetch", {"wants": [outside]}, token)
    absent = call(app, "POST", "/v1/tenants/acme/fetch", {"wants": ["run:sha256:" + "f" * 64]},
                  token)  # fmt: skip
    assert refused[0] == absent[0] == 404 and refused[2] == absent[2]
    assert call(app, "POST", "/v1/tenants/acme/negotiate", {"wants": [outside]}, token)[0] == 404
    for method, path in (
        ("GET", f"/v1/tenants/acme/objects/{quote(inside, safe='')}"),
        ("GET", "/v1/tenants/acme/list/refs"),
        ("POST", "/v1/tenants/acme/search"),
        ("GET", "/v1/tenants/acme/usage"),
        ("GET", "/v1/tenants/acme/shares"),
    ):
        assert call(app, method, path, {} if method == "POST" else None, token)[0] in (403, 404)


def test_a_namespace_limited_writer_moves_only_its_refs(app, tmp_path):
    run_id = push(app, tmp_path, "base", "heads/main")
    token = mint(app, "write", ["heads/ci/"])
    ok = call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fci%2Fx", {"new": run_id}, token)
    assert ok[0] == 200
    out = call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fmain", {"new": run_id,
               "expected_old": run_id, "force": True}, token)  # fmt: skip
    assert out[0] == 404  # outside its namespaces: the uniform 404
    txn = {"updates": [{"name": "heads/ci/y", "new": run_id, "expected_old": None},
                       {"name": "heads/other", "new": run_id, "expected_old": None}]}  # fmt: skip
    assert call(app, "POST", "/v1/tenants/acme/ref-txn", txn, token)[0] == 404
    refs = app.service.index.list_refs("acme")
    assert "heads/ci/y" not in refs and "heads/other" not in refs  # all or nothing
    reader = mint(app, "read", ["heads/ci/"])
    moved = call(app, "PUT", "/v1/tenants/acme/refs/heads%2Fci%2Fz", {"new": run_id}, reader)
    assert moved[0] == 404


def test_a_whole_tenant_token_is_a_reader_or_writer_and_never_crosses_tenants(app, tmp_path):
    push(app, tmp_path, "one", "heads/main")
    reader = mint(app, "read", ["*"])
    assert call(app, "GET", "/v1/tenants/acme/list/refs", token=reader)[0] == 200
    assert call(app, "GET", "/v1/tenants/acme/webhooks", token=reader)[0] == 403
    assert call(app, "GET", "/v1/tenants/acme/tokens", token=reader)[0] == 403
    assert call(app, "GET", "/v1/tenants/other/refs", token=reader)[0] in (403, 404)


def test_tokens_over_http_are_admin_only_and_tenant_private(app):
    minted = call(app, "POST", "/v1/tenants/acme/tokens", {"access": "read", "refs": ["heads/x"]})
    assert minted[0] == 201
    record = json.loads(minted[2])
    assert record["token"].startswith("tine_pat_") and record["refs"] == ["heads/x"]
    assert _schemas.validate_output({"schema": "tine-cli-serve-token/1", "command":
                                     "serve token mint", "ok": True,
                                     "tokens": [{k: v for k, v in record.items()
                                                 if k != "token"}]}) == []  # fmt: skip
    listed = json.loads(call(app, "GET", "/v1/tenants/acme/tokens")[2])["tokens"]
    assert [item["id"] for item in listed] == [record["id"]]
    assert "token" not in listed[0] and "digest" not in listed[0]
    assert call(app, "GET", "/v1/tenants/acme/tokens", token="writer-token")[0] == 403
    assert call(app, "DELETE", f"/v1/tenants/other/tokens/{record['id']}",
                token="other-token")[0] == 404  # fmt: skip
    gone = call(app, "DELETE", f"/v1/tenants/acme/tokens/{record['id']}")
    assert gone[0] == 200 and json.loads(gone[2])["state"] == "revoked"
    assert call(app, "GET", "/v1/tenants/acme/refs", token=record["token"])[0] == 401
    bad = {"access": "admin", "refs": ["*"]}
    assert call(app, "POST", "/v1/tenants/acme/tokens", bad)[0] == 400


def test_the_cli_mints_lists_and_revokes(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def tine(*argv):
        cli.main(["serve", *argv])
        return json.loads(capsys.readouterr().out)

    minted = tine("token", "mint", "--root", "r", "--tenant", "acme", "--ref", "heads/ci/",
                  "--ttl", "2h", "--json")  # fmt: skip
    assert _schemas.validate_output(minted) == []
    token_id = minted["tokens"][0]["id"]
    store = TokenStore.at(tmp_path / "r")
    assert store.identity(minted["token"]).claims["opentine_scope"]["refs"] == ["heads/ci/"]
    listed = tine("token", "list", "--root", "r", "--tenant", "acme", "--json")
    assert "token" not in listed and listed["tokens"][0]["id"] == token_id
    revoked = tine("token", "revoke", token_id, "--root", "r", "--tenant", "acme", "--json")
    assert revoked["tokens"][0]["state"] == "revoked"
    with pytest.raises(SystemExit):
        cli.main(["serve", "token", "revoke", token_id, "--root", "r", "--tenant", "other"])


def test_capabilities_point_at_the_new_documents_without_changing_old_keys(app):
    caps = app.service.capabilities()
    assert caps["scoped_tokens"]["path"] == "tokens"
    assert caps["limits"]["path"] == "/v1/limits"
    assert "oidc_exchange" not in caps  # only with --ci-trust
    assert caps["authentication"] == ["bearer", "oidc"]
    status, _, body = call(app, "GET", "/v1/auth-methods", token=None)
    assert status == 200
    assert {m["type"] for m in json.loads(body)["methods"]} == {"bearer", "scoped_token"}
