"""API v1 conformance for 0.52 caps.scoped_tokens and caps.limits (skipped unless advertised)."""

from __future__ import annotations


def test_limits_and_auth_methods_are_public_documents(api):
    api.require("limits")
    limits = api.call("GET", "/v1/limits", token=None)
    assert limits.status == 200 and api.schema_errors("Limits", limits.json()) == []
    assert limits.json()["never_deletes"] is True
    methods = api.call("GET", "/v1/auth-methods", token=None)
    assert methods.status == 200 and api.schema_errors("AuthMethods", methods.json()) == []
    usage = api.call("GET", api.tenant_path("usage"), token="reader")
    assert usage.status == 200 and api.schema_errors("Usage", usage.json()) == []
    assert api.call("GET", api.tenant_path("usage"), token=None).status == 401
    assert api.call("GET", api.tenant_path("usage"), token="other").status in (403, 404)


def test_scoped_tokens_round_trip_and_stay_in_scope(api, work):
    api.require("scoped_tokens")
    assert api.call("GET", api.tenant_path("tokens"), token="writer").status in (403, 404)
    name = "heads/scoped-" + work.name[-12:]
    oid = api.push_run(work, name)
    request = {"access": "read", "refs": [name], "ttl_seconds": 600, "label": "conformance"}
    minted = api.call("POST", api.tenant_path("tokens"), request, token="admin")
    assert minted.status == 201 and api.schema_errors("MintedToken", minted.json()) == []
    secret, token_id = minted.json()["token"], minted.json()["id"]
    refs = api.call("GET", api.tenant_path("refs"), token=secret)
    assert refs.status == 200 and refs.json()["refs"] == {name: oid}
    assert api.call("GET", api.tenant_path("list/runs"), token=secret).status in (403, 404)
    listed = api.call("GET", api.tenant_path("tokens"), token="admin")
    assert listed.status == 200 and api.schema_errors("TokenList", listed.json()) == []
    assert token_id in {item["id"] for item in listed.json()["tokens"]}
    revoked = api.call("DELETE", api.tenant_path("tokens/" + token_id), token="admin")
    assert revoked.status == 200 and revoked.json()["state"] == "revoked"
    assert api.call("GET", api.tenant_path("refs"), token=secret).status == 401
