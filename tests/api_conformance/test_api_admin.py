"""API v1 conformance for the 0.52 admin surface (``caps.session``, ``caps.tenancy``; SPEC 8.27).

Skipped unless advertised. Read-only except one invitation, made and revoked.
Every error body is ``{"error": ..., "code"?: ...}`` (the ``Error`` schema).
"""

from __future__ import annotations

from urllib.parse import quote


def test_whoami_lists_the_callers_tenants(api):
    api.require("session")
    reply = api.call("GET", "/v1/session", token="reader")
    assert reply.status == 200 and api.schema_errors("Session", reply.json()) == []
    assert api.tenant in {t["name"] for t in reply.json()["tenants"]}
    other = api.call("GET", "/v1/session", token="other").json()
    assert api.tenant not in {t["name"] for t in other["tenants"]}
    anonymous = api.call("GET", "/v1/session", token=None)
    assert anonymous.status == 401 and api.schema_errors("Error", anonymous.json()) == []
    listed = api.call("GET", "/v1/tenants", token="reader")
    assert listed.status == 200 and api.schema_errors("TenantList", listed.json()) == []


def test_tenant_admin_reads_are_a_uniform_404_for_other_tenants(api):
    api.require("tenancy")
    for resource in ("members", "settings", "retention", "holds"):
        other = api.call("GET", api.tenant_path(resource), token="other")
        nowhere = api.call("GET", f"/v1/tenants/no-such-tenant-x/{resource}", token="other")
        assert other.status == 404 and (other.status, other.body) == (nowhere.status, nowhere.body)
    tenant = api.call("GET", f"/v1/tenants/{quote(api.tenant, safe='')}", token="reader")
    assert tenant.status == 200 and api.schema_errors("Tenant", tenant.json()) == []
    holds = api.call("GET", api.tenant_path("holds"), token="reader")
    assert holds.status == 200 and api.schema_errors("HoldList", holds.json()) == []


def test_only_an_admin_invites_and_tokens_are_never_listed(api):
    api.require("tenancy")
    refused = api.call("POST", api.tenant_path("invitations"), {"role": "reader"}, token="writer")
    assert refused.status in (403, 404) and api.schema_errors("Error", refused.json()) == []
    made = api.call("POST", api.tenant_path("invitations"), {"role": "reader"}, token="admin")
    if made.status == 404:  # a tenant not registered on the admin surface
        assert made.json() == {"error": "not found"}
        return
    assert made.status == 201 and api.schema_errors("InvitationCreated", made.json()) == []
    listed = api.call("GET", api.tenant_path("invitations"), token="admin")
    assert made.json()["token"] not in listed.body.decode()
    gone = api.call("DELETE", api.tenant_path("invitations/" + made.json()["id"]), token="admin")
    assert gone.status == 200


def test_a_malformed_admin_request_has_the_uniform_error_shape(api):
    api.require("tenancy")
    reply = api.call("PUT", api.tenant_path("retention"), {"keep_days": "soon"}, token="admin")
    assert reply.status in (400, 404)
    assert api.schema_errors("Error", reply.json()) == []
