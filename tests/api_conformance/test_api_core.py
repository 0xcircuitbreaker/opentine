"""API v1 conformance: capabilities, authentication, refs, packs, negotiation, fetch, search."""

from __future__ import annotations

import hashlib
import uuid
from urllib.parse import quote

from opentine.repository.pack import inspect_pack

MISSING = "run:sha256:" + "0" * 64


def test_capabilities_are_public_and_match_the_schema(api):
    reply = api.call("GET", "/v1/capabilities", token=None)
    assert reply.status == 200
    assert reply.headers["Content-Type"].startswith("application/json")
    assert api.schema_errors("Capabilities", reply.json()) == []


def test_tenant_routes_are_private_by_default(api):
    for token in (None, "not-a-valid-token"):
        reply = api.call("GET", api.tenant_path("refs"), token=token)
        assert reply.status == 401
        assert api.schema_errors("Error", reply.json()) == []


def test_another_tenants_admin_cannot_read_or_write(api):
    read = api.call("GET", api.tenant_path("refs"), token="other")
    assert read.status in (403, 404)
    assert api.schema_errors("Error", read.json()) == []
    assert b"heads/" not in read.body
    write = api.call("PUT", api.tenant_path("refs/heads%2Fx"), {"new": MISSING}, token="other")
    assert write.status in (403, 404)


def test_refusals_do_not_reveal_whether_a_tenant_exists(api):
    """Anonymous, foreign and unprovisioned callers get the same bytes for a real tenant as
    for one that does not exist (ROADMAP 0.46: no tenant-existence oracle)."""
    nowhere = "no-such-tenant-" + uuid.uuid4().hex[:12]
    for resource in ("refs", "transparency/checkpoint"):
        for token in (None, "other"):
            real = api.call("GET", api.tenant_path(resource), token=token)
            fake = api.call("GET", f"/v1/tenants/{nowhere}/{resource}", token=token)
            assert real.status in (401, 403, 404)
            assert (real.status, real.body) == (fake.status, fake.body), (resource, token)


def test_an_unknown_route_is_a_uniform_404(api):
    for path in (api.tenant_path("no-such-route"), "/v1/no-such-route"):
        reply = api.call("GET", path, token="admin")
        assert (reply.status, reply.json()) == (404, {"error": "not found"})


def test_push_then_list_refs_and_compare_and_swap(api, work):
    ref = "heads/conformance-" + work.name[-12:]
    oid = api.push_run(work, ref)
    listed = api.call("GET", api.tenant_path("refs"), token="reader")
    assert listed.status == 200
    assert api.schema_errors("RefList", listed.json()) == []
    assert listed.json()["refs"][ref] == oid
    stale = api.call(
        "PUT", api.tenant_path("refs/" + quote(ref, safe="")), {"new": oid, "expected_old": None}
    )
    assert stale.status == 409 and stale.json() == {"updated": False}


def test_a_reader_cannot_move_a_ref_or_upload(api, work):
    oid = api.push_run(work)
    moved = api.call("PUT", api.tenant_path("refs/heads%2Freader"), {"new": oid}, token="reader")
    assert moved.status == 403
    upload = api.call("POST", api.tenant_path("packs"), {"sha256": "0" * 64, "size": 1},
                      token="reader")  # fmt: skip
    assert upload.status == 403


def test_negotiate_fetch_and_verify_the_pack(api, work):
    oid = api.push_run(work)
    missing = api.call("POST", api.tenant_path("negotiate"), {"wants": [oid], "haves": []})
    assert missing.status == 200 and api.schema_errors("Missing", missing.json()) == []
    assert oid in missing.json()["missing"]
    fetched = api.call("POST", api.tenant_path("fetch"), {"wants": [oid]}, token="reader")
    assert fetched.status == 200
    assert fetched.headers["Content-Type"].startswith("application/vnd.opentine.pack")
    _, objects, _ = inspect_pack(fetched.body)  # recomputes every oid from its bytes
    assert oid in {object_id for object_id, _ in objects}


def test_fetching_an_absent_object_reveals_nothing(api):
    """An absent want is not an error that could tell absent from forbidden: no objects."""
    reply = api.call("POST", api.tenant_path("fetch"), {"wants": [MISSING]}, token="reader")
    if reply.status == 200:
        assert inspect_pack(reply.body)[1] == []
    else:
        assert (reply.status, reply.json()) == (404, {"error": "not found"})


def test_search_matches_its_schema(api, work):
    api.push_run(work)
    reply = api.call("POST", api.tenant_path("search"), {"type": "run"}, token="reader")
    assert reply.status == 200
    assert api.schema_errors("SearchResult", reply.json()) == []


def test_a_resumable_upload_declares_reports_and_installs(api, work):
    from opentine.repository import Repo

    repo = Repo.init(work / "resumable")
    data = repo.pack()
    declared = api.call(
        "POST", api.tenant_path("packs"),
        {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
    )  # fmt: skip
    assert declared.status == 201 and api.schema_errors("Installed", declared.json()) == []
    path = api.tenant_path("packs/" + declared.json()["upload_id"])
    assert api.call("HEAD", path).headers["Upload-Offset"] == "0"
    head, tail = data[:10], data[10:]
    wrong = api.call("PATCH", path, raw=head, headers={"Upload-Offset": "5"})
    assert wrong.status == 409 and wrong.json() == {"offset": 0}
    first = api.call("PATCH", path, raw=head, headers={"Upload-Offset": "0"})
    assert first.status == 200 and first.json() == {"offset": 10}
    done = api.call("PATCH", path, raw=tail, headers={"Upload-Offset": "10"})
    assert done.status == 201 and api.schema_errors("Installed", done.json()) == []
    stranger = api.call("HEAD", path, token="other")
    assert stranger.status in (403, 404)


def test_audit_verify_is_admin_only(api):
    assert api.call("GET", api.tenant_path("audit/verify"), token="reader").status == 403
    reply = api.call("GET", api.tenant_path("audit/verify"), token="admin")
    assert reply.status == 200 and api.schema_errors("AuditStatus", reply.json()) == []
