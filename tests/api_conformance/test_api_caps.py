"""API v1 conformance for capability-gated routes: skipped unless the server advertises them."""

from __future__ import annotations

import urllib.request
from urllib.parse import quote

from opentine.kernel import ObjectEnvelope
from opentine.repository.pack import inspect_pack
from tests.api_conformance.conftest import opener

ABSENT = "run:sha256:" + "f" * 64


def test_ref_txn_moves_refs_all_or_nothing(api, work):
    api.require("ref_txn")
    oid = api.push_run(work)
    name = "heads/txn-" + work.name[-12:]
    update = {"name": name, "new": oid, "expected_old": None}
    reply = api.call("POST", api.tenant_path("ref-txn"), {"updates": [update]})
    assert reply.status == 200 and reply.json() == {"updated": True}
    again = api.call("POST", api.tenant_path("ref-txn"), {"updates": [update]})
    assert again.status == 409 and again.json() == {"updated": False}


def test_events_stream_is_server_sent_events_for_readers_only(api):
    sse = api.require("events_sse")
    path = api.tenant_path(sse.get("path", "events") if isinstance(sse, dict) else "events")
    assert api.call("GET", path, token="other").status in (403, 404)
    request = urllib.request.Request(api.base + path)
    request.add_header("Authorization", f"Bearer {api.tokens['reader']}")
    with opener(api.local).open(request, timeout=30) as response:
        assert response.status == 200
        assert response.headers["Content-Type"].startswith("text/event-stream")
        assert response.readline().startswith(b"retry:")


def test_webhooks_are_admin_only_and_round_trip(api):
    api.require("webhooks")
    assert api.call("GET", api.tenant_path("webhooks"), token="writer").status == 403
    added = api.call(
        "POST", api.tenant_path("webhooks"), {"url": "https://hooks.example/conformance"},
        token="admin",
    )  # fmt: skip
    assert added.status == 201 and api.schema_errors("Webhook", added.json()) == []
    hook = added.json()["id"]
    listed = api.call("GET", api.tenant_path("webhooks"), token="admin")
    assert listed.status == 200 and api.schema_errors("WebhookList", listed.json()) == []
    assert hook in {item["id"] for item in listed.json()["webhooks"]}
    removed = api.call("DELETE", api.tenant_path("webhooks/" + hook), token="admin")
    assert removed.status == 200 and removed.json() == {"removed": hook}
    private = api.call("POST", api.tenant_path("webhooks"), {"url": "http://127.0.0.1/"},
                       token="admin")  # fmt: skip
    assert private.status == 400 or api.local


def test_transparency_checkpoint_when_the_log_exists(api, work):
    api.push_run(work, "heads/tlog-" + work.name[-12:])
    reply = api.call("GET", api.tenant_path("transparency/checkpoint"), token="reader")
    assert reply.status in (200, 404)
    if reply.status == 200:
        assert api.schema_errors("Checkpoint", reply.json()) == []
    assert api.call("GET", api.tenant_path("transparency/checkpoint"), token=None).status == 401


# --------------------------------------------------------------------------- #
# 0.46 caps for the hosted web app (planned in docs/api/openapi-v1.yaml)
# --------------------------------------------------------------------------- #


def test_object_read_is_verifiable_and_a_uniform_404(api, work):
    api.require("object_read_http")
    oid = api.push_run(work)
    reply = api.call("GET", api.tenant_path("objects/" + quote(oid, safe="")), token="reader")
    assert reply.status == 200
    assert ObjectEnvelope.decode(reply.body).oid == oid  # the client checks what it got
    absent = api.call("GET", api.tenant_path("objects/" + quote(ABSENT, safe="")), token="reader")
    assert absent.status == 404
    _assert_no_cross_tenant_oracle(api, "objects/{}", oid)


def test_run_closure_is_a_pack_holding_the_run(api, work):
    api.require("run_closure")
    oid = api.push_run(work)
    path = api.tenant_path(f"runs/{quote(oid, safe='')}/closure")
    reply = api.call("POST", path, {}, token="reader")
    assert reply.status == 200
    assert oid in {object_id for object_id, _ in inspect_pack(reply.body)[1]}
    absent = api.call("POST", api.tenant_path(f"runs/{quote(ABSENT, safe='')}/closure"), {})
    assert absent.status == 404
    _assert_no_cross_tenant_oracle(api, "runs/{}/closure", oid, method="POST")


def _assert_no_cross_tenant_oracle(api, template, oid, method="GET"):
    """Another tenant's caller gets the same refusal for an object that exists as for one that
    does not (a 403 at the tenant check, or a 404), byte for byte."""

    def get(target):
        path = api.tenant_path(template.format(quote(target, safe="")))
        return api.call(method, path, {} if method == "POST" else None, token="other")

    present, absent = get(oid), get(ABSENT)
    assert present.status in (403, 404)
    assert (present.status, present.body) == (absent.status, absent.body)


def test_list_pages_runs_and_refs(api, work):
    api.require("list")
    name = "heads/list-" + work.name[-12:]
    oid = api.push_run(work, name)
    reply = api.call("GET", api.tenant_path("list/runs?limit=500"), token="reader")
    assert reply.status == 200 and api.schema_errors("ListPage", reply.json()) == []
    assert oid in reply.json()["items"]
    refs = api.call("GET", api.tenant_path("list/refs?limit=500"), token="reader")
    assert refs.status == 200 and api.schema_errors("ListPage", refs.json()) == []
    assert {"name": name, "oid": oid} in refs.json()["items"]
    bad = api.call("GET", api.tenant_path("list/runs?limit=0"), token="reader")
    assert bad.status == 400


def test_admin_stats_are_admin_only(api):
    api.require("admin")
    writer = api.call("GET", api.tenant_path("admin/stats"), token="writer")
    assert writer.status in (403, 404)
    reply = api.call("GET", api.tenant_path("admin/stats"), token="admin")
    assert reply.status == 200 and api.schema_errors("AdminStats", reply.json()) == []


def test_a_share_reads_only_its_run_and_dies_when_revoked(api, work):
    api.require("share")
    oid = api.push_run(work)
    made = api.call("POST", api.tenant_path("shares"), {"run": oid}, token="writer")
    assert made.status == 201 and api.schema_errors("Share", made.json()) == []
    share = made.json()
    token, base = share["token"], "/v1/share/" + share["token"]
    listed = api.call("GET", api.tenant_path("shares"), token="writer")
    assert listed.status == 200 and api.schema_errors("ShareList", listed.json()) == []
    assert all("token" not in row for row in listed.json()["shares"])
    info = api.call("GET", base, token=None)
    assert info.status == 200 and api.schema_errors("SharedRun", info.json()) == []
    assert info.headers.get("Referrer-Policy") == "no-referrer"
    run = api.call("GET", f"{base}/objects/{quote(oid, safe='')}", token=None)
    assert run.status == 200 and ObjectEnvelope.decode(run.body).oid == oid
    outside = api.call("GET", f"{base}/objects/{quote(ABSENT, safe='')}", token=None)
    unknown = api.call("GET", "/v1/share/tine_share_" + "A" * 43, token=None)
    assert (outside.status, outside.body) == (unknown.status, unknown.body)
    assert outside.status == 404 and outside.json() == {"error": "not found"}
    gone = api.call("DELETE", api.tenant_path("shares/" + share["id"]), token="writer")
    assert gone.status == 200 and gone.json()["state"] == "revoked"
    after = api.call("GET", base, token=None)
    assert (after.status, after.body) == (unknown.status, unknown.body)
    assert token not in after.body.decode()


def test_tombstone_reads_are_a_uniform_404(api):
    api.require("tombstones")
    blob = "blob:sha256:" + "e" * 64
    reply = api.call("GET", api.tenant_path("tombstones/" + quote(blob, safe="")), token="reader")
    malformed = api.call("GET", api.tenant_path("tombstones/nonsense"), token="reader")
    assert (reply.status, reply.body) == (malformed.status, malformed.body)
    assert reply.status == 404
