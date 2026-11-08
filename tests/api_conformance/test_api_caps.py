"""API v1 conformance for capability-gated routes: skipped unless the server advertises them."""

from __future__ import annotations

import urllib.request
from urllib.parse import quote

from opentine.kernel import ObjectEnvelope
from opentine.repository.pack import inspect_pack

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
    handlers = [urllib.request.ProxyHandler({})] if api.local else []
    with urllib.request.build_opener(*handlers).open(request, timeout=30) as response:
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
    hidden = api.call("GET", api.tenant_path("objects/" + quote(oid, safe="")), token="other")
    assert absent.status == hidden.status == 404
    assert absent.body == hidden.body  # no oid-existence oracle across tenants


def test_run_closure_is_a_pack_holding_the_run(api, work):
    api.require("run_closure")
    oid = api.push_run(work)
    reply = api.call("GET", api.tenant_path(f"runs/{quote(oid, safe='')}/closure"), token="reader")
    assert reply.status == 200
    assert oid in {object_id for object_id, _ in inspect_pack(reply.body)[1]}
    absent = api.call("GET", api.tenant_path(f"runs/{quote(ABSENT, safe='')}/closure"))
    hidden = api.call("GET", api.tenant_path(f"runs/{quote(oid, safe='')}/closure"), token="other")
    assert absent.status == hidden.status == 404 and absent.body == hidden.body


def test_list_pages_runs(api, work):
    api.require("list")
    oid = api.push_run(work, "heads/list-" + work.name[-12:])
    reply = api.call("GET", api.tenant_path("runs?limit=50"), token="reader")
    assert reply.status == 200 and api.schema_errors("RunPage", reply.json()) == []
    assert oid in {run["oid"] for run in reply.json()["runs"]}


def test_admin_quota_is_admin_only(api):
    api.require("admin")
    assert api.call("GET", api.tenant_path("admin/quota"), token="writer").status == 403
    reply = api.call("GET", api.tenant_path("admin/quota"), token="admin")
    assert reply.status == 200 and api.schema_errors("Quota", reply.json()) == []
