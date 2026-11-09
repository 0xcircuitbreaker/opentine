"""API v1 conformance for ``caps.coord`` (0.47, SPEC 8.22).

Skipped unless the server advertises it. Every task made here has a fresh id,
so the checks run against a live tenant as well as the loopback reference.
"""

from __future__ import annotations

import uuid


def _task(api) -> str:
    return "conf-" + uuid.uuid4().hex[:16]


def _post(api, resource: str, body: dict, token: str = "writer"):
    return api.call("POST", api.tenant_path(resource), body, token=token)


def test_a_task_moves_by_lease_and_fencing(api):
    api.require("coord")
    task = _task(api)
    made = _post(api, "coord/tasks", {"task": task, "title": "conformance"})
    assert made.status == 201 and api.schema_errors("TaskReply", made.json()) == []
    again = _post(api, "coord/tasks", {"task": task})
    assert again.status == 409 and api.schema_errors("LeaseRefusal", again.json()) == []
    assert again.json()["code"] == "exists"
    claimed = _post(api, f"coord/tasks/{task}/claim", {"holder": "a", "ttl": 60})
    assert claimed.status == 200 and claimed.json()["task"]["fencing"] == 1
    held = _post(api, f"coord/tasks/{task}/claim", {"holder": "b", "ttl": 60})
    assert held.status == 409 and held.json()["code"] == "held"
    beat = _post(api, f"coord/tasks/{task}/heartbeat", {"holder": "a", "fencing": 1, "ttl": 60})
    assert beat.status == 200
    stale = _post(api, f"coord/tasks/{task}/done", {"holder": "a", "fencing": 0})
    assert stale.status == 409 and stale.json()["code"] == "stale"
    done = _post(api, f"coord/tasks/{task}/done", {"holder": "a", "fencing": 1})
    assert done.status == 200 and done.json()["task"]["status"] == "done"
    read = api.call("GET", api.tenant_path(f"coord/tasks/{task}"), token="reader")
    assert read.status == 200 and api.schema_errors("TaskReply", read.json()) == []
    listing = api.call("GET", api.tenant_path("coord/tasks"), token="reader")
    assert listing.status == 200 and api.schema_errors("TaskList", listing.json()) == []
    assert task in {row["task"] for row in listing.json()["tasks"]}


def test_coord_refusals_are_a_uniform_404_or_403(api):
    api.require("coord")
    task = _task(api)
    _post(api, "coord/tasks", {"task": task})
    missing = api.call("GET", api.tenant_path(f"coord/tasks/{_task(api)}"), token="reader")
    assert missing.status == 404 and missing.json() == {"error": "not found"}
    other = api.call("GET", api.tenant_path(f"coord/tasks/{task}"), token="other")
    nowhere = api.call("GET", f"/v1/tenants/no-such-tenant-x/coord/tasks/{task}", token="other")
    assert other.status in (403, 404)
    assert (other.status, other.body) == (nowhere.status, nowhere.body)
    reader = _post(api, f"coord/tasks/{task}/claim", {"holder": "r"}, token="reader")
    assert reader.status in (403, 404)
    anonymous = api.call("GET", api.tenant_path("coord/tasks"), token=None)
    assert anonymous.status == 401
