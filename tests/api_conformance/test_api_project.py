"""API v1 conformance for ``caps.project`` and ``caps.social_export`` (0.46.1, SPEC 8.18).

Skipped unless the server advertises them. Against a tenant that already has a
project the write checks only probe refusals; on an empty one (the loopback
reference server) they write a two-version chain signed by a key made here.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _project

SLOT = {
    "role": "primary",
    "forge": "git",
    "forge_repo_id": None,
    "upstream_visibility": "public",
    "locator": {"url": "https://git.example.org/app.git"},
    "default_branch": "main",
}


def _version(api, key, previous=None, **fields):
    owner = key.public_key().public_bytes_raw().hex()
    record = _project.build("conformance", api.tenant, owners=[owner], slots=[SLOT],
                            previous=previous, **fields)  # fmt: skip
    return _project.sign(record, key)


def _head(api):
    reply = api.call("GET", api.tenant_path("project"), token="reader")
    assert reply.status in (200, 404)
    if reply.status == 404:
        assert reply.json() == {"error": "not found"}
        return None
    assert api.schema_errors("Project", reply.json()) == []
    return reply.json()


def test_project_reads_are_a_uniform_404_for_other_tenants(api):
    api.require("project")
    for resource in ("project", "project/history", "social"):
        other = api.call("GET", api.tenant_path(resource), token="other")
        nowhere = api.call("GET", f"/v1/tenants/no-such-tenant-x/{resource}", token="other")
        assert other.status in (403, 404)
        assert (other.status, other.body) == (nowhere.status, nowhere.body)
    anonymous = api.call("GET", api.tenant_path("project"), token=None)
    missing = api.call("GET", "/v1/tenants/no-such-tenant-x/project", token=None)
    assert anonymous.status == 401 and (anonymous.status, anonymous.body) == (
        missing.status,
        missing.body,
    )


def test_put_project_is_a_signed_chained_compare_and_swap(api):
    api.require("project")
    key = Ed25519PrivateKey.generate()
    head = _head(api)
    stale = api.call(
        "PUT",
        api.tenant_path("project"),
        {"expected_old": "blob:sha256:" + "0" * 64, "manifest": _version(api, key)},
    )
    assert stale.status in (400, 409)
    reader = api.call(
        "PUT",
        api.tenant_path("project"),
        {"expected_old": None, "manifest": _version(api, key)},
        token="reader",
    )
    assert reader.status in (403, 404)
    if head is not None:
        return  # a live project: only refusals are probed
    first = _version(api, key)
    unsigned = {k: v for k, v in first.items() if k != "signature"}
    bad = api.call("PUT", api.tenant_path("project"), {"expected_old": None, "manifest": unsigned})
    assert bad.status == 400 and bad.json().get("code") == "project.unsigned"
    made = api.call("PUT", api.tenant_path("project"), {"expected_old": None, "manifest": first})
    assert made.status == 200 and api.schema_errors("ProjectUpdated", made.json()) == []
    assert made.json() == {"updated": True, "digest": _project.digest(first)}
    again = api.call("PUT", api.tenant_path("project"), {"expected_old": None, "manifest": first})
    assert again.status == 409 and again.json() == {"updated": False}
    stranger = Ed25519PrivateKey.generate()
    wrong = _version(api, stranger, previous=first)
    refused = api.call("PUT", api.tenant_path("project"),
                       {"expected_old": _project.digest(first), "manifest": wrong})  # fmt: skip
    assert refused.status == 400 and refused.json()["code"] == "project.wrong-signer"
    second = _version(api, key, previous=first)
    moved = api.call("PUT", api.tenant_path("project"),
                     {"expected_old": _project.digest(first), "manifest": second})  # fmt: skip
    assert moved.status == 200
    current = _head(api)
    assert current is not None and current["manifest"] == second and current["seq"] == 1
    history = api.call("GET", api.tenant_path("project/history"), token="reader")
    assert history.status == 200 and api.schema_errors("ProjectHistory", history.json()) == []
    assert history.json()["versions"] == [first, second] and history.json()["next_cursor"] is None
    assert _project.chain(history.json()["versions"])["head"] == _project.digest(second)


def test_social_counts_are_counts_only(api):
    api.require("social_export")
    reply = api.call("GET", api.tenant_path("social"), token="reader")
    assert reply.status == 200 and api.schema_errors("SocialCounts", reply.json()) == []
    assert set(reply.json()) == {"stars", "watches"}


def test_the_server_offers_no_code_storage(api):
    caps = api.caps()
    assert not {"mirror", "upload_pack", "receive_pack", "code"} & set(caps)
