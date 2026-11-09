"""API v1 conformance for ``caps.reviews`` (0.47, SPEC 4.20 and 8.19).

Skipped unless the server advertises it. Every write uses a fresh review id, so
the suite runs against a live tenant too: it writes a two-version Review and
one gate decision signed by a key made here, and checks that the bundle the
server answers verifies offline with the decision counted.
"""

from __future__ import annotations

import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _review

REPOS = [{"name": "app", "project": None}]


def _version(review_id: str, key, previous=None, **fields):
    me = key.public_key().public_bytes_raw().hex()
    record = _review.build(review_id, title="API conformance", reviewers=[me], repos=REPOS,
                           gates=["ship"], previous=previous, **fields)  # fmt: skip
    return _review.sign(record, key)


def test_review_reads_are_a_uniform_404_for_other_tenants(api):
    api.require("reviews")
    for resource in ("reviews", "reviews/nope", "reviews/BAD%20ID"):
        other = api.call("GET", api.tenant_path(resource), token="other")
        nowhere = api.call("GET", f"/v1/tenants/no-such-tenant-x/{resource}", token="other")
        assert other.status in (403, 404)
        assert (other.status, other.body) == (nowhere.status, nowhere.body)
    missing = api.call("GET", api.tenant_path(f"reviews/r-{uuid.uuid4().hex[:12]}"), token="reader")
    assert missing.status == 404 and missing.json() == {"error": "not found"}
    anonymous = api.call("GET", api.tenant_path("reviews"), token=None)
    assert anonymous.status == 401


def test_a_review_is_a_signed_chained_compare_and_swap_with_gate_decisions(api):
    api.require("reviews")
    review_id = f"r-{uuid.uuid4().hex[:12]}"
    path = api.tenant_path(f"reviews/{review_id}")
    key = Ed25519PrivateKey.generate()
    first = _version(review_id, key)
    reader = api.call("PUT", path, {"expected_old": None, "version": first}, token="reader")
    assert reader.status in (403, 404)
    unsigned = {k: v for k, v in first.items() if k != "signature"}
    bad = api.call("PUT", path, {"expected_old": None, "version": unsigned})
    assert bad.status == 400 and bad.json().get("code") == "review.unsigned"
    made = api.call("PUT", path, {"expected_old": None, "version": first})
    assert made.status == 200 and api.schema_errors("ReviewUpdated", made.json()) == []
    again = api.call("PUT", path, {"expected_old": None, "version": first})
    assert again.status == 409 and again.json() == {"updated": False}
    monitor = {"name": "coverage", "scorer": "exact", "score": "0.9", "threshold": "0.8",
               "passed": True, "verdict": None}  # fmt: skip
    second = _version(review_id, key, previous=first, monitors=[monitor])
    moved = api.call("PUT", path, {"expected_old": _review.digest(first), "version": second})
    assert moved.status == 200
    stranger = Ed25519PrivateKey.generate()
    forged = _review.sign_gate(_review.build_gate(second, "ship", "approve"), stranger)
    refused = api.call("POST", f"{path}/decisions", {"decision": forged})
    assert refused.status == 400 and refused.json()["code"] == "review-gate.wrong-signer"
    decision = _review.sign_gate(_review.build_gate(second, "ship", "approve", "lgtm"), key)
    stored = api.call("POST", f"{path}/decisions", {"decision": decision})
    assert stored.status == 201 and api.schema_errors("ReviewDecided", stored.json()) == []
    assert api.call("POST", f"{path}/decisions", {"decision": decision}).status == 201
    read = api.call("GET", path, token="reader")
    assert read.status == 200 and api.schema_errors("Review", read.json()) == []
    result = _review.verify_bundle(read.json()["bundle"])
    assert result["status"] == "approved" and result["decisions"] == 1
    assert result["head"] == read.json()["head"] == _review.digest(second)
    listed = api.call("GET", api.tenant_path("reviews"), token="reader")
    assert listed.status == 200 and api.schema_errors("ReviewList", listed.json()) == []
    assert {"review_id": review_id, "seq": 1, "head": _review.digest(second)} in listed.json()[
        "reviews"
    ]
