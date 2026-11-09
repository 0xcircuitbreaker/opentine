"""``caps.reviews``: a tenant's Reviews over HTTP (0.47, SPEC 4.19 and 8.19).

* ``GET reviews`` (``read_ref``): ``{reviews: [{review_id, seq, head}]}``.
* ``GET reviews/<id>`` (``read_ref``): ``{bundle, head, seq}``, the Review as an
  ``opentine.review-bundle`` that verifies offline.
* ``PUT reviews/<id>`` (``update_ref``: writers and admins): ``{expected_old,
  version}``, a compare-and-swap on the head version's digest (``null`` for a
  new Review; a stale one answers ``409 {"updated": false}``). The version must
  follow the head and be signed by one of its reviewers, else ``400``.
* ``POST reviews/<id>/decisions`` (``update_ref``): ``{decision}``, one
  ``opentine.review-gate`` checked against the stored version it names
  (``opentine._review.check_gate``), else ``400``. A repeat is not stored twice.

The server checks and stores; it never signs a version or a decision. Each
stored record is an ``update_ref`` row of the audit chain (name
``reviews/<id>`` or ``reviews/<id>/decisions``, new = its digest), so it is in
the transparency log. A read
the caller may not make, of a Review that does not exist, or of another tenant
answers the same ``404 {"error": "not found"}``; a write the caller may not
make answers it too, unless the caller may read the tenant (then ``403``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from opentine import _review
from opentine._review_rules import ID, gate_body
from opentine._signed_record import RecordError
from opentine.remote import _hosted_reads as reads
from opentine.remote import _review_store as store

PREFIX = "reviews"
NOT_FOUND = {"error": "not found"}


def capabilities(service: Any) -> dict[str, Any]:
    if getattr(service.objects, "root", None) is None:
        return {}
    return {"reviews": {"path": PREFIX, "kind": _review.KIND, "decisions": "decisions",
                        "update": "PUT", "max_versions": store.MAX_ITEMS}}  # fmt: skip


def _writer(app: Any, identity, tenant: str) -> None:
    try:
        app.service._authorize(identity, "update_ref", tenant)
    except PermissionError:
        reads.readable(app.service, identity, tenant, "read_ref")  # else the uniform 404
        raise


def _refused(app: Any, identity, tenant: str, sr, exc: RecordError):
    app.service._audit(identity, tenant, "update_ref", "refused", {"review": exc.code})
    return app._json_response(sr, "400 Bad Request", {"error": str(exc), "code": exc.code})


def _put(app: Any, identity, tenant: str, root, review_id: str, environ, sr):
    _writer(app, identity, tenant)
    request = app._json(environ, "expected_old", "version")
    record = request.get("version")
    known = store.versions(root, tenant, review_id)
    head = _review.digest(known[-1]) if known else None
    if request.get("expected_old") != head:
        return app._json_response(sr, "409 Conflict", {"updated": False})
    try:
        found = _review.check(record, previous=known[-1] if known else None)
        if not known and found["seq"] != 0:
            raise RecordError("review.chain-break", "the first version stored must be seq 0")
        if found["review_id"] != review_id:
            raise RecordError("review.malformed", "review is malformed: another review's id")
    except RecordError as exc:
        return _refused(app, identity, tenant, sr, exc)
    if not store.append(root, tenant, record):
        return app._json_response(sr, "409 Conflict", {"updated": False})
    details = {"name": f"reviews/{review_id}", "new": found["digest"], "expected_old": head}
    app.service._audit(identity, tenant, "update_ref", "ok", details)
    return app._json_response(sr, "200 OK", {"updated": True, "digest": found["digest"]})


def _decide(app: Any, identity, tenant: str, root, review_id: str, environ, sr):
    _writer(app, identity, tenant)
    record = app._json(environ, "decision").get("decision")
    by_digest = {_review.digest(v): v for v in store.versions(root, tenant, review_id)}
    if not by_digest:
        raise reads.Hidden("no review")
    try:
        named = by_digest.get(gate_body(record)["review"])
        if named is None:
            raise RecordError("review-gate.wrong-review", "the decision names no stored version")
        _review.check_gate(record, named)
    except RecordError as exc:
        return _refused(app, identity, tenant, sr, exc)
    digest = _review.digest(record)
    known = {_review.digest(d) for d in store.decisions(root, tenant, review_id)}
    if digest not in known:
        store.decide(root, tenant, record)
        details = {"name": f"reviews/{review_id}/decisions", "new": digest}
        app.service._audit(identity, tenant, "update_ref", "ok", details)  # in the tlog too
    return app._json_response(sr, "201 Created", {"stored": True, "digest": digest})


def _read(app: Any, identity, tenant: str, root, review_id: str | None, sr):
    reads.readable(app.service, identity, tenant, "read_ref")
    if review_id is None:
        rows = []
        for name in store.names(root, tenant):
            known = store.versions(root, tenant, name)
            if known:
                rows.append({"review_id": name, "seq": known[-1]["seq"],
                             "head": _review.digest(known[-1])})  # fmt: skip
        return app._json_response(sr, "200 OK", {"reviews": rows})
    known = store.versions(root, tenant, review_id)
    if not known:
        raise reads.Hidden("no review")
    bundle = _review.bundle(known, store.decisions(root, tenant, review_id))
    body = {"bundle": bundle, "head": _review.digest(known[-1]), "seq": known[-1]["seq"]}
    return app._json_response(sr, "200 OK", body)


def review_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """The ``reviews`` routes, or ``None`` when *resource* is not one of them."""
    root = getattr(app.service.objects, "root", None)
    parts = resource.split("/")
    if parts[0] != PREFIX or len(parts) > 3 or root is None:
        return None
    review_id = unquote(parts[1]) if len(parts) > 1 else None
    tail = parts[2] if len(parts) > 2 else None
    try:
        if review_id is not None and not ID.fullmatch(review_id):
            reads.readable(app.service, identity, tenant, "read_ref")
            raise reads.Hidden("not a review id")
        if review_id is not None and tail == "decisions" and method == "POST":
            return _decide(app, identity, tenant, root, review_id, environ, sr)
        if tail is not None:
            return None
        if review_id is not None and method == "PUT":
            return _put(app, identity, tenant, root, review_id, environ, sr)
        if method == "GET":
            return _read(app, identity, tenant, root, review_id, sr)
        return None
    except reads.Hidden:
        return app._json_response(sr, "404 Not Found", NOT_FOUND)


__all__ = ["PREFIX", "capabilities", "review_routes"]
