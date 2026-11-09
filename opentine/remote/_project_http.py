"""``GET|PUT project``, ``GET project/history`` and ``GET social`` (0.46.1, ``caps.project``).

* ``GET project`` (``read_ref``): ``{manifest, digest, seq}`` of the current
  ``opentine.project`` version.
* ``GET project/history?cursor=N`` (``read_ref``): versions oldest first, at
  most :data:`PAGE` per page, ``next_cursor`` null on the last page.
* ``PUT project`` (``update_ref``: writers and admins): ``{expected_old,
  manifest}``. A compare-and-swap of ``project/manifest``: ``expected_old`` is
  the current version's digest (``null`` for none) or the answer is ``409
  {"updated": false}``; the manifest must name this tenant, follow the current
  version and be signed by one of its owners (``opentine._project.check``),
  else ``400``. The server checks and stores; it never signs a manifest.
* ``GET social`` (``caps.social_export``, ``read_ref``): count-only stars and
  watches, for self-host parity.

Every read the caller may not make, of a tenant without a project, or of
another tenant answers the same ``404 {"error": "not found"}``; an
unauthenticated caller gets the same ``401`` for every tenant, existing or not.
``tine serve`` stores no code: there is no upload-pack, receive-pack or mirror
route, and no ``mirror`` capability.
"""

from __future__ import annotations

from typing import Any

from opentine import _project
from opentine._signed_record import RecordError
from opentine.remote import _hosted_reads as reads
from opentine.remote import _project_store as store

PAGE = 100
NOT_FOUND = {"error": "not found"}


def capabilities(service: Any) -> dict[str, Any]:
    if getattr(service.objects, "root", None) is None:
        return {}
    return {
        "project": {"path": "project", "history": "project/history", "max_page": PAGE,
                    "kind": _project.KIND, "update": "PUT"},
        "social_export": {"path": "social", "counts": ["stars", "watches"]},
    }  # fmt: skip


def _query_cursor(environ) -> int:
    from urllib.parse import parse_qs

    raw = str(environ.get("QUERY_STRING", ""))
    values = parse_qs(raw).get("cursor") if len(raw) <= 256 else None
    if not values:
        return 0
    if not values[-1].isdigit() or len(values[-1]) > 6:
        raise ValueError("cursor is a version number")
    return int(values[-1])


def _put(app: Any, identity, tenant: str, root, environ, sr):
    service = app.service
    service._authorize(identity, "update_ref", tenant)
    request = app._json(environ, "expected_old", "manifest")
    record = request.get("manifest")
    current = store.head(root, tenant)
    current_digest = None if current is None else _project.digest(current)
    if request.get("expected_old") != current_digest:
        service._audit(identity, tenant, "update_ref", "conflict", {"name": "project/manifest"})
        return app._json_response(sr, "409 Conflict", {"updated": False})
    try:
        found = _project.check(record, previous=current)
    except RecordError as exc:
        service._audit(identity, tenant, "update_ref", "refused", {"project": exc.code})
        return app._json_response(sr, "400 Bad Request", {"error": str(exc), "code": exc.code})
    if found["tenant"] != tenant:
        raise ValueError("the manifest names another tenant")
    if not store.append(root, tenant, record):
        return app._json_response(sr, "409 Conflict", {"updated": False})
    details = {"name": "project/manifest", "new": found["digest"], "expected_old": current_digest}
    service._audit(identity, tenant, "update_ref", "ok", details)  # logged: opentine-log/1
    return app._json_response(sr, "200 OK", {"updated": True, "digest": found["digest"]})


def project_routes(app: Any, identity, tenant: str, resource: str, method: str, environ, sr):
    """The project and social routes, or ``None`` when *resource* is not one of them."""
    root = getattr(app.service.objects, "root", None)
    if resource not in ("project", "project/history", "social") or root is None:
        return None
    try:
        if resource == "project" and method == "PUT":
            return _put(app, identity, tenant, root, environ, sr)
        if method != "GET":
            return None
        reads.readable(app.service, identity, tenant, "read_ref")
        if resource == "social":
            return app._json_response(sr, "200 OK", store.social(root, tenant))
        if resource == "project":
            current = store.head(root, tenant)
            if current is None:
                raise reads.Hidden("no project")
            body = {"manifest": current, "digest": _project.digest(current), "seq": current["seq"]}
            return app._json_response(sr, "200 OK", body)
        start = _query_cursor(environ)
        versions, total = store.page(root, tenant, start, PAGE)
        if total == 0:
            raise reads.Hidden("no project")
        following = start + PAGE if start + PAGE < total else None
        body = {"versions": versions, "next_cursor": following, "total": total}
        return app._json_response(sr, "200 OK", body)
    except reads.Hidden:
        return app._json_response(sr, "404 Not Found", NOT_FOUND)


__all__ = ["PAGE", "capabilities", "project_routes"]
