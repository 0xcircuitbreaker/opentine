"""``GET audit/verify`` and ``GET transparency/{checkpoint,consistency,receipt}``.

``audit/verify`` needs the ``audit`` permission (the server-keyed chain status);
the transparency routes need only ``read_ref``: anyone who may fetch may check
that the log they fetch from is append-only (:mod:`._audit_tlog`).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from opentine.remote._audit_tlog import respond

MAX_QUERY = 4096


def audit_routes(app: Any, identity, tenant: str, resource: str, environ, start_response):
    service = app.service
    if resource == "audit/verify":
        result = service.verify_audit_chain(identity, tenant)
        return app._json_response(start_response, "200 OK", result)
    service._authorize(identity, "read_ref", tenant)
    raw = str(environ.get("QUERY_STRING", ""))
    if len(raw) > MAX_QUERY:
        raise ValueError("query string is too long")
    query = {key: values[-1] for key, values in parse_qs(raw).items()}
    body = respond(service.audit, tenant, resource.removeprefix("transparency/"), query)
    if body is None:
        return app._json_response(start_response, "404 Not Found", {"error": "not found"})
    return app._json_response(start_response, "200 OK", body)
