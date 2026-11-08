"""Build and render ``docs/api/openapi-v1.yaml`` from the v1 route table.

``python -m opentine.remote._openapi > docs/api/openapi-v1.yaml`` regenerates
it; ``tests/test_api_v1_openapi.py`` fails when the committed file differs.
The YAML is a deterministic block-style rendering of the JSON document (every
string double-quoted, keys sorted), so any YAML 1.2 parser reads it back as
exactly :func:`build`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from opentine.remote._api_routes import API_VERSION, ROUTES, Route
from opentine.remote._openapi_schemas import SCHEMAS

_PARAM = re.compile(r"\{([a-z_]+)\}")
_PLAIN_KEY = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$-]*$")
_REASONS = {
    "200": "OK", "201": "Created", "400": "Bad request", "401": "Authentication failed",
    "403": "Forbidden", "404": "Not found (uniform: also when not visible to the caller)",
    "409": "Conflict", "429": "Quota or throttle exceeded; honour Retry-After",
    "503": "Busy; retry later",
}  # fmt: skip
_PARAM_DOCS = {
    "tenant": "Tenant name.",
    "ref": "Ref name, percent-encoded (e.g. heads%2Fmain).",
    "upload_id": "Resumable upload id from POST packs.",
    "webhook_id": "Webhook id (wh_...).",
    "oid": "Typed object id (TYPE:sha256:HEX), percent-encoded.",
    "share_id": "Share id from POST shares.",
}
_QUERY = {
    "streamEvents": [("last_event_id", "Resume after this event id (or Last-Event-ID).")],
    "logConsistency": [("old", "Older tree size."), ("new", "Newer tree size.")],
    "logReceipt": [("name", "Ref name."), ("new", "The oid the ref moved to.")],
    "listRuns": [("cursor", "Opaque cursor from next_cursor."), ("limit", "Page size.")],
}


def _content(target: str) -> dict[str, Any]:
    if "/" in target:
        return {target: {"schema": {"type": "string", "format": "binary"}}}
    return {"application/json": {"schema": {"$ref": f"#/components/schemas/{target}"}}}


def _operation(route: Route) -> dict[str, Any]:
    params = [
        {"name": name, "in": "path", "required": True, "schema": {"type": "string"},
         "description": _PARAM_DOCS[name]}
        for name in _PARAM.findall(route.path)
    ]  # fmt: skip
    params += [
        {"name": name, "in": "query", "required": False, "schema": {"type": "string"},
         "description": text}
        for name, text in _QUERY.get(route.operation, [])
    ]  # fmt: skip
    op: dict[str, Any] = {
        "operationId": route.operation,
        "summary": route.summary,
        "x-opentine-cap": route.cap,
        "x-opentine-status": route.status,
        "x-opentine-permission": route.permission,
        "responses": {
            code: {"description": _REASONS[code], "content": _content(target)}
            for code, target in route.responses
        },
    }
    if route.method == "HEAD":
        op["responses"]["200"] = {"description": "OK; the offset is in Upload-Offset"}
    if params:
        op["parameters"] = params
    if route.permission is None:
        op["security"] = []
    if route.request:
        op["requestBody"] = {"required": True, "content": _content(route.request)}
    return op


def build() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for route in ROUTES:
        paths.setdefault("/v1" + route.path, {})[route.method.lower()] = _operation(route)
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "OpenTine remote API",
            "version": API_VERSION,
            "description": (
                "The v1 HTTP API of `tine serve` and the hosted service. Tenant routes "
                "are private by default and authorized per tenant on every read; an "
                "object the caller may not read is a uniform 404. Routes marked "
                "x-opentine-status: planned are served only when GET /v1/capabilities "
                "advertises their x-opentine-cap. The server never signs as a user."
            ),
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "servers": [{"url": "https://tine.example", "description": "Your remote's base URL"}],
        "security": [{"bearer": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "description": "Token or OIDC JWT"}
            },
            "schemas": SCHEMAS,
        },
    }


def _scalar(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def _key(key: str) -> str:
    return key if _PLAIN_KEY.match(key) and key not in {"true", "false", "null"} else _scalar(key)


def _emit(value: Any, indent: int, out: list[str]) -> None:
    pad = "  " * indent
    if isinstance(value, dict):
        for key in sorted(value):
            item = value[key]
            if isinstance(item, dict | list) and item:
                out.append(f"{pad}{_key(key)}:")
                _emit(item, indent + 1, out)
            else:
                out.append(f"{pad}{_key(key)}: {_inline(item)}")
    else:
        for item in value:
            if isinstance(item, dict | list) and item:
                inner: list[str] = []
                _emit(item, indent + 1, inner)
                out.append(f"{pad}- {inner[0].lstrip()}")
                out.extend(inner[1:])
            else:
                out.append(f"{pad}- {_inline(item)}")


def _inline(value: Any) -> str:
    if isinstance(value, dict):
        return "{}"
    if isinstance(value, list):
        return "[]"
    return _scalar(value)


def render() -> str:
    out = ["# Generated by `python -m opentine.remote._openapi`; do not edit by hand."]
    _emit(build(), 0, out)
    return "\n".join(out) + "\n"


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.stdout.write(render())

__all__ = ["build", "render"]
