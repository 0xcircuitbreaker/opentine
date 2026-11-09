"""0.46: docs/api/openapi-v1.yaml is generated from, and checked against, the server's routes."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from opentine import _jsonschema
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._api_routes import API_VERSION, ROUTES
from opentine.remote._openapi import build, render

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "api" / "openapi-v1.yaml"
OID = "run:sha256:" + "a" * 64
#: A request body that gets each route past parsing to its authorization check.
BODIES = {
    "updateRef": {"new": OID, "expected_old": None},
    "updateRefs": {"updates": [{"name": "heads/main", "new": OID, "expected_old": None}]},
    "negotiate": {"wants": [OID]},
    "fetchPack": {"wants": [OID]},
    "uploadPack": {"sha256": "0" * 64, "size": 10},
    "search": {"type": "run"},
    "addWebhook": {"url": "https://hooks.example/x"},
    "createShare": {"run": "run:sha256:" + "a" * 64},
    "putTombstone": {"kind": "opentine.tombstone"},
}
VALUES = {"tenant": "acme", "ref": "heads%2Fmain", "upload_id": "0" * 32, "webhook_id": "wh_x"}
VALUES |= {"oid": OID, "share_id": "s1", "token": "tine_share_" + "x" * 43}


@pytest.fixture
def app(tmp_path):
    identities = StaticTokenIdentityProvider(
        {
            "admin-token": Identity("root", "acme", ("admin",)),
            "other-token": Identity("eve", "other", ("admin",)),
        }
    )
    return server.reference_app(
        tmp_path / "remote", identities=identities, keys=LocalKeyProvider(b"k" * 32)
    )


def _call(app, method: str, path: str, body: dict | None = None, token="other-token"):
    raw = json.dumps(body).encode() if body is not None else b""
    state: dict = {}
    environ = {
        "CONTENT_LENGTH": str(len(raw)),
        "CONTENT_TYPE": "application/json",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "HTTP_UPLOAD_OFFSET": "0",
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(raw),
    }
    out = b"".join(app(environ, lambda status, headers: state.update(status=status)))
    return state["status"].split()[0], out


def test_the_committed_document_is_the_rendered_route_table():
    assert SPEC.read_text(encoding="utf-8") == render(), (
        "regenerate: python -m opentine.remote._openapi > docs/api/openapi-v1.yaml"
    )


def test_the_yaml_parses_back_to_the_document():
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(SPEC.read_text(encoding="utf-8")) == build()


def test_every_component_schema_is_in_the_validated_subset():
    document = build()
    assert document["openapi"] == "3.1.0"
    for name, schema in document["components"]["schemas"].items():
        assert _jsonschema.check_schema(schema) == [], name
    refs = json.dumps(document).split('"$ref": "#/components/schemas/')[1:]
    assert {ref.split('"')[0] for ref in refs} <= set(document["components"]["schemas"])


def test_routes_are_unique_and_operation_ids_are_unique():
    assert len({(r.method, r.path) for r in ROUTES}) == len(ROUTES)
    assert len({r.operation for r in ROUTES}) == len(ROUTES)
    assert {r.status for r in ROUTES} == {"stable", "planned"}


@pytest.mark.parametrize("route", ROUTES, ids=lambda r: r.operation)
def test_the_server_dispatches_exactly_the_stable_routes(app, route):
    """A stable route reaches its tenant authorization (403 for another tenant's
    admin, or the uniform 404 on the hosted-beta caps); a public share route is
    the uniform 404 for an unknown token; a planned one is the generic 404 until
    its cap is advertised."""
    path = "/v1" + route.path.format(**VALUES)
    status, body = _call(app, route.method, path, BODIES.get(route.operation))
    caps = app.service.capabilities()
    if route.status == "stable":
        assert route.cap is None or route.cap in caps, route
    if route.path.startswith("/share/"):
        assert (status, json.loads(body)) == ("404", {"error": "not found"})
    elif route.permission is None:
        assert status == "200"
    elif route.status == "stable":
        assert status in ("403", "404"), (route, status)
        if status == "404":
            assert json.loads(body) == {"error": "not found"}
    else:
        assert route.cap not in caps, f"{route.cap} is advertised: mark {route.operation} stable"
        assert status == "404"


def test_the_ts_sdk_operation_table_matches_the_spec():
    source = (ROOT / "ts" / "sdk" / "src" / "operations.ts").read_text(encoding="utf-8")
    pattern = (
        r'^  (\w+): \{ method: "(\w+)", path: "([^"]+)", '
        r'cap: (?:"(\w+)"|null), status: "(\w+)" \},$'
    )
    sdk = {m[0]: (m[1], m[2], m[3] or None, m[4]) for m in re.findall(pattern, source, re.M)}
    spec = {r.operation: (r.method, "/v1" + r.path, r.cap, r.status) for r in ROUTES}
    assert sdk == spec
    assert f'API_VERSION = "{API_VERSION}"' in source


def test_an_unlisted_route_is_a_uniform_404(app):
    status, body = _call(app, "GET", "/v1/tenants/acme/nonexistent", token="admin-token")
    assert (status, json.loads(body)) == ("404", {"error": "not found"})
    status, body = _call(app, "GET", "/v1/elsewhere", token="admin-token")
    assert (status, json.loads(body)) == ("404", {"error": "not found"})
