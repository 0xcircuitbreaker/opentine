"""The target under test: a base URL from the environment, or a loopback reference server."""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from wsgiref.simple_server import make_server

import pytest

from opentine import _jsonschema
from opentine.remote._openapi import build

TOKENS = ("writer", "reader", "admin", "other")


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass
class Target:
    base: str
    tenant: str
    tokens: dict[str, str]
    local: bool
    spec: dict[str, Any] = field(default_factory=build)

    def call(self, method, path, body=None, *, token="writer", headers=None, raw=None) -> Reply:
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            request.add_header("Authorization", f"Bearer {self.tokens.get(token, token)}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        handlers = [urllib.request.ProxyHandler({})] if self.local else []
        try:
            with urllib.request.build_opener(*handlers).open(request, timeout=30) as response:
                return Reply(response.status, dict(response.headers), response.read())
        except urllib.error.HTTPError as error:
            return Reply(error.code, dict(error.headers), error.read())

    def tenant_path(self, resource: str) -> str:
        return f"/v1/tenants/{quote(self.tenant, safe='')}/{resource}"

    def schema_errors(self, name: str, value: Any) -> list[str]:
        schema = {"$ref": f"#/components/schemas/{name}", "components": self.spec["components"]}
        return _jsonschema.validate(schema, value)

    def caps(self) -> dict[str, Any]:
        return self.call("GET", "/v1/capabilities", token=None).json()

    def require(self, cap: str) -> Any:
        advertised = self.caps().get(cap)
        if not advertised:
            pytest.skip(f"server does not advertise {cap}")
        return advertised

    def push_run(self, workdir: Path, ref: str | None = None) -> str:
        """Push a fresh one-step run (and move *ref* to it); its run oid."""
        from opentine import Run
        from opentine.graph import StepKind
        from opentine.repository import Repo

        label = uuid.uuid4().hex
        local = Repo.init(workdir / label)
        run = Run(id=label, metadata={"label": "api-conformance"})
        run.add_step(StepKind.done, {"text": label})
        oid = local.put_run(run).run_id
        reply = self.call(
            "POST",
            self.tenant_path("packs"),
            raw=local.pack(),
            headers={"Content-Type": "application/vnd.opentine.pack"},
        )
        assert reply.status == 201, reply
        if ref:
            moved = self.call("PUT", self.tenant_path("refs/" + quote(ref, safe="")),
                              {"new": oid, "expected_old": None})  # fmt: skip
            assert moved.status == 200, moved
        return oid


def _local_target(root: Path) -> tuple[Target, Any]:
    from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
    from opentine.remote._http_server import ThreadingWSGIServer, TimeoutRequestHandler

    tokens = {name: f"{name}-{uuid.uuid4().hex}" for name in TOKENS}
    roles = {"writer": "writer", "reader": "reader", "admin": "admin", "other": "admin"}
    identities = StaticTokenIdentityProvider(
        {
            tokens[name]: Identity(name, "other" if name == "other" else "acme", (roles[name],))
            for name in TOKENS
        }
    )
    app = server.reference_app(root, identities=identities, keys=LocalKeyProvider(b"c" * 32))
    quiet = type("_Quiet", (TimeoutRequestHandler,), {"log_message": lambda *args: None})
    httpd = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer, handler_class=quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    return Target(base, "acme", tokens, local=True), httpd


@pytest.fixture(scope="session")
def api(tmp_path_factory):
    base = os.environ.get("TINE_API_BASE_URL")
    if base:
        tokens = {name: os.environ[f"TINE_API_{name.upper()}_TOKEN"] for name in TOKENS}
        host = urlsplit(base).hostname or ""
        local = host in {"127.0.0.1", "localhost", "::1"}
        yield Target(base.rstrip("/"), os.environ["TINE_API_TENANT"], tokens, local)
        return
    target, httpd = _local_target(tmp_path_factory.mktemp("api-remote"))
    try:
        yield target
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def work(tmp_path) -> Path:
    return tmp_path
