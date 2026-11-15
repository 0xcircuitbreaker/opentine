"""Shared fixtures of the 0.52 scoped-token, CI exchange and quota tests."""

from __future__ import annotations

import base64
import io
import json
import random
from pathlib import Path
from typing import Any

from opentine import Run
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.repository import Repo

KEY = b"k" * 32
STATIC = {
    "admin-token": Identity("root", "acme", ("admin",)),
    "writer-token": Identity("alice", "acme", ("writer",)),
    "other-token": Identity("eve", "other", ("admin",)),
}


def make_app(root: Path, **kwargs: Any):
    identities = StaticTokenIdentityProvider(dict(STATIC))
    return server.reference_app(root, identities=identities, keys=LocalKeyProvider(KEY), **kwargs)


def call(app, method: str, path: str, body: Any = None, token: str | None = "admin-token",
         *, raw: bytes | None = None, content_type: str = "application/json",
         addr: str = "10.0.0.1"):  # fmt: skip
    """``(status code, headers, body)``; the response is closed, as a server would."""
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    state: dict = {}

    def start_response(status, headers, exc_info=None):
        state["status"], state["headers"] = status, dict(headers)

    environ = {
        "CONTENT_LENGTH": str(len(data)),
        "CONTENT_TYPE": content_type,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "REMOTE_ADDR": addr,
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(data),
    }
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    result = app(environ, start_response)
    try:
        out = b"".join(result)
    finally:
        close = getattr(result, "close", None)
        if callable(close):
            close()
    return int(state["status"].split()[0]), state["headers"], out


def local_run(tmp: Path, label: str, noise: int = 0) -> tuple[str, bytes]:
    """A run's oid and a pack holding it (*noise* incompressible bytes more)."""
    local = Repo.init(tmp / f"local-{label}")
    run = Run(id=label, metadata={"label": label})
    filler = base64.b64encode(random.Random(label).randbytes(noise)).decode()
    run.add_step(StepKind.done, {"text": label * 20 + filler})
    stored = local.put_run(run)
    return stored.run_id, local.pack()


def push(app, tmp: Path, label: str, ref: str) -> str:
    """Install a run as the tenant's admin and point *ref* at it."""
    run_id, pack = local_run(tmp, label)
    admin = app.service.authenticate({"authorization": "Bearer admin-token"})
    app.service.install_pack(admin, "acme", pack)
    assert app.service.update_ref(admin, "acme", ref, run_id, None)
    return run_id


def mint(app, access: str, refs: list[str], tenant: str = "acme", ttl: int = 3600) -> str:
    secret, _record = app.tokens.mint(tenant, access, refs, ttl=ttl)
    return secret
