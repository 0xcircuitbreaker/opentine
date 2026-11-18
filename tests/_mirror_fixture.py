"""A fixture git repo and a ``tine serve --mirror`` app for the 0.55 code mirror tests."""

from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _jsonschema, _project
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.remote._openapi import build

UPSTREAM = "https://git.example.org/app.git"
TOKENS = {
    "acme-writer": Identity("alice", "acme", ("writer",)),
    "acme-reader": Identity("rita", "acme", ("reader",)),
    "other-admin": Identity("eve", "other", ("admin",)),
}


def git(repo: Path, *args: str, when: int = 0) -> str:
    stamp = f"2026-01-0{1 + when}T12:00:00Z"
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_AUTHOR_NAME": "Ada", "GIT_AUTHOR_EMAIL": "ada@example.org",
           "GIT_COMMITTER_NAME": "Ada", "GIT_COMMITTER_EMAIL": "ada@example.org",
           "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}  # fmt: skip
    done = subprocess.run(["git", "-C", str(repo), *args], env=env, check=True,
                          capture_output=True, text=True)  # fmt: skip
    return done.stdout.strip()


def fixture_repo(path: Path) -> dict[str, str]:
    """main: two commits; a feature branch one ahead; a tag ``v1`` at the first."""
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    (path / "src").mkdir()
    (path / "README.md").write_text("# App\n\nThe fixture app.\n")
    (path / "src" / "parser.py").write_text("def parse_tokens(text):\n    return text.split()\n")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "First commit")
    git(path, "tag", "v1")
    first = git(path, "rev-parse", "HEAD")
    (path / "data.bin").write_bytes(bytes(range(256)))
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "Add binary data", when=1)
    second = git(path, "rev-parse", "HEAD")
    git(path, "checkout", "-q", "-b", "feature")
    (path / "src" / "lexer.py").write_text("def lex(source):\n    return list(source)\n")
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "Add a lexer", when=2)
    feature = git(path, "rev-parse", "HEAD")
    git(path, "checkout", "-q", "main")
    return {"first": first, "second": second, "feature": feature}


def make_app(tmp_path: Path, **mirror: Any):
    options = {"allow_local": True, "min_interval_seconds": 3600, **mirror}
    return server.reference_app(
        tmp_path / "remote",
        identities=StaticTokenIdentityProvider(dict(TOKENS)),
        keys=LocalKeyProvider(b"k" * 32),
        mirror=options,
    )


class Reply:
    def __init__(self, status: str, headers: list, body: bytes):
        self.status, self.headers, self.body = int(status.split()[0]), dict(headers), body

    def json(self) -> Any:
        return json.loads(self.body)


def call(app, method: str, path: str, body: Any = None, token: str | None = "acme-writer",
         query: str = "") -> Reply:  # fmt: skip
    raw = json.dumps(body).encode() if body is not None else b""
    state: dict = {}
    environ = {"CONTENT_LENGTH": str(len(raw)), "CONTENT_TYPE": "application/json",
               "PATH_INFO": path, "QUERY_STRING": query, "REQUEST_METHOD": method,
               "REMOTE_ADDR": "127.0.0.1", "wsgi.input": io.BytesIO(raw)}  # fmt: skip
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    def start(status, headers):
        state.update(status=status, headers=headers)

    out = b"".join(app(environ, start))
    return Reply(state["status"], state["headers"], out)


def put_project(app, tenant: str = "acme", visibility: str = "public", locator=None) -> dict:
    key = Ed25519PrivateKey.generate()
    slot = {"role": "primary", "forge": "git", "forge_repo_id": None,
            "upstream_visibility": visibility, "locator": locator or {"url": UPSTREAM},
            "default_branch": "main"}  # fmt: skip
    owner = key.public_key().public_bytes_raw().hex()
    record = _project.build("app", tenant, owners=[owner], slots=[slot], visibility=visibility)
    manifest = _project.sign(record, key)
    reply = call(app, "PUT", f"/v1/tenants/{tenant}/project",
                 {"expected_old": None, "manifest": manifest})  # fmt: skip
    assert reply.status == 200, reply.body
    return manifest


def schema_errors(name: str, value: Any) -> list[str]:
    spec = build()
    schema = {"$ref": f"#/components/schemas/{name}", "components": spec["components"]}
    return _jsonschema.validate(schema, value)
