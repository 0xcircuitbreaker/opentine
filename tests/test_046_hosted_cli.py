"""0.46: ``tine share``, ``tine open``, ``tine repo-search --remote``, ``tine remote login``."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest

from opentine import Run, _schemas, cli
from opentine.graph import StepKind
from opentine.remote import Identity, LocalKeyProvider, StaticTokenIdentityProvider, server
from opentine.repository import Repo


class _Quiet(WSGIRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def remote(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("TINE_REMOTE_TOKEN", raising=False)
    monkeypatch.delenv("TINE_WEB_URL", raising=False)
    identities = StaticTokenIdentityProvider(
        {"writer-token": Identity("alice", "acme", ("writer",))}
    )
    app = server.reference_app(
        tmp_path / "srv", identities=identities, keys=LocalKeyProvider(b"k" * 32)
    )
    httpd = make_server("127.0.0.1", 0, app, handler_class=_Quiet)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    local = Repo.init(tmp_path / "repo")
    run = Run(id="alpha", metadata={"label": "alpha"})
    run.add_step(StepKind.done, {"text": "alpha"})
    run_id = local.put_run(run).run_id
    writer = app.service.authenticate({"authorization": "Bearer writer-token"})
    app.service.install_pack(writer, "acme", local.pack())
    token = tmp_path / "token"
    token.write_text("writer-token\n")
    token.chmod(0o600)
    url = f"http://127.0.0.1:{httpd.server_port}"
    root = tmp_path / "repo"
    assert _tine(monkeypatch, "remote", "--repo", str(root), "add", "origin", url,
                 "--tenant", "acme", "--token-file", str(token)) == 0  # fmt: skip
    monkeypatch.chdir(root)
    yield {"url": url, "run": run_id, "repo": root}
    httpd.shutdown()


def _tine(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return 0


def _json(monkeypatch, capsys, *argv: str) -> dict:
    capsys.readouterr()
    assert _tine(monkeypatch, *argv) == 0
    document = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(document) == []
    return document


def test_share_create_list_revoke_through_the_cli(remote, monkeypatch, capsys):
    made = _json(monkeypatch, capsys, "share", "create", remote["run"], "--ttl", "1h", "--json")
    assert made["action"] == "create" and made["share"]["run"] == remote["run"]
    assert made["url"].startswith(remote["url"] + "/v1/share/tine_share_")
    listed = _json(monkeypatch, capsys, "share", "list", "--json")
    assert [row["id"] for row in listed["shares"]] == [made["share"]["id"]]
    assert "tine_share_" not in json.dumps(listed)
    gone = _json(monkeypatch, capsys, "share", "revoke", made["share"]["id"], "--json")
    assert gone["share"]["state"] == "revoked"
    assert _tine(monkeypatch, "share", "revoke", "0000000000000000") != 0


def test_repo_search_remote_and_open(remote, monkeypatch, capsys):
    found = _json(monkeypatch, capsys, "repo-search", "alpha", "--remote", "origin", "--json")
    assert [row["run_id"] for row in found["results"]] == [remote["run"]]
    none = _json(monkeypatch, capsys, "repo-search", "zzz-nothing", "--remote", "origin", "--json")
    assert none["count"] == 0
    opened = _json(
        monkeypatch, capsys, "open", remote["run"], "--web-url", "https://app.invalid", "--json"
    )
    assert opened["url"] == f"https://app.invalid/acme/runs/{remote['run']}"


class _Issuer(BaseHTTPRequestHandler):
    polls = 0

    def log_message(self, *args):
        pass

    def _send(self, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_port}"
        self._send(
            {"device_authorization_endpoint": base + "/device", "token_endpoint": base + "/token"}
        )

    def do_POST(self):
        form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        if self.path == "/device":
            assert form["client_id"] == ["cli"]
            self._send({"device_code": "dc", "user_code": "ABCD-EFGH", "interval": 1,
                        "verification_uri": "https://login.invalid/device"})  # fmt: skip
            return
        type(self).polls += 1
        if type(self).polls < 2:
            self._send({"error": "authorization_pending"})
        else:
            self._send({"id_token": "id.jwt.token", "access_token": "opaque"})


def test_remote_login_device_flow_stores_the_token_owner_only(remote, monkeypatch, capsys):
    import opentine._cli_remote_login as login

    monkeypatch.setattr(login.time, "sleep", lambda _s: None)
    issuer = HTTPServer(("127.0.0.1", 0), _Issuer)
    threading.Thread(target=issuer.serve_forever, daemon=True).start()
    try:
        code = _tine(monkeypatch, "remote", "login", "origin", "--client-id", "cli",
                     "--issuer", f"http://127.0.0.1:{issuer.server_port}")  # fmt: skip
    finally:
        issuer.shutdown()
    captured = capsys.readouterr()
    assert code == 0 and "ABCD-EFGH" in captured.err
    assert "id.jwt.token" not in captured.out + captured.err
    settings = json.loads((remote["repo"] / ".tine" / "porcelain.json").read_text())
    stored = Path(settings["remotes"]["origin"]["token_file"])
    assert stored.read_text().strip() == "id.jwt.token"
    if sys.platform != "win32":
        assert stored.stat().st_mode & 0o077 == 0
