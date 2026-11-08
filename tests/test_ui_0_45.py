"""0.45: ``tine ui`` serves a read-only, redacted, offline viewer on 127.0.0.1."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from opentine import Run
from opentine._ui_server import CSP, Catalog, make_server
from opentine.cli import main
from opentine.core import StepKind

SECRET = "sk-ant-api03-" + "Q" * 80  # an Anthropic-shaped key the redactor knows
ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "opentine" / "data" / "ui"


def _run(tmp_path: Path, steps: int = 3) -> Path:
    run = Run(user_prompt=f"use key {SECRET}", model_info="model-a")
    run.add_step(StepKind.model, inputs={"messages": [{"role": "user", "content": SECRET}]})
    run.add_step(
        StepKind.tool,
        inputs={"name": "Write", "arguments": {"file_path": "a.txt", "content": "one\n"}},
        tool_info={"name": "Write"},
    )
    for i in range(max(0, steps - 2)):
        run.add_step(StepKind.tool, inputs={"name": "Bash", "arguments": {"command": f"ls {i}"}})
    path = tmp_path / "r.tine"
    run.save(path)
    return path


def _serve(paths: list[Path]):
    server = make_server(Catalog(paths))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def _get(url: str) -> tuple[bytes, dict]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as res:
        return res.read(), dict(res.headers)


def _all(base: str, run_id: str) -> str:
    pages = ["/", "/app.js", "/verify-browser.js", "/api/runs", f"/api/run/{run_id}"]
    pages += [f"/api/run/{run_id}/{tail}" for tail in ("tree", "diff?a=0", "verify", "attribution")]
    pages += [f"/api/run/{run_id}/step/{i}" for i in range(3)]
    return "".join(_get(base + p)[0].decode("utf-8") for p in pages)


def test_serves_viewer_and_api_redacted(tmp_path):
    path = _run(tmp_path)
    run = Run.load(path)
    server, base = _serve([path])
    try:
        body, headers = _get(base + "/")
        assert b"app.js" in body and headers["Content-Security-Policy"] == CSP
        doc = json.loads(_get(base + f"/api/run/{run.id}")[0])
        assert len(doc["timeline"]) == 3 and doc["timeline"][1]["tool"] == "Write"
        checked = json.loads(_get(base + f"/api/run/{run.id}/verify")[0])
        assert checked["integrity"] == "verified"
        assert checked["overall"] in {"verified", "partial"}
        rows = json.loads(_get(base + f"/api/run/{run.id}/attribution")[0])
        assert rows[0]["path"].endswith("a.txt")
        step = json.loads(_get(base + f"/api/run/{run.id}/step/1")[0])
        assert step["inputs"]["arguments"]["file_path"] == "a.txt"
        everything = _all(base, run.id[:8])
        assert SECRET not in everything and "[REDACTED" in everything
    finally:
        server.shutdown()
        server.server_close()


def test_tampered_run_shows_failed(tmp_path):
    from opentine._ui_model import verification

    path = _run(tmp_path)
    run = Run.load(path)
    assert verification(None, run)["overall"] == "unchecked"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["root"] = "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    assert verification(path, run)["integrity"] == "failed"


def test_no_outbound_connections(tmp_path, monkeypatch):
    path = _run(tmp_path)
    run = Run.load(path)
    seen: list[object] = []
    real = socket.socket.connect

    def audit(self, address):
        seen.append(address)
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", audit)
    server, base = _serve([path])
    try:
        _all(base, run.id)
    finally:
        server.shutdown()
        server.server_close()
    hosts = {addr[0] for addr in seen if isinstance(addr, tuple)}
    assert hosts <= {"127.0.0.1"}, hosts  # only the test client's own loopback requests
    for asset in UI.iterdir():
        text = asset.read_text(encoding="utf-8")
        assert "http://" not in text and "https://" not in text, asset.name


def test_10k_step_run_under_two_seconds(tmp_path):
    path = _run(tmp_path, steps=10_000)
    run = Run.load(path)
    server, base = _serve([path])
    server.RequestHandlerClass.catalog.runs()  # tine ui reads artifacts before serving
    try:
        start = time.perf_counter()
        doc = json.loads(_get(base + f"/api/run/{run.id}")[0])
        _get(base + "/app.js")
        elapsed = time.perf_counter() - start
    finally:
        server.shutdown()
        server.server_close()
    assert len(doc["timeline"]) == 10_000
    assert elapsed < 2.0, f"10k-step run took {elapsed:.2f}s"


def test_unknown_paths_404(tmp_path):
    path = _run(tmp_path)
    run_id = Run.load(path).id
    server, base = _serve([path])
    try:
        for bad in ("/api/run/nope", "/../pyproject.toml", "/api/x", f"/api/run/{run_id}/step/9"):
            with pytest.raises(urllib.error.HTTPError) as err:
                _get(base + bad)
            assert err.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_cli_refuses_unknown_run(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["ui", "no_such_run_zz"])


def test_bad_port_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["ui", "--port", "70000"])
    assert exc.value.code == 2


def test_foreign_host_header_is_refused(tmp_path):
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 gets 403."""
    import http.client

    path = _run(tmp_path)
    server, _base = _serve([path])
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        conn.request("GET", "/api/runs", headers={"Host": "evil.example"})
        res = conn.getresponse()
        assert res.status == 403 and b"model-a" not in res.read()
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_render_time_redaction_covers_the_leak_corpus():
    """An unsaved (never redacted) run: every corpus secret is scrubbed on render."""
    from opentine._ui_model import run_doc, step_doc
    from tests.test_security_0_10_redaction import LEAKS

    for name, text, needle in LEAKS:
        run = Run(user_prompt=text, model_info="m")
        run.add_step(StepKind.tool, inputs={"name": "Bash", "arguments": {"command": text}})
        rendered = json.dumps([run_doc(run), step_doc(0, run.steps[0])])
        assert needle not in rendered, name


def test_assets_are_inert_text_only():
    app = (UI / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in app and "eval(" not in app
    assert "aria-selected" in app and "focus-visible" in (UI / "app.css").read_text("utf-8")


@pytest.mark.skipif(
    not (ROOT / "ts" / "run-viewer" / "node_modules" / "typescript").is_dir()
    or shutil.which("node") is None,
    reason="run-viewer devDependencies not installed",
)
def test_committed_assets_match_the_typescript_build(tmp_path):
    tsc = ROOT / "ts" / "run-viewer" / "node_modules" / "typescript" / "bin" / "tsc"
    project = (ROOT / "ts" / "run-viewer" / "tsconfig.json").as_posix()
    cmd = ["node", tsc.as_posix(), "-p", project, "--outDir", tmp_path.as_posix()]
    subprocess.run(cmd, check=True)
    for name in ("app.js", "verify-browser.js"):
        assert (tmp_path / name).read_bytes() == (UI / name).read_bytes(), name
