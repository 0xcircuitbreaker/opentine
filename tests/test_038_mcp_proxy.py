"""0.38 ``tine mcp-proxy``: stdio and Streamable HTTP relays that record a run."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from opentine.core import Run

SECRET = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"

FAKE_SERVER = r"""
import json, sys
SECRET = sys.argv[1]
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "fake"}}
    else:
        result = {"content": [{"type": "text", "text": "key=" + SECRET}]}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
    sys.stderr.write("served " + msg["method"] + "\n")
"""


def _msg(ident, method, params=None) -> bytes:
    return (json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}})
            + "\n").encode()  # fmt: skip


def _proxy(tmp_path: Path, *extra: str) -> subprocess.Popen[bytes]:
    script = tmp_path / "fake_server.py"
    script.write_text(FAKE_SERVER, encoding="utf-8")
    argv = [sys.executable, "-m", "opentine.cli", "mcp-proxy", *extra, "--save"]
    argv += [str(tmp_path / "run.tine"), "--", sys.executable, str(script), SECRET]
    return subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tmp_path
    )


def _steps(path: Path) -> list:
    return list(Run.load(path).steps)


def test_stdio_round_trip_relays_unchanged_and_redacts_before_storage(tmp_path: Path) -> None:
    proxy = _proxy(tmp_path)
    out, errout = proxy.communicate(_msg(1, "initialize") + _msg(2, "tools/call", {"name": "echo"}))
    assert proxy.returncode == 0, errout
    replies = [json.loads(line) for line in out.splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert SECRET in replies[1]["result"]["content"][0]["text"]  # relay is untouched
    assert b"served tools/call" in errout  # server stderr passes through
    saved = (tmp_path / "run.tine").read_bytes()
    assert SECRET.encode() not in saved
    steps = _steps(tmp_path / "run.tine")
    methods = [s.inputs["method"] for s in steps]
    assert methods == ["initialize", "tools/call"]
    assert steps[1].tool_info["name"] == "echo"
    assert "key=" in json.dumps(steps[1].outputs)


@pytest.mark.skipif(sys.platform == "win32", reason="kill signals differ on Windows")
def test_killed_proxy_leaves_a_partial_run(tmp_path: Path) -> None:
    proxy = _proxy(tmp_path)
    assert proxy.stdin is not None and proxy.stdout is not None
    proxy.stdin.write(_msg(1, "tools/call", {"name": "echo"}))
    proxy.stdin.flush()
    assert json.loads(proxy.stdout.readline())["id"] == 1
    path = tmp_path / "run.tine"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if path.exists() and _steps(path):
            break
        time.sleep(0.1)
    proxy.kill()
    proxy.wait()
    steps = _steps(path)
    assert [s.inputs["method"] for s in steps] == ["tools/call"]


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        reply = {"jsonrpc": "2.0", "id": msg["id"], "result": {"text": "token " + SECRET}}
        self.send_response(200)
        self.send_header("Mcp-Session-Id", self.headers.get("Mcp-Session-Id") or "sess-1")
        if msg["method"] == "tools/call":
            body = f"event: message\ndata: {json.dumps(reply)}\n\n".encode()
            self.send_header("Content-Type", "text/event-stream")
        else:
            body = json.dumps(reply).encode()
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_http_round_trip_preserves_session_and_guards_host(tmp_path: Path) -> None:
    from opentine import _mcp_proxy_http
    from opentine._mcp_proxy_record import McpRecorder

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{upstream.server_address[1]}/mcp"
    recorder = McpRecorder(tmp_path / "http.tine", [url], "http")
    proxy = _mcp_proxy_http.start(("127.0.0.1", 0), url, recorder)
    base = f"http://127.0.0.1:{proxy.port}/mcp"
    try:

        def post(ident, method, headers=None):
            request = urllib.request.Request(base, data=_msg(ident, method).strip(), method="POST")
            request.add_header("Content-Type", "application/json")
            for key, value in (headers or {}).items():
                request.add_header(key, value)
            return urllib.request.urlopen(request, timeout=10)

        first = post(1, "initialize")
        assert first.headers["Mcp-Session-Id"] == "sess-1"
        assert json.loads(first.read())["id"] == 1
        second = post(2, "tools/call", {"Mcp-Session-Id": "sess-9"})
        assert second.headers["Mcp-Session-Id"] == "sess-9"
        assert SECRET in second.read().decode()
        with pytest.raises(urllib.error.HTTPError) as refused:
            post(3, "ping", {"Origin": "http://evil.example"})
        assert refused.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as rebound:
            post(4, "ping", {"Host": "evil.example"})
        assert rebound.value.code == 403
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()
    recorder.close(0)
    assert SECRET.encode() not in (tmp_path / "http.tine").read_bytes()
    assert [s.inputs["method"] for s in _steps(tmp_path / "http.tine")] == [
        "initialize",
        "tools/call",
    ]


def test_cli_parses_and_refuses_non_loopback_listen(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "opentine.cli", "mcp-proxy", "--http-upstream", "http://x/",
         "--listen", "0.0.0.0:0", "--save", str(tmp_path / "x.tine")],
        capture_output=True, cwd=tmp_path, env={**os.environ}, timeout=60,
    )  # fmt: skip
    assert result.returncode == 1
    assert b"loopback" in result.stderr
