"""0.63: the gate in the MCP proxy and the hook path, and the offline verdict check."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import urllib.request
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from opentine import _mcp_proxy_http, _monitor_verdict, _schemas, cli
from opentine._http_linger import LingeringCloseMixin
from opentine._mcp_proxy_record import McpRecorder
from opentine._monitor_gate import Gate
from opentine._monitor_hook import run as hook_run
from opentine._monitor_mcp import McpGuard
from opentine._monitors import load
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CONFIG = """version = 1
mode = "{mode}"
deadline_ms = 600000
[monitor]
id = "rules"
kind = "rule"
threshold = 0.5
action = "block"
[[monitor.rules]]
tool = "shell"
pattern = "rm -rf"
score = 0.9
"""
FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" in msg:
        out = {"jsonrpc": "2.0", "id": msg["id"], "result": {"ran": msg.get("params")}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
"""


def _msg(ident, method, params=None) -> bytes:
    body = {"jsonrpc": "2.0", "id": ident, "method": method, "params": params or {}}
    return (json.dumps(body) + "\n").encode("utf-8")


def _shell(ident, cmd) -> bytes:
    return _msg(ident, "tools/call", {"name": "shell", "arguments": {"cmd": cmd}})


@pytest.fixture
def env(tmp_path):
    repo = Repo.init(tmp_path / "r")
    key = tmp_path / "monitor.key"
    key.write_bytes((b"\x07" * 32).hex().encode("ascii"))
    for mode in ("gate", "advisory"):
        (tmp_path / f"{mode}.toml").write_bytes(CONFIG.format(mode=mode).encode("utf-8"))
    return tmp_path, repo, key


def _verify(capsys, repo_dir: Path, *runs: Path):
    argv = ["monitor", "verify", "--repo", repo_dir.as_posix(), "--json"]
    for run in runs:
        argv += ["--run", run.as_posix()]
    code = 0
    try:
        cli.main(argv)
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(out) == [], out
    return code, out


def test_stdio_gate_blocks_and_every_block_verifies_offline(env, capsys):
    tmp, repo, key = env
    (tmp / "server.py").write_bytes(FAKE_SERVER.encode("utf-8"))
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    argv = [sys.executable, "-m", "opentine.cli", "mcp-proxy", "--monitor", "gate.toml",
            "--monitor-repo", "r", "--monitor-key", key.as_posix(), "--save", "run.tine",
            "--", sys.executable, "server.py"]  # fmt: skip
    proc = subprocess.run(argv, input=_msg(1, "initialize") + _shell(2, "rm -rf /")
                          + _shell(3, "ls"), capture_output=True, cwd=tmp, env=env,
                          timeout=600)  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
    assert "result" in replies[1] and "result" in replies[3]
    mark = replies[2]["error"]["data"]["opentine.monitor"]
    assert mark["outcome"] == "block" and mark["verdict"].startswith("attestation:")
    code, out = _verify(capsys, tmp / "r", tmp / "run.tine")
    assert code == 0 and out["ok"], out
    assert out["blocked_actions"] == 1 and out["verdicts"] == 1
    (repo.path / "holds").write_bytes(b'{"format":"tine-holds/1","holds":[]}\n')
    code, out = _verify(capsys, tmp / "r", tmp / "run.tine")
    assert code == 1 and "fail:monitor.verdict-not-held" in {f["code"] for f in out["findings"]}


def _guard(env, mode: str, **gate) -> McpGuard:
    tmp, repo, key = env
    from opentine._key_hygiene import ed25519_private

    config = load(tmp / f"{mode}.toml")
    return McpGuard(Gate(config, repo=repo, key=ed25519_private(key.as_posix()), **gate))


def test_a_replacement_names_its_verdict_and_a_tampered_step_fails(env, capsys):
    tmp, repo, _ = env
    guard = _guard(
        env, "gate", alternate=lambda role, req: {"name": "shell", "arguments": {"cmd": "ls"}}
    )
    guard.gate.config["action"] = "defer"
    forward, back, blocked = guard.check(_shell(7, "rm -rf /"))
    assert back is None and blocked is None
    sent = json.loads(forward)
    assert sent["params"]["arguments"] == {"cmd": "ls"}
    recorder = McpRecorder(tmp / "alt.tine", ["x"], "stdio")
    recorder.feed("client", forward)
    recorder.feed("server", b'{"jsonrpc":"2.0","id":7,"result":{}}\n')
    recorder.close(0)
    code, out = _verify(capsys, tmp / "r", tmp / "alt.tine")
    assert code == 0 and out["replaced_actions"] == 1
    recorder = McpRecorder(tmp / "bad.tine", ["x"], "stdio")
    sent["params"]["arguments"] = {"cmd": "something else"}
    recorder.feed("client", json.dumps(sent).encode("utf-8"))
    recorder.close(0)
    code, out = _verify(capsys, tmp / "r", tmp / "bad.tine")
    assert code == 1 and "fail:monitor.verdict-mismatch" in {f["code"] for f in out["findings"]}


def test_advisory_relays_every_byte_unchanged(env):
    guard = _guard(env, "advisory")
    raw = _shell(1, "rm -rf /")
    assert guard.check(raw) == (raw, None, None)
    guard.close()
    assert guard.gate.counts["forward"] == 1 and guard.gate.counts["recorded"] == 1


def test_an_allowed_call_costs_one_monitor_call_and_no_signature(env, monkeypatch):
    guard = _guard(env, "gate")
    calls = {"score": 0, "record": 0}
    score, record = guard.gate.monitor.score, _monitor_verdict.record

    def counted_score(request):
        calls["score"] += 1
        return score(request)

    def counted_record(*args, **kwargs):
        calls["record"] += 1
        return record(*args, **kwargs)

    monkeypatch.setattr(guard.gate.monitor, "score", counted_score)
    monkeypatch.setattr(_monitor_verdict, "record", counted_record)
    for n in range(50):
        guard.check(_shell(n, "ls"))
        guard.check(_msg(1000 + n, "resources/list"))  # not gated: never scored
    assert calls == {"score": 50, "record": 0}
    guard.check(_shell(99, "rm -rf /"))
    assert calls == {"score": 51, "record": 1}


class _Upstream(BaseHTTPRequestHandler):
    hits: list[bytes] = []

    def log_message(self, *args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).hits.append(body)
        reply = json.dumps({"jsonrpc": "2.0", "id": json.loads(body)["id"], "result": {}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply.encode("utf-8"))


class _Server(LingeringCloseMixin, ThreadingHTTPServer):
    daemon_threads = True


def test_http_gate_answers_a_blocked_call_without_reaching_upstream(env):
    import threading

    tmp, _, _ = env
    _Upstream.hits = []
    upstream = _Server(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    recorder = McpRecorder(tmp / "http.tine", ["x"], "http")
    proxy = _mcp_proxy_http.start(("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_address[1]}/mcp",
                                  recorder, _guard(env, "gate"))  # fmt: skip
    try:

        def post(body: bytes) -> dict:
            req = urllib.request.Request(f"http://127.0.0.1:{proxy.port}/mcp", data=body,
                                         headers={"Content-Type": "application/json"})  # fmt: skip
            with urllib.request.urlopen(req, timeout=600) as reply:
                return json.loads(reply.read())

        assert "error" in post(_shell(1, "rm -rf /"))
        assert "result" in post(_shell(2, "ls"))
        assert len(_Upstream.hits) == 1 and b"ls" in _Upstream.hits[0]
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()
        recorder.close(0)


def _hook(env, agent: str, payload: bytes, config: str = "gate.toml", fail_closed=False):
    tmp, _, key = env
    args = Namespace(config=(tmp / config).as_posix(), repo=(tmp / "r").as_posix(),
                     key=key.as_posix(), agent=agent, fail_closed=fail_closed)  # fmt: skip
    out = io.BytesIO()
    assert hook_run(args, io.BytesIO(payload), out) == 0
    return json.loads(out.getvalue())


def test_the_hook_path_denies_in_each_dialect(env):
    pre = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "s1",
            "tool_name": "shell",
            "tool_input": {"cmd": "rm -rf /"},
        }
    ).encode()
    denied = _hook(env, "claude-code", pre)["hookSpecificOutput"]
    assert denied["permissionDecision"] == "deny"
    assert _hook(env, "gemini", pre)["decision"] == "deny"
    generic = json.dumps({"protocol": "opentine-monitor/1", "session": "s2",
                          "tool": {"name": "shell", "input": {"cmd": "ls"}}}).encode()  # fmt: skip
    answer = _hook(env, "generic", generic)
    assert answer["decision"] == "allow"
    assert _schemas.validate(answer, "opentine-monitor-hook-1")[1] == []
    assert _hook(env, "claude-code", pre, config="missing.toml") == {}  # D12: proceeds
    closed = _hook(env, "claude-code", pre, config="missing.toml", fail_closed=True)
    assert closed["hookSpecificOutput"]["permissionDecision"] == "deny"
