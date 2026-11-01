"""0.20: ``tine record -- CMD`` records a child's model calls through a local proxy."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from opentine import Run
from opentine.cli import main

SECRET = "sk-test-SECRETVALUE0123456789abcdef"
SEEN: list[dict] = []


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        SEEN.append({"path": self.path, "auth": self.headers.get("Authorization")})
        SEEN[-1]["key"] = self.headers.get("x-api-key")
        if self.path.endswith("/messages"):
            if body.get("stream"):
                return self._sse(
                    [
                        {
                            "type": "message_start",
                            "message": {"model": "claude-x", "usage": {"input_tokens": 9}},
                        },  # noqa: E501
                        {
                            "type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": "he"},
                        },  # noqa: E501
                        {
                            "type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": "llo"},
                        },  # noqa: E501
                        {"type": "message_delta", "usage": {"output_tokens": 4}},
                    ]
                )
            reply = {"model": "claude-x", "content": [{"type": "text", "text": "hi from claude"}]}
            reply["usage"] = {"input_tokens": 11, "output_tokens": 5}
            return self._json(reply)
        if body.get("stream"):
            return self._sse(
                [
                    {"model": "gpt-x", "choices": [{"delta": {"content": "str"}}]},
                    {"model": "gpt-x", "choices": [{"delta": {"content": "eam"}}]},
                    {
                        "model": "gpt-x",
                        "choices": [],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
                    },  # noqa: E501
                ]
            )
        reply = {"model": "gpt-x", "choices": [{"message": {"content": "hi from gpt"}}]}
        reply["usage"] = {"prompt_tokens": 7, "completion_tokens": 3}
        return self._json(reply)

    def _json(self, reply):
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in events:
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")


CHILD = """
import json, os, sys, urllib.request
def call(base, path, body, headers):
    req = urllib.request.Request(base + path, json.dumps(body).encode(), headers)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        return r.read().decode()
o, a = os.environ["OPENAI_BASE_URL"], os.environ["ANTHROPIC_BASE_URL"]
auth = {"Authorization": "Bearer " + os.environ["T_KEY"]}
msgs = [{"role": "user", "content": "say hi"}]
out = [call(o, "/chat/completions", {"model": "gpt-x", "messages": msgs}, auth)]
out.append(call(o, "/chat/completions", {"model": "gpt-x", "messages": msgs, "stream": True}, auth))
akey = {"x-api-key": os.environ["T_KEY"]}
out.append(call(a, "/v1/messages", {"model": "claude-x", "messages": msgs}, akey))
out.append(call(a, "/v1/messages", {"model": "claude-x", "messages": msgs, "stream": True}, akey))
print(json.dumps(out))
sys.exit(int(os.environ.get("T_EXIT", "0")))
"""


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    SEEN.clear()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("OPENAI_BASE_URL", base + "/v1")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", base)
    monkeypatch.setenv("T_KEY", SECRET)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "child.py").write_text(CHILD, encoding="utf-8")
    yield tmp_path
    server.shutdown()
    server.server_close()


def _record(tmp_path: Path, capfd, *extra: str) -> tuple[int, Run, str]:
    with pytest.raises(SystemExit) as exc:
        main(["record", "--save", "rec.tine", *extra, "--", sys.executable, "child.py"])
    out = capfd.readouterr().out
    return exc.value.code, Run.load(tmp_path / "rec.tine"), out


def test_records_openai_and_anthropic_calls_plain_and_streaming(upstream, capfd):
    code, run, out = _record(upstream, capfd)
    assert code == 0
    assert "hi from gpt" in out and "text_delta" in out and "[DONE]" in out  # raw bytes relayed
    assert "Saved:" in out
    steps = sorted(run.graph.steps.values(), key=lambda s: s.timestamp)
    assert [s.kind.value for s in steps] == ["model"] * 4
    assert [s.provider for s in steps] == ["openai", "openai", "anthropic", "anthropic"]
    assert [s.outputs["text"] for s in steps] == [
        "hi from gpt",
        "stream",
        "hi from claude",
        "hello",
    ]
    assert steps[0].usage["input"] == 7 and steps[0].usage["output"] == 3
    assert steps[1].usage["output"] == 2
    assert steps[2].usage["input"] == 11 and steps[3].usage["output"] == 4
    assert steps[0].model_info == "gpt-x" and steps[3].model_info == "claude-x"
    assert steps[0].inputs["messages"][0]["content"] == "say hi"
    assert [s["path"] for s in SEEN] == ["/v1/chat/completions"] * 2 + ["/v1/messages"] * 2


def test_credentials_reach_upstream_but_never_the_run(upstream, capfd):
    _, _, _ = _record(upstream, capfd)
    assert SEEN[0]["auth"] == "Bearer " + SECRET and SEEN[2]["key"] == SECRET
    assert SECRET not in (upstream / "rec.tine").read_bytes().decode("utf-8", "replace")


def test_exit_code_is_the_childs(upstream, capfd, monkeypatch):
    monkeypatch.setenv("T_EXIT", "3")
    code, run, _ = _record(upstream, capfd)
    assert code == 3
    assert run.status.value == "failed" and run.metadata["record"]["exit_code"] == 3


def test_unreachable_upstream_is_passed_through_not_fatal(upstream, capfd, monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
    (upstream / "child.py").write_text(
        "import os, urllib.request, urllib.error\n"
        "try:\n"
        "    urllib.request.urlopen(os.environ['OPENAI_BASE_URL'] + '/models')\n"
        "except urllib.error.HTTPError as e:\n"
        "    print('status', e.code)\n",
        encoding="utf-8",
    )
    code, run, out = _record(upstream, capfd)
    assert code == 0 and "status 502" in out
    (step,) = run.graph.steps.values()
    assert step.error["type"] == "UpstreamError"


def test_no_command_is_refused(upstream, capfd):
    with pytest.raises(SystemExit) as exc:
        main(["record"])
    assert exc.value.code == 1
