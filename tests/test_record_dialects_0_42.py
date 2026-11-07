"""0.42: ``tine record`` speaks the Gemini and Azure OpenAI dialects, and ``--upstream``."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opentine import Run
from opentine._record_parse import step_args
from opentine._record_proxy import child_env, parse_upstreams, upstream_bases
from opentine.cli import main

KEY = "AIzaSECRETVALUE0123456789abcdefghij"
SEEN: list[str] = []


class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        SEEN.append(self.path)
        usage = {"promptTokenCount": 6, "candidatesTokenCount": 2}
        if ":streamGenerateContent" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for text in ("gem", "ini"):
                chunk = {"candidates": [{"content": {"parts": [{"text": text}]}}]}
                chunk.update(modelVersion="gemini-x", usageMetadata=usage)
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            return
        if ":generateContent" in self.path:
            reply = {"candidates": [{"content": {"parts": [{"text": "hi gemini"}]}}]}
            reply["usageMetadata"] = usage
        else:  # Azure OpenAI: the openai wire under /openai/deployments/...
            reply = {"model": "gpt-az", "choices": [{"message": {"content": "hi azure"}}]}
            reply["usage"] = {"prompt_tokens": 4, "completion_tokens": 1}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


CHILD = """
import json, os, urllib.request
def call(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode())
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        return r.read().decode()
g, z = os.environ["GOOGLE_GEMINI_BASE_URL"], os.environ["AZURE_OPENAI_ENDPOINT"]
key = os.environ["T_KEY"]
msg = {"contents": [{"parts": [{"text": "hi"}]}]}
call(g + "/v1beta/models/gemini-x:generateContent?key=" + key, msg)
call(g + "/v1beta/models/gemini-x:streamGenerateContent?alt=sse&key=" + key, msg)
dep = "/openai/deployments/d1/chat/completions?api-version=2024-10-21"
call(z + dep, {"messages": [{"role": "user", "content": "hi"}]})
"""


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    SEEN.clear()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("GOOGLE_GEMINI_BASE_URL", raising=False)
    monkeypatch.delenv("GEMINI_BASE_URL", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.setenv("T_KEY", KEY)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "child.py").write_text(CHILD, encoding="utf-8")
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_gemini_and_azure_through_upstream_flags(upstream, tmp_path, capfd):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "record",
                "--upstream",
                f"gemini={upstream}",
                "--upstream",
                f"azure={upstream}/",
                "--save",
                "rec.tine",
                "--",
                sys.executable,
                "child.py",
            ]
        )
    assert exc.value.code == 0, capfd.readouterr()
    run = Run.load(tmp_path / "rec.tine")
    steps = sorted(run.graph.steps.values(), key=lambda s: s.timestamp)
    assert [s.provider for s in steps] == ["google", "google", "azure"]
    assert [s.outputs["text"] for s in steps] == ["hi gemini", "gemini", "hi azure"]
    assert [s.model_info for s in steps] == ["gemini-x", "gemini-x", "gpt-az"]
    assert steps[0].usage["input"] == 6 and steps[2].usage["output"] == 1
    assert steps[0].inputs["path"] == "/v1beta/models/gemini-x:generateContent"
    assert any("key=" + KEY in path for path in SEEN)  # the key reached the upstream...
    assert KEY not in (tmp_path / "rec.tine").read_bytes().decode("utf-8", "replace")  # ...only


def test_azure_without_an_endpoint_is_not_injected():
    bases = upstream_bases({})
    assert bases["azure"] == "" and bases["gemini"].startswith("https://generativelanguage")
    env = child_env({}, 1234, bases)
    assert "AZURE_OPENAI_ENDPOINT" not in env
    assert env["GOOGLE_GEMINI_BASE_URL"] == "http://127.0.0.1:1234/gemini"
    assert upstream_bases({"AZURE_OPENAI_ENDPOINT": "https://r.openai.azure.com/"})["azure"] == (
        "https://r.openai.azure.com"
    )


@pytest.mark.parametrize("value", ["nope=http://x", "openai", "openai=ftp://x", "openai=http://"])
def test_bad_upstream_values_are_refused(value):
    with pytest.raises(ValueError):
        parse_upstreams([value])


def test_bad_upstream_flag_exits_2(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["record", "--upstream", "bogus=http://x", "--", "true"])
    assert exc.value.code == 2


def test_upstream_overrides_the_environment():
    bases = upstream_bases({"OPENAI_BASE_URL": "http://a/v1"}, {"openai": "http://b/v1/"})
    assert bases["openai"] == "http://b/v1"


def test_gemini_model_from_path_when_the_body_names_none():
    record = {"upstream": "gemini", "path": "/v1beta/models/gemini-y:generateContent?key=k"}
    record.update(request=b"{}", response=b"{}", content_type="application/json", status=200)
    args = step_args(record)
    assert args["model_info"] == "gemini-y" and args["inputs"]["path"].endswith("Content")
