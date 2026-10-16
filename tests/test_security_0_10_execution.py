"""Audit round 3 (0.10): execution, adapter credentials, budgets, pricing pass."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opentine import Budget
from opentine._pricing_pass import price_run
from opentine.graph import Run, StepKind
from opentine.runtime import Agent

# --------------------------------------------------------------------------- #
# D3-1 / H1: the key the transport rule checks is the key the SDK sends
# --------------------------------------------------------------------------- #


def test_gemini_api_key_alone_is_checked_against_cleartext_transport(monkeypatch):
    pytest.importorskip("google.genai")
    from opentine.models.google import Google

    for name in (
        "GOOGLE_API_KEY",
        "OPENTINE_ALLOW_INSECURE_ENDPOINTS",
        "GOOGLE_GENAI_USE_VERTEXAI",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy-fake-gemini-key-000000000000000")
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "http://192.0.2.1")

    with pytest.raises(ValueError, match="cleartext"):
        Google("gemini-x")._get_client()

    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com")
    assert Google("gemini-x")._get_client() is not None


def test_anthropic_auth_token_is_checked_and_sent_explicitly(monkeypatch):
    pytest.importorskip("anthropic")
    from opentine.models.anthropic import Anthropic

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENTINE_ALLOW_INSECURE_ENDPOINTS", raising=False)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat-fake-token-0000000000")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://192.0.2.1")
    with pytest.raises(ValueError, match="cleartext"):
        Anthropic("claude-opus-5-5")._get_client()

    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:9")
    client = Anthropic("claude-opus-5-5")._get_client()
    # An AUTH_TOKEN-only user used to get api_key="" and no credential at all.
    assert client.auth_token == "sk-ant-oat-fake-token-0000000000"


def test_anthropic_sdk_1_gets_temperature_in_extra_body(monkeypatch):
    from opentine.models import _anthropic_client
    from opentine.models.anthropic import Anthropic

    monkeypatch.setattr(_anthropic_client, "sdk_major", lambda: 1)
    kwargs = Anthropic("claude-haiku-4-5")._kwargs([], None, None, 0.2)
    assert "temperature" not in kwargs  # SDK 1.x: TypeError before any request
    assert kwargs["extra_body"] == {"temperature": 0.2}

    monkeypatch.setattr(_anthropic_client, "sdk_major", lambda: 0)
    assert Anthropic("claude-haiku-4-5")._kwargs([], None, None, 0.2)["temperature"] == 0.2
    # Models that reject sampling get it in neither place.
    assert "extra_body" not in Anthropic("claude-opus-5-5")._kwargs([], None, None, 0.2)


# --------------------------------------------------------------------------- #
# D3-3: the budget holds between the tool calls of one response
# --------------------------------------------------------------------------- #


class _Batch:
    name = "batch-model"
    supports_tools = True
    supports_thinking = False

    def __init__(self):
        self.calls = 0

    async def complete(self, messages, tools=None, system=None, temperature=0.0):
        self.calls += 1
        if self.calls == 1:
            calls = [{"name": "act", "arguments": {"target": str(i)}} for i in range(50)]
            return {"text": "", "tool_calls": calls, "cost": 0}
        return {"text": "done", "tool_calls": [], "cost": 0}

    async def stream(self, *args, **kwargs):  # pragma: no cover - unused
        yield {}


@pytest.mark.parametrize("budget", [Budget(max_steps=3), Budget(max_duration=0.2)])
def test_budget_is_enforced_between_tool_calls_in_one_batch(budget):
    executed: list[str] = []

    def act(target: str) -> str:
        """Do one side effect."""
        executed.append(target)
        time.sleep(0.05)
        return "ok"

    run = Agent(_Batch(), tools=[act], budget=budget).run_sync("go")

    assert len(executed) < 10, "the model, not the budget, decided how many ran"
    assert run.metadata["budget_state"]["breached"] is True
    skipped = [
        step
        for step in run.steps
        if step.kind == StepKind.tool and "not executed" in str(step.outputs.get("result"))
    ]
    # Every call in the batch is answered, so a resume sees a complete batch.
    assert len(skipped) + len(executed) == 50


# --------------------------------------------------------------------------- #
# D3-4: environment scrub
# --------------------------------------------------------------------------- #


def test_clean_env_scrubs_passphrase_session_and_pw_names(monkeypatch):
    from opentine.tools._process import clean_env

    leaked = {
        "BORG_PASSPHRASE": "v1",
        "GPG_PASSPHRASE": "v2",
        "PASSPHRASE": "v3",
        "BW_SESSION": "v4",
        "OP_SESSION_acme": "v5",
        "LDAP_BIND_PW": "v6",
        "WALLET_MNEMONIC": "v7",
    }
    kept = {"PWD": "/w", "PATH": "/usr/bin", "HOME": "/h", "LANG": "C.UTF-8"}
    monkeypatch.setattr(os, "environ", {**leaked, **kept})
    assert clean_env(True, ()) == kept


_CREDENTIAL_ENV = {
    # SDK / OTLP header variables carry gateway credentials (final pass 2, #6).
    "OPENAI_CUSTOM_HEADERS": "X-Gateway-Auth: gw-4c1d",
    "ANTHROPIC_CUSTOM_HEADERS": "X-Corp-Token: corp-77",
    "OTEL_EXPORTER_OTLP_HEADERS": "api-key=otlp-9f",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS": "x-honeycomb-team=hc-1",
    # A header-shaped value under an innocent name.
    "GATEWAY_EXTRA": "Authorization=Bearer abcdefghijklmnop",
    "PROXY_HDR": "x-api-key: plainvalue",
    # Cloud and vendor credential names (audit of the full list).
    "AWS_ACCESS_KEY_ID": "a",
    "AWS_SECRET_ACCESS_KEY": "b",
    "AWS_SESSION_TOKEN": "c",
    "AWS_BEARER_TOKEN_BEDROCK": "d",
    "GOOGLE_APPLICATION_CREDENTIALS": "/home/u/sa.json",
    "AZURE_CLIENT_SECRET": "e",
    "AZURE_OPENAI_API_KEY": "f",
    "AZURE_STORAGE_CONNECTION_STRING": "g",
    "HF_TOKEN": "h",
    "HUGGING_FACE_HUB_TOKEN": "i",
    "OLLAMA_API_KEY": "j",
    "ANTHROPIC_COMPAT_API_KEY": "k",
    "OPENAI_COMPAT_API_KEY": "l",
    "OPENTINE_REMOTE_TOKEN": "m",
    "ANTHROPIC_AUTH_TOKEN": "n",
    "GEMINI_API_KEY": "o",
}
_BENIGN_ENV = {
    "PATH": "/usr/bin",
    "HOME": "/h",
    "LANG": "C.UTF-8",
    "OPENAI_ORG_ID": "org-public",
    "EDITOR": "vim",
    "NOTE": "basic mode on",
}


def test_clean_env_scrubs_header_variables_and_cloud_credentials(monkeypatch):
    from opentine.tools._process import clean_env

    monkeypatch.setattr(os, "environ", {**_CREDENTIAL_ENV, **_BENIGN_ENV})
    assert clean_env(True, ()) == _BENIGN_ENV


def test_python_tool_with_inherited_env_never_sees_header_credentials(monkeypatch):
    from opentine.policies import PythonPolicy
    from opentine.tools.python import execute

    for name, value in _CREDENTIAL_ENV.items():
        monkeypatch.setenv(name, value)
    code = "import os, json; print(json.dumps(sorted(os.environ)))"
    out = execute(code, policy=PythonPolicy(enabled=True, inherit_env=True))
    seen = set(json.loads(out.strip().splitlines()[-1]))
    assert not seen & set(_CREDENTIAL_ENV), seen & set(_CREDENTIAL_ENV)


# --------------------------------------------------------------------------- #
# D3-5 / D3-6: web tool
# --------------------------------------------------------------------------- #


def test_web_server_charset_cannot_make_decoding_superlinear():
    from opentine.tools.web import _decode

    body = b"-" + b"a" * 400_000
    started = time.monotonic()
    text = _decode(SimpleNamespace(encoding="punycode", content=body))
    assert time.monotonic() - started < 1.0
    assert text.startswith("-aaa")
    for name in ("idna", "utf-7", "unicode_escape", "rot13", "no-such-codec"):
        assert _decode(SimpleNamespace(encoding=name, content=b"+AGE-")) == "+AGE-"
    assert _decode(SimpleNamespace(encoding="latin-1", content=b"\xe9")) == "é"
    assert (
        _decode(SimpleNamespace(encoding="shift_jis", content="日本".encode("shift_jis"))) == "日本"
    )


@pytest.mark.parametrize(
    "address",
    ["224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1", "::ffff:0:a9fe:a9fe", "::1:a9fe:a9fe"],
)
def test_multicast_and_reserved_are_not_public(address):
    from opentine.tools.web import _public

    assert _public(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700::1111", "64:ff9b::808:808"])
def test_public_addresses_stay_public(address):
    from opentine.tools.web import _public

    assert _public(ipaddress.ip_address(address)) is True


# --------------------------------------------------------------------------- #
# D3-7: descendants that leave the process group (Linux subreaper)
# --------------------------------------------------------------------------- #


def _escaper(tmp_path: Path, marker: str, linger: float) -> list[str]:
    script = tmp_path / f"{marker}.py"
    target = tmp_path / marker
    script.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', "
        f'\'import time; time.sleep(2); open(r"{target}", "w")\'], start_new_session=True)\n'
        "print('spawned', flush=True)\n"
        f"time.sleep({linger})\n"
    )
    return [sys.executable, str(script)]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
@pytest.mark.parametrize(("linger", "timeout"), [(30, 1.0), (0, 20.0)])
def test_setsid_descendant_is_killed_on_timeout_and_on_exit(tmp_path, linger, timeout):
    from opentine.tools._process import run_bounded

    result = run_bounded(_escaper(tmp_path, "survivor", linger), timeout=timeout, max_chars=100)
    assert b"spawned" in result.stdout
    time.sleep(3)
    assert not (tmp_path / "survivor").exists(), "setsid() descendant outlived the tool"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
def test_supervised_command_keeps_exit_status_and_signal():
    from opentine.tools._process import run_bounded

    code = run_bounded([sys.executable, "-c", "raise SystemExit(3)"], timeout=10, max_chars=9)
    assert code.returncode == 3
    suicide = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    killed = run_bounded([sys.executable, "-c", suicide], timeout=10, max_chars=9)
    assert killed.returncode == -9
    missing = run_bounded(["opentine-no-such-binary"], timeout=10, max_chars=9)
    assert missing.returncode == 127


def test_harness_cleanup_still_accepts_asyncio_processes():
    from opentine.tools._process import _cleanup_owned

    class AsyncioLike:  # an asyncio Process has no poll()
        pid = 2**22 + 12345
        returncode = 0

        def kill(self):
            pass

    _cleanup_owned(AsyncioLike(), None)  # must not raise AttributeError


# --------------------------------------------------------------------------- #
# P-1 / L-1 / service tier: post hoc agrees with capture
# --------------------------------------------------------------------------- #


def _billing(provider: str, tier: str | None = None) -> dict[str, Any]:
    calculation: dict[str, Any] = {"provider": provider}
    if tier:
        calculation["service_tier"] = tier
    return {"status": "complete", "calculation": calculation}


def test_price_counts_the_done_step_of_a_single_call_run():
    run = Run(id="p1")
    run.add_step(
        StepKind.done,
        {"text": "ok"},
        usage={"input": 100_000, "output": 50_000},
        provider="anthropic",
        model_info="claude-opus-5-5",
        billing=_billing("anthropic"),
    )
    priced = price_run(run, effective_at="2026-10-14")
    assert priced.priced_steps == 1
    assert priced.total_cost == pytest.approx(1.4)


def test_price_does_not_count_a_harness_closing_step():
    run = Run(id="p2")
    run.add_step(
        StepKind.model,
        {"event": "model"},
        usage={"input": 1_000_000},
        provider="anthropic",
        model_info="claude-opus-5-5",
    )
    run.add_step(StepKind.done, {"result": "x"}, cost=4.0)  # Claude Code's own figure
    priced = price_run(run, effective_at="2026-10-14")
    assert priced.priced_steps == 1
    assert priced.total_cost == pytest.approx(4.0)


def test_price_reprices_recorded_fast_mode_at_its_tier():
    run = Run(id="p3")
    run.add_step(
        StepKind.model,
        {"service_tier": "fast"},
        usage={"input": 1_000_000},
        provider="anthropic",
        model_info="claude-opus-5-5",
    )
    assert price_run(run, effective_at="2026-10-14").total_cost == pytest.approx(8.0)


@pytest.mark.parametrize("provider", ["ollama", "lmstudio", "vllm", "llamacpp", "sglang"])
def test_local_unmetered_capture_reprices_as_unmetered(provider):
    # A billing-less local step is free only inside a harness capture (positive
    # evidence): the harness wrapper marks every run it records.
    run = Run(id="p4", manifest={"kind": "external-harness", "harness": "codex"})
    run.add_step(
        StepKind.model,
        {},
        usage={"input": 10, "output": 5},
        provider=provider,
        model_info="qwen3:8b",
    )
    priced = price_run(run, effective_at="2026-10-14")
    assert priced.status_counts == {"unmetered": 1}
    assert priced.unknown_models == ()


@pytest.mark.parametrize("provider", ["ollama", "lmstudio", "vllm", "llamacpp", "sglang"])
def test_a_billing_less_local_step_outside_a_harness_run_is_never_free(provider):
    # What a library import or a 0.9.x ``tine import`` stored: no billing, a
    # provider name from a file (final security pass 5, #4).
    run = Run(id="p4b")
    run.add_step(
        StepKind.model, {}, usage={"input": 10, "output": 5}, provider=provider, model_info="m"
    )
    assert price_run(run, effective_at="2026-10-14").status_counts == {"unknown": 1}


def test_litellm_and_ollama_cloud_are_not_unmetered():
    run = Run(id="p5")
    for provider in ("litellm", "ollama-cloud"):
        run.add_step(StepKind.model, {}, usage={"input": 1}, provider=provider, model_info="m")
    assert price_run(run, effective_at="2026-10-14").status_counts == {"unknown": 2}


def test_fast_speed_maps_to_the_fast_modifier():
    from opentine.models._anthropic_rules import pricing_tier

    usage = SimpleNamespace(speed="fast", service_tier="standard", inference_geo=None)
    assert pricing_tier(SimpleNamespace(usage=usage), None, None) == "fast"
    usage.inference_geo = "us"
    assert pricing_tier(SimpleNamespace(usage=usage), None, None) == "fast_us"
    usage.speed, usage.inference_geo = "standard", None
    assert pricing_tier(SimpleNamespace(usage=usage), None, None) == "standard"


def test_subprocess_is_not_left_running(tmp_path):
    """Sanity: the supervised path still drains and returns ordinary output."""
    from opentine.tools._process import run_bounded

    result = run_bounded([sys.executable, "-c", "print('hi')"], timeout=10, max_chars=100)
    assert result.stdout.strip() == b"hi" and result.returncode == 0
    assert subprocess.run([sys.executable, "-c", "pass"], check=False).returncode == 0


# --------------------------------------------------------------------------- #
# Round-4 re-audit: the command cannot switch the subreaper off
# --------------------------------------------------------------------------- #

_KILLERS = {
    "parent": "os.kill(os.getppid(), signal.SIGKILL)",
    "group": "os.killpg(0, signal.SIGKILL)",
    "ancestor": (
        "sup = int(open(f'/proc/{os.getppid()}/status').read().split('PPid:')[1].split()[0]); "
        "os.kill(sup, signal.SIGKILL); time.sleep(0.3)"
    ),
}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
@pytest.mark.parametrize("how", sorted(_KILLERS))
def test_killing_the_supervisor_does_not_free_a_setsid_descendant(tmp_path, how):
    from opentine.tools._process import run_bounded

    target = tmp_path / "survivor"
    script = tmp_path / "escape.py"
    script.write_text(
        "import os, signal, subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', "
        f'\'import time; time.sleep(2); open(r"{target}", "w")\'], start_new_session=True)\n'
        "time.sleep(0.2)\n"
        f"{_KILLERS[how]}\n"
    )
    run_bounded([sys.executable, str(script)], timeout=10, max_chars=100)
    time.sleep(3)
    assert not target.exists(), f"setsid() descendant escaped after the {how} kill"


# --------------------------------------------------------------------------- #
# Re-audit round 2, #7: the supervisor's report cannot be forged, and OpenTine
# sweeps after every command whatever the report says
# --------------------------------------------------------------------------- #

_FIND_SUPERVISOR = (
    "def ppid(pid):\n"
    "    return int(open(f'/proc/{pid}/status').read().split('PPid:')[1].split()[0])\n"
    "sup = ppid(os.getppid())\n"
)

_FORGE_OK = (
    "host = ppid(sup)\n"
    "for fd in os.listdir(f'/proc/{host}/fd'):\n"
    "    if int(fd) < 3: continue\n"
    "    try:\n"
    "        if os.readlink(f'/proc/{host}/fd/{fd}').startswith('pipe:'):\n"
    "            w = os.open(f'/proc/{host}/fd/{fd}', os.O_WRONLY | os.O_NONBLOCK)\n"
    "            os.write(w, b'ok\\n'); os.close(w)\n"
    "    except OSError:\n"
    "        pass\n"
)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
@pytest.mark.parametrize("hidden", [False, True], ids=["dumpable", "non-dumpable"])
def test_a_forged_sweep_report_does_not_free_a_setsid_descendant(tmp_path, hidden):
    from opentine.tools._process import run_bounded

    target = tmp_path / "survivor"
    hide = "import ctypes; ctypes.CDLL(None).prctl(4, 0, 0, 0, 0); " if hidden else ""
    survivor = f'{hide}import time; time.sleep(2); open(r"{target}", "w")'
    script = tmp_path / "escape.py"
    script.write_text(
        "import os, signal, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {survivor!r}], start_new_session=True)\n"
        "time.sleep(0.3)\n" + _FIND_SUPERVISOR + _FORGE_OK + "os.kill(sup, signal.SIGKILL)\n"
        "time.sleep(0.3)\n"
    )
    run_bounded([sys.executable, str(script)], timeout=10, max_chars=100)
    time.sleep(3)
    assert not target.exists(), "a forged 'ok' let a setsid() descendant escape"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
def test_the_command_cannot_read_the_supervisors_fds_memory_or_environment(tmp_path):
    from opentine.tools._process import run_bounded

    probe = (
        "import os\n" + _FIND_SUPERVISOR + "for name in ('fd', 'environ', 'mem'):\n"
        "    try:\n"
        "        path = f'/proc/{sup}/{name}'\n"
        "        os.listdir(path) if name == 'fd' else open(path, 'rb').read(1)\n"
        "        print(name, 'open')\n"
        "    except PermissionError:\n"
        "        print(name, 'closed')\n"
    )
    result = run_bounded([sys.executable, "-c", probe], timeout=10, max_chars=500)
    assert result.stdout.split() == [b"fd", b"closed", b"environ", b"closed", b"mem", b"closed"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="subreaper is Linux-only")
def test_the_hidden_process_sweep_spares_opentines_own_tree():
    from opentine.tools._subreaper_sweep import boot_ticks, kill_hidden

    since = max(0, boot_ticks() - 2)
    hidden_child = "import ctypes, time; ctypes.CDLL(None).prctl(4, 0, 0, 0, 0); time.sleep(10)"
    child = subprocess.Popen([sys.executable, "-c", hidden_child])
    try:
        time.sleep(0.5)
        kill_hidden(since)  # e.g. a concurrent tool's (non-dumpable) supervisor
        assert child.poll() is None, "OpenTine's own non-dumpable child was killed"
    finally:
        child.kill()
        child.wait()


# --------------------------------------------------------------------------- #
# Final pass #8: the SDKs' env custom headers stay with the first-party host
# --------------------------------------------------------------------------- #

_PORTKEY = "x-portkey-api-key: PORTKEY-FAKE-SECRET"
_GATEWAY = "cf-aig-authorization: Bearer CF-FAKE-SECRET"


def _capture_server():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append({k.lower(): v for k, v in self.headers.items()})
            if self.path.endswith("/messages"):
                body = {
                    "id": "m",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-x",
                    "content": [{"type": "text", "text": "ok"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            else:
                body = {
                    "id": "c",
                    "object": "chat.completion",
                    "model": "m",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}", seen


@pytest.fixture
def env_headers(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_COMPAT_API_KEY",
        "OPENAI_BASE_URL",
        "OPENTINE_ALLOW_INSECURE_ENDPOINTS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_CUSTOM_HEADERS", _PORTKEY)
    monkeypatch.setenv("OPENAI_CUSTOM_HEADERS", _GATEWAY)
    monkeypatch.setenv("OPENAI_ORG_ID", "org-fake-identity")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-fake-first-party-0000000000")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fake_groq_key_000000000000000000000000000")
    server, url, seen = _capture_server()
    yield url, seen
    server.shutdown()


def _call(adapter) -> None:
    import asyncio

    asyncio.run(adapter.complete([{"role": "user", "content": "hi"}]))


def test_custom_header_env_never_reaches_a_compatible_or_local_server(env_headers):
    pytest.importorskip("anthropic")
    pytest.importorskip("openai")
    from opentine._cli_run_model import build_model
    from opentine.models.openai import OpenAI

    url, seen = env_headers
    _call(build_model("anthropic:claude-x", url, None))
    _call(build_model("vllm", url + "/v1", None))
    _call(build_model("groq", url + "/v1", "GROQ_API_KEY"))
    _call(OpenAI("gpt-x", base_url=url + "/v1"))
    assert len(seen) == 4
    for headers in seen:
        assert "x-portkey-api-key" not in headers
        assert "cf-aig-authorization" not in headers
        assert "openai-organization" not in headers
        assert "PORTKEY-FAKE-SECRET" not in str(headers)
        assert "CF-FAKE-SECRET" not in str(headers)
        assert "sk-proj-fake-first-party" not in str(headers)


def test_the_operators_env_gateway_keeps_its_custom_headers(env_headers, monkeypatch):
    pytest.importorskip("anthropic")
    pytest.importorskip("openai")
    from opentine.models.anthropic import Anthropic
    from opentine.models.openai import OpenAI

    url, seen = env_headers
    monkeypatch.setenv("ANTHROPIC_BASE_URL", url)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-operator-gateway-000")
    monkeypatch.setenv("OPENAI_BASE_URL", url + "/v1")
    monkeypatch.setenv("OPENAI_COMPAT_API_KEY", "gateway-key")
    _call(Anthropic("claude-x"))
    _call(OpenAI("gpt-x"))
    assert seen[0].get("x-portkey-api-key") == "PORTKEY-FAKE-SECRET"
    assert seen[1].get("cf-aig-authorization") == "Bearer CF-FAKE-SECRET"


def test_env_custom_headers_never_go_in_cleartext_to_another_machine(env_headers, monkeypatch):
    pytest.importorskip("anthropic")
    pytest.importorskip("openai")
    from opentine.models.anthropic import Anthropic
    from opentine.models.openai import OpenAI

    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://192.0.2.10:11434")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://192.0.2.10/v1")
    with pytest.raises(ValueError, match="cleartext"):
        Anthropic("claude-x")._get_client()
    with pytest.raises(ValueError, match="cleartext"):
        OpenAI("gpt-x", api_key="")._get_client()
    monkeypatch.setenv("OPENTINE_ALLOW_INSECURE_ENDPOINTS", "1")
    assert OpenAI("gpt-x", api_key="")._get_client() is not None


# --- final security pass #5: a provider name alone never books a call free ----


@pytest.mark.parametrize("model", ["gpt-oss:120b-cloud", "kimi-k3:cloud"])
@pytest.mark.parametrize("provider", ["ollama", "local-anthropic-compatible"])
def test_a_cloud_tagged_model_never_reprices_as_unmetered(provider, model):
    run = Run(id="p6")
    run.add_step(
        StepKind.model, {}, usage={"input": 2_000_000}, provider=provider, model_info=model
    )
    priced = price_run(run, effective_at="2026-10-14")
    assert priced.status_counts == {"unknown": 1}
    assert priced.unknown_models == (model,)


def test_a_recorded_verdict_decides_and_old_unmetered_runs_still_reprice_free():
    run = Run(id="p7")
    run.add_step(  # 0.9.2 capture: billing recorded unmetered
        StepKind.model,
        {},
        usage={"input": 10},
        provider="ollama",
        model_info="qwen3:8b",
        billing={"status": "unmetered", "amount_usd": "0"},
    )
    run.add_step(  # a record whose capture said something else
        StepKind.model,
        {},
        usage={"input": 10},
        provider="ollama",
        model_info="qwen3:8b",
        billing={"status": "unknown", "amount_usd": None},
    )
    priced = price_run(run, effective_at="2026-10-14")
    assert priced.status_counts == {"unmetered": 1, "unknown": 1}


def test_an_imported_local_provider_label_is_never_booked_free():
    from opentine._pricing_pass import price_events
    from opentine.trace.schema import TraceEvent

    imported = TraceEvent(
        kind="model",
        timestamp=1_791_000_000.0,
        trace_id="t",
        span_id="s",
        model="qwen3:8b",
        provider="ollama",
        usage={"input": 10, "output": 5},
    )
    (priced,) = price_events([imported], effective_at="2026-10-14")
    assert priced.billing["status"] == "unknown"


def test_pricing_and_the_ollama_adapter_agree_on_cloud_tags():
    from opentine._local_providers import cloud_model
    from opentine.models._ollama_host import cloud_model as adapter_cloud_model

    for model in ("qwen3:8b", "gpt-oss:120b-cloud", "x:cloud", "ft:gpt-4.1:acme::id", "plain"):
        assert cloud_model(model) == adapter_cloud_model(model)


# --- Final pass 5, #8: connection strings never reach a tool subprocess --------- #


def test_clean_env_scrubs_connection_strings_and_keyed_credentials(monkeypatch):
    from opentine.tools._process import clean_env

    leaked = {
        "ConnectionStrings__DefaultConnection": "Server=db;Database=app;User Id=sa;Password=Sup3r;",
        "APP_CONNECTIONSTRING": "Server=db;Integrated Security=true",
        "SPRING_DATASOURCE_URL": "jdbc:postgresql://db:5432/app?user=app&password=Sup3rJdbc",
        "ODBC_SETTINGS": "Driver={x};Server=db;Uid=u;Pwd=Sup3rOdbc;",
        "SERVICE_ENDPOINT": "https://api.example.com/v1?api_key=abc123",
    }
    kept = {"PATH": "/usr/bin", "DATABASE_HOST": "db", "APP_URL": "https://example.com/a?b=c"}
    monkeypatch.setattr(os, "environ", {**leaked, **kept})
    assert clean_env(True, ()) == kept
