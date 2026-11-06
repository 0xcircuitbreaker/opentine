"""0.39 (X21): assurance tiers T0..T3, ``tine proxy keygen``, ``--min-assurance``
and the proxy-versus-import divergence report."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402

from opentine import Run, RunStatus, StepKind, cli  # noqa: E402
from opentine._artifact_io import read_artifact_json  # noqa: E402
from opentine._assurance import key_paths, proxy_marker, witness_save  # noqa: E402
from opentine._timestamp_sidecar import bound_string  # noqa: E402
from opentine.kernel import canonical_json  # noqa: E402
from opentine.signing import generate_ed25519  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" in msg:
        result = {"content": [{"type": "text", "text": "ok"}]}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
        sys.stdout.flush()
"""


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _tine(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _json(monkeypatch, capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _tine(monkeypatch, *argv, "--json")
    return code, json.loads(capsys.readouterr().out)


def _transcript(path: Path, tool: str = "mcp__fake__echo") -> Path:
    base = {"sessionId": "s1", "timestamp": "2026-10-14T00:00:00Z"}
    call = {"type": "tool_use", "id": "t1", "name": tool, "input": {"x": 1}}
    lines = [
        {**base, "type": "user", "uuid": "u1", "message": {"role": "user", "content": "go"}},
        {**base, "type": "assistant", "uuid": "a1", "requestId": "r1",
         "message": {"id": "m1", "model": "m", "role": "assistant", "content": [call]}},
        {**base, "type": "user", "uuid": "u2", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}]}},
    ]  # fmt: skip
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


def _import(monkeypatch, room: Path, tool: str = "mcp__fake__echo") -> str:
    source = _transcript(room / f"{tool}.jsonl", tool)
    argv = ["import", str(source), "--format", "claude-code-transcript", "--save", "imp.tine"]
    assert _tine(monkeypatch, *argv, "--force") == 0
    return "imp.tine"


def _proxied(room: Path) -> str:
    """A real ``tine mcp-proxy`` session: one tools/call to ``echo``."""
    (room / "server.py").write_text(FAKE_SERVER, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    argv = [sys.executable, "-m", "opentine.cli", "mcp-proxy", "--save", str(room / "px.tine")]
    argv += ["--", sys.executable, str(room / "server.py")]
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "echo", "arguments": {"x": 1}}}  # fmt: skip
    done = subprocess.run(
        argv, input=(json.dumps(message) + "\n").encode(), capture_output=True, env=env, cwd=room
    )
    assert done.returncode == 0, done.stderr
    return "px.tine"


def _proxy_run(path: Path) -> Path:
    run = Run(model_info="m", user_prompt="p")
    run.metadata["capture"] = proxy_marker("mcp-proxy")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    witness_save(run, path)
    return path


def test_an_import_reports_t0_and_a_t2_floor_exits_4(room, monkeypatch, capsys):
    target = _import(monkeypatch, room)
    code, report = _json(monkeypatch, capsys, "verify", target)
    assert code == 0
    assert report["assurance"]["claimed"] == "T0"
    assert report["assurance"]["verified"] == "T0"
    code, report = _json(monkeypatch, capsys, "verify", target, "--min-assurance", "T2")
    assert code == 4 and report["assurance"]["verified"] == "T0"
    assert _tine(monkeypatch, "verify", target, "--min-assurance", "T2") == 4
    assert _tine(monkeypatch, "verify", target, "--min-assurance", "T0") == 0
    code, shown = _json(monkeypatch, capsys, "show", target)
    assert shown["assurance"]["verified"] == "T0"


def test_proxy_keygen_writes_a_separate_key_and_refuses_to_clobber(room, monkeypatch, capsys):
    code, out = _json(monkeypatch, capsys, "proxy", "keygen")
    assert code == 0 and out["fingerprint"].startswith("sha256:")
    private, public = key_paths()
    assert private.is_file() and public.is_file()
    assert "agent-keys" not in str(private)
    assert _tine(monkeypatch, "proxy", "keygen") == 1
    assert _tine(monkeypatch, "proxy", "keygen", "--force") == 0


def test_an_mcp_proxy_capture_signed_with_the_proxy_key_reports_t2(room, monkeypatch, capsys):
    assert _tine(monkeypatch, "proxy", "keygen") == 0
    target = _proxied(room)
    code, report = _json(monkeypatch, capsys, "verify", target, "--min-assurance", "T2")
    assert code == 0, report
    assert report["assurance"]["claimed"] == "T2"
    assert report["assurance"]["verified"] == "T2"
    assert report["assurance"]["witness"].startswith("sha256:")
    code, offline = _json(monkeypatch, capsys, "verify", target, "--offline")
    assert code == 0 and offline["assurance"]["verified"] == "T2"  # MCP verify_run's report
    assert _tine(monkeypatch, "verify", target, "--min-assurance", "T3") == 4


def test_an_unwitnessed_proxy_capture_is_t0(room, monkeypatch, capsys):
    target = _proxied(room)  # no proxy key: the run says T2, nothing proves it
    code, report = _json(monkeypatch, capsys, "verify", target, "--min-assurance", "T2")
    assert code == 4
    assert (report["assurance"]["claimed"], report["assurance"]["verified"]) == ("T2", "T0")


def test_a_wrong_key_drops_the_run_to_t0(room, monkeypatch, capsys):
    assert _tine(monkeypatch, "proxy", "keygen") == 0
    path = _proxy_run(room / "run.tine")
    assert _tine(monkeypatch, "proxy", "keygen", "--force") == 0  # the trusted key changes
    code, report = _json(monkeypatch, capsys, "verify", str(path))
    assert code == 0 and report["assurance"]["verified"] == "T0"
    # ...until that old key is trusted explicitly.
    seed, public = generate_ed25519()
    (room / "other.pub").write_text(public + "\n", encoding="ascii")
    code, report = _json(monkeypatch, capsys, "verify", str(path), "--proxy-pubkey", "other.pub")
    assert report["assurance"]["verified"] == "T0"


def test_a_forged_proxy_signature_drops_the_run_to_t0(room, monkeypatch, capsys):
    assert _tine(monkeypatch, "proxy", "keygen") == 0
    path = _proxy_run(room / "run.tine")
    assert _json(monkeypatch, capsys, "verify", "run.tine")[1]["assurance"]["verified"] == "T2"
    data = read_artifact_json(path)
    block = data["signatures"][0]
    block["value"] = ("0" if block["value"][0] != "0" else "1") + block["value"][1:]
    path.write_bytes(canonical_json(data))
    code, report = _json(monkeypatch, capsys, "verify", "run.tine", "--min-assurance", "T1")
    assert code == 4 and report["assurance"]["verified"] == "T0"


def test_a_proxy_key_that_is_also_an_agent_key_is_not_a_witness(room, monkeypatch, capsys):
    assert _tine(monkeypatch, "proxy", "keygen") == 0
    path = _proxy_run(room / "run.tine")
    agents = key_paths()[1].parent.parent / "agent-keys"
    agents.mkdir(parents=True)
    (agents / "rogue.pub").write_bytes(key_paths()[1].read_bytes())
    code, report = _json(monkeypatch, capsys, "verify", str(path))
    assert report["assurance"]["verified"] == "T0"


def test_t3_is_t2_plus_a_verified_timestamp(room, monkeypatch, capsys):
    from tests.test_timestamp_offline_0_31 import pki, token

    assert _tine(monkeypatch, "proxy", "keygen") == 0
    path = _proxy_run(room / "run.tine")
    ca, tsa, key = pki()
    bound = bound_string(Run.verify_integrity(path)).encode()
    (room / "t.tsr").write_bytes(token(bound, tsa, key))
    (room / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    assert _tine(monkeypatch, "timestamp", "attach", "run.tine", "t.tsr") == 0
    floor = ("--min-assurance", "T3")
    code, report = _json(monkeypatch, capsys, "verify", "run.tine", *floor, "--tsa-roots", "ca.pem")
    assert code == 0 and report["assurance"]["verified"] == "T3"
    assert _tine(monkeypatch, "verify", "run.tine", *floor) == 4  # no TSA root: unproven
    code, report = _json(monkeypatch, capsys, "verify", "run.tine", "--offline", "--tsa-roots",
                         "ca.pem")  # fmt: skip
    assert code == 0 and report["assurance"]["verified"] == "T3"


def test_divergence_report_compares_the_proxy_with_the_import(room, monkeypatch, capsys):
    assert _tine(monkeypatch, "proxy", "keygen") == 0
    proxied = _proxied(room)
    _import(monkeypatch, room)
    code, report = _json(monkeypatch, capsys, "verify", proxied, "--compare-capture", "imp.tine")
    assert code == 0 and report["consistent"], report
    assert report["witness"]["assurance"]["verified"] == "T2"
    _import(monkeypatch, room, tool="mcp__fake__delete_everything")
    code, report = _json(monkeypatch, capsys, "verify", "imp.tine", "--compare-capture", proxied)
    assert code == 4 and not report["consistent"]
    assert report["witness"]["path"].endswith("px.tine")  # the witnessed run leads
    (item,) = report["divergences"]
    assert item["kind"] == "changed"
    assert item["witness"]["name"] == "echo" and item["other"]["name"] == "delete_everything"
