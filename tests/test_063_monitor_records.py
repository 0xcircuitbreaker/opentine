"""0.63: ``tine monitor backtest --repo --run`` reads the gate's held verdict records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _schemas, cli
from opentine._mcp_proxy_record import McpRecorder
from opentine._monitor_gate import Gate
from opentine._monitor_mcp import McpGuard
from opentine._monitors import parse
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

KEY = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
SPEC = {"monitor": "candidate", "kind": "rule",
        "rules": [{"tool": "shell", "pattern": "rm -rf", "score": 0.95}],
        "actions": [{"at": 0.5, "action": "flag"}, {"at": 0.9, "action": "block"}]}  # fmt: skip


def _shell(ident: int, cmd: str) -> bytes:
    body = {"jsonrpc": "2.0", "id": ident, "method": "tools/call",
            "params": {"name": "shell", "arguments": {"cmd": cmd}}}  # fmt: skip
    return (json.dumps(body) + "\n").encode("utf-8")


def _gate(repo: Repo, mode: str) -> McpGuard:
    config = parse({"version": 1, "mode": mode, "deadline_ms": 600000,
                    "monitor": {"id": "rules", "kind": "rule", "threshold": 0.5,
                                "action": "block",
                                "rules": [{"tool": "shell", "pattern": "rm -rf|curl",
                                           "score": 0.9}]}})  # fmt: skip
    return McpGuard(Gate(config, repo=repo, key=KEY))


def _record(guard: McpGuard, path: Path, lines: list[bytes]) -> None:
    recorder = McpRecorder(path, ["x"], "stdio")
    for raw in lines:
        forward, back, blocked = guard.check(raw)
        recorder.feed("client", blocked or forward or raw)
        if back:
            recorder.feed("server", back)
    guard.close()  # advisory scores after relaying: wait for every verdict
    recorder.close(0)


def _backtest(capsys, tmp: Path, *runs: str) -> tuple[int, dict]:
    (tmp / "spec.json").write_bytes(json.dumps(SPEC).encode("utf-8"))
    argv = ["monitor", "backtest", (tmp / "spec.json").as_posix(), "--repo",
            (tmp / "r").as_posix(), "--json"]  # fmt: skip
    for run in runs:
        argv += ["--run", (tmp / run).as_posix()]
    code = 0
    try:
        cli.main(argv)
    except SystemExit as exc:
        code = int(exc.code or 0)
    out = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(out) == [], out
    return code, out


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _pin(repo: Repo) -> None:
    pub = KEY.public_key().public_bytes_raw().hex()
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\nmonitor = ["{pub}"]\n'.encode("ascii")
    )
    pin_roles(repo.path)


def test_backtest_reads_held_gate_verdicts_only_when_pinned(repo, tmp_path, capsys):
    guard = _gate(repo, "gate")
    _record(guard, tmp_path / "run.tine", [_shell(1, "rm -rf /"), _shell(2, "ls"),
                                            _shell(3, "curl x")])  # fmt: skip
    code, out = _backtest(capsys, tmp_path, "run.tine")
    assert code == 0
    counts = out["counts"]
    assert counts["steps"] == 3 and counts["unverified_verdicts"] == 2
    assert counts["no_online_verdict"] == 3
    _pin(repo)
    code, out = _backtest(capsys, tmp_path, "run.tine")
    counts = out["counts"]
    assert counts["unverified_verdicts"] == 0 and counts["other_monitor"] == 2
    # The gate blocked curl; the candidate allows it: the diff shows the change.
    changed = [(d["online_action"], d["replay_action"]) for d in out["diff"]]
    assert changed == [("block", "allow")]


def test_a_step_edited_after_its_verdict_is_not_matched(repo, tmp_path, capsys):
    _pin(repo)
    guard = _gate(repo, "gate")
    forward, back, blocked = guard.check(_shell(1, "rm -rf /"))
    edited = json.loads(blocked)
    edited["params"]["arguments"] = {"cmd": "rm -rf /home"}
    recorder = McpRecorder(tmp_path / "bad.tine", ["x"], "stdio")
    recorder.feed("client", json.dumps(edited).encode("utf-8") + b"\n")
    recorder.feed("server", back)
    recorder.close(0)
    code, out = _backtest(capsys, tmp_path, "bad.tine")
    assert out["counts"]["input_mismatch"] == 1 and out["counts"]["other_monitor"] == 0


def test_advisory_verdicts_on_relayed_calls_are_found_by_their_action(repo, tmp_path, capsys):
    _pin(repo)
    _record(_gate(repo, "advisory"), tmp_path / "adv.tine", [_shell(1, "rm -rf /")])
    code, out = _backtest(capsys, tmp_path, "adv.tine")
    assert out["counts"]["other_monitor"] == 1 and out["diff"] == []


def test_repo_and_runs_files_are_exclusive(repo, tmp_path, capsys):
    (tmp_path / "x.jsonl").write_bytes(b"")
    (tmp_path / "spec.json").write_bytes(json.dumps(SPEC).encode("utf-8"))
    with pytest.raises(SystemExit) as caught:
        cli.main(["monitor", "backtest", (tmp_path / "spec.json").as_posix(), "--repo",
                  (tmp_path / "r").as_posix()])  # fmt: skip
    assert caught.value.code not in (0, None)
