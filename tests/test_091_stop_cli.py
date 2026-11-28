"""0.91: ``tine stop`` and the stop policy wired into ``tine record`` and the agent loop.

``tine record`` runs real child processes; the stop is issued by the child
itself, from another repository sharing the channel, so the order is fixed by
the child's own steps. The guard's clock is a fixed instant (monkeypatched),
never the wall.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import _stop_compliance, _stop_guard, _stop_policy, _stop_supervise, cli
from opentine.core import Run, StepKind
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import (
    FLEET,
    OPT,
    POLICY,
    RUNNER,
    STOPPER,
    Clock,
    fleet,
    keep_going,
    key_file,  # fmt: skip
)

CHILD = """\
import json, os, sys, urllib.error, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentine._stop_ops import issue_stop
from opentine.repo import Repo
Path(sys.argv[4]).write_bytes(b"started")
stopper = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[3]))
issue_stop(Repo.open(sys.argv[1]), Path(sys.argv[2]), "fleet-a", stopper, reason="halt",
           now_ms=int(sys.argv[5]))
base = os.environ["OPENAI_BASE_URL"]
while True:  # hostile: it keeps calling after every refusal until it is killed
    request = urllib.request.Request(base + "/chat/completions", data=b"{}",
                                     headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request)
    except urllib.error.HTTPError as exc:
        Path(sys.argv[4]).write_bytes(json.loads(exc.read())["error"]["code"].encode())
"""


def tine(*argv: str) -> int:
    try:
        cli.main([str(a) for a in argv])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    return 0


@pytest.fixture
def fixed(monkeypatch) -> Clock:
    clock = Clock()
    monkeypatch.setattr(_stop_guard, "_now_ms", clock)
    monkeypatch.setattr(_stop_supervise, "_ms", clock)
    return clock


def test_record_halts_a_hostile_child_when_another_repository_stops_the_fleet(
    tmp_path, fixed, capsys
):
    channel, (repo, other) = fleet(tmp_path, 2)
    keep_going(repo, channel, ["r"], fixed)
    script, marker = tmp_path / "child.py", tmp_path / "marker"
    script.write_bytes(CHILD.encode("utf-8"))
    code = tine("record", "--repo", Path(repo.path).parent, "--stop-run", "r", "--stop-key",
                key_file(tmp_path, RUNNER, "runner"), "--save", tmp_path / "out.tine",
                "--upstream", "openai=http://127.0.0.1:9", "--", sys.executable, script,
                Path(other.path).parent, channel, STOPPER, marker, fixed())  # fmt: skip
    assert code == 3
    # the child ran, and its first call after the stop killed it (or it was told and kept going)
    assert marker.read_bytes() in (b"started", b"stop.stopped")
    (record,) = _stop_compliance.held(repo)
    claim = repo.get(record).payload()["claim"]
    assert claim["code"] == "stop.stopped" and claim["forwarded_after_stop"] == 0
    assert claim["residual_processes"] == 0 and claim["refused_after_stop"] >= 1
    assert claim["compliant"] is True and claim["since_stop_ms"] == 0
    run = Run.load(tmp_path / "out.tine")
    assert run.metadata["record"]["stop"]["record"] == record


def test_record_refuses_to_start_without_a_fresh_proof_or_a_run_id(tmp_path, fixed):
    channel, (repo,) = fleet(tmp_path)
    marker = tmp_path / "marker"
    child = [sys.executable, "-c", f"open({marker.as_posix()!r}, 'w').close()"]
    base = ["record", "--repo", Path(repo.path).parent, "--save", tmp_path / "o.tine"]
    runner = key_file(tmp_path, RUNNER, "runner")
    assert tine(*base, "--stop-key", runner, "--", *child) == 3  # no --stop-run
    assert tine(*base, "--stop-run", "r", "--", *child) == 3  # no runner key
    assert tine(*base, "--stop-run", "r", "--stop-key", runner, "--", *child) == 3  # no proof
    keep_going(repo, channel, ["r"], fixed)
    fixed.advance(301)
    assert tine(*base, "--stop-run", "r", "--stop-key", runner, "--", *child) == 3  # stale
    assert not marker.exists()
    keep_going(repo, channel, ["r"], fixed)
    assert tine(*base, "--force", "--stop-run", "r", "--stop-key", runner, "--", *child) == 0
    assert marker.exists()


def test_record_without_a_policy_is_unchanged(tmp_path):
    from tests.stop_helpers import make_repo

    repo = make_repo(tmp_path / "plain")
    child = [sys.executable, "-c", "raise SystemExit(5)"]
    assert tine("record", "--repo", Path(repo.path).parent, "--save", tmp_path / "o.tine",
                "--", *child) == 5  # fmt: skip


class _LoopingModel:
    """Asks for one tool call per turn, forever."""

    name = "test/looping"

    async def complete(self, messages, tools=None, system=None):
        return {"text": "", "tool_calls": [{"name": "touch", "arguments": {}}]}


def test_the_agent_loop_checks_before_every_model_and_tool_call(tmp_path, fixed):
    from opentine._stop_runner import StopRunner
    from opentine.runtime import Agent
    from tests.stop_helpers import key

    channel, (repo,) = fleet(tmp_path)
    keep_going(repo, channel, ["r"], fixed)
    stop = StopRunner(repo, _stop_policy.load(repo), "r", key(RUNNER))
    touched = []

    def touch() -> str:
        """Touch."""
        touched.append(len(touched))
        if len(touched) == 2:
            fixed.advance(301)  # the proof goes stale during the second tool call
        return "ok"

    agent = Agent(model=_LoopingModel(), tools=[touch], max_steps=10)
    agent.stop_check = stop.check
    run = agent.run_sync("go")
    assert len(touched) == 2 and run.status.value == "failed"
    assert run.steps[-1].kind == StepKind.error and "stop.continue-stale" in json.dumps(
        run.steps[-1].error
    )
    assert stop.finish()["claim"]["residual_method"] == "in-process"


def test_stop_commands_issue_continue_report_and_refuse(tmp_path, fixed, capsys):
    from tests.stop_helpers import make_repo

    repo = make_repo(tmp_path / "r0")
    root, channel = Path(repo.path).parent, tmp_path / "ch"
    at = ["--at", "2026-12-01T09:00:00Z", "--json"]
    assert tine("stop", "init", "--channel", channel, "--fleet", FLEET, "--repo", root, *at) == 0
    init = json.loads(capsys.readouterr().out)
    assert init["policy"]["window_s"] == 300 and init["schema"] == "tine-cli-stop/1"
    assert tine("stop", "status", "--run", "r", "--repo", root, *at) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "stop.no-continue"
    for seed, want in ((OPT, 1), (POLICY, 0)):
        k = key_file(tmp_path, seed, seed[:2])
        assert tine("stop", "continue", "--channel", channel, "--fleet", FLEET, "--run", "r",
                    "--key", k, "--repo", root, *at) == want  # fmt: skip
        capsys.readouterr()
    assert tine("stop", "status", "--run", "r", "--repo", root, *at) == 0
    assert json.loads(capsys.readouterr().out)["proof"]["seq"] == 1
    k = key_file(tmp_path, STOPPER, "stopper")
    assert tine("stop", "issue", "--channel", channel, "--fleet", FLEET, "--key", k,
                "--reason", "enough", "--repo", root, *at) == 0  # fmt: skip
    capsys.readouterr()
    assert tine("stop", "status", "--repo", root, *at) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["code"] == "stop.stopped" and len(body["stops"]) == 1
    assert tine("stop", "compliance", "--repo", root, "--strict", *at) == 0
    assert json.loads(capsys.readouterr().out)["records"] == []
