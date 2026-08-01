"""``tine replay --harness ... --verify``: the real nondeterminism gate.

Cache-mode verification (``tests/test_cli_replay_verify.py``) proves a replay of
*recorded* steps round-trips; it cannot prove anything about an agent that is
executed again, because nothing is executed. This module does: it stands a
shell script in for an agent CLI, records a run through the generic harness,
and then asks ``--verify`` to re-execute it **twice** and compare the two
artifacts. A script that prints fixed output must be reported as reproduced; a
script that prints a different line each time must be reported as drift and
must exit 1. That is the only shape of test that can fail when an agent is
nondeterministic, which is what the claim is about.

Everything here therefore spawns a real external program. Per the shelling
contract in ``tests/test_release_audit_round11_misc.py`` the module is declared
in ``BINARY_DEPENDENT_TEST_MODULES`` and skips as a whole when ``sh`` is not on
PATH, so an sdist validated on a machine without a POSIX shell stays green.
Cache-mode verification, which shells nothing, remains the default CI gate.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from opentine import Run, cli

SHELL = shutil.which("sh")
pytestmark = pytest.mark.skipif(
    SHELL is None or sys.platform == "win32",
    reason=(
        "the stand-in agent is a POSIX shell script; sh is required, and Windows sh "
        "(Git Bash) does not run it with a Windows script path reliably. The verify "
        "feature is OS-agnostic and cache-mode verification covers every platform"
    ),
)

#: Two JSONL events, byte-identical on every invocation.
STABLE = """#!/bin/sh
printf '%s\\n' '{"type":"think","text":"planning"}' '{"type":"done","text":"finished"}'
"""

#: The same two events, but the first carries a counter that advances per run.
DRIFTING = """#!/bin/sh
count=$(cat COUNTER 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > COUNTER
printf '%s\\n' "{\\"type\\":\\"think\\",\\"text\\":\\"attempt $count\\"}" \\
    '{"type":"done","text":"finished"}'
"""


def _script(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body.replace("COUNTER", str(directory / "counter")), encoding="utf-8")
    return path


def _emits(script: Path) -> list[str]:
    """Run the stand-in agent directly; the fixture must be valid before opentine is blamed."""
    result = subprocess.run(
        ["sh", str(script), "a task"], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.splitlines() if line.strip()]


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _record(monkeypatch, capsys, workspace: Path, script: Path) -> Path:
    """Record a source run through the stand-in agent, exactly as a user would."""
    source = workspace / "recorded.tine"
    code, _ = _invoke(
        monkeypatch,
        capsys,
        "run",
        "--harness",
        "generic",
        "--harness-command",
        f"sh {script}",
        "--prompt",
        "a task",
        "--save",
        str(source),
    )
    assert code == 0
    return source


def _verify(monkeypatch, capsys, script: Path, source: Path, *extra: str) -> tuple[int, str]:
    return _invoke(
        monkeypatch,
        capsys,
        "replay",
        str(source),
        "--harness",
        "generic",
        "--harness-command",
        f"sh {script}",
        "--prompt",
        "a task",
        "--verify",
        *extra,
    )


def test_the_stand_in_agents_are_what_this_module_claims(workspace):
    """Guard the fixtures: one script is deterministic, the other is not."""
    stable = _script(workspace, "stable.sh", STABLE)
    drifting = _script(workspace, "drifting.sh", DRIFTING)

    assert _emits(stable) == _emits(stable)
    first, second = _emits(drifting), _emits(drifting)
    assert first != second and len(first) == len(second) == 2


def test_a_deterministic_agent_reruns_reproduced(workspace, monkeypatch, capsys):
    script = _script(workspace, "stable.sh", STABLE)
    source = _record(monkeypatch, capsys, workspace, script)

    code, out = _verify(monkeypatch, capsys, script, source, "--json")

    verdict = json.loads(out)
    assert (code, verdict["ok"]) == (0, True), verdict
    assert verdict["mode"] == "rerun"
    assert verdict["structural_drift"] == []
    # Two executions are two acts: distinct 64-hex ids, never a name spliced from
    # the source run id.
    assert verdict["replay_id"] != verdict["second_id"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", verdict[key]) for key in ("replay_id", "second_id"))
    assert verdict["identity_ok"] is True
    assert verdict["fork_point"] is None and verdict["reused_steps"] is None


def test_a_nondeterministic_agent_is_reported_as_drift_and_exits_one(
    workspace, monkeypatch, capsys
):
    script = _script(workspace, "drifting.sh", DRIFTING)
    source = _record(monkeypatch, capsys, workspace, script)

    code, out = _verify(monkeypatch, capsys, script, source, "--json")

    verdict = json.loads(out)
    assert (code, verdict["ok"]) == (1, False), verdict
    assert verdict["structural_drift"], "the counter changed the recorded text"
    assert any("inputs" in entry for entry in verdict["structural_drift"])


def test_ignore_cost_drift_does_not_excuse_a_nondeterministic_agent(workspace, monkeypatch, capsys):
    script = _script(workspace, "drifting.sh", DRIFTING)
    source = _record(monkeypatch, capsys, workspace, script)

    code, _ = _verify(monkeypatch, capsys, script, source, "--ignore-cost-drift")

    assert code == 1


@pytest.mark.parametrize("body", [STABLE, DRIFTING], ids=["stable", "drifting"])
def test_harness_verification_writes_nothing_without_save(workspace, monkeypatch, capsys, body):
    script = _script(workspace, "agent.sh", body)
    source = _record(monkeypatch, capsys, workspace, script)
    runs = workspace / ".tine_runs"
    shutil.rmtree(runs, ignore_errors=True)

    _verify(monkeypatch, capsys, script, source)

    assert not runs.exists() or list(runs.glob("*")) == []
    assert sorted(path.name for path in workspace.glob("*.tine")) == ["recorded.tine"]


def test_save_keeps_the_artifact_that_was_verified(workspace, monkeypatch, capsys):
    script = _script(workspace, "stable.sh", STABLE)
    source = _record(monkeypatch, capsys, workspace, script)
    output = workspace / "rerun.tine"

    code, out = _verify(monkeypatch, capsys, script, source, "--json", "--save", str(output))

    verdict = json.loads(out)
    assert (code, verdict["ok"]) == (0, True)
    kept = Run.load(output)
    # The saved bytes are the artifact the verdict describes, not a third execution.
    assert kept.id == verdict["replay_id"] != Run.load(source).id
    assert [step.kind.value for step in kept.steps] == ["model", "model", "think", "think", "done"]


def test_a_harness_that_cannot_start_exits_one_without_a_verdict(workspace, monkeypatch, capsys):
    script = _script(workspace, "stable.sh", STABLE)
    source = _record(monkeypatch, capsys, workspace, script)
    before = set(Path(tempfile.gettempdir()).glob("tine-verify-*"))

    code, out = _invoke(
        monkeypatch,
        capsys,
        "replay",
        str(source),
        "--harness",
        "generic",
        "--harness-command",
        str(workspace / "no-such-agent"),
        "--prompt",
        "a task",
        "--verify",
        "--json",
    )

    assert code == 1
    assert "Harness replay failed" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
    # The temporary workspace is removed even when the check dies mid-execution.
    assert set(Path(tempfile.gettempdir()).glob("tine-verify-*")) - before == set()
