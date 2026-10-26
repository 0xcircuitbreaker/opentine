"""0.13 F5: ``fleet.toml`` trust, layouts, and ``tine fleet up/status/stop/cost``.

Members are ``sys.executable`` one-liners, so no external binary is shelled.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path

import pytest

from opentine import cli
from opentine.fleet import _manifest, _runner
from opentine.parallel._state import State


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def _py(code: str) -> str:
    return json.dumps([sys.executable, "-c", code])


COST = "import os; open(os.environ['OPENTINE_FANOUT_COST_FILE'], 'w').write('{cost}')"


def _write(tmp_path, body: str) -> Path:
    path = tmp_path / "fleet.toml"
    path.write_text(body)
    return path


def _fanout(tmp_path, cost="0.25", count=3):
    return _write(
        tmp_path,
        f"""
[fleet]
name = "review"
layout = "fan-out"
jobs = 2

[[agents]]
name = "coder"
argv = {_py(COST.format(cost=cost))}
count = {count}
""",
    )


def test_an_untrusted_manifest_is_refused_and_any_edit_revokes_trust(tmp_path):
    path = _fanout(tmp_path)
    with pytest.raises(SystemExit):
        cli.main(["fleet", "up", str(path)])
    assert not (tmp_path / ".tine_fleet").exists()  # nothing ran, nothing recorded
    assert _manifest.load(path, trust_now=True).digest
    assert _manifest.load(path).name == "review"
    path.write_text(path.read_text().replace("count = 3", "count = 4"))
    with pytest.raises(ValueError, match="not trusted"):
        _manifest.load(path)


def test_fleet_up_runs_members_and_cost_is_the_sum(tmp_path, capsys):
    path = _fanout(tmp_path)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["fleet", "up", str(path), "--trust"])
    assert exit_.value.code == 0
    directory = tmp_path / ".tine_fleet"
    (state_file,) = directory.glob("*.json")
    state = State.load(directory, state_file.stem)
    assert [m["status"] for m in state.data["members"]] == ["ok"] * 3
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.main(["fleet", "cost", state.id, "--dir", str(directory), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert Decimal(report["cost_usd"]) == Decimal("0.75") and report["unknown_members"] == 0
    with pytest.raises(SystemExit):
        cli.main(["fleet", "status", "--dir", str(directory), "--json"])
    (fleet,) = json.loads(capsys.readouterr().out)["fleets"]
    assert fleet["name"] == "review" and len(fleet["members"]) == 3


def test_supervisor_layout_starts_the_supervisor_first_and_links_workers(tmp_path):
    ref = "agt_" + "a" * 32
    dump = ("import os, sys; open(sys.argv[1], 'w').write(os.environ.get('OPENTINE_FLEET_ROLE','') "
            "+ ' ' + os.environ.get('OPENTINE_AGENT_PARENT', '-'))")  # fmt: skip
    argv = lambda name: json.dumps([sys.executable, "-c", dump, str(tmp_path / name)])  # noqa: E731
    path = _write(
        tmp_path,
        f"""
[fleet]
name = "team"
layout = "supervisor"
jobs = 1

[[agents]]
name = "worker"
argv = {argv("w.txt")}

[[agents]]
name = "lead"
role = "supervisor"
agent_ref = "{ref}"
argv = {argv("s.txt")}
""",
    )
    fleet = _manifest.load(path, trust_now=True)
    assert [m["vary"]["agent"] for m in _runner.plan(fleet)] == ["lead", "worker"]
    state = _runner.create(fleet)
    assert _runner.run(fleet, state) == 0
    assert (tmp_path / "s.txt").read_text() == "supervisor -"
    assert (tmp_path / "w.txt").read_text() == f"worker {ref}"


@pytest.mark.parametrize(
    "agents",
    [
        'name = "a"\nargv = "rm -rf /"',  # a shell string, not a list
        'name = "a"\nargv = ["--evil"]',  # an option, not a program
        'name = "a"\nargv = ["x\\u0000"]',
        'name = "A b"\nargv = ["x"]',
        'name = "a"\nargv = ["x"]\ncwd = "../../etc"',
        'name = "a"\nargv = ["x"]\nenv = ["BAD-NAME"]',
        'name = "a"\nargv = ["x"]\ncount = 0',
        'name = "a"\nargv = ["x"]\nrole = "supervisor"',  # fan-out has workers only
        'name = "a"\nargv = ["x"]\nshell = true',
    ],
)
def test_hostile_manifests_are_refused(tmp_path, agents):
    raw = f'[fleet]\nname = "f"\n\n[[agents]]\n{agents}\n'.encode()
    with pytest.raises(ValueError):
        _manifest.parse(raw, tmp_path / "fleet.toml")


def test_members_get_only_allowlisted_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "hunter2")
    monkeypatch.setenv("NAMED_KEY", "ok")
    dump = "import os, sys, json; open(sys.argv[1], 'w').write(json.dumps(dict(os.environ)))"
    out = tmp_path / "env.json"
    path = _write(
        tmp_path,
        f"""
[fleet]
name = "envcheck"
env = ["NAMED_KEY"]

[[agents]]
name = "a"
argv = {json.dumps([sys.executable, "-c", dump, str(out)])}
""",
    )
    fleet = _manifest.load(path, trust_now=True)
    assert _runner.run(fleet, _runner.create(fleet)) == 0
    env = json.loads(out.read_text())
    assert env.get("NAMED_KEY") == "ok" and "SECRET_TOKEN" not in env


def test_argv_reaches_members_literally(tmp_path):
    out = tmp_path / "argv.json"
    hostile = "$(touch pwned); `id` && echo {run} > x"
    code = "import sys, json; open(sys.argv[1], 'w').write(json.dumps(sys.argv[2:]))"
    path = _write(
        tmp_path,
        f"""
[fleet]
name = "argv"

[[agents]]
name = "a"
argv = {json.dumps([sys.executable, "-c", code, str(out), hostile])}
""",
    )
    fleet = _manifest.load(path, trust_now=True)
    assert _runner.run(fleet, _runner.create(fleet)) == 0
    assert json.loads(out.read_text()) == [hostile]
    assert not (tmp_path / "pwned").exists()


def test_stop_kills_running_members(tmp_path):
    path = _write(
        tmp_path,
        f"""
[fleet]
name = "sleepy"

[[agents]]
name = "a"
count = 2
argv = {_py("import time; time.sleep(120)")}
""",
    )
    fleet = _manifest.load(path, trust_now=True)
    state = _runner.create(fleet)
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(_runner.run(fleet, state, poll=0.05)))
    started = time.monotonic()
    thread.start()
    time.sleep(0.5)
    _runner.request_stop(state.directory, state.id)
    thread.join(timeout=30)
    assert not thread.is_alive() and result == [1]
    assert time.monotonic() - started < 30
    statuses = {m["status"] for m in State.load(state.directory, state.id).data["members"]}
    assert statuses <= {"stopped", "skipped"}


def test_stop_needs_a_known_fleet_id(tmp_path):
    with pytest.raises(ValueError):
        _runner.request_stop(tmp_path, "../../etc")


def test_dry_run_lists_members_without_trust_or_running(tmp_path, capsys):
    path = _fanout(tmp_path, count=2)
    with pytest.raises(SystemExit) as exit_:
        cli.main(["fleet", "up", str(path), "--dry-run"])
    assert exit_.value.code == 0 and "coder" in capsys.readouterr().out
    assert not (tmp_path / ".tine_fleet").exists()


def test_fleet_status_and_cost_escape_member_text(tmp_path, capsys):
    from opentine.parallel._executor import read_cost

    hostile = tmp_path / "cost.txt"
    hostile.write_bytes(b"1\x1b[2J")
    assert read_cost(hostile) == "NaN"  # only a number is ever stored
    hostile.write_bytes(b" 0.125\n")
    assert read_cost(hostile) == "0.125"
    path = _fanout(tmp_path, count=1)
    with pytest.raises(SystemExit):
        cli.main(["fleet", "up", str(path), "--trust"])
    directory = tmp_path / ".tine_fleet"
    (state_file,) = directory.glob("*.json")
    data = json.loads(state_file.read_text())  # e.g. a state file committed to a clone
    data["members"][0]["vary"]["agent"] = "\x1b]0;PWNED\x07\x1b[31mRED"
    data["members"][0]["cost"] = "1\x1b[2J"
    state_file.write_text(json.dumps(data))
    capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.main(["fleet", "status", "--dir", str(directory)])
    out = capsys.readouterr().out
    assert "RED" in out and "\x1b" not in out and "\x07" not in out
