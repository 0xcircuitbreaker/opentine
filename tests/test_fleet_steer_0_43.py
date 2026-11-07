"""0.43 mailbox and steering, and ``tine fleet resume|logs|send``.

``tine fleet send`` queues a message as an ``opentine-coord/1`` mailbox
annotation; the member's ``opentine-hook/1`` turn callback delivers it once,
records it as a ``steer`` step, and (Claude Code) injects it as the ``Stop``
hook's block reason.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from opentine import cli
from opentine._hook_protocol import PROTOCOL, handle, run_capture
from opentine.coord import _mailbox
from opentine.parallel._state import State

FLEET = "0123456789ab"


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def _repo(tmp_path) -> Path:
    from opentine import _porcelain_config as porcelain
    from opentine.repo import Repo

    root = tmp_path / "repo"
    repo = Repo.init(root)
    porcelain.save(Path(repo.path), {"remotes": {}, "config": {"hooks.capture": "true"}})
    return root


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_mailbox_send_and_take_deliver_each_message_once(tmp_path):
    from opentine.repo import Repo

    repo = Repo.open(_repo(tmp_path))
    first = _mailbox.send(repo, FLEET, "Coder-0", "focus on tests")
    second = _mailbox.send(repo, FLEET, "coder-0", "and docs")
    assert (first["id"], second["id"]) == (1, 2)
    assert [m["text"] for m in _mailbox.take(repo, FLEET, "coder-0")] == [
        "focus on tests",
        "and docs",
    ]
    assert _mailbox.take(repo, FLEET, "coder-0") == []
    assert _mailbox.send(repo, FLEET, "coder-0", "later")["id"] == 3
    assert repo.read_ref(_mailbox.ref_name(FLEET, "coder-0")).startswith("annotation:")


def test_a_sent_message_is_injected_at_turn_end_and_recorded_as_a_steer_step(
    tmp_path, monkeypatch, capsys
):
    root = _repo(tmp_path)
    argv = ("--member", "coder-0", "--message", "stop and write tests", "--repo", str(root))
    code, out = _tine(capsys, "fleet", "send", FLEET, *argv, "--json")
    assert code == 0 and out["mailbox"] == f"coord/mailbox/{FLEET}/coder-0"
    monkeypatch.setenv("OPENTINE_FLEET_ID", FLEET)
    monkeypatch.setenv("OPENTINE_FLEET_MEMBER", "coder-0")
    event = {"protocol": PROTOCOL, "event": "turn_end", "session": "s", "message": "done"}
    response = handle(json.dumps(event).encode(), str(root), "generic")
    assert response["ok"] and response["steer"] == ["stop and write tests"]
    from opentine.repo import Repo

    repo = Repo.open(root)
    steps = [
        repo.get(oid).payload()
        for oid in repo.get(repo.read_ref(response["ref"])).payload()["events"]
    ]
    assert [s["actor"] for s in steps] == ["generic", "steer"]
    assert steps[1]["attributes"]["opentine.steer.id"] == 1
    again = handle(json.dumps(event).encode(), str(root), "generic")
    assert "steer" not in again  # delivered exactly once

    _mailbox.send(repo, FLEET, "coder-0", "one more thing")
    out = io.StringIO()
    stop = {"hook_event_name": "Stop", "session_id": "c", "last_assistant_message": "ok"}
    run_capture(str(root), "claude-code", io.BytesIO(json.dumps(stop).encode()), out)
    assert json.loads(out.getvalue()) == {"decision": "block", "reason": "one more thing"}
    out = io.StringIO()
    run_capture(str(root), "claude-code", io.BytesIO(json.dumps(stop).encode()), out)
    assert json.loads(out.getvalue()) == {"suppressOutput": True}


def test_no_fleet_environment_means_no_delivery(tmp_path, monkeypatch):
    from opentine.repo import Repo

    root = _repo(tmp_path)
    _mailbox.send(Repo.open(root), FLEET, "coder-0", "hello")
    monkeypatch.delenv("OPENTINE_FLEET_ID", raising=False)
    event = {"protocol": PROTOCOL, "event": "turn_end", "session": "s", "message": "x"}
    assert "steer" not in handle(json.dumps(event).encode(), str(root), "generic")
    assert len(_mailbox.pending(Repo.open(root), FLEET, "coder-0")) == 1


def _fleet(tmp_path, code: str) -> Path:
    path = tmp_path / "fleet.toml"
    path.write_text(f"""
[fleet]
name = "f"
layout = "fan-out"

[[agents]]
name = "coder"
argv = {json.dumps([sys.executable, "-c", code])}
count = 2
""")
    return path


def test_fleet_logs_and_resume_run_only_unfinished_members(tmp_path, capsys):
    path = _fleet(
        tmp_path, "print('hello from', __import__('os').environ['OPENTINE_FLEET_MEMBER'])"
    )
    code, out = _tine(capsys, "fleet", "up", str(path), "--trust", "--json")
    assert code == 0
    fleet_id, directory = out["id"], str(tmp_path / ".tine_fleet")
    code, out = _tine(capsys, "fleet", "logs", fleet_id, "--dir", directory, "--json")
    assert code == 0 and "hello from coder-1" in out["logs"]["1"]
    state = State.load(Path(directory), fleet_id)
    state.update("1", {}, status="pending")  # as if its supervisor was killed mid-run
    code, out = _tine(capsys, "fleet", "resume", str(path), "--id", fleet_id, "--json")
    assert code == 0 and [m["status"] for m in out["members"]] == ["ok", "ok"]
    path.write_text(path.read_text().replace('name = "f"', 'name = "g"'))
    code, _ = _tine(capsys, "fleet", "resume", str(path), "--id", fleet_id, "--trust", "--json")
    assert code != 0  # another manifest cannot take over the record
