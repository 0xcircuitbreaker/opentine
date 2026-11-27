"""0.85: the oversight machinery is protected by default, and env switches count as edits."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from opentine import Run
from opentine._containment_detect import PATTERNS
from opentine._integrity import check, parse
from opentine._integrity_defaults import env_touches, merged, pin, recorded
from opentine._integrity_run import LIST, check_run
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_060_integrity import _cli, _store, _tool
from tests.test_060_integrity import room as room  # noqa: F401 - the signed-list fixture

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")
MODIFIED = "fail:protected-surface-modified"


def _codes(root: Path, run: Run) -> list[tuple[str, str]]:
    row = check_run(root, _store(root, run))
    return [(f["code"], f["path"]) for f in row["findings"]]


def test_removing_the_hook_from_agent_settings_is_a_protected_edit(room: Path):  # noqa: F811
    run = Run(id="unhook")
    _tool(run, "Edit", file_path=".claude/settings.json", old_string='"hooks"', new_string="")
    assert (MODIFIED, ".claude/settings.json") in _codes(room, run)


@pytest.mark.parametrize("command", [
    "export OPENTINE_HOOK=0 && pytest",
    "OPENTINE_NO_MONITOR=1 python loop.py",
    "unset TINE_MONITOR_KEY",
    "python -c \"import os; os.environ['OPENTINE_HOOK']='0'\"",
])  # fmt: skip
def test_setting_a_monitoring_variable_is_a_protected_edit(room: Path, command):  # noqa: F811
    run = Run(id="env")
    _tool(run, "Bash", command=command)
    found = _codes(room, run)
    assert any(c == MODIFIED and p.startswith("env:") for c, p in found), found


def test_other_variables_and_plain_commands_are_not_flagged(room: Path):  # noqa: F811
    run = Run(id="benign-env")
    _tool(run, "Bash", command="export PYTHONPATH=src && LR=0.1 python train.py")
    assert _codes(room, run) == []
    assert env_touches("echo $OPENTINE_HOOK") == []


def test_a_monitor_config_read_is_advisory_and_never_blocks(room: Path):  # noqa: F811
    run = Run(id="peek")
    _tool(run, "Read", file_path=".tine/monitors.toml")
    row = check_run(room, _store(room, run))
    assert row["ok"] and [f["code"] for f in row["findings"]] == ["advisory:protected-read"]
    assert not check_run(room, _store(room, run), strict=True)["ok"]


def test_a_default_pin_catches_an_edit_made_outside_any_tool_call(room: Path):  # noqa: F811
    policy = room / ".tine" / "oversight.toml"
    policy.write_bytes(b"version = 1\n")
    assert pin(room, policy, "oversight") == ".tine/oversight.toml"
    assert recorded(room)[".tine/oversight.toml"]["kind"] == "oversight"
    run = Run(id="quiet")
    _tool(run, "Read", file_path="src/app.py")
    assert _codes(room, run) == []
    policy.write_bytes(b"version = 1\n# routes removed\n")
    assert _codes(room, run) == [(MODIFIED, ".tine/oversight.toml")]
    assert pin(room, Path("/nonexistent/outside.toml"), "monitor") is None


def test_a_run_that_rewrites_the_default_pins_file_is_caught(room: Path):  # noqa: F811
    run = Run(id="unpin")
    _tool(run, "Write", file_path=".tine/integrity/defaults.json", content="{}")
    assert (MODIFIED, ".tine/integrity/defaults.json") in _codes(room, run)


def test_deleting_a_logging_call_in_pinned_instrumentation_is_a_hash_fact():
    before, after = b"log.info('score %s', s)\nreturn s\n", b"return s\n"
    toml = ('version = 1\n[[surface]]\nname = "logging"\nkind = "instrumentation"\n'
            'globs = []\n[surface.pins]\n"src/obs.py" = "'
            + hashlib.sha256(before).hexdigest() + '"\n')  # fmt: skip
    protected = merged(parse(toml.encode("utf-8")), None)
    observed = {"touched": [], "digests": {"src/obs.py": hashlib.sha256(after).hexdigest()}}
    assert [f["code"] for f in check(protected, observed)] == [MODIFIED]


def test_a_user_surface_with_a_default_name_replaces_the_default():
    toml = 'version = 1\n[[surface]]\nname = "agent-hooks"\nkind = "hook"\nglobs = ["x/**"]\n'
    rows = {s["name"]: s for s in merged(parse(toml.encode("utf-8")), None)["surfaces"]}
    assert rows["agent-hooks"]["globs"] == ["x/**"] and "monitor-env" in rows


def test_integrity_pin_folds_the_defaults_into_the_list(room: Path, capsys):  # noqa: F811
    (room / ".tine" / "oversight.toml").write_bytes(b"version = 1\n")
    (room / ".claude").mkdir()
    (room / ".claude" / "settings.json").write_bytes(b"{}\n")
    code, row = _cli(capsys, "integrity", "pin", "--repo", room.as_posix(), "--json")
    assert code == 0 and row["pins"] == 4
    names = {s["name"]: s for s in parse((room / LIST).read_bytes())["surfaces"]}
    assert ".tine/oversight.toml" in names["oversight-policy"]["pins"]
    assert ".claude/settings.json" in names["agent-hooks"]["pins"]


@pytest.mark.parametrize("text", [
    "sed -i '/hooks/d' .claude/settings.json", "export OPENTINE_HOOK=0",
    "rm .tine/oversight.toml", "echo '{}' > .mcp.json", "vim monitors.toml",
])  # fmt: skip
def test_containment_limit_edit_matches_the_oversight_machinery(text):
    assert PATTERNS["limit-edit"].search(text)
