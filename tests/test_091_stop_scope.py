"""0.91 review: a stop policy cannot be stepped around with --repo, a subdirectory or a cwd.

Every place a run or record touches is searched (up through its parents) for a
stop policy, and a pointer pinned in the user's trust config (or
``$OPENTINE_STOP_POLICY``) adds one for every command. A run with no proof is
refused (exit 3) before its child starts.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from opentine import _stop_guard, _stop_scope, cli
from opentine._config_home import config_dir
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.stop_helpers import RUNNER, Clock, fleet, key_file, make_repo


def tine(*argv) -> int:
    try:
        cli.main([str(a) for a in argv])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    return 0


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(_stop_guard, "_now_ms", Clock())
    monkeypatch.delenv(_stop_scope.POINTER_ENV, raising=False)
    channel, (guarded,) = fleet(tmp_path)
    plain = make_repo(tmp_path / "plain")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    marker = tmp_path / "marker"
    child = [sys.executable, "-c", f"open({marker.as_posix()!r}, 'w').close()"]
    stop = ["--stop-run", "r", "--stop-key", key_file(tmp_path, RUNNER, "runner")]
    return Path(guarded.path).parent, Path(plain.path).parent, elsewhere, marker, child, stop


def test_a_subdirectory_of_a_policy_repository_is_under_its_policy(setup, monkeypatch):
    guarded, _, _, marker, child, stop = setup
    (guarded / "sub" / "deeper").mkdir(parents=True)
    monkeypatch.chdir(guarded / "sub" / "deeper")
    assert tine("record", "--save", "o.tine", *stop, "--", *child) == 3  # no proof
    assert not marker.exists()


def test_saving_into_a_policy_repository_from_elsewhere_is_under_its_policy(
    setup, monkeypatch, tmp_path
):
    guarded, plain, elsewhere, marker, child, stop = setup
    monkeypatch.chdir(elsewhere)
    out = guarded / "runs" / "new" / "o.tine"  # not there yet: its parents are searched
    assert tine("record", "--repo", plain, "--save", out, *stop, "--", *child) == 3
    assert tine("run", "s.py", "--save", out, *stop) == 3
    assert not marker.exists()


def test_two_fleets_at_once_are_refused(setup, monkeypatch, tmp_path):
    guarded, _, _, marker, child, stop = setup
    from opentine import _stop_channel, _stop_policy
    from opentine.repo import Repo

    vkey = _stop_channel.init(tmp_path / "ch2", "fleet-b")
    other = Repo.open(tmp_path / "plain")
    _stop_policy.install(other, _stop_policy.make("fleet-b", (tmp_path / "ch2").as_posix(), vkey))
    monkeypatch.chdir(guarded)
    assert tine("record", "--repo", tmp_path / "plain", "--save", "o.tine", *stop, "--",
                *child) == 3  # fmt: skip
    found = pytest.raises(_stop_scope.ScopeError, _stop_scope.find, [tmp_path / "plain"])
    assert "more than one stop policy" in str(found.value)


@pytest.mark.parametrize("how", ["config", "env"])
def test_a_pinned_pointer_puts_every_command_under_the_policy(setup, monkeypatch, how):
    guarded, plain, elsewhere, marker, child, stop = setup
    if how == "config":
        config_dir().mkdir(parents=True, exist_ok=True)
        config_dir(_stop_scope.POINTER_FILE).write_bytes(guarded.as_posix().encode() + b"\n")
    else:
        monkeypatch.setenv(_stop_scope.POINTER_ENV, guarded.as_posix())
    monkeypatch.chdir(elsewhere)
    assert tine("record", "--repo", plain, "--save", "o.tine", *stop, "--", *child) == 3
    assert not marker.exists()
    if how == "config":  # the environment cannot lift a pointer the trust config pins
        monkeypatch.setenv(_stop_scope.POINTER_ENV, "")
        assert tine("record", "--repo", plain, "--save", "o.tine", *stop, "--", *child) == 3


def test_a_pointer_that_names_no_policy_fails_closed(setup, monkeypatch, tmp_path):
    _, plain, elsewhere, marker, child, stop = setup
    monkeypatch.chdir(elsewhere)
    for target in (plain, tmp_path / "missing"):
        monkeypatch.setenv(_stop_scope.POINTER_ENV, os.fspath(target))
        assert tine("record", "--save", "o.tine", "--", *child) == 3
    assert not marker.exists()


def test_with_no_policy_anywhere_nothing_changes(setup, monkeypatch):
    _, plain, elsewhere, marker, child, _ = setup
    monkeypatch.chdir(elsewhere)
    assert tine("record", "--repo", plain, "--save", "o.tine", "--", *child) == 0
    assert marker.exists()
