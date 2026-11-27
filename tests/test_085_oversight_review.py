"""0.85 review: holes found in the oversight protection, each with its regression test."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from opentine._containment_detect import PATTERNS
from opentine._integrity_defaults import DEFAULTS, env_touches, recorded
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_064_oversight_floor import _pin
from tests.test_064_oversight_gate import _codes
from tests.test_064_oversight_gate import repo as repo  # noqa: F401 - the pinned fixture
from tests.test_085_oversight_pin import _restore_without_promotion_route

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def test_a_digest_only_pin_refuses_an_old_policy_without_the_route(repo):  # noqa: F811
    digest = hashlib.sha256((repo.path / "oversight.toml").read_bytes()).hexdigest()
    _pin(repo.path, {"version": 1, "policy_sha256": digest})
    _restore_without_promotion_route(repo)
    assert _codes(repo) == ["promote.oversight-insufficient"]


@pytest.mark.parametrize("command", [
    "unset -v OPENTINE_HOOK",
    "export -n OPENTINE_HOOK",
    "env -i python loop.py",
    "python -c 'import os; os.environ.clear()'",
    "declare +x TINE_MONITOR",
])  # fmt: skip
def test_clearing_monitoring_variables_is_seen(command):
    assert env_touches(command), command
    assert PATTERNS["limit-edit"].search(command), command


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "C:/x", "env:OPENTINE_X"])
def test_default_pins_cannot_name_paths_outside_the_repository(tmp_path: Path, path):
    target = tmp_path / DEFAULTS
    target.parent.mkdir(parents=True)
    doc = {"version": 1, "pins": {path: {"kind": "hook", "sha256": "0" * 64}}}
    target.write_bytes(json.dumps(doc).encode("utf-8"))
    assert recorded(tmp_path) == {}
