"""Security pass: a pinned optimizer key never grants a monitor, auditor or curator power."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _audit_game_check, _memory_quarantine, _monitor_verdict
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401


def _fpr(seed: int) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return key_fingerprint(key.public_key().public_bytes_raw())


@pytest.mark.parametrize("check", [_monitor_verdict.monitors, _audit_game_check.auditors,
                                   _memory_quarantine.curators])  # fmt: skip
def test_an_optimizer_key_named_in_a_guarded_role_grants_nothing(tmp_path, check):
    repo = Repo.init(tmp_path / "r")
    both, other = _fpr(7), _fpr(8)
    text = (f'version = 1\n[roles]\noptimizer = ["{both}"]\nmonitor = ["{both}", "{other}"]\n'
            f'auditor = ["{both}", "{other}"]\ncurator = ["{both}", "{other}"]\n')  # fmt: skip
    (repo.path / "key-roles.toml").write_text(text, encoding="utf-8")
    pin_roles(repo.path)
    keys, _ = check(SimpleNamespace(path=repo.path))
    assert keys == {other}
