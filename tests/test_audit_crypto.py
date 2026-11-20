"""Security audit (crypto): signer binding and a fail-closed trust bundle."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _audit_game, _monitor_stop
from opentine._key_roles import KeyRoleError
from opentine._key_roles_pin import resolve
from opentine._signing_pins import key_fingerprint
from opentine.coord import _loop_stop
from opentine.repository import Repo
from opentine.repository._attest import attest
from opentine.repository._holds import AUDIT_GAME, edit_holds, holds_path
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

PINNED = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
AGENT = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
POLICY = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)


def _pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


def _fp(key: Ed25519PrivateKey) -> str:
    return key_fingerprint(key.public_key().public_bytes_raw())


def _roles(repo: Repo, text: str) -> None:
    (repo.path / "key-roles.toml").write_bytes(f"version = 1\n[roles]\n{text}".encode("ascii"))


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


def _run(repo: Repo) -> str:
    return _loop_stop._control_run(repo, "lp", "audit")


def test_an_audit_game_record_naming_another_signer_is_not_signed(repo):
    claim = {"convention": _audit_game.CONVENTION, "game": "g1", "step": "findings",
             "verdict": "no-concern", "findings_digest": "sha256:" + "0" * 64,
             "at": "2026-11-02T00:00:00Z"}  # fmt: skip
    oid = attest(repo, _run(repo), claim, signer=_fp(PINNED), key=AGENT, algorithm="ed25519")
    row = {"oid": oid, "target": f"{AUDIT_GAME}g1"}
    edit_holds(holds_path(repo), lambda rows: [*rows, row])
    [record] = _audit_game.records(repo, "g1")["g1"]
    assert record["signed"] is False
    assert _audit_game.latest([record], "findings") is None


def test_a_pinned_owner_with_a_missing_bundle_fails_closed(repo):
    from opentine._history_merge_repo import _signer_may_merge

    _roles(repo, f'optimizer = ["{_pub(AGENT)}"]\npolicy = ["{_pub(POLICY)}"]\n')
    pin_roles(repo.path)
    assert resolve(repo.path)["status"] == "pinned"
    (repo.path / "trust-bundle.note").unlink()
    _roles(repo, f'policy = ["{_pub(POLICY)}"]\n')
    with pytest.raises(KeyRoleError):
        resolve(repo.path)
    with pytest.raises((KeyRoleError, ValueError)):
        _signer_may_merge(repo, AGENT)


def _stop_claim(convention: str, **extra: str) -> dict:
    return {"convention": convention, "reason": "x", "stopped_at": "2026-11-02T00:00:00Z",
            **extra}  # fmt: skip


def test_a_loop_stop_naming_the_stopper_but_signed_by_another_key_is_unverified(repo):
    _roles(repo, f'stopper = ["{_pub(PINNED)}"]\n')
    pin_roles(repo.path)
    claim = _stop_claim(_loop_stop.CONVENTION, loop="lp")
    forged = attest(repo, _run(repo), claim, signer=_fp(PINNED), key=AGENT, algorithm="ed25519")
    assert _loop_stop.verify_stop(repo, "lp", forged).startswith("unverified")
    real = attest(repo, _run(repo), claim, signer=_fp(PINNED), key=PINNED, algorithm="ed25519")
    assert _loop_stop.verify_stop(repo, "lp", real) == "verified"


def test_a_monitor_stop_naming_the_stopper_but_signed_by_another_key_is_unverified(repo):
    _roles(repo, f'stopper = ["{_pub(PINNED)}"]\n')
    pin_roles(repo.path)
    claim = _stop_claim(_monitor_stop.CONVENTION, scope="*")
    forged = attest(repo, _run(repo), claim, signer=_fp(PINNED), key=AGENT, algorithm="ed25519")
    assert _monitor_stop.verify_token(repo, forged, "*").startswith("unverified")
    real = attest(repo, _run(repo), claim, signer=_fp(PINNED), key=PINNED, algorithm="ed25519")
    assert _monitor_stop.verify_token(repo, real, "*") == "verified"
