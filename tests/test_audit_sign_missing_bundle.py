"""Audit SIGN-1: deleting the trust bundle must not switch pinned roles off.

A loop that can write the repository can delete ``.tine/trust-bundle.note``
(and ``key-roles.toml``). The owner pin lives outside the repository, so with
an owner pinned a missing bundle fails closed, like a bad or rolled-back one.
"""

from __future__ import annotations

import pytest

from opentine import _key_roles_pin
from opentine._key_roles import KeyRoleError
from tests.key_roles_helpers import isolated_trust_config, pin_owner, pin_roles  # noqa: F401

OPT = "sha256:" + "ab" * 32


def _store(tmp_path):
    store = tmp_path / ".tine"
    store.mkdir()
    (store / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\noptimizer = ["{OPT}"]\n'.encode()
    )
    return store


def test_deleting_the_bundle_with_an_owner_pinned_fails_closed(tmp_path):
    store = _store(tmp_path)
    pin_roles(store)
    assert _key_roles_pin.resolve(store)["status"] == "pinned"
    (store / "trust-bundle.note").unlink()
    (store / "key-roles.toml").unlink()
    with pytest.raises(KeyRoleError, match="missing"):
        _key_roles_pin.resolve(store)
    with pytest.raises(KeyRoleError):
        _key_roles_pin.pinned(store)


def test_no_owner_pinned_and_no_bundle_is_still_absent(tmp_path):
    assert _key_roles_pin.resolve(tmp_path)["status"] == "absent"
