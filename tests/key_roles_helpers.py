"""Pin key roles the 0.59 way in tests: an owner-signed trust bundle.

``pin_roles(store)`` signs the roles of ``store/key-roles.toml`` into
``store/trust-bundle.note`` with a fixed owner key and pins that owner in the
user config (``$XDG_CONFIG_HOME/opentine/trust-owner``), outside the
repository. ``isolated_trust_config`` (autouse where imported) points the
config at a per-test directory so no pin leaks between tests or workers.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _key_roles, _trust_bundle
from opentine.repository._tlog_note import vkey_for

OWNER = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
OWNER_NAME = "example.com/trust"
OWNER_VKEY = vkey_for(OWNER_NAME, OWNER.public_key().public_bytes_raw())


@pytest.fixture(autouse=True)
def isolated_trust_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", (tmp_path / "xdg-config").as_posix())
    monkeypatch.delenv("OPENTINE_TRUST_OWNER", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_BUNDLE", raising=False)


def _config() -> Path:
    return Path(os.environ["XDG_CONFIG_HOME"]) / "opentine"


def bundle(roles: dict[str, list[str]], serial: int, extra: dict | None = None) -> bytes:
    payload = {**(extra or {}),"trust_bundle": 1, "serial": serial,
               "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "trust_policy": {"pin": ["sha256:" + "0" * 64]},
               "key_roles": {"version": 1,
                             "roles": {r: k for r, k in roles.items() if k}}}  # fmt: skip
    return _trust_bundle.sign(payload, OWNER, OWNER_NAME)


def pin_owner() -> None:
    _config().mkdir(parents=True, exist_ok=True)
    (_config() / "trust-owner").write_bytes((OWNER_VKEY + "\n").encode("utf-8"))


def pin_roles(store: Path, serial: int | None = None, extra: dict | None = None) -> None:
    """Sign ``store/key-roles.toml`` into ``store/trust-bundle.note`` and pin the owner."""
    roles = _key_roles.parse((Path(store) / _key_roles.FILE_NAME).read_bytes())
    if serial is None:
        try:
            seen = json.loads((_config() / "trust-bundle-serials.json").read_bytes())
        except OSError:
            seen = {}
        serial = seen.get(OWNER_VKEY, 0) + 1
    (Path(store) / "trust-bundle.note").write_bytes(bundle(roles, serial, extra))
    pin_owner()


__all__ = ["OWNER", "OWNER_NAME", "OWNER_VKEY", "bundle", "isolated_trust_config", "pin_owner",
           "pin_roles"]  # fmt: skip
