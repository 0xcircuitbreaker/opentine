"""0.64: owner-pinned k floors in the trust bundle survive a rolled-back oversight policy."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from opentine import _key_roles, _oversight_policy, _trust_bundle
from tests.key_roles_helpers import (  # noqa: F401
    OWNER,
    OWNER_NAME,
    OWNER_VKEY,
    isolated_trust_config,
)
from tests.test_064_oversight_gate import _approve, _codes
from tests.test_064_oversight_gate import repo as repo  # noqa: F401 - the pinned fixture

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _pin(store: Path, oversight: dict) -> None:
    roles = _key_roles.parse((store / _key_roles.FILE_NAME).read_bytes())
    cfg = Path(os.environ["XDG_CONFIG_HOME"]) / "opentine" / "trust-bundle-serials.json"
    seen = json.loads(cfg.read_bytes()) if cfg.is_file() else {}
    payload = {"trust_bundle": 1, "serial": seen.get(OWNER_VKEY, 0) + 1,
               "issued_at": "2026-12-03T00:00:00Z",
               "trust_policy": {"pin": ["sha256:" + "0" * 64]},
               "key_roles": {"version": 1, "roles": {r: k for r, k in roles.items() if k}},
               "oversight": oversight}  # fmt: skip
    (store / "trust-bundle.note").write_bytes(_trust_bundle.sign(payload, OWNER, OWNER_NAME))


def test_a_pinned_floor_raises_k_above_the_signed_file(repo):  # noqa: F811
    _pin(repo.path, {"version": 1, "tiers": {"high": {"k": 3}}})
    state = _oversight_policy.load(repo.path)
    assert state["floors"] is True and state["policy"]["tiers"]["high"]["k"] == 3
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert _codes(repo) == ["promote.oversight-insufficient"]  # 2 of a pinned 3
    _approve(repo, "a1")
    assert _codes(repo) == []


def test_a_pinned_tier_the_policy_lacks_leaves_it_unpinned(repo):  # noqa: F811
    _pin(repo.path, {"version": 1, "tiers": {"critical": {"k": 1}}})
    state = _oversight_policy.load(repo.path)
    assert state["status"] == "unpinned" and "critical" in state["why"]
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert _codes(repo) == ["promote.oversight-insufficient"]


def test_a_malformed_oversight_section_is_refused_by_the_bundle(repo):  # noqa: F811
    with pytest.raises(_trust_bundle.BundleError):
        _pin(repo.path, {"version": 1, "tiers": {"high": {"k": 0}}})


def test_deleting_the_policy_file_does_not_lift_pinned_floors(repo):  # noqa: F811
    _pin(repo.path, {"version": 1, "tiers": {"high": {"k": 3}}})
    assert _codes(repo) == ["promote.oversight-insufficient"]
    (repo.path / "oversight.toml").unlink()
    (repo.path / "oversight.sig.json").unlink()
    assert _oversight_policy.load(repo.path)["floors"] is True
    assert _codes(repo) == ["promote.oversight-insufficient"]
