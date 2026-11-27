"""0.85: the owner pins oversight routes and the policy digest in the trust bundle."""

from __future__ import annotations

import hashlib
import json

import pytest

from opentine import _oversight_policy, _trust_bundle
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_064_oversight_floor import _pin
from tests.test_064_oversight_gate import AT, SEEDS, _approve, _codes, _key
from tests.test_064_oversight_gate import repo as repo  # noqa: F401 - the pinned fixture

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _restore_without_promotion_route(repo) -> None:  # noqa: F811
    """Put back an older, validly signed policy that routes only monitor verdicts."""
    text = (repo.path / "oversight.toml").read_bytes().decode("utf-8")
    old = text.replace('[[route]]\nsource = "promotion"\nlabel = "prod*"\ntier = "high"\n', "")
    assert old != text
    data = old.encode("utf-8")
    (repo.path / "oversight.toml").write_bytes(data)
    doc = _oversight_policy.sign(_key(SEEDS["policy"]), data, AT)
    (repo.path / "oversight.sig.json").write_bytes(json.dumps(doc).encode("utf-8"))


def test_without_a_route_pin_an_old_policy_lets_promotion_through(repo):  # noqa: F811
    _restore_without_promotion_route(repo)
    assert _oversight_policy.load(repo.path)["status"] == "pinned"
    assert _codes(repo) == []  # the gap the route pin closes


def test_a_pinned_promotion_route_refuses_an_old_policy_without_it(repo):  # noqa: F811
    _pin(repo.path, {"version": 1, "routes": ["promotion"]})
    _approve(repo, "a2")
    _approve(repo, "a3")
    assert _codes(repo) == []  # the current policy keeps the route
    _restore_without_promotion_route(repo)
    state = _oversight_policy.load(repo.path)
    assert state["status"] == "unpinned" and "promotion" in state["why"]
    assert _codes(repo) == ["promote.oversight-insufficient"]


def test_a_pinned_policy_digest_refuses_any_other_signed_bytes(repo):  # noqa: F811
    digest = hashlib.sha256((repo.path / "oversight.toml").read_bytes()).hexdigest()
    _pin(repo.path, {"version": 1, "policy_sha256": digest})
    assert _oversight_policy.load(repo.path)["status"] == "pinned"
    _restore_without_promotion_route(repo)
    state = _oversight_policy.load(repo.path)
    assert state["status"] == "unpinned" and digest in state["why"]


def test_deleting_the_policy_under_a_route_pin_still_refuses(repo):  # noqa: F811
    _pin(repo.path, {"version": 1, "routes": ["promotion"]})
    (repo.path / "oversight.toml").unlink()
    assert _codes(repo) == ["promote.oversight-insufficient"]


@pytest.mark.parametrize("section", [
    {"version": 1, "routes": ["nope"]},
    {"version": 1, "policy_sha256": "xyz"},
    {"version": 1},
    {"version": 1, "routes": "promotion"},
])  # fmt: skip
def test_malformed_route_and_digest_pins_are_refused(repo, section):  # noqa: F811
    with pytest.raises(_trust_bundle.BundleError):
        _pin(repo.path, section)


def test_bundle_create_pins_a_policy_file(repo, tmp_path, capsys):  # noqa: F811
    from opentine import cli
    from tests.key_roles_helpers import OWNER

    key = tmp_path / "owner.key"
    key.write_text(OWNER.private_bytes_raw().hex(), encoding="utf-8", newline="\n")
    out = tmp_path / "b.note"
    cli.main(["trust", "bundle", "create", "--key", str(key), "--name", "example.com/o",
              "--serial", "1", "--pin", "sha256:" + "0" * 64,
              "--oversight-policy", str(repo.path / "oversight.toml"),
              "--out", str(out)])  # fmt: skip
    payload = json.loads(out.read_bytes().split(b"\n")[1])
    section = payload["oversight"]
    assert section["routes"] == ["monitor", "promotion"]
    assert section["policy_sha256"] == hashlib.sha256(
        (repo.path / "oversight.toml").read_bytes()).hexdigest()  # fmt: skip
    capsys.readouterr()
