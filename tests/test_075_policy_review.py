"""0.74 review: holes a loop holding only its optimizer key could use to get an admission."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _containment, _policy, _policy_input, _policy_record
from opentine._signing_pins import key_fingerprint
from opentine.repository._attest import attest
from opentine.repository._holds import edit_holds, holds_path
from tests.containment_fixture import POLICY
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_policy_cli import POLICY_KEY, RUNNER, _cli, _key_file, make_setup

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

APPROVER_ONLY = Ed25519PrivateKey.from_private_bytes(b"\x34" * 32)
STRANGER = Ed25519PrivateKey.from_private_bytes(b"\x35" * 32)


@pytest.fixture
def setup(tmp_path):
    return make_setup(tmp_path)


def _base(repo):
    return ("--repo", str(repo.path.parent), "--json")


def test_a_file_named_like_a_standard_policy_cannot_shadow_it(setup, tmp_path, capsys,
                                                              monkeypatch):  # fmt: skip
    repo, run = setup
    fake = {"schema": "opentine.policy/1", "name": "promote",
            "rules": [{"id": "ok", "effect": "require", "expr": "true"}]}  # fmt: skip
    (tmp_path / "promote").write_bytes(json.dumps(fake).encode())
    monkeypatch.chdir(tmp_path)
    code, body = _cli(capsys, "policy", "check", "promote", "--subject", run, *_base(repo))
    std, _raw = _policy.load(_policy.STANDARD_DIR / "promote.json")
    assert body["policy"]["digest"] == _policy.policy_digest(std)
    assert code == 1
    code, body = _cli(capsys, "policy", "check", "./promote", "--subject", run, *_base(repo))
    assert code == 0 and body["policy"]["digest"] == _policy.policy_digest(fake)


@pytest.mark.parametrize("text", [
    b'{"schema": "opentine.policy/1", "name": "x", "rules": [{"id": "a", "effect": "require",'
    b' "expr": "false"}], "rules": [{"id": "a", "effect": "require", "expr": "true"}]}',
    b'{"schema": "opentine.policy/1", "name": "x", "params": {"cap": NaN},'
    b' "rules": [{"id": "a", "effect": "require", "expr": "true"}]}',
    b'{"schema": "opentine.policy/1", "name": "x", "params": {"cap": 1e400},'
    b' "rules": [{"id": "a", "effect": "require", "expr": "true"}]}',
    b'{"schema": "opentine.policy/1", "name": "x", "params": {"cap": 99999999999999999999},'
    b' "rules": [{"id": "a", "effect": "require", "expr": "true"}]}',
])  # fmt: skip
def test_duplicate_keys_and_unsafe_numbers_in_a_policy_are_refused(tmp_path, text):
    path = tmp_path / "p.json"
    path.write_bytes(text)
    with pytest.raises(_policy.PolicyFileError):
        _policy.load(path)


@pytest.mark.parametrize("raw", ["Infinity", "-Infinity", "NaN", "1e400", "99999999999999999999"])
def test_non_finite_or_unsafe_params_are_an_error_not_a_crash_or_null(setup, capsys, raw):
    repo, run = setup
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run,
                      "--param", f"sandbox_digest={raw}", *_base(repo))  # fmt: skip
    assert code != 0 and "error" in body


def test_infinite_record_values_do_not_crash_input_assembly():
    assert _policy_input._safe({"a": float("inf"), "b": float("-inf")}) == {"a": None, "b": None}


@pytest.mark.parametrize("key", [APPROVER_ONLY, STRANGER])
def test_only_a_pinned_policy_key_signs_an_admission(setup, tmp_path, capsys, key):
    repo, run = setup
    roles = (repo.path / "key-roles.toml").read_bytes().decode()
    roles += f'approver = ["{key_fingerprint(APPROVER_ONLY.public_key().public_bytes_raw())}"]\n'
    from tests.key_roles_helpers import pin_roles

    (repo.path / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(repo.path)
    path = _key_file(tmp_path, "k", key)
    code, body = _cli(capsys, "policy", "check", "no-integrity-fail", "--subject", run,
                      "--key", path, *_base(repo))  # fmt: skip
    assert code != 0 and "policy.signer-role" in body["error"]["message"]
    assert _policy_record.rows(repo, run) == []


def _plant(repo, run, body, key):
    """An admission attested and held by hand, bypassing the signing role check."""
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    oid = attest(repo, run, body, signer=signer, key=key, algorithm="ed25519",
                 signed_at=body["at"])  # fmt: skip
    row = {"oid": oid, "target": _policy_record.hold_target(run)}
    edit_holds(holds_path(repo), lambda held: [*held, row])
    return oid


def _allow_claim(run, digest, input_digest="sha256:" + "1" * 64, subject=None):
    result = {"decision": "allow", "rules": [{"id": "a", "effect": "require", "outcome": "true",
                                              "code": None}]}  # fmt: skip
    return _policy_record.claim({"name": "promote"}, digest, subject or run, input_digest,
                                result, "2026-01-01T00:00:00Z")  # fmt: skip


def test_admission_counts_only_from_a_pinned_policy_key_and_a_deny_wins(setup, tmp_path, capsys):
    repo, run = setup
    std, _raw = _policy.load("promote")
    digest = _policy.policy_digest(std)
    _plant(repo, run, _allow_claim(run, digest), STRANGER)
    _plant(repo, run, _allow_claim(run, digest), RUNNER)
    assert not _policy_record.admitted(repo, run, digest)
    code, body = _cli(capsys, "policy", "show", run, "--policy", "promote", *_base(repo))
    assert code == 1 and body["admitted"] is False
    assert [r["counts"] for r in body["records"]] == [False, False]
    _plant(repo, run, _allow_claim(run, digest), POLICY_KEY)
    assert _policy_record.admitted(repo, run, digest)
    assert not _policy_record.admitted(repo, run, digest, "sha256:" + "2" * 64)  # replay
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    code, _body = _cli(capsys, "policy", "check", "promote", "--subject", run, "--key", key,
                       *_base(repo))  # fmt: skip
    assert code == 1  # a deny for the policy refuses, whatever ids or "at" say
    assert not _policy_record.admitted(repo, run, digest)


def test_an_admission_naming_another_subject_does_not_count(setup):
    repo, run = setup
    _containment.record(repo, run, POLICY, RUNNER)
    std, _raw = _policy.load("promote")
    digest = _policy.policy_digest(std)
    _plant(repo, run, _allow_claim(run, digest, subject="run:" + "f" * 64), POLICY_KEY)
    assert not _policy_record.admitted(repo, run, digest)
