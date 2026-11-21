"""0.74: `tine policy check|list|show` over the signed records of a run, end to end."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _containment, _policy, _policy_record, _schemas
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release
from tests.containment_fixture import POLICY, costed_run
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

RUNNER = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
POLICY_KEY = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)


def _hex(key) -> str:
    return key.public_key().public_bytes_raw().hex()


def _key_file(tmp_path, name, key):
    path = tmp_path / f"{name}.hex"
    path.write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    return str(path)


@pytest.fixture
def setup(tmp_path):
    return make_setup(tmp_path)


def make_setup(tmp_path):
    repo = Repo.init(tmp_path / "r")
    run = repo.put_run(costed_run("subject", 0.5, 100)).run_id
    roles = (f'version = 1\n[roles]\nrunner = ["{_hex(RUNNER)}"]\npolicy = ["{_hex(POLICY_KEY)}"]\n'
             f'optimizer = ["{_hex(OPTIMIZER)}"]\n')  # fmt: skip
    (repo.path / "key-roles.toml").write_bytes(roles.encode())
    pin_roles(repo.path)
    return repo, run


def _cli(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


def test_sandbox_digest_policy_denies_then_allows_and_signs_a_held_admission(
    setup, tmp_path, capsys
):
    repo, run = setup
    base = ("--repo", str(repo.path.parent), "--json")
    digest = _containment.digest(POLICY)
    param = f"sandbox_digest={digest}"
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run,
                      "--param", param, *base)  # fmt: skip
    assert code == 1 and body["decision"] == "deny" and body["recorded"] is None
    assert body["rules"][0]["outcome"] == "false"
    _containment.record(repo, run, POLICY, RUNNER)
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run,
                      "--param", param, "--key", key, "--show-input", *base)  # fmt: skip
    assert code == 0 and body["decision"] == "allow"
    assert body["input"]["sandbox"][0]["roles"] == ["runner"]
    assert body["input"]["params"]["sandbox_digest"] == digest
    assert body["input_digest"] == _policy.input_digest(body["input"])
    std, _raw = _policy.load("sandbox-digest")
    assert body["policy"]["digest"] == _policy.policy_digest(std)
    rows = _policy_record.rows(repo, run)
    assert [r["oid"] for r in rows] == [body["recorded"]]
    assert rows[0]["signed"] and rows[0]["roles"] == ["policy"]
    claim = rows[0]["claim"]
    assert claim["verificationResult"] == "PASSED" and claim["input_digest"] == body["input_digest"]
    assert _schemas.validate(claim, "opentine-policy-admission-1")[1] == []
    with pytest.raises(HoldError):
        release(repo, body["recorded"])
    code, shown = _cli(capsys, "policy", "show", run, *base)
    assert shown["records"][0]["oid"] == body["recorded"]


def test_another_digest_param_denies_and_the_deny_is_recorded(setup, tmp_path, capsys):
    repo, run = setup
    _containment.record(repo, run, POLICY, RUNNER)
    base = ("--repo", str(repo.path.parent), "--json")
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run, "--param",
                      "sandbox_digest=sha256:" + "0" * 64, "--key", key, *base)  # fmt: skip
    assert code == 1 and body["recorded"]
    assert _policy_record.rows(repo, run)[0]["claim"]["verificationResult"] == "FAILED"


def test_a_pinned_optimizer_key_cannot_sign_an_admission(setup, tmp_path, capsys):
    repo, run = setup
    base = ("--repo", str(repo.path.parent), "--json")
    key = _key_file(tmp_path, "opt", OPTIMIZER)
    code, body = _cli(capsys, "policy", "check", "no-integrity-fail", "--subject", run,
                      "--key", key, *base)  # fmt: skip
    assert code != 0 and "key-separation" in body["error"]["message"]
    assert _policy_record.rows(repo, run) == []


def test_records_signed_by_an_optimizer_key_are_left_out_of_the_input(setup, capsys):
    repo, run = setup
    _containment.record(repo, run, POLICY, OPTIMIZER)
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run,
                      "--show-input", *base)  # fmt: skip
    assert body["input"]["sandbox"] == [] and code == 1


def test_a_missing_or_invalid_policy_fails_closed(setup, tmp_path, capsys):
    repo, run = setup
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "policy", "check", str(tmp_path / "nope.json"), "--subject", run,
                      *base)  # fmt: skip
    assert code != 0 and "error" in body
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"schema": "opentine.policy/1", "name": "x", "rules": []}')
    code, body = _cli(capsys, "policy", "check", str(bad), "--subject", run, *base)
    assert code != 0 and "error" in body


def test_promote_policy_denies_by_default_and_advisory_never_blocks(setup, tmp_path, capsys):
    repo, run = setup
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "policy", "check", "promote", "--subject", run, *base)
    assert code == 1
    outcome = {r["id"]: (r["effect"], r["outcome"]) for r in body["rules"]}
    assert outcome["no-integrity-fail"] == ("require", "true")
    assert outcome["budget-within-cap"] == ("require", "false")  # no --budget: fail closed
    assert outcome["no-containment-findings"] == ("advisory", "true")
    doc = {
        "schema": "opentine.policy/1",
        "name": "adv",
        "rules": [
            {"id": "ok", "effect": "require", "expr": "subject.steps >= 1"},
            {"id": "warn", "effect": "advisory", "expr": "size(containment) > 99"},
        ],
    }
    path = tmp_path / "adv.json"
    path.write_bytes(json.dumps(doc).encode())
    code, body = _cli(capsys, "policy", "check", str(path), "--subject", run, *base)
    assert code == 0 and [r["outcome"] for r in body["rules"]] == ["true", "false"]


def test_input_file_mode_is_never_signed(setup, tmp_path, capsys):
    repo, run = setup
    doc = tmp_path / "in.json"
    doc.write_bytes(b'{"integrity": {"fail_codes": [], "taints": 0}}')
    base = ("--repo", str(repo.path.parent), "--json")
    code, body = _cli(capsys, "policy", "check", "no-integrity-fail", "--subject", "x",
                      "--input", str(doc), *base)  # fmt: skip
    assert code == 0 and body["recorded"] is None
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    code, body = _cli(capsys, "policy", "check", "no-integrity-fail", "--subject", "x",
                      "--input", str(doc), "--key", key, *base)  # fmt: skip
    assert code != 0


def test_list_names_every_standard_policy(capsys, tmp_path):
    code, body = _cli(capsys, "policy", "list", "--repo", str(tmp_path), "--json")
    names = {p["name"] for p in body["policies"]}
    assert names == {"budget-within-cap", "holdout-signed", "k-of-n-approvals",
                     "no-integrity-fail", "promote", "sandbox-digest"}  # fmt: skip
