"""The promotion gate counts only admissions over the run's current policy input.

``tine promote --require-admission`` assembles the same input ``tine policy check``
does, takes its digest and asks :func:`opentine._policy_record.admitted` for an
admission over exactly that input: a run denied earlier can be admitted once its
inputs change, and an old allow over inputs that have since changed no longer counts.
"""

from __future__ import annotations

import copy

import pytest

from opentine import _containment
from opentine._promote_admission import refusals
from tests.containment_fixture import POLICY
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_policy_cli import POLICY_KEY, RUNNER, _cli, _key_file, make_setup

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _check(capsys, tmp_path, root, run, param):
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    code, body = _cli(capsys, "policy", "check", "sandbox-digest", "--subject", run, "--param",
                      param, "--key", key, "--repo", str(root), "--json")  # fmt: skip
    assert body["recorded"]
    return body["decision"]


def test_a_run_denied_earlier_is_admitted_over_new_inputs(tmp_path, capsys):
    repo, run = make_setup(tmp_path)
    root = repo.path.parent
    param = f"sandbox_digest={_containment.digest(POLICY)}"
    assert _check(capsys, tmp_path, root, run, param) == "deny"
    _containment.record(repo, run, POLICY, RUNNER)  # the input changes
    assert _check(capsys, tmp_path, root, run, param) == "allow"
    assert refusals(root, run, ["sandbox-digest"], [param]) == []


def test_an_old_allow_over_stale_inputs_does_not_count(tmp_path, capsys):
    repo, run = make_setup(tmp_path)
    root = repo.path.parent
    param = f"sandbox_digest={_containment.digest(POLICY)}"
    _containment.record(repo, run, POLICY, RUNNER)
    assert _check(capsys, tmp_path, root, run, param) == "allow"
    assert refusals(root, run, ["sandbox-digest"], [param]) == []
    other = copy.deepcopy(POLICY)
    other["privileges"] = ["no-new-privileges", "read-only-root"]
    _containment.record(repo, run, other, RUNNER)  # the input changes after the allow
    got = refusals(root, run, ["sandbox-digest"], [param])
    assert [r["code"] for r in got] == ["promote.not-admitted"]


def test_params_change_the_input_the_gate_checks(tmp_path, capsys):
    repo, run = make_setup(tmp_path)
    root = repo.path.parent
    param = f"sandbox_digest={_containment.digest(POLICY)}"
    _containment.record(repo, run, POLICY, RUNNER)
    assert _check(capsys, tmp_path, root, run, param) == "allow"
    got = refusals(root, run, ["sandbox-digest"])  # default params: a different input
    assert [r["code"] for r in got] == ["promote.not-admitted"]


def test_query_verify_marks_an_admission_about_another_run_unverified(tmp_path, capsys):
    from opentine import _policy, _policy_record
    from opentine._signing_pins import key_fingerprint
    from opentine.repository._attest import attest
    from tests.test_075_policy_cli import costed_run

    repo, run = make_setup(tmp_path)
    root = repo.path.parent
    other = repo.put_run(costed_run("other", 0.5, 100)).run_id
    doc = _policy.load("sandbox-digest")[0]
    claim = _policy_record.claim(
        doc,
        _policy.policy_digest(doc),
        other,
        "sha256:" + "0" * 64,
        {"decision": "allow", "rules": []},
        "2026-01-01T00:00:00Z",
    )
    signer = key_fingerprint(POLICY_KEY.public_key().public_bytes_raw())
    oid = attest(repo, run, claim, signer=signer, key=POLICY_KEY, algorithm="ed25519",
                 signed_at=claim["at"])  # fmt: skip  # claim names `other`, attached to `run`
    assert not _policy_record.admitted(repo, run, _policy.policy_digest(doc))
    code, body = _cli(capsys, "query", "SELECT oid, subject, target FROM policy_admissions",
                      "--rebuild", "--verify", "--repo", str(root), "--json")  # fmt: skip
    assert code == 0
    checks = {c["oid"]: c for c in body["verification"]["rows"]}
    assert checks[oid]["status"] == "unverified"
