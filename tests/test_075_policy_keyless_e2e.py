"""0.75 acceptance, end to end: standard policies, admissions in the query index and the
promotion gate, and the keyless tier in ``tine verify`` output.

* ``promote`` allows only when a holdout eval is signed, no ``fail:`` integrity,
  k-of-n approvals, the budget is within its cap and the sandbox digest matches;
  removing any one of them denies; the advisory containment rule never blocks (D12).
* A signed admission appears in ``tine query`` and ``--verify`` checks each row:
  verified for a pinned ``policy`` signer, unverified for any other signer.
* ``tine promote --require-admission`` refuses until the policy admitted the run,
  and a policy that cannot be read refuses (fails closed).
* A keyless signature in ``tine verify --offline --attestation`` names its tier as
  ``caveat:keyless-unpinned`` with no authorship, until the owner pins it.
"""

from __future__ import annotations

import copy
import json

import pytest

import opentine.cli as cli
from opentine import _containment, _policy, _schemas
from opentine._promote_admission import refusals
from tests.containment_fixture import POLICY
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_075_keyless_sign import _pin, _setup, _sign, ws  # noqa: F401
from tests.test_075_policy_cli import POLICY_KEY, RUNNER, _key_file, make_setup

pytestmark = pytest.mark.filterwarnings("ignore::Warning")
DIGEST = "sha256:" + "ab" * 32


def _tine(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == []
    return code, body


def _good_input() -> dict:
    return {
        "evals": [{"holdout": True, "pinned": True, "passed": True}],
        "integrity": {"fail_codes": [], "taints": 0},
        "oversight": {"approvers": ["a", "b"]},
        "budget": {"in_force": True, "decision": "allow", "over": [], "fail_codes": []},
        "sandbox": [{"policy_digest": DIGEST, "roles": ["runner"]}],
        "containment": [{"finding": "advisory only"}],
        "params": {"approvals": 2, "sandbox_digest": DIGEST},
    }


BREAKS = {
    "holdout-signed": lambda d: d["evals"][0].update(pinned=False),
    "no-integrity-fail": lambda d: d["integrity"]["fail_codes"].append("fail:digest"),
    "k-of-n-approvals": lambda d: d["oversight"].update(approvers=["a"]),
    "budget-within-cap": lambda d: d["budget"]["over"].append("usd"),
    "sandbox-digest": lambda d: d["sandbox"][0].update(roles=["optimizer"]),
}


def test_the_promote_policy_allows_only_when_every_condition_holds():
    doc, _raw = _policy.load("promote")
    result = _policy.decide(doc, _good_input())
    assert result["decision"] == "allow"
    advisory = {r["id"]: r["outcome"] for r in result["rules"]}["no-containment-findings"]
    assert advisory == "false"  # recorded, never blocks (D12)
    for rule, breaks in BREAKS.items():
        document = copy.deepcopy(_good_input())
        breaks(document)
        result = _policy.decide(doc, document)
        failed = [r["id"] for r in result["rules"] if r["effect"] == "require"
                  and r["outcome"] != "true"]  # fmt: skip
        assert result["decision"] == "deny" and failed == [rule], rule


def test_admissions_reach_the_query_index_and_the_promotion_gate(tmp_path, capsys):
    from opentine import _policy_record
    from opentine.repository._attest import attest

    repo, run = make_setup(tmp_path)
    root = repo.path.parent
    base = ("--repo", str(root), "--json")
    assert [r["code"] for r in refusals(root, run, ["sandbox-digest"])] == ["promote.not-admitted"]
    _containment.record(repo, run, POLICY, RUNNER)
    key = _key_file(tmp_path, "policy", POLICY_KEY)
    param = f"sandbox_digest={_containment.digest(POLICY)}"
    code, body = _tine(capsys, "policy", "check", "sandbox-digest", "--subject", run, "--param",
                       param, "--key", key, *base)  # fmt: skip
    assert code == 0 and body["decision"] == "allow" and body["recorded"]
    assert refusals(root, run, ["sandbox-digest"], [param]) == []
    digest = _policy.policy_digest(_policy.load("sandbox-digest")[0])
    assert refusals(root, run, [digest], [param]) == []
    assert [r["code"] for r in refusals(root, run, ["promote"])] == ["promote.not-admitted"]
    missing = refusals(root, run, [str(tmp_path / "missing.json")])
    assert [r["code"] for r in missing] == ["promote.admission-policy"]
    # A record by a key without the policy role (here the runner) is indexed, not verified.
    allow = {"decision": "allow", "rules": []}
    claim = _policy_record.claim({"name": "sandbox-digest"}, digest, run, DIGEST, allow,
                                 "2026-01-01T00:00:00Z")  # fmt: skip
    from opentine._signing_pins import key_fingerprint

    signer = key_fingerprint(RUNNER.public_key().public_bytes_raw())
    stray = attest(repo, run, claim, signer=signer, key=RUNNER, algorithm="ed25519",
                   signed_at=claim["at"])  # fmt: skip
    sql = "SELECT oid, subject, decision, policy, signed FROM policy_admissions ORDER BY oid"
    code, body = _tine(capsys, "query", sql, "--rebuild", "--verify", *base)
    assert code == 0
    rows = {r["oid"]: r for r in body["rows"]}
    checks = {c["oid"]: c for c in body["verification"]["rows"]}
    assert len(rows) == 2 and stray in rows
    good = next(o for o in rows if o != stray)
    assert rows[good]["decision"] == "allow" and rows[good]["subject"] == run
    assert checks[good]["status"] == "verified" and checks[good]["roles"] == ["policy"]
    assert rows[stray]["signed"] == 1 and checks[stray]["status"] == "unverified"
    assert refusals(root, run, ["sandbox-digest"], [param]) == []  # the stray record is not held


def _verify(capsys) -> dict:
    from tests._keyless_fixtures import GH_ISSUER, WORKFLOW

    capsys.readouterr()
    try:
        cli.main(
            [
                "verify",
                "run.tine",
                "--offline",
                "--attestation",
                "run.sigstore.json",
                "--fulcio-root",
                "fulcio.pem",
                "--rekor-key",
                "rekor.pub",
                "--cert-identity",
                WORKFLOW,
                "--cert-oidc-issuer",
                GH_ISSUER,
                "--json",
            ]
        )
    except SystemExit:
        pass
    return json.loads(capsys.readouterr().out)


def test_tine_verify_shows_the_keyless_tier_as_a_caveat_until_the_owner_pins_it(ws, capsys):  # noqa: F811
    from tests._keyless_fixtures import GH_ISSUER, WORKFLOW

    _setup(ws)
    _sign(capsys)
    report = _verify(capsys)
    cert = next(c for c in report["checks"] if c["name"] == "certificate")
    assert cert["outcome"] == "pass", cert
    assert "tier keyless-workflow" in cert["detail"]
    assert "caveat:keyless-unpinned" in cert["detail"] and "not trusted" in cert["detail"]
    assert report["authorship"] is None
    _pin(ws[0], GH_ISSUER, WORKFLOW)
    report = _verify(capsys)
    cert = next(c for c in report["checks"] if c["name"] == "certificate")
    assert "pinned by the owner's trust bundle" in cert["detail"]
    assert "caveat" not in cert["detail"] and report["authorship"]
