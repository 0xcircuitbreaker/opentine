"""0.48 review: compliance facts never overclaim from a failing or forgeable report."""

from __future__ import annotations

import pytest

from opentine import _compliance
from opentine._compliance_facts import _bare, from_report
from opentine.core import Run, StepKind


def _run() -> Run:
    run = Run(id="r", model_info="m", user_prompt="p")
    run.add_step(StepKind.tool, {"q": 1}, outputs={"r": 2}, tool_info={"name": "bash"})
    return run


def _check(name: str, outcome: str = "pass") -> dict:
    return {"name": name, "outcome": outcome, "reason": f"{name}.x", "detail": "d",
            "trust_basis": "b", "required": True}  # fmt: skip


def _report(*checks: dict, authorship: str | None = "--pubkey k.pub") -> dict:
    ok = all(c["outcome"] != "fail" for c in checks)
    return {"verdict": "pass" if ok else "fail", "ok": ok, "checks": list(checks),
            "authorship": authorship, "assurance": {"verified": "T2"}}  # fmt: skip


def test_a_failing_check_taints_every_verifier_fact():
    report = _report(_check("digest", "fail"), _check("signature"), _check("timestamp"))
    facts = from_report(report, _run(), signer_authenticated=True)
    for name in ("integrity", "signature", "signature.authenticated", "timestamp",
                 "capture.independent", "log.events", "log.period"):  # fmt: skip
        assert facts[name]["status"] == "missing", name
    assert "verdict is fail" in facts["signature"]["detail"]


def test_every_timestamp_token_must_pass_not_just_the_last():
    report = _report(_check("digest"), _check("timestamp", "fail"), _check("timestamp"))
    assert from_report(report, _run())["timestamp"]["status"] == "missing"


def test_authorship_from_another_check_does_not_authenticate_the_signature():
    report = _report(_check("digest"), _check("signature"), _check("delegation"))
    facts = from_report(report, _run(), signer_authenticated=False)
    assert facts["signature"]["status"] == "evidenced"
    assert facts["signature.authenticated"]["status"] == "missing"
    good = from_report(report, _run(), signer_authenticated=True)
    assert good["signature.authenticated"]["status"] == "evidenced"


def test_legal_hold_matches_whole_digests_only():
    hexd = "ab" * 32
    assert _bare(f"run:sha256:{hexd}") == _bare(f"sha256:{hexd.upper()}") == hexd
    assert _bare(hexd[:8]) != hexd


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["requirements"][0].update(cite="Regulation, somewhere"),
        lambda p: p["requirements"][0].update(id=["unhashable"]),
        lambda p: p["requirements"][0].update(evidence="integrity"),
        lambda p: p["requirements"][0].update(text=""),
        lambda p: p.update(sources=[]),
        lambda p: p.update(requirements=[]),
        lambda p: p.update(title=3),
    ],
)
def test_malformed_profiles_are_refused_not_crashed(mutate):
    profile = _compliance.load("fre-902")
    mutate(profile)
    with pytest.raises(_compliance.ProfileError):
        _compliance.validate(profile)


def test_run_crate_ids_are_iris_even_for_odd_tool_names():
    from opentine._run_crate import to_run_crate
    from opentine._run_crate_check import validate

    run = _run()
    run.add_step(StepKind.tool, {}, outputs={}, tool_info={"name": "my tool #1/x"})
    f = {"run_id": "r", "created": "1970-01-01T00:00:00Z", "file": "run.tine",
         "date": "1970-01-01", "digest": "sha256:" + "0" * 64, "version": "0"}  # fmt: skip
    crate = to_run_crate(f, run)
    ids = [e["@id"] for e in crate["@graph"]]
    assert "#tool-my%20tool%20%231%2Fx" in ids and not any(" " in i for i in ids)
    assert validate(crate) == []


def test_no_profile_claims_the_agent_output_is_accurate():
    for name in _compliance.available():
        for req in _compliance.load(name)["requirements"]:
            if req["scope"] == "in":
                assert not req["text"].startswith("The process or system produces an accurate")
