"""0.48: ``opentine.review-finding`` (SPEC 4.25) agrees in Python, the pyz and the TS verifier.

The 74-review-finding family is answered here by the reference and by the pyz
port (``ts/verifier``'s conformance test answers it in TypeScript); every
accepted vector holds the published record schema; and the built
``tine-verify.pyz`` checks a Review's stored findings file offline, one row each.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _review_finding, _schemas
from opentine._pyz import _finding as pyz
from opentine._pyz_build import build_bytes
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "docs/conformance/vectors/74-review-finding.json"
CASES = json.loads(FAMILY.read_text("utf-8"))["cases"]


def _answer(verifier: str, value: dict):
    key = bytes.fromhex(value["public_key"]) if value["public_key"] else None
    if verifier == "python":
        return _review_finding.check(value["record"], public_key=key, reviewers=value["reviewers"])
    return pyz.finding_verify(value["record"], key, value["reviewers"])


@pytest.mark.parametrize("verifier", ["python", "pyz"])
def test_the_73_family_agrees_in_python_and_the_pyz(verifier):
    assert len(CASES) == 21
    for case in CASES:
        value = tagged.decode(case["input"]["value"])
        if case["expect"] == "accept":
            assert _answer(verifier, value) == case["output"], case["id"]
        else:
            with pytest.raises(ValueError) as caught:
                _answer(verifier, value)
            assert caught.value.code == case["reason"], case["id"]  # type: ignore[attr-defined]


def test_the_record_schema_holds_the_accepted_vectors():
    accepted = [c for c in CASES if c["expect"] == "accept"]
    assert accepted
    for case in accepted:
        record = tagged.decode(case["input"]["value"])["record"]
        assert _schemas.validate(record) == ("opentine-review-finding-1", []), case["id"]


def test_the_built_pyz_checks_a_findings_file_offline(tmp_path):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("ab" * 32))
    records = [
        _review_finding.sign(
            _review_finding.build(
                "auth",
                f"rf-{n}",
                "high",
                "a token is logged",
                reviewer="fake-0",
                path="app.py",
                line=n,
            ),
            key,
        )  # fmt: skip
        for n in (1, 2)
    ]
    findings = tmp_path / "auth.json"
    findings.write_text(json.dumps(records), encoding="utf-8")
    pyz_path = tmp_path / "tine-verify.pyz"
    pyz_path.write_bytes(build_bytes())

    def run(path: Path) -> tuple[int, dict]:
        argv = [sys.executable, "-I", "-S", pyz_path.as_posix(), path.as_posix()]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
        return done.returncode, json.loads(done.stdout)

    code, result = run(findings)
    assert code == 0 and result["mode"] == "review-finding" and result["verdict"] == "pass"
    assert [c["finding_id"] for c in result["checks"]] == ["rf-1", "rf-2"]
    records[1]["severity"] = "low"
    findings.write_text(json.dumps(records), encoding="utf-8")
    code, result = run(findings)
    assert code == 1
    assert [c["reason"] for c in result["checks"]][1] == "review-finding.bad-signature"
