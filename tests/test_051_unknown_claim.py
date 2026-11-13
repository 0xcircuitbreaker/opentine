"""An unknown predicate inside a frozen envelope is ``unchecked``, never pass or fail (0.51).

FREEZE.md ruling condition (b): a verifier that does not know an in-toto
``predicateType`` or ``attestation.claim`` schema reports it ``unchecked``.
The conformance inventory admits no new vector family and no new case is
needed in an existing one, so this is a unit test per implementation over one
committed fixture (``tests/data/unknown_claim_attestation.json``, read by
``ts/verifier/test/claim.test.ts`` too):

* the envelope -- the ``tine-attest/1`` and ``tine-attest/2`` signature over
  the canonical bytes -- verifies exactly as before, through each
  implementation's existing ``sig.verify`` op;
* the claim is reported ``unchecked:claim.unknown-predicate`` by the Python
  reference, the built ``tine-verify.pyz`` and (in its own test) the TS verifier;
* no predicate is granted (FREEZE.md "Granted predicates: none").
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import re
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _claim_status
from opentine._pyz import _conform_sig
from opentine._pyz_build import build_bytes
from tests.conformance.adapter import OPS, OpInput

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "data" / "unknown_claim_attestation.json"
UNKNOWN = "https://example.invalid/not-granted/v1"
HEADER = {"signed_at": "2026-11-13T00:00:00Z", "signer": "release-bot"}
TARGET = "run:sha256:" + "1" * 64


def _keys() -> dict[str, bytes]:
    raw = json.loads((ROOT / "docs" / "conformance" / "keys.json").read_text("utf-8"))
    return {name: bytes.fromhex(value) for name, value in raw.items()}


def _payload(claim: dict) -> dict:
    return {"claim": claim, "evidence_ids": [], "signer": "release-bot", "target_id": TARGET}


def build_fixture() -> dict:
    """The fixture, rebuilt from the published test keys (deterministic)."""
    keys = _keys()
    seed = Ed25519PrivateKey.from_private_bytes(keys["ed25519_seed"])
    public = seed.public_key().public_bytes_raw().hex()
    claim = {"predicateType": UNKNOWN, "predicate": {"anything": ["the verifier cannot judge"]}}
    cases = []
    v1 = {**HEADER, "alg": "hmac-sha256", "scheme": "tine-attest/1"}
    payload = _payload(claim)
    mac = hmac.new(keys["hmac_a"], _conform_sig.attest_message(payload, v1), hashlib.sha256)
    cases.append(
        {
            "id": "tine-attest/1",
            "args": {"family": "attestation", "key": "hmac_a"},
            "value": {**payload, "signature": {**v1, "value": mac.hexdigest()}},
        }
    )
    v2 = {**HEADER, "alg": "ed25519", "public_key": public, "scheme": "tine-attest/2"}
    sig = seed.sign(_conform_sig.attest_message(payload, v2)).hex()
    cases.append(
        {
            "id": "tine-attest/2",
            "args": {"family": "attestation", "public_key": public},
            "value": {**payload, "signature": {**v2, "value": sig}},
        }
    )
    return {
        "about": "attestations whose claim names a predicate no verifier is granted "
        "(FREEZE.md ruling (b)); regenerate with tests/test_051_unknown_claim.py",
        "expect_claim": {
            "status": "unchecked",
            "reason": "claim.unknown-predicate",
            "predicate": UNKNOWN,
        },
        "cases": cases,
    }


def _cases() -> list[dict]:
    return json.loads(FIXTURE.read_text("utf-8"))["cases"]


def _tampered(case: dict) -> dict:
    value = json.loads(json.dumps(case["value"]))
    value["claim"]["predicateType"] = UNKNOWN + "-edited"
    return value


def test_fixture_is_current() -> None:
    assert json.loads(FIXTURE.read_text("utf-8")) == build_fixture()


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["id"])
def test_reference_checks_the_envelope_and_leaves_the_claim_unchecked(case: dict) -> None:
    verdict = OPS["sig.verify"](OpInput("value", None, case["value"]), dict(case["args"]))
    assert (verdict["ok"], verdict["state"]) == (True, "verified")
    edited = OPS["sig.verify"](OpInput("value", None, _tampered(case)), dict(case["args"]))
    assert (edited["ok"], edited["state"]) == (False, "mismatch")
    status = _claim_status.claim_status(case["value"]["claim"])
    assert status == json.loads(FIXTURE.read_text("utf-8"))["expect_claim"]
    assert status["status"] not in ("pass", "fail")


@pytest.fixture(scope="module")
def built_pyz(tmp_path_factory: pytest.TempPathFactory):
    archive = tmp_path_factory.mktemp("pyz") / "tine-verify.pyz"
    archive.write_bytes(build_bytes())
    sys.path.insert(0, str(archive))
    try:
        conform = importlib.import_module("tine_verify._pyz._conform")
        claim = importlib.import_module("tine_verify._pyz._claim")
        assert Path(claim.__file__).as_posix().startswith(archive.as_posix())
        yield conform, claim
    finally:
        sys.path.remove(str(archive))
        for name in [n for n in sys.modules if n.split(".")[0] == "tine_verify"]:
            del sys.modules[name]


def test_built_pyz_checks_the_envelope_and_leaves_the_claim_unchecked(built_pyz) -> None:
    conform, claim = built_pyz
    for case in _cases():
        verdict = conform.answer("sig.verify", None, case["value"], case["args"], _keys())
        assert (verdict["ok"], verdict["state"]) == (True, "verified"), case["id"]
        edited = conform.answer("sig.verify", None, _tampered(case), case["args"], _keys())
        assert (edited["ok"], edited["state"]) == (False, "mismatch"), case["id"]
        status = claim.claim_status(case["value"]["claim"])
        assert status == _claim_status.claim_status(case["value"]["claim"])
        assert status["status"] == "unchecked"
    assert claim.GRANTED_PREDICATES == frozenset()


@pytest.mark.parametrize("claim", [None, [], {}, {"result": "pass"}, {"predicateType": ""}])
def test_an_unnamed_claim_is_unchecked_too(claim) -> None:
    assert _claim_status.claim_status(claim)["status"] == "unchecked"
    assert _claim_status.claim_status(claim)["reason"] == "claim.unnamed"


def test_no_predicate_is_granted_anywhere() -> None:
    assert _claim_status.GRANTED_PREDICATES == frozenset()
    ts = (ROOT / "ts" / "verifier" / "src" / "claim.ts").read_text("utf-8")
    assert "GRANTED_PREDICATES: ReadonlySet<string> = new Set<string>([]);" in ts
    freeze = (ROOT / "docs" / "FREEZE.md").read_text("utf-8")
    assert re.search(r"^\*\*Granted predicates: none\.\*\*", freeze, re.MULTILINE)
