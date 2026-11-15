"""0.52: the TS verifier's RFC 3161 fixtures still carry the Python reference's answers.

``ts/verifier/test/fixtures/tsp-tokens.json`` holds real tokens (written once by
``make_tsp_fixtures.py``) and what ``opentine._tsp_verify.verify_token`` and
``opentine._keyless_tsa.token_time`` say about each; ``ts/verifier/test/tsp.test.ts``
holds the TS verifier to the same answers. This test fails if Python's answer
drifts, so the two cannot silently part ways.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "ts" / "verifier" / "test" / "fixtures"
CASES = json.loads((FIXTURES / "tsp-tokens.json").read_text("utf-8"))["cases"]


def _maker():
    spec = importlib.util.spec_from_file_location(
        "make_tsp_fixtures", FIXTURES / "make_tsp_fixtures.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_python_still_gives_the_pinned_answer(case):
    assert _maker().answer(case) == case["expect"]


def test_the_fixture_covers_every_verdict_the_ts_port_names():
    reasons = {c["expect"].get("reason") or c["expect"].get("error") for c in CASES}
    for needed in (
        "timestamp.verified",
        "timestamp.bad-signature",
        "timestamp.untrusted-root",
        "timestamp.missing-eku",
        "timestamp.signing-cert-mismatch",
        "timestamp.critical-extension",
        "timestamp.outside-validity",
        "timestamp.tsa-retired",
        "timestamp.no-roots",
        "timestamp.malformed",
        "keyless.tsa-imprint-mismatch",
        "keyless.cert-not-valid-at-signing",
    ):
        assert needed in reasons, needed
    deviations = [c["id"] for c in CASES if "ts_expect" in c]
    assert deviations == ["token.embedded-crl"]  # TS fails closed on CRL/OCSP; may only shrink
