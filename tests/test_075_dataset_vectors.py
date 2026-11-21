"""0.75: the shared dataset-version vectors are current and the Python check answers them.

``tests/data/dataset_version.json`` is read by ``ts/verifier/test/datasetversion.test.ts``
too, so both verifiers agree on every case field for field. Like the lineage
and history-merge fixtures it lives outside the frozen conformance vector
families: ``tine verify`` gives the claim no verdict (FREEZE.md).
"""

from __future__ import annotations

import json

import pytest

from opentine._dataset_claims import offline
from tests.dataset_vectors import OUT, PATH, build, text


def _fixture() -> dict:
    return json.loads(PATH.read_bytes().decode("utf-8"))


def test_fixture_is_current() -> None:
    assert PATH.read_bytes() == text()
    assert _fixture() == json.loads(json.dumps(build()))


def test_fixture_covers_good_and_bad_and_every_signature_state() -> None:
    cases = _fixture()["cases"]
    states = {c["expect"]["signature"] for c in cases}
    assert states == {"verified-tofu", "bad-signature", "signer-mismatch", "curator-mismatch",
                      "unsigned"}  # fmt: skip
    assert sum(c["expect"]["ok"] for c in cases) == 3


@pytest.mark.parametrize("case", _fixture()["cases"], ids=lambda c: c["id"])
def test_the_offline_check_answers_every_case(case: dict) -> None:
    found = offline(case["payload"])
    assert {k: found[k] for k in OUT} == case["expect"]
