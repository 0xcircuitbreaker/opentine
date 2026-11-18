"""0.58: the shared lineage-check fixture is current and the reference answers it.

``tests/data/lineage_check.json`` is the lineage folder (base64) and the
``(code, variant)`` pairs each case must report; ``ts/verifier/test/lineage.test.ts``
reads the same file, so the Python and TS checks agree code for code. It lives
outside the frozen conformance vector family: ``tine verify`` and the pyz do not
emit ``lineage.*`` codes.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

from opentine._lineage_check import check
from tests.lineage_helpers import build_fixture

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "data" / "lineage_check.json"
pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _fixture() -> dict:
    return json.loads(FIXTURE.read_bytes().decode("utf-8"))


def _files() -> dict[str, bytes]:
    return {k: base64.b64decode(v) for k, v in _fixture()["files"].items()}


def test_fixture_is_current(tmp_path) -> None:
    assert _fixture() == build_fixture(tmp_path)


def test_fixture_covers_every_code() -> None:
    codes = {code for case in _fixture()["cases"] for code, _ in case["expect"]}
    names = ("variant-unknown", "record-invalid", "parent-missing", "cycle", "evidence-missing",
             "decision-mismatch", "signer-untrusted")  # fmt: skip
    assert codes == {f"lineage.{c}" for c in names}
    assert any(not case["expect"] for case in _fixture()["cases"])


@pytest.mark.parametrize("case", _fixture()["cases"], ids=lambda c: c["id"])
def test_reference_answers_every_case(case: dict) -> None:
    found = check(_files(), case["variant"], case.get("trust"))
    assert found["signers"] == ("pinned" if case.get("trust") else "unpinned")
    assert [[f["code"], f["variant"]] for f in found["findings"]] == case["expect"]
    assert found["ok"] is (not case["expect"])


if __name__ == "__main__":  # regenerate: python -m tests.test_059_lineage_fixture DIR
    out = build_fixture(Path(sys.argv[1]))
    FIXTURE.write_bytes((json.dumps(out, indent=2, sort_keys=True) + "\n").encode())
