"""0.69: the shared history-merge fixture is current; the reference and the pyz answer it.

``tests/data/history_merge.json`` holds seeded base/ours/theirs snapshots, the
signed ``opentine.history-merge/1`` record of each merge and what a verifier
must answer; ``ts/verifier/test/histmerge.test.ts`` reads the same file, so the
Python, pyz and TS checks agree on merged history field for field. Like the
lineage fixture it lives outside the frozen conformance vector families:
``tine verify`` gives the claim no verdict (FREEZE.md, D1).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import _history_merge as hm
from opentine._history_merge_record import check
from opentine._pyz import _histmerge
from tests.history_merge_helpers import build_fixture

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "data" / "history_merge.json"
OUT = ("ok", "signature", "merged", "merged_matches", "conflicts_match", "conflicts")


def _fixture() -> dict:
    return json.loads(FIXTURE.read_bytes().decode("utf-8"))


def _key(case: dict) -> bytes | None:
    return bytes.fromhex(case["public_key"]) if case["public_key"] else None


def test_fixture_is_current() -> None:
    assert _fixture() == json.loads(json.dumps(build_fixture()))


def test_fixture_covers_every_conflict_kind_and_every_verdict() -> None:
    cases = _fixture()["cases"]
    kinds = {row["kind"] for case in cases for row in case["expect"]["conflict_rows"]}
    assert kinds == set(hm.KINDS)
    states = {case["expect"]["signature"] for case in cases}
    assert {"verified", "verified-tofu", "mismatch", "unsigned"} <= states
    assert any(c["expect"]["ok"] for c in cases) and any(not c["expect"]["ok"] for c in cases)


@pytest.mark.parametrize("case", _fixture()["cases"], ids=lambda c: c["id"])
def test_reference_and_pyz_answer_every_case(case: dict) -> None:
    expect = case["expect"]
    args = (case["record"], case["base"], case["ours"], case["theirs"], _key(case))
    assert check(*args) == {k: expect[k] for k in OUT}
    assert _histmerge.check(*args) == {k: expect[k] for k in OUT}
    merged = _histmerge.merge(case["base"], case["ours"], case["theirs"])
    assert merged["merged"] == expect["merged_snapshot"]
    assert merged["conflicts"] == expect["conflict_rows"]


if __name__ == "__main__":  # regenerate: python -m tests.test_069_history_merge_fixture
    text = json.dumps(build_fixture(), indent=2, sort_keys=True) + "\n"
    FIXTURE.write_bytes(text.encode("utf-8"))
    sys.exit(0)
