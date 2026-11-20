"""Audit: a snapshot hold row must be one read_holds accepts (holds-merge-poison)."""

from __future__ import annotations

import pytest

from opentine import _history_merge as hm

OID = "run:sha256:" + "a" * 64


def _snap(holds: list) -> dict:
    return {"format": hm.FORMAT, "refs": {}, "labels": {}, "lineage": {}, "holds": holds}


@pytest.mark.parametrize(
    "row", [["harmless", "not-an-oid"], ["harmless", OID + "x"], ["x" * 1025, OID], ["", OID]]
)
def test_a_hold_with_an_invalid_oid_or_target_is_refused(row: list) -> None:
    with pytest.raises(ValueError, match="holds"):
        hm.normalize(_snap([row]))


def test_a_well_formed_hold_still_normalizes() -> None:
    assert hm.normalize(_snap([["loop-stop:x", OID]]))["holds"] == [["loop-stop:x", OID]]
