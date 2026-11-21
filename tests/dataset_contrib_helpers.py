"""Test helper: the licence annotation a contributed bundle carries onto its run (0.75)."""

from __future__ import annotations

from opentine import _containment_records as records
from opentine._dataset_licence import CONVENTION as LICENCE
from opentine.repository._attest import attest

AT = "2026-11-21T00:00:00Z"


def annotate(repo, run, key):
    """Sign and store a licence annotation on *run* with *key* (the contributor key)."""
    who = records.fingerprint(key)
    claim = {"convention": LICENCE, "run": run, "spdx": "MIT", "relicensing_grant": False,
             "contributor": who, "annotated_at": AT}  # fmt: skip
    return attest(repo, run, claim, signer=who, key=key, algorithm="ed25519")
