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


def pin_contributor(repo, key):
    """Pin *key* in the ``runner`` role, which a contributor key needs (0.75 review)."""
    from tests.key_roles_helpers import pin_roles

    path = repo.path / "key-roles.toml"
    text = path.read_text() if path.exists() else "version = 1\n[roles]\n"
    hexkey = key.public_key().public_bytes_raw().hex()
    if "runner = [" in text:
        text = text.replace("runner = [", f'runner = ["{hexkey}", ', 1)
    else:
        text += f'runner = ["{hexkey}"]\n'
    path.write_text(text)
    pin_roles(repo.path)
