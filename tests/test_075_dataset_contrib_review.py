"""0.75 review: holes found in the contributor tooling, each pinned by a test.

* an object-id-shaped string with a private prefix (``janedoe:sha256:<hex>``)
  was skipped whole by the deny-list, so the name left in the bundle;
* homoglyphs (Cyrillic letters) and doubled separators dodged the deny-list;
* an attestation that only *claimed* the licence convention was skipped by the
  file-level licence scan; UTF-16 text, a lower-case tag and a notice split
  over lines dodged it too;
* a tombstone manifest with duplicate keys or an impossible date was accepted;
* ``contrib-redact`` signed with a pinned optimizer key.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _contrib_denylist, _dataset_licence, _dataset_withdraw
from opentine._containment_records import fingerprint
from opentine.kernel import ObjectEnvelope
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.test_075_dataset_contrib import _redact, room  # noqa: F401

HEX = "0" * 64


def test_an_oid_shaped_string_with_a_private_prefix_is_scrubbed():
    deny = _contrib_denylist.DenyList(["Jane Doe"])
    text, hits = deny.scrub_text(f"janedoe:sha256:{HEX}")
    assert hits == 1 and "jane" not in text.casefold()
    assert deny.scrub_text(f"run:sha256:{HEX}") == (f"run:sha256:{HEX}", 0)


@pytest.mark.parametrize("text", ["Jаne Dоe", "Jane  Doe", "Jane ,  Doe", "JANE\t\tDOE"])
def test_homoglyphs_and_doubled_separators_are_matched(text):
    assert _contrib_denylist.DenyList(["Jane Doe"]).count(text) == 1


def _note(claim: dict) -> ObjectEnvelope:
    payload = {"claim": claim, "evidence_ids": [], "signer": "sha256:" + HEX}
    return ObjectEnvelope.create("attestation", {**payload, "target_id": f"run:sha256:{HEX}"})


def test_a_claim_that_only_names_the_licence_convention_is_still_scanned():
    env = _note({"convention": _dataset_licence.CONVENTION, "spdx": "All rights reserved"})
    found = _dataset_licence.scan({env.oid: env}, _dataset_licence.DEFAULT_ALLOW)
    assert found and found[0]["finding"] == "notice: all rights reserved"


@pytest.mark.parametrize(
    "body",
    [
        "Copyright. All rights reserved.".encode("utf-16-le"),
        b"spdx-license-identifier: gpl-3.0-only\n",
        b"Copyright 2020. All rights\n   reserved.",
    ],
)
def test_the_licence_scan_sees_utf16_case_and_split_notices(body):
    env = ObjectEnvelope.create("blob", body)
    assert _dataset_licence.scan({env.oid: env}, _dataset_licence.DEFAULT_ALLOW)


_BAD_DATE = {"digest": "sha256:" + HEX, "date": "2026-13-45", "reason": "other"}


@pytest.mark.parametrize(
    "raw",
    [
        b'{"format": "opentine-dataset/tombstones/1", "tombstones": [], "tombstones": []}',
        json.dumps({"format": _dataset_withdraw.TOMBSTONES, "tombstones": [_BAD_DATE]}).encode(),
    ],
)
def test_a_duplicate_key_or_impossible_date_manifest_is_refused(tmp_path, raw):
    path = tmp_path / "t.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        _dataset_withdraw.read_tombstones(path)


def test_a_withdrawal_at_an_impossible_time_is_refused():
    claim = {
        "convention": _dataset_withdraw.CONVENTION,
        "run": f"run:sha256:{HEX}",
        "reason": "other",
        "contributor": "sha256:" + HEX,
        "withdrawn_at": "2026-02-30T25:61:00Z",
    }
    assert _dataset_withdraw.check_claim(claim)


def test_contrib_redact_refuses_a_pinned_optimizer_key(capsys, room):  # noqa: F811
    key = Ed25519PrivateKey.from_private_bytes(bytes([21]) * 32)  # alice's key in the fixture
    store = room["repo"].path
    (store / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\noptimizer = ["{fingerprint(key)}"]\n'.encode()
    )
    pin_roles(store)
    code, body = _redact(capsys, room)
    assert code != 0 and not (room["tmp"] / "public.bundle").exists()
