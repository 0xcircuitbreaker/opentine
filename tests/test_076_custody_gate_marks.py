"""Audit OT-10: the weight-custody load gate counts only role-held tags and token marks."""

from __future__ import annotations

import pytest

from opentine import _containment_records as records
from opentine import _weight_custody as wc
from opentine import _weight_custody_gate as gate
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_072_organism import _key, repo  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _created(repo, name, key, location, digest="sha256:" + "0" * 64):  # noqa: F811
    return wc.record(repo, name, "created", _key(key), location=location, digest=digest,
                     tags=[wc.MODEL_ORGANISM])  # fmt: skip


def test_an_optimizer_signed_tag_does_not_gate_loads(repo):  # noqa: F811
    _created(repo, "junk", "optimizer", "ckpt/junk.safetensors")
    assert gate.decide(repo, {"command": "load ckpt/junk.safetensors"})["decision"] == "allow"


def test_a_short_location_is_matched_as_a_token_not_a_substring(repo):  # noqa: F811
    _created(repo, "tiny", "policy", "e")
    assert gate.decide(repo, {"command": "echo hello"})["decision"] == "allow"
    assert gate.decide(repo, {"command": "load e"})["decision"] == "block"
    _created(repo, "mo", "policy", "ckpt/mo.safetensors", "sha256:" + "1" * 64)
    for text in ("load ./ckpt/mo.safetensors", "--ckpt=ckpt/mo.safetensors", "sha256:" + "1" * 64):
        assert gate.decide(repo, {"command": text})["decision"] == "block", text
    assert gate.decide(repo, {"command": "load ckpt/mo.safetensors.bak2"})["decision"] == "allow"


def test_a_malformed_digest_refuses_only_that_record(repo):  # noqa: F811
    _created(repo, "mo", "policy", "ckpt/mo.safetensors")
    claim = {"convention": wc.CONVENTION, "artifact": "bad", "event": "created", "seq": 0,
             "prev": None, "location": ["x"], "digest": ["sha256:" + "2" * 64],
             "tags": [wc.MODEL_ORGANISM]}  # fmt: skip
    target = records.anchor(repo, "custody", "weight custody of bad")
    records.record(repo, target, claim, _key("policy"), f"{wc.HOLD}bad:00000000")
    assert gate.decide(repo, {"command": "ls"})["decision"] == "allow"
    assert gate.decide(repo, {"command": "load ckpt/mo.safetensors"})["decision"] == "block"
