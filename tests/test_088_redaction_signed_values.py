"""0.88: base64 signatures and blobs survive every redacted v3 write byte for byte.

The shape scrubber read a padded base64 value whose text before its ``=``
padding ends like a credential name (``...Pw==``, ``...pw=``) as an empty
credential assignment and appended a marker; about 1 Ed25519 signature in 150
were affected. Each write path that redacts before signing or storing is
checked with fixed values, so the cases are deterministic.
"""

from __future__ import annotations

import base64

import pytest

from opentine._v3_guards import guarded_redaction
from tests.promote_helpers import key

SIGNED = [
    base64.b64encode(b"abc?").decode(),
    base64.b64encode(bytes.fromhex("102030029c")).decode(),
]


def test_the_values_are_the_shapes_that_used_to_be_rewritten():
    assert SIGNED == ["YWJjPw==", "ECAwApw="]


@pytest.mark.parametrize("value", [*SIGNED, {"sig": SIGNED[0]}, [SIGNED[1], "x"]])
def test_the_guard_keeps_padded_base64(value):
    assert guarded_redaction({"v": value}, where="t") == {"v": value}


def test_real_credential_assignments_are_still_redacted():
    out = guarded_redaction({"a": "API_KEY=sk-live-0123456789abcdef", "b": "password: hunter2",
                             "c": "SECRET_KEY="}, where="t")  # fmt: skip
    assert "sk-live" not in out["a"] and "hunter2" not in out["b"]
    assert "REDACTED" in out["a"] and "REDACTED" in out["b"] and "REDACTED" in out["c"]


@pytest.fixture
def repo(tmp_path):
    from opentine.repo import Repo

    return Repo.init(tmp_path / "r")


def test_an_attestation_claim_keeps_its_base64_fields(repo):
    from opentine import _containment_records as records

    run = records.anchor(repo, "test", "anchor")
    claim = {"convention": "test/1", "sig": SIGNED[0], "blob": SIGNED[1]}
    oid = records.record(repo, run, claim, key("5a" * 32), "containment:test")
    row = records.read(repo, oid)
    assert row["signed"] and row["claim"] == claim


def test_an_ingest_record_keeps_base64_fields(repo):
    from opentine import _containment_records as records
    from opentine import _ingest_holds

    claim = {"convention": "test/1", "sig": SIGNED[0], "blob": SIGNED[1]}
    target = records.anchor(repo, "test", "a")
    oid = _ingest_holds.write(repo, target, claim, key("5a" * 32), previous=None,
                              signed_at="2026-11-27T00:00:00Z")  # fmt: skip
    row = _ingest_holds.read(repo, oid, "test/1")
    assert row["signed"] and row["claim"] == claim


def test_a_stored_run_keeps_provider_signatures(repo):
    from opentine.core import Run, StepKind

    run = Run(user_prompt="p")
    block = {"type": "thinking", "thinking": "t", "signature": SIGNED[0]}
    run.add_step(StepKind.model, {"messages": []}, outputs={"content": [block], "data": SIGNED[1]})
    stored = repo.put_run(run)
    loaded = repo.load_run(stored.run_id)
    assert loaded.steps[0].outputs == {"content": [block], "data": SIGNED[1]}


def test_a_coordination_record_keeps_base64(repo):
    payload = {"coord": "test", "kind": "k", "value": {"sig": SIGNED[0]}}
    oid = repo.put("annotation", payload)
    assert repo.get(oid).payload()["value"] == {"sig": SIGNED[0]}
