"""0.88: padded base64 survives every redacted write byte for byte.

About one random padded base64 string in 200 ends in ``...pw=`` or ``...Pw==``.
The field scrubber read that as a credential name with an empty value and
appended a marker, corrupting signatures, digests and opaque provider blobs it
was handed (0.87.1 fixed one site, RL audit checkpoints, with ``verbatim``).
These tests drive one fixed blob through each kind of redacted write.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine.repository import Repo

BLOB = "AAAAAAAAAAAAAAAAAAAApw=="  # a valid base64 of 18 bytes ending "pw=="
BLOBS = [BLOB, "q83vASNFZ4mrze8BI0VniaPw=="]


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "repo")


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.mark.parametrize("blob", BLOBS)
def test_the_shared_scrubber_keeps_padded_base64(blob):
    from opentine._canon import _redact
    from opentine._v3_guards import guarded_redaction

    assert _redact({"v": blob}) == {"v": blob}
    assert guarded_redaction({"claim": {"sig": blob}}, where="test") == {"claim": {"sig": blob}}


def test_a_credential_assignment_is_still_redacted():
    from opentine._v3_guards import guarded_redaction

    for text in ("password=hunter2hunter2", "api_key=AAAAAAAAAAAAAAAAAAAA==", "pw=AAAApw=="):
        out = guarded_redaction({"v": text}, where="test")["v"]
        assert "[REDACTED]" in out and "hunter2" not in out


def test_an_attestation_claim_keeps_its_base64_and_verifies(repo):
    from opentine._containment_records import anchor, read, record

    target = anchor(repo, "test", "anchor")
    oid = record(repo, target, {"convention": "test.blob", "receipt": BLOB}, _key(), "test:1")
    row = read(repo, oid)
    assert row["signed"] and row["claim"]["receipt"] == BLOB


def test_an_annotation_record_keeps_its_base64_without_verbatim(repo):
    from opentine import _ingest_holds
    from opentine._containment_records import anchor

    target = anchor(repo, "test", "anchor")
    oid = _ingest_holds.write(repo, target, {"convention": "test.blob", "root": BLOB}, _key(),
                              previous=None, signed_at="2026-11-01T00:00:00Z")  # fmt: skip
    row = _ingest_holds.read(repo, oid, "test.blob")
    assert row["signed"] and row["claim"]["root"] == BLOB


def test_a_provider_thought_signature_round_trips_through_a_stored_run(repo):
    from opentine.graph import Run, StepKind

    run = Run(id="r-thought", model_info="test/model", user_prompt="hi")
    run.add_step(StepKind.done, {"text": "ok"}, {"parts": [{"thought_signature": BLOB}]})
    stored = repo.put_run(run).run_id
    loaded = repo.load_run(stored)
    part = loaded.steps[-1].outputs["parts"][0]
    assert part["thought_signature"] == BLOB
    assert base64.b64decode(part["thought_signature"], validate=True)


def test_a_saved_tine_file_keeps_the_signature(tmp_path):
    from opentine._graph_serde import load_run, save_run
    from opentine.graph import Run, StepKind

    run = Run(id="r-file", model_info="test/model", user_prompt="hi")
    run.add_step(StepKind.done, {"text": "ok"}, {"signature": BLOB})
    path = tmp_path / "r.tine"
    save_run(run, path)
    assert load_run(path, Run).steps[-1].outputs["signature"] == BLOB
