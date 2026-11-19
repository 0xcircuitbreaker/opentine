"""0.64 review: a loop holding only its optimizer key cannot hide decisions or drop the policy."""
# ruff: noqa: F811 - the imported fixture is used by name in test signatures

from __future__ import annotations

from opentine import _oversight
from opentine._signing_pins import key_fingerprint
from opentine.attest_signing import sign_attestation
from tests.test_064_oversight_gate import (  # noqa: F401
    RUN,
    SEEDS,
    _approve,
    _codes,
    _key,
    isolated_trust_config,
    repo,
)


def _fork(repo, previous: str | None, at: str) -> str:
    """An optimizer-signed decision forking the chain at *previous*, dated *at*."""
    item = _oversight.promotion_item("prod", RUN)
    key = _key(SEEDS["optimizer"])
    value = {"convention": _oversight.DECISION, "item": item, "decision": "request",
             "bind": None, "human": None, "note": "", "decided_at": at}  # fmt: skip
    signer = key_fingerprint(key.public_key().public_bytes_raw())
    payload = {"target_id": _oversight.anchor(repo, item), "previous_id": previous,
               "value": value, "signer": signer}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519", signed_at=at)
    return repo.put("annotation", payload, redact=False)


def test_a_newer_fork_of_the_chain_does_not_hide_a_rejection(repo):
    _approve(repo, "a2")
    kept = _approve(repo, "a3")
    _approve(repo, "a1", decision="reject")
    assert _codes(repo) == ["promote.oversight-rejected"]
    _fork(repo, kept, "2099-01-01T00:00:00Z")
    assert _codes(repo) == ["promote.oversight-rejected"]
    rows = _oversight.by_objects(repo)[_oversight.promotion_item("prod", RUN)]
    assert [r["decision"] for r in rows].count("reject") == 1


def test_deleting_the_policy_after_oversight_began_does_not_ungate(repo):
    _approve(repo, "a2")  # held decisions show the repository is under oversight
    (repo.path / "oversight.toml").unlink()
    (repo.path / "oversight.sig.json").unlink()
    assert _codes(repo) == ["promote.oversight-insufficient"]
