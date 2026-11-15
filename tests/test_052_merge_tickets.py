"""0.52: merge approvals gain a queue id, a nonce and an expiry (local queue state).

The ``opentine.merge-approval`` schema is closed, and a claim schema inside an
attestation that ``land`` reads is a new claim schema under FREEZE.md (none is
granted), so the binding lives in the queue record (``_merge_tickets``).
"""

from __future__ import annotations

import json
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_record, _schemas, cli
from opentine.coord import _merge_queue as queue
from opentine.coord._merge_tickets import issue
from opentine.coord._tasks import LeaseError
from tests.test_047_merge_queue import _key, _repo

ALICE = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
ALICE_HEX = ALICE.public_key().public_bytes_raw().hex()
GATES = {"format": "opentine-merge-gates/1", "approvals": {"required": 1, "keys": [ALICE_HEX]}}


def _approval(run: str, target: str = "heads/main") -> dict:
    record = _merge_record.build_approval(run, target, "alice")
    return _merge_record.sign_approval(record, ALICE, algorithm="ed25519")


def _queue(tmp_path, name="main", count=1):
    repo, runs = _repo(tmp_path / "r", count)
    queue.init(repo, name, "heads/main", GATES)
    for run in runs:
        queue.enqueue(repo, name, run, "ci")
    return repo, runs


def _land(repo, name, evidence, key=None):
    token = queue.claim(repo, name, "w", 30)["fencing"]
    return queue.land(repo, name, "w", token, evidence=evidence, key=key or _key())


def test_an_issued_approval_lands_once_and_its_nonce_is_spent(tmp_path):
    repo, runs = _queue(tmp_path, count=2)
    approval = _approval(runs[0])
    ticket = issue(repo, "main", approval, 3600)
    assert len(ticket["nonce"]) == 32 and ticket["approver"] == ALICE_HEX
    assert ticket["spent_fencing"] is None and ticket["run"] == runs[0]
    out = _land(repo, "main", {"approvals": [approval]})
    assert out["status"] == "landed" and out["attestation"]
    spent = queue.get(repo, "main")["tickets"][0]
    assert spent["nonce"] == ticket["nonce"] and spent["spent_fencing"] == out["fencing"]
    # The same signed approval offered again is a replayed nonce.
    replay = _land(repo, "main", {"approvals": [approval]})
    assert replay["status"] == "rejected"
    assert f"replayed nonce {ticket['nonce']}" in replay["reason"]
    with pytest.raises(LeaseError) as again:
        issue(repo, "main", approval, 3600)
    assert again.value.code == "exists"


def test_an_unissued_approval_or_one_from_another_queue_is_refused(tmp_path):
    repo, runs = _queue(tmp_path)
    queue.init(repo, "side", "heads/main", GATES)
    approval = _approval(runs[0])
    issue(repo, "side", approval, 3600)  # issued, but into another queue
    out = _land(repo, "main", {"approvals": [approval]})
    assert out["status"] == "rejected" and "not issued for merge queue main" in out["reason"]


def test_an_expired_approval_is_refused(tmp_path, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr("opentine.coord._tasks.now_ms", lambda: clock[0])
    monkeypatch.setattr("opentine.coord._merge_queue.now_ms", lambda: clock[0])
    repo, runs = _queue(tmp_path)
    approval = _approval(runs[0])
    ticket = issue(repo, "main", approval, 60)
    clock[0] += 61_000
    out = _land(repo, "main", {"approvals": [approval]})
    assert out["status"] == "rejected"
    assert f"nonce {ticket['nonce']} expired" in out["reason"]


def test_a_spent_approval_cannot_be_issued_again_after_it_expires(tmp_path, monkeypatch):
    clock = [1_000_000_000]
    monkeypatch.setattr("opentine.coord._tasks.now_ms", lambda: clock[0])
    monkeypatch.setattr("opentine.coord._merge_queue.now_ms", lambda: clock[0])
    repo, runs = _queue(tmp_path, count=2)
    approval = _approval(runs[0])
    issue(repo, "main", approval, 60)
    assert _land(repo, "main", {"approvals": [approval]})["status"] == "landed"
    clock[0] += 120_000  # the spent ticket is past its expiry, but is kept
    with pytest.raises(LeaseError) as again:
        issue(repo, "main", approval, 60)
    assert again.value.code == "exists"
    assert queue.get(repo, "main")["tickets"][0]["spent_fencing"] is not None


def test_issuing_checks_the_signature_target_and_expiry(tmp_path):
    repo, runs = _queue(tmp_path)
    with pytest.raises(LeaseError) as wrong:
        issue(repo, "main", _approval(runs[0], "heads/other"), 60)
    assert wrong.value.code == "target"
    forged = {**_approval(runs[0]), "decision": "reject"}
    with pytest.raises(ValueError):
        issue(repo, "main", forged, 60)
    for ttl in (0, -1, 10**9):
        with pytest.raises(ValueError):
            issue(repo, "main", _approval(runs[0]), ttl)


def test_a_gated_landing_without_a_signing_key_is_refused(tmp_path):
    repo, runs = _queue(tmp_path)
    approval = _approval(runs[0])
    issue(repo, "main", approval, 3600)
    token = queue.claim(repo, "main", "w", 30)["fencing"]
    with pytest.raises(LeaseError) as refused:
        queue.land(repo, "main", "w", token, evidence={"approvals": [approval]}, key=None)
    assert refused.value.code == "no-key"
    assert queue.get(repo, "main")["entries"]  # nothing popped


def test_the_cli_issues_an_approval_into_a_queue(monkeypatch, capsys, tmp_path):
    repo, runs = _queue(tmp_path)
    path = (tmp_path / "r").as_posix()
    key = tmp_path / "alice.key"
    key.write_text((b"\x01" * 32).hex(), encoding="utf-8")
    argv = ["tine", "merge-queue", "approve", runs[0], "--target", "heads/main",
            "--approver", "alice", "--ed25519-key-file", key.as_posix(), "--queue", "main",
            "--expires", "600", "--repo", path, "--json"]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    cli.main()
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == [], body
    assert body["ticket"]["approver"] == ALICE_HEX
    shown = queue.get(repo, "main")
    assert shown["tickets"][0]["nonce"] == body["ticket"]["nonce"]
    out = _land(repo, "main", {"approvals": [body["record"]]})
    assert out["status"] == "landed"
    shown = {"command": "merge-queue", "action": "show", "ok": True,
             "queue": queue.get(repo, "main")}  # fmt: skip
    assert _schemas.validate_output(shown) == [], shown
