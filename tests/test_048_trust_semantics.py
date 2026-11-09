"""0.48 trust semantics: a TSA token gives a Rekor v2 keyless receipt its signing time,
and delegation chains honour the key-revocation registry (SPEC 8.12.1, 4.10.1).

Built offline: the Rekor v2 tile log and the TSA are the fixtures of the 0.44 and
0.31 tests; the token is minted over the envelope's signature bytes.
"""

from __future__ import annotations

import argparse
import base64
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from opentine import _delegation_check, _keyless_root, _keyless_tsa
from opentine._delegation import DelegationError
from opentine._delegation_verify import verify_chain
from opentine._trusted_root import TrustedRoot, _Window
from opentine._verify_report import Check
from tests.conformance.cases_delegation import AT, CHAIN, LEAF_FPR, MID_FPR
from tests.test_044_rekor_v2_scitt import _fixture
from tests.test_timestamp_offline_0_31 import NOW, _cert, pki, token


def _leaf(start=None, end=None):
    key = ec.generate_private_key(ec.SECP256R1())
    return _cert("leaf", "leaf", key, key, ca=False, eku=False,
                 start=start or NOW - timedelta(minutes=5),
                 end=end or NOW + timedelta(minutes=5))  # fmt: skip


@pytest.fixture
def v2(tmp_path):
    entry, trusted, envelope, signer, _ = _fixture(tmp_path)
    from opentine._rekor_v2 import tile_logs

    ca, tsa, tsa_key = pki()
    root = TrustedRoot(tile_logs=tile_logs(trusted))
    root.timestamp_authorities = [([tsa, ca], _Window(NOW - timedelta(days=30), None))]
    signature = base64.b64decode(envelope["signatures"][0]["sig"])

    def material(*bound: bytes) -> dict:
        tokens = [{"signedTimestamp": base64.b64encode(token(b, tsa, tsa_key)).decode()}
                  for b in bound]  # fmt: skip
        return {"timestampVerificationData": {"rfc3161Timestamps": tokens}}

    return entry, envelope, signer, root, signature, material


def test_a_bound_token_gives_the_v2_receipt_a_verified_signing_time(v2):
    entry, envelope, signer, root, signature, material = v2
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(),
                                        material(signature), _leaf())  # fmt: skip
    assert result.ok and result.status == "verified", result.reason
    assert result.integrated_time == int(NOW.timestamp())
    assert "RFC 3161" in result.reason and _keyless_tsa.stamp(NOW) in result.reason


def test_without_a_token_the_v2_receipt_stays_unchecked(v2):
    entry, envelope, signer, root, _, _ = v2
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(), {}, _leaf())
    assert not result.ok and result.status == "unchecked"


def test_a_token_over_the_payload_is_refused(v2):
    entry, envelope, signer, root, _, material = v2
    payload = base64.b64decode(envelope["payload"])
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(),
                                        material(payload), _leaf())  # fmt: skip
    assert result.status == "invalid" and "keyless.tsa-imprint-mismatch" in result.reason


def test_a_token_outside_the_certificate_window_is_refused(v2):
    entry, envelope, signer, root, signature, material = v2
    late = _leaf(NOW - timedelta(hours=2), NOW - timedelta(hours=1))
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(),
                                        material(signature), late)  # fmt: skip
    assert result.status == "invalid" and "cert-not-valid-at-signing" in result.reason


def test_a_token_from_an_untrusted_tsa_is_refused(v2):
    entry, envelope, signer, root, signature, material = v2
    root.timestamp_authorities = [(pki()[:1], _Window(NOW - timedelta(days=30), None))]
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(),
                                        material(signature), _leaf())  # fmt: skip
    assert result.status == "invalid" and result.reason.startswith("timestamp.untrusted-root:")


def test_a_malformed_timestamp_list_is_refused(v2):
    entry, envelope, signer, root, _, _ = v2
    bad = {"timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": "%%"}]}}
    result = _keyless_root.root_receipt(root, envelope, [entry], signer.public_key(), bad, _leaf())
    assert result.status == "invalid" and "keyless.malformed" in result.reason


# --- delegation x revocation ------------------------------------------------- #


def test_revocation_semantics_on_the_reference_chain():
    common = {"signer": LEAF_FPR, "at": AT, "agent": "coder", "actions": ["Bash"]}
    assert verify_chain(CHAIN, revoked={LEAF_FPR: "2026-09-01T00:00:00Z"}, **common)
    with pytest.raises(DelegationError) as refused:
        verify_chain(CHAIN, revoked={MID_FPR: "2026-03-01T00:00:00Z"}, **common)
    assert refused.value.code == "delegation.revoked"
    with pytest.raises(DelegationError):
        verify_chain(CHAIN, revoked={MID_FPR: "2027-03-01T00:00:00Z"}, time_verified=False,
                     **common)  # fmt: skip


def test_the_offline_check_reads_the_lifecycle_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    registry = tmp_path / "opentine" / "key-lifecycle.json"
    registry.parent.mkdir(parents=True)
    keys = {MID_FPR: {"revoked_at": "2026-03-01T00:00:00Z"}}
    registry.write_text(json.dumps({"schema": "tine-key-lifecycle/1", "keys": keys}), "utf-8")
    monkeypatch.setattr("opentine._key_lifecycle_verify.signer", lambda a, p: (LEAF_FPR, AT))
    monkeypatch.setattr(_delegation_check, "agent_names", lambda run: ["coder"])
    monkeypatch.setattr(_delegation_check, "tool_names", lambda run: ["Bash"])
    run = argparse.Namespace(metadata={"delegation": CHAIN})
    signature = Check("signature", "pass", "signature.verified", "ok", "key")
    args = argparse.Namespace(pin=None, key_lifecycle=None)
    check = _delegation_check.delegation_check(args, tmp_path, run, signature, AT)
    assert check.outcome == "fail" and check.reason == "delegation.revoked", check.detail
    registry.write_text(json.dumps({"schema": "tine-key-lifecycle/1", "keys": {}}), "utf-8")
    check = _delegation_check.delegation_check(args, tmp_path, run, signature, AT)
    assert check.outcome == "pass" and check.reason == "delegation.verified"
