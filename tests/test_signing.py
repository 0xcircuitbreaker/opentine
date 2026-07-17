"""HMAC / Ed25519 signing coverage (the tine-sig/1 trust boundary)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import opentine.signing as signing
from opentine import Run, StepKind
from opentine._canon import _integrity_digest
from opentine._signing_keys import MAX_SIGNING_KEY_BYTES, hmac_key_from_file
from opentine.core import RunStatus
from opentine.signing import SignatureError, generate_ed25519

KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes


def _terminal_run(run_id: str = "x", *, user_prompt: str = "ask", tags=()) -> Run:
    run = Run(id=run_id, user_prompt=user_prompt, tags=list(tags))
    run.add_step(StepKind.done, {"text": "hi"}, cost=0.1)
    run.status = RunStatus.completed
    return run


# --- HMAC -------------------------------------------------------------------


def test_hmac_roundtrip(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY, key_id="k1", signer="alice")
    res = Run.verify_signature(p, hmac_key=KEY)
    assert res.ok and res.state == "verified" and res.algorithm == "hmac-sha256"
    assert res.key_id == "k1" and res.signer == "alice"


def test_unsigned_has_no_signature_block(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "u.tine")
    assert "signature" not in json.loads(p.read_text())["metadata"]["integrity"]
    res = Run.verify_signature(p, hmac_key=KEY)
    assert not res.ok and res.state == "unsigned"


def test_wrong_key_is_mismatch(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY)
    res = Run.verify_signature(p, hmac_key=b"x" * 32)
    assert not res.ok and res.state == "mismatch"


def test_no_key_is_fail_closed_state(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY)
    res = Run.verify_signature(p)
    assert not res.ok and res.state == "no-key"


def test_body_tamper_with_digest_rewrite_still_fails_signature(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY)
    data = json.loads(p.read_text())
    sid = next(iter(data["graph"]["steps"]))
    data["graph"]["steps"][sid]["inputs"]["text"] = "EVIL"
    # attacker recomputes the (unkeyed) integrity digest over the tampered body
    data["metadata"]["integrity"]["digest"] = _integrity_digest(data)
    p.write_text(json.dumps(data), encoding="utf-8")

    assert Run.verify_integrity(p).ok  # digest passes — it's just a checksum
    assert not Run.verify_signature(p, hmac_key=KEY).ok  # signature commits to content


def test_allowlisted_metadata_tamper_breaks_signature(tmp_path: Path):
    p = _terminal_run(user_prompt="benign").save(tmp_path / "a.tine", sign_key=KEY)
    data = json.loads(p.read_text())
    data["metadata"]["user_prompt"] = "INJECTED"  # user_prompt is in the signed allowlist
    p.write_text(json.dumps(data), encoding="utf-8")
    assert Run.verify_integrity(p).ok  # metadata is outside the digest
    assert not Run.verify_signature(p, hmac_key=KEY).ok  # but inside the signature


def test_tags_and_budget_state_edits_do_not_break_signature(tmp_path: Path):
    run = _terminal_run(tags=["a"])
    run.metadata["budget_state"] = {"breached": False}
    p = run.save(tmp_path / "a.tine", sign_key=KEY)
    assert Run.verify_signature(p, hmac_key=KEY).ok

    data = json.loads(p.read_text())
    data["metadata"]["tags"] = ["a", "b", "c"]  # mutable label, outside the signature
    data["metadata"]["budget_state"] = {"breached": True, "dimension": "cost"}
    p.write_text(json.dumps(data), encoding="utf-8")
    assert Run.verify_signature(p, hmac_key=KEY).ok  # re-tagging never re-signs


def test_key_id_is_not_redacted(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY, key_id="prod-key-2026")
    block = json.loads(p.read_text())["metadata"]["integrity"]["signature"]
    assert block["key_id"] == "prod-key-2026"


def test_refuse_to_sign_nonterminal_or_draft(tmp_path: Path):
    running = Run(id="r")
    running.add_step(StepKind.think, {"text": "wip"})  # status running
    with pytest.raises(SignatureError):
        running.save(tmp_path / "a.tine", sign_key=KEY)

    done = _terminal_run()
    with pytest.raises(SignatureError):
        done.save(tmp_path / "b.tine", sign_key=KEY, draft=True)


def test_weak_hmac_key_rejected(tmp_path: Path):
    with pytest.raises(SignatureError):
        _terminal_run().save(tmp_path / "a.tine", sign_key=b"short")


def test_signing_key_file_read_is_bounded(tmp_path: Path):
    key = tmp_path / "oversized.key"
    key.write_bytes(b"x" * (MAX_SIGNING_KEY_BYTES + 1))
    with pytest.raises(SignatureError, match="exceeds the 1 MiB limit"):
        hmac_key_from_file(key)


def test_signature_stripped_on_plain_resave(tmp_path: Path):
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=KEY)
    loaded = Run.load(p)
    loaded.save(p)  # plain re-save, no sign_key
    assert "signature" not in json.loads(p.read_text())["metadata"]["integrity"]


def test_no_variable_length_concat_collision(tmp_path: Path):
    run = _terminal_run()
    v1 = json.loads(
        run.save(tmp_path / "a.tine", sign_key=KEY, key_id="ab", signer="c").read_text()
    )["metadata"]["integrity"]["signature"]["value"]
    v2 = json.loads(
        run.save(tmp_path / "b.tine", sign_key=KEY, key_id="a", signer="bc").read_text()
    )["metadata"]["integrity"]["signature"]["value"]
    assert v1 != v2  # structured signed view, not ('ab','c') vs ('a','bc') concat


# --- Ed25519 ----------------------------------------------------------------


def test_ed25519_roundtrip_and_tofu(tmp_path: Path):
    seed, pub = generate_ed25519()
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=seed, sign_algorithm="ed25519")

    explicit = Run.verify_signature(p, public_key=pub)
    assert explicit.ok and explicit.state == "verified" and explicit.algorithm == "ed25519"

    tofu = Run.verify_signature(p, trust_embedded=True)
    assert tofu.ok and tofu.state == "verified-tofu"

    no_key = Run.verify_signature(p)
    assert not no_key.ok and no_key.state == "no-key"


def test_ed25519_missing_crypto_reports_error(tmp_path: Path, monkeypatch):
    seed, _ = generate_ed25519()
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=seed, sign_algorithm="ed25519")
    monkeypatch.setattr(signing, "HAS_ED25519", False)
    res = Run.verify_signature(p, trust_embedded=True)
    assert res.state == "error" and "cryptography" in res.reason


def test_malformed_embedded_ed25519_key_is_a_fail_closed_result(tmp_path: Path):
    seed, _ = generate_ed25519()
    path = _terminal_run().save(tmp_path / "bad-key.tine", sign_key=seed, sign_algorithm="ed25519")
    data = json.loads(path.read_text())
    data["metadata"]["integrity"]["signature"]["public_key"] = "00"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = Run.verify_signature(path, trust_embedded=True)

    assert not result.ok and result.state == "error"
    assert result.reason == "malformed ed25519 public key"


def test_golden_signed_fixture_verifies():
    # Guards the tine-sig/1 signed-view canonicalization against accidental drift.
    fixture = Path(__file__).parent / "fixtures" / "golden_signed_v2.tine"
    golden_key = b"golden-tine-signing-key-01234567"
    res = Run.verify_signature(fixture, hmac_key=golden_key)
    assert res.ok and res.state == "verified"
    assert res.key_id == "golden" and res.signed_at == "2026-01-01T00:00:00Z"
    assert Run.verify_integrity(fixture).ok


def test_ed25519_without_trust_is_no_key(tmp_path: Path):
    seed, _ = generate_ed25519()
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=seed, sign_algorithm="ed25519")
    # an embedded public key alone is not trusted unless trust_embedded is set
    res = Run.verify_signature(p)
    assert not res.ok and res.state == "no-key"


def test_algorithm_downgrade_does_not_bypass(tmp_path: Path):
    seed, pub = generate_ed25519()
    p = _terminal_run().save(tmp_path / "a.tine", sign_key=seed, sign_algorithm="ed25519")
    data = json.loads(p.read_text())
    # attacker flips alg to hmac-sha256 to try a confusion attack
    data["metadata"]["integrity"]["signature"]["alg"] = "hmac-sha256"
    p.write_text(json.dumps(data), encoding="utf-8")
    assert not Run.verify_signature(p, hmac_key=KEY).ok
