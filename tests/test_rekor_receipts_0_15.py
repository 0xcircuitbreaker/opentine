"""Rekor transparency-log receipts for ``tine export --format intoto --rekor``.

Fully offline: a fake log (local P-256 key, a real RFC 6962 Merkle tree) behind
an ``httpx.MockTransport``. The claims: a receipt verifies only under the log
key the verifier supplies, for exactly this envelope; any edit to the SET, the
inclusion proof, the checkpoint or the logged body fails closed; and
``--require-receipt`` refuses an attestation with no receipt or no key.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from opentine import Run, RunStatus, StepKind, cli, rekor
from opentine._rekor_proof import leaf_hash, load_log_key, verify_inclusion
from opentine._signing_keys import generate_ed25519
from opentine.sigstore_bundle import BUNDLE_MEDIA_TYPE, check_entry, split
from tests._sigstore_fakes import FakeLog, _path, _root, transport


@pytest.fixture
def ws(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="rekor_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    seed, public = generate_ed25519()
    (tmp_path / "k.key").write_text(seed + "\n")
    (tmp_path / "k.pub").write_text(public + "\n")
    log = FakeLog()
    (tmp_path / "rekor.pub").write_bytes(log.public_pem())
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log))
    return tmp_path, log


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _export(*extra: str) -> int:
    return _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key",
                "--output", "a.intoto.jsonl", *extra)  # fmt: skip


def _verify(capsys, *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "a.intoto.jsonl", "--pubkey", "k.pub",
                "--json", *extra)  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def _bundle(root: Path) -> dict:
    return json.loads((root / "a.intoto.jsonl").read_text())


def _rewrite(root: Path, bundle: dict) -> None:
    (root / "a.intoto.jsonl").write_text(json.dumps(bundle) + "\n")


def test_merkle_proofs_for_every_leaf_and_size() -> None:
    for size in range(1, 12):
        leaves = [leaf_hash(b"%d" % i) for i in range(size)]
        for index in range(size):
            verify_inclusion(index, size, leaves[index], _path(index, leaves), _root(leaves))
            with pytest.raises(ValueError):
                verify_inclusion(index, size, leaf_hash(b"x"), _path(index, leaves), _root(leaves))


def test_export_writes_a_sigstore_bundle_and_it_verifies(ws, capsys) -> None:
    root, log = ws
    assert _export("--rekor", "https://rekor.test") == 0
    bundle = _bundle(root)
    assert bundle["mediaType"] == BUNDLE_MEDIA_TYPE
    assert bundle["verificationMaterial"]["publicKey"]["hint"].startswith("did:key:z6Mk")
    (entry,) = bundle["verificationMaterial"]["tlogEntries"]
    assert entry["kindVersion"] == {"kind": "dsse", "version": "0.0.1"}
    assert log.posted[0]["kind"] == "dsse"
    code, out = _verify(capsys, "--rekor-key", "rekor.pub", "--require-receipt")
    assert code == 0 and out["ok"] is True
    assert out["receipt"]["status"] == "verified"
    assert out["receipt"]["log_index"] == int(entry["logIndex"])
    assert out["receipt"]["integrated_time"] == int(entry["integratedTime"])
    # Without a key the receipt is reported unchecked, and the signature alone passes.
    code, out = _verify(capsys)
    assert code == 0 and out["receipt"]["status"] == "unchecked"


def _tamper_set(b):
    promise = b["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]
    key = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import hashes

    promise["signedEntryTimestamp"] = base64.b64encode(
        key.sign(b"x", ec.ECDSA(hashes.SHA256()))
    ).decode()


def _tamper_time(b):
    entry = b["verificationMaterial"]["tlogEntries"][0]
    entry["integratedTime"] = str(int(entry["integratedTime"]) + 1)


def _tamper_proof(b):
    hashes_ = b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"]
    hashes_[0] = base64.b64encode(b"\x00" * 32).decode()


def _tamper_root(b):
    proof = b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    proof["rootHash"] = base64.b64encode(b"\x11" * 32).decode()


def _tamper_body(b):
    entry = b["verificationMaterial"]["tlogEntries"][0]
    body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
    body["spec"]["payloadHash"]["value"] = "0" * 64
    entry["canonicalizedBody"] = base64.b64encode(json.dumps(body).encode()).decode()


def _tamper_payload(b):
    # A different (re-signed elsewhere) envelope cannot borrow this receipt.
    statement = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
    statement["predicate"]["step_count"] = 99
    b["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()


@pytest.mark.parametrize(
    "tamper", [_tamper_set, _tamper_time, _tamper_proof, _tamper_root, _tamper_body]
)
def test_tampered_receipts_fail_closed(ws, capsys, tamper) -> None:
    root, _ = ws
    assert _export("--rekor", "https://rekor.test") == 0
    bundle = _bundle(root)
    tamper(bundle)
    _rewrite(root, bundle)
    code, out = _verify(capsys, "--rekor-key", "rekor.pub")
    assert code == 1 and out["ok"] is False
    assert out["receipt"]["status"] == "invalid"
    assert out["signature"]["status"] == "verified"


def test_receipt_does_not_cover_another_envelope(ws) -> None:
    root, log = ws
    assert _export("--rekor", "https://rekor.test") == 0
    bundle = _bundle(root)
    envelope, _, entries = split(json.loads(json.dumps(bundle)))
    _tamper_payload(bundle)
    from opentine.did_key import public_from_did

    signer = public_from_did(envelope["signatures"][0]["keyid"])
    rekor_key = load_log_key(log.public_pem())
    assert check_entry(entries[0], envelope, signer, rekor_key).ok
    result = check_entry(entries[0], bundle["dsseEnvelope"], signer, rekor_key)
    assert not result.ok and "different payload" in result.reason
    other = public_from_did(_other_did())
    assert "different signing key" in check_entry(entries[0], envelope, other, rekor_key).reason


def _other_did() -> str:
    from opentine.did_key import did_from_public

    return did_from_public(generate_ed25519()[1])


def test_wrong_log_key_fails(ws, capsys) -> None:
    root, _ = ws
    assert _export("--rekor", "https://rekor.test") == 0
    (root / "other.pub").write_bytes(FakeLog().public_pem())
    code, out = _verify(capsys, "--rekor-key", "other.pub")
    assert code == 1 and out["receipt"]["status"] == "invalid"
    assert "different log" in out["receipt"]["reason"]


def test_require_receipt_fails_closed(ws, capsys) -> None:
    root, _ = ws
    assert _export() == 0  # a bare envelope: no receipt at all
    code, out = _verify(capsys, "--require-receipt", "--rekor-key", "rekor.pub")
    assert code == 1 and out["receipt"]["status"] == "absent"
    code, out = _verify(capsys)
    assert code == 0 and out["receipt"]["status"] == "absent"
    assert _export("--rekor", "https://rekor.test", "--force") == 0
    code, out = _verify(capsys, "--require-receipt")  # receipt but no key
    assert code == 1 and out["receipt"]["status"] == "no-key"
    (root / "bad.pub").write_text("not a key")
    code, out = _verify(capsys, "--require-receipt", "--rekor-key", "bad.pub")
    assert code == 1 and out["receipt"]["status"] == "no-key"


def test_rekor_flags_need_intoto_and_https(ws) -> None:
    root, _ = ws
    assert _cli("export", "run.tine", "--rekor") == 1
    assert _export("--rekor", "http://rekor.test") == 1
    assert not (root / "a.intoto.jsonl").exists()
    assert _export("--identity-token", "x.y.z") == 1  # only with --keyless
