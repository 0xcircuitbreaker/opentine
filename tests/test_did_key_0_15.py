"""``did:key`` for Ed25519 keys: base58btc, the W3C vector, and canonical parsing."""

from __future__ import annotations

import json

import pytest

from opentine import cli
from opentine._signing_keys import SignatureError
from opentine.did_key import (
    b58decode,
    b58encode,
    did_from_public,
    local_dids,
    public_from_did,
)

# W3C CCG did:key test vector: the Ed25519 key of the all-zero seed.
ZERO_SEED_PUB = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
ZERO_SEED_DID = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"


@pytest.mark.parametrize(
    ("raw", "text"),
    [
        (b"", ""),
        (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
        (bytes.fromhex("000000287fb4cd"), "111233QC4"),
        (b"\0", "1"),
    ],
)
def test_base58btc_vectors(raw: bytes, text: str) -> None:
    assert b58encode(raw) == text
    assert b58decode(text) == raw


def test_w3c_ed25519_vector_both_ways() -> None:
    assert did_from_public(ZERO_SEED_PUB) == ZERO_SEED_DID
    assert public_from_did(ZERO_SEED_DID).public_bytes_raw().hex() == ZERO_SEED_PUB


@pytest.mark.parametrize(
    "bad",
    [
        "did:web:example.com",
        "did:key:" + ZERO_SEED_DID[9:],  # no multibase prefix
        ZERO_SEED_DID[:-1],  # truncated
        ZERO_SEED_DID + "1",  # trailing zero byte
        ZERO_SEED_DID.replace("z6Mk", "z6M0"),  # '0' is not base58btc
        "did:key:z" + b58encode(b"\x12\x00" + bytes(32)),  # another multicodec
        "did:key:z" + "1" * 500,
        None,
    ],
)
def test_malformed_did_is_refused(bad) -> None:
    with pytest.raises(SignatureError):
        public_from_did(bad)


def test_small_order_key_is_refused() -> None:
    with pytest.raises(SignatureError):
        did_from_public(bytes(32))


def test_agent_keys_expose_did(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.chdir(tmp_path)
    cli.main(["keygen", "--agent", "bot"])
    capsys.readouterr()
    cli.main(["agent", "keys", "--json"])
    payload = json.loads(capsys.readouterr().out)
    [fpr] = payload["keys"]
    did = payload["dids"][fpr]
    assert did.startswith("did:key:z6Mk")
    pub = (tmp_path / "cfg" / "opentine" / "agent-keys" / "bot.pub").read_text().strip()
    assert did == did_from_public(pub)
    assert local_dids(tmp_path / "cfg" / "opentine" / "agent-keys") == {fpr: did}
    cli.main(["agent", "id", "--harness", "custom", "--agent", "bot", "--json"])
    assert json.loads(capsys.readouterr().out)["did"] == did
