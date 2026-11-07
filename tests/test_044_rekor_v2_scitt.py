"""0.44 X34 (Rekor v2 tile receipts, SigningConfig) and experimental SCITT, all offline.

The Rekor v2 fixture is built, not downloaded: a C2SP tlog-tiles log written by
opentine's own ``opentine-log/1`` code (the same tile layout, RFC 6962 hashing
and Ed25519 signed-note checkpoint rekor-tiles serves), whose origin is the
trusted root's ``baseUrl`` host and whose ``logId.keyId`` is the signed-note key
id -- the shape the public-good root has listed for v2 shards since 2025.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from opentine import _cbor, _rekor_v2, _rekor_v2_body, _scitt, _signing_config
from opentine.repository import _tlog, _tlog_note

ORIGIN = "log2025-1.rekor.example.dev"
b64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731


def _der(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _fixture(tmp_path: Path, entries: int = 5):
    signer = ec.generate_private_key(ec.SECP256R1())
    payload = b'{"_type":"https://in-toto.io/Statement/v1"}'
    sig = b64(signer.sign(b"DSSEv1 ...", ec.ECDSA(hashes.SHA256())))
    envelope = {"payload": b64(payload), "payloadType": "application/vnd.in-toto+json",
                "signatures": [{"sig": sig}]}  # fmt: skip
    spki = b64(_der(signer.public_key()))
    verifier = {"publicKey": {"rawBytes": spki}, "keyDetails": "PKIX_ECDSA_P256_SHA_256"}
    digest = {"algorithm": "SHA2_256", "digest": b64(hashlib.sha256(payload).digest())}
    spec = {"payloadHash": digest, "signatures": [{"content": sig, "verifier": verifier}]}
    body = json.dumps({"apiVersion": "0.0.2", "kind": "dsse", "spec": {"dsseV002": spec}}).encode()
    root = tmp_path / "rekor"
    for i in range(entries):
        _tlog_note.append(root, ORIGIN, lambda _e, i=i: body if i == 2 else f"other {i}".encode())
    from opentine.repository._tlog_receipt import make

    receipt = make(root, ORIGIN, 2)
    _, raw = _tlog_note.parse_vkey(_tlog_note.stored_vkey(root))
    log_key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    note = receipt["checkpoint"]
    lines = note.split("\n")
    entry = {
        "logIndex": "2",
        "logId": {"keyId": b64(_rekor_v2.note_key_id(ORIGIN, log_key))},
        "kindVersion": {"kind": "dsse", "version": "0.0.2"},
        "canonicalizedBody": b64(body),
        "inclusionProof": {"logIndex": "2", "treeSize": lines[1], "rootHash": lines[2],
                           "hashes": receipt["inclusion"], "checkpoint": {"envelope": note}},
    }  # fmt: skip
    trusted = {"tlogs": [{"baseUrl": f"https://{ORIGIN}", "logId": entry["logId"],
                          "publicKey": {"rawBytes": b64(_der(log_key))}}]}  # fmt: skip
    return entry, trusted, envelope, signer, root


def test_a_rekor_v2_entry_verifies_offline_and_against_its_tiles(tmp_path):
    entry, trusted, envelope, signer, root = _fixture(tmp_path)
    logs = _rekor_v2.tile_logs(trusted)
    assert [o for _, o, _ in logs] == [ORIGIN]
    index, body = _rekor_v2.verify_entry(entry, logs, tiles=root)
    assert index == 2
    _rekor_v2_body.check_body(body, envelope, _der(signer.public_key()))
    result = _rekor_v2_body.check_v2_entry(logs, entry, envelope, signer.public_key())
    assert result.status == "unchecked" and "TSA" in result.reason  # fail closed, named


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (
            lambda e: e["inclusionProof"].update(
                logIndex="3", treeSize=e["inclusionProof"]["treeSize"]
            ),
            "index",
        ),
        (lambda e: e.update(canonicalizedBody=b64(b"forged")), "inclusion"),
        (
            lambda e: e["inclusionProof"]["checkpoint"].update(envelope="x\n1\nAA==\n\n"),
            "checkpoint",
        ),
        (lambda e: e["logId"].update(keyId=b64(b"\0" * 32)), "logId"),
    ],
)
def test_a_tampered_rekor_v2_entry_is_refused(tmp_path, mutate, reason):
    entry, trusted, *_ = _fixture(tmp_path)
    mutate(entry)
    with pytest.raises(ValueError, match=reason):
        _rekor_v2.verify_entry(entry, _rekor_v2.tile_logs(trusted))


def _config(**extra):
    def service(url, major, start="2025-01-01T00:00:00Z", end=None, op="sigstore.dev"):
        valid = {"start": start, **({"end": end} if end else {})}
        return {"url": url, "majorApiVersion": major, "validFor": valid, "operator": op}

    return {
        "mediaType": _signing_config.MEDIA_TYPE,
        "rekorTlogUrls": [
            service("https://rekor.sigstore.dev", 1),
            service("https://log2025-1.rekor.sigstore.dev", 2, start="2025-09-01T00:00:00Z"),
            service("https://log2024.rekor.sigstore.dev", 2, end="2025-06-01T00:00:00Z"),
            service("https://rekor.other.dev", 2, op="other.dev"),
        ],
        "tsaUrls": [service("https://timestamp.sigstore.dev/api/v1/timestamp", 1)],
        **extra,
    }


def test_signing_config_selects_logs_and_tsas_without_fetching():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    doc = _signing_config.parse(json.dumps(_config()).encode())
    assert _signing_config.select(doc, "rekor", now=now) == ["https://log2025-1.rekor.sigstore.dev"]
    every = _config(rekorTlogConfig={"selector": "ALL"})
    assert _signing_config.select(every, "rekor", now=now) == [
        "https://log2025-1.rekor.sigstore.dev",
        "https://rekor.other.dev",
    ]  # one per operator, newest v2 first; the expired 2024 shard is gone
    assert _signing_config.select(doc, "rekor", now=now, versions=(1,)) == [
        "https://rekor.sigstore.dev"
    ]
    assert _signing_config.select(doc, "tsa", now=now)[0].startswith("https://timestamp.")
    exact = _config(rekorTlogConfig={"selector": "EXACT", "count": 3})
    with pytest.raises(ValueError, match="needs 3"):
        _signing_config.select(exact, "rekor", now=now)
    with pytest.raises(ValueError, match="mediaType|signingconfig"):
        _signing_config.parse(b'{"mediaType": "x"}')


# --- SCITT (experimental) ------------------------------------------------------ #


def _sign1(key, protected: dict, payload, unprotected=None, detached=None) -> bytes:
    prot = _cbor.dumps(protected)
    body = payload if detached is None else detached
    message = _cbor.dumps(["Signature1", prot, b"", body])
    if isinstance(key, ed25519.Ed25519PrivateKey):
        sig = key.sign(message)
    else:
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _cbor.dumps(_cbor.Tag(18, [prot, unprotected or {}, payload, sig]))


def test_a_scitt_statement_and_receipt_verify_against_pinned_keys():
    issuer, service = ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate()
    statement = _sign1(
        issuer, {1: -7, 3: "application/json", 15: {1: "did:x:iss", 2: "pkg"}}, b"{}"
    )
    leaves = [_tlog.leaf_hash(b"a"), _tlog.leaf_hash(statement), _tlog.leaf_hash(b"c")]
    root = _tlog.merkle_root(leaves)
    path = [leaves[0], leaves[2]]  # index 1 of 3: sibling 0, then the right subtree
    proof = _cbor.dumps([3, 1, path])
    receipt = _sign1(service, {1: -8, 395: 1}, None, {396: {-1: [proof]}}, detached=root)
    result = _scitt.verify_statement(
        statement, issuer.public_key(), service_key=service.public_key(), receipts=[receipt]
    )
    assert result["issuer"] == "did:x:iss" and result["receipts"][0]["tree_size"] == 3
    with pytest.raises(_scitt.SCITTError, match="pinned key"):
        _scitt.verify_statement(statement, ec.generate_private_key(ec.SECP256R1()).public_key())
    forged = _sign1(service, {1: -8, 395: 1}, None, {396: {-1: [proof]}}, detached=b"\0" * 32)
    with pytest.raises(_scitt.SCITTError):
        _scitt.verify_statement(statement, issuer.public_key(), service_key=service.public_key(),
                                receipts=[forged])  # fmt: skip


def test_the_cbor_codec_is_bounded():
    assert _cbor.loads(_cbor.dumps({1: [b"x", "y", -5, None, True]})) == {
        1: [b"x", "y", -5, None, True]
    }
    for bad in (b"\x9f\xff", b"\x5a\xff\xff\xff\xff", b"\x01\x02", b"\x81" * 40 + b"\x00"):
        with pytest.raises(_cbor.CBORError):
            _cbor.loads(bad)


def test_scitt_cli_needs_experimental(tmp_path):
    from tests.test_044_transparency import _code

    key = ed25519.Ed25519PrivateKey.generate()
    pem = tmp_path / "k.pem"
    pem.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))  # fmt: skip
    stmt = tmp_path / "s.cose"
    stmt.write_bytes(_sign1(key, {1: -8}, b"hello"))
    assert _code(["scitt", "verify", str(stmt), "--key", str(pem)]) == 2
    assert _code(["scitt", "verify", str(stmt), "--key", str(pem), "--experimental"]) == 0
