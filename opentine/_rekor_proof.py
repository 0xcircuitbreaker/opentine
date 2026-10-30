"""The offline checks behind a Rekor receipt: SET, Merkle inclusion, checkpoint.

* The **signed entry timestamp** (SET) is the log's ECDSA signature over the
  canonical JSON ``{"body", "integratedTime", "logID", "logIndex"}``: a promise
  that the entry was accepted at that time and index.
* The **inclusion proof** is an RFC 6962 / RFC 9162 audit path from the entry's
  leaf hash (``SHA256(0x00 || body)``) to the tree's ``rootHash``.
* The **checkpoint** is the log's signed note over ``origin / treeSize /
  rootHash``; it binds that root to the log key, so a proof cannot be against a
  root the verifier made up.

Every function raises ``ValueError`` with a reason; none of them touch the network.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

__all__ = [
    "leaf_hash",
    "load_log_key",
    "log_id",
    "verify_checkpoint",
    "verify_inclusion",
    "verify_set",
]


def load_log_key(pem: bytes) -> ec.EllipticCurvePublicKey:
    """The Rekor log's public key from PEM, refused unless it is ECDSA P-256."""
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise ValueError(f"Rekor key is not a PEM public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("Rekor key must be an ECDSA P-256 public key")
    return key


def log_id(key: Any) -> bytes:
    """A log's id: SHA-256 of its DER SubjectPublicKeyInfo."""
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()


def _ecdsa_ok(key: Any, signature: bytes, message: bytes) -> bool:
    try:
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_set(key: Any, body_b64: str, integrated_time: int, log_index: int, sig: bytes) -> None:
    payload = json.dumps(
        {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": log_id(key).hex(),
            "logIndex": log_index,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if not _ecdsa_ok(key, sig, payload):
        raise ValueError("signed entry timestamp does not verify under the Rekor key")


def leaf_hash(body: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(index: int, size: int, leaf: bytes, path: list[bytes], root: bytes) -> None:
    """RFC 9162 section 2.1.3.2: recompute the root from *leaf* and its audit path."""
    if not 0 <= index < size:
        raise ValueError("inclusion proof index is outside the tree")
    fn, sn, node = index, size - 1, leaf
    for sibling in path:
        if len(sibling) != 32 or sn == 0:
            raise ValueError("inclusion proof is malformed")
        if fn & 1 or fn == sn:
            node = _node(sibling, node)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            node = _node(node, sibling)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0 or node != root:
        raise ValueError("inclusion proof does not lead to the tree's root hash")


def verify_checkpoint(key: Any, note: str, size: int, root: bytes) -> None:
    """Check the signed note names this tree size and root, signed by *key*."""
    if not isinstance(note, str) or "\n\n" not in note:
        raise ValueError("checkpoint is not a signed note")
    text, _, signatures = note.partition("\n\n")
    lines = text.split("\n")
    if len(lines) < 3 or lines[1] != str(size):
        raise ValueError("checkpoint names a different tree size")
    try:
        named_root = base64.b64decode(lines[2], validate=True)
    except binascii.Error as exc:
        raise ValueError("checkpoint root hash is not base64") from exc
    if named_root != root:
        raise ValueError("checkpoint names a different root hash")
    hint, message = log_id(key)[:4], (text + "\n").encode("utf-8")
    for line in signatures.split("\n"):
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "—":
            continue
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except binascii.Error:
            continue
        if raw[:4] == hint and _ecdsa_ok(key, raw[4:], message):
            return
    raise ValueError("checkpoint carries no signature by the Rekor key")
