"""Rekor v2 (tile log) receipts, verified offline (0.44, X34).

A Rekor v2 log (rekor-tiles) is a C2SP tlog-tiles log: there is no signed entry
timestamp, only an RFC 9162 inclusion proof to a C2SP signed-note checkpoint.
A ``TransparencyLogEntry`` with ``kindVersion.version == "0.0.2"`` carries:

* ``canonicalizedBody`` -- the leaf (``SHA-256(0x00 || body)``), a ``dsse``
  v0.0.2 entry (:mod:`._rekor_v2_body`);
* ``inclusionProof`` -- ``logIndex``, ``treeSize``, ``rootHash``, ``hashes``
  and ``checkpoint.envelope``, the signed note;
* ``logId.keyId`` -- for a v2 log this is the signed-note key id of the
  checkpoint key, ``SHA-256(origin || 0x0A || type || key)``, not the v1
  ``SHA-256(SPKI)``; the trusted root's ``baseUrl`` host is the origin.

Ed25519 keys (type ``0x01``, what the public-good 2025 v2 shards use) follow
signed-note exactly. ECDSA P-256 keys are accepted under type ``0x02`` over the
SPKI DER, as sigstore-go's note verifier does -- that form is *not* covered by a
public fixture we could check, so treat it as best effort. ``tiles`` (a local
tile mirror) additionally recomputes the proof from hash tiles and requires
the entry's hashes to match. Nothing here opens a socket.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from opentine.repository import _tlog, _tlog_proof

V2 = "0.0.2"


def _der(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def note_key_id(origin: str, key: Any) -> bytes:
    if isinstance(key, ed25519.Ed25519PublicKey):
        material = b"\x01" + key.public_bytes_raw()
    elif isinstance(key, ec.EllipticCurvePublicKey):
        material = b"\x02" + _der(key)
    else:
        raise ValueError("a Rekor v2 key must be Ed25519 or ECDSA")
    return hashlib.sha256(origin.encode() + b"\n" + material).digest()


def origin_of(base_url: str) -> str:
    parsed = urlparse(base_url)
    return (parsed.netloc + parsed.path.rstrip("/")) if parsed.netloc else base_url


def tile_logs(doc: dict) -> list[tuple[bytes, str, Any]]:
    """``(key id, origin, key)`` of every ``tlogs`` entry whose id is a note key id."""
    found = []
    for item in doc.get("tlogs") or []:
        try:
            public = item["publicKey"]
            key = serialization.load_der_public_key(base64.b64decode(public["rawBytes"]))
            key_id = base64.b64decode(item["logId"]["keyId"])
            origin = origin_of(str(item.get("baseUrl", "")))
            if key_id == note_key_id(origin, key):
                found.append((key_id, origin, key))
        except (KeyError, TypeError, ValueError):
            continue
    return found


def is_v2(entry: Any) -> bool:
    return isinstance(entry, dict) and (entry.get("kindVersion") or {}).get("version") == V2


def _signed(key: Any, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_checkpoint(note: str, origin: str, key: Any, size: int, root: bytes) -> None:
    text, sep, signatures = str(note).partition("\n\n")
    lines = text.split("\n")
    if not sep or len(lines) < 3 or lines[0] != origin:
        raise ValueError("checkpoint is not a signed note from this log")
    if lines[1] != str(size) or base64.b64decode(lines[2], validate=True) != root:
        raise ValueError("checkpoint names a different tree size or root hash")
    hint, message = note_key_id(origin, key)[:4], (text + "\n").encode()
    for line in signatures.split("\n"):
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "—" or parts[1] != origin:
            continue
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except ValueError:
            continue
        if raw[:4] == hint and _signed(key, raw[4:], message):
            return
    raise ValueError("checkpoint carries no signature by the log key")


def _int(value: Any) -> int:
    if isinstance(value, bool) or not str(value).isdigit():
        raise ValueError("Rekor v2 entry has a malformed integer")
    return int(str(value))


def verify_entry(
    entry: dict, logs: list[tuple[bytes, str, Any]], *, tiles: Path | None = None
) -> tuple[int, bytes]:
    """``(log index, body)`` of a v2 entry whose proof and checkpoint verify."""
    key_id = base64.b64decode(str((entry.get("logId") or {}).get("keyId")), validate=True)
    match = next(((o, k) for i, o, k in logs if i == key_id), None)
    if match is None:
        raise ValueError("no Rekor v2 log in the trusted root matches the entry's logId")
    origin, key = match
    body = base64.b64decode(str(entry.get("canonicalizedBody")), validate=True)
    proof = entry.get("inclusionProof")
    if not isinstance(proof, dict):
        raise ValueError("Rekor v2 entry carries no inclusion proof")
    index, size = _int(proof.get("logIndex")), _int(proof.get("treeSize"))
    root = base64.b64decode(str(proof.get("rootHash")), validate=True)
    path = _tlog_proof.decode(proof.get("hashes"))
    if _int(entry.get("logIndex", index)) != index:
        raise ValueError("entry and proof name different log indexes")
    try:
        if tiles is not None:
            hashes = _tlog_proof.Hashes(size, lambda rel: _tlog._read(tiles, rel))
            if _tlog_proof.inclusion_proof(hashes, index) != path:
                raise ValueError("inclusion proof differs from the one the tiles give")
        _tlog_proof.verify_inclusion(_tlog.leaf_hash(body), index, size, path, root)
    except _tlog.LogError as exc:
        raise ValueError(str(exc)) from exc
    verify_checkpoint((proof.get("checkpoint") or {}).get("envelope"), origin, key, size, root)
    return index, body
