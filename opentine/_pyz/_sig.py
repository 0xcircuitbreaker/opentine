"""Signature blocks: ``tine-sig/1``, ``/2`` (v2 files) and ``tine-sig/3`` (v4 files).

The rules are ``opentine._signing_verify.verify_block`` and
``_signing_verdicts``: the stored block holds the five header keys, ``value``
and, for Ed25519 only, ``public_key``; no key is ``null``; the value and key
are lowercase hex of their exact length; a trusted Ed25519 key must equal the
embedded one and must not be of small order. The verdict is one of the five
states ``verified``, ``unsigned``, ``no-key``, ``mismatch`` and ``error``.
HMAC uses the stdlib; Ed25519 uses the pure-Python :mod:`._ed25519`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from typing import Any

from .. import kernel
from .._ed25519_order import weak_public_key
from . import _ed25519, _pqsig

HEADER_KEYS = ("alg", "key_id", "scheme", "signed_at", "signer")
BLOCK_KEYS = frozenset((*HEADER_KEYS, "value", "public_key"))
VALUE_LENGTHS = {"hmac-sha256": 64, "ed25519": 128}
MIN_HMAC_KEY_BYTES = 16
SIG_DOMAIN = b"opentine.signature.v1:"
SIG3_DOMAIN = b"opentine.signature.v3:"
V1_METADATA = (
    "model_info", "system_prompt", "user_prompt", "forked_from", "fork_point", "warnings",
    "replay", "context", "next_harness", "migration", "fork",
)  # fmt: skip
_LOWER_HEX = re.compile(r"[0-9a-f]+")

Verdict = tuple[bool, str, str]  # (ok, state, reason)


def lower_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and bool(_LOWER_HEX.fullmatch(value))


def verify_block(
    block: Any,
    message: Callable[[dict[str, Any]], bytes],
    schemes: tuple[str, ...],
    *,
    hmac_key: bytes | None,
    public_key: bytes | None,
) -> Verdict:
    if block is None:
        return False, "unsigned", "no signature present"
    if not isinstance(block, dict):
        return False, "error", "signature is not an object"
    if block.get("scheme") not in schemes:
        return False, "error", "unsupported signature scheme"
    if hmac_key is not None and public_key is not None:
        return False, "error", "pass exactly one verification key"
    algorithm = block.get("alg")
    if set(block) - BLOCK_KEYS or (
        algorithm not in ("ed25519", *_pqsig.SIZES) and "public_key" in block
    ):
        return False, "error", "malformed signature header"
    if any(item is None for item in block.values()) or not isinstance(algorithm, str):
        return False, "error", "malformed signature header"
    if any(not isinstance(block.get(k, ""), str) for k in ("key_id", "signer", "signed_at")):
        return False, "error", "malformed signature header"
    if algorithm not in VALUE_LENGTHS and algorithm not in _pqsig.SIZES:
        return False, "error", "unsupported signature algorithm"
    value = block.get("value")
    if algorithm in VALUE_LENGTHS and not lower_hex(value, VALUE_LENGTHS[algorithm]):
        return False, "error", "malformed signature value"
    header = {name: block.get(name) for name in HEADER_KEYS}
    try:
        signed = message(header)
    except (RecursionError, TypeError, ValueError):
        return False, "error", "malformed signed artifact content"
    if algorithm in _pqsig.SIZES:
        return _pqsig.verdict(algorithm, value, block.get("public_key"), signed, public_key)
    if algorithm == "hmac-sha256":
        if hmac_key is None:
            return False, "no-key", "HMAC signature present but no key supplied"
        if len(hmac_key) < MIN_HMAC_KEY_BYTES:
            return False, "error", f"HMAC key too short ({len(hmac_key)} bytes)"
        expected = hmac.new(hmac_key, signed, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, value):
            return True, "verified", "ok"
        return False, "mismatch", "signature mismatch"
    embedded = block.get("public_key")
    if not lower_hex(embedded, 64):
        return False, "error", "malformed ed25519 public key"
    if public_key is None:
        return False, "no-key", "ed25519 signature present but no trusted public key"
    if weak_public_key(public_key):
        return False, "error", "ed25519 public key has small order or a non-canonical encoding"
    if embedded != public_key.hex():
        return False, "mismatch", "embedded public key is not the trusted key"
    if not _ed25519.verify(public_key, signed, bytes.fromhex(value)):
        return False, "mismatch", "signature mismatch"
    return True, "verified", "ok"


def _canon_v2(value: Any) -> bytes:
    """``opentine._canon._canonical_bytes`` over parsed JSON (already plain values)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def v2_message(data: dict[str, Any]) -> Callable[[dict[str, Any]], bytes]:
    def build(header: dict[str, Any]) -> bytes:
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("artifact metadata must be an object")
        if header.get("scheme") == "tine-sig/2":
            signed = {k: v for k, v in metadata.items() if k != "integrity"}
        else:
            signed = {k: metadata.get(k) for k in V1_METADATA if k in metadata}
        view = {
            "body": {k: v for k, v in data.items() if k != "metadata"},
            "header": header,
            "metadata": signed,
        }
        return SIG_DOMAIN + _canon_v2(view)

    return build


def v4_message(data: dict[str, Any]) -> Callable[[dict[str, Any]], bytes]:
    def build(header: dict[str, Any]) -> bytes:
        annotations = data.get("annotations")
        if not isinstance(annotations, list):
            raise ValueError("v4 annotations must be a list")
        head = None
        if annotations:
            head = annotations[-1].get("id") if isinstance(annotations[-1], dict) else None
            if not isinstance(head, str):
                raise ValueError("v4 annotation head has no id")
        view = {
            "annotations_head": head,
            "format_version": 4,
            "header": header,
            "kind": "tine-artifact/4",
            "root": data["root"],
        }
        return SIG3_DOMAIN + kernel.canonical_json(view)

    return build


def artifact_verdict(
    data: dict[str, Any], v4: bool, *, hmac_key: bytes | None, public_key: bytes | None
) -> Verdict:
    """The verdict ``Run.verify_signature`` gives (the first block a key verifies wins)."""
    if not v4:
        meta = data.get("metadata")
        integrity = meta.get("integrity") if isinstance(meta, dict) else None
        block = integrity.get("signature") if isinstance(integrity, dict) else None
        schemes = ("tine-sig/1", "tine-sig/2")
        return verify_block(
            block, v2_message(data), schemes, hmac_key=hmac_key, public_key=public_key
        )
    blocks = data.get("signatures")
    if not blocks:
        return False, "unsigned", "no signature present"
    if any(not isinstance(b, dict) or b.get("scheme") != "tine-sig/3" for b in blocks):
        return False, "error", "unsupported signature scheme"
    results = [
        verify_block(b, v4_message(data), ("tine-sig/3",), hmac_key=hmac_key, public_key=public_key)
        for b in blocks
    ]
    return next((r for r in results if r[0]), results[0])


__all__ = ["artifact_verdict", "verify_block"]
