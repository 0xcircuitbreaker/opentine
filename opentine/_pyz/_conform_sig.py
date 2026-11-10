"""``sig.message`` and ``sig.verify`` as conformance ops, in the pyz's own code (0.50).

The signed-message bytes of every scheme (SPEC 4.5 to 4.8, 9.3) and the full
seven-field verdict (``ok``, ``state``, ``algorithm``, ``key_id``, ``signer``,
``signed_at``, ``reason``) of ``_signing_verify.verify_block`` and
``_signing_v4.verify_artifact_v4``, including ``trust_embedded`` (the
``verified-tofu`` state). Before 0.50 the pyz gave only the verdict state, for
whole files; the parity gate now compares every field of every case.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from .. import _tine_v5, kernel
from .._ed25519_order import weak_public_key
from . import _artifact, _conform_artifact, _ed25519, _mldsa, _pqsig, _sig

HEADER_KEYS = _sig.HEADER_KEYS
VALUE_LENGTHS = _sig.VALUE_LENGTHS
_EMBEDS_KEY = frozenset(("ed25519", "ml-dsa-65", "ed25519+ml-dsa-65"))
_ATTEST_V1 = b"opentine.attestation.v1:"
_ATTEST_V2 = b"opentine.attestation.v2:"
_ACTIONS = b"opentine.actions.v1:"
FIELDS = ("ok", "state", "algorithm", "key_id", "signer", "signed_at", "reason")


def _header(header: dict) -> dict:
    return {key: header.get(key) for key in HEADER_KEYS}


def artifact_message(data: Any, header: dict) -> bytes:
    """``tine-sig/1`` and ``/2``: SPEC 4.5's view of a v2 artifact."""
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("artifact metadata must be an object")
    if header.get("scheme") == "tine-sig/2":
        signed = {k: v for k, v in metadata.items() if k != "integrity"}
    else:
        signed = {k: metadata.get(k) for k in _sig.V1_METADATA if k in metadata}
    body = {k: v for k, v in data.items() if k != "metadata"}
    view = {"body": body, "header": _header(header), "metadata": signed}
    return _sig.SIG_DOMAIN + _sig.canon_v2(view)


def v4_message(data: Any, header: dict) -> bytes:
    """``tine-sig/3``: the root and the annotation head of a v4 artifact (SPEC 9.3)."""
    root = data.get("root") if isinstance(data, dict) else None
    if not isinstance(root, str):
        raise ValueError("v4 artifact has no root")
    annotations = data.get("annotations")
    if not isinstance(annotations, list):
        raise ValueError("v4 annotations must be a list")
    head = None
    if annotations:
        head = annotations[-1].get("id") if isinstance(annotations[-1], dict) else None
        if not isinstance(head, str):
            raise ValueError("v4 annotation head has no id")
    view = {"annotations_head": head, "format_version": 4, "header": _header(header),
            "kind": "tine-artifact/4", "root": root}  # fmt: skip
    return _sig.SIG3_DOMAIN + kernel.canonical_json(view)


def attest_message(payload: Any, header: dict) -> bytes:
    """``tine-attest/1`` (v2 canonical form) and ``tine-attest/2`` (JCS, Ed25519, a run)."""
    if not isinstance(payload, dict):
        raise ValueError("attestation payload must be an object")
    body = {key: value for key, value in payload.items() if key != "signature"}
    view = {"body": body, "header": _header(header)}
    if header.get("scheme") != "tine-attest/2":
        return _ATTEST_V1 + _sig.canon_v2(view)
    if header.get("alg") != "ed25519":
        raise ValueError("tine-attest/2 is Ed25519 only")
    target = payload.get("target_id")
    if not isinstance(target, str) or kernel.parse_oid(target)[0] != "run":
        raise ValueError("tine-attest/2 must target a run root")
    return _ATTEST_V2 + kernel.canonical_json(view)


def actions_message(body: Any, header: dict) -> bytes:
    return _ACTIONS + kernel.canonical_json({"body": body, "header": _header(header)})


MESSAGES: dict[str, Callable[[Any, dict], bytes]] = {
    "tine-sig/1": artifact_message, "tine-sig/2": artifact_message, "tine-sig/3": v4_message,
    "tine-attest/1": attest_message, "tine-attest/2": attest_message,
    "tine-actions/1": actions_message,
}  # fmt: skip


def _keyed(algorithm: str, message: bytes, value: str, block: dict, keys: dict) -> tuple:
    """``(ok, state, reason)``: ``_signing_verdicts`` and ``_signing_pq.pq_verdict``."""
    public_key, trust = keys["public_key"], keys["trust_embedded"]
    embedded = block.get("public_key")
    if algorithm == "hmac-sha256":
        key = keys["hmac_key"]
        if key is None:
            return False, "no-key", "HMAC signature present but no key supplied"
        if len(key) < _sig.MIN_HMAC_KEY_BYTES:
            floor = _sig.MIN_HMAC_KEY_BYTES
            return False, "error", f"HMAC key too short ({len(key)} bytes); use at least {floor}"
        good = hmac.compare_digest(hmac.new(key, message, hashlib.sha256).hexdigest(), value)
        return good, "verified" if good else "mismatch", "ok" if good else "signature mismatch"
    if algorithm in _pqsig.SIZES:
        value_len, key_len = _pqsig.SIZES[algorithm]
        if not _sig.lower_hex(value, 2 * value_len):
            return False, "error", "malformed signature value"
        if not _sig.lower_hex(embedded, 2 * key_len):
            return False, "error", f"malformed {algorithm} public key"
        if public_key is not None:
            if len(public_key) != key_len:
                return False, "mismatch", f"the trusted key is not a {algorithm} key"
            if public_key.hex() != embedded:
                return False, "mismatch", "embedded public key is not the trusted key"
            state = "verified"
        elif trust:
            state = "verified-tofu"
        else:
            return False, "no-key", f"{algorithm} signature present but no trusted public key"
        public, raw = bytes.fromhex(embedded), bytes.fromhex(value)
        if algorithm == "ml-dsa-65":
            good = _mldsa.verify(public, message, raw)
        else:
            if weak_public_key(public[:32]):
                return False, "error", "ed25519 public key has small order or non-canonical"
            good = _ed25519.verify(public[:32], message, raw[:64])
            good = _mldsa.verify(public[32:], message, raw[64:], _pqsig.COMPOSITE_CONTEXT) and good
        return (True, state, "ok") if good else (False, "mismatch", "signature mismatch")
    if not _sig.lower_hex(embedded, 64):
        return False, "error", "malformed ed25519 public key"
    if public_key is not None:
        trusted, state = public_key, "verified"
    elif trust:
        trusted, state = bytes.fromhex(embedded), "verified-tofu"
    else:
        return False, "no-key", "ed25519 signature present but no trusted public key"
    if len(trusted) != 32:
        return False, "error", "malformed ed25519 public key"
    if weak_public_key(trusted):
        return False, "error", "ed25519 public key has small order or a non-canonical encoding"
    if state == "verified" and embedded != trusted.hex():
        return False, "mismatch", "embedded public key is not the trusted key"
    if not _ed25519.verify(trusted, message, bytes.fromhex(value)):
        return False, "mismatch", "signature mismatch"
    return True, state, "ok"


def verify_block(block: Any, build: Callable, schemes: tuple, subject: str, keys: dict) -> dict:
    """``_signing_verify.verify_block``: the seven-field verdict of one block."""
    if block is None:
        return dict(
            zip(FIELDS, (False, "unsigned", None, None, None, None, "no signature present"))
        )
    if not isinstance(block, dict):
        reason = f"{subject} signature is not an object"
        return dict(zip(FIELDS, (False, "error", None, None, None, None, reason)))
    algorithm = block.get("alg")
    raw_optional = (block.get("key_id"), block.get("signer"), block.get("signed_at"))
    details = (algorithm if isinstance(algorithm, str) else None,
               *(item if isinstance(item, str) else None for item in raw_optional))  # fmt: skip

    def result(ok: bool, state: str, reason: str) -> dict:
        return dict(zip(FIELDS, (ok, state, *details, reason)))

    if block.get("scheme") not in schemes:
        return result(False, "error", "unsupported signature scheme")
    given = (keys["hmac_key"] is not None) + (keys["public_key"] is not None)
    if given + bool(keys["trust_embedded"]) > 1:
        return result(False, "error", "pass exactly one verification key")
    if set(block) - _sig.BLOCK_KEYS or (algorithm not in _EMBEDS_KEY and "public_key" in block):
        return result(False, "error", "malformed signature header")
    if any(item is None for item in block.values()):
        return result(False, "error", "malformed signature header")
    if not isinstance(algorithm, str) or any(
        item is not None and not isinstance(item, str) for item in raw_optional
    ):
        return result(False, "error", "malformed signature header")
    if algorithm not in VALUE_LENGTHS and algorithm not in _pqsig.SIZES:
        return result(False, "error", "unsupported signature algorithm")
    value = block.get("value")
    if algorithm not in _pqsig.SIZES and not _sig.lower_hex(value, VALUE_LENGTHS[algorithm]):
        return result(False, "error", "malformed signature value")
    header = {name: block.get(name) for name in HEADER_KEYS}
    try:
        message = build(header)
    except (AttributeError, RecursionError, TypeError, ValueError):
        return result(False, "error", f"malformed signed {subject} content")
    return result(*_keyed(algorithm, message, value, block, keys))


def _refusal(state: str, reason: str) -> dict:
    return dict(zip(FIELDS, (False, state, None, None, None, None, reason)))


def verify_v4(data: Any, keys: dict) -> dict:
    """``_signing_v4.verify_artifact_v4`` (a v5 document is read as v4)."""
    if not isinstance(data, dict):
        raise ValueError("a v4 artifact is an object")
    signatures = data.get("signatures")
    if not isinstance(signatures, list) or len(signatures) > 16:
        return _refusal("error", "v4 signatures must be a list of at most 16")
    if not signatures:
        return _refusal("unsigned", "no signature present")
    if any(not isinstance(b, dict) or b.get("scheme") != "tine-sig/3" for b in signatures):
        return _refusal("error", "unsupported signature scheme")
    root = data.get("root") if isinstance(data.get("root"), str) else None
    try:
        document = _tine_v5.as_v4(data)
        if not _artifact.is_v4(document):
            raise ValueError("not a format v4 artifact (kind 'tine-artifact/4')")
        integrity = _conform_artifact.integrity(document)
    except (KeyError, RecursionError, TypeError, ValueError) as exc:
        integrity = {"ok": False, "reason": f"invalid v4 artifact: {exc}", "expected": root}
    if not integrity["ok"]:
        reason = f"content does not match the signed root: {integrity['reason']}"
        return _refusal("mismatch", reason)
    results = [
        verify_block(b, lambda h: v4_message(data, h), ("tine-sig/3",), "artifact", keys)
        for b in signatures
    ]
    return next((found for found in results if found["ok"]), results[0])


__all__ = ["MESSAGES", "verify_block", "verify_v4"]
