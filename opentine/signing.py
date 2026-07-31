"""Authenticity signatures for legacy .tine artifacts (tine-sig/1)."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from opentine._canon import _canonical_bytes
from opentine._signing_keys import (
    HAS_ED25519,
    Ed25519PublicKey,
    SignatureError,
    ed25519_private_from_file,
    ed25519_public_from_file,
    generate_ed25519,
    hmac_key_from_env,
    hmac_key_from_file,
)
from opentine._signing_keys import (
    coerce_ed25519_public as _coerce_ed25519_public,
)
from opentine._signing_keys import (
    is_hex as _is_hex,
)
from opentine._signing_keys import (
    load_ed25519_private as _load_ed25519_private,
)

SCHEME = "tine-sig/1"
DOMAIN_PREFIX = b"opentine.signature.v1:"
MIN_HMAC_KEY_BYTES = 16
_SIGNED_METADATA_KEYS = (
    "model_info",
    "system_prompt",
    "user_prompt",
    "forked_from",
    "fork_point",
    "warnings",
    "replay",
    "context",
    "next_harness",
    "migration",
    # "fork" (the 0.4.0 fork-identity record) is safe to sign: 0.3.0 never wrote
    # metadata["fork"], so it changes no existing signature. "fork_reason" is NOT
    # added here — 0.3.0 emits it (the MCP fork reason) but did not sign it, so
    # signing it now would flip genuine 0.3.0 signatures to a false mismatch.
    "fork",
)


@dataclass(frozen=True)
class SignatureResult:
    ok: bool
    state: str
    algorithm: str | None
    key_id: str | None
    signer: str | None
    signed_at: str | None
    reason: str


def _signed_view(data: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise SignatureError("artifact metadata must be an object")
    return {
        "body": {key: value for key, value in data.items() if key != "metadata"},
        "header": {
            "alg": header.get("alg"),
            "key_id": header.get("key_id"),
            "scheme": header.get("scheme"),
            "signed_at": header.get("signed_at"),
            "signer": header.get("signer"),
        },
        "metadata": {key: metadata.get(key) for key in _SIGNED_METADATA_KEYS if key in metadata},
    }


def _message(data: dict[str, Any], header: dict[str, Any]) -> bytes:
    return DOMAIN_PREFIX + _canonical_bytes(_signed_view(data, header))


def _require_strong_hmac_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise SignatureError("HMAC key must be non-empty bytes")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise SignatureError(
            f"HMAC key too short ({len(key)} bytes); use at least {MIN_HMAC_KEY_BYTES}"
        )


def sign_artifact(
    data: dict[str, Any],
    key: Any,
    *,
    algorithm: str = "hmac-sha256",
    key_id: str | None = None,
    signer: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    if algorithm not in {"hmac-sha256", "ed25519"}:
        raise SignatureError(f"unsupported signature algorithm {algorithm!r}")
    if any(item is not None and not isinstance(item, str) for item in (key_id, signer, signed_at)):
        raise SignatureError("signature metadata values must be strings")
    if algorithm == "hmac-sha256":
        _require_strong_hmac_key(key)
        private = None
    else:
        private = _load_ed25519_private(key)
    header = {
        "alg": algorithm,
        "key_id": key_id,
        "scheme": SCHEME,
        "signed_at": signed_at,
        "signer": signer,
    }
    try:
        message = _message(data, header)
    except SignatureError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        raise SignatureError("artifact content cannot be signed") from exc
    block = {key: value for key, value in header.items() if value is not None}
    if algorithm == "hmac-sha256":
        block["value"] = hmac.new(bytes(key), message, hashlib.sha256).hexdigest()
    else:
        block["value"] = private.sign(message).hex()
        block["public_key"] = private.public_key().public_bytes_raw().hex()
    return block


def verify_artifact(
    data: dict[str, Any],
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    if not isinstance(data, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact root is not an object"
        )
    metadata = data.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact metadata is not an object"
        )
    integrity = (metadata or {}).get("integrity")
    if integrity is not None and not isinstance(integrity, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact integrity is not an object"
        )
    block = (integrity or {}).get("signature")
    if block is None:
        return SignatureResult(False, "unsigned", None, None, None, None, "no signature present")
    if not isinstance(block, dict):
        return SignatureResult(
            False, "error", None, None, None, None, "artifact signature is not an object"
        )
    algorithm = block.get("alg")
    raw_optional = (block.get("key_id"), block.get("signer"), block.get("signed_at"))
    optional = tuple(item if isinstance(item, str) else None for item in raw_optional)
    details = (algorithm if isinstance(algorithm, str) else None, *optional)

    def result(ok: bool, state: str, reason: str) -> SignatureResult:
        return SignatureResult(ok, state, *details, reason)

    if block.get("scheme") != SCHEME:
        return result(False, "error", "unsupported signature scheme")
    if not isinstance(algorithm, str) or any(
        item is not None and not isinstance(item, str) for item in raw_optional
    ):
        return result(False, "error", "malformed signature header")
    if algorithm not in {"hmac-sha256", "ed25519"}:
        return result(False, "error", "unsupported signature algorithm")
    value = block.get("value")
    expected_length = 64 if algorithm == "hmac-sha256" else 128
    if not isinstance(value, str) or len(value) != expected_length or not _is_hex(value):
        return result(False, "error", "malformed signature value")
    header = {
        "alg": algorithm,
        "key_id": block.get("key_id"),
        "scheme": block.get("scheme"),
        "signed_at": block.get("signed_at"),
        "signer": block.get("signer"),
    }
    try:
        message = _message(data, header)
    except (RecursionError, SignatureError, TypeError, ValueError):
        return result(False, "error", "malformed signed artifact content")
    if algorithm == "hmac-sha256":
        if hmac_key is None:
            return result(False, "no-key", "HMAC signature present but no key supplied")
        try:
            _require_strong_hmac_key(hmac_key)
        except SignatureError as exc:
            return result(False, "error", str(exc))
        expected = hmac.new(bytes(hmac_key), message, hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(expected, value)
        return result(
            valid,
            "verified" if valid else "mismatch",
            "ok" if valid else "signature mismatch",
        )
    if algorithm == "ed25519":
        if not HAS_ED25519:
            return result(False, "error", "ed25519 requires the 'cryptography' extra")
        try:
            if public_key is not None:
                public = _coerce_ed25519_public(public_key)
                state = "verified"
            elif trust_embedded:
                embedded = block.get("public_key")
                if not isinstance(embedded, str) or len(embedded) != 64 or not _is_hex(embedded):
                    raise SignatureError("malformed embedded public key")
                public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(embedded))
                state = "verified-tofu"
            else:
                return result(
                    False, "no-key", "ed25519 signature present but no trusted public key"
                )
        except (SignatureError, TypeError, ValueError):
            return result(False, "error", "malformed ed25519 public key")
        try:
            public.verify(bytes.fromhex(value), message)
        except Exception:
            return result(False, "mismatch", "signature mismatch")
        return result(True, state, "ok")
    return result(False, "error", "unsupported signature algorithm")


__all__ = [
    "HAS_ED25519",
    "SignatureError",
    "SignatureResult",
    "ed25519_private_from_file",
    "ed25519_public_from_file",
    "generate_ed25519",
    "hmac_key_from_env",
    "hmac_key_from_file",
    "sign_artifact",
    "verify_artifact",
]
