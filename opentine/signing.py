"""Authenticity signing for ``.tine`` artifacts (``tine-sig/1``).

Layers a real signature on top of the (unkeyed) integrity digest. The signature
commits to a single canonical *signed view* recomputed from the artifact's
content — never to the stored digest string — so a body edit plus a digest
rewrite still fails verification.

What is signed (the ``tine-sig/1`` trust boundary):

- the whole artifact body (every top-level key except ``metadata``), and
- an allowlist of *authenticity-relevant* metadata fields, and
- an authenticated header (scheme/alg/key_id/signer/signed_at).

What is deliberately NOT signed, so sibling features can mutate it without
breaking a signature: ``metadata.tags`` (mutable labels), ``metadata.budget_state``
and ``metadata.autosave`` (derived/transient), and the whole ``metadata.integrity``
container (it holds the signature itself).

HMAC-SHA256 is the zero-dependency baseline (shared-secret authenticity, no
non-repudiation). Ed25519 is the stronger public-key tier, available only when
the optional ``cryptography`` extra is installed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opentine._canon import _canonical_bytes

SCHEME = "tine-sig/1"
DOMAIN_PREFIX = b"opentine.signature.v1:"
MIN_HMAC_KEY_BYTES = 16

#: metadata fields the signature DOES cover (everything else in metadata is excluded)
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
)

try:  # optional public-key tier
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    HAS_ED25519 = True
except Exception:  # pragma: no cover - exercised only without the extra
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    HAS_ED25519 = False


class SignatureError(Exception):
    """Raised for signing/key errors (not for an honest verification failure)."""


@dataclass(frozen=True)
class SignatureResult:
    ok: bool
    #: unsigned | verified | verified-tofu | mismatch | no-key | error
    state: str
    algorithm: str | None
    key_id: str | None
    signer: str | None
    signed_at: str | None
    reason: str


def _is_hex(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return len(value) % 2 == 0


def _signed_view(data: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in data.items() if k != "metadata"}
    meta = data.get("metadata") or {}
    signed_meta = {k: meta.get(k) for k in _SIGNED_METADATA_KEYS if k in meta}
    return {
        "body": body,
        "metadata": signed_meta,
        "header": {
            "scheme": header.get("scheme"),
            "alg": header.get("alg"),
            "key_id": header.get("key_id"),
            "signer": header.get("signer"),
            "signed_at": header.get("signed_at"),
        },
    }


def _message(data: dict[str, Any], header: dict[str, Any]) -> bytes:
    return DOMAIN_PREFIX + _canonical_bytes(_signed_view(data, header))


def _require_strong_hmac_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
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
    """Return a signature block to embed at ``metadata.integrity.signature``."""
    header = {
        "scheme": SCHEME,
        "alg": algorithm,
        "key_id": key_id,
        "signer": signer,
        "signed_at": signed_at,
    }
    message = _message(data, header)
    block: dict[str, Any] = {"scheme": SCHEME, "alg": algorithm}
    if key_id is not None:
        block["key_id"] = key_id
    if signer is not None:
        block["signer"] = signer
    if signed_at is not None:
        block["signed_at"] = signed_at

    if algorithm == "hmac-sha256":
        _require_strong_hmac_key(key)
        block["value"] = hmac.new(bytes(key), message, hashlib.sha256).hexdigest()
    elif algorithm == "ed25519":
        private = _load_ed25519_private(key)
        block["value"] = private.sign(message).hex()
        block["public_key"] = private.public_key().public_bytes_raw().hex()
    else:
        raise SignatureError(f"unsupported signature algorithm {algorithm!r}")
    return block


def verify_artifact(
    data: dict[str, Any],
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    meta = data.get("metadata") or {}
    integrity = meta.get("integrity") or {}
    block = integrity.get("signature")
    if not isinstance(block, dict):
        return SignatureResult(False, "unsigned", None, None, None, None, "no signature present")

    alg = block.get("alg")
    key_id = block.get("key_id")
    signer = block.get("signer")
    signed_at = block.get("signed_at")

    def result(ok: bool, state: str, reason: str) -> SignatureResult:
        return SignatureResult(ok, state, alg, key_id, signer, signed_at, reason)

    if block.get("scheme") != SCHEME:
        return result(False, "error", f"unsupported signature scheme {block.get('scheme')!r}")
    value = block.get("value")
    if not _is_hex(value):
        return result(False, "error", "malformed signature value")

    header = {
        "scheme": block.get("scheme"),
        "alg": alg,
        "key_id": key_id,
        "signer": signer,
        "signed_at": signed_at,
    }
    message = _message(data, header)

    if alg == "hmac-sha256":
        if hmac_key is None:
            return result(False, "no-key", "HMAC signature present but no key supplied")
        expected = hmac.new(bytes(hmac_key), message, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(expected, value)
        return result(ok, "verified" if ok else "mismatch", "ok" if ok else "signature mismatch")

    if alg == "ed25519":
        if not HAS_ED25519:
            return result(False, "error", "ed25519 requires the 'cryptography' extra")
        state_suffix = ""
        if public_key is not None:
            pub = _coerce_ed25519_public(public_key)
        elif trust_embedded and _is_hex(block.get("public_key")):
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(block["public_key"]))
            state_suffix = "-tofu"  # trust-on-first-use: key is self-asserted, not verified
        else:
            return result(False, "no-key", "ed25519 signature present but no trusted public key")
        try:
            pub.verify(bytes.fromhex(value), message)
        except Exception:
            return result(False, "mismatch", "signature mismatch")
        return result(True, "verified" + state_suffix, "ok")

    return result(False, "error", f"unsupported signature algorithm {alg!r}")


# --- key loading ------------------------------------------------------------


def hmac_key_from_env(name: str) -> bytes:
    value = os.environ.get(name)
    if value is None:
        raise SignatureError(f"environment variable {name!r} is not set")
    return value.encode()


def hmac_key_from_file(path: str | Path) -> bytes:
    raw = Path(path).read_bytes()
    if raw.endswith(b"\n"):  # filesystem newline noise; env values carry none
        raw = raw[:-1]
    return raw


def _require_crypto() -> None:
    if not HAS_ED25519:
        raise SignatureError("ed25519 support requires: pip install 'opentine[crypto]'")


def _load_ed25519_private(key: Any):
    _require_crypto()
    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, str):
        key = key.strip()
        if _is_hex(key) and len(key) == 64:
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key))
        key = key.encode()
    if isinstance(key, (bytes, bytearray)):
        if len(key) == 32:
            return Ed25519PrivateKey.from_private_bytes(bytes(key))
        text = bytes(key).strip()
        if len(text) == 64 and _is_hex(text.decode(errors="ignore")):
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text.decode()))
    raise SignatureError("ed25519 private key must be a 32-byte seed or 64-char hex")


def _coerce_ed25519_public(key: Any):
    _require_crypto()
    if isinstance(key, Ed25519PublicKey):
        return key
    if isinstance(key, str):
        key = key.strip()
        if _is_hex(key) and len(key) == 64:
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        key = key.encode()
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return Ed25519PublicKey.from_public_bytes(bytes(key))
    raise SignatureError("ed25519 public key must be a 32-byte key or 64-char hex")


def ed25519_private_from_file(path: str | Path):
    raw = hmac_key_from_file(path)
    try:  # hex-text key files are the common case; fall back to raw 32-byte seeds
        return _load_ed25519_private(raw.decode())
    except UnicodeDecodeError:
        return _load_ed25519_private(raw)


def ed25519_public_from_file(path: str | Path):
    raw = hmac_key_from_file(path)
    try:
        return _coerce_ed25519_public(raw.decode())
    except UnicodeDecodeError:
        return _coerce_ed25519_public(raw)


def generate_ed25519() -> tuple[str, str]:
    """Generate an Ed25519 keypair, returned as (private_seed_hex, public_hex)."""
    _require_crypto()
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes_raw().hex()
    public = private.public_key().public_bytes_raw().hex()
    return seed, public
