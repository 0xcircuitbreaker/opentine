"""Post-quantum ``tine-sig/3`` algorithms: ``ml-dsa-65`` and ``ed25519+ml-dsa-65`` (0.41, X29).

Both are new values of the block's ``alg``; the scheme, the signed message and
the header are unchanged (SPEC 4.6.1), so the signed bytes still cover only the
canonical view. The stored block is the usual five header keys, ``value`` and
``public_key``, all lowercase hex:

* ``ml-dsa-65`` (FIPS 204, pure, empty context): ``value`` is the 3309-byte
  signature and ``public_key`` the 1952-byte key.
* ``ed25519+ml-dsa-65`` (composite): ``value`` is the Ed25519 signature (64
  bytes) then the ML-DSA-65 signature, ``public_key`` the Ed25519 key (32
  bytes) then the ML-DSA-65 key. Both halves sign the same message, the
  ML-DSA half under the context ``COMPOSITE_CONTEXT``, and **both must
  verify**. Because ``alg`` is signed, neither half can be stripped out and
  relabelled as a lone ``ed25519`` or ``ml-dsa-65`` block.

A 0.34 verifier skips a block whose ``alg`` it does not know and accepts the
run through its classical Ed25519 block (``tests/test_041_post_quantum.py``
runs the real v0.34.0 code), so ``sign_hybrid`` always writes that classical
block first.

Signing needs ``cryptography`` with ML-DSA (OpenSSL 3.5+ wheels, ``cryptography``
47+). Verification falls back to the pure-Python :mod:`opentine._pyz._mldsa`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from opentine._ed25519_order import weak_public_key
from opentine._pyz import _mldsa
from opentine._signing_keys import SignatureError, load_ed25519_private
from opentine._signing_verdicts import lower_hex

if TYPE_CHECKING:
    from opentine._signing_verify import SignatureResult

try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA65PrivateKey,
        MLDSA65PublicKey,
    )

    HAS_MLDSA = True
except Exception:  # pragma: no cover - an older cryptography or OpenSSL
    MLDSA65PrivateKey = MLDSA65PublicKey = None  # type: ignore[assignment,misc]
    HAS_MLDSA = False

MLDSA65 = "ml-dsa-65"
COMPOSITE = "ed25519+ml-dsa-65"
COMPOSITE_CONTEXT = b"opentine.tine-sig/3:ed25519+ml-dsa-65"
#: ``alg -> (value bytes, public key bytes)``.
PQ_SIZES = {
    MLDSA65: (_mldsa.SIGNATURE_BYTES, _mldsa.PUBLIC_KEY_BYTES),
    COMPOSITE: (64 + _mldsa.SIGNATURE_BYTES, 32 + _mldsa.PUBLIC_KEY_BYTES),
}
PQ_ALGORITHMS = frozenset(PQ_SIZES)


def _mldsa_private(seed: Any):
    if not HAS_MLDSA:
        raise SignatureError("ml-dsa-65 signing needs 'cryptography' built with ML-DSA")
    if isinstance(seed, MLDSA65PrivateKey):
        return seed
    raw = bytes.fromhex(seed) if isinstance(seed, str) else seed
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise SignatureError("an ml-dsa-65 key is its 32-byte seed (or 64-char hex)")
    return MLDSA65PrivateKey.from_seed_bytes(bytes(raw))


def sign_pq(message: bytes, key: Any, algorithm: str) -> tuple[str, str]:
    """``(value, public_key)`` hex for *message*.

    *key* is the ML-DSA-65 seed for ``ml-dsa-65`` and an ``(ed25519 key,
    ml-dsa-65 seed)`` pair for the composite.
    """
    if algorithm == MLDSA65:
        private = _mldsa_private(key)
        return private.sign(message).hex(), private.public_key().public_bytes_raw().hex()
    if algorithm != COMPOSITE or not isinstance(key, tuple) or len(key) != 2:
        raise SignatureError(f"{COMPOSITE} signs with an (ed25519, ml-dsa-65) key pair")
    ed = load_ed25519_private(key[0])
    pq = _mldsa_private(key[1])
    value = ed.sign(message) + pq.sign(message, COMPOSITE_CONTEXT)
    public = ed.public_key().public_bytes_raw() + pq.public_key().public_bytes_raw()
    return value.hex(), public.hex()


def mldsa_verify(public: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
    """ML-DSA-65 Verify (FIPS 204 Algorithm 3) through ``cryptography`` or pure Python."""
    if not HAS_MLDSA:
        return _mldsa.verify(public, message, signature, context)
    try:
        MLDSA65PublicKey.from_public_bytes(public).verify(signature, message, context or None)
    except Exception:
        return False
    return True


def _ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:  # pragma: no cover
        from opentine._pyz import _ed25519

        return _ed25519.verify(public, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except Exception:
        return False
    return True


def verify_pq(algorithm: str, public: bytes, message: bytes, value: bytes) -> bool:
    """True only when every component of *algorithm* verifies."""
    if algorithm == MLDSA65:
        return mldsa_verify(public, message, value)
    ed_ok = _ed25519_verify(public[:32], message, value[:64])
    pq_ok = mldsa_verify(public[32:], message, value[64:], COMPOSITE_CONTEXT)
    return ed_ok and pq_ok


def _trusted(public_key: Any) -> bytes:
    if isinstance(public_key, str):
        return bytes.fromhex(public_key.strip())
    if isinstance(public_key, (bytes, bytearray)):
        return bytes(public_key)
    raise SignatureError("a post-quantum public key is raw bytes or hex")


def pq_verdict(
    message: bytes,
    value: str,
    block: dict[str, Any],
    public_key: Any | None,
    trust_embedded: bool,
    result: Callable[..., SignatureResult],
) -> SignatureResult:
    """The keyed verdict for a post-quantum block (``_signing_verdicts`` style)."""
    algorithm = block["alg"]
    value_len, key_len = PQ_SIZES[algorithm]
    embedded = block.get("public_key")
    if not lower_hex(value, 2 * value_len):
        return result(False, "error", "malformed signature value")
    if not lower_hex(embedded, 2 * key_len):
        return result(False, "error", f"malformed {algorithm} public key")
    if public_key is not None:
        try:
            trusted = _trusted(public_key)
        except (SignatureError, ValueError):
            return result(False, "error", f"malformed {algorithm} public key")
        if len(trusted) != key_len:
            return result(False, "mismatch", f"the trusted key is not a {algorithm} key")
        if trusted.hex() != embedded:
            return result(False, "mismatch", "embedded public key is not the trusted key")
        state = "verified"
    elif trust_embedded:
        state = "verified-tofu"
    else:
        return result(False, "no-key", f"{algorithm} signature present but no trusted public key")
    public = bytes.fromhex(embedded)
    if algorithm == COMPOSITE and weak_public_key(public[:32]):
        return result(False, "error", "ed25519 public key has small order or non-canonical")
    if not verify_pq(algorithm, public, message, bytes.fromhex(value)):
        return result(False, "mismatch", "signature mismatch")
    return result(True, state, "ok")


def sign_hybrid(document: dict[str, Any], ed_key: Any, mldsa_seed: Any, **header: Any) -> bytes:
    """Append a classical Ed25519 block, then an ``ed25519+ml-dsa-65`` block.

    The classical block comes first so a 0.34 verifier accepts the run through it.
    """
    from opentine._signing_v4 import sign_artifact_v4
    from opentine.kernel import canonical_json

    classical = sign_artifact_v4(document, ed_key, algorithm="ed25519", **header)
    composite = sign_artifact_v4(document, (ed_key, mldsa_seed), algorithm=COMPOSITE, **header)
    blocks = [*document.get("signatures", []), classical, composite]
    return canonical_json({**document, "signatures": blocks})


__all__ = [
    "COMPOSITE",
    "COMPOSITE_CONTEXT",
    "HAS_MLDSA",
    "MLDSA65",
    "PQ_ALGORITHMS",
    "mldsa_verify",
    "pq_verdict",
    "sign_hybrid",
    "sign_pq",
    "verify_pq",
]
