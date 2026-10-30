"""``did:key`` identifiers for Ed25519 public keys.

A ``did:key`` is a public key spelled as a self-describing identifier: the
multicodec prefix for an Ed25519 public key (``0xed 0x01``) followed by the 32
raw key bytes, base58btc-encoded with the multibase prefix ``z``. Every Ed25519
key therefore reads ``did:key:z6Mk...``, and the identifier *is* the key -- no
registry, no resolution, nothing to fetch.

That is also its limit: a ``did:key`` names a key, not a person. Holding one
proves nothing about who controls it, so a verifier still pins the key (by
``--pubkey`` or ``--pin``) before a signature under it counts as authenticated.

base58btc is implemented here (Bitcoin alphabet) rather than taken from a
dependency; it is a few lines and is pinned by known test vectors.
"""

from __future__ import annotations

from typing import Any

from opentine._signing_keys import SignatureError, coerce_ed25519_public

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: value for value, char in enumerate(ALPHABET)}
ED25519_PUB = b"\xed\x01"
PREFIX = "did:key:z"
#: A did:key for a 34-byte multicodec key is 48 base58 characters; anything far
#: longer is refused before the quadratic decode loop sees it.
MAX_ENCODED = 128


def b58encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    out = []
    while number:
        number, rest = divmod(number, 58)
        out.append(ALPHABET[rest])
    return "1" * zeros + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > MAX_ENCODED:
        raise ValueError("base58btc text is not a short string")
    number = 0
    for char in text:
        if char not in _INDEX:
            raise ValueError(f"invalid base58btc character {char!r}")
        number = number * 58 + _INDEX[char]
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * zeros + body


def did_from_public(key: Any) -> str:
    """The ``did:key`` of an Ed25519 public key (object, 32 raw bytes, or hex)."""
    raw = coerce_ed25519_public(key).public_bytes_raw()
    return PREFIX + b58encode(ED25519_PUB + raw)


def public_from_did(did: Any):
    """The Ed25519 public key a ``did:key`` names; raises :class:`SignatureError`.

    Only the Ed25519 multicodec is accepted, and the key goes through the same
    small-order / non-canonical refusal as every other trusted key.
    """
    if not isinstance(did, str) or not did.startswith(PREFIX):
        raise SignatureError("not an Ed25519 did:key (expected did:key:z6Mk...)")
    try:
        decoded = b58decode(did[len(PREFIX) :])
    except ValueError as exc:
        raise SignatureError(f"malformed did:key: {exc}") from exc
    if len(decoded) != 34 or not decoded.startswith(ED25519_PUB):
        raise SignatureError("did:key does not name an Ed25519 public key")
    public = coerce_ed25519_public(decoded[2:])
    if did_from_public(public) != did:  # one key, one spelling
        raise SignatureError("did:key is not in canonical form")
    return public


def did_from_pub_hex(text: str) -> str | None:
    """``did:key`` for a ``.pub`` file's hex contents, or ``None`` if not a key."""
    try:
        return did_from_public(text.strip())
    except (SignatureError, ValueError):
        return None


def local_dids(directory: Any) -> dict[str, str]:
    """``{fingerprint: did:key}`` for the Ed25519 ``.pub`` files in *directory*."""
    from opentine._signing_pins import key_fingerprint

    found: dict[str, str] = {}
    try:
        files = sorted(directory.glob("*.pub"))[:256]
    except OSError:
        return found
    for path in files:
        try:
            did = did_from_pub_hex(path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError):
            continue
        if did is not None:
            found[key_fingerprint(public_from_did(did).public_bytes_raw())] = did
    return found


__all__ = [
    "b58decode",
    "b58encode",
    "did_from_pub_hex",
    "did_from_public",
    "local_dids",
    "public_from_did",
]
