"""Server-side WebAuthn (passkey) checks for the 0.52 admin surface (stdlib + cryptography).

Registration (``webauthn.create``) and assertion (``webauthn.get``) are
verified as WebAuthn Level 2 §7.1 / §7.2 describe, for ES256 (COSE -7) and
EdDSA/Ed25519 (COSE -8) credentials: the client data's type, challenge and
origin, the authenticator data's RP id hash and user-present flag, the
signature over ``authenticatorData || SHA-256(clientDataJSON)``, and a
non-decreasing signature counter. Attestation statements are *not*
evaluated (the server asks for ``attestation: "none"``): a passkey proves
possession of a key, not which hardware holds it. The server keeps only the
credential's public key; it never sees or holds a user signing key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from typing import Any

from opentine import _cbor

ES256, EDDSA = -7, -8
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40
MAX_FIELD = 64 * 1024


class WebAuthnError(ValueError):
    """The ceremony response does not verify."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_FIELD:
        raise WebAuthnError(f"{what} must be base64url text")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise WebAuthnError(f"{what} is not base64url") from exc


@dataclass(frozen=True)
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes = b""
    cose_key: Any = None


def parse_auth_data(raw: bytes) -> AuthData:
    if len(raw) < 37:
        raise WebAuthnError("authenticator data is too short")
    flags = raw[32]
    (count,) = struct.unpack(">I", raw[33:37])
    if not flags & FLAG_AT:
        return AuthData(raw[:32], flags, count)
    if len(raw) < 55:
        raise WebAuthnError("attested credential data is truncated")
    (length,) = struct.unpack(">H", raw[53:55])
    credential_id = raw[55 : 55 + length]
    if len(credential_id) != length or not 1 <= length <= 1023:
        raise WebAuthnError("credential id is malformed")
    reader = _cbor._Reader(raw[55 + length :])
    try:
        key = reader.item()
    except _cbor.CBORError as exc:
        raise WebAuthnError("credential public key is not CBOR") from exc
    return AuthData(raw[:32], flags, count, credential_id, key)


def public_key(cose: Any) -> tuple[int, str]:
    """``(alg, hex public key)``: an uncompressed P-256 point, or a raw Ed25519 key."""
    if not isinstance(cose, dict):
        raise WebAuthnError("COSE key must be a map")
    alg = cose.get(3)
    if alg == ES256 and cose.get(1) == 2 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
            raise WebAuthnError("P-256 key coordinates are malformed")
        return ES256, (b"\x04" + x + y).hex()
    if alg == EDDSA and cose.get(1) == 1 and cose.get(-1) == 6:
        x = cose.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise WebAuthnError("Ed25519 key is malformed")
        return EDDSA, x.hex()
    raise WebAuthnError("only ES256 and Ed25519 passkeys are accepted")


def check_client_data(raw: bytes, kind: str, challenge: str, origin: str) -> None:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebAuthnError("client data is not JSON") from exc
    if not isinstance(data, dict) or data.get("type") != kind:
        raise WebAuthnError(f"client data type is not {kind}")
    if not hmac.compare_digest(str(data.get("challenge", "")), challenge):
        raise WebAuthnError("challenge does not match")
    if data.get("origin") != origin:
        raise WebAuthnError("origin does not match")
    if data.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin ceremonies are refused")


def check_rp(auth: AuthData, rp_id: str) -> None:
    expected = hashlib.sha256(rp_id.encode("utf-8")).digest()
    if not hmac.compare_digest(auth.rp_id_hash, expected):
        raise WebAuthnError("RP id hash does not match")
    if not auth.flags & FLAG_UP:
        raise WebAuthnError("user presence flag is not set")


def verify_registration(
    response: dict[str, Any], challenge: str, *, rp_id: str, origin: str
) -> dict[str, Any]:
    """The credential row to store for a verified ``navigator.credentials.create`` result."""
    client = unb64url(response.get("clientDataJSON"), "clientDataJSON")
    check_client_data(client, "webauthn.create", challenge, origin)
    try:
        attestation = _cbor.loads(unb64url(response.get("attestationObject"), "attestationObject"))
    except _cbor.CBORError as exc:
        raise WebAuthnError("attestationObject is not CBOR") from exc
    if not isinstance(attestation, dict) or not isinstance(attestation.get("authData"), bytes):
        raise WebAuthnError("attestationObject lacks authData")
    auth = parse_auth_data(attestation["authData"])
    check_rp(auth, rp_id)
    if auth.cose_key is None:
        raise WebAuthnError("no attested credential data")
    alg, key = public_key(auth.cose_key)
    return {"credential_id": b64url(auth.credential_id), "alg": alg, "public_key": key,
            "sign_count": auth.sign_count, "fmt": str(attestation.get("fmt", ""))}  # fmt: skip


def verify_assertion(
    response: dict[str, Any], credential: dict[str, Any], challenge: str, *, rp_id: str,
    origin: str,
) -> int:  # fmt: skip
    """Verify a ``navigator.credentials.get`` result; the new signature counter."""
    client = unb64url(response.get("clientDataJSON"), "clientDataJSON")
    check_client_data(client, "webauthn.get", challenge, origin)
    raw_auth = unb64url(response.get("authenticatorData"), "authenticatorData")
    auth = parse_auth_data(raw_auth)
    check_rp(auth, rp_id)
    signature = unb64url(response.get("signature"), "signature")
    signed = raw_auth + hashlib.sha256(client).digest()
    _verify(credential["alg"], bytes.fromhex(credential["public_key"]), signature, signed)
    old = int(credential.get("sign_count", 0))
    if (auth.sign_count or old) and auth.sign_count <= old:
        raise WebAuthnError("signature counter went backwards (cloned authenticator?)")
    return auth.sign_count


def _verify(alg: int, key: bytes, signature: bytes, signed: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        if alg == ES256:
            point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
            point.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, signed)
        else:
            raise WebAuthnError("unsupported credential algorithm")
    except (InvalidSignature, ValueError) as exc:
        if isinstance(exc, WebAuthnError):
            raise
        raise WebAuthnError("passkey signature does not verify") from exc


__all__ = ["WebAuthnError", "b64url", "verify_assertion", "verify_registration"]
