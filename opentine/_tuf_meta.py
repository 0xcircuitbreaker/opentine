"""TUF 1.0 metadata checks: canonical JSON, keys, threshold signatures, expiry.

Pure functions, no I/O. Signatures cover the securesystemslib canonical form of
``signed`` (sorted keys, no whitespace, only ``"`` and ``\\`` escaped, strings,
integers, booleans and null only). That differs from
:func:`opentine.kernel.canonical_json` (which escapes control characters and
sorts by UTF-16), so it is implemented here rather than reused.

Supported keys: ``ed25519``/``ed25519`` (hex public key) and ``ecdsa`` or
``ecdsa-sha2-nistp256`` with scheme ``ecdsa-sha2-nistp256`` (PEM P-256 key, DER
signature over SHA-256). A threshold counts distinct keys -- by key id *and* by
key value -- so one key listed under two ids counts once.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

__all__ = [
    "TUFError",
    "canonical",
    "check_expiry",
    "check_hashes",
    "parse",
    "verify_role",
]

_HASHES = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}


class TUFError(ValueError):
    """Metadata that must not be trusted; the message says why."""


def _string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def canonical(value: Any) -> bytes:
    """securesystemslib ``encode_canonical`` of *value*, as UTF-8 bytes."""

    def enc(item: Any) -> str:
        if item is None:
            return "null"
        if item is True or item is False:
            return "true" if item else "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, str):
            return _string(item)
        if isinstance(item, list | tuple):
            return "[" + ",".join(enc(v) for v in item) + "]"
        if isinstance(item, dict):
            if not all(isinstance(k, str) for k in item):
                raise TUFError("canonical JSON keys must be strings")
            return "{" + ",".join(_string(k) + ":" + enc(item[k]) for k in sorted(item)) + "}"
        raise TUFError(f"canonical JSON cannot encode {type(item).__name__}")

    try:
        return enc(value).encode("utf-8")
    except (RecursionError, UnicodeEncodeError) as exc:
        raise TUFError("metadata is too deep or not valid Unicode") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise TUFError("metadata has a duplicate key")
    return dict(pairs)


def _expires(signed: dict) -> datetime:
    raw = signed.get("expires")
    try:
        if not isinstance(raw, str) or not raw.endswith("Z"):
            raise ValueError
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise TUFError(f"expires {raw!r} is not YYYY-MM-DDTHH:MM:SSZ") from None


def parse(raw: bytes, role: str) -> dict:
    """``{"signed", "signatures"}`` of *role* with a well-formed header, unverified."""
    try:
        meta = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise TUFError(f"{role} metadata is not JSON: {exc}") from None
    signed = meta.get("signed") if isinstance(meta, dict) else None
    sigs = meta.get("signatures") if isinstance(meta, dict) else None
    if not isinstance(signed, dict) or not isinstance(sigs, list):
        raise TUFError(f"{role} metadata lacks signed/signatures")
    if signed.get("_type") != role:
        raise TUFError(f"expected {role} metadata, got {signed.get('_type')!r}")
    if str(signed.get("spec_version", "")).split(".")[0] != "1":
        raise TUFError(f"{role} metadata has unsupported spec_version")
    version = signed.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise TUFError(f"{role} metadata version is not a positive integer")
    _expires(signed)
    canonical(signed)  # refuse floats etc. before anyone verifies a signature
    return meta


def check_expiry(meta: dict, now: datetime) -> None:
    signed = meta["signed"]
    if _expires(signed) <= now:
        raise TUFError(f"{signed['_type']} metadata expired at {signed['expires']}")


def _public(key: Any) -> tuple[str, Any]:
    """``(identity, verifier)`` for a TUF key object; ``TUFError`` if unsupported."""
    if not isinstance(key, dict) or not isinstance(key.get("keyval"), dict):
        raise TUFError("key is malformed")
    keytype, scheme, public = key.get("keytype"), key.get("scheme"), key["keyval"].get("public")
    if not isinstance(public, str):
        raise TUFError("key has no public value")
    try:
        if keytype == "ed25519" and scheme == "ed25519":
            verifier = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public))
        elif keytype in ("ecdsa", "ecdsa-sha2-nistp256") and scheme == "ecdsa-sha2-nistp256":
            verifier = serialization.load_pem_public_key(public.encode("ascii"))
            if not isinstance(verifier, ec.EllipticCurvePublicKey) or (
                verifier.curve.name != "secp256r1"
            ):
                raise TUFError("ecdsa-sha2-nistp256 key is not P-256")
        else:
            raise TUFError(f"unsupported key {keytype}/{scheme}")
    except (ValueError, UnicodeEncodeError) as exc:
        raise TUFError(f"key is malformed: {exc}") from None
    der = verifier.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest(), verifier


def _valid(verifier: Any, sig_hex: Any, data: bytes) -> bool:
    try:
        sig = bytes.fromhex(sig_hex)
        if isinstance(verifier, ed25519.Ed25519PublicKey):
            verifier.verify(sig, data)
        else:
            verifier.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_role(meta: dict, delegator: dict, role: str) -> None:
    """Raise unless *meta* carries a threshold of *role* signatures per *delegator* root."""
    spec = (delegator.get("roles") or {}).get(role)
    keys = delegator.get("keys") or {}
    if not isinstance(spec, dict) or not isinstance(keys, dict):
        raise TUFError(f"root does not delegate {role}")
    threshold, keyids = spec.get("threshold"), spec.get("keyids")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise TUFError(f"{role} threshold is not a positive integer")
    if not isinstance(keyids, list):
        raise TUFError(f"{role} keyids is not a list")
    data = canonical(meta["signed"])
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    for sig in meta["signatures"]:
        keyid = sig.get("keyid") if isinstance(sig, dict) else None
        if not isinstance(keyid, str) or keyid not in keyids or keyid in seen_ids:
            continue
        if keyid not in keys:
            continue
        try:
            identity, verifier = _public(keys[keyid])
        except TUFError:
            continue
        if identity not in seen_keys and _valid(verifier, sig.get("sig"), data):
            seen_ids.add(keyid)
            seen_keys.add(identity)
    if len(seen_keys) < threshold:
        raise TUFError(f"{role} metadata has {len(seen_keys)} of {threshold} required signatures")


def check_hashes(raw: bytes, info: dict, what: str, *, required: bool = False) -> None:
    """Length and every supported hash in a ``meta``/``targets`` entry must match."""
    length = info.get("length")
    if length is not None and (not isinstance(length, int) or len(raw) != length):
        raise TUFError(f"{what} length does not match its metadata")
    hashes_ = info.get("hashes")
    if hashes_ is None and not required:
        return
    if not isinstance(hashes_, dict) or not (set(hashes_) & set(_HASHES)):
        raise TUFError(f"{what} has no sha256/sha512 hash in its metadata")
    if required and length is None:
        raise TUFError(f"{what} has no length in its metadata")
    for name, expected in hashes_.items():
        if name in _HASHES and _HASHES[name](raw).hexdigest() != expected:
            raise TUFError(f"{what} {name} does not match its metadata")
