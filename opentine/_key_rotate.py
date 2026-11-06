"""``tine key rotate`` and ``tine key revoke`` (0.41, X23), without the CLI.

Rotation makes a new Ed25519 key, ends the old key's window
(``not_after = now``), opens the new one's (``not_before = now``) and has the
**old** key endorse the new one: an Ed25519 signature over
``opentine.key-rotation.v1:`` + JCS of ``{schema, old, new, new_public_key,
at}``, stored on the new key's lifecycle entry, so the chain old -> new can be
checked by anyone holding the old public key. The old key files are kept beside
the new ones as ``<name>-retired-<fp12>``: signatures made inside its window
keep verifying.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine._canon import atomic_write_text
from opentine._key_lifecycle import load_registry, parse_time, stamp, update_registry
from opentine._signing_pins import key_fingerprint, normalize_pin
from opentine.kernel import canonical_json

DOMAIN = b"opentine.key-rotation.v1:"
SCHEMA = "tine-key-rotation/1"


def _retired(path: Path, fpr: str, into: tuple[Path, str] | None = None) -> Path:
    if into is not None:  # the proxy key: ``proxy-keys/retired/<public hex>``, as migrate does
        into[0].mkdir(parents=True, exist_ok=True, mode=0o700)
        return into[0] / f"{into[1]}{path.suffix}"
    tag = fpr.split(":", 1)[1][:12]
    return path.with_name(f"{path.stem}-retired-{tag}{path.suffix}")


def endorsement(old: Any, statement: dict[str, Any]) -> dict[str, Any]:
    signature = old.sign(DOMAIN + canonical_json(statement))
    public = old.public_key().public_bytes_raw().hex()
    return {"statement": statement, "signature": signature.hex(), "public_key": public}


def verify_endorsement(entry: dict[str, Any]) -> bool:
    """Whether a new key's ``endorsement`` is the old key's valid signature over it."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        end = entry["endorsement"]
        raw = bytes.fromhex(end["public_key"])
        if key_fingerprint(raw) != end["statement"]["old"]:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(
            bytes.fromhex(end["signature"]), DOMAIN + canonical_json(end["statement"])
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return end["statement"].get("schema") == SCHEMA


def rotate(
    private: Path, public: Path | None, out: Path | None = None, *, retired_dir: Path | None = None
) -> dict[str, Any]:
    """Rotate the key in *private* (and *public*); returns a summary.

    The new private key is written encrypted (``_key_store.write_private``).
    With *retired_dir* the old pair goes there as ``<public hex>.key/.pub`` --
    the layout ``tine proxy migrate`` uses, so the retired proxy key stays
    trusted for T2.
    """
    from opentine._key_store import write_private
    from opentine._signing_keys import ed25519_private_from_file, load_ed25519_private
    from opentine.signing import generate_ed25519

    old = ed25519_private_from_file(private, signer=False)
    old_pub = old.public_key().public_bytes_raw()
    old_fpr = key_fingerprint(old_pub)
    if load_registry().get(old_fpr, {}).get("revoked_at"):
        raise ValueError(f"{old_fpr} is revoked; a revoked key cannot endorse a successor")
    seed, new_hex = generate_ed25519()
    new_fpr = key_fingerprint(bytes.fromhex(new_hex))
    now = stamp(datetime.now(UTC))
    statement = {"schema": SCHEMA, "old": old_fpr, "new": new_fpr, "new_public_key": new_hex}
    statement["at"] = now
    signed = endorsement(old, statement)
    target = out or private
    target_pub = (public if out is None else None) or Path(f"{target}.pub")
    into = None if retired_dir is None else (retired_dir, old_pub.hex())
    new_key = load_ed25519_private(seed)  # the new seed loads before anything points at it
    if out is None:  # in place: keep the old pair as <name>-retired-<fp12>
        retired = _retired(private, old_fpr, into)
        if retired.exists():
            raise FileExistsError(f"{retired} already exists")
        os.replace(private, retired)
        if public is not None and public.is_file():
            os.replace(public, _retired(public, old_fpr, into))
    elif target.exists():
        raise FileExistsError(f"{target} already exists")
    write_private(target, new_key)
    atomic_write_text(target_pub, new_hex + "\n")
    update_registry(old_fpr, not_after=now, successor=new_fpr)
    update_registry(new_fpr, not_before=now, predecessor=old_fpr, endorsement=signed)
    return {
        "old": old_fpr,
        "new": new_fpr,
        "not_after": now,
        "private_key": str(target),
        "public_key": str(target_pub),
    }


def key_fpr(spec: str) -> str:
    """A fingerprint from ``sha256:<hex>``, a ``.pub`` file, or a private key file."""
    from opentine.signing import (
        SignatureError,
        ed25519_private_from_file,
        ed25519_public_from_file,
    )

    if spec.startswith("sha256:"):
        return normalize_pin(spec)
    path = Path(spec)
    try:
        if path.suffix == ".pub":  # a seed and a public key are both 64 hex characters
            return key_fingerprint(ed25519_public_from_file(path).public_bytes_raw())
        private = ed25519_private_from_file(path)
    except (OSError, SignatureError, TypeError, ValueError) as exc:
        raise ValueError(
            f"{spec} is neither a fingerprint nor a readable key file: {exc}"
        ) from None
    return key_fingerprint(private.public_key().public_bytes_raw())


def revoke(spec: str, at: str | None = None) -> dict[str, Any]:
    """Record ``revoked_at`` (default now); an earlier existing revocation stands."""
    fpr = key_fpr(spec)
    when = stamp(parse_time(at, "--at")) if at else stamp(datetime.now(UTC))
    existing = load_registry().get(fpr, {}).get("revoked_at")
    if existing and parse_time(existing) <= parse_time(when):
        when = existing
    entry = update_registry(fpr, revoked_at=when)
    return {"key": fpr, "revoked_at": entry["revoked_at"], "already": bool(existing)}


__all__ = ["DOMAIN", "SCHEMA", "endorsement", "key_fpr", "revoke", "rotate", "verify_endorsement"]
