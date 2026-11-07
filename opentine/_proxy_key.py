"""Where the T2 proxy key lives (0.39), and moving it into a signer (0.41, X24).

``proxy-keys/`` (a sibling of ``agent-keys/``) holds the public half
``proxy.pub`` and either ``proxy.key`` (an encrypted PKCS#8 file) or
``proxy.signer`` (one signer URI: ``ssh-agent:``, ``pkcs11:``, ``kms:``), never
both. ``tine proxy keygen --signer URI`` and ``tine proxy migrate --to URI`` write
the second form; a migration moves the old pair to ``retired/`` so runs it
signed still verify as T2 here, and the old private key file is no longer read.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def base() -> Path:
    from opentine._agent_keys import key_dir

    return key_dir().parent / "proxy-keys"


def key_paths() -> tuple[Path, Path]:
    """``(proxy.key, proxy.pub)``."""
    stem = base() / "proxy"
    return stem.with_suffix(".key"), stem.with_suffix(".pub")


def signer_path() -> Path:
    return base() / "proxy.signer"


def retired_publics() -> list[Path]:
    try:
        return sorted((base() / "retired").glob("*.pub"))[:256]
    except OSError:
        return []


def _exists() -> bool:
    private, public = key_paths()
    return private.exists() or public.exists() or signer_path().exists()


def _check_separate(public: bytes) -> str:
    from opentine._agent_keys import local_fingerprints
    from opentine._signing_pins import key_fingerprint

    fingerprint = key_fingerprint(public)
    if fingerprint in local_fingerprints():  # the separation is the point of T2
        raise ValueError("that key is an agent key; the proxy key must be kept apart")
    return fingerprint


def _retire() -> None:
    """Move the current pair aside, keyed by fingerprint; drop a signer pointer."""
    private, public = key_paths()
    if not public.exists():
        return
    retired = base() / "retired"
    retired.mkdir(parents=True, exist_ok=True, mode=0o700)
    stem = public.read_text(encoding="ascii").strip()[:64] or "unknown"
    public.replace(retired / f"{stem}.pub")
    if private.exists():
        private.replace(retired / f"{stem}.key")
    signer_path().unlink(missing_ok=True)


def keygen(force: bool = False, signer: str | None = None) -> tuple[Path, str]:
    """A new proxy key -- a fresh encrypted file, or the key *signer* names."""
    from opentine._canon import atomic_write_text

    if _exists() and not force:
        raise FileExistsError(f"{key_paths()[0]} already exists; pass --force to replace it")
    if signer:
        return _adopt(signer, retire=False)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine._key_store import write_private

    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes_raw()
    fingerprint = _check_separate(raw)
    private, public = key_paths()
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    signer_path().unlink(missing_ok=True)
    write_private(private, private_key)
    atomic_write_text(public, raw.hex() + "\n")
    del fingerprint
    return _shown(public)


def _shown(public: Path) -> tuple[Path, str]:
    """Report only what is read back from the public file, never the generated pair."""
    from opentine._signing_pins import key_fingerprint

    return public, key_fingerprint(bytes.fromhex(public.read_text().strip()))


def _adopt(uri: str, *, retire: bool) -> tuple[Path, str]:
    from opentine._canon import atomic_write_text
    from opentine._signer import is_uri, resolve

    if not is_uri(uri) or uri.startswith("file:"):
        raise ValueError("name a signer URI: ssh-agent:..., pkcs11:..., kms:aws:..., kms:gcp:...")
    found = resolve(uri)
    raw = bytes(found.public_key)
    fingerprint = _check_separate(raw)
    if retire:
        _retire()
    private, public = key_paths()
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if private.exists():  # keygen --force --signer: the old file key is replaced
        private.unlink()
    stored = found.uri if uri.startswith("pkcs11:") else uri  # never store a pin-value
    atomic_write_text(signer_path(), stored + "\n", mode=0o600)
    atomic_write_text(public, raw.hex() + "\n")
    del fingerprint
    return _shown(public)


def _shown(public: Path) -> tuple[Path, str]:
    """Report only what is read back from the public file, never the generated pair."""
    from opentine._signing_pins import key_fingerprint

    return public, key_fingerprint(bytes.fromhex(public.read_text().strip()))


def migrate(uri: str) -> tuple[Path, str]:
    """Move the proxy identity to the signer *uri*; the old key is retired."""
    return _adopt(uri, retire=True)


def signing_key() -> Any | None:
    """The proxy signer, or ``None`` when none is set up or it cannot be opened."""
    from opentine._signer import key_for
    from opentine.signing import SignatureError

    pointer, private = signer_path(), key_paths()[0]
    try:
        if pointer.is_file():
            return key_for(pointer.read_text(encoding="utf-8").strip())
        if private.is_file():
            from opentine.signing import ed25519_private_from_file

            return ed25519_private_from_file(private)
    except (OSError, SignatureError, ValueError):
        return None
    return None


__all__ = ["key_paths", "keygen", "migrate", "retired_publics", "signer_path", "signing_key"]
