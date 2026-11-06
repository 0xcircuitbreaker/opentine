"""FIPS mode (0.41, roadmap X30): ``tine --fips`` or ``OPENTINE_FIPS=1``.

In FIPS mode a command first checks that ``cryptography`` runs on an OpenSSL
with the FIPS provider active, then refuses any primitive outside the approved
set before using it. Approved here: AES-GCM and XAES-256-GCM (AES only),
HMAC-SHA256, SHA-256 and Ed25519 (FIPS 186-5). Refused: ChaCha20-Poly1305, and
xz's CRC64 where it would be the only integrity check (the archival xz form,
read by the stdlib verifier). zstd/zlib/xz as plain compression under a SHA-256
content address are not cryptography and stay allowed. Verify reports record
the mode and provider (``status``).
"""

from __future__ import annotations

import os

ENV = "OPENTINE_FIPS"
APPROVED = frozenset(
    {"aes-256-gcm", "xaes-256-gcm", "hmac-sha256", "sha-256", "ed25519", "ecdsa-p256"}
)
REFUSED = {
    "chacha20-poly1305": "ChaCha20-Poly1305 is not FIPS-approved",
    "xz-crc64": "xz's CRC64 is not an approved integrity check (the archival xz form)",
}


class FipsError(RuntimeError):
    """A non-approved primitive, or no active FIPS provider, under ``--fips``."""


def enabled() -> bool:
    return os.environ.get(ENV, "").strip().lower() in ("1", "true", "yes", "on")


def provider_active() -> bool:
    """Whether ``cryptography``'s OpenSSL has the FIPS provider active."""
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl

        return bool(rust_openssl.is_fips_enabled())
    except (ImportError, AttributeError):  # older cryptography
        from cryptography.hazmat.backends.openssl import backend

        return bool(getattr(backend, "_fips_enabled", False))


def status() -> dict:
    """The mode and provider, as recorded in reports."""
    from cryptography.hazmat.backends.openssl import backend

    return {
        "mode": "fips" if enabled() else "default",
        "provider_fips": provider_active(),
        "openssl": backend.openssl_version_text(),
    }


def require_provider() -> None:
    if enabled() and not provider_active():
        raise FipsError(
            "--fips needs cryptography linked to an OpenSSL 3 with the FIPS provider "
            f"active (found {status()['openssl']}, FIPS provider not active)"
        )


def require(primitive: str) -> None:
    """Refuse *primitive* in FIPS mode unless it is approved."""
    if not enabled() or primitive in APPROVED:
        return
    reason = REFUSED.get(primitive, f"{primitive} is not FIPS-approved")
    raise FipsError(f"refused under --fips: {reason}")
