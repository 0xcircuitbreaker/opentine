"""Transparency-log receipts and keyless signing for ``--format intoto``.

Export: ``--rekor [URL]`` logs the signed envelope in Rekor and writes a Sigstore
bundle (envelope + key hint + receipt) instead of a bare envelope;
``--keyless`` signs with a Fulcio certificate for an OIDC identity
(``--identity-token``, ``SIGSTORE_ID_TOKEN`` or GitHub Actions' ambient token)
and always logs, since a short-lived certificate means nothing without a
trusted signing time.

Verify: ``--rekor-key FILE`` checks any receipt offline; ``--require-receipt``
fails closed without a valid one. A keyless bundle additionally needs
``--cert-identity``, ``--cert-oidc-issuer`` and ``--fulcio-root``. The identity
token is never printed, logged or written.
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from opentine._cli_flags import refuse_unhonoured

EXPORT_DESTS = ("rekor", "keyless", "identity_token", "fulcio_url")
VERIFY_DESTS = ("require_receipt", "rekor_key", "cert_identity", "cert_oidc_issuer", "fulcio_root")
_KEYLESS_VERIFY = ("cert_identity", "cert_oidc_issuer", "fulcio_root")

__all__ = [
    "EXPORT_DESTS",
    "VERIFY_DESTS",
    "add_sigstore_export_args",
    "add_sigstore_verify_args",
    "receipt_for",
    "sign_for_export",
    "verify_keyless_cli",
]


def add_sigstore_export_args(parser: argparse.ArgumentParser) -> None:
    from opentine.rekor import DEFAULT_REKOR_URL

    parser.add_argument(
        "--rekor",
        nargs="?",
        const=DEFAULT_REKOR_URL,
        metavar="URL",
        help=f"--format intoto: log in Rekor (default {DEFAULT_REKOR_URL}), write a bundle",
    )
    parser.add_argument(
        "--keyless", action="store_true", help="--format intoto: sign with a Fulcio certificate"
    )
    parser.add_argument(
        "--identity-token", metavar="JWT", help="--keyless: OIDC token (else SIGSTORE_ID_TOKEN)"
    )
    parser.add_argument("--fulcio-url", metavar="URL", help="--keyless: Fulcio instance")


def add_sigstore_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--require-receipt",
        action="store_true",
        help="--attestation: fail unless a Rekor receipt verifies under --rekor-key",
    )
    parser.add_argument("--rekor-key", metavar="FILE", help="--attestation: Rekor log key (PEM)")
    parser.add_argument("--cert-identity", metavar="SAN", help="Keyless: expected signer identity")
    parser.add_argument("--cert-oidc-issuer", metavar="URL", help="Keyless: expected OIDC issuer")
    parser.add_argument("--fulcio-root", metavar="FILE", help="Keyless: Fulcio root/intermediates")


def _token(args: argparse.Namespace) -> str:
    from opentine.fulcio import ambient_token

    token = getattr(args, "identity_token", None) or os.environ.get("SIGSTORE_ID_TOKEN")
    token = token or ambient_token()
    if not token:
        raise ValueError(
            "--keyless needs an OIDC identity: --identity-token, SIGSTORE_ID_TOKEN, "
            "or a GitHub Actions job with id-token: write"
        )
    return token.strip()


def sign_for_export(args: argparse.Namespace, statement: dict, signing_key) -> dict[str, Any]:
    """The JSON object to write: a bare envelope, or a bundle with a receipt."""
    from opentine.intoto import sign_statement
    from opentine.rekor import DEFAULT_REKOR_URL, upload_dsse
    from opentine.sigstore_bundle import make_bundle

    if getattr(args, "keyless", False):
        from opentine.fulcio import DEFAULT_FULCIO_URL, KeylessSigner

        token = _token(args)
        try:
            signer = KeylessSigner(token, args.fulcio_url or DEFAULT_FULCIO_URL)
        except ValueError as exc:  # the token is in no message, but scrub anyway
            raise ValueError(str(exc).replace(token, "[REDACTED]")) from None
        del token
        envelope = signer.sign(statement)
        entry = upload_dsse(envelope, signer.leaf_pem, args.rekor or DEFAULT_REKOR_URL)
        return make_bundle(envelope, signer.material(), [entry])
    refuse_unhonoured(
        args,
        ("identity_token", "fulcio_url"),
        mode="without --keyless",
        hint="They obtain a Fulcio certificate.",
    )
    key = signing_key()
    envelope = sign_statement(statement, key)
    if not args.rekor:
        return envelope
    from cryptography.hazmat.primitives import serialization

    from opentine.did_key import did_from_public

    public = key.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    entry = upload_dsse(envelope, pem, args.rekor)
    return make_bundle(envelope, {"publicKey": {"hint": did_from_public(public)}}, [entry])


def receipt_for(args: argparse.Namespace, envelope: dict, entries: list, signer, *, need=False):
    """Check the bundle's receipts under ``--rekor-key``; ``need`` forces one."""
    from opentine._rekor_proof import load_log_key
    from opentine.sigstore_bundle import ReceiptResult, check_entry

    need = need or bool(getattr(args, "require_receipt", False))
    key_file = getattr(args, "rekor_key", None)
    if not entries:
        return ReceiptResult(not need, "absent", "attestation carries no transparency-log receipt")
    if not key_file:
        status = "no-key" if need else "unchecked"
        return ReceiptResult(not need, status, "pass --rekor-key FILE to check the receipt")
    if signer is None:
        return ReceiptResult(False, "unchecked", "signature did not verify; receipt not checked")
    try:
        with open(key_file, "rb") as handle:
            rekor_key = load_log_key(handle.read(64 * 1024))
    except (OSError, ValueError) as exc:
        return ReceiptResult(False, "no-key", f"cannot read --rekor-key: {exc}")
    results = [check_entry(entry, envelope, signer, rekor_key) for entry in entries]
    return next((r for r in results if r.ok), results[0])


def verify_keyless_cli(args: argparse.Namespace, envelope: dict, leaf, entries: list):
    """``(EnvelopeResult, ReceiptResult)`` for a Fulcio-certificate bundle."""
    import hashlib

    from cryptography.hazmat.primitives import serialization

    from opentine._fulcio_verify import cert_identity, load_roots, verify_keyless
    from opentine.intoto import EnvelopeResult, _b64, _statement

    refuse_unhonoured(
        args,
        ("pubkey", "pin", "trust_embedded_key"),
        mode="for a keyless attestation",
        hint="Its key is a Fulcio certificate: pass --cert-identity and --cert-oidc-issuer.",
    )
    missing = [f"--{d.replace('_', '-')}" for d in _KEYLESS_VERIFY if not getattr(args, d, None)]
    if missing or not getattr(args, "rekor_key", None):
        reason = f"keyless attestation needs {', '.join(missing + ['--rekor-key'])}"
        return EnvelopeResult(False, "no-key", reason), None
    receipt = receipt_for(args, envelope, entries, leaf.public_key(), need=True)
    if not receipt.ok:
        return EnvelopeResult(False, "error", "keyless signature needs a verified receipt"), receipt
    try:
        with open(args.fulcio_root, "rb") as handle:
            roots = load_roots(handle.read(1 << 20))
        verify_keyless(
            envelope,
            leaf,
            roots=roots,
            identity=args.cert_identity,
            issuer=args.cert_oidc_issuer,
            integrated_time=receipt.integrated_time,
        )
        statement = _statement(_b64(envelope.get("payload")))
    except (OSError, ValueError) as exc:
        return EnvelopeResult(False, "mismatch", str(exc)), receipt
    der = leaf.public_bytes(serialization.Encoding.DER)
    names, _ = cert_identity(leaf)
    fpr = "sha256:" + hashlib.sha256(der).hexdigest()
    identity = args.cert_identity if args.cert_identity in names else None
    return EnvelopeResult(True, "verified-keyless", "ok", identity, fpr, statement), receipt
