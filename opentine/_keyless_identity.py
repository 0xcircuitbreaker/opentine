"""Keyless signer identities (0.74): what a Fulcio-style certificate says, and its tier.

A short-lived certificate names its holder by an OIDC identity: the SAN (an
email for a person, a workflow URI for a CI job) plus Fulcio's extensions under
1.3.6.1.4.1.57264.1 (issuer, build signer URI, source repository and ref,
runner environment, trigger). :func:`facts` reads them; :func:`tier` maps them
to an *assurance tier*:

* ``keyless-workflow`` -- a CI workload identity: the certificate names both
  the workflow that signed (build signer URI) and the source repository;
* ``keyless-person`` -- an email identity, a human at an OIDC provider;
* ``keyless-unbound`` -- anything else.

The tier describes the identity; it never grants trust. A keyless identity is
trusted only when an owner-pinned trust bundle (SPEC 8.26) names its issuer and
the exact identity (``trust_policy.cert_oidc_issuer`` + ``cert_identity``):
see :func:`pinned_by`.
"""

from __future__ import annotations

from typing import Any

from cryptography import x509

_ARC = "1.3.6.1.4.1.57264.1."
#: Fulcio v2 extensions (DER UTF8String) a verifier reports, by field name.
EXTENSIONS = {
    "issuer": "8",
    "build_signer_uri": "9",
    "build_signer_digest": "10",
    "runner_environment": "11",
    "source_repository_uri": "12",
    "source_repository_digest": "13",
    "source_repository_ref": "14",
    "build_trigger": "20",
}
#: Legacy (v1) extensions, raw bytes: used only when the v2 field is absent.
LEGACY = {"issuer": "1", "build_trigger": "2", "source_repository_ref": "6"}
TIERS = ("keyless-workflow", "keyless-person", "keyless-unbound")


def _utf8(raw: bytes) -> str:
    """A DER UTF8String (tag 0x0C, short or one/two-byte long form)."""
    if len(raw) < 2 or raw[0] != 0x0C:
        raise ValueError("extension is not a DER UTF8String")
    head = raw[1]
    if head < 0x80:
        start, size = 2, head
    elif head in (0x81, 0x82):
        width = head - 0x80
        start, size = 2 + width, int.from_bytes(raw[2 : 2 + width], "big")
    else:
        raise ValueError("extension length is malformed")
    if len(raw) != start + size:
        raise ValueError("extension length does not match its content")
    return raw[start:].decode("utf-8")


def _ext(cert: x509.Certificate, arc: str) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(_ARC + arc))
    except x509.ExtensionNotFound:
        return None
    return ext.value.value


def facts(cert: x509.Certificate) -> dict[str, Any]:
    """The identity a certificate names: SAN values and Fulcio extensions."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        emails = [str(v) for v in san.get_values_for_type(x509.RFC822Name)]
        uris = [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        emails, uris = [], []
    out: dict[str, Any] = {"san": emails + uris, "san_email": emails, "san_uri": uris}
    for name, arc in EXTENSIONS.items():
        raw = _ext(cert, arc)
        out[name] = _utf8(raw) if raw is not None else None
    for name, arc in LEGACY.items():
        if out[name] is None and (raw := _ext(cert, arc)) is not None:
            out[name] = raw.decode("utf-8", "replace")
    return out


def tier(identity: dict[str, Any]) -> str:
    """The assurance tier of :func:`facts` output (descriptive only)."""
    if identity.get("build_signer_uri") and identity.get("source_repository_uri"):
        if identity.get("san_uri"):
            return "keyless-workflow"
    if identity.get("san_email") and not identity.get("san_uri"):
        return "keyless-person"
    return "keyless-unbound"


def pinned_by(identity: dict[str, Any], pins: list[dict[str, str]]) -> dict[str, str] | None:
    """The pin naming this exact issuer *and* identity, else ``None`` (never a prefix)."""
    for pin in pins:
        issuer, name = pin.get("cert_oidc_issuer"), pin.get("cert_identity")
        if not issuer or not name:
            continue  # half a pin names nobody
        if identity.get("issuer") == issuer and name in identity.get("san", []):
            return pin
    return None


__all__ = ["EXTENSIONS", "TIERS", "facts", "pinned_by", "tier"]
