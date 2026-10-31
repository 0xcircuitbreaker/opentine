"""Sigstore ``trusted_root.json``: Rekor, Fulcio and CT trust from one file.

The public-good format (``application/vnd.dev.sigstore.trustedroot+json;
version=0.1``) lists, each with a ``validFor`` window:

* ``tlogs`` -- Rekor log keys (DER SubjectPublicKeyInfo) and their ``logId``;
* ``certificateAuthorities`` -- Fulcio certificate chains;
* ``ctlogs`` -- Certificate Transparency log keys;
* ``timestampAuthorities`` -- RFC 3161 TSAs (parsed for shape, not used).

A key or CA is used only for a signature whose time lies inside its window: a
Rekor key for an entry's ``integratedTime``, a CA for that verified
``integratedTime``, a CT key for the leaf's ``notBefore`` (when Fulcio logged
it). A ``logId`` that is not the SHA-256 of its key is refused outright.

The installed copy lives in ``$XDG_CONFIG_HOME/opentine/sigstore/``; it is the
default for ``--trusted-root`` only after ``tine trust root update`` opted in.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from opentine._rekor_proof import log_id

MEDIA_TYPES = frozenset(
    {
        "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "application/vnd.dev.sigstore.trustedroot.v0.1+json",
        "application/vnd.dev.sigstore.trustedroot.v0.2+json",
    }
)
MAX_BYTES = 1 << 20
FILE_NAME = "trusted_root.json"
_MAX_ENTRIES = 64

__all__ = [
    "TrustedRoot",
    "default_trusted_root",
    "load_trusted_root",
    "parse_trusted_root",
    "sigstore_dir",
]


@dataclass(frozen=True)
class _Window:
    start: datetime
    end: datetime | None

    def contains(self, when: datetime) -> bool:
        return self.start <= when and (self.end is None or when <= self.end)


@dataclass
class TrustedRoot:
    tlogs: list[tuple[bytes, Any, _Window]] = field(default_factory=list)
    authorities: list[tuple[list[x509.Certificate], _Window]] = field(default_factory=list)
    ctlogs: list[tuple[bytes, Any, _Window]] = field(default_factory=list)

    def rekor_key(self, key_id: bytes, when: datetime) -> Any:
        """The Rekor key with *key_id* valid at *when*, else ``None``."""
        return next((k for i, k, w in self.tlogs if i == key_id and w.contains(when)), None)

    def fulcio_roots(self, when: datetime) -> list[x509.Certificate]:
        certs = [c for chain, w in self.authorities if w.contains(when) for c in chain]
        if not certs:
            raise ValueError("no certificate authority in --trusted-root is valid at that time")
        return certs

    def ct_keys(self, when: datetime) -> list:
        return [k for _, k, w in self.ctlogs if w.contains(when)]


def sigstore_dir() -> Path:
    home = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(home, "opentine", "sigstore")


def default_trusted_root() -> Path | None:
    """The TUF-installed root, but only once ``tine trust root update`` opted in."""
    base = sigstore_dir()
    path, state = base / FILE_NAME, base / "tuf" / "state.json"
    return path if path.is_file() and state.is_file() else None


def _time(value: Any, what: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{what} is not an RFC 3339 time")
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f"{what} is not an RFC 3339 time") from None
    if when.tzinfo is None:
        raise ValueError(f"{what} has no time zone")
    return when.astimezone(UTC)


def _window(item: dict, what: str) -> _Window:
    valid = item.get("validFor")
    if not isinstance(valid, dict) or "start" not in valid:
        raise ValueError(f"{what} has no validFor.start")
    start = _time(valid["start"], f"{what} validFor.start")
    end = _time(valid["end"], f"{what} validFor.end") if valid.get("end") else None
    if end is not None and end < start:
        raise ValueError(f"{what} validFor ends before it starts")
    return _Window(start, end)


def _b64(value: Any, what: str) -> bytes:
    try:
        return base64.b64decode(str(value).encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValueError(f"{what} is not base64") from None


def _log(item: Any, what: str, strict: bool = True) -> tuple[bytes, Any, _Window] | None:
    if not isinstance(item, dict) or not isinstance(item.get("publicKey"), dict):
        raise ValueError(f"{what} has no publicKey")
    public = item["publicKey"]
    try:
        key = serialization.load_der_public_key(_b64(public.get("rawBytes"), what))
    except ValueError as exc:
        raise ValueError(f"{what} key is not DER SubjectPublicKeyInfo: {exc}") from None
    if not isinstance(key, ec.EllipticCurvePublicKey | rsa.RSAPublicKey | ed25519.Ed25519PublicKey):
        raise ValueError(f"{what} key type is not supported")
    key_id = _b64((item.get("logId") or {}).get("keyId"), f"{what} logId")
    if key_id != log_id(key):
        # A Rekor v2 (tile) log derives its id from its checkpoint key name, not
        # the key's SHA-256 (the public-good root lists one since 2025). Its
        # entries never match a v1 receipt's logId, so skip it; CT log ids are
        # fixed by RFC 6962 and stay strict.
        if not strict:
            return None
        raise ValueError(f"{what} logId is not the SHA-256 of its key")
    return key_id, key, _window(public, what)


def _authority(item: Any, what: str) -> tuple[list[x509.Certificate], _Window]:
    chain = (
        ((item or {}).get("certChain") or {}).get("certificates")
        if isinstance(item, dict)
        else None
    )
    if not isinstance(chain, list) or not chain or len(chain) > 8:
        raise ValueError(f"{what} has no certChain")
    try:
        certs = [x509.load_der_x509_certificate(_b64(c.get("rawBytes"), what)) for c in chain]
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{what} certificate is malformed: {exc}") from None
    return certs, _window(item, what)


def _list(doc: dict, name: str) -> list:
    value = doc.get(name, [])
    if not isinstance(value, list) or len(value) > _MAX_ENTRIES:
        raise ValueError(f"trusted root {name} is not a list")
    return value


def parse_trusted_root(raw: bytes) -> TrustedRoot:
    """Validate *raw* and return its trust material; ``ValueError`` names the flaw."""
    if len(raw) > MAX_BYTES:
        raise ValueError(f"trusted root exceeds {MAX_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("trusted root is not JSON") from None
    if not isinstance(doc, dict) or doc.get("mediaType") not in MEDIA_TYPES:
        raise ValueError("not a Sigstore trusted root (unexpected mediaType)")
    tlogs = [_log(t, f"tlogs[{i}]", strict=False) for i, t in enumerate(_list(doc, "tlogs"))]
    root = TrustedRoot(
        tlogs=[log for log in tlogs if log is not None],
        authorities=[
            _authority(c, f"certificateAuthorities[{i}]")
            for i, c in enumerate(_list(doc, "certificateAuthorities"))
        ],
        ctlogs=[_log(t, f"ctlogs[{i}]") for i, t in enumerate(_list(doc, "ctlogs"))],
    )
    for i, tsa in enumerate(_list(doc, "timestampAuthorities")):
        _authority(tsa, f"timestampAuthorities[{i}]")
    if not root.tlogs or not root.authorities:
        raise ValueError("trusted root lists no tlogs or no certificateAuthorities")
    return root


def load_trusted_root(path: str | os.PathLike) -> TrustedRoot:
    with open(path, "rb") as handle:
        return parse_trusted_root(handle.read(MAX_BYTES + 1))
