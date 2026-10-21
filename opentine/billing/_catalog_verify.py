"""Schema acceptance, canonical hashing, and signature trust for catalogs.

Split out of ``catalog.py``: what a catalog *is* (cards, effective dates, lookup
precedence) and what makes one *trusted* are separate concerns, and only this
half needs to know about keys.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from opentine._canon import _canonical_bytes
from opentine.billing._media import check_schema_features

#: Every catalog schema this build reads. ``/2`` adds the optional time-of-day
#: ``schedule`` to a rate card; ``/1`` stays readable forever, because a repo of
#: runs priced against an older catalog must keep loading (the backwards-compat
#: policy) and user overlays in the wild are still written as ``/1``. The two
#: differ only by that optional field, so one parser reads both. ``/3`` adds the
#: optional media fields ``units`` and ``same_rate_as`` (``billing._media``);
#: a /1 or /2 catalog that carries them is refused, so no reader prices a
#: per-image rate as a per-million one.
SUPPORTED_SCHEMAS = ("opentine-pricing/1", "opentine-pricing/2", "opentine-pricing/3")
TRUSTED_KEYS = {
    "opentine-release-2026-07-r3": "VuhZjI3+QIPzZEA0y0Emw+o11f69o1J4kETghGGCwgc=",
}


class CatalogError(ValueError):
    pass


def checked_cards(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The catalog's card objects, after the shape and schema-feature checks."""
    cards = data.get("cards")
    if not isinstance(cards, list) or not all(isinstance(item, dict) for item in cards):
        raise CatalogError("pricing catalog cards must be a list of objects")
    try:
        check_schema_features(data)
    except ValueError as exc:
        raise CatalogError(str(exc)) from exc
    return cards


#: The whole ``signature`` block is left out of the signed bytes, so anything
#: in it beyond these fields is unsigned, and it is copied into every billed
#: step's provenance: a catalog padded there (a cloned ``.tine/pricing.json``)
#: would grow every run record by the padding. Only these keys are accepted,
#: and only they are ever copied.
SIGNATURE_FIELDS = ("algorithm", "key_id", "value")
_MAX_SIGNATURE_FIELD = 256


def signature_fields(signature: Any) -> dict[str, str] | None:
    """The known, bounded signature fields, or None: never arbitrary content."""
    if not isinstance(signature, dict):
        return None
    return {
        key: value
        for key in SIGNATURE_FIELDS
        if isinstance(value := signature.get(key), str) and len(value) <= _MAX_SIGNATURE_FIELD
    }


def _body(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key not in {"catalog_id", "signature"}}


def catalog_hash(data: dict[str, Any]) -> str:
    try:
        return hashlib.sha256(_canonical_bytes(_body(data))).hexdigest()
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise CatalogError(f"catalog is not canonical JSON: {exc}") from exc


def verify_catalog(data: dict[str, Any], *, require_signature: bool = True) -> str:
    if not isinstance(data, dict):
        raise CatalogError("pricing catalog root is not an object")
    if data.get("schema") not in SUPPORTED_SCHEMAS:
        raise CatalogError("unsupported pricing catalog schema")
    actual = catalog_hash(data)
    if data.get("catalog_id") != f"sha256:{actual}":
        raise CatalogError("catalog id/hash mismatch")
    signature = data.get("signature")
    if signature is None:
        if require_signature:
            raise CatalogError("catalog is unsigned")
        return actual
    if not isinstance(signature, dict):
        raise CatalogError("catalog signature is not an object")
    if set(signature) - set(SIGNATURE_FIELDS):
        raise CatalogError("catalog signature has unexpected fields")
    if any(
        not isinstance(signature.get(key), str) or len(signature[key]) > _MAX_SIGNATURE_FIELD
        for key in SIGNATURE_FIELDS
    ):
        raise CatalogError("catalog signature fields must be short strings")
    if signature.get("algorithm") != "ed25519":
        raise CatalogError("unsupported catalog signature algorithm")
    key_id = signature.get("key_id")
    encoded_key = TRUSTED_KEYS.get(key_id) if isinstance(key_id, str) else None
    if not encoded_key:
        raise CatalogError("untrusted catalog signing key")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        encoded_signature = signature.get("value")
        if not isinstance(encoded_signature, str):
            raise CatalogError("catalog signature value is missing")
        public_bytes = base64.b64decode(encoded_key, validate=True)
        signature_bytes = base64.b64decode(encoded_signature, validate=True)
        if len(public_bytes) != 32 or len(signature_bytes) != 64:
            raise CatalogError("catalog signature has the wrong length")
        public = Ed25519PublicKey.from_public_bytes(public_bytes)
        public.verify(signature_bytes, _canonical_bytes(_body(data)))
    except ImportError as exc:
        raise CatalogError("catalog verification requires cryptography") from exc
    except CatalogError:
        raise
    except Exception as exc:
        raise CatalogError("catalog signature mismatch") from exc
    return actual
