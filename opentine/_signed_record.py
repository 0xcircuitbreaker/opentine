"""Signed JSON records outside the object store: tombstones and redacted copies (0.46).

A record is a canonical JSON object with a fixed set of fields plus a
``tine-sig/3`` block (``signature``) over ``DOMAIN`` + JCS of
``{"body": <the record without signature>, "header": <header>}``, the shape the
0.45.1 redaction report uses (SPEC 4.13). Each kind has its own domain prefix,
so a record of one kind can never pass for another or for an artifact.

:func:`check_signature` applies the key rules every such kind shares, with the
kind's reason-code prefix: an HMAC record needs ``hmac_key``; a supplied key
never falls back to the embedded one; with no key an Ed25519 record verifies
under its embedded key (trust on first use, state ``verified-tofu``). Records
are signed only where the key is (the CLI), never by a server.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._signing_v4 import SCHEME_V3
from opentine._signing_verify import HEADER_KEYS, sign_block, verify_block
from opentine.kernel import canonical_json

NAME = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}")
WHEN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
BLOB_OID = re.compile(r"blob:sha256:[0-9a-f]{64}")
RUN_OID = re.compile(r"run:sha256:[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class RecordError(ValueError):
    """A refusal; ``code`` is the conformance reason (``<kind>.<reason>``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def fields(record: Any, kind: str, names: tuple[str, ...], code: str, what: str) -> dict:
    """The fixed fields of *record* (``signature`` aside); ``<code>.malformed`` else."""
    if not isinstance(record, dict) or record.get("kind") != kind:
        raise RecordError(f"{code}.malformed", f"{what} is malformed: kind is not {kind}")
    if set(record) - {*names, "signature"} or set(names) - set(record):
        raise RecordError(f"{code}.malformed", f"{what} is malformed: wrong set of fields")
    return {name: record[name] for name in names}


def _message(domain: bytes, body: dict[str, Any], header: dict[str, Any]) -> bytes:
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    return domain + canonical_json(view)


def sign(
    body: dict[str, Any], domain: bytes, subject: str, key: Any, *, algorithm: str, **header: Any
) -> dict[str, Any]:
    block = sign_block(
        lambda h: _message(domain, body, h),
        key,
        algorithm=algorithm,
        scheme=SCHEME_V3,
        subject=subject,
        **header,
    )
    return {**body, "signature": block}


def check_signature(
    record: dict[str, Any],
    body: dict[str, Any],
    *,
    domain: bytes,
    code: str,
    subject: str,
    hmac_key: bytes | None = None,
    public_key: bytes | None = None,
) -> str:
    """The verified state (``verified`` / ``verified-tofu``); :class:`RecordError` else."""
    block = record.get("signature")
    if block is None:
        raise RecordError(f"{code}.unsigned", f"the {subject} is unsigned")
    if not isinstance(block, dict):
        raise RecordError(f"{code}.bad-signature", f"the {subject} signature is not a block")
    algorithm = block.get("alg")
    if algorithm == "hmac-sha256" and hmac_key is None:
        raise RecordError(f"{code}.no-key", f"no key for an hmac-sha256 {subject}")
    if hmac_key is not None and algorithm != "hmac-sha256":
        raise RecordError(f"{code}.wrong-key", "not the trusted key's algorithm")
    if public_key is not None:
        if algorithm != "ed25519":
            raise RecordError(f"{code}.wrong-key", "not the trusted key's algorithm")
        if block.get("public_key") != bytes(public_key).hex():
            raise RecordError(f"{code}.wrong-key", "signed by a key other than the trusted key")
    keys: dict[str, Any] = {}
    if algorithm == "hmac-sha256":
        keys["hmac_key"] = hmac_key
    elif public_key is not None:
        keys["public_key"] = bytes(public_key)
    else:
        keys["trust_embedded"] = True
    result = verify_block(
        block, lambda h: _message(domain, body, h), schemes=(SCHEME_V3,), subject=subject, **keys
    )
    if not result.ok:
        raise RecordError(
            f"{code}.bad-signature",
            f"the {subject} signature does not hold ({result.state}: {result.reason})",
        )
    return result.state


__all__ = [
    "BLOB_OID",
    "DIGEST",
    "NAME",
    "RUN_OID",
    "WHEN",
    "RecordError",
    "check_signature",
    "fields",
    "is_count",
    "sign",
]
