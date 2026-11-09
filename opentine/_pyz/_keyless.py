"""The keyless TSA binding for ``tine-verify.pyz`` (SPEC 8.12.1, 0.48).

A stdlib port of ``opentine._keyless_tsa.bind_request``: over decoded RFC 3161
tokens, the imprint must be the hash of the DSSE signature bytes, genTime must
sit inside the TSA's ``validFor`` and (with its accuracy) inside the leaf
certificate's validity, and the earliest genTime is the signing time. With no
token the time stays ``unchecked``. Refusals carry ``keyless.*`` codes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from ._gitobj import Refused

HASHES = ("sha256", "sha384", "sha512")
MAX_TOKENS = 16
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:[Zz]|[+-]\d{2}:?\d{2})", re.ASCII
)
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*", re.ASCII)


def _no(code: str, message: str) -> Refused:
    prefix = "keyless input is malformed: " if code == "malformed" else ""
    return Refused(f"keyless.{code}", prefix + message)


def _time(value: Any, what: str) -> datetime:
    try:
        ok = isinstance(value, str) and _RFC3339.fullmatch(value)
        when = datetime.fromisoformat(value) if ok else None
    except ValueError:
        when = None
    if when is None or when.tzinfo is None:
        raise _no("malformed", f"{what} is not an RFC 3339 time with a zone")
    return when.astimezone(UTC)


def _window(value: Any, what: str) -> tuple[datetime, datetime | None]:
    if not isinstance(value, dict) or set(value) - {"start", "end"} or "start" not in value:
        raise _no("malformed", f"{what} must be {{start, end?}}")
    end = value.get("end")
    return _time(value["start"], f"{what}.start"), _time(end, f"{what}.end") if end else None


def _stamp(when: datetime) -> str:
    text = when.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (f".{when.microsecond:06d}" if when.microsecond else "") + "Z"


def _check(index: int, token: Any, signature: bytes, start, end) -> datetime:
    if not isinstance(token, dict) or token.get("hash_algorithm") not in HASHES:
        raise _no("malformed", f"token {index}: hash_algorithm is one of {HASHES}")
    raw = token.get("message_imprint")
    if not isinstance(raw, str) or not _HEX.fullmatch(raw):
        raise _no("malformed", f"token {index}: message_imprint is not hex")
    imprint = bytes.fromhex(raw)
    if not hmac.compare_digest(imprint, hashlib.new(token["hash_algorithm"], signature).digest()):
        raise _no("tsa-imprint-mismatch", f"token {index} does not cover the signature")
    gen = _time(token.get("gen_time"), f"token {index} gen_time")
    accuracy = token.get("accuracy_us")
    accuracy = 0 if accuracy is None else accuracy
    if type(accuracy) is not int or accuracy < 0:
        raise _no("malformed", f"token {index}: accuracy_us is a non-negative integer")
    if token.get("tsa_valid_for") is not None:
        tsa_start, tsa_end = _window(token["tsa_valid_for"], f"token {index} tsa_valid_for")
        if gen < tsa_start or (tsa_end is not None and gen > tsa_end):
            raise _no("tsa-retired", f"token {index}: genTime is outside its TSA's validFor")
    slack = timedelta(microseconds=accuracy)
    if not (start <= gen - slack and (end is None or gen + slack <= end)):
        detail = f"token {index}: the certificate was not valid at genTime {_stamp(gen)}"
        raise _no("cert-not-valid-at-signing", detail)
    return gen


def signing_time(value: Any) -> dict[str, Any]:
    """``{signing_time, status}`` for ``{signature, tokens, leaf, receipt}``; raises ``Refused``."""
    if not isinstance(value, dict):
        raise _no("malformed", "the request is not an object")
    try:
        if not isinstance(value.get("signature"), str):
            raise binascii.Error
        signature = base64.b64decode(value["signature"], validate=True)
    except binascii.Error:
        raise _no("malformed", "signature is not base64") from None
    if value.get("receipt") != "verified":
        raise _no(
            "receipt-invalid", f"the Rekor v2 receipt is {value.get('receipt')}, not verified"
        )
    tokens = value.get("tokens")
    if not isinstance(tokens, list) or len(tokens) > MAX_TOKENS:
        raise _no("malformed", f"tokens must be a list of at most {MAX_TOKENS}")
    start, end = _window(value.get("leaf"), "leaf")
    if not tokens:
        return {"signing_time": None, "status": "unchecked"}
    times = [_check(i, token, signature, start, end) for i, token in enumerate(tokens)]
    return {"signing_time": _stamp(min(times)), "status": "verified"}


__all__ = ["Refused", "signing_time"]
