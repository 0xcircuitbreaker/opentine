"""Bind an RFC 3161 token to a Rekor v2 keyless signature (0.48, SPEC 8.12.1).

A Rekor v2 (tile) receipt proves inclusion but, unlike a v1 receipt, carries
no signed ``integratedTime``: a short-lived Fulcio certificate then proves
nothing until something trusted says *when* it signed. Sigstore bundles carry
that as ``verificationMaterial.timestampVerificationData.rfc3161Timestamps``:
tokens whose messageImprint is the hash of the DSSE **signature bytes** (not
the payload, not the envelope).

:func:`bind` holds the binding rules the ``77-keyless-tsa`` vectors pin, over
tokens already decoded: the receipt must have verified; with no token the
signing time stays ``unchecked``; every token carried must cover the signature
(``keyless.tsa-imprint-mismatch``), fall inside its TSA's ``validFor``
(``keyless.tsa-retired``) and, with its accuracy, inside the leaf
certificate's validity (``keyless.cert-not-valid-at-signing``). The earliest
genTime is the verified signing time. :func:`token_time` runs those rules on
real tokens after :func:`opentine._tsp_verify.verify_token` has checked each
one's CMS signature and chain to the trusted root's ``timestampAuthorities``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Any

from opentine._key_lifecycle import parse_time

HASHES = ("sha256", "sha384", "sha512")
MAX_TOKENS = 16
_FROM_TSP = {
    "timestamp.imprint-mismatch": "tsa-imprint-mismatch",
    "timestamp.tsa-retired": "tsa-retired",
}


class TsaBindError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _no(code: str, message: str) -> TsaBindError:
    prefix = "keyless input is malformed: " if code == "malformed" else ""
    return TsaBindError(f"keyless.{code}", prefix + message)


def _time(value: Any, what: str) -> datetime:
    try:
        return parse_time(value, what)
    except ValueError as exc:
        raise _no("malformed", str(exc)) from None


def stamp(when: datetime) -> str:
    """RFC 3339 UTC, with a fraction only when there is one."""
    text = when.strftime("%Y-%m-%dT%H:%M:%S")
    return text + (f".{when.microsecond:06d}" if when.microsecond else "") + "Z"


def _window(value: Any, what: str) -> tuple[datetime, datetime | None]:
    if not isinstance(value, dict) or set(value) - {"start", "end"} or "start" not in value:
        raise _no("malformed", f"{what} must be {{start, end?}}")
    end = value.get("end")
    return _time(value["start"], f"{what}.start"), _time(end, f"{what}.end") if end else None


def bind(*, signature: bytes, tokens: Any, leaf: Any, receipt: str) -> dict[str, Any]:
    """``{signing_time, status}`` from decoded tokens; raises :class:`TsaBindError`."""
    if receipt != "verified":
        raise _no("receipt-invalid", f"the Rekor v2 receipt is {receipt}, not verified")
    if not isinstance(tokens, list) or len(tokens) > MAX_TOKENS:
        raise _no("malformed", f"tokens must be a list of at most {MAX_TOKENS}")
    start, end = _window(leaf, "leaf")
    if not tokens:
        return {"signing_time": None, "status": "unchecked"}
    times = []
    for index, token in enumerate(tokens):
        if not isinstance(token, dict) or token.get("hash_algorithm") not in HASHES:
            raise _no("malformed", f"token {index}: hash_algorithm is one of {HASHES}")
        try:
            imprint = bytes.fromhex(str(token.get("message_imprint")))
        except ValueError:
            raise _no("malformed", f"token {index}: message_imprint is not hex") from None
        expected = hashlib.new(token["hash_algorithm"], signature).digest()
        if not hmac.compare_digest(imprint, expected):
            raise _no("tsa-imprint-mismatch", f"token {index} does not cover the signature")
        gen = _time(token.get("gen_time"), f"token {index} gen_time")
        accuracy = token.get("accuracy_us") or 0
        if type(accuracy) is not int or accuracy < 0:
            raise _no("malformed", f"token {index}: accuracy_us is a non-negative integer")
        if token.get("tsa_valid_for") is not None:
            tsa_start, tsa_end = _window(token["tsa_valid_for"], f"token {index} tsa_valid_for")
            if gen < tsa_start or (tsa_end is not None and gen > tsa_end):
                raise _no("tsa-retired", f"token {index}: genTime is outside its TSA's validFor")
        slack = timedelta(microseconds=accuracy)
        if not (start <= gen - slack and gen + slack <= (end or gen + slack)):
            raise _no("cert-not-valid-at-signing", f"token {index}: the certificate was not "
                      f"valid at genTime {stamp(gen)}")  # fmt: skip
        times.append(gen)
    return {"signing_time": stamp(min(times)), "status": "verified"}


def bind_request(value: Any) -> dict[str, Any]:
    """:func:`bind` over the vector input ``{signature (base64), tokens, leaf, receipt}``."""
    if not isinstance(value, dict):
        raise _no("malformed", "the request is not an object")
    try:
        signature = base64.b64decode(str(value.get("signature")), validate=True)
    except binascii.Error:
        raise _no("malformed", "signature is not base64") from None
    return bind(signature=signature, tokens=value.get("tokens"), leaf=value.get("leaf"),
                receipt=value.get("receipt"))  # fmt: skip


def bundle_tokens(material: Any) -> list[bytes]:
    """The DER tokens of ``timestampVerificationData``; ``[]`` when there are none."""
    data = material.get("timestampVerificationData") if isinstance(material, dict) else None
    items = (data or {}).get("rfc3161Timestamps") if isinstance(data, dict) else None
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > MAX_TOKENS:
        raise _no("malformed", "rfc3161Timestamps is not a short list")
    try:
        return [base64.b64decode(str(item["signedTimestamp"]), validate=True) for item in items]
    except (KeyError, TypeError, binascii.Error):
        raise _no("malformed", "an rfc3161Timestamps entry has no signedTimestamp") from None


def signature_bytes(envelope: dict) -> bytes:
    sigs = envelope.get("signatures") if isinstance(envelope, dict) else None
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
        raise _no("malformed", "a keyless envelope carries exactly one signature")
    try:
        return base64.b64decode(str(sigs[0].get("sig")), validate=True)
    except binascii.Error:
        raise _no("malformed", "the envelope signature is not base64") from None


def token_time(material: Any, envelope: dict, root: Any, leaf: Any) -> datetime | None:
    """The verified signing time from the bundle's tokens; ``None`` when it carries none."""
    from opentine._tsp_verify import verify_token

    raw = bundle_tokens(material)
    if not raw:
        return None
    signature = signature_bytes(envelope)
    decoded = []
    for index, token in enumerate(raw):
        verdict = verify_token(token, signature, [], root.timestamp_authorities)
        if not verdict.ok:
            code = _FROM_TSP.get(verdict.reason, "tsa-invalid")
            raise _no(code, f"token {index}: {verdict.reason}: {verdict.detail}")
        name = verdict.info["hash_algorithm"]
        decoded.append({"hash_algorithm": name, "gen_time": verdict.info["gen_time"],
                        "message_imprint": hashlib.new(name, signature).hexdigest(),
                        "accuracy_us": verdict.info.get("accuracy_us")})  # fmt: skip
    window = {"start": stamp(leaf.not_valid_before_utc), "end": stamp(leaf.not_valid_after_utc)}
    result = bind(signature=signature, tokens=decoded, leaf=window, receipt="verified")
    return parse_time(result["signing_time"])


__all__ = [
    "TsaBindError",
    "bind",
    "bind_request",
    "bundle_tokens",
    "signature_bytes",
    "stamp",
    "token_time",
]
