"""SPEC 8.14 (0.46): check a remote's signed SLSA VSA for one pushed object.

``tine serve --vsa-dir`` (and ``--trust-policy``) emits, for every admitted ref
update, an in-toto Statement v1 whose predicate is a SLSA Verification Summary
Attestation, in a DSSE envelope signed by the *server's* Ed25519 key -- never a
user's. A CI gate holds that key pinned and asks one question: did this
server admit this object, under this policy, at these levels?

:func:`classify` answers with one class, in this order: **malformed** (not a
DSSE envelope of ``application/vnd.in-toto+json``), **bad-signature** (no
signature verifies under the pinned key over the DSSE PAE), **malformed**
again (the signed payload is not a VSA statement with exactly one subject),
**wrong-subject** (its sha256 is not the expected one), **failed**
(``verificationResult`` is not ``PASSED``), **wrong-policy** (a policy URI was
required and ``predicate.policy.uri`` differs), **missing-level** (a required
level is absent from ``verifiedLevels``); otherwise **valid**. It never raises.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VSA_TYPE = "https://slsa.dev/verification_summary/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MAX_ENVELOPE_BYTES = 1 << 20
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def pae(payload_type: str, body: bytes) -> bytes:
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body)


def _b64(text: Any) -> bytes:
    if not isinstance(text, str) or len(text) % 4 or not _B64.fullmatch(text):
        raise ValueError("not base64")
    return base64.b64decode(text, validate=True)


def _ed25519(key: bytes, sig: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _statement(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or value.get("_type") != STATEMENT_TYPE:
        return None
    subject, predicate = value.get("subject"), value.get("predicate")
    if value.get("predicateType") != VSA_TYPE or not isinstance(predicate, dict):
        return None
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        return None
    digest = subject[0].get("digest")
    if not isinstance(digest, dict) or not _HEX64.fullmatch(str(digest.get("sha256", ""))):
        return None
    levels, policy = predicate.get("verifiedLevels"), predicate.get("policy")
    if not isinstance(levels, list) or not all(isinstance(level, str) for level in levels):
        return None
    if not isinstance(policy, dict) or not isinstance(policy.get("uri"), str):
        return None
    return value


def classify(
    envelope: Any,
    key: bytes,
    subject: str,
    *,
    levels: list[str] | tuple[str, ...] = (),
    policy: str = "",
    verify: Any = _ed25519,
) -> str:
    """The class of *envelope* for *subject* under the pinned server *key*."""
    try:
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            return "malformed"
        body = _b64(envelope.get("payload"))
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures or len(body) > MAX_ENVELOPE_BYTES:
            return "malformed"
        sigs = []
        for entry in signatures:
            if not isinstance(entry, dict) or set(entry) - {"keyid", "sig"}:
                return "malformed"
            sigs.append(_b64(entry.get("sig")))
    except (ValueError, binascii.Error):
        return "malformed"
    message = pae(PAYLOAD_TYPE, body)
    if len(key) != 32 or not any(len(s) == 64 and verify(key, s, message) for s in sigs):
        return "bad-signature"
    statement = _statement(body)
    if statement is None:
        return "malformed"
    predicate = statement["predicate"]
    if statement["subject"][0]["digest"]["sha256"] != subject.rsplit(":", 1)[-1]:
        return "wrong-subject"
    if predicate.get("verificationResult") != "PASSED":
        return "failed"
    if policy and predicate["policy"]["uri"] != policy:
        return "wrong-policy"
    if not set(levels) <= set(predicate["verifiedLevels"]):
        return "missing-level"
    return "valid"


def verify_case(value: dict[str, Any], verify: Any = _ed25519) -> dict[str, Any]:
    """A conformance ``vsa.verify`` input -> ``{"ok", "class"}``."""
    try:
        key = base64.urlsafe_b64decode(value["key"] + "=" * (-len(value["key"]) % 4))
        levels = value["levels"]
        if not isinstance(levels, list) or not all(isinstance(x, str) for x in levels):
            raise TypeError("levels")
        kind = classify(
            value["envelope"],
            key,
            str(value["subject"]),
            levels=levels,
            policy=str(value["policy"]),
            verify=verify,
        )
    except (KeyError, TypeError, ValueError, AttributeError, binascii.Error):
        kind = "malformed"
    return {"class": kind, "ok": kind == "valid"}


__all__ = ["classify", "pae", "verify_case"]
