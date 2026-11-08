"""SPEC 8.14 (0.46): a remote's signed SLSA VSA for one pushed object.

Every case is a verdict: ``ok`` and a ``class`` (valid, malformed,
bad-signature, wrong-subject, failed, wrong-policy, missing-level), never a
raise. The server key is a fixed Ed25519 seed and the time is fixed, so
regeneration is byte-identical.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine.intoto import sign_statement
from opentine.remote._vsa import build_vsa
from tests.conformance.cases import VERDICT, Case, Family, V

KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"conformance vsa").digest())
OTHER = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"another vsa key").digest())
RAW = base64.urlsafe_b64encode(KEY.public_key().public_bytes_raw()).decode().rstrip("=")
OID = "run:" + "ab" * 32
POLICY = {"uri": "opentine:trust-policy/prod", "digest": {"sha256": "cd" * 32}}
TIME = "2026-11-08T12:00:00Z"


def _vsa(**predicate) -> dict:
    statement = build_vsa("acme", "heads/main", OID, ["OPENTINE_ADMITTED", "SIGNED"],
                          time_verified=TIME, policy=POLICY)  # fmt: skip
    statement["predicate"].update(predicate)
    return statement


SIGNED = sign_statement(_vsa(), KEY)


def _value(envelope=SIGNED, subject=OID, levels=("OPENTINE_ADMITTED",), policy="") -> dict:
    return {"envelope": envelope, "key": RAW, "subject": subject, "levels": list(levels),
            "policy": policy}  # fmt: skip


def _case(cid: str, intent: str, value: dict) -> Case:
    return Case(id=cid, section="8.14", checklist=(8,), op="vsa.verify", profile="verifier",
                expect=VERDICT, intent=intent, input=V(value), requires=("ed25519",))  # fmt: skip


def _payload(statement: dict) -> str:
    from opentine.kernel import canonical_json

    return base64.b64encode(canonical_json(statement)).decode()


_SWAPPED = {**SIGNED, "payload": _payload({**_vsa(), "subject": [{"name": "x", "digest": {
    "sha256": "ef" * 32}}]})}  # fmt: skip
_NOT_VSA = {**_vsa(), "predicateType": "https://opentine.dev/attestation/run/v1"}

VSA = Family(
    "61-vsa.json",
    "8.14",
    "vsa",
    (
        _case("vsa.valid", "admitted under the pinned server key", _value()),
        _case(
            "vsa.valid.policy-and-levels",
            "the required policy URI and every required level are present",
            _value(levels=("OPENTINE_ADMITTED", "SIGNED"), policy=POLICY["uri"]),
        ),  # fmt: skip
        _case(
            "vsa.other-key",
            "signed by a key that is not pinned",
            _value(sign_statement(_vsa(), OTHER)),
        ),  # fmt: skip
        _case(
            "vsa.tampered-payload", "the payload swapped under the old signature", _value(_SWAPPED)
        ),  # fmt: skip
        _case(
            "vsa.wrong-subject",
            "a valid VSA for another object",
            _value(subject="run:" + "ef" * 32),
        ),  # fmt: skip
        _case(
            "vsa.failed",
            "verificationResult is FAILED",
            _value(sign_statement(_vsa(verificationResult="FAILED"), KEY)),
        ),  # fmt: skip
        _case(
            "vsa.wrong-policy",
            "admitted under another policy",
            _value(policy="opentine:trust-policy/dev"),
        ),  # fmt: skip
        _case(
            "vsa.missing-level",
            "a required level the server did not verify",
            _value(levels=("SLSA_BUILD_LEVEL_3",)),
        ),  # fmt: skip
        _case(
            "vsa.not-a-vsa",
            "a correctly signed statement of another predicate type",
            _value(sign_statement(_NOT_VSA, KEY)),
        ),  # fmt: skip
        _case("vsa.not-dsse", "a bare statement, not an envelope", _value(_vsa())),
        _case(
            "vsa.payload-not-base64", "payload is not base64", _value({**SIGNED, "payload": "%%%"})
        ),  # fmt: skip
        _case(
            "vsa.no-signatures",
            "an envelope with no signatures",
            _value({**SIGNED, "signatures": []}),
        ),  # fmt: skip
    ),
)

FAMILIES = (VSA,)
