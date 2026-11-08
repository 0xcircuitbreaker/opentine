"""SPEC 8.13 (0.45.1): signed webhook payloads, ``tine-webhook/1``.

Every case is a verdict: ``ok`` and a ``class`` (valid, malformed, stale,
unknown-key, bad-signature), never a raise. The key is a fixed Ed25519 seed and
every timestamp is fixed, so regeneration is byte-identical.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _webhook_sig
from tests.conformance.cases import VERDICT, Case, Family, V

T = 1_762_600_000
KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"conformance webhook").digest())
OTHER = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"another webhook key").digest())
RAW = KEY.public_key().public_bytes_raw()
KID = _webhook_sig.key_id(RAW)
KEYS = {KID: _webhook_sig.b64url(RAW)}
EVENT = {"data": {"forced": False, "name": "heads/main", "new": "run:" + "ab" * 32, "old": None},
         "format": "tine-event/1", "id": "0a1b2c3d-7", "kind": "ref.updated",
         "tenant": "acme", "time": "2025-11-08T11:06:40Z"}  # fmt: skip
PAYLOAD = {"delivery": "6f1c1c5e-0d2a-4a59-9c41-3f1f4f0e2b11", "event": EVENT,
           "format": "tine-webhook/1", "webhook": "wh_00112233aabbccdd"}  # fmt: skip
BODY = _webhook_sig.canonical_body(PAYLOAD)
_b64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731


def _value(body: bytes = BODY, header: str | None = None, now: int = T, **extra) -> dict:
    header = header if header is not None else _webhook_sig.sign(KEY, body, T)
    return {"body_b64": _b64(body), "header": header, "keys": KEYS, "now": now,
            "window": 300, **extra}  # fmt: skip


def _case(cid: str, intent: str, value: dict) -> Case:
    return Case(id=cid, section="8.13", checklist=(8,), op="webhook.verify", profile="verifier",
                expect=VERDICT, intent=intent, input=V(value), requires=("ed25519",))  # fmt: skip


_SIGNED = _webhook_sig.sign(KEY, BODY, T)
_OTHER_T = _webhook_sig.sign(KEY, BODY, T - 60)
_FORGED = _SIGNED.split(",sig=")[0] + ",sig=" + _webhook_sig.sign(OTHER, BODY, T).split("sig=")[1]
_TAMPERED = BODY.replace(b"heads/main", b"heads/mair")
_NOT_HOOK = _webhook_sig.canonical_body({**PAYLOAD, "format": "tine-event/1"})

WEBHOOK = Family(
    "59-webhook.json",
    "8.13",
    "webhook",
    (
        _case("webhook.valid", "a fresh delivery signed by the pinned key", _value()),
        _case(
            "webhook.valid.window-edge",
            "exactly 300 s old is still inside the window",
            _value(now=T + 300),
        ),  # fmt: skip
        _case("webhook.stale", "301 s old is outside the replay window", _value(now=T + 301)),
        _case(
            "webhook.future", "301 s in the future is outside the window too", _value(now=T - 301)
        ),  # fmt: skip
        _case(
            "webhook.unknown-key",
            "a key id the receiver never pinned",
            _value(keys={"ed25519:0000000000000000": KEYS[KID]}),
        ),  # fmt: skip
        _case("webhook.tampered-body", "one byte of the body changed", _value(_TAMPERED, _SIGNED)),
        _case(
            "webhook.other-key",
            "signed by another key under the pinned key id",
            _value(header=_FORGED),
        ),  # fmt: skip
        _case(
            "webhook.moved-timestamp",
            "a signature for t-60 presented with t",
            _value(header=_SIGNED.split(",kid=")[0] + "," + _OTHER_T.split(",", 1)[1]),
        ),
        _case(
            "webhook.malformed-header",
            "a header without its signature field",
            _value(header=_SIGNED.split(",sig=")[0]),
        ),  # fmt: skip
        _case(
            "webhook.not-a-webhook", "a correctly signed body of another format", _value(_NOT_HOOK)
        ),  # fmt: skip
    ),
)

FAMILIES = (WEBHOOK,)
