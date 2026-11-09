"""SPEC 4.11 ``opentine-fleet/1`` and its signed ``opentine-fleet-record/1`` (vectors 0.48).

The 0.48 freeze audit found the fleet record, a 0.43 kind, with no vectors.
The documents are signed here with the published seeds in ``keys`` and a fixed
``signed_at``, so the bytes are stable. Only ``adapter_agent`` answers.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _fleet_record
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
SIGNED_AT = "2026-01-01T00:00:00Z"
RUN_ID = "run-fleet-0001"
RUN_DIGEST = "sha256:" + "a1" * 32
RECORD = {"scheme": "opentine-fleet/1", "fleet_id": "fleet-7", "member": "w1",
          "role": "worker", "parent": "lead"}  # fmt: skip


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _public(name: str) -> str:
    return _key(name).public_key().public_bytes_raw().hex()


DOCUMENT = _fleet_record.sign(RECORD, RUN_ID, RUN_DIGEST, _key("ed25519_seed"),
                              signed_at=SIGNED_AT)  # fmt: skip


def _edit(**changes) -> dict:
    document = copy.deepcopy(DOCUMENT)
    for key, value in changes.items():
        if key.startswith("record_"):
            document["record"][key.removeprefix("record_")] = value
        else:
            document[key] = value
    return document


def _c(name, expect, intent, document, reason=None, *, key: str | None = None) -> Case:
    value = {"document": document, "public_key": key}
    return Case(id=f"fleet.{name}", section="4.11", checklist=(8,), op="fleet.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


HMAC_BLOCK = {**DOCUMENT["signature"], "alg": "hmac-sha256"}
HMAC_BLOCK.pop("public_key", None)

FLEET = Family(
    "78-fleet.json",
    "4.11",
    "fleet",
    (
        _c("tofu", ACCEPT, "a signed record verifies under its embedded key, as TOFU", DOCUMENT),
        _c("pinned", ACCEPT, "a signed record verifies under the supplied key", DOCUMENT,
           key=_public("ed25519_seed")),
        _c("wrong-key", REJECT, "a record signed by another key than the supplied one",
           DOCUMENT, "fleet.wrong-key", key=_public("ed25519_seed_b")),
        _c("moved-run", REJECT, "a signed record copied onto another run fails its signature",
           _edit(run_id="run-fleet-0002"), "fleet.bad-signature"),
        _c("edited-role", REJECT, "a role changed after signing fails its signature",
           _edit(record_role="lead"), "fleet.bad-signature"),
        _c("hmac", REJECT, "a fleet record is Ed25519 only", _edit(signature=HMAC_BLOCK),
           "fleet.bad-signature"),
        _c("extra-field", REJECT, "a record field the scheme does not define",
           _edit(record_host="x"), "fleet.malformed"),
        _c("bad-fleet-id", REJECT, "fleet_id is 1..128 of [A-Za-z0-9_.-]",
           _edit(record_fleet_id="fleet 7"), "fleet.malformed"),
        _c("not-normalised", REJECT, "a name a normaliser would change is refused, not fixed",
           _edit(record_member=" w1"), "fleet.malformed"),
        _c("wrong-scheme", REJECT, "only opentine-fleet-record/1 documents",
           _edit(scheme="opentine-fleet-record/2"), "fleet.malformed"),
    ),
)  # fmt: skip

FAMILIES = (FLEET,)
