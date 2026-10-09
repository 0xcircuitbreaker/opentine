"""Shared *inputs* for the authored cases.

These helpers construct the bytes a case feeds an op. They use the reference
canonicalizer to do it, because an input built by a second, hand-rolled encoder
would be testing that encoder. No *expected answer* is produced here: every
``output`` in a vector comes from an op call in ``adapter``/``adapter_repo``,
and the generator refuses to emit if the answer disagrees with the disposition
the case declared.
"""

from __future__ import annotations

import base64
import hashlib
import zlib
from typing import Any

from opentine.kernel import ObjectEnvelope, canonical_json
from opentine.repository.pack import MAGIC
from tests.conformance.frames import stable_frame

#: A fixed run oid used wherever a case needs a syntactically valid target.
RUN_ID = "run:sha256:" + "11" * 32
#: A second, different one, for "not the same target" cases.
OTHER_RUN_ID = "run:sha256:" + "22" * 32
#: A syntactically valid oid of each type that names nothing.
ABSENT = {
    kind: f"{kind}:sha256:" + digit * 64
    for kind, digit in (
        ("blob", "3"),
        ("event", "4"),
        ("run", "5"),
        ("attestation", "6"),
        ("annotation", "7"),
    )
}


def raw_blob(body: bytes) -> bytes:
    """The stored envelope bytes of a ``blob`` object."""
    return ObjectEnvelope("blob", 1, body, "raw").encode()


def json_object(object_type: str, payload: Any, schema: int = 1) -> bytes:
    """The stored envelope bytes of a JSON-encoded object."""
    return ObjectEnvelope.create(object_type, payload, schema).encode()


def oid_of(stored: bytes) -> str:
    return ObjectEnvelope.decode(stored).oid


def header_bytes(object_type: str, schema: int, encoding: str) -> bytes:
    return canonical_json({"encoding": encoding, "schema": schema, "type": object_type})


def envelope_bytes(object_type: str, schema: int, encoding: str, body: bytes) -> bytes:
    return header_bytes(object_type, schema, encoding) + b"\n" + body


def pack_frame(objects: list[bytes], shallow: list[str], *, version: Any = 1) -> bytes:
    """A TINEPACK3 frame over already-stored envelope bytes, in the given order."""
    entries = [
        {"data": base64.b64encode(raw).decode("ascii"), "id": oid_of(raw)} for raw in objects
    ]
    body = canonical_json({"objects": entries, "shallow": shallow, "version": version})
    return stable_frame(MAGIC + hashlib.sha256(body).digest() + zlib.compress(body, level=9))


def pack_frame_from_body(body: bytes, *, digest: bytes | None = None) -> bytes:
    """A frame over arbitrary manifest bytes, for the malformed-manifest cases."""
    return stable_frame(
        MAGIC + (digest or hashlib.sha256(body).digest()) + zlib.compress(body, level=9)
    )


# --- the objects every family reuses ---------------------------------------- #

HELLO_BODY = b"hello\n"
HELLO_BLOB = raw_blob(HELLO_BODY)
HELLO_OID = oid_of(HELLO_BLOB)

CESU8_BLOB = raw_blob(b"\xed\xa0\x80")

ROOT_EVENT = json_object("event", {"cost": 0, "kind": "model", "parent_ids": []})
ROOT_EVENT_OID = oid_of(ROOT_EVENT)

CHILD_EVENT = json_object("event", {"cost": 0, "kind": "tool", "parent_ids": [ROOT_EVENT_OID]})
CHILD_EVENT_OID = oid_of(CHILD_EVENT)

LINKED_EVENT = json_object(
    "event",
    {
        "cost": 0,
        "input_blob": HELLO_OID,
        "kind": "model",
        "output_blob": HELLO_OID,
        "parent_ids": [],
    },
)
LINKED_EVENT_OID = oid_of(LINKED_EVENT)

RUN_PAYLOAD = {
    "events": [ROOT_EVENT_OID, CHILD_EVENT_OID],
    "manifests": {"transcript": HELLO_OID},
    "roots": [ROOT_EVENT_OID],
    "status": "completed",
    "tips": [CHILD_EVENT_OID],
}
RUN_OBJECT = json_object("run", RUN_PAYLOAD)
RUN_OBJECT_OID = oid_of(RUN_OBJECT)

ATTESTATION_PAYLOAD = {
    "claim": {"result": "pass"},
    "evidence_ids": [],
    "signer": "release-bot",
    "target_id": RUN_ID,
}
UNSIGNED_ATTESTATION = {**ATTESTATION_PAYLOAD, "signature": None}
UNSIGNED_ATTESTATION_OBJECT = json_object("attestation", UNSIGNED_ATTESTATION)

ANNOTATION_V1_PAYLOAD = {
    "compatibility": "run-metadata-v1",
    "target_id": RUN_OBJECT_OID,
    "value": {"metadata": {}, "tags": ["a"]},
}
ANNOTATION_V1 = json_object("annotation", ANNOTATION_V1_PAYLOAD)
ANNOTATION_V1_OID = oid_of(ANNOTATION_V1)
ANNOTATION_V2_PAYLOAD = {
    "compatibility": "run-metadata-v1",
    "previous_id": ANNOTATION_V1_OID,
    "target_id": RUN_OBJECT_OID,
    "value": {"metadata": {}, "tags": ["a", "b"]},
}
ANNOTATION_V2 = json_object("annotation", ANNOTATION_V2_PAYLOAD)

CONFIG_BYTES = (
    canonical_json({"format": 3, "object_hash": "sha256", "repository": "opentine", "version": 1})
    + b"\n"
)

SIG_HEADER = {
    "alg": "hmac-sha256",
    "key_id": "demo-key",
    "scheme": "tine-attest/1",
    "signed_at": "2026-09-05T00:00:00Z",
    "signer": "release-bot",
}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def nested(depth: int, opener: str = "[", closer: str = "]") -> Any:
    """A tagged value nested ``depth`` containers deep, innermost ``0``."""
    node: Any = 0
    for _ in range(depth):
        node = [node] if opener == "[" else {"n": node}
    return node
