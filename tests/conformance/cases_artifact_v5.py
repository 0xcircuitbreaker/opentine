"""SPEC Part 10: ``.tine`` v5, text blobs carried as JSON strings.

The documents are the signed golden_v2 run of ``cases_sig_v4`` re-spelled as
v5 (``_tine_v5.to_v5``). The ``tine-sig/3`` blocks are the v4 blocks verbatim:
v5 changes no oid, no root and no signed byte. Each verdict runs under the
``artifact-v5`` family, so a consumer without a v5 reader reports it as
unsupported rather than as a v4 failure.
"""

from __future__ import annotations

import base64

from opentine._tine_v5 import to_v5
from tests.conformance.cases import ACCEPT, VERDICT, B, Case, Family, V
from tests.conformance.cases_sig_v4 import ED_PUBLIC, SIGNED_ED, SIGNED_HMAC, V4_DOC

VERIFIER = "verifier"
V5_DOC = to_v5(V4_DOC)
SIGNED_V5 = to_v5(SIGNED_HMAC)
SIGNED_V5_ED = to_v5(SIGNED_ED)
_V5 = {"family": "artifact-v5"}


def _texts(document: dict) -> list[str]:
    return sorted(o for o, e in document["objects"].items() if e["encoding"] == "text")


def _with(document: dict, oid: str, entry: dict) -> dict:
    return {**document, "objects": {**document["objects"], oid: entry}}


_TEXT = _texts(SIGNED_V5)[0]
_ENTRY = SIGNED_V5["objects"][_TEXT]
_EVENT = next(o for o in SIGNED_V5["objects"] if o.startswith("event:"))
EDITED_TEXT = _with(SIGNED_V5, _TEXT, {**_ENTRY, "text": _ENTRY["text"] + " "})
AS_BASE64 = _with(
    SIGNED_V5,
    _TEXT,
    {
        "data": base64.b64encode(_ENTRY["text"].encode()).decode(),
        "encoding": "raw",
        "schema": _ENTRY["schema"],
        "type": "blob",
    },
)
TEXT_EVENT = _with(
    SIGNED_V5,
    _TEXT,
    {**_ENTRY, "type": "event"},
)
EXTRA_KEY = _with(SIGNED_V5, _TEXT, {**_ENTRY, "data": ""})


def _verdict(cid, intent, document, args, section="10.2", **extra) -> Case:
    return Case(
        id=cid,
        section=section,
        checklist=(8,),
        op="sig.verify",
        profile=VERIFIER,
        expect=VERDICT,
        intent=intent,
        input=V(document),
        args=args,
        **extra,
    )


def _oid(cid: str, intent: str, body: bytes) -> Case:
    return Case(
        id=cid,
        section="10.3",
        checklist=(3,),
        op="oid.derive",
        profile="reader",
        expect=ACCEPT,
        intent=intent,
        input=B(body),
        args={"header": {"type": "blob", "schema": 1}},
    )


ARTIFACT_V5 = Family(
    "54-artifact-v5.json",
    "10",
    "artifact-v5",
    (
        _verdict(
            "v5.verdict.verified-hmac",
            "the v4 tine-sig/3 block verifies unchanged over the v5 spelling: text blobs "
            "rebuild the v4 stored bytes, so the root is the same",
            SIGNED_V5,
            {**_V5, "key": "hmac_a"},
            section="10.4",
        ),
        _verdict(
            "v5.verdict.verified-ed25519",
            "an Ed25519 tine-sig/3 block carries over to v5 as well",
            SIGNED_V5_ED,
            {**_V5, "public_key": ED_PUBLIC},
            section="10.4",
        ),
        _verdict(
            "v5.verdict.unsigned",
            "an unsigned v5 document is unsigned, as in v4",
            V5_DOC,
            {**_V5, "key": "hmac_a"},
            section="10.4",
        ),
        _verdict(
            "v5.verdict.mismatch-edited-text",
            "one added space in a text blob changes its UTF-8 bytes, so its oid no longer "
            "re-derives: mismatch under an intact signature",
            EDITED_TEXT,
            {**_V5, "key": "hmac_a"},
            section="10.5",
            twin="v5.verdict.verified-hmac",
            must_differ=True,
        ),
        _verdict(
            "v5.verdict.mismatch-text-as-base64",
            "UTF-8 text spelled as base64 is a second spelling of the same blob: refused, "
            "even though the bytes and the oid are right",
            AS_BASE64,
            {**_V5, "key": "hmac_a"},
            twin="v5.verdict.verified-hmac",
            must_differ=True,
        ),
        _verdict(
            "v5.verdict.mismatch-text-event",
            "only blobs have a text spelling: a text envelope typed event is refused",
            TEXT_EVENT,
            {**_V5, "key": "hmac_a"},
        ),
        _verdict(
            "v5.verdict.mismatch-extra-key",
            "a text envelope is exactly encoding, schema, text and type",
            EXTRA_KEY,
            {**_V5, "key": "hmac_a"},
        ),
        _oid(
            "v5.oid.text-blob",
            "a text blob's stored body is UTF-8(text) under the raw header: CR, LF, NUL, "
            "a BOM and a non-BMP scalar survive, nothing is normalized",
            "﻿line\r\nnul\x00   \U0001f600 é".encode(),
        ),
        _oid(
            "v5.oid.binary-blob",
            "bytes that are not UTF-8 (an encoded surrogate) keep the base64 spelling and "
            "the same oid rule",
            b"\xed\xa0\x80\xff",
        ),
    ),
)

FAMILIES = (ARTIFACT_V5,)
