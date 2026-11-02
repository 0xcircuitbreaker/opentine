"""SPEC 9.6-9.7: ``tine-sig/3`` over a v4 artifact and ``tine-attest/2``.

The signed document is golden_v2.tine written as format v4 by the reference
writer (an upgrade on write, SPEC 9.1). Its bytes are fixed by the fixture, so
every message and verdict below is reproducible. ``UPGRADED_DOC`` is the same
run carrying a fixed ``upgraded_from`` record (SPEC 9.9) in its payload.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine._artifact_v4 import write_v4
from opentine._signing_v4 import append_signature, sign_attestation_v2
from opentine.core import Run
from opentine.kernel import canonical_json
from tests.conformance.builders import ATTESTATION_PAYLOAD
from tests.conformance.cases import ACCEPT, VERDICT, B, Case, Family, V
from tests.conformance.keys import ED25519_SEED, HMAC_A

VERIFIER = "verifier"
SIG3, ATTEST2 = "tine-sig/3", "tine-attest/2"
AT = "2026-11-01T00:00:00Z"
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "golden_v2.tine"

V4_DOC = json.loads(write_v4(Run.load(_FIXTURE)))
UPGRADE = {
    "digest": "075f50686a3e758fe665307ddebca51a1cd63d51de44420661a4867c5460983c",
    "digest_algorithm": "sha256",
    "format": "tine/2",
    "integrity_digest": None,
    "signature": {
        "key_fingerprint": None,
        "scheme": None,
        "state": "unsigned",
        "trust_basis": "none: the source carries no signature",
    },
    "tool": "opentine/0.26.0",
    "upgraded_at": AT,
}


def _upgraded() -> dict:
    run = Run.load(_FIXTURE)
    run._v4_upgraded_from = UPGRADE
    return json.loads(write_v4(run))


UPGRADED_DOC = _upgraded()
SIGNED_UPGRADED = json.loads(
    append_signature(UPGRADED_DOC, HMAC_A, key_id="demo-key", signer="release-bot", signed_at=AT)
)
SIGNED_HMAC = json.loads(
    append_signature(V4_DOC, HMAC_A, key_id="demo-key", signer="release-bot", signed_at=AT)
)
SIGNED_ED = json.loads(
    append_signature(V4_DOC, ED25519_SEED, algorithm="ed25519", key_id="ed-demo", signed_at=AT)
)
ED_PUBLIC = SIGNED_ED["signatures"][0]["public_key"]
HEADER_HMAC = {
    "alg": "hmac-sha256",
    "key_id": "demo-key",
    "scheme": SIG3,
    "signed_at": AT,
    "signer": "release-bot",
}
HEADER_ED = {"alg": "ed25519", "key_id": None, "scheme": ATTEST2, "signed_at": AT, "signer": None}
ATTEST_ED = {
    **ATTESTATION_PAYLOAD,
    "signature": sign_attestation_v2(ATTESTATION_PAYLOAD, ED25519_SEED, signed_at=AT),
}

OLD_SCHEME_BLOCK = {**SIGNED_HMAC["signatures"][0], "scheme": "tine-sig/2"}
HMAC_UNDER_ATTEST2 = {
    **{k: v for k, v in ATTEST_ED["signature"].items() if k != "public_key"},
    "alg": "hmac-sha256",
    "value": "0" * 64,
}


def _first_event(document: dict) -> str:
    return next(oid for oid in document["objects"] if oid.startswith("event:"))


def _edited_provenance(document: dict) -> dict:
    root = document["root"]
    entry = document["objects"][root]
    upgraded = {**entry["body"]["upgraded_from"], "digest": "0" * 64}
    body = {**entry["body"], "upgraded_from": upgraded}
    return {**document, "objects": {**document["objects"], root: {**entry, "body": body}}}


def _edited_event(document: dict) -> dict:
    oid = _first_event(document)
    entry = document["objects"][oid]
    body = {**entry["body"], "cost": 12345}
    return {**document, "objects": {**document["objects"], oid: {**entry, "body": body}}}


def _msg(cid, section, intent, document, header, scheme, **args) -> Case:
    return Case(
        id=cid,
        section=section,
        checklist=(8,),
        op="sig.message",
        profile=VERIFIER,
        expect=ACCEPT,
        intent=intent,
        input=V({"document": document, "header": header}),
        args={"scheme": scheme, **args},
    )


def _verdict(cid, section, intent, document, args, **extra) -> Case:
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


_V4 = {"family": "artifact-v4"}
SIG_V4 = Family(
    "53-sig-v4.json",
    "9.6",
    "sig-v4",
    (
        _msg(
            "sig3.message.hmac",
            "9.6",
            "the tine-sig/3 message: opentine.signature.v3: then JCS of format_version, kind, "
            "root, annotations_head and the five-key header",
            V4_DOC,
            HEADER_HMAC,
            SIG3,
            key="hmac_a",
        ),
        _msg(
            "sig3.message.no-annotations",
            "9.6",
            "with no annotations the head is signed as null, never omitted",
            {**V4_DOC, "annotations": []},
            HEADER_HMAC,
            SIG3,
        ),
        _verdict(
            "sig3.verdict.verified-hmac",
            "9.6",
            "a supplied HMAC key agrees with the root and annotation head",
            SIGNED_HMAC,
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.mismatch-wrong-key",
            "9.6",
            "a different key disagrees: the tamper verdict",
            SIGNED_HMAC,
            {**_V4, "key": "hmac_b"},
            twin="sig3.verdict.verified-hmac",
            must_differ=True,
        ),
        _verdict(
            "sig3.verdict.no-key",
            "9.6",
            "a block without a caller key is no-key, never verified",
            SIGNED_HMAC,
            _V4,
        ),
        _verdict(
            "sig3.verdict.unsigned",
            "9.6",
            "an empty signatures list is unsigned",
            V4_DOC,
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.mismatch-edited-envelope",
            "9.6",
            "an edited event no longer re-derives its oid, so the signed root does not cover "
            "the content: mismatch, as an edited v2 body is",
            {**_edited_event(SIGNED_HMAC)},
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.mismatch-stripped-annotations",
            "9.6",
            "dropping the annotation chain changes annotations_head, which is signed",
            {**SIGNED_HMAC, "annotations": []},
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.error-old-scheme",
            "9.6",
            "a v4 artifact only carries tine-sig/3 blocks; any other scheme is an error",
            {**SIGNED_HMAC, "signatures": [OLD_SCHEME_BLOCK]},
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.verified-ed25519",
            "9.6",
            "Ed25519 under a supplied public key",
            SIGNED_ED,
            {**_V4, "public_key": ED_PUBLIC},
        ),
        _verdict(
            "sig3.verdict.tofu-ed25519",
            "9.6",
            "the embedded key alone is verified-tofu: consistency, not authorship",
            SIGNED_ED,
            {**_V4, "trust_embedded": True},
        ),
        _verdict(
            "sig3.verdict.verified-upgraded",
            "9.9",
            "upgraded_from lives in the run payload, so the signed root covers it",
            SIGNED_UPGRADED,
            {**_V4, "key": "hmac_a"},
        ),
        _verdict(
            "sig3.verdict.mismatch-edited-provenance",
            "9.9",
            "an edited upgraded_from no longer re-derives the root: mismatch, never verified",
            _edited_provenance(SIGNED_UPGRADED),
            {**_V4, "key": "hmac_a"},
            twin="sig3.verdict.verified-upgraded",
            must_differ=True,
        ),
        Case(
            id="sig3.envelope.root-recompute",
            section="9.3",
            checklist=(3,),
            op="oid.derive",
            profile="reader",
            expect=ACCEPT,
            intent="a v4 envelope's id is SPEC 1.3 over its JCS body: the run envelope that "
            "carries upgraded_from re-derives the root",
            input=B(canonical_json(UPGRADED_DOC["objects"][UPGRADED_DOC["root"]]["body"])),
            args={"header": {"type": "run", "schema": 1}},
        ),
        _msg(
            "attest2.message.ed25519",
            "9.7",
            "the tine-attest/2 message: opentine.attestation.v2: then JCS of the payload "
            "without signature, beside the header",
            ATTESTATION_PAYLOAD,
            HEADER_ED,
            ATTEST2,
        ),
        _verdict(
            "attest2.verdict.verified",
            "9.7",
            "an Ed25519 tine-attest/2 block under the supplied public key",
            ATTEST_ED,
            {"family": "attestation", "public_key": ED_PUBLIC},
        ),
        _verdict(
            "attest2.verdict.mismatch-edited-claim",
            "9.7",
            "the claim is inside the signed payload",
            {**ATTEST_ED, "claim": {"result": "fail"}},
            {"family": "attestation", "public_key": ED_PUBLIC},
            twin="attest2.verdict.verified",
            must_differ=True,
        ),
        _verdict(
            "attest2.verdict.error-hmac",
            "9.7",
            "tine-attest/2 is Ed25519 only: an HMAC block under it is an error, not a check",
            {**ATTEST_ED, "signature": HMAC_UNDER_ATTEST2},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest2.verdict.error-target-not-run",
            "9.7",
            "a tine-attest/2 record must target a run root",
            {**ATTEST_ED, "target_id": "event:sha256:" + "0" * 64},
            {"family": "attestation", "public_key": ED_PUBLIC},
        ),
    ),
)

FAMILIES = (SIG_V4,)
