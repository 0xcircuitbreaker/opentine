"""SPEC 4.6.1 and 1.3.1 (0.41): post-quantum ``tine-sig/3`` blocks and the hash tag.

ML-DSA signing is hedged (randomized), so the signed documents are committed
fixtures -- golden_v2.tine written as v4 and signed once -- not re-signed on
every generation. ``pq_hybrid_v4.tine`` carries a classical Ed25519 block then
an ``ed25519+ml-dsa-65`` block; ``pq_mldsa_v4.tine`` one ``ml-dsa-65`` block.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.conformance.cases import REJECT, VERDICT, Case, Family, V

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HYBRID = json.loads((_FIXTURES / "pq_hybrid_v4.tine").read_text(encoding="utf-8"))
MLDSA = json.loads((_FIXTURES / "pq_mldsa_v4.tine").read_text(encoding="utf-8"))
CLASSICAL, COMPOSITE = HYBRID["signatures"]
PURE = MLDSA["signatures"][0]
PQ = ("ml-dsa-65",)
_V4 = {"family": "artifact-v4"}


def _only(document: dict, block: dict) -> dict:
    return {**document, "signatures": [block]}


def _flip(hex_text: str, index: int) -> str:
    return hex_text[:index] + ("1" if hex_text[index] == "0" else "0") + hex_text[index + 1 :]


VALUE, PUBLIC = COMPOSITE["value"], COMPOSITE["public_key"]
ED_RELABELLED = {**COMPOSITE, "alg": "ed25519", "value": VALUE[:128], "public_key": PUBLIC[:64]}
PQ_RELABELLED = {**COMPOSITE, "alg": "ml-dsa-65", "value": VALUE[128:], "public_key": PUBLIC[64:]}
ED_BROKEN = {**COMPOSITE, "value": _flip(VALUE, 0)}
PQ_BROKEN = {**COMPOSITE, "value": _flip(VALUE, len(VALUE) - 1)}


def _verdict(cid, intent, document, args, requires=PQ, **extra) -> Case:
    return Case(
        id=cid,
        section="4.6.1",
        checklist=(8,),
        op="sig.verify",
        profile="verifier",
        expect=VERDICT,
        intent=intent,
        input=V(document),
        args={**_V4, **args},
        requires=requires,
        **extra,
    )


SIG_PQ = Family(
    "55-sig-pq.json",
    "4.6.1",
    "sig-pq",
    (
        _verdict(
            "pq.verdict.verified-composite",
            "ed25519+ml-dsa-65 under the trusted composite key: both halves verify",
            _only(HYBRID, COMPOSITE),
            {"public_key": PUBLIC},
        ),
        _verdict(
            "pq.verdict.tofu-composite",
            "the embedded composite key alone is verified-tofu, never verified",
            _only(HYBRID, COMPOSITE),
            {"trust_embedded": True},
        ),
        _verdict(
            "pq.verdict.no-key-composite",
            "a composite block without a caller key is no-key",
            _only(HYBRID, COMPOSITE),
            {},
        ),
        _verdict(
            "pq.verdict.classical-block-of-a-hybrid",
            "the classical Ed25519 block a hybrid writer puts first verifies on its own: "
            "the path a 0.34 verifier takes",
            HYBRID,
            {"public_key": CLASSICAL["public_key"]},
            requires=("ed25519",),
        ),
        _verdict(
            "pq.verdict.mismatch-ed25519-half-relabelled",
            "the Ed25519 half of a composite, relabelled alg=ed25519, signed a header naming "
            "the composite: stripping the ML-DSA half fails",
            _only(HYBRID, ED_RELABELLED),
            {"public_key": PUBLIC[:64]},
            requires=("ed25519",),
            twin="pq.verdict.verified-composite",
            must_differ=True,
        ),
        _verdict(
            "pq.verdict.mismatch-ml-dsa-half-relabelled",
            "the ML-DSA half of a composite, relabelled alg=ml-dsa-65: stripping the Ed25519 "
            "half fails (alg is signed, and the half was signed under the composite context)",
            _only(HYBRID, PQ_RELABELLED),
            {"public_key": PUBLIC[64:]},
            twin="pq.verdict.verified-composite",
            must_differ=True,
        ),
        _verdict(
            "pq.verdict.mismatch-ed25519-half-broken",
            "one flipped bit in the Ed25519 half fails the whole composite",
            _only(HYBRID, ED_BROKEN),
            {"public_key": PUBLIC},
            twin="pq.verdict.verified-composite",
            must_differ=True,
        ),
        _verdict(
            "pq.verdict.mismatch-ml-dsa-half-broken",
            "one flipped bit in the ML-DSA half fails the whole composite",
            _only(HYBRID, PQ_BROKEN),
            {"public_key": PUBLIC},
            twin="pq.verdict.verified-composite",
            must_differ=True,
        ),
        _verdict(
            "pq.verdict.verified-ml-dsa-65",
            "a pure ml-dsa-65 block (FIPS 204, empty context) under its trusted key",
            MLDSA,
            {"public_key": PURE["public_key"]},
        ),
        _verdict(
            "pq.verdict.mismatch-ml-dsa-65-edited-header",
            "the header is signed: a changed signer fails",
            _only(MLDSA, {**PURE, "signer": "someone-else"}),
            {"public_key": PURE["public_key"]},
            twin="pq.verdict.verified-ml-dsa-65",
            must_differ=True,
        ),
        _verdict(
            "pq.verdict.mismatch-wrong-key-length",
            "an Ed25519 key never verifies an ml-dsa-65 block",
            MLDSA,
            {"public_key": CLASSICAL["public_key"]},
        ),
        Case(
            id="oid.parse.reserved-hash-tag",
            section="1.3.1",
            checklist=(3,),
            op="oid.parse",
            profile="reader",
            expect=REJECT,
            intent="the middle field of an oid is a reserved hash-algorithm tag; a tag the "
            "reader does not implement is refused by name, never treated as sha256",
            input=V("blob:sha3-256:" + "1" * 64),
            reason="oid.hash-unsupported",
            repair_temptation="hash with sha256 anyway, or strip the tag",
        ),
        Case(
            id="oid.parse.unknown-hash-tag",
            section="1.3.1",
            checklist=(3,),
            op="oid.parse",
            profile="reader",
            expect=REJECT,
            intent="an unknown tag is refused the same way as a reserved one",
            input=V("run:blake2b:" + "1" * 64),
            reason="oid.hash-unsupported",
        ),
    ),
)

FAMILIES = (SIG_PQ,)
