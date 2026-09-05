"""SPEC Part 4: the three signed views, the shared message, and the verdict."""

from __future__ import annotations

import math

from opentine.attest_signing import sign_attestation
from opentine.signing import sign_artifact
from tests.conformance.builders import (
    ATTESTATION_PAYLOAD,
    RUN_OBJECT,
    RUN_OBJECT_OID,
    SIG_HEADER,
    b64,
)
from tests.conformance.cases import ACCEPT, REJECT, VERDICT, Case, Family, V
from tests.conformance.cases_artifact import BASE
from tests.conformance.keys import ED25519_SEED, HMAC_A, HMAC_FLOOR

VERIFIER, WRITER = "verifier", "writer"

#: The run object an attestation targets, so SPEC 1.5.6 resolves inside the op.
ATTEST_TARGET_B64 = b64(RUN_OBJECT)
ATTEST = "tine-attest/1"
SIG1, SIG2 = "tine-sig/1", "tine-sig/2"

ARTIFACT_HEADER_V2 = {
    "alg": "hmac-sha256",
    "key_id": "demo-key",
    "scheme": SIG2,
    "signed_at": "2026-09-05T00:00:00Z",
    "signer": "release-bot",
}
ARTIFACT_HEADER_V1 = {**ARTIFACT_HEADER_V2, "scheme": SIG1}
BARE_HEADER = {
    "alg": "hmac-sha256",
    "key_id": None,
    "scheme": ATTEST,
    "signed_at": None,
    "signer": "release-bot",
}

ARTIFACT_METADATA = {
    "model_info": "anthropic/claude-sonnet-5",
    "system_prompt": "be careful",
    "user_prompt": "summarize",
    "tags": ["release"],
    "fork_reason": "explored approach A",
    "project": "opentine",
}
ARTIFACT_DOC = {**BASE, "metadata": ARTIFACT_METADATA}


def _c(**kwargs) -> Case:
    return Case(**kwargs)


def _msg(name, expect, intent, document, header, scheme, section="4.2", **extra) -> Case:
    return _c(
        id=f"sig.{name}",
        section=section,
        checklist=(8,),
        op="sig.message",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V({"document": document, "header": header}),
        args={"scheme": scheme, **extra.pop("args", {})},
        **extra,
    )


_ATTEST_VARIANTS = (
    (
        "claim-changed",
        {"claim": {"result": "fail"}},
        "the claim is covered: changing what is asserted changes the message",
    ),
    (
        "target-changed",
        {"target_id": "run:sha256:" + "22" * 32},
        "the target is covered: the same claim about a different run is a different message",
    ),
    (
        "signer-changed",
        {"signer": "someone-else"},
        "the signer is covered, and it is read off the payload rather than accepted separately",
    ),
    (
        "evidence-added",
        {"evidence_ids": ["blob:sha256:" + "aa" * 32]},
        "evidence_ids is covered: what backs the claim is inside the signature",
    ),
    (
        "extra-field-added",
        {"reviewed_by": "qa"},
        "and so is any field a later writer adds, without needing a new scheme",
    ),
)

_HEADER_VARIANTS = (
    (
        "alg-ed25519",
        {"alg": "ed25519"},
        "alg is inside the signed header, so the algorithm cannot be downgraded after the fact",
    ),
    (
        "key-id-absent",
        {"key_id": None},
        "an absent key_id is signed as null, so adding one later changes the message",
    ),
    (
        "signed-at-moved",
        {"signed_at": "2027-01-01T00:00:00Z"},
        "signed_at is covered, so the timestamp cannot be moved after the fact",
    ),
    (
        "scheme-attest-only",
        {"scheme": ATTEST},
        "the scheme string is one of the five header keys, so no message can be lifted between "
        "schemes even over identical content",
    ),
)

SIGNING = Family(
    "42-signing.json",
    "4.2",
    "signing",
    (
        _msg(
            "attest.spec-4-5-worked-vector",
            ACCEPT,
            "SPEC 4.5's own worked vector, message and HMAC value",
            ATTESTATION_PAYLOAD,
            SIG_HEADER,
            ATTEST,
            section="4.5",
            args={"key": "hmac_a"},
        ),
        _msg(
            "attest.domain-prefix",
            ACCEPT,
            "the message begins with the literal bytes opentine.attestation.v1:, which is "
            "what stops an artifact signature ever being lifted into the attestation family",
            ATTESTATION_PAYLOAD,
            SIG_HEADER,
            ATTEST,
            section="4.2",
        ),
        _msg(
            "attest.signature-key-excluded",
            ACCEPT,
            "the signature key itself is outside the view -- it is the value being computed -- "
            "so a payload carrying one produces the same message as one without",
            {**ATTESTATION_PAYLOAD, "signature": {"alg": "hmac-sha256", "value": "0" * 64}},
            SIG_HEADER,
            ATTEST,
            section="4.5",
            must_differ=False,
            twin="sig.attest.domain-prefix",
        ),
        _msg(
            "attest.unsigned-slot-excluded",
            ACCEPT,
            'the same holds for the literal "signature": null 0.3.0-0.8.1 already wrote',
            {**ATTESTATION_PAYLOAD, "signature": None},
            SIG_HEADER,
            ATTEST,
            section="4.5",
            must_differ=False,
            twin="sig.attest.domain-prefix",
        ),
        _msg(
            "attest.bare-header-nulls",
            ACCEPT,
            "the signed header always has all five keys, with null for any not supplied; the "
            "stored block drops the nulls, which is what makes an absent key_id unforgeable",
            ATTESTATION_PAYLOAD,
            BARE_HEADER,
            ATTEST,
            section="4.1",
            must_differ=False,
            twin="sig.attest.header-keys-omitted",
        ),
        _msg(
            "attest.header-keys-omitted",
            ACCEPT,
            "SPEC 4.1's rebuild MUST, from the other side: this header OMITS key_id and "
            "signed_at rather than spelling them null, and the message is byte-identical to "
            "its twin's -- an implementation that canonicalizes the keys it was handed "
            "signs a three-key header and reports mismatch on a legitimately signed block",
            ATTESTATION_PAYLOAD,
            {key: value for key, value in BARE_HEADER.items() if value is not None},
            ATTEST,
            section="4.1",
            must_differ=False,
            twin="sig.attest.bare-header-nulls",
            repair_temptation="canonicalize the keys the block carries instead of the "
            "five-key header the scheme defines",
        ),
        *(
            _msg(
                f"attest.{name}",
                ACCEPT,
                intent,
                {**ATTESTATION_PAYLOAD, **delta},
                SIG_HEADER,
                ATTEST,
                section="4.5",
                must_differ=True,
                twin="sig.attest.domain-prefix",
            )
            for name, delta, intent in _ATTEST_VARIANTS
        ),
        *(
            _msg(
                f"attest.header.{name}",
                ACCEPT,
                intent,
                ATTESTATION_PAYLOAD,
                {**SIG_HEADER, **delta},
                ATTEST,
                section="4.1",
            )
            for name, delta, intent in _HEADER_VARIANTS
        ),
        _msg(
            "attest.hmac-with-floor-key",
            ACCEPT,
            "a 16-byte key is exactly MIN_HMAC_KEY_BYTES and produces a real value",
            ATTESTATION_PAYLOAD,
            SIG_HEADER,
            ATTEST,
            section="4.6",
            args={"key": "hmac_floor"},
        ),
        _msg(
            "attest.hmac-with-second-key",
            ACCEPT,
            "the same message under a different key is a different value -- the whole content "
            "of a mismatch verdict",
            ATTESTATION_PAYLOAD,
            SIG_HEADER,
            ATTEST,
            section="4.6",
            args={"key": "hmac_b"},
            must_differ=True,
            twin="sig.attest.spec-4-5-worked-vector",
        ),
        _msg(
            "v2.artifact-base",
            ACCEPT,
            "tine-sig/2 covers the body, the five-key header, and every metadata key but integrity",
            ARTIFACT_DOC,
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
        ),
        _msg(
            "v2.tags-are-covered",
            ACCEPT,
            "metadata.tags is inside a v2 signature, which it never was under v1",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "tags": ["release", "extra"]}},
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
            must_differ=True,
            twin="sig.v1.tags-are-not-covered",
        ),
        _msg(
            "v2.application-metadata-is-covered",
            ACCEPT,
            "so is any application-added metadata key",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "project": "other"}},
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
            must_differ=True,
            twin="sig.v2.artifact-base",
        ),
        _msg(
            "v2.integrity-is-excluded",
            ACCEPT,
            "integrity is excluded because it holds the block being computed, alongside the "
            "unkeyed digest which is itself taken over body keys this view already covers",
            {
                **ARTIFACT_DOC,
                "metadata": {
                    **ARTIFACT_METADATA,
                    "integrity": {"algorithm": "sha256", "digest": "0" * 64},
                },
            },
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
            must_differ=False,
            twin="sig.v2.artifact-base",
        ),
        _msg(
            "v2.body-is-covered",
            ACCEPT,
            "every top-level key except metadata is the body, and a body edit changes it",
            {**ARTIFACT_DOC, "run_id": "other"},
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
        ),
        _msg(
            "v2.hmac-value",
            ACCEPT,
            "the keyed half over the same message",
            ARTIFACT_DOC,
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.6",
            args={"key": "hmac_a"},
        ),
        _msg(
            "v1.artifact-base",
            ACCEPT,
            "tine-sig/1 covers the body, the header, and only the frozen metadata allowlist",
            ARTIFACT_DOC,
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
        ),
        _msg(
            "v1.tags-are-not-covered",
            ACCEPT,
            "metadata.tags is absent from the frozen allowlist, which is why re-tagging never "
            "broke a v1 signature -- the message is unchanged",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "tags": ["release", "extra"]}},
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
            must_differ=False,
            twin="sig.v1.artifact-base",
        ),
        _msg(
            "v1.fork-reason-is-not-covered",
            ACCEPT,
            "fork_reason is absent for the same reason: 0.3.0 wrote it but did not sign it, "
            "and adding it now would retroactively falsify genuine older signatures",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "fork_reason": "something else"}},
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
            must_differ=False,
            twin="sig.v1.artifact-base",
        ),
        _msg(
            "v1.application-metadata-is-not-covered",
            ACCEPT,
            "and neither is application-added metadata, which v2 does cover",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "project": "other"}},
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
            must_differ=True,
            twin="sig.v2.application-metadata-is-covered",
        ),
        _msg(
            "v1.model-info-is-covered",
            ACCEPT,
            "model_info is on the allowlist, so changing it does change the v1 message",
            {**ARTIFACT_DOC, "metadata": {**ARTIFACT_METADATA, "model_info": "other/model"}},
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
        ),
        _msg(
            "v1.fork-record-is-covered",
            ACCEPT,
            "fork was safe to add to the frozen list in 0.4.0 precisely because 0.3.0 never "
            "wrote metadata.fork, so it changed no existing signature",
            {
                **ARTIFACT_DOC,
                "metadata": {**ARTIFACT_METADATA, "fork": {"source": "a", "point": "b"}},
            },
            ARTIFACT_HEADER_V1,
            SIG1,
            section="4.3",
        ),
        _msg(
            "v1.and-v2-differ-over-the-same-artifact",
            ACCEPT,
            "the two schemes share one domain prefix and are separated by the scheme string "
            "inside the signed header, so their messages already differ",
            ARTIFACT_DOC,
            {**ARTIFACT_HEADER_V1},
            SIG1,
            section="4.2",
            must_differ=True,
            twin="sig.v2.artifact-base",
        ),
        _msg(
            "attest.non-bmp-claim-key",
            ACCEPT,
            "a non-BMP key in a claim is escaped as a surrogate pair by the v2 canonicalizer, "
            "and ordered by code point -- the divergence, inside a signature",
            {**ATTESTATION_PAYLOAD, "claim": {"\U00010000": 1, "": 2}},
            SIG_HEADER,
            ATTEST,
            section="4.5",
        ),
        _c(
            id="sig.attest.sign-covers-the-stored-claim",
            section="4.5",
            checklist=(8, 9),
            op="attest.sign",
            profile=WRITER,
            expect=ACCEPT,
            intent="SPEC 4.5's ordering rule, which sig.message cannot express because it is "
            "handed a document someone has already decided to store: the claim carries a "
            "credential, Repo.put scrubs it, and the signature covers the scrubbed body",
            repair_temptation="sign the caller's claim and store the redacted one, which "
            "signs bytes no reader ever sees and verifies as mismatch everywhere",
            input=V(
                {
                    "claim": {"api_key": "sk-live-0123456789abcdefghij", "result": "pass"},
                    "signer": "release-bot",
                    "target_id": RUN_OBJECT_OID,
                }
            ),
            args={"key": "hmac_a", "objects": [ATTEST_TARGET_B64]},
            must_differ=False,
            twin="sig.attest.sign-over-an-already-scrubbed-claim",
        ),
        _c(
            id="sig.attest.sign-over-an-already-scrubbed-claim",
            section="4.5",
            checklist=(8, 9),
            op="attest.sign",
            profile=WRITER,
            expect=ACCEPT,
            intent="the discriminating half: the same claim with the credential already "
            "scrubbed must produce the identical stored body, oid and signature value -- "
            "which it does only for a writer that redacts before it signs",
            input=V(
                {
                    "claim": {"api_key": "[REDACTED]", "result": "pass"},
                    "signer": "release-bot",
                    "target_id": RUN_OBJECT_OID,
                }
            ),
            args={"key": "hmac_a", "objects": [ATTEST_TARGET_B64]},
            must_differ=False,
            twin="sig.attest.sign-covers-the-stored-claim",
        ),
        _msg(
            "attest.document-not-an-object",
            REJECT,
            "the signed view is a projection of an *object*; a list has no body to project",
            [1, 2, 3],
            SIG_HEADER,
            ATTEST,
            section="4.5",
            reason="sig.payload-not-object",
        ),
        _msg(
            "v2.metadata-not-an-object",
            REJECT,
            "the artifact view refuses a non-object metadata rather than coercing it",
            {**BASE, "metadata": [1, 2]},
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.4",
            reason="sig.payload-not-object",
        ),
        _msg(
            "attest.non-finite-in-claim",
            REJECT,
            "content the v2 canonicalizer refuses has no message, so there is nothing to sign",
            {**ATTESTATION_PAYLOAD, "claim": {"n": math.inf}},
            SIG_HEADER,
            ATTEST,
            section="4.2",
            reason="canon.non-finite",
        ),
        _msg(
            "v2.non-finite-in-body",
            REJECT,
            "the same rule in the artifact family",
            {**ARTIFACT_DOC, "created_at": math.nan},
            ARTIFACT_HEADER_V2,
            SIG2,
            section="4.2",
            reason="canon.non-finite",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 47 -- the verdict vocabulary
# --------------------------------------------------------------------------- #

SIGNED_BLOCK = sign_attestation(
    ATTESTATION_PAYLOAD, HMAC_A, key_id="demo-key", signed_at="2026-09-05T00:00:00Z"
)
SIGNED_ATTESTATION = {**ATTESTATION_PAYLOAD, "signature": SIGNED_BLOCK}
FLOOR_BLOCK = sign_attestation(
    ATTESTATION_PAYLOAD, HMAC_FLOOR, key_id="floor", signed_at="2026-09-05T00:00:00Z"
)
ED_BLOCK = sign_attestation(
    ATTESTATION_PAYLOAD,
    ED25519_SEED,
    algorithm="ed25519",
    key_id="ed-demo",
    signed_at="2026-09-05T00:00:00Z",
)
SIGNED_ARTIFACT = {
    **BASE,
    "metadata": {
        **ARTIFACT_METADATA,
        "integrity": {
            "algorithm": "sha256",
            "digest": "0" * 64,
            "signature": sign_artifact(
                {**BASE, "metadata": ARTIFACT_METADATA},
                HMAC_A,
                key_id="demo-key",
                signer="release-bot",
                signed_at="2026-09-05T00:00:00Z",
            ),
        },
    },
}


def _verdict(name, intent, document, args, **extra) -> Case:
    return _c(
        id=f"verdict.{name}",
        section="4.7",
        checklist=(8,),
        op="sig.verify",
        profile=VERIFIER,
        expect=VERDICT,
        intent=intent,
        input=V(document),
        args=args,
        **extra,
    )


VERDICT_FAMILY = Family(
    "47-verdict.json",
    "4.7",
    "verdict",
    (
        _verdict(
            "attest.verified",
            "a key the caller supplied was applied and agreed: the only ok=true state for HMAC",
            SIGNED_ATTESTATION,
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.verified-with-floor-key",
            "a 16-byte key is exactly MIN_HMAC_KEY_BYTES and must verify",
            {**ATTESTATION_PAYLOAD, "signature": FLOOR_BLOCK},
            {"family": "attestation", "key": "hmac_floor"},
        ),
        _verdict(
            "attest.unsigned-null-slot",
            'the literal "signature": null 0.3.0-0.8.1 wrote verifies as unsigned -- never an '
            "error, never verified",
            {**ATTESTATION_PAYLOAD, "signature": None},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.unsigned-absent-slot",
            "and so does a payload with no signature key at all",
            ATTESTATION_PAYLOAD,
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.no-key",
            "a block is present but the caller supplied no key, so nothing was checked; "
            "ok is false, because 'not checked' is never 'verified'",
            SIGNED_ATTESTATION,
            {"family": "attestation"},
        ),
        _verdict(
            "attest.mismatch-wrong-key",
            "a key was applied and disagreed: the tamper verdict",
            SIGNED_ATTESTATION,
            {"family": "attestation", "key": "hmac_b"},
            must_differ=True,
            twin="verdict.attest.verified",
        ),
        _verdict(
            "attest.mismatch-edited-claim",
            "the claim is inside the signature, so editing it flips the verdict",
            {**SIGNED_ATTESTATION, "claim": {"result": "fail"}},
            {"family": "attestation", "key": "hmac_a"},
            must_differ=True,
            twin="verdict.attest.verified",
        ),
        _verdict(
            "attest.mismatch-edited-target",
            "so is the target run",
            {**SIGNED_ATTESTATION, "target_id": "run:sha256:" + "22" * 32},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.mismatch-key-id-added",
            "an absent header value is signed as null, so adding a key_id afterwards is a "
            "mismatch rather than a silently accepted improvement",
            {
                **ATTESTATION_PAYLOAD,
                "signature": {
                    **{k: v for k, v in SIGNED_BLOCK.items() if k != "key_id"},
                    "key_id": "someone-elses-key",
                },
            },
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.mismatch-signed-at-moved",
            "and so is moving the timestamp",
            {
                **ATTESTATION_PAYLOAD,
                "signature": {**SIGNED_BLOCK, "signed_at": "2027-01-01T00:00:00Z"},
            },
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-unsupported-scheme",
            "a block is verified under the scheme it names, and an unknown scheme is an error",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "scheme": "tine-attest/2"}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-scheme-is-checked-before-alg",
            "the reference's check order is fixed: a block with BOTH a bad scheme and a bad "
            "algorithm reports the scheme, which is why every other vector violates one rule",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "scheme": "nope", "alg": "md5"}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-unknown-algorithm",
            "an algorithm outside {hmac-sha256, ed25519}",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "alg": "md5"}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-value-wrong-length",
            "an HMAC value is exactly 64 hex characters",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "value": "ab" * 16}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-value-not-hex",
            "and it is hex",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "value": "z" * 64}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "attest.error-block-not-an-object",
            "a signature slot holding something that is not an object is an error, not unsigned",
            {**ATTESTATION_PAYLOAD, "signature": "0" * 64},
            {"family": "attestation", "key": "hmac_a"},
            must_differ=True,
            twin="verdict.attest.unsigned-null-slot",
        ),
        _verdict(
            "attest.error-hmac-key-too-short",
            "a key below MIN_HMAC_KEY_BYTES is refused at verify as well as at sign, and the "
            "refusal is a returned error rather than a raised exception",
            SIGNED_ATTESTATION,
            {"family": "attestation", "key": "hmac_short"},
        ),
        _verdict(
            "attest.error-non-string-key-id",
            "an optional header value that is present but not a string is malformed",
            {**ATTESTATION_PAYLOAD, "signature": {**SIGNED_BLOCK, "key_id": 7}},
            {"family": "attestation", "key": "hmac_a"},
        ),
        _verdict(
            "ed25519.verified-tofu",
            "trust on first use: verified against the public key embedded in the block, which "
            "the signature does not cover. It proves the block is internally consistent, not "
            "that the key is anyone's -- and it requires an explicit opt-in",
            {**ATTESTATION_PAYLOAD, "signature": ED_BLOCK},
            {"family": "attestation", "trust_embedded": True},
            requires=("ed25519",),
        ),
        _verdict(
            "artifact.consistent-but-not-authentic",
            "SPEC Part 6 item 7, the other half: this document's integrity digest was "
            "rewritten to match its edited body and verifies -- and its tine-sig/2 signature "
            "does not, because a signature is recomputed from content, not read from the file",
            {**SIGNED_ARTIFACT, "run_id": "tampered"},
            {"family": "artifact", "key": "hmac_a"},
            twin="integrity.verify.body-edited-and-digest-rewritten",
        ),
    ),
)

FAMILIES = (SIGNING, VERDICT_FAMILY)
