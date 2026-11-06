"""Format v4 signatures: ``tine-sig/3`` (artifacts) and ``tine-attest/2``.

Both sign §0.2 (RFC 8785 JCS) bytes, never the v2 canonicalizer, and both reuse
the keyed half, header and fail-closed verdict of ``_signing_verify``.

* ``tine-sig/3`` signs ``opentine.signature.v3:`` + JCS of ``{format_version,
  kind, root, annotations_head, header}``. The root commits to the whole run
  (SPEC 9.1); the annotation head commits to the tags and metadata beside it.
  ``upgraded_from`` is deliberately not signed: phase 4 moves it inside the run
  payload, where the root covers it.
* ``tine-attest/2`` signs ``opentine.attestation.v2:`` + JCS of the attestation
  payload without ``signature``, plus the signature header (so the algorithm
  and scheme cannot be swapped). Ed25519 only, and the target must be a run.
"""

from __future__ import annotations

from typing import Any

from opentine._format_v4 import ARTIFACT_V4_KIND, ARTIFACT_V4_VERSION, is_v4_artifact
from opentine._signing_keys import SignatureError
from opentine._signing_verify import HEADER_KEYS, SignatureResult, sign_block, verify_block
from opentine.kernel import KernelError, canonical_json, parse_oid

SCHEME_V3 = "tine-sig/3"
DOMAIN_PREFIX_V3 = b"opentine.signature.v3:"
SCHEME_ATTEST_V2 = "tine-attest/2"
ATTEST_DOMAIN_PREFIX_V2 = b"opentine.attestation.v2:"
#: Signature blocks one v4 artifact may carry.
MAX_V4_SIGNATURES = 16


def annotations_head(data: dict[str, Any]) -> str | None:
    """The newest annotation's id: what the signature binds the tags to."""
    annotations = data.get("annotations")
    if not isinstance(annotations, list):
        raise SignatureError("v4 annotations must be a list")
    if not annotations:
        return None
    head = annotations[-1].get("id") if isinstance(annotations[-1], dict) else None
    if not isinstance(head, str):
        raise SignatureError("v4 annotation head has no id")
    return head


def artifact_message(data: dict[str, Any], header: dict[str, Any]) -> bytes:
    """``tine-sig/3``: the exact bytes signed for a v4 artifact."""
    root = data.get("root") if isinstance(data, dict) else None
    if not isinstance(root, str):
        raise SignatureError("v4 artifact has no root")
    view = {
        "annotations_head": annotations_head(data),
        "format_version": ARTIFACT_V4_VERSION,
        "header": {key: header.get(key) for key in HEADER_KEYS},
        "kind": ARTIFACT_V4_KIND,
        "root": root,
    }
    try:
        return DOMAIN_PREFIX_V3 + canonical_json(view)
    except KernelError as exc:
        raise SignatureError(f"v4 signed view cannot be canonicalized: {exc}") from exc


def attest_message(payload: dict[str, Any], header: dict[str, Any]) -> bytes:
    """``tine-attest/2``: Ed25519 over the JCS payload, targeting a run root."""
    if header.get("alg") != "ed25519":
        raise SignatureError("tine-attest/2 is Ed25519 only")
    if not isinstance(payload, dict):
        raise SignatureError("attestation payload must be an object")
    target = payload.get("target_id")
    if not isinstance(target, str) or parse_oid(target)[0] != "run":
        raise SignatureError("tine-attest/2 must target a run root")
    body = {key: value for key, value in payload.items() if key != "signature"}
    view = {"body": body, "header": {key: header.get(key) for key in HEADER_KEYS}}
    try:
        return ATTEST_DOMAIN_PREFIX_V2 + canonical_json(view)
    except KernelError as exc:
        raise SignatureError(f"attestation cannot be canonicalized: {exc}") from exc


def sign_artifact_v4(
    data: dict[str, Any],
    key: Any,
    *,
    algorithm: str = "hmac-sha256",
    key_id: str | None = None,
    signer: str | None = None,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """One ``tine-sig/3`` block for a parsed v4 artifact."""
    if not is_v4_artifact(data):
        raise SignatureError("tine-sig/3 signs format v4 artifacts only")
    return sign_block(
        lambda header: artifact_message(data, header),
        key,
        algorithm=algorithm,
        scheme=SCHEME_V3,
        key_id=key_id,
        signer=signer,
        signed_at=signed_at,
        subject="artifact",
    )


def _refusal(state: str, reason: str) -> SignatureResult:
    return SignatureResult(False, state, None, None, None, None, reason)


def verify_artifact_v4(
    data: dict[str, Any],
    *,
    hmac_key: bytes | None = None,
    public_key: Any | None = None,
    trust_embedded: bool = False,
) -> SignatureResult:
    """The §4.7 verdict for a v4 artifact, with the v2 vocabulary.

    The signature names only the root, so the content is checked against the
    root first: a tampered envelope under an intact signature is ``mismatch``,
    exactly what an edited v2 body under a v2 signature reports. With several
    blocks, the first one the supplied key verifies wins; otherwise the first
    block's verdict is returned.
    """
    signatures = data.get("signatures")
    if not isinstance(signatures, list) or len(signatures) > MAX_V4_SIGNATURES:
        return _refusal("error", f"v4 signatures must be a list of at most {MAX_V4_SIGNATURES}")
    if not signatures:
        return _refusal("unsigned", "no signature present")
    if any(not isinstance(b, dict) or b.get("scheme") != SCHEME_V3 for b in signatures):
        return _refusal("error", "unsupported signature scheme")
    from opentine._artifact_v4_read import verify_v4

    integrity = verify_v4(data)
    if not integrity.ok:
        return _refusal("mismatch", f"content does not match the signed root: {integrity.reason}")
    results = [
        verify_block(
            block,
            lambda header: artifact_message(data, header),
            schemes=(SCHEME_V3,),
            subject="artifact",
            hmac_key=hmac_key,
            public_key=public_key,
            trust_embedded=trust_embedded,
        )
        for block in signatures
    ]
    return next((result for result in results if result.ok), results[0])


def append_signature(document: dict[str, Any], key: Any, **header: Any) -> bytes:
    """Sign a parsed v4 document and return its new canonical bytes."""
    block = sign_artifact_v4(document, key, **header)
    signed = {**document, "signatures": [*document.get("signatures", []), block]}
    return canonical_json(signed)


def sign_attestation_v2(payload: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    """A ``tine-attest/2`` block (Ed25519) for an attestation *payload* on a run root."""
    return sign_block(
        lambda h: attest_message(payload, h),
        key,
        algorithm="ed25519",
        scheme=SCHEME_ATTEST_V2,
        signer=payload.get("signer"),
        subject="attestation",
        **header,
    )


def statement_for(run: Any, actual: str, key: Any | None) -> dict[str, Any]:
    """The in-toto statement for a run; a v4 run carries a ``tine-attest/2`` record.

    The subject digest of a v4 run is its root's hex digest (the root names the
    whole run, SPEC 9.1). With an Ed25519 *key* the predicate also carries a
    ``tine-attest/2`` attestation on that root, signed by the envelope's key.
    """
    from opentine.intoto import PREDICATE_TYPE, build_statement

    if not actual.startswith("run:"):
        return build_statement(run, actual)
    statement = build_statement(run, parse_oid(actual)[1])
    if key is not None:
        from opentine._signing_pins import key_fingerprint
        from opentine.intoto import did_from_public, load_ed25519_private

        public = load_ed25519_private(key).public_key()
        payload = {
            "claim": {"predicateType": PREDICATE_TYPE},
            "evidence_ids": [],
            "signer": did_from_public(public),
            # 0.41 (X27): the record names the key that must sign the envelope.
            "signer_key": key_fingerprint(public.public_bytes_raw()),
            "target_id": actual,
        }
        statement["predicate"]["attestation"] = {
            **payload,
            "signature": sign_attestation_v2(payload, key),
        }
    return statement


def check_v4_attestation(
    statement: dict[str, Any], actual: str, envelope_key: str | None = None
) -> str | None:
    """Why a statement's embedded ``tine-attest/2`` record is unacceptable, if it is.

    With *envelope_key* (the DSSE signer's fingerprint) the record must be
    signed by that key, and a record naming a ``signer_key`` must name it.
    """
    record = (statement.get("predicate") or {}).get("attestation")
    if record is None:
        return None
    from opentine.attest_signing import verify_attestation

    if not isinstance(record, dict) or record.get("target_id") != actual:
        return "embedded tine-attest/2 record does not target this run's root"
    block = record.get("signature")
    if not isinstance(block, dict) or block.get("scheme") != SCHEME_ATTEST_V2:
        return "embedded attestation is not tine-attest/2"
    if not verify_attestation(record, trust_embedded=True).ok:
        return "embedded tine-attest/2 signature does not verify"
    if envelope_key is None:
        return None
    from opentine._signing_pins import used_key_fingerprint

    named = record.get("signer_key")
    if named is not None and named != envelope_key:
        return (
            f"tine-attest/2 record names signer {named}, the envelope is signed by {envelope_key}"
        )
    if used_key_fingerprint(block) != envelope_key:
        return "tine-attest/2 record is signed by a different key than the envelope"
    return None


def attestation_binding(statement: dict[str, Any]) -> str | None:
    """``bound`` (names its signer key), ``unbound`` (pre-0.41), or ``None`` (no record)."""
    record = (statement.get("predicate") or {}).get("attestation")
    if not isinstance(record, dict):
        return None
    return "bound" if isinstance(record.get("signer_key"), str) else "unbound"
