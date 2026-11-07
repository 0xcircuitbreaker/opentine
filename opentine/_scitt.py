"""SCITT signed statements and receipts, verified offline (0.44, *experimental*).

* A **signed statement** is a COSE_Sign1 (RFC 9052, tag 18) whose protected
  header names ``alg`` (1) and usually ``cty`` (3) and CWT claims (15: ``iss``
  1, ``sub`` 2). It is verified against a pinned public key (PEM).
* A **receipt** is a COSE_Sign1 by the transparency service in the
  draft-ietf-cose-merkle-tree-proofs ``RFC9162_SHA256`` profile: protected
  ``vds`` (395) = 1, unprotected ``vdp`` (396) = ``{-1: [bstr .cbor [tree_size,
  leaf_index, [hash...]]]}``, detached payload = the Merkle root the inclusion
  proof implies. Receipts travel in the statement's unprotected header 394 or
  as a separate file.
* The leaf is ``SHA-256(0x00 || signed statement)``, the statement re-encoded
  without header 394. **This leaf construction is our reading of the drafts and
  has not been matched against scitt-community/scitt-api-emulator** (whose
  receipts have followed CCF and older draft layouts): interop is not claimed,
  which is why the command sits behind ``--experimental``.

Nothing here opens a socket; inputs are bounded by :mod:`._cbor`.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from opentine import _cbor
from opentine.repository import _tlog, _tlog_proof

ALGS = {-7: ("ec", hashes.SHA256, 32), -35: ("ec", hashes.SHA384, 48),
        -36: ("ec", hashes.SHA512, 66), -8: ("ed25519", None, 0)}  # fmt: skip
RECEIPTS, VDS, VDP, RFC9162_SHA256, INCLUSION = 394, 395, 396, 1, -1
MAX_RECEIPTS = 16


class SCITTError(ValueError):
    pass


def decode_sign1(data: bytes) -> list[Any]:
    item = _cbor.loads(data)
    if isinstance(item, _cbor.Tag):
        if item.tag != 18:
            raise SCITTError(f"CBOR tag {item.tag} is not COSE_Sign1 (18)")
        item = item.value
    if not (isinstance(item, list) and len(item) == 4 and isinstance(item[0], bytes)):
        raise SCITTError("not a COSE_Sign1 array")
    if not isinstance(item[1], dict) or not isinstance(item[3], bytes):
        raise SCITTError("COSE_Sign1 headers or signature are malformed")
    if item[2] is not None and not isinstance(item[2], bytes):
        raise SCITTError("COSE_Sign1 payload is neither bytes nor nil")
    return item


def protected(sign1: list[Any]) -> dict:
    headers = _cbor.loads(sign1[0]) if sign1[0] else {}
    if not isinstance(headers, dict):
        raise SCITTError("protected header is not a map")
    return headers


def verify_sign1(sign1: list[Any], key: Any, payload: bytes | None = None) -> dict:
    """Check the signature (detached ``payload`` if given); return the protected header."""
    headers = protected(sign1)
    alg = headers.get(1)
    if alg not in ALGS:
        raise SCITTError(f"unsupported COSE alg {alg!r}")
    body = sign1[2] if payload is None else payload
    if body is None:
        raise SCITTError("detached payload is missing")
    message = _cbor.dumps(["Signature1", sign1[0], b"", body])
    kind, digest, size = ALGS[alg]
    signature = sign1[3]
    try:
        if kind == "ed25519":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise SCITTError("EdDSA statement needs an Ed25519 key")
            key.verify(signature, message)
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey) or len(signature) != 2 * size:
                raise SCITTError("ECDSA statement needs a matching EC key and r||s signature")
            der = encode_dss_signature(
                int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            )
            key.verify(der, message, ec.ECDSA(digest()))
    except InvalidSignature:
        raise SCITTError("COSE signature does not verify under the pinned key") from None
    return headers


def leaf_bytes(sign1: list[Any], original: bytes) -> bytes:
    """The statement as registered: its own bytes, or re-encoded without header 394."""
    if RECEIPTS not in sign1[1]:
        return original
    unprotected = {k: v for k, v in sign1[1].items() if k != RECEIPTS}
    return _cbor.dumps(_cbor.Tag(18, [sign1[0], unprotected, sign1[2], sign1[3]]))


def verify_receipt(
    receipt: bytes, statement: list[Any], original: bytes, service_key: Any
) -> dict[str, Any]:
    sign1 = decode_sign1(receipt)
    headers = protected(sign1)
    if headers.get(VDS) != RFC9162_SHA256:
        raise SCITTError("receipt is not an RFC9162_SHA256 (vds 1) receipt")
    proofs = (sign1[1].get(VDP) or {}).get(INCLUSION) if isinstance(sign1[1], dict) else None
    if not isinstance(proofs, list) or not 1 <= len(proofs) <= MAX_RECEIPTS:
        raise SCITTError("receipt carries no inclusion proof")
    leaf = _tlog.leaf_hash(leaf_bytes(statement, original))
    for raw in proofs:
        proof = _cbor.loads(raw) if isinstance(raw, bytes) else None
        if not (isinstance(proof, list) and len(proof) == 3 and isinstance(proof[2], list)):
            raise SCITTError("inclusion proof is not [tree_size, leaf_index, path]")
        size, index, path = proof
        if not all(isinstance(h, bytes) for h in path):
            raise SCITTError("inclusion path is not a list of hashes")
        root = _tlog_proof.root_from_inclusion(leaf, int(index), int(size), list(path))
        verify_sign1(sign1, service_key, payload=root)
    return {"issuer": _cwt(headers).get(1), "leaf_index": int(index), "tree_size": int(size)}


def _cwt(headers: dict) -> dict:
    claims = headers.get(15)
    return claims if isinstance(claims, dict) else {}


def verify_statement(
    data: bytes, key: Any, *, service_key: Any = None, receipts: list[bytes] = ()
) -> dict[str, Any]:
    """Verify a statement and (with ``service_key``) every receipt; SCITTError otherwise."""
    sign1 = decode_sign1(data)
    headers = verify_sign1(sign1, key)
    embedded = sign1[1].get(RECEIPTS) or []
    if not isinstance(embedded, list) or not all(isinstance(r, bytes) for r in embedded):
        raise SCITTError("embedded receipts (header 394) are malformed")
    found = list(receipts) + list(embedded)
    if len(found) > MAX_RECEIPTS:
        raise SCITTError("too many receipts")
    checked = []
    if found and service_key is None:
        raise SCITTError("receipts need --service-key to verify")
    for receipt in found:
        checked.append(verify_receipt(receipt, sign1, data, service_key))
    claims = _cwt(headers)
    return {"alg": headers.get(1), "content_type": headers.get(3), "experimental": True,
            "issuer": claims.get(1), "ok": True, "receipts": checked,
            "subject": claims.get(2)}  # fmt: skip
