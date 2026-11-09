"""Parse an RFC 3161 ``TimeStampResp`` or ``TimeStampToken`` (CMS SignedData).

:func:`parse` accepts either form (a ``.tsr`` from ``openssl ts -reply`` is a
response; a bare token is a ``ContentInfo``) and returns a :class:`Token`: the
TSTInfo fields a verifier reports, the embedded certificates, and the one
SignerInfo's pieces. It checks shape only; :mod:`opentine._tsp_verify` checks
the imprint, signature, chain, EKU and validity. Any malformed input raises
``ValueError`` (``_der.DerError``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from opentine import _der
from opentine._der import OCTETS, OID, SEQUENCE, SET, DerError

SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
HASHES = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


@dataclass
class Token:
    policy: str
    hash_oid: str
    imprint: bytes
    serial: int
    gen_time: datetime
    tst_info: bytes
    #: DER certificates carried in SignedData.certificates.
    certs: list[bytes] = field(default_factory=list)
    #: SignedData.crls (0.50): DER CRLs, and RFC 5940 OCSP responses.
    crls: list[bytes] = field(default_factory=list)
    ocsp: list[bytes] = field(default_factory=list)
    signer_serial: int | None = None
    signer_issuer: bytes | None = None
    signer_ski: bytes | None = None
    digest_oid: str = ""
    signed_attrs: bytes = b""
    attrs: dict[str, list[Any]] = field(default_factory=dict)
    sig_oid: str = ""
    signature: bytes = b""
    #: 0.41 (X26): TSTInfo's optional fields.
    accuracy_us: int | None = None
    ordering: bool = False
    nonce: int | None = None
    #: ``(extnID, critical)`` of each TSTInfo extension.
    extensions: list[tuple[str, bool]] = field(default_factory=list)

    @property
    def hash_name(self) -> str:
        return HASHES.get(self.hash_oid, self.hash_oid)


def _content_info(node: _der.Node) -> _der.Node:
    """The SignedData SEQUENCE inside a TimeStampResp or a bare ContentInfo."""
    items = node.expect(SEQUENCE, "token").children()
    if items and items[0].tag == SEQUENCE:  # TimeStampResp {status, timeStampToken}
        status = _der.as_int(items[0].children()[0])
        if status not in (0, 1) or len(items) < 2:
            raise DerError(f"timestamp response status {status}: not granted")
        items = items[1].expect(SEQUENCE, "ContentInfo").children()
    if len(items) != 2 or _der.as_oid(items[0]) != SIGNED_DATA or items[1].tag != 0xA0:
        raise DerError("not a CMS SignedData ContentInfo")
    (signed,) = items[1].children()
    return signed.expect(SEQUENCE, "SignedData")


def _tst_info(raw: bytes) -> dict[str, Any]:
    items = _der.read(raw).expect(SEQUENCE, "TSTInfo").children()
    if len(items) < 5 or _der.as_int(items[0]) != 1:
        raise DerError("TSTInfo must be version 1")
    imprint = items[2].expect(SEQUENCE, "messageImprint").children()
    algorithm = imprint[0].expect(SEQUENCE, "hashAlgorithm").children()
    return {
        "policy": _der.as_oid(items[1]),
        "hash_oid": _der.as_oid(algorithm[0]),
        "imprint": imprint[1].expect(OCTETS, "hashedMessage").value,
        "serial": _der.as_int(items[3]),
        "gen_time": _der.as_gentime(items[4]),
        "tst_info": raw,
        **_optional(items[5:]),
    }


def _optional(items: list[_der.Node]) -> dict[str, Any]:
    """accuracy, ordering, nonce, tsa and extensions, in their DER order."""
    out: dict[str, Any] = {}
    for node in items:
        if node.tag == SEQUENCE and not out:
            out["accuracy_us"] = _accuracy(node)
        elif node.tag == 0x01 and "nonce" not in out:
            out["ordering"] = node.value not in (b"", b"\x00")
        elif node.tag == 0x02:
            out["nonce"] = _der.as_int(node)
        elif node.tag == 0xA0:
            continue  # tsa GeneralName: reported by the certificate instead
        elif node.tag == 0xA1:
            out["extensions"] = [_extension(ext) for ext in node.children()]
        else:
            raise DerError(f"unexpected TSTInfo field 0x{node.tag:02x}")
    return out


def _accuracy(node: _der.Node) -> int:
    total = 0
    for part in node.children():
        if part.tag == 0x02:
            total += _der.as_int(part) * 1_000_000
        elif part.tag in (0x80, 0x81):
            value = int.from_bytes(part.value, "big", signed=True)
            if not 1 <= value <= 999:
                raise DerError("accuracy millis/micros must be 1..999")
            total += value * (1000 if part.tag == 0x80 else 1)
        else:
            raise DerError("malformed accuracy")
    if total < 0:
        raise DerError("negative accuracy")
    return total


def _extension(node: _der.Node) -> tuple[str, bool]:
    parts = node.expect(SEQUENCE, "Extension").children()
    critical = len(parts) == 3 and parts[1].tag == 0x01 and parts[1].value != b"\x00"
    return _der.as_oid(parts[0]), critical


def _signer(token: Token, node: _der.Node) -> None:
    items = node.expect(SEQUENCE, "SignerInfo").children()
    if len(items) < 5:
        raise DerError("SignerInfo is too short")
    sid = items[1]
    if sid.tag == SEQUENCE:
        issuer, serial = sid.children()
        token.signer_issuer, token.signer_serial = issuer.raw, _der.as_int(serial)
    elif sid.tag == 0x80:
        token.signer_ski = sid.value
    else:
        raise DerError("unknown SignerIdentifier")
    token.digest_oid = _der.as_oid(items[2].expect(SEQUENCE, "digestAlgorithm").children()[0])
    if items[3].tag != 0xA0:
        raise DerError("SignerInfo has no signed attributes")
    token.signed_attrs = _der.retag(items[3], SET)
    for attr in items[3].children():
        oid, values = attr.expect(SEQUENCE, "Attribute").children()
        token.attrs[_der.as_oid(oid)] = values.expect(SET, "AttributeValues").children()
    token.sig_oid = _der.as_oid(items[4].expect(SEQUENCE, "signatureAlgorithm").children()[0])
    token.signature = items[5].expect(OCTETS, "signature").value


OCSP_FORMAT = "1.3.6.1.5.5.7.16.2"  # id-ri-ocsp-response (RFC 5940)


def _revocation(token: Token, node: _der.Node) -> None:
    """SignedData.crls: CRLs, and OtherRevocationInfoFormat OCSP responses."""
    for item in node.children():
        if item.tag == SEQUENCE:
            token.crls.append(item.raw)
        elif item.tag == 0xA1:
            fmt, info = item.children()
            if _der.as_oid(fmt) == OCSP_FORMAT:
                token.ocsp.append(info.raw)


def parse(data: bytes) -> Token:
    """Decode *data*; ``ValueError`` names the first structural flaw."""
    try:
        signed = _content_info(_der.read(data)).children()
        if len(signed) < 4:
            raise DerError("SignedData is too short")
        encap = signed[2].expect(SEQUENCE, "encapContentInfo").children()
        if _der.as_oid(encap[0].expect(OID, "eContentType")) != TST_INFO or len(encap) != 2:
            raise DerError("the token does not hold a TSTInfo")
        (content,) = encap[1].children()
        token = Token(**_tst_info(content.expect(OCTETS, "eContent").value))
        rest = signed[3:]
        if rest and rest[0].tag == 0xA0:
            token.certs = [cert.raw for cert in rest[0].children()]
            rest = rest[1:]
        if rest and rest[0].tag == 0xA1:
            _revocation(token, rest[0])
        signers = rest[-1].expect(SET, "signerInfos").children()
        if len(signers) != 1:
            raise DerError("expected exactly one SignerInfo")
        _signer(token, signers[0])
        return token
    except (IndexError, TypeError) as exc:  # a child list of the wrong length
        raise DerError(f"malformed timestamp token: {exc}") from None


__all__ = ["HASHES", "Token", "parse"]
