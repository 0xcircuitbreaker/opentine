"""0.50: CRLs and OCSP responses embedded in an RFC 3161 token's SignedData.crls.

Embedded revocation data can only fail a token (``timestamp.revoked``,
``timestamp.revocation-invalid``); it never strengthens one, because the field
lies outside the TSA signature and stripping it is not detectable. Everything is
minted locally and checked under the network guard.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from opentine._offline_guard import no_network  # noqa: E402
from opentine._tsp import parse  # noqa: E402
from opentine._tsp_verify import verify_token  # noqa: E402
from tests.test_timestamp_offline_0_31 import BOUND, NOW, oid, pki, tlv, token  # noqa: E402

OCSP_FORMAT = "1.3.6.1.5.5.7.16.2"
DER = serialization.Encoding.DER


@pytest.fixture
def world():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _, tsa, tsa_key = pki()
    # re-issue the TSA under this CA (pki() makes its own root)
    tsa = (
        x509.CertificateBuilder()
        .subject_name(tsa.subject)
        .issuer_name(name)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca, ca_key, tsa, tsa_key


def crl(ca, key, revoked=(), signer=None):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(NOW - timedelta(hours=1))
        .next_update(NOW + timedelta(hours=1))
    )
    for serial, when, reason in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(signer or key, hashes.SHA256()).public_bytes(DER)


def ocsp_der(tsa, ca, key, *, status, when=None, reason=None, responder=None, certs=()):
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=tsa,
        issuer=ca,
        algorithm=hashes.SHA256(),
        cert_status=status,
        this_update=NOW - timedelta(hours=1),
        next_update=NOW + timedelta(hours=1),
        revocation_time=when,
        revocation_reason=reason,
    )
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder or ca)
    if certs:
        builder = builder.certificates(list(certs))
    return builder.sign(key, hashes.SHA256()).public_bytes(DER)


def crls_field(*crl_ders: bytes, ocsps: tuple[bytes, ...] = ()) -> bytes:
    other = [tlv(0xA1, oid(OCSP_FORMAT) + der) for der in ocsps]
    return tlv(0xA1, b"".join([*crl_ders, *other]))


def check(world, crls: bytes):
    ca, _, tsa, tsa_key = world
    with no_network():
        return verify_token(token(BOUND, tsa, tsa_key, crls=crls), BOUND, [ca])


def test_a_token_without_revocation_data_verifies_as_before(world):
    assert check(world, b"").reason == "timestamp.verified"


def test_the_parser_keeps_crls_and_ocsp_apart(world):
    ca, ca_key, tsa, tsa_key = world
    one = crl(ca, ca_key)
    two = ocsp_der(tsa, ca, ca_key, status=ocsp.OCSPCertStatus.GOOD)
    parsed = parse(token(BOUND, tsa, tsa_key, crls=crls_field(one, ocsps=(two,))))
    assert parsed.crls == [one] and parsed.ocsp == [two]


def test_a_crl_that_does_not_list_the_tsa_passes(world):
    ca, ca_key, _, _ = world
    assert check(world, crls_field(crl(ca, ca_key, [(7, NOW, None)]))).ok


def test_a_crl_revoking_the_tsa_before_gentime_fails(world):
    ca, ca_key, tsa, _ = world
    revoked = [(tsa.serial_number, NOW - timedelta(minutes=5), None)]
    verdict = check(world, crls_field(crl(ca, ca_key, revoked)))
    assert (verdict.ok, verdict.reason) == (False, "timestamp.revoked")


def test_a_later_revocation_passes_unless_the_key_was_compromised(world):
    ca, ca_key, tsa, _ = world
    later = NOW + timedelta(minutes=5)
    assert check(world, crls_field(crl(ca, ca_key, [(tsa.serial_number, later, None)]))).ok
    compromise = [(tsa.serial_number, later, x509.ReasonFlags.key_compromise)]
    assert check(world, crls_field(crl(ca, ca_key, compromise))).reason == "timestamp.revoked"


def test_a_crl_signed_by_another_key_is_invalid_not_ignored(world):
    ca, ca_key, tsa, _ = world
    forged = crl(ca, ca_key, [], signer=ec.generate_private_key(ec.SECP256R1()))
    assert check(world, crls_field(forged)).reason == "timestamp.revocation-invalid"


def test_a_tampered_crl_is_invalid(world):
    ca, ca_key, tsa, _ = world
    good = bytearray(crl(ca, ca_key, [(tsa.serial_number, NOW + timedelta(days=1), None)]))
    good[-3] ^= 1  # inside the signature
    assert check(world, crls_field(bytes(good))).reason == "timestamp.revocation-invalid"


def test_ocsp_good_passes_and_revoked_fails(world):
    ca, ca_key, tsa, _ = world
    good = ocsp_der(tsa, ca, ca_key, status=ocsp.OCSPCertStatus.GOOD)
    assert check(world, crls_field(ocsps=(good,))).ok
    bad = ocsp_der(
        tsa, ca, ca_key, status=ocsp.OCSPCertStatus.REVOKED, when=NOW - timedelta(minutes=1)
    )
    assert check(world, crls_field(ocsps=(bad,))).reason == "timestamp.revoked"


def test_ocsp_from_a_delegated_responder_needs_the_ocsp_signing_eku(world):
    ca, ca_key, tsa, _ = world
    key = ec.generate_private_key(ec.SECP256R1())

    def responder(eku):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP")])
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=1))
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

    revoked = dict(status=ocsp.OCSPCertStatus.REVOKED, when=NOW - timedelta(minutes=1))
    good = responder(ExtendedKeyUsageOID.OCSP_SIGNING)
    der = ocsp_der(tsa, ca, key, responder=good, certs=(good,), **revoked)
    assert check(world, crls_field(ocsps=(der,))).reason == "timestamp.revoked"
    wrong = responder(ExtendedKeyUsageOID.CODE_SIGNING)
    der = ocsp_der(tsa, ca, key, responder=wrong, certs=(wrong,), **revoked)
    assert check(world, crls_field(ocsps=(der,))).reason == "timestamp.revocation-invalid"


def test_ocsp_from_a_stranger_is_invalid(world):
    ca, _, tsa, _ = world
    stranger = ec.generate_private_key(ec.SECP256R1())
    imposter = (  # same name as the root, another key
        x509.CertificateBuilder()
        .subject_name(ca.subject)
        .issuer_name(ca.subject)
        .public_key(stranger.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        .sign(stranger, hashes.SHA256())
    )
    der = ocsp_der(
        tsa, ca, stranger, status=ocsp.OCSPCertStatus.GOOD, responder=imposter, certs=(imposter,)
    )
    assert check(world, crls_field(ocsps=(der,))).reason == "timestamp.revocation-invalid"


def test_garbage_in_the_crls_field_is_a_clean_failure(world):
    verdict = check(world, tlv(0xA1, tlv(0x30, b"\x01\x02")))
    assert not verdict.ok and verdict.reason in (
        "timestamp.malformed",
        "timestamp.revocation-invalid",
    )


def test_a_corrupted_crl_or_ocsp_response_never_raises(world):
    """cryptography parses CRLs lazily: a flaw found late is still a verdict."""
    ca, ca_key, tsa, _ = world
    base = crl(ca, ca_key, [(tsa.serial_number, NOW + timedelta(days=1), None), (5, NOW, None)])
    resp = ocsp_der(tsa, ca, ca_key, status=ocsp.OCSPCertStatus.GOOD)
    bad_version = bytearray(base)
    bad_version[base.index(b"\x02\x01\x01") + 2] = 0x2A  # CRL version 42
    cases = [crls_field(bytes(bad_version))]
    for der, wrap in ((base, lambda d: crls_field(d)), (resp, lambda d: crls_field(ocsps=(d,)))):
        for at in range(4, len(der)):
            for value in (0x00, 0xFF):
                mutated = bytearray(der)
                mutated[at] = value
                if mutated != der:
                    cases.append(wrap(bytes(mutated)))
    for field in cases:
        verdict = check(world, field)
        assert verdict.reason in (
            "timestamp.verified",  # an item the parser drops, as if stripped
            "timestamp.malformed",
            "timestamp.revocation-invalid",
        ), verdict
