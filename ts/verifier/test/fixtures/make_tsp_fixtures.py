"""Regenerate ts/verifier/test/fixtures/tsp-tokens.json from the Python reference.

    python ts/verifier/test/fixtures/make_tsp_fixtures.py

RFC 3161 tokens are signed with fresh keys, so no conformance vector pins
their bytes (and the 0.48 freeze adds no vector family). They are written once
here, with the answers the Python reference gives for them:
``opentine._tsp_verify.verify_token`` for each ``token`` case and
``opentine._keyless_tsa.token_time`` for each ``keyless`` case. The TS verifier
must give the same answers (``test/tsp.test.ts``), and
``tests/test_052_ts_keyless_tsp.py`` re-checks that Python still does.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).with_name("tsp-tokens.json")
NOW = datetime(2026, 6, 1, 10, 5, tzinfo=UTC)
SIGNATURE = hashlib.sha512(b"opentine.tsp-fixture.signature").digest()
SHA256 = "2.16.840.1.101.3.4.2.1"
POLICY = "1.3.6.1.4.1.99999.1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _der(cert) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.DER)


def _cert(subject, issuer, key, signer, *, ca, eku=True, critical_eku=True, start=None, end=None,
          extra=()):  # fmt: skip
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])  # noqa: E731
    builder = (
        x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start or NOW - timedelta(days=1))
        .not_valid_after(end or NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )  # fmt: skip
    if eku and not ca:
        usage = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING])
        builder = builder.add_extension(usage, critical=critical_eku)
    for ext in extra:
        builder = builder.add_extension(ext, critical=True)
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, algorithm)


def _pki(kind: str = "ec", **options):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    make = {"ec": lambda: ec.generate_private_key(ec.SECP256R1()),
            "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ed25519": ed25519.Ed25519PrivateKey.generate}[kind]  # fmt: skip
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca = _cert("Fixture Root", "Fixture Root", ca_key, ca_key, ca=True)
    tsa_key = make()
    return ca, _cert("Fixture TSA", "Fixture Root", tsa_key, ca_key, ca=False, **options), tsa_key


def _token(bound: bytes, tsa, key, *, when=NOW, tamper=False, ess="v2", extra=b"", crls=b""):
    sys.path.insert(0, str(ROOT))
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    from tests.test_timestamp_offline_0_31 import der_set, gentime, integer, octets, oid, seq, tlv

    tst = seq(
        integer(1),
        oid(POLICY),
        seq(seq(oid(SHA256), b"\x05\x00"), octets(hashlib.sha256(bound).digest())),
        integer(42),
        gentime(when),
        extra,
    )
    attrs = [
        seq(oid("1.2.840.113549.1.9.3"), der_set(oid("1.2.840.113549.1.9.16.1.4"))),
        seq(oid("1.2.840.113549.1.9.4"), der_set(octets(hashlib.sha256(tst).digest()))),
    ]
    if ess == "v1":
        digest = hashlib.new("sha1", _der(tsa), usedforsecurity=False).digest()
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.12"), der_set(seq(seq(seq(octets(digest)))))))
    elif ess in ("v2", "wrong"):
        digest = hashlib.sha256(_der(tsa) if ess == "v2" else b"other").digest()
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.47"), der_set(seq(seq(seq(octets(digest)))))))
    signed_attrs = der_set(*attrs)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature, sig_alg = key.sign(signed_attrs), "1.3.101.112"
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signed_attrs, padding.PKCS1v15(), hashes.SHA256())
        sig_alg = "1.2.840.113549.1.1.11"
    else:
        signature, sig_alg = (
            key.sign(signed_attrs, ec.ECDSA(hashes.SHA256())),
            "1.2.840.10045.4.3.2",
        )
    if tamper:
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    signer = seq(integer(1), seq(tsa.issuer.public_bytes(), integer(tsa.serial_number)),
                 seq(oid(SHA256)), b"\xa0" + signed_attrs[1:], seq(oid(sig_alg)),
                 octets(signature))  # fmt: skip
    signed = seq(integer(3), der_set(seq(oid(SHA256))),
                 seq(oid("1.2.840.113549.1.9.16.1.4"), tlv(0xA0, octets(tst))),
                 tlv(0xA0, _der(tsa)), crls, der_set(signer))  # fmt: skip
    return seq(seq(integer(0)), seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed)))


def _stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def cases() -> list[dict]:
    sys.path.insert(0, str(ROOT))
    from cryptography import x509

    from tests.test_timestamp_offline_0_31 import oid, seq, tlv

    out: list[dict] = []
    ca, tsa, key = _pki()

    def add(name, data, roots, windowed=(), bound=SIGNATURE):
        out.append({"id": f"token.{name}", "kind": "token", "token": _b64(data),
                    "bound": _b64(bound), "roots": [_b64(_der(r)) for r in roots],
                    "windowed": [{"certs": [_b64(_der(c)) for c in chain], **window}
                                 for chain, window in windowed]})  # fmt: skip

    add("ec-v2", _token(SIGNATURE, tsa, key), [ca])
    add("ess-v1", _token(SIGNATURE, tsa, key, ess="v1"), [ca])
    for kind in ("rsa", "ed25519"):
        ca2, tsa2, key2 = _pki(kind)
        add(kind, _token(SIGNATURE, tsa2, key2), [ca2])
    add("imprint-mismatch", _token(b"other", tsa, key), [ca])
    add("tampered", _token(SIGNATURE, tsa, key, tamper=True), [ca])
    add("untrusted-root", _token(SIGNATURE, tsa, key), [_pki()[0]])
    add("outside-validity", _token(SIGNATURE, tsa, key, when=NOW + timedelta(days=9)), [ca])
    ca3, tsa3, key3 = _pki(eku=False)
    add("no-eku", _token(SIGNATURE, tsa3, key3), [ca3])
    ca4, tsa4, key4 = _pki(critical_eku=False)
    add("eku-not-critical", _token(SIGNATURE, tsa4, key4), [ca4])
    add("ess-none", _token(SIGNATURE, tsa, key, ess="none"), [ca])
    add("ess-wrong", _token(SIGNATURE, tsa, key, ess="wrong"), [ca])
    add("no-roots", _token(SIGNATURE, tsa, key), [])
    critical = tlv(0xA1, seq(oid("1.2.3.4"), b"\x01\x01\xff", b"\x04\x00"))
    add("critical-tstinfo-extension", _token(SIGNATURE, tsa, key, extra=critical), [ca])
    unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00")
    ca5, tsa5, key5 = _pki(extra=(unknown,))
    add("unknown-critical-cert-extension", _token(SIGNATURE, tsa5, key5), [ca5])
    accuracy = seq(b"\x02\x01\x00", b"\x80\x01\x01")  # 1 ms: still inside
    add("accuracy", _token(SIGNATURE, tsa, key, extra=accuracy), [ca])
    straddle = seq(b"\x02\x03\x01\x51\x81")  # 86401 s: past the TSA certificate
    add("accuracy-straddles", _token(SIGNATURE, tsa, key, extra=straddle), [ca])
    open_ = {"start": _stamp(NOW - timedelta(days=30))}
    retired = {"start": _stamp(NOW - timedelta(days=30)), "end": _stamp(NOW - timedelta(days=2))}
    add("windowed", _token(SIGNATURE, tsa, key), [], [([ca], open_)])
    add("retired", _token(SIGNATURE, tsa, key), [], [([ca], retired)])
    add("garbage", b"\x30\x03\x02\x01", [ca])
    good = _token(SIGNATURE, tsa, key)
    add("truncated", good[:-7], [ca])
    add("trailing", good + b"\x00", [ca])
    add("embedded-crl", _token(SIGNATURE, tsa, key, crls=tlv(0xA1, seq(b"\x02\x01\x01"))), [ca])
    del seq

    leaf = {"start": _stamp(NOW - timedelta(minutes=5)), "end": _stamp(NOW + timedelta(minutes=5))}
    authorities = [{"certs": [_b64(_der(ca))], **open_}]

    def keyless(name, tokens, auths=authorities, window=leaf):
        out.append(
            {
                "id": f"keyless.{name}",
                "kind": "keyless",
                "tokens": [_b64(t) for t in tokens],
                "signature": _b64(SIGNATURE),
                "authorities": auths,
                "leaf": window,
            }
        )

    keyless("bound", [good])
    keyless("earliest", [_token(SIGNATURE, tsa, key, when=NOW + timedelta(minutes=2)), good])
    keyless("no-token", [])
    keyless("imprint-mismatch", [_token(b"payload", tsa, key)])
    keyless("tampered", [_token(SIGNATURE, tsa, key, tamper=True)])
    keyless("retired", [good], [{"certs": [_b64(_der(ca))], **retired}])
    keyless("untrusted", [good], [{"certs": [_b64(_der(_pki()[0]))], **open_}])
    late = {
        "start": _stamp(NOW - timedelta(minutes=20)),
        "end": _stamp(NOW - timedelta(minutes=10)),
    }
    keyless("cert-not-valid", [good], window=late)
    return out


def answer(case: dict) -> dict:
    """What the Python reference says: ``{ok, reason}`` or ``{signing_time}`` / ``{error}``."""
    from types import SimpleNamespace

    from cryptography import x509

    from opentine._key_lifecycle import parse_time
    from opentine._keyless_tsa import TsaBindError, token_time
    from opentine._trusted_root import _Window
    from opentine._tsp_verify import verify_token

    def certs(items):
        return [x509.load_der_x509_certificate(base64.b64decode(i)) for i in items]

    def window(item):
        end = item.get("end")
        return _Window(parse_time(item["start"]), parse_time(end) if end else None)

    if case["kind"] == "token":
        windowed = [(certs(w["certs"]), window(w)) for w in case["windowed"]]
        verdict = verify_token(base64.b64decode(case["token"]), base64.b64decode(case["bound"]),
                               certs(case["roots"]), windowed)  # fmt: skip
        return {"ok": verdict.ok, "reason": verdict.reason}
    root = SimpleNamespace(timestamp_authorities=[(certs(a["certs"]), window(a))
                                                  for a in case["authorities"]])  # fmt: skip
    leaf = SimpleNamespace(not_valid_before_utc=parse_time(case["leaf"]["start"]),
                           not_valid_after_utc=parse_time(case["leaf"]["end"]))  # fmt: skip
    material = {"timestampVerificationData": {"rfc3161Timestamps": [
        {"signedTimestamp": t} for t in case["tokens"]]}}  # fmt: skip
    envelope = {"signatures": [{"sig": case["signature"]}]}
    try:
        when = token_time(material, envelope, root, leaf)
    except TsaBindError as exc:
        return {"error": exc.code}
    from opentine._keyless_tsa import stamp

    return {"signing_time": None if when is None else stamp(when)}


def main() -> None:
    sys.path.insert(0, str(ROOT))
    rows = cases()
    for row in rows:
        row["expect"] = answer(row)
        if row["id"] == "token.embedded-crl":  # TS reads no CRL/OCSP: it fails closed instead
            row["ts_expect"] = {"ok": False, "reason": "timestamp.revocation-unchecked"}
    OUT.write_text(json.dumps({"cases": rows}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} cases to {OUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
