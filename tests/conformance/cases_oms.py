"""SPEC 4.26 OMS model signatures (0.48): an OpenSSF Model Signing bundle, pinned key.

The bundles are signed here with a fixed P-256 test scalar and a nonce derived
from it and the message, so regeneration is byte-identical. Only
``adapter_oms`` answers in Python; the pyz and the TS verifier port it.
"""

from __future__ import annotations

import base64
import hashlib
import json

from opentine._oms import PAYLOAD_TYPE, PREDICATE, STATEMENT, pae
from opentine._pyz import _p256
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V

VERIFIER = "verifier"
SECRET = int.from_bytes(hashlib.sha256(b"opentine conformance oms key").digest(), "big") % _p256.N
OTHER = int.from_bytes(hashlib.sha256(b"opentine conformance oms other").digest(), "big") % _p256.N
FILES = {
    "config.json": hashlib.sha256(b'{"arch": "tiny"}').hexdigest(),
    "model.safetensors": hashlib.sha256(b"weights").hexdigest(),
    "tokenizer/vocab.txt": hashlib.sha256(b"a\nb\n").hexdigest(),
}


def _point(secret: int) -> bytes:
    x, y = _p256.multiply(secret, _p256.G)  # type: ignore[misc]
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


PUBLIC = _point(SECRET).hex()


def _der(r: int, s: int) -> bytes:
    def integer(value: int) -> bytes:
        body = value.to_bytes((value.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(body)]) + body

    inner = integer(r) + integer(s)
    return b"\x30" + bytes([len(inner)]) + inner


def _sign(message: bytes, secret: int = SECRET, *, high_s: bool = False) -> str:
    n = _p256.N
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    k = int.from_bytes(hashlib.sha256(secret.to_bytes(32, "big") + message).digest(), "big") % n
    r = _p256.multiply(k, _p256.G)[0] % n  # type: ignore[index]
    s = pow(k, -1, n) * (e + r * secret) % n
    s = min(s, n - s) if not high_s else max(s, n - s)
    return base64.b64encode(_der(r, s)).decode()


def _statement(files=FILES, **change) -> dict:
    resources = [{"name": n, "algorithm": "sha256", "digest": d} for n, d in sorted(files.items())]
    root = hashlib.sha256(b"".join(bytes.fromhex(r["digest"]) for r in resources)).hexdigest()
    serialization = {"method": "files", "hash_type": "sha256", "allow_symlinks": False,
                     "ignore_paths": [".git"]}  # fmt: skip
    subject = [{"name": "tiny-model", "digest": {"sha256": root}}]
    statement = {"_type": STATEMENT, "subject": subject,
                 "predicateType": PREDICATE,
                 "predicate": {"serialization": serialization, "resources": resources}}  # fmt: skip
    for key, value in change.items():
        statement[key] = value
    return statement


def _bundle(statement=None, *, secret=SECRET, payload_type=PAYLOAD_TYPE, sigs=None, **extra):
    payload = json.dumps(statement or _statement(), sort_keys=True).encode()
    signatures = sigs if sigs is not None else [{"sig": _sign(pae(PAYLOAD_TYPE, payload), secret),
                                                 "keyid": ""}]  # fmt: skip
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {"publicKey": {"hint": "test"}},
              "dsseEnvelope": {"payload": base64.b64encode(payload).decode(),
                               "payloadType": payload_type, "signatures": signatures}}  # fmt: skip
    bundle.update(extra)
    return bundle


def _pred(**change) -> dict:
    statement = _statement()
    statement["predicate"] = {**statement["predicate"], **change}
    return statement


def _o(name, expect, intent, bundle, reason=None, *, files=FILES, key=PUBLIC) -> Case:
    value = {"bundle": bundle, "files": files, "public_key": key}
    return Case(id=f"oms.{name}", section="4.26", checklist=(8,), op="oms.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


GOOD = _bundle()
_PAYLOAD = base64.b64decode(GOOD["dsseEnvelope"]["payload"])
_TAMPERED = {**FILES, "model.safetensors": "0" * 64}
_DUP = _pred(resources=_statement()["predicate"]["resources"] * 2)
_SHARDS = _pred(serialization={"method": "shards", "hash_type": "sha256", "shard_size": 1024})
_ROOT = _statement(subject=[{"name": "tiny-model", "digest": {"sha256": "1" * 64}}])
_BAD_SUBJECT = _statement(subject=[{"name": "tiny-model", "digest": {"sha256": "XYZ"}}])
_HIGH = _sign(pae(PAYLOAD_TYPE, _PAYLOAD), high_s=True)
_OTHER_SIG = {"sig": _sign(pae(PAYLOAD_TYPE, _PAYLOAD), OTHER), "keyid": ""}
_SWAPPED = {**GOOD["dsseEnvelope"], "payload": base64.b64encode(
    json.dumps(_statement(_TAMPERED), sort_keys=True).encode()).decode()}  # fmt: skip

OMS = Family(
    "75-oms.json",
    "4.26",
    "oms",
    (
        _o("verified", ACCEPT, "a key-signed OMS v1.0 bundle over exactly the model's files", GOOD),
        _o("manifest-only", ACCEPT, "no files given: the signature and manifest alone",
           GOOD, files=None),
        _o("ignored-path", ACCEPT, "a file under a signed ignore_paths entry is not compared",
           GOOD, files={**FILES, ".git/HEAD": "2" * 64}),
        _o("second-signature", ACCEPT, "any one DSSE signature verifying with the key suffices",
           _bundle(sigs=[_OTHER_SIG, GOOD["dsseEnvelope"]["signatures"][0]])),
        _o("high-s", ACCEPT, "a high-S ECDSA signature verifies, as in OpenSSL",
           _bundle(sigs=[{"sig": _HIGH, "keyid": ""}])),
        _o("no-envelope", REJECT, "a bundle without a dsseEnvelope",
           {"mediaType": GOOD["mediaType"]}, "oms.malformed"),
        _o("payload-not-base64", REJECT, "the payload is not base64",
           {**GOOD, "dsseEnvelope": {**GOOD["dsseEnvelope"], "payload": "%%%"}}, "oms.malformed"),
        _o("payload-type", REJECT, "a DSSE payloadType other than in-toto JSON",
           _bundle(payload_type="application/json"), "oms.unsupported"),
        _o("keyless", REJECT, "a keyless (Fulcio certificate) bundle is never reported verified",
           _bundle(verificationMaterial={"certificate": {"rawBytes": "AAAA"}}),
           "oms.unsupported"),
        _o("no-key", REJECT, "no pinned public key", GOOD, "oms.no-key", key=None),
        _o("wrong-key", REJECT, "signed by another key", _bundle(secret=OTHER),
           "oms.bad-signature"),
        _o("payload-swapped", REJECT, "a payload replaced after signing",
           {**GOOD, "dsseEnvelope": _SWAPPED}, "oms.bad-signature"),
        _o("not-statement", REJECT, "a signed payload that is not an in-toto Statement v1",
           _bundle(_statement(_type="https://in-toto.io/Statement/v0.1")), "oms.malformed"),
        _o("predicate-v0", REJECT, "a predicate type other than model_signing v1.0",
           _bundle(_statement(predicateType="https://model_signing/Digests/v0.1")),
           "oms.unsupported"),
        _o("shards", REJECT, "a serialization method other than 'files'",
           _bundle(_SHARDS), "oms.unsupported"),
        _o("duplicate-resource", REJECT, "a resource listed twice",
           _bundle(_DUP), "oms.malformed"),
        _o("bad-subject", REJECT, "a subject digest that is not 64 lowercase hex",
           _bundle(_BAD_SUBJECT), "oms.malformed"),
        _o("root-mismatch", REJECT, "a subject digest that is not the digest of the resources",
           _bundle(_ROOT), "oms.root-mismatch"),
        _o("missing-file", REJECT, "a signed resource absent from the model",
           GOOD, "oms.missing-file",
           files={k: v for k, v in FILES.items() if k != "config.json"}),
        _o("digest-mismatch", REJECT, "a model file whose bytes changed since signing",
           GOOD, "oms.digest-mismatch", files=_TAMPERED),
        _o("extra-file", REJECT, "a model file the signature does not cover",
           GOOD, "oms.extra-file", files={**FILES, "adapter.bin": "3" * 64}),
    ),
)  # fmt: skip

FAMILIES = (OMS,)
