"""SPEC 8.12.1 (0.48): an RFC 3161 token bound to a Rekor v2 keyless signature.

The tokens are given decoded (genTime, messageImprint, accuracy, the TSA's
``validFor``): their CMS signature and chain are SPEC 8.6, pinned elsewhere.
These cases pin the *binding*: what the imprint covers, which windows the
genTime must sit in, and which time is reported. Only ``adapter_keyless`` answers.
"""

from __future__ import annotations

import base64
import hashlib

from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V

VERIFIER = "verifier"
SIGNATURE = hashlib.sha512(b"opentine.conformance.keyless-signature").digest()
PAYLOAD = b'{"_type":"https://in-toto.io/Statement/v1"}'
LEAF = {"not_before": "2026-06-01T10:00:00Z", "not_after": "2026-06-01T10:10:00Z"}
LEAF_WINDOW = {"start": LEAF["not_before"], "end": LEAF["not_after"]}
TSA = {"start": "2025-01-01T00:00:00Z"}


def _token(gen: str, *, over: bytes = SIGNATURE, alg: str = "sha256", **extra) -> dict:
    imprint = hashlib.new(alg, over).hexdigest()
    return {"hash_algorithm": alg, "message_imprint": imprint, "gen_time": gen,
            "accuracy_us": 0, "tsa_valid_for": TSA, **extra}  # fmt: skip


def _k(name, expect, intent, tokens, reason=None, *, receipt="verified") -> Case:
    value = {"signature": base64.b64encode(SIGNATURE).decode("ascii"), "tokens": tokens,
             "leaf": LEAF_WINDOW, "receipt": receipt}  # fmt: skip
    return Case(id=f"keyless-tsa.{name}", section="8.12.1", checklist=(8,),
                op="keyless.signing-time", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


GOOD = _token("2026-06-01T10:05:00Z")

KEYLESS_TSA = Family(
    "77-keyless-tsa.json",
    "8.12.1",
    "keyless-tsa",
    (
        _k("bound", ACCEPT, "a token over the signature bytes gives the verified signing time",
           [GOOD]),
        _k("no-token", ACCEPT, "with no token the signing time stays unchecked, never a pass",
           []),
        _k("earliest", ACCEPT, "with several tokens the earliest genTime is the signing time",
           [_token("2026-06-01T10:07:00Z"), _token("2026-06-01T10:03:00Z")]),
        _k("sha384", ACCEPT, "the imprint may use SHA-384", [_token("2026-06-01T10:05:00Z",
           alg="sha384")]),
        _k("over-payload", REJECT, "a token over the payload, not the signature, binds nothing",
           [_token("2026-06-01T10:05:00Z", over=PAYLOAD)], "keyless.tsa-imprint-mismatch"),
        _k("one-unbound", REJECT, "every token carried must bind, not just one",
           [GOOD, _token("2026-06-01T10:06:00Z", over=PAYLOAD)],
           "keyless.tsa-imprint-mismatch"),
        _k("tsa-retired", REJECT, "a genTime after the TSA's validFor end is refused",
           [_token("2026-06-01T10:05:00Z", tsa_valid_for={"start": "2025-01-01T00:00:00Z",
                                                         "end": "2026-01-01T00:00:00Z"})],
           "keyless.tsa-retired"),
        _k("tsa-not-yet", REJECT, "a genTime before the TSA's validFor start is refused",
           [_token("2026-06-01T10:05:00Z", tsa_valid_for={"start": "2026-07-01T00:00:00Z"})],
           "keyless.tsa-retired"),
        _k("after-cert", REJECT, "a genTime after the leaf certificate expired is refused",
           [_token("2026-06-01T10:15:00Z")], "keyless.cert-not-valid-at-signing"),
        _k("before-cert", REJECT, "a genTime before the leaf certificate was issued is refused",
           [_token("2026-06-01T09:59:59Z")], "keyless.cert-not-valid-at-signing"),
        _k("accuracy-straddles", REJECT, "genTime plus its accuracy must sit inside the window",
           [_token("2026-06-01T10:09:30Z", accuracy_us=60_000_000)],
           "keyless.cert-not-valid-at-signing"),
        _k("receipt-invalid", REJECT, "a token never rescues a receipt that did not verify",
           [GOOD], "keyless.receipt-invalid", receipt="invalid"),
        _k("bad-hash", REJECT, "an imprint hash outside SHA-256/384/512 is refused",
           [_token("2026-06-01T10:05:00Z", alg="md5")], "keyless.malformed"),
        # 0.48 review: pin the microsecond and grammar edges both verifiers share.
        _k("microseconds", ACCEPT, "a genTime keeps microsecond precision in the signing time",
           [_token("2026-06-01T10:05:00.000123Z")]),
        _k("sub-ms-before-cert", REJECT, "a genTime a microsecond before notBefore is refused",
           [_token("2026-06-01T09:59:59.999999Z")], "keyless.cert-not-valid-at-signing"),
        _k("compact-time", REJECT, "a compact ISO 8601 genTime is not RFC 3339",
           [_token("20260601T100500Z")], "keyless.malformed"),
        _k("spaced-imprint", REJECT, "an imprint with whitespace is not hex",
           [{**GOOD, "message_imprint": " ".join(GOOD["message_imprint"][i:i + 2]
                                                  for i in range(0, 64, 2))}],
           "keyless.malformed"),
        _k("float-accuracy", REJECT, "accuracy_us is an integer, not a float",
           [{**GOOD, "accuracy_us": 0.0}], "keyless.malformed"),
    ),
)  # fmt: skip

FAMILIES = (KEYLESS_TSA,)
