"""SPEC 4.14 tombstones and 4.15 redacted public copies (0.46).

Both records are signed here with the published keys in ``keys`` (HMAC and
Ed25519 are deterministic and every record fixes ``signed_at``), so the input
bytes are stable. ``inconsistent`` cases are signed bodies no writer would
produce. Only the ops in ``adapter_share`` produce an answer.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _redacted_copy, _tombstone
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
WHEN = "2026-11-08T00:00:00Z"
BLOB = "blob:sha256:" + "2" * 64
RUN = "run:sha256:" + "1" * 64
PUBLIC = "run:sha256:" + "3" * 64
PACK = "sha256:" + "4" * 64
_HMAC_A = KEYS["hmac_a"].hex()


def _private(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _public(name: str) -> str:
    return _private(name).public_key().public_bytes_raw().hex()


def _edited(record: dict, **fields) -> dict:
    out = copy.deepcopy(record)
    out.update(fields)
    return out


def _signed(module, body: dict, kind: str) -> dict:
    if kind == "hmac":
        return module.sign(body, KEYS["hmac_a"], algorithm="hmac-sha256", key_id="vector",
                           signed_at=WHEN)  # fmt: skip
    return module.sign(body, _private(kind), algorithm="ed25519", key_id="vector",
                       signed_at=WHEN)  # fmt: skip


def _raw_sign(domain: bytes, body: dict) -> dict:
    """Sign a body the field rules would refuse (the inconsistent cases)."""
    from opentine._signed_record import sign

    return sign(body, domain, "record", KEYS["hmac_a"], algorithm="hmac-sha256", key_id="vector",
                signed_at=WHEN)  # fmt: skip


# --- 4.14 tombstones --------------------------------------------------------- #


def _tomb(**fields) -> dict:
    return {"kind": _tombstone.KIND, "tombstone_version": 1, "oid": BLOB,
            "reason": "erasure request 42", "actor": "alice@example", "purged_at": WHEN,
            **fields}  # fmt: skip


def _t(name, expect, intent, record, reason=None, *, hmac=None, public=None) -> Case:
    return Case(id=f"tombstone.{name}", section="4.14", checklist=(8,), op="tombstone.verify",
                profile=VERIFIER, expect=expect, intent=intent,
                input=V({"tombstone": record, "hmac_key_hex": hmac, "public_key": public}),
                reason=reason)  # fmt: skip


# A three-object run whose output blob is purged: the closure walk (4.14).
def _graph() -> tuple[str, str, dict[str, bytes]]:
    from opentine.kernel import ObjectEnvelope

    prompt = ObjectEnvelope.create("blob", b"prompt")
    output = ObjectEnvelope.create("blob", b"the purged output")
    event = ObjectEnvelope.create(
        "event",
        {"causal_ids": [], "input_blob": prompt.oid, "output_blob": output.oid, "parent_ids": []},
    )
    run = ObjectEnvelope.create(
        "run", {"events": [event.oid], "manifests": {}, "roots": [event.oid], "tips": [event.oid]}
    )
    objects = {env.oid: env.encode() for env in (prompt, output, event, run)}
    return run.oid, output.oid, objects


_RUN3, _PURGED, _OBJECTS = _graph()


def _closure(name, expect, intent, drop, tombstones, reason=None) -> Case:
    import base64

    objects = [
        {"id": oid, "data_b64": base64.b64encode(raw).decode("ascii")}
        for oid, raw in sorted(_OBJECTS.items())
        if oid not in drop
    ]
    value = {"run": _RUN3, "objects": objects, "tombstones": tombstones}
    return Case(id=f"tombstone.closure.{name}", section="4.14", checklist=(8,),
                op="tombstone.closure", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


_T_PURGED = _signed(_tombstone, _tomb(oid=_PURGED), "hmac")

_T_HMAC = _signed(_tombstone, _tomb(), "hmac")
_T_ED = _signed(_tombstone, _tomb(), "ed25519_seed")

TOMBSTONE = Family(
    "63-tombstone.json",
    "4.14",
    "tombstone",
    (
        _t("valid-hmac", ACCEPT, "an HMAC tombstone verifies under its key", _T_HMAC,
           hmac=_HMAC_A),
        _t("valid-ed25519-trusted", ACCEPT, "an Ed25519 tombstone under the trusted key", _T_ED,
           public=_public("ed25519_seed")),
        _t("valid-ed25519-tofu", ACCEPT, "with no key, an Ed25519 tombstone on its embedded key",
           _T_ED),
        _t("oid-edited", REJECT, "a tombstone moved to another blob after signing",
           _edited(_T_HMAC, oid="blob:sha256:" + "5" * 64), "tombstone.bad-signature",
           hmac=_HMAC_A),
        _t("reason-edited", REJECT, "a reason edited after signing fails",
           _edited(_T_ED, reason="routine cleanup"), "tombstone.bad-signature"),
        _t("wrong-hmac-key", REJECT, "an HMAC tombstone under another key fails", _T_HMAC,
           "tombstone.bad-signature", hmac=KEYS["hmac_b"].hex()),
        _t("wrong-key", REJECT, "an Ed25519 tombstone by a key other than the trusted one",
           _T_ED, "tombstone.wrong-key", public=_public("ed25519_seed_b")),
        _t("hmac-key-ed25519-record", REJECT, "a supplied HMAC key never falls back to TOFU",
           _T_ED, "tombstone.wrong-key", hmac=_HMAC_A),
        _t("no-key", REJECT, "an HMAC tombstone with no key cannot verify", _T_HMAC,
           "tombstone.no-key"),
        _t("unsigned", REJECT, "a tombstone without a signature is refused", _tomb(),
           "tombstone.unsigned", hmac=_HMAC_A),
        _t("not-a-blob", REJECT, "only a blob can be purged",
           _edited(_T_HMAC, oid=RUN), "tombstone.malformed", hmac=_HMAC_A),
        _t("empty-reason", REJECT, "a tombstone must say why",
           _edited(_T_HMAC, reason=" "), "tombstone.malformed", hmac=_HMAC_A),
        _t("control-in-reason", REJECT, "a reason holding a control character",
           _edited(_T_HMAC, reason="a\nb"), "tombstone.malformed", hmac=_HMAC_A),
        _t("bad-time", REJECT, "purged_at is RFC 3339 UTC to the second",
           _edited(_T_HMAC, purged_at="2026-11-08 00:00"), "tombstone.malformed",
           hmac=_HMAC_A),
        _t("extra-field", REJECT, "a field the tombstone format does not define",
           _edited(_T_HMAC, size=3), "tombstone.malformed", hmac=_HMAC_A),
        _t("wrong-version", REJECT, "a tombstone_version other than 1",
           _edited(_T_HMAC, tombstone_version=2), "tombstone.malformed", hmac=_HMAC_A),
        _closure("intact", ACCEPT, "every linked object present: verified", set(), []),
        _closure("purged", ACCEPT, "a purged blob with its tombstone is content-unavailable",
                 {_PURGED}, [_T_PURGED]),
        _closure("unused-tombstone", ACCEPT, "a tombstone for a present blob changes nothing",
                 set(), [_T_PURGED]),
        _closure("missing", REJECT, "a missing blob without a tombstone fails", {_PURGED}, [],
                 "tombstone.missing-content"),
        _closure("other-tombstone", REJECT, "a tombstone for another blob does not cover it",
                 {_PURGED}, [_T_HMAC], "tombstone.missing-content"),
        _closure("missing-event", REJECT, "only a blob can be content-unavailable",
                 {next(oid for oid in _OBJECTS if oid.startswith("event:"))}, [_T_PURGED],
                 "tombstone.missing-content"),
        _closure("malformed-tombstone", REJECT, "the walk still needs well-formed tombstones",
                 {_PURGED}, [_edited(_T_PURGED, actor="")], "tombstone.malformed"),
    ),
)  # fmt: skip


# --- 4.15 redacted public copies -------------------------------------------- #


def _copy(**fields) -> dict:
    return {"kind": _redacted_copy.KIND, "copy_version": 1, "source_run": RUN,
            "public_run": PUBLIC, "ruleset": "opentine-redaction/2", "objects": 9,
            "redacted": 2, "pack": PACK, **fields}  # fmt: skip


def _c(name, expect, intent, record, reason=None, *, hmac=None, public=None, pack=None) -> Case:
    value = {"record": record, "hmac_key_hex": hmac, "public_key": public, "pack": pack}
    return Case(id=f"redacted-copy.{name}", section="4.15", checklist=(8,),
                op="redacted-copy.verify", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


_C_HMAC = _signed(_redacted_copy, _copy(), "hmac")
_C_ED = _signed(_redacted_copy, _copy(), "ed25519_seed")
_SAME = _signed(_redacted_copy, _copy(public_run=RUN, redacted=0), "hmac")

REDACTED_COPY = Family(
    "64-redacted-copy.json",
    "4.15",
    "redacted-copy",
    (
        _c("valid-hmac", ACCEPT, "an HMAC record verifies under its key", _C_HMAC, hmac=_HMAC_A),
        _c("valid-hmac-pack", ACCEPT, "a record checked against the pack it came with",
           _C_HMAC, hmac=_HMAC_A, pack=PACK),
        _c("valid-nothing-redacted", ACCEPT, "nothing redacted: the copy is the run itself",
           _SAME, hmac=_HMAC_A),
        _c("valid-ed25519-trusted", ACCEPT, "an Ed25519 record under the trusted key", _C_ED,
           public=_public("ed25519_seed")),
        _c("valid-ed25519-tofu", ACCEPT, "with no key, an Ed25519 record on its embedded key",
           _C_ED),
        _c("source-edited", REJECT, "a record re-pointed at another private run",
           _edited(_C_HMAC, source_run="run:sha256:" + "6" * 64),
           "redacted-copy.bad-signature", hmac=_HMAC_A),
        _c("wrong-key", REJECT, "an Ed25519 record by a key other than the trusted one", _C_ED,
           "redacted-copy.wrong-key", public=_public("ed25519_seed_b")),
        _c("hmac-key-ed25519-record", REJECT, "a supplied HMAC key never falls back to TOFU",
           _C_ED, "redacted-copy.wrong-key", hmac=_HMAC_A),
        _c("no-key", REJECT, "an HMAC record with no key cannot verify", _C_HMAC,
           "redacted-copy.no-key"),
        _c("unsigned", REJECT, "a record without a signature is refused", _copy(),
           "redacted-copy.unsigned", hmac=_HMAC_A),
        _c("pack-mismatch", REJECT, "a record that names another pack than the bundled one",
           _C_HMAC, "redacted-copy.pack-mismatch", hmac=_HMAC_A, pack="sha256:" + "7" * 64),
        _c("redacted-but-same-run", REJECT, "objects changed yet the run oid did not",
           _raw_sign(_redacted_copy.DOMAIN, _copy(public_run=RUN)),
           "redacted-copy.inconsistent", hmac=_HMAC_A),
        _c("more-redacted-than-objects", REJECT, "redacted exceeds objects",
           _raw_sign(_redacted_copy.DOMAIN, _copy(redacted=10)),
           "redacted-copy.inconsistent", hmac=_HMAC_A),
        _c("bad-pack-digest", REJECT, "pack must be sha256:<64 hex>",
           _edited(_C_HMAC, pack="sha256:XYZ"), "redacted-copy.malformed", hmac=_HMAC_A),
        _c("extra-field", REJECT, "a field the record format does not define",
           _edited(_C_HMAC, note="x"), "redacted-copy.malformed", hmac=_HMAC_A),
        _c("wrong-version", REJECT, "a copy_version other than 1",
           _edited(_C_HMAC, copy_version=2), "redacted-copy.malformed", hmac=_HMAC_A),
    ),
)  # fmt: skip

FAMILIES = (TOMBSTONE, REDACTED_COPY)
