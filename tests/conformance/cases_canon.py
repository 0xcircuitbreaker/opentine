"""SPEC Part 0: the tagged-value self-test, text validity, both canonical JSON
forms, their divergence, and the structural byte scanner."""

from __future__ import annotations

import base64
import math

from tests.conformance.builders import (
    CESU8_BLOB,
    RUN_ID,
    SIG_HEADER,
    envelope_bytes,
)
from tests.conformance.cases import ACCEPT, REJECT, B, Case, Family, G, V

READER, WRITER, VERIFIER = "reader", "writer", "verifier"


def _c(**kwargs) -> Case:
    return Case(**kwargs)


# --------------------------------------------------------------------------- #
# 01 -- the tagged-number reader self-test
# --------------------------------------------------------------------------- #

SELFTEST = Family(
    "01-selftest.json",
    "0.2",
    "selftest",
    (
        _c(
            id="selftest.tag.integer",
            section="0.2",
            checklist=(2,),
            op="canon.v3",
            profile=READER,
            expect=ACCEPT,
            intent='{"$i":"1"} denotes the integer 1, which v3 renders as the literal 1',
            input=V({"n": 1}),
        ),
        _c(
            id="selftest.tag.integer-beyond-double",
            section="0.3",
            checklist=(2,),
            op="canon.v2",
            profile=READER,
            expect=ACCEPT,
            intent="$i carries an integer no IEEE-754 double can hold; v2 has no magnitude bound",
            input=V({"n": 12345678901234567890123456789}),
        ),
        _c(
            id="selftest.tag.float-integral",
            section="0.3",
            checklist=(2,),
            op="canon.v2",
            profile=READER,
            expect=ACCEPT,
            intent='{"$f":"1.0"} is a double, not an integer, and v2 keeps its .0 suffix',
            input=V({"n": 1.0}),
        ),
        _c(
            id="selftest.tag.dollar-object-escape",
            section="0.2",
            checklist=(2,),
            op="canon.v3",
            profile=READER,
            expect=ACCEPT,
            intent='{"$obj":{"$i":"x"}} denotes a real object whose sole key is the string $i',
            input=V({"$i": "x"}),
        ),
        _c(
            id="selftest.tag.code-units-and-keys",
            section="0.3",
            checklist=(2,),
            op="canon.v2",
            profile=READER,
            expect=ACCEPT,
            intent='{"$u":["d800"]} is a string given as its UTF-16 code units, and '
            '{"$obj":[[key,value],...]} carries a key that needs that spelling; both '
            "exist so a vector file never has to contain a lone surrogate itself",
            input=V({"\ud800": 1, "a": 2}),
            requires=("wtf8",),
        ),
        _c(
            id="selftest.untagged.strings-and-literals",
            section="0.2",
            checklist=(2,),
            op="canon.v3",
            profile=READER,
            expect=ACCEPT,
            intent="strings, booleans and null are literal JSON; nothing about them is tagged",
            input=V({"f": False, "n": None, "s": "$i", "t": True}),
        ),
        _c(
            id="selftest.untagged.arrays-and-objects",
            section="0.2",
            checklist=(2,),
            op="canon.v3",
            profile=READER,
            expect=ACCEPT,
            intent="arrays and multi-key objects are literal; only a single $-key object escapes",
            input=V({"a": [1, "x", None], "b": {"$i": "1", "other": 2}}),
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 00 -- text validity
# --------------------------------------------------------------------------- #

_SURROGATE_REPAIR = "substitute U+FFFD, which rewrites recorded output under a fidelity digest"


def _text_reject(name: str, raw: bytes, intent: str) -> Case:
    return _c(
        id=name,
        section="0.1",
        checklist=(1,),
        op="text.validate",
        profile=READER,
        expect=REJECT,
        reason="text.lone-surrogate",
        intent=intent,
        repair_temptation=_SURROGATE_REPAIR,
        input=B(raw),
    )


def _text_accept(name: str, raw: bytes, intent: str) -> Case:
    return _c(
        id=name,
        section="0.1",
        checklist=(1,),
        op="text.validate",
        profile=READER,
        expect=ACCEPT,
        intent=intent,
        input=B(raw),
    )


TEXT = Family(
    "00-text.json",
    "0.1",
    "text",
    (
        _text_reject(
            "text.surrogate.value-escape",
            b'{"k":"\\ud800"}',
            "a lone high surrogate as a \\uXXXX escape in a string value is not a scalar value",
        ),
        _text_reject(
            "text.surrogate.key-escape",
            b'{"\\ud800":1}',
            "the same rule applies to an object key, which no UTF-8 encoder can spell",
        ),
        _text_reject(
            "text.surrogate.value-raw-cesu8",
            b'{"k":"\xed\xa0\x80"}',
            "raw CESU-8 bytes ED A0 80 decode to the same lone code unit without any escape",
        ),
        _text_reject(
            "text.surrogate.key-raw-cesu8",
            b'{"\xed\xa0\x80":1}',
            "raw CESU-8 surrogate bytes in a key are refused exactly as the escape spelling is",
        ),
        _text_reject(
            "text.surrogate.low-escape",
            b'{"k":"\\udfff"}',
            "a lone LOW surrogate is refused too; the rule is the whole D800-DFFF range",
        ),
        _text_reject(
            "text.surrogate.low-raw-cesu8",
            b'{"k":"\xed\xbf\xbf"}',
            "ED BF BF is the raw spelling of U+DFFF and is refused with its escape twin",
        ),
        _text_reject(
            "text.surrogate.split-emoji-high",
            b'{"k":"\\ud83d"}',
            "the lead half of a mid-emoji slice, the shape a streamed JSON producer emits",
        ),
        _text_reject(
            "text.surrogate.nested-in-array",
            b'{"k":[{"deep":"\\udbff"}]}',
            "the rule is over every string in the document, not only top-level values",
        ),
        _text_reject(
            "text.surrogate.mixed-with-valid",
            b'{"ok":"fine","bad":"a\\udc00b"}',
            "one bad string refuses the whole document; valid siblings do not rescue it",
        ),
        _text_accept(
            "text.boundary.u-d7ff",
            b'{"k":"\xed\x9f\xbf"}',
            "ED 9F BF is U+D7FF, ordinary text one code point below the surrogate range",
        ),
        _text_accept(
            "text.boundary.u-e000",
            b'{"k":"\xee\x80\x80"}',
            "EE 80 80 is U+E000, ordinary text one code point above the surrogate range",
        ),
        _text_accept(
            "text.pair.escaped-emoji",
            b'{"k":"\\ud83d\\ude00"}',
            "a correctly paired escape denotes U+1F600, a scalar value, and is ordinary text",
        ),
        _text_accept(
            "text.pair.raw-emoji",
            b'{"k":"\xf0\x9f\x98\x80"}',
            "the same character spelled as raw UTF-8 is the same ordinary text",
        ),
        _c(
            id="text.blob.cesu8-stores-unchanged",
            section="0.1",
            checklist=(1, 9),
            op="envelope.decode",
            profile=READER,
            expect=ACCEPT,
            intent="the one exception: a blob is a byte string, so CESU-8 bytes store unchanged",
            input=B(CESU8_BLOB),
        ),
        _c(
            id="text.blob.raw-invalid-utf8",
            section="0.1",
            checklist=(1, 9),
            op="envelope.decode",
            profile=READER,
            expect=ACCEPT,
            intent="a raw blob body is opaque: bytes that are not UTF-8 at all store unchanged",
            input=B(envelope_bytes("blob", 1, "raw", b"\xff\xfe\x00\n")),
        ),
        _c(
            id="text.blob.cesu8-json-body-refused",
            section="0.1",
            checklist=(1, 2),
            op="envelope.decode",
            profile=READER,
            expect=REJECT,
            reason="canon.unencodable-text",
            intent="the exception is for blobs only: the same bytes inside a json body refuse",
            repair_temptation=_SURROGATE_REPAIR,
            twin="text.blob.cesu8-stores-unchanged",
            input=B(envelope_bytes("event", 1, "json", b'{"k":"\xed\xa0\x80"}')),
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 02 -- v3 canonical JSON
# --------------------------------------------------------------------------- #

_V3_LADDER = (
    ("zero", 0.0),
    ("negative-zero", -0.0),
    ("one", 1.0),
    ("1e20", 1e20),
    ("1e21", 1e21),
    ("1e-6", 1e-6),
    ("1e-7", 1e-7),
    ("1e16", 1e16),
    ("1e-5", 1e-5),
    ("1e308", 1e308),
)


def _v3(name: str, expect: str, intent: str, value, **extra) -> Case:
    return _c(
        id=f"canon.v3.{name}",
        section="0.2",
        checklist=(2,),
        op="canon.v3",
        profile=READER,
        expect=expect,
        intent=intent,
        input=value
        if isinstance(value, dict) and ("gen" in value or "value" in value)
        else V(value),
        **extra,
    )


CANON_V3 = Family(
    "02-canon-v3.json",
    "0.2",
    "canon-v3",
    (
        *(
            _v3(
                f"float.{name}",
                ACCEPT,
                "rule 8: the shortest round-tripping decimal, positional inside "
                "[1e-6, 1e21) and exponential outside it",
                {"n": value},
            )
            for name, value in _V3_LADDER
        ),
        _v3(
            "integer.max-safe",
            ACCEPT,
            "rule 7: 2**53-1 is the largest integer the v3 form will render",
            {"n": 9007199254740991},
        ),
        _v3(
            "integer.min-safe",
            ACCEPT,
            "rule 7 is symmetric: -(2**53-1) renders with a leading minus and no padding",
            {"n": -9007199254740991},
        ),
        _v3("integer.zero", ACCEPT, "rule 7: the integer zero renders as a bare 0", {"n": 0}),
        _v3(
            "string.escapes",
            ACCEPT,
            "rule 5: only the seven named escapes and \\u00XX below U+0020 are escaped",
            {"k": '"\\\b\f\n\r\t\x1f'},
        ),
        _v3(
            "string.solidus-and-del",
            ACCEPT,
            "rule 5: / and DEL (U+007F) go through literally; neither is escaped",
            {"k": "/\x7f"},
        ),
        _v3(
            "string.non-ascii-literal",
            ACCEPT,
            "rule 1: non-ASCII is emitted literally as UTF-8, never as a \\uXXXX escape",
            {"k": "é☃"},
        ),
        _v3(
            "key.order-bmp",
            ACCEPT,
            "rule 3: members are ordered by the key's UTF-16BE code units, so a sorts before b",
            {"b": 1, "a": 2},
        ),
        _v3(
            "key.order-bmp-boundary",
            ACCEPT,
            "rule 3: for BMP keys UTF-16BE order equals code-point order",
            {"Ā": 1, "ÿ": 2},
        ),
        _v3("key.empty-string", ACCEPT, "rule 4: the empty string is a legal key", {"": 1}),
        _v3(
            "literals.null-true-false",
            ACCEPT,
            "rule 6: the three literals are spelled exactly null, true and false",
            {"f": False, "n": None, "t": True},
        ),
        _v3(
            "array.order-preserved",
            ACCEPT,
            "rule 9: canonicalization never sorts an array",
            {"a": [3, 1, 2]},
        ),
        _v3("object.empty", ACCEPT, "an empty object renders as two bytes", {}),
        _v3("array.empty", ACCEPT, "an empty array renders as two bytes", []),
        _v3(
            "separators.no-whitespace",
            ACCEPT,
            "rule 2: , and : carry no whitespace anywhere, and there is no trailing newline",
            {"a": [1, {"b": 2}], "c": {}},
        ),
        _v3(
            "depth.at-512",
            ACCEPT,
            "rule 10: 512 nested containers is the deepest value the encoder will render",
            G({"kind": "nest-value", "container": "array", "depth": 512, "inner": {"$i": "0"}}),
            spec_note=(
                "SPEC 0.2 rule 10 says nesting is rejected 'at or beyond 512 levels'; the "
                "encoder accepts 512 nested containers and rejects 513."
            ),
            twin="canon.v3.depth.at-513",
        ),
        _c(
            id="canon.v3.demotion.fixpoint",
            section="0.2",
            checklist=(2, 3),
            op="envelope.decode",
            profile=READER,
            expect=ACCEPT,
            intent=(
                "the integer-literal demotion hazard: a body holding 1e20's canonical spelling "
                "must re-encode to itself, which is impossible without demoting the literal "
                "back to the float it came from"
            ),
            repair_temptation=(
                "read 100000000000000000000 as an integer, then refuse to re-encode it as one, "
                "calling a legitimately written object corrupt"
            ),
            input=B(envelope_bytes("event", 1, "json", b'{"n":100000000000000000000}')),
        ),
        _v3(
            "float.nan",
            REJECT,
            "rule 8: NaN has no canonical JSON spelling and is refused, never mapped to null",
            {"n": math.nan},
            reason="canon.non-finite",
            repair_temptation="emit null, or the JavaScript literal NaN",
        ),
        _v3(
            "float.positive-infinity",
            REJECT,
            "rule 8: +Infinity is refused for the same reason",
            {"n": math.inf},
            reason="canon.non-finite",
        ),
        _v3(
            "float.negative-infinity",
            REJECT,
            "rule 8: -Infinity is refused for the same reason",
            {"n": -math.inf},
            reason="canon.non-finite",
        ),
        _v3(
            "integer.at-2-53",
            REJECT,
            "rule 7: 2**53 exceeds the bound and is refused, not rounded",
            {"n": 9007199254740992},
            reason="canon.integer-overflow",
            repair_temptation="round to the nearest double, losing the exact value",
            twin="canon.v2.integer.at-2-53",
        ),
        _v3(
            "integer.negative-2-53",
            REJECT,
            "rule 7 is symmetric: -2**53 is refused as well",
            {"n": -9007199254740992},
            reason="canon.integer-overflow",
        ),
        _v3(
            "depth.at-513",
            REJECT,
            "rule 10: the 513th nested container is refused",
            G({"kind": "nest-value", "container": "array", "depth": 513, "inner": {"$i": "0"}}),
            reason="canon.depth-exceeded",
            twin="canon.v3.depth.at-512",
        ),
        _v3(
            "surrogate.value",
            REJECT,
            "rule 1: a lone surrogate has no UTF-8 spelling, so the v3 form cannot encode it",
            {"k": "\ud800"},
            reason="canon.unencodable-text",
            repair_temptation=_SURROGATE_REPAIR,
            twin="canon.v2.surrogate.value-accepts",
            requires=("wtf8",),
        ),
        _v3(
            "surrogate.key",
            REJECT,
            "the same rule over an object key",
            {"\ud800": 1},
            reason="canon.unencodable-text",
            repair_temptation=_SURROGATE_REPAIR,
            requires=("wtf8",),
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 03 -- v2 canonical JSON
# --------------------------------------------------------------------------- #

_V2_LADDER = _V3_LADDER + (("small-positional", 0.0001),)


def _v2(name: str, expect: str, intent: str, value, **extra) -> Case:
    return _c(
        id=f"canon.v2.{name}",
        section="0.3",
        checklist=(2,),
        op="canon.v2",
        profile=READER,
        expect=expect,
        intent=intent,
        input=V(value),
        **extra,
    )


CANON_V2 = Family(
    "03-canon-v2.json",
    "0.3",
    "canon-v2",
    (
        *(
            _v2(
                f"float.{name}",
                ACCEPT,
                "rule 5: CPython repr() spelling -- an integral value keeps .0, the sign of "
                "zero is preserved, and the exponent carries a sign and two digits",
                {"n": value},
            )
            for name, value in _V2_LADDER
        ),
        _v2(
            "integer.at-2-53",
            ACCEPT,
            "rule 4: v2 has no 2**53 rule, so the one input the two forms disagree about "
            "*accepting* is an integer at 2**53",
            {"n": 9007199254740992},
            twin="canon.v3.integer.at-2-53",
        ),
        _v2(
            "integer.4097-digits-accepts",
            ACCEPT,
            "rule 4's 4096-digit bound belongs to the .tine layer, not to this canonicalizer",
            {"n": int("9" * 4097)},
            spec_note=(
                "SPEC 0.3 rule 4's 4096-digit bound is enforced at the .tine layer "
                "(_artifact_io), not by _canonical_bytes; this op accepts a 4097-digit "
                "integer that artifact.parse refuses."
            ),
            twin="artifact.integer.4097-digits",
        ),
        _v2(
            "surrogate.value-accepts",
            ACCEPT,
            "the v2 canonicalizer alone does not refuse a lone surrogate: it escapes it",
            {"k": "\ud800"},
            spec_note=(
                "SPEC 0.1 says both formats reject a lone surrogate at write and at read; "
                "_canonical_bytes alone does not -- the refusal lives in "
                "_artifact_io.parse_artifact_json and _v3_guards.guarded_redaction."
            ),
            twin="canon.v3.surrogate.value",
            requires=("wtf8",),
        ),
        _v2(
            "surrogate.key-accepts",
            ACCEPT,
            "the same for an object key: the escape is emitted, and the refusal is elsewhere",
            {"\ud800": 1},
            twin="canon.v3.surrogate.key",
            requires=("wtf8",),
        ),
        _v2(
            "escaping.non-ascii",
            ACCEPT,
            "rule 1: ensure_ascii is on, so every non-ASCII character becomes a \\uXXXX escape",
            {"k": "é☃"},
        ),
        _v2(
            "escaping.non-bmp-surrogate-pair",
            ACCEPT,
            "rule 1: a non-BMP character is escaped as its UTF-16 surrogate *pair*",
            {"k": "\U0001f600"},
        ),
        _v2(
            "key.order-code-point",
            ACCEPT,
            "rule 3: members are ordered by the key's Unicode code points",
            {"b": 1, "a": 2},
        ),
        _v2("key.empty-string", ACCEPT, "the empty string is a legal key here too", {"": 1}),
        _v2(
            "literals.null-true-false",
            ACCEPT,
            "the three literals are spelled exactly as JSON requires",
            {"f": False, "n": None, "t": True},
        ),
        _v2(
            "array.order-preserved",
            ACCEPT,
            "rule 2/3: sort_keys orders object members and never touches an array",
            {"a": [3, 1, 2]},
        ),
        _v2("object.empty", ACCEPT, "an empty object renders as two bytes", {}),
        _v2(
            "string.escapes",
            ACCEPT,
            "the same seven named escapes, and \\u00XX below U+0020",
            {"k": '"\\\b\f\n\r\t\x1f'},
        ),
        _v2(
            "float.nan",
            REJECT,
            "rule 5: NaN is refused by the explicit check in _jsonable",
            {"n": math.nan},
            reason="canon.non-finite",
            twin="canon.v3.float.nan",
        ),
        _v2(
            "float.positive-infinity",
            REJECT,
            "rule 5: +Infinity is refused",
            {"n": math.inf},
            reason="canon.non-finite",
        ),
        _v2(
            "float.negative-infinity",
            REJECT,
            "rule 5: -Infinity is refused",
            {"n": -math.inf},
            reason="canon.non-finite",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 04 -- the divergence
# --------------------------------------------------------------------------- #

_NONBMP_KEYS = {"": 1, "\U00010000": 2}
_HAZARD_PAYLOAD = {
    "claim": {"n": 1e20, "\U00010000": 1, "": 2},
    "evidence_ids": [],
    "signer": "release-bot",
    "target_id": RUN_ID,
}


def _jcs_mistake() -> str:
    """The HMAC an implementer gets by reaching for JCS on a v3 object's message.

    Computed here rather than quoted, so it stays true if the scheme changes.
    """
    import hashlib
    import hmac

    from opentine._attest_view import ATTEST_DOMAIN_PREFIX, signed_view
    from opentine.kernel import canonical_json
    from tests.conformance.keys import HMAC_A

    wrong = ATTEST_DOMAIN_PREFIX + canonical_json(signed_view(_HAZARD_PAYLOAD, SIG_HEADER))
    return hmac.new(HMAC_A, wrong, hashlib.sha256).hexdigest()


#: A .tine body carrying both halves of the SPEC 0.4 divergence -- a non-BMP key
#: that the two canonicalizers order differently, and a float the two spell
#: differently. tine-sig/1 and tine-sig/2 both sign the whole body, so it reaches
#: their signed view under either scheme.
_ARTIFACT_HAZARD_DOC = {"n": 1e20, "\U00010000": 1, "\ue000": 2}


def _artifact_v3_mistake(scheme: str) -> dict:
    """The message an implementer gets by canonicalizing a .tine signature under v3.

    Computed with the reference, never transcribed. SPEC 0.4's hazard is usually
    told about ``tine-attest/1`` -- a v3 object signed under the v2 form -- but
    the artifact schemes have the mirror trap: a reader that has already written a
    v3 canonicalizer for object ids reaches for it here too.
    """
    import hashlib
    import hmac

    from opentine._signing_view import DOMAIN_PREFIX, signed_view
    from opentine.kernel import canonical_json
    from tests.conformance.keys import HMAC_A

    header = {**SIG_HEADER, "scheme": scheme}
    wrong = DOMAIN_PREFIX + canonical_json(signed_view(_ARTIFACT_HAZARD_DOC, header))
    return {
        "message_b64": base64.b64encode(wrong).decode("ascii"),
        "value": hmac.new(HMAC_A, wrong, hashlib.sha256).hexdigest(),
    }


def _artifact_hazard(scheme: str, name: str, twin: str) -> Case:
    return _c(
        id=f"sig.artifact.hazard.nonbmp-1e20.{name}",
        section="0.4",
        checklist=(2, 8),
        op="sig.message",
        profile=VERIFIER,
        expect=ACCEPT,
        args={"scheme": scheme, "key": "hmac_a"},
        intent=(
            f"{scheme} signs a .tine document under the SPEC 0.3 canonicalizer, the same as "
            "tine-attest/1 does -- all three schemes share one canonical form. This body "
            "carries a non-BMP key and a float the two forms disagree about, so a signer "
            "that reaches for the v3 canonicalizer it already wrote for object ids answers "
            "with different bytes"
        ),
        repair_temptation=(
            "canonicalize a .tine signature under SPEC 0.2 because the repository objects "
            "beside it are canonicalized that way"
        ),
        forbidden=_artifact_v3_mistake(scheme),
        must_differ=True,
        twin=twin,
        input=V({"document": _ARTIFACT_HAZARD_DOC, "header": {**SIG_HEADER, "scheme": scheme}}),
    )


def _forbidden(value, which: str) -> dict | None:
    """The bytes the *other* canonicalizer produces, so no single one passes both.

    Computed with the reference, never transcribed: an implementation that
    answers with this has used SPEC 0.3 where 0.2 was required, or the reverse,
    and the runner reports REPAIRED rather than FAIL.
    """
    from opentine._canon import _canonical_bytes
    from opentine.kernel import canonical_json

    other = _canonical_bytes(value) if which == "v3" else canonical_json(value)
    return {"bytes_b64": base64.b64encode(other).decode("ascii")}


def _pair(name: str, value, intent_v3: str, intent_v2: str, differ: bool) -> tuple[Case, Case]:
    v3 = _c(
        id=f"canon.divergence.{name}.v3",
        section="0.4",
        checklist=(2,),
        op="canon.v3",
        profile=READER,
        expect=ACCEPT,
        must_differ=differ,
        intent=intent_v3,
        twin=f"canon.divergence.{name}.v2",
        forbidden=_forbidden(value, "v3") if differ else None,
        input=V(value),
    )
    v2 = _c(
        id=f"canon.divergence.{name}.v2",
        section="0.4",
        checklist=(2,),
        op="canon.v2",
        profile=READER,
        expect=ACCEPT,
        must_differ=differ,
        intent=intent_v2,
        twin=f"canon.divergence.{name}.v3",
        forbidden=_forbidden(value, "v2") if differ else None,
        input=V(value),
    )
    return v3, v2


DIVERGENCE = Family(
    "04-divergence.json",
    "0.4",
    "divergence",
    (
        *_pair(
            "nonbmp-key",
            _NONBMP_KEYS,
            "v3 orders members by UTF-16BE code unit, so U+10000's lead surrogate sorts "
            "below U+E000 and the non-BMP key comes first",
            "v2 orders members by code point, so U+E000 comes first -- the same input, the "
            "opposite order",
            True,
        ),
        *_pair(
            "float-integral",
            {"n": 1.0},
            "v3 renders an integral double as a bare integer literal",
            "v2 keeps repr()'s .0 suffix, so the same double is two different byte strings",
            True,
        ),
        *_pair(
            "negative-zero",
            {"n": -0.0},
            "v3 discards the sign of zero",
            "v2 preserves it",
            True,
        ),
        *_pair(
            "non-ascii-value",
            {"k": "é"},
            "v3 emits non-ASCII literally as UTF-8",
            "v2 escapes it as \\u00e9, so the byte streams differ even for one BMP character",
            True,
        ),
        *_pair(
            "ascii-agreement",
            {"a": 1, "b": "x", "c": [1, 2]},
            "with ASCII keys, integer values and no floats the two forms coincide",
            "the control: an implementation cannot pass by always returning two answers",
            False,
        ),
        *_pair(
            "nested-agreement",
            {"outer": {"inner": [{"k": None}, True, False]}},
            "structure alone does not diverge; only numbers, non-ASCII and non-BMP keys do",
            "the second control, over containers rather than scalars",
            False,
        ),
        _c(
            id="sig.attest.hazard.nonbmp-1e20",
            section="0.4",
            checklist=(2, 8),
            op="sig.message",
            profile=VERIFIER,
            expect=ACCEPT,
            args={"scheme": "tine-attest/1", "key": "hmac_a"},
            intent=(
                "tine-attest/1 signs a v3 object using the v2 canonicalizer: the same payload "
                "that is *stored* under 0.2 is *signed* under 0.3, and this input is chosen so "
                "the two disagree on both the float spelling and the key order"
            ),
            repair_temptation=(
                "reach for JCS because the object is v3, producing a different message and a "
                "signature that verifies nowhere"
            ),
            forbidden={"value": _jcs_mistake()},
            input=V({"document": _HAZARD_PAYLOAD, "header": SIG_HEADER}),
        ),
        _artifact_hazard("tine-sig/1", "v1", "sig.artifact.hazard.nonbmp-1e20.v2"),
        _artifact_hazard("tine-sig/2", "v2", "sig.artifact.hazard.nonbmp-1e20.v1"),
        _c(
            id="sig.attest.hazard.non-finite-claim",
            section="0.4",
            checklist=(2, 8),
            op="sig.message",
            profile=VERIFIER,
            expect=REJECT,
            reason="canon.non-finite",
            intent=(
                "the divergence is about spelling, not about what is signable: both forms "
                "refuse a non-finite claim value, so no message exists to sign"
            ),
            args={"scheme": "tine-attest/1"},
            input=V(
                {
                    "document": {
                        "claim": {"n": math.inf},
                        "evidence_ids": [],
                        "signer": "release-bot",
                        "target_id": RUN_ID,
                    },
                    "header": SIG_HEADER,
                }
            ),
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 05 -- the structural byte scanner
# --------------------------------------------------------------------------- #


def _shape(name: str, expect: str, intent: str, spec_input, **extra) -> Case:
    return _c(
        id=f"shape.{name}",
        section="0.5",
        checklist=(5,),
        op="shape.scan",
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


SHAPE = Family(
    "05-shape.json",
    "0.5",
    "shape",
    (
        _shape(
            "depth.at-512",
            ACCEPT,
            "the running bracket depth may reach 512 but not exceed it",
            G({"kind": "nest", "open": "[", "close": "]", "depth": 512, "inner": "0"}),
            twin="shape.depth.at-513",
        ),
        _shape(
            "depth.at-512-objects",
            ACCEPT,
            "{ and } count exactly as [ and ] do",
            G({"kind": "nest", "open": "{", "close": "}", "depth": 512, "inner": ""}),
        ),
        _shape(
            "tokens.at-budget",
            ACCEPT,
            "[ { , : ] } each count one; a document exactly at the budget is accepted",
            B(b"[[[[]]]]"),
            args={"max_tokens": 8},
            twin="shape.tokens.one-over-budget",
        ),
        _shape(
            "string.brackets-ignored",
            ACCEPT,
            "characters inside a string literal are skipped, so brackets in a value are free",
            B(b'{"k":"[[[[[[[[[["}'),
            args={"max_tokens": 4},
        ),
        _shape(
            "string.escaped-quote",
            ACCEPT,
            "a backslash-escaped quote does not end the string, so its brackets stay skipped",
            B(b'{"k":"\\"[[[["}'),
            args={"max_tokens": 4},
        ),
        _shape(
            "negative-depth-tolerated",
            ACCEPT,
            "this is a byte scanner, not a parser: unbalanced closers drive depth negative and "
            "are not its business; the grammar error surfaces from the later parse",
            B(b"}]}]"),
        ),
        _shape(
            "depth.at-513",
            REJECT,
            "the 513th open bracket exceeds MAX_JSON_DEPTH",
            G({"kind": "nest", "open": "[", "close": "]", "depth": 513, "inner": "0"}),
            reason="shape.depth-exceeded",
            twin="shape.depth.at-512",
        ),
        _shape(
            "depth.at-513-objects",
            REJECT,
            "the object spelling of the same bound",
            G({"kind": "nest", "open": "{", "close": "}", "depth": 513, "inner": ""}),
            reason="shape.depth-exceeded",
        ),
        _shape(
            "depth.mixed-containers",
            REJECT,
            "depth counts both container kinds together, not one bound each",
            G({"kind": "nest", "open": "[", "close": "]", "depth": 600, "inner": "0"}),
            reason="shape.depth-exceeded",
        ),
        _shape(
            "tokens.one-over-budget",
            REJECT,
            "one structural token past the caller's budget refuses the whole document",
            B(b"[[[[]]]]"),
            args={"max_tokens": 7},
            reason="shape.tokens-exceeded",
            twin="shape.tokens.at-budget",
        ),
        _shape(
            "tokens.config-budget",
            REJECT,
            "the config call site's budget is 10 000 tokens, and it is a real refusal",
            G(
                {
                    "kind": "repeat",
                    "unit_b64": "W10s",
                    "count": 4000,
                    "prefix_b64": "Ww==",
                    "suffix_b64": "W11d",
                }
            ),
            args={"max_tokens": 10_000},
            reason="shape.tokens-exceeded",
        ),
        _shape(
            "tokens.minimal-budget",
            REJECT,
            "an empty object already costs two structural tokens",
            B(b"{}"),
            args={"max_tokens": 1},
            reason="shape.tokens-exceeded",
        ),
    ),
)

FAMILIES = (SELFTEST, TEXT, CANON_V3, CANON_V2, DIVERGENCE, SHAPE)
