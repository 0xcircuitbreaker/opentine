"""SPEC Part 6 item 9: the repairs an implementation MUST NOT perform.

Every case here is a **reject**, and every case carries ``forbidden``: the
answer a wrong-but-plausible implementation returns when it repairs the input
instead of refusing it. A runner whose output equals ``forbidden`` reports
``REPAIRED`` rather than ``FAIL``, because the two are different failures: a
``FAIL`` says the implementation disagreed, a ``REPAIRED`` says it accepted
input that no other reader will read the same way and produced a digest that
claims fidelity to bytes it silently changed.

Most published vector suites test only accepts. This family is the reason this
one exists.
"""

from __future__ import annotations

import base64
import math

from opentine.kernel import canonical_json
from tests.conformance.builders import (
    HELLO_OID,
    LINKED_EVENT,
    LINKED_EVENT_OID,
    json_object,
    pack_frame_from_body,
)
from tests.conformance.cases import REJECT, B, Case, Family, V

READER = "reader"


def _repair(name, section, op, intent, forbidden, spec_input, reason, **extra) -> Case:
    return Case(
        id=f"repair.{name}",
        section=section,
        checklist=(9,),
        op=op,
        profile=extra.pop("profile", READER),
        expect=REJECT,
        reason=reason,
        intent=intent,
        input=spec_input,
        forbidden=forbidden,
        **extra,
    )


_WHITESPACE_DATA = (
    base64.b64encode(LINKED_EVENT).decode("ascii")[:8]
    + " "
    + base64.b64encode(LINKED_EVENT).decode("ascii")[8:]
)
_WHITESPACE_BODY = canonical_json(
    {
        "objects": [{"data": _WHITESPACE_DATA, "id": LINKED_EVENT_OID}],
        "shallow": [HELLO_OID],
        "version": 1,
    }
)
_EXTRA_KEY_BODY = canonical_json(
    {"generator": "someone-elses-writer", "objects": [], "shallow": [], "version": 1}
)
_CLEAN_BODY = canonical_json({"objects": [], "shallow": [], "version": 1})


def _pack_id(body: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(body).hexdigest()}"


REPAIR = Family(
    "99-repair.json",
    "6",
    "repair",
    (
        _repair(
            "surrogate-to-replacement-character",
            "0.1",
            "text.validate",
            "substituting U+FFFD rewrites recorded model output under a digest that claims "
            "fidelity to it; Go does this by default, which is why the rule is explicit",
            {},
            B(b'{"k":"\\ud800"}'),
            "text.lone-surrogate",
            repair_temptation="decode with a lossy UTF-8 codec",
        ),
        _repair(
            "header-reserialized-canonically",
            "1.2",
            "envelope.decode",
            "re-serializing a non-canonical header and continuing gives two byte strings one "
            "object id -- content addressing stops meaning anything",
            {"oid": HELLO_OID},
            B(b'{"schema":1,"encoding":"raw","type":"blob"}\nhello\n'),
            "envelope.header-non-canonical",
            repair_temptation="parse, re-serialize, and carry on",
        ),
        _repair(
            "header-unknown-key-dropped",
            "1.2",
            "envelope.decode",
            "an unknown header key is not a forward-compatibility slot: dropping it lands on "
            "the id of a *different*, legitimate object",
            {"oid": HELLO_OID},
            B(b'{"encoding":"raw","extra":1,"schema":1,"type":"blob"}\nhello\n'),
            "envelope.header-key-count",
            repair_temptation="ignore keys you do not recognise",
        ),
        _repair(
            "integer-rounded-to-a-double",
            "0.2",
            "canon.v3",
            "rounding 2**53 to the nearest double loses the exact value the writer recorded, "
            "and the canonical bytes then name a number nobody wrote",
            {"bytes_b64": base64.b64encode(b'{"n":9007199254740992}').decode("ascii")},
            V({"n": 9007199254740992}),
            "canon.integer-overflow",
            repair_temptation="round to the nearest representable double",
        ),
        _repair(
            "nan-to-null",
            "0.2",
            "canon.v3",
            "mapping NaN to null turns a measurement that failed into a measurement that was "
            "not taken",
            {"bytes_b64": base64.b64encode(b'{"n":null}').decode("ascii")},
            V({"n": math.nan}),
            "canon.non-finite",
            repair_temptation="emit null for anything that will not serialize",
        ),
        _repair(
            "artifact-nul-stripped",
            "3.7",
            "artifact.parse",
            "a NUL is a parser differential: strip it and your reader and the next one hold "
            "different strings while both report success",
            {"top_level_keys": ["format_version", "run_id"]},
            B(b'{"format_version": 2, "run_id": "a\x00b"}'),
            "artifact.nul-byte",
            repair_temptation="strip control characters before parsing",
        ),
        _repair(
            "artifact-duplicate-key-last-wins",
            "3.7",
            "artifact.parse",
            "last-wins is what every unguarded JSON parser does, and it is exactly how two "
            "readers come to disagree about a document they both accepted",
            {"top_level_keys": ["format_version", "run_id"]},
            B(b'{"format_version": 2, "run_id": "a", "run_id": "b"}'),
            "artifact.duplicate-key",
            repair_temptation="keep the last value, as the JSON spec permits",
        ),
        _repair(
            "artifact-nan-literal-to-null",
            "3.7",
            "artifact.parse",
            "the same substitution at the .tine layer, where the value is a recorded cost",
            {"top_level_keys": ["cost", "format_version"]},
            B(b'{"format_version": 2, "cost": NaN}'),
            "artifact.non-finite",
            repair_temptation="accept the Python/JavaScript extension literals",
        ),
        _repair(
            "pack-base64-whitespace-stripped",
            "2.8",
            "pack.inspect",
            "base64 in a pack is strictly validated: silently stripping whitespace accepts a "
            "manifest whose bytes are not the bytes the pack id covers",
            {
                "pack_id": _pack_id(_WHITESPACE_BODY),
                "objects": [LINKED_EVENT_OID],
                "shallow": [HELLO_OID],
            },
            B(pack_frame_from_body(_WHITESPACE_BODY)),
            "pack.entry-base64",
            repair_temptation="use a lenient base64 decoder",
        ),
        _repair(
            "pack-unknown-top-level-key-dropped",
            "2.8",
            "pack.inspect",
            "dropping an unknown manifest key and continuing computes the pack id of a "
            "manifest that was never transmitted",
            {"pack_id": _pack_id(_CLEAN_BODY), "objects": [], "shallow": []},
            B(pack_frame_from_body(_EXTRA_KEY_BODY)),
            "pack.manifest-key-set",
            repair_temptation="ignore unknown keys for forward compatibility",
        ),
        _repair(
            "shallow-crlf-normalised",
            "2.7",
            "shallow.parse",
            "normalizing CRLF makes a corrupted boundary file look healthy, and the boundary "
            "is what tells a reader 'absent by design' from 'absent and broken'",
            {"oids": [HELLO_OID]},
            B((HELLO_OID + "\r\n").encode("ascii")),
            "shallow.carriage-return",
            repair_temptation="normalize line endings on read",
        ),
        _repair(
            "shallow-duplicate-collapsed",
            "2.7",
            "shallow.parse",
            "de-duplicating on read hides a writer that is producing a file no reader agrees "
            "with; the writer de-duplicates, the reader refuses",
            {"oids": [HELLO_OID]},
            B((HELLO_OID + "\n" + HELLO_OID + "\n").encode("ascii")),
            "shallow.duplicate",
            repair_temptation="collect the lines into a set",
        ),
        _repair(
            "ref-carriage-return-stripped",
            "2.4",
            "ref.file",
            "a bare CR is not one of the two accepted terminators, and stripping whitespace "
            "accepts a ref file that no other reader will read the same way",
            {"oid": HELLO_OID},
            B((HELLO_OID + "\r").encode("ascii")),
            "ref.file-not-canonical",
            repair_temptation="call .strip() on the file's contents",
        ),
        _repair(
            "usage-string-coerced-to-a-number",
            "1.5.2",
            "event.metrics",
            "cost and duration accept a numeric string; usage values do not. Coercing one "
            "makes a token count that was never recorded look recorded",
            {},
            B(json_object("event", {"kind": "model", "usage": {"input": "5"}})),
            "metrics.usage-value-not-numeric",
            repair_temptation="parse any numeric-looking string",
        ),
    ),
)

FAMILIES = (REPAIR,)
