"""SPEC Part 1: envelope framing, oid derivation, links, metrics, graphs, bounds."""

from __future__ import annotations

import base64

from tests.conformance.builders import (
    ABSENT,
    ANNOTATION_V1,
    ANNOTATION_V1_OID,
    ANNOTATION_V2,
    CHILD_EVENT,
    CHILD_EVENT_OID,
    HELLO_BLOB,
    HELLO_OID,
    LINKED_EVENT,
    OTHER_RUN_ID,
    ROOT_EVENT,
    ROOT_EVENT_OID,
    RUN_ID,
    RUN_OBJECT,
    RUN_OBJECT_OID,
    UNSIGNED_ATTESTATION_OBJECT,
    b64,
    envelope_bytes,
    json_object,
    oid_of,
    pack_frame,
)
from tests.conformance.cases import ACCEPT, REJECT, B, Case, Family, G, V

READER, WRITER = "reader", "writer"
BLOB_HEADER = {"type": "blob", "schema": 1}
EVENT_HEADER = {"type": "event", "schema": 1}


def _c(**kwargs) -> Case:
    return Case(**kwargs)


def _env(name, expect, intent, spec_input, **extra) -> Case:
    return _c(
        id=f"env.{name}",
        section="1.2",
        checklist=(3, 9),
        op=extra.pop("op", "envelope.decode"),
        profile=extra.pop("profile", READER),
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


ENVELOPE = Family(
    "12-envelope.json",
    "1.2",
    "envelope",
    (
        _env(
            "header.canonical",
            ACCEPT,
            "the three-key header, canonicalized, names the object whose body follows the LF",
            B(HELLO_BLOB),
            twin="env.header.reordered",
        ),
        _env(
            "header.maximal-66-bytes",
            ACCEPT,
            "the largest header the canonical form can produce is 66 bytes, far under the "
            "256-byte bound, which is why that bound has no accepting twin",
            B(envelope_bytes("attestation", 9007199254740991, "json", b"{}")),
            twin="env.header.oversized",
        ),
        _env(
            "schema.seven-accepts",
            ACCEPT,
            "a reader MUST accept any schema in range and treat a different schema as a "
            "different object, even though this build only ever writes 1",
            B(envelope_bytes("event", 7, "json", b'{"cost":0,"kind":"model","parent_ids":[]}')),
        ),
        _env(
            "blob.arbitrary-bytes",
            ACCEPT,
            "a raw body is opaque: LF, NUL and 0xFF are all ordinary blob content",
            B(envelope_bytes("blob", 1, "raw", b"a\nb\x00c\xff")),
        ),
        _env(
            "body.empty-object",
            ACCEPT,
            "no field is required: an event with an empty payload is a valid stored object",
            B(envelope_bytes("event", 1, "json", b"{}")),
        ),
        _env(
            "body.non-ascii-literal",
            ACCEPT,
            "a json body carries non-ASCII literally, as SPEC 0.2 rule 1 requires",
            B(json_object("event", {"note": "é☃"})),
        ),
        _env(
            "decode.expected-oid-matches",
            ACCEPT,
            "a reader that knows the name it fetched under re-derives it from the bytes",
            B(HELLO_BLOB),
            args={"expected_oid": HELLO_OID},
        ),
        _env(
            "encode.blob",
            ACCEPT,
            "the writer side of the same framing, over opaque bytes",
            B(b"hello\n"),
            op="envelope.encode",
            profile=WRITER,
            args={"header": BLOB_HEADER},
        ),
        _env(
            "encode.event",
            ACCEPT,
            "the writer side over a JSON payload: canonicalize, then frame",
            V({"cost": 0, "kind": "model", "parent_ids": []}),
            op="envelope.encode",
            profile=WRITER,
            args={"header": EVENT_HEADER},
        ),
        _env(
            "header.reordered",
            REJECT,
            "SPEC 0.2 rule 3 fixes the key order, so a re-ordered header names no object",
            B(b'{"schema":1,"encoding":"raw","type":"blob"}\nhello\n'),
            reason="envelope.header-non-canonical",
            repair_temptation=(
                "parse the header, re-serialize it canonically and continue, which silently "
                "renames the object"
            ),
            twin="env.header.canonical",
            forbidden={"oid": HELLO_OID},
        ),
        _env(
            "header.whitespace-padded",
            REJECT,
            "canonical means byte-identical: one space after a colon is a different header",
            B(b'{"encoding": "raw", "schema": 1, "type": "blob"}\nhello\n'),
            reason="envelope.header-non-canonical",
            forbidden={"oid": HELLO_OID},
        ),
        _env(
            "header.extra-key",
            REJECT,
            "the header has exactly three keys; a fourth is not an extension point",
            B(b'{"encoding":"raw","extra":1,"schema":1,"type":"blob"}\nhello\n'),
            reason="envelope.header-key-count",
            repair_temptation="ignore the unknown key and read the three you understand",
        ),
        _env(
            "header.missing-key",
            REJECT,
            "and not fewer: a two-key header is refused rather than defaulted",
            B(b'{"schema":1,"type":"blob"}\nhello\n'),
            reason="envelope.header-key-count",
        ),
        _env(
            "header.oversized",
            REJECT,
            "a header past 256 bytes is refused inside the framing try, so it reports a "
            "framing error rather than a size error -- the reason code names the rule",
            B(b'{"encoding":"raw","pad":"' + b"y" * 240 + b'","schema":1,"type":"blob"}\nhello\n'),
            reason="envelope.malformed",
            reachable=False,
            twin="env.header.maximal-66-bytes",
        ),
        _env(
            "header.no-lf",
            REJECT,
            "the header is split off at the first LF; with no LF there is no body",
            B(b'{"encoding":"raw","schema":1,"type":"blob"}'),
            reason="envelope.malformed",
        ),
        _env(
            "header.not-json",
            REJECT,
            "bytes before the first LF that are not JSON are not a header",
            B(b"not a header\nhello\n"),
            reason="envelope.malformed",
        ),
        _env(
            "schema.zero",
            REJECT,
            "schema must satisfy 1 <= schema < 2**53",
            B(b'{"encoding":"raw","schema":0,"type":"blob"}\nhello\n'),
            reason="envelope.schema-out-of-range",
        ),
        _env(
            "schema.negative",
            REJECT,
            "the lower bound is 1, not 0 and not -1",
            B(b'{"encoding":"raw","schema":-1,"type":"blob"}\nhello\n'),
            reason="envelope.schema-out-of-range",
        ),
        _env(
            "schema.boolean-true",
            REJECT,
            "type(schema) is not int refuses True, which Python would otherwise equal 1",
            B(b'{"encoding":"raw","schema":true,"type":"blob"}\nhello\n'),
            reason="envelope.schema-not-integer",
            repair_temptation="read true as 1 because it compares equal",
        ),
        _env(
            "schema.string",
            REJECT,
            "a string schema is refused, not parsed",
            B(b'{"encoding":"raw","schema":"1","type":"blob"}\nhello\n'),
            reason="envelope.schema-not-integer",
        ),
        _env(
            "schema.float-one-point-zero",
            REJECT,
            "1.0 never survives canonicalization as an integer, so the header is refused as "
            "non-canonical *before* any schema check runs",
            B(b'{"encoding":"raw","schema":1.0,"type":"blob"}\nhello\n'),
            reason="envelope.header-non-canonical",
        ),
        _env(
            "schema.at-2-53",
            REJECT,
            "a schema of 2**53 breaks two rules at once -- SPEC 0.2 rule 7 and SPEC 1.2's "
            "1 <= schema < 2**53 -- and which one a reader reports depends on whether it "
            "applies the 0.2 integer demotion to the three-key header as well as to bodies",
            B(b'{"encoding":"raw","schema":9007199254740992,"type":"blob"}\nhello\n'),
            reason_any=(
                "canon.integer-overflow",
                "envelope.schema-not-integer",
                "envelope.schema-out-of-range",
            ),
            spec_note=(
                "SPEC 0.2's hazard says 'every kernel reader' demotes an integer literal "
                "past 2**53-1; ObjectEnvelope.decode's header parse is the one that does "
                "not, so the reference reports the integer bound here where a reader that "
                "demotes uniformly reports the schema type or range."
            ),
        ),
        _env(
            "type.unknown-widget",
            REJECT,
            "OBJECT_TYPES has no extension point",
            B(b'{"encoding":"json","schema":1,"type":"widget"}\n{}'),
            reason="envelope.unknown-type",
            repair_temptation="store an unknown type opaquely for forward compatibility",
        ),
        _env(
            "encoding.blob-says-json",
            REJECT,
            'encoding MUST be "raw" if and only if the type is "blob"',
            B(b'{"encoding":"json","schema":1,"type":"blob"}\nhello\n'),
            reason="envelope.encoding-mismatch",
        ),
        _env(
            "body.non-canonical-order",
            REJECT,
            "a json body must be byte-identical to the canonical encoding of its own value",
            B(envelope_bytes("event", 1, "json", b'{"b":1,"a":2}')),
            reason="envelope.body-non-canonical",
            repair_temptation="re-serialize the body canonically, which renames the object",
        ),
        _env(
            "body.malformed-json",
            REJECT,
            "a json body that will not parse is refused before canonicality is considered",
            B(envelope_bytes("event", 1, "json", b'{"a":')),
            reason="envelope.body-malformed-json",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 13 -- object ids
# --------------------------------------------------------------------------- #


def _oid(name, expect, intent, spec_input, op, **extra) -> Case:
    return _c(
        id=f"oid.{name}",
        section="1.3",
        checklist=(3,),
        op=op,
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


OID = Family(
    "13-oid.json",
    "1.3",
    "oid",
    (
        _oid(
            "derive.blob-worked-vector",
            ACCEPT,
            "SPEC 1.3's first worked vector: TYPE 0x00 SCHEMA 0x00 BODY, hashed",
            B(b"hello\n"),
            "oid.derive",
            args={"header": BLOB_HEADER},
        ),
        _oid(
            "derive.event-worked-vector",
            ACCEPT,
            "SPEC 1.3's second worked vector, over a canonical event body",
            B(b'{"cost":0,"kind":"model","parent_ids":[]}'),
            "oid.derive",
            args={"header": EVENT_HEADER},
        ),
        _oid(
            "derive.schema-is-inside-the-hash",
            ACCEPT,
            "the same body at schema 2 is a different object, because SCHEMA is framed in",
            B(b"hello\n"),
            "oid.derive",
            args={"header": {"type": "blob", "schema": 2}},
            must_differ=True,
            twin="oid.derive.blob-worked-vector",
        ),
        _oid(
            "derive.type-is-inside-the-hash",
            ACCEPT,
            "so is TYPE: the same bytes as an annotation are a different object",
            B(b"{}"),
            "oid.derive",
            args={"header": {"type": "annotation", "schema": 1}},
        ),
        _oid(
            "derive.empty-body",
            ACCEPT,
            "an empty body is legal and hashes the two NUL separators plus nothing",
            B(b""),
            "oid.derive",
            args={"header": BLOB_HEADER},
        ),
        _oid(
            "derive.body-with-nul",
            ACCEPT,
            "the separators are literal 0x00 bytes and a body may contain them too",
            B(b"a\x00b"),
            "oid.derive",
            args={"header": BLOB_HEADER},
        ),
        _oid(
            "parse.blob", ACCEPT, "OID_RE accepts each of the five types", V(HELLO_OID), "oid.parse"
        ),
        _oid("parse.run", ACCEPT, "the run spelling", V(RUN_ID), "oid.parse"),
        _oid(
            "parse.annotation", ACCEPT, "the annotation spelling", V(ANNOTATION_V1_OID), "oid.parse"
        ),
        _oid(
            "decode.expected-oid-matches",
            ACCEPT,
            "decoding under the right name re-derives that name from the bytes",
            B(ROOT_EVENT),
            "envelope.decode",
            args={"expected_oid": ROOT_EVENT_OID},
        ),
        _oid(
            "parse.uppercase-hex",
            REJECT,
            "hex digits are lowercase only; an uppercase spelling is not a valid oid",
            V("blob:sha256:" + "C5251CF4C201EDE74C8E3564DC6D02E597CBC20FBD91A84704A91179757BD008"),
            "oid.parse",
            reason="oid.malformed",
            repair_temptation="lowercase the digest and continue",
        ),
        _oid(
            "parse.short-digest",
            REJECT,
            "the digest is exactly 64 hex characters",
            V("blob:sha256:" + "c5" * 31),
            "oid.parse",
            reason="oid.malformed",
        ),
        _oid(
            "parse.unknown-type",
            REJECT,
            "the type must be one of the five",
            V("widget:sha256:" + "1" * 64),
            "oid.parse",
            reason="oid.malformed",
        ),
        _oid(
            "parse.missing-algorithm",
            REJECT,
            "the literal ':sha256:' is part of the grammar",
            V("blob:" + "1" * 64),
            "oid.parse",
            reason="oid.malformed",
        ),
        _oid(
            "parse.trailing-newline",
            REJECT,
            "fullmatch: a trailing newline makes it a different string",
            V("blob:sha256:" + "1" * 64 + "\n"),
            "oid.parse",
            reason="oid.malformed",
            repair_temptation="strip surrounding whitespace before matching",
        ),
        _oid(
            "decode.oid-mismatch",
            REJECT,
            "bytes fetched under a name that is not their own digest are refused",
            B(HELLO_BLOB),
            "envelope.decode",
            args={"expected_oid": ABSENT["blob"]},
            reason="envelope.oid-mismatch",
            repair_temptation="trust the name the bytes were filed under",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 15 -- links
# --------------------------------------------------------------------------- #


def _links(name, expect, intent, stored, section="1.5", **extra) -> Case:
    return _c(
        id=f"links.{name}",
        section=section,
        checklist=(4,),
        op=extra.pop("op", "links.extract"),
        profile=READER,
        expect=expect,
        intent=intent,
        input=B(stored),
        **extra,
    )


_EVENT_PRESENT = {"present": [ROOT_EVENT_OID, HELLO_OID]}
_RUN_PRESENT = {"present": [ROOT_EVENT_OID, CHILD_EVENT_OID, HELLO_OID]}

LINKS = Family(
    "15-links.json",
    "1.5",
    "links",
    (
        _links(
            "event.parent-ids-present",
            ACCEPT,
            "parent_ids is a duplicate-free list of event oids, and each must resolve",
            CHILD_EVENT,
            section="1.5.2",
            args=_EVENT_PRESENT,
        ),
        _links(
            "event.parent-ids-shallow",
            ACCEPT,
            "SPEC 1.5.6 is satisfied by the shallow boundary as well as by a local object",
            CHILD_EVENT,
            section="1.5.6",
            args={"shallow": [ROOT_EVENT_OID]},
            must_differ=False,
            twin="links.event.parent-ids-present",
        ),
        _links(
            "event.empty-payload",
            ACCEPT,
            "parent_ids and causal_ids default to [], so an empty event has no links",
            json_object("event", {}),
            section="1.5.2",
        ),
        _links(
            "event.input-and-output-blob",
            ACCEPT,
            "a truthy input_blob/output_blob must be a blob oid, and is a link",
            LINKED_EVENT,
            section="1.5.2",
            args={"present": [HELLO_OID]},
        ),
        _links(
            "event.artifact-blob-reserved",
            ACCEPT,
            "artifact_blob is validated though no writer emits it: a reserved link field",
            json_object("event", {"artifact_blob": HELLO_OID, "kind": "model"}),
            section="1.5.2",
            args={"present": [HELLO_OID]},
        ),
        _links(
            "event.causal-ids",
            ACCEPT,
            "causal_ids carries the same rule as parent_ids",
            json_object("event", {"causal_ids": [ROOT_EVENT_OID], "kind": "tool"}),
            section="1.5.2",
            args=_EVENT_PRESENT,
        ),
        _links(
            "event.falsy-blob-not-a-link",
            ACCEPT,
            "an empty input_blob is falsy, so it is not a link and is not type-checked",
            json_object("event", {"input_blob": "", "kind": "model"}),
            section="1.5.2",
        ),
        _links(
            "run.events-roots-tips",
            ACCEPT,
            "events is duplicate-free, and roots and tips are subsets of it",
            RUN_OBJECT,
            section="1.5.3",
            args=_RUN_PRESENT,
        ),
        _links(
            "run.manifests-values-are-blobs",
            ACCEPT,
            "manifests is an object whose *values* are blob oids",
            json_object("run", {"manifests": {"transcript": HELLO_OID}}),
            section="1.5.3",
            args={"present": [HELLO_OID]},
        ),
        _links(
            "run.patch-blob-suffix-rule",
            ACCEPT,
            "the _blob suffix rule is open-ended: a writer adding patch_blob inherits it",
            json_object("run", {"patch_blob": HELLO_OID}),
            section="1.5.3",
            args={"present": [HELLO_OID]},
            twin="links.run.patch-blob-is-an-object",
        ),
        _links(
            "run.patch-blob-empty-string",
            ACCEPT,
            "the rule applies only to a *truthy* value, so an empty patch_blob is not a link",
            json_object("run", {"patch_blob": ""}),
            section="1.5.3",
        ),
        _links(
            "attestation.target-run",
            ACCEPT,
            "an attestation's target_id is REQUIRED and MUST be a run oid",
            UNSIGNED_ATTESTATION_OBJECT,
            section="1.5.4",
            args={"shallow": [RUN_ID]},
        ),
        _links(
            "attestation.evidence-any-type",
            ACCEPT,
            "an evidence_ids entry may be an oid of any type",
            json_object(
                "attestation",
                {"evidence_ids": [HELLO_OID, ROOT_EVENT_OID], "signer": "x", "target_id": RUN_ID},
            ),
            section="1.5.4",
            args={"present": [HELLO_OID, ROOT_EVENT_OID], "shallow": [RUN_ID]},
        ),
        _links(
            "annotation.target-any-type",
            ACCEPT,
            "unlike an attestation, an annotation may target any object type",
            json_object("annotation", {"target_id": ROOT_EVENT_OID}),
            section="1.5.5",
            args=_EVENT_PRESENT,
        ),
        _links(
            "annotation.target-absent",
            ACCEPT,
            "and an annotation's target_id may be absent entirely",
            json_object("annotation", {"value": {"tags": []}}),
            section="1.5.5",
        ),
        _links(
            "annotation.previous-annotation",
            ACCEPT,
            "a truthy previous_id must be an annotation oid, and is a link",
            ANNOTATION_V2,
            section="1.5.5",
            args={"present": [ANNOTATION_V1_OID, RUN_OBJECT_OID]},
        ),
        _links(
            "blob.has-no-links",
            ACCEPT,
            "a blob is opaque: it has no structure and therefore no links",
            HELLO_BLOB,
            section="1.5.1",
        ),
        _c(
            id="chain.same-target",
            section="1.5.5",
            checklist=(4,),
            op="annotation.chain",
            profile=READER,
            expect=ACCEPT,
            intent="a chained annotation must carry the same target_id as its predecessor",
            input=B(ANNOTATION_V2),
            args={"objects": [b64(ANNOTATION_V1)]},
        ),
        _links(
            "event.parent-not-an-event",
            REJECT,
            "every parent_ids entry must be an *event* oid, not merely a valid oid",
            json_object("event", {"kind": "model", "parent_ids": [HELLO_OID]}),
            section="1.5.2",
            reason="link.parent-ids-not-events",
            repair_temptation="filter the offending entry out and keep the rest",
        ),
        _links(
            "event.parent-ids-not-a-list",
            REJECT,
            "a non-list parent_ids is refused, not wrapped",
            json_object("event", {"kind": "model", "parent_ids": ROOT_EVENT_OID}),
            section="1.5.2",
            reason="link.parent-ids-not-events",
        ),
        _links(
            "event.parent-ids-duplicate",
            REJECT,
            "duplicates are refused rather than de-duplicated",
            json_object("event", {"kind": "model", "parent_ids": [ROOT_EVENT_OID, ROOT_EVENT_OID]}),
            section="1.5.2",
            reason="link.parent-ids-duplicate",
            repair_temptation="de-duplicate the list",
        ),
        _links(
            "run.tips-not-event-ids",
            REJECT,
            "a tips entry that is not an event oid fails before the subset check",
            json_object("run", {"tips": [HELLO_OID]}),
            section="1.5.3",
            reason="link.run-roots-tips-invalid",
        ),
        _links(
            "event.input-blob-is-an-event",
            REJECT,
            "a truthy input_blob must be a *blob* oid",
            json_object("event", {"input_blob": ROOT_EVENT_OID, "kind": "model"}),
            section="1.5.2",
            reason="link.event-blob-not-blob",
        ),
        _links(
            "event.output-blob-is-an-object",
            REJECT,
            "a truthy output_blob that is not even a string is refused; note that the "
            "reference reports the *oid* error here, which is what x_reference exists to show",
            json_object("event", {"kind": "model", "output_blob": {"a": 1}}),
            section="1.5.2",
            reason="link.event-blob-not-blob",
        ),
        _links(
            "event.artifact-blob-is-a-run",
            REJECT,
            "the reserved field is type-checked exactly like the two written ones",
            json_object("event", {"artifact_blob": RUN_ID, "kind": "model"}),
            section="1.5.2",
            reason="link.event-blob-not-blob",
        ),
        _links(
            "run.events-not-event-ids",
            REJECT,
            "a run's events list holds event oids only",
            json_object("run", {"events": [HELLO_OID]}),
            section="1.5.3",
            reason="link.run-events-invalid",
        ),
        _links(
            "run.events-duplicate",
            REJECT,
            "and it must be duplicate-free",
            json_object("run", {"events": [ROOT_EVENT_OID, ROOT_EVENT_OID]}),
            section="1.5.3",
            reason="link.run-events-invalid",
        ),
        _links(
            "run.roots-not-subset",
            REJECT,
            "roots must be a subset of events",
            json_object("run", {"events": [ROOT_EVENT_OID], "roots": [CHILD_EVENT_OID]}),
            section="1.5.3",
            reason="link.run-roots-tips-not-subset",
            repair_temptation="add the stray entry to events",
        ),
        _links(
            "run.tips-not-subset",
            REJECT,
            "and so must tips",
            json_object("run", {"events": [ROOT_EVENT_OID], "tips": [CHILD_EVENT_OID]}),
            section="1.5.3",
            reason="link.run-roots-tips-not-subset",
        ),
        _links(
            "run.manifests-not-an-object",
            REJECT,
            "manifests must be an object, not a list of pairs",
            json_object("run", {"manifests": [["transcript", HELLO_OID]]}),
            section="1.5.3",
            reason="link.run-manifests-not-object",
        ),
        _links(
            "run.manifests-value-not-a-blob",
            REJECT,
            "every manifests value must be a blob oid",
            json_object("run", {"manifests": {"transcript": ROOT_EVENT_OID}}),
            section="1.5.3",
            reason="link.run-blob-not-blob",
        ),
        _links(
            "run.patch-blob-is-an-object",
            REJECT,
            "the open-ended suffix rule refuses a patch_blob holding an object",
            json_object("run", {"patch_blob": {"a": 1}}),
            section="1.5.3",
            reason="link.run-blob-not-blob",
            repair_temptation="apply the _blob rule only to a fixed list of known field names",
            twin="links.run.patch-blob-suffix-rule",
        ),
        _links(
            "attestation.target-absent",
            REJECT,
            "target_id is REQUIRED for an attestation",
            json_object("attestation", {"claim": {}, "signer": "x"}),
            section="1.5.4",
            reason="link.attestation-target-not-run",
        ),
        _links(
            "attestation.target-not-a-run",
            REJECT,
            "and it must be a run oid, never an event or a blob",
            json_object("attestation", {"signer": "x", "target_id": ROOT_EVENT_OID}),
            section="1.5.4",
            reason="link.attestation-target-not-run",
        ),
        _links(
            "attestation.evidence-not-a-list",
            REJECT,
            "a non-list evidence_ids is refused; the reference reports the oid error for the "
            "None it substitutes, which is exactly the conflation x_reference exposes",
            json_object(
                "attestation", {"evidence_ids": {"a": 1}, "signer": "x", "target_id": RUN_ID}
            ),
            section="1.5.4",
            reason="link.evidence-not-list",
            repair_temptation="wrap a single oid in a list",
        ),
        _links(
            "annotation.previous-not-an-annotation",
            REJECT,
            "a truthy previous_id must be an annotation oid",
            json_object("annotation", {"previous_id": RUN_ID, "target_id": RUN_ID}),
            section="1.5.5",
            reason="link.annotation-previous-not-annotation",
        ),
        _links(
            "missing-object",
            REJECT,
            "SPEC 1.5.6: a link must resolve locally or appear in the shallow boundary",
            CHILD_EVENT,
            section="1.5.6",
            args={"present": []},
            reason="link.missing-object",
            repair_temptation="treat an unresolvable link as absent and continue",
            twin="links.event.parent-ids-present",
        ),
        _c(
            id="chain.target-changed",
            section="1.5.5",
            checklist=(4,),
            op="annotation.chain",
            profile=READER,
            expect=REJECT,
            reason="chain.target-changed",
            intent="a chain may not re-target midway: both versions describe one object",
            input=B(
                json_object(
                    "annotation", {"previous_id": ANNOTATION_V1_OID, "target_id": OTHER_RUN_ID}
                )
            ),
            args={"objects": [b64(ANNOTATION_V1)]},
            repair_temptation="let the later version's target win",
        ),
        _c(
            id="chain.previous-unavailable",
            section="1.5.5",
            checklist=(4,),
            op="annotation.chain",
            profile=READER,
            expect=REJECT,
            reason="chain.previous-unavailable",
            intent="an unreadable predecessor is a refusal, not a chain root",
            input=B(ANNOTATION_V2),
            args={"objects": []},
            repair_temptation="treat an unreadable predecessor as the start of the chain",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 15b -- event metrics
# --------------------------------------------------------------------------- #


def _metrics(name, expect, intent, payload, **extra) -> Case:
    return _c(
        id=f"metrics.{name}",
        section="1.5.2",
        checklist=(5,),
        op="event.metrics",
        profile=READER,
        expect=expect,
        intent=intent,
        input=B(json_object("event", payload)),
        **extra,
    )


METRICS = Family(
    "15b-metrics.json",
    "1.5.2",
    "metrics",
    (
        _metrics(
            "cost.numeric-string",
            ACCEPT,
            "a documented hazard: cost is validated by Decimal(str(value)), so the *string* "
            '"1.5" is accepted and stored -- a reader MUST NOT assume these are JSON numbers',
            {"cost": "1.5", "kind": "model"},
        ),
        _metrics(
            "cost.absent-defaults-to-zero",
            ACCEPT,
            "cost and duration default to 0 when absent",
            {"kind": "model"},
        ),
        _metrics(
            "duration.numeric-string-at-128-chars",
            ACCEPT,
            "the numeric-meter string bound is 128 characters, and 128 is inside it",
            {"duration": "1." + "0" * 126, "kind": "model"},
            twin="metrics.meter.string-at-129-chars",
        ),
        _metrics(
            "time-unix.negative",
            ACCEPT,
            "time_unix is the one meter that may be negative: a pre-epoch timestamp is data",
            {"kind": "model", "time_unix": -1},
        ),
        _metrics(
            "usage.falsy-zero",
            ACCEPT,
            'a documented hazard: usage is read as payload.get("usage") or {}, so 0 passes '
            "validation as 'no usage'",
            {"kind": "model", "usage": 0},
        ),
        _metrics(
            "usage.falsy-empty-string",
            ACCEPT,
            "the same for an empty string",
            {"kind": "model", "usage": ""},
        ),
        _metrics(
            "usage.falsy-empty-list",
            ACCEPT,
            "the same for an empty list, which is not even a mapping",
            {"kind": "model", "usage": []},
        ),
        _metrics(
            "usage.falsy-false",
            ACCEPT,
            "the same for false",
            {"kind": "model", "usage": False},
        ),
        _metrics(
            "usage.falsy-null",
            ACCEPT,
            "and the same for null",
            {"kind": "model", "usage": None},
        ),
        _metrics(
            "usage.token-dimension-at-max-safe",
            ACCEPT,
            "a known token dimension may be exactly 2**53-1",
            {"kind": "model", "usage": {"input": 9007199254740991}},
            twin="metrics.usage.token-dimension-at-2-53",
        ),
        _metrics(
            "usage.non-token-dimension-fractional",
            ACCEPT,
            "the integrality rule applies only to the seven known token dimensions",
            {"kind": "model", "usage": {"latency_ms": 1.5}},
            twin="metrics.usage.token-dimension-fractional",
        ),
        _metrics(
            "cost.negative",
            REJECT,
            "cost must be non-negative",
            {"cost": -1, "kind": "model"},
            reason="metrics.meter-not-finite",
            repair_temptation="clamp a negative meter to zero",
        ),
        _metrics(
            "duration.negative",
            REJECT,
            "so must duration",
            {"duration": -0.5, "kind": "model"},
            reason="metrics.meter-not-finite",
        ),
        _metrics(
            "meter.string-at-129-chars",
            REJECT,
            "129 characters is one past the numeric-meter string bound",
            {"duration": "1." + "0" * 127, "kind": "model"},
            reason="metrics.meter-too-long",
            twin="metrics.duration.numeric-string-at-128-chars",
        ),
        _metrics(
            "meter.decimal-finite-but-not-a-double",
            REJECT,
            'Decimal("1e999999999") is finite but float() of it is not; this bound exists '
            "because such a value passed validation, was hashed in, and broke every later read",
            {"cost": "1e999999999", "kind": "model"},
            reason="metrics.meter-not-finite",
        ),
        _metrics(
            "time-unix.not-numeric",
            REJECT,
            "time_unix may be negative but must still be a finite number",
            {"kind": "model", "time_unix": "later"},
            reason="metrics.meter-not-finite",
        ),
        _metrics(
            "usage.truthy-non-object",
            REJECT,
            "a *truthy* non-object usage is refused; only the falsy ones pass as absent",
            {"kind": "model", "usage": 5},
            reason="metrics.usage-not-object",
            twin="metrics.usage.falsy-zero",
        ),
        _metrics(
            "usage.value-boolean",
            REJECT,
            "a usage value must be exactly an int or a float; a bool is not numeric here",
            {"kind": "model", "usage": {"input": True}},
            reason="metrics.usage-value-not-numeric",
            repair_temptation="read true as 1",
        ),
        _metrics(
            "usage.value-string",
            REJECT,
            "and a numeric *string* is refused inside usage, unlike cost and duration",
            {"kind": "model", "usage": {"input": "5"}},
            reason="metrics.usage-value-not-numeric",
        ),
        _metrics(
            "usage.value-negative",
            REJECT,
            "a usage value must be non-negative",
            {"kind": "model", "usage": {"input": -1}},
            reason="metrics.meter-not-finite",
        ),
        _metrics(
            "usage.token-dimension-fractional",
            REJECT,
            "a known token dimension must be integral",
            {"kind": "model", "usage": {"input": 1.5}},
            reason="metrics.token-dimension-unsafe",
            repair_temptation="round a fractional token count",
        ),
        _metrics(
            "usage.token-dimension-at-2-53",
            REJECT,
            "and at most 2**53-1",
            {"kind": "model", "usage": {"input": 9007199254740992.0}},
            reason="metrics.token-dimension-unsafe",
            twin="metrics.usage.token-dimension-at-max-safe",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 15c -- the run event graph
# --------------------------------------------------------------------------- #

_GRAPH_OBJECTS = [b64(ROOT_EVENT), b64(CHILD_EVENT)]


def _graph(name, expect, intent, payload, objects=None, **extra) -> Case:
    return _c(
        id=f"graph.{name}",
        section="1.5.3",
        checklist=(4, 5),
        op="run.graph",
        profile=READER,
        expect=expect,
        intent=intent,
        input=B(json_object("run", payload)),
        args={"objects": _GRAPH_OBJECTS if objects is None else objects},
        **extra,
    )


_COMPLETE = {
    "events": [ROOT_EVENT_OID, CHILD_EVENT_OID],
    "roots": [ROOT_EVENT_OID],
    "status": "completed",
    "tips": [CHILD_EVENT_OID],
}

GRAPH = Family(
    "15c-graph.json",
    "1.5.3",
    "graph",
    (
        _graph("status.completed", ACCEPT, "one of the four run statuses", _COMPLETE),
        _graph(
            "status.absent-defaults-to-running",
            ACCEPT,
            "an absent status means running",
            {key: value for key, value in _COMPLETE.items() if key != "status"},
        ),
        _graph(
            "order.parent-before-child",
            ACCEPT,
            "every parent must appear at a strictly earlier index than its child",
            _COMPLETE,
        ),
        _graph(
            "roots-tips.exact-when-complete",
            ACCEPT,
            "with every event present, roots must be exactly the parentless events and tips "
            "exactly the leaves",
            _COMPLETE,
            twin="graph.roots.mismatch",
        ),
        _graph(
            "shallow.exactness-skipped-when-incomplete",
            ACCEPT,
            "when any event is missing -- a shallow fetch -- both exactness checks are skipped, "
            "so a partial run is readable rather than corrupt",
            {**_COMPLETE, "roots": [], "tips": []},
            objects=[b64(ROOT_EVENT)],
            twin="graph.roots.mismatch",
        ),
        _graph(
            "legacy-refs.valid",
            ACCEPT,
            "legacy_refs maps string names to events inside the run",
            {**_COMPLETE, "legacy_refs": {"step-1": ROOT_EVENT_OID}},
        ),
        _graph("empty-events", ACCEPT, "a run with no events is a valid run", {"events": []}),
        _graph(
            "causal.in-order",
            ACCEPT,
            "causal_ids are ordered by the same rule as parent_ids",
            {
                "events": [ROOT_EVENT_OID, CHILD_EVENT_OID],
                "roots": [ROOT_EVENT_OID],
                "tips": [CHILD_EVENT_OID],
            },
        ),
        _graph(
            "status.unknown",
            REJECT,
            "an unrecognised status is refused, never defaulted",
            {**_COMPLETE, "status": "cancelled"},
            reason="graph.status-invalid",
            repair_temptation="default an unknown status to running",
        ),
        _graph(
            "parent-outside-graph",
            REJECT,
            "a present event whose parent is not in events breaks graph closure",
            {"events": [CHILD_EVENT_OID], "roots": [], "tips": [CHILD_EVENT_OID]},
            objects=[b64(CHILD_EVENT)],
            reason="graph.parent-outside-graph",
            repair_temptation="add the missing parent to events",
        ),
        _graph(
            "causal-outside-graph",
            REJECT,
            "the same rule for a causal link",
            {
                "events": [
                    oid_of(json_object("event", {"causal_ids": [ROOT_EVENT_OID], "kind": "tool"}))
                ],
                "roots": [],
                "tips": [],
            },
            objects=[b64(json_object("event", {"causal_ids": [ROOT_EVENT_OID], "kind": "tool"}))],
            reason="graph.causal-outside-graph",
        ),
        _graph(
            "order.child-before-parent",
            REJECT,
            "a parent at a later index than its child is refused, not re-sorted",
            {
                "events": [CHILD_EVENT_OID, ROOT_EVENT_OID],
                "roots": [ROOT_EVENT_OID],
                "tips": [CHILD_EVENT_OID],
            },
            reason="graph.order-not-topological",
            repair_temptation="topologically sort events on read",
        ),
        _graph(
            "roots.mismatch",
            REJECT,
            "roots must equal the parentless set exactly, not merely be a subset of it",
            {**_COMPLETE, "roots": []},
            reason="graph.roots-mismatch",
            repair_temptation="recompute roots and ignore the stored value",
            twin="graph.roots-tips.exact-when-complete",
        ),
        _graph(
            "tips.mismatch",
            REJECT,
            "and tips must equal the leaf set exactly",
            {**_COMPLETE, "tips": [ROOT_EVENT_OID, CHILD_EVENT_OID]},
            reason="graph.tips-mismatch",
        ),
        _graph(
            "legacy-refs.target-outside-run",
            REJECT,
            "a legacy ref must name an event inside this run",
            {**_COMPLETE, "legacy_refs": {"step-1": ABSENT["event"]}},
            reason="graph.legacy-refs-invalid",
        ),
        _graph(
            "legacy-refs.not-an-object",
            REJECT,
            "and legacy_refs itself must be an object of string keys",
            {**_COMPLETE, "legacy_refs": [ROOT_EVENT_OID]},
            reason="graph.legacy-refs-invalid",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 15d -- a full local read
# --------------------------------------------------------------------------- #

_LOAD_OBJECTS = [b64(ROOT_EVENT), b64(CHILD_EVENT), b64(HELLO_BLOB)]


def _load(name, expect, intent, stored, **extra) -> Case:
    return _c(
        id=f"load.{name}",
        section="1.5",
        checklist=(3, 4, 5),
        op="object.load",
        profile=READER,
        expect=expect,
        intent=intent,
        input=B(stored),
        **extra,
    )


LOAD = Family(
    "15d-load.json",
    "1.5",
    "load",
    (
        _load("blob", ACCEPT, "the simplest full read: framing, oid, and no links", HELLO_BLOB),
        _load(
            "event-links-present",
            ACCEPT,
            "framing, oid, link types, link existence and metrics, in one answer",
            CHILD_EVENT,
            args={"objects": _LOAD_OBJECTS},
        ),
        _load(
            "event-links-shallow",
            ACCEPT,
            "the shallow boundary satisfies existence without the object being present",
            CHILD_EVENT,
            args={"shallow": [ROOT_EVENT_OID]},
            must_differ=False,
            twin="load.event-links-present",
        ),
        _load(
            "run-complete",
            ACCEPT,
            "a run read additionally runs graph validation",
            RUN_OBJECT,
            args={"objects": _LOAD_OBJECTS},
        ),
        _load(
            "annotation-chain",
            ACCEPT,
            "an annotation read additionally runs the chain validator",
            ANNOTATION_V2,
            args={"objects": [b64(ANNOTATION_V1), b64(RUN_OBJECT)]},
        ),
        _load(
            "oid-mismatch",
            REJECT,
            "a full read verifies the name it fetched under before anything else",
            HELLO_BLOB,
            args={"expected_oid": ABSENT["blob"]},
            reason="envelope.oid-mismatch",
        ),
        _load(
            "missing-link",
            REJECT,
            "a link neither present nor declared shallow refuses the read",
            CHILD_EVENT,
            args={"objects": []},
            reason="link.missing-object",
            twin="load.event-links-present",
        ),
        _load(
            "event-bad-metrics",
            REJECT,
            "metric validation is part of a full read, not a separate optional pass",
            json_object("event", {"cost": -1, "kind": "model"}),
            reason="metrics.meter-not-finite",
        ),
        _load(
            "run-bad-graph",
            REJECT,
            "and so is graph validation",
            json_object(
                "run",
                {
                    "events": [ROOT_EVENT_OID, CHILD_EVENT_OID],
                    "roots": [],
                    "tips": [CHILD_EVENT_OID],
                },
            ),
            args={"objects": _LOAD_OBJECTS},
            reason="graph.roots-mismatch",
        ),
        _load(
            "annotation-chain-broken",
            REJECT,
            "and so is the annotation chain",
            ANNOTATION_V2,
            args={"objects": [b64(RUN_OBJECT)], "present": [ANNOTATION_V1_OID]},
            reason="chain.previous-unavailable",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 16 -- the rejection table of SPEC 1.6
# --------------------------------------------------------------------------- #

_CONFIG_PREFIX = b'{"format":3,"object_hash":"sha256","pad":"'
_CONFIG_SUFFIX = b'","repository":"opentine","version":1}'
_CONFIG_FIXED = len(_CONFIG_PREFIX) + len(_CONFIG_SUFFIX)
_EVENT_JSON_HEADER = b'{"encoding":"json","schema":1,"type":"event"}\n'


def _config_gen(total: int) -> dict:
    return {
        "kind": "repeat",
        "unit_b64": b64(b"x"),
        "count": total - _CONFIG_FIXED,
        "prefix_b64": b64(_CONFIG_PREFIX),
        "suffix_b64": b64(_CONFIG_SUFFIX),
    }


def _config_tokens_gen(pairs: int) -> dict:
    prefix = b'{"format":3,"object_hash":"sha256","pad":['
    suffix = b'[]],"repository":"opentine","version":1}'
    return {
        "kind": "repeat",
        "unit_b64": b64(b"[],"),
        "count": pairs,
        "prefix_b64": b64(prefix),
        "suffix_b64": b64(suffix),
    }


def _body_tokens_gen(pairs: int, prefix: bytes = b"") -> dict:
    return {
        "kind": "repeat",
        "unit_b64": b64(b"[],"),
        "count": pairs,
        "prefix_b64": b64(prefix + b"["),
        "suffix_b64": b64(b"[]]"),
    }


def _bounds(name, expect, intent, op, spec_input, **extra) -> Case:
    return _c(
        id=f"bounds.{name}",
        section="1.6",
        checklist=(5,),
        op=op,
        profile=extra.pop("profile", READER),
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


_LONG_REF = "heads/" + "a" * 240 + "/" + "b" * 240 + "/" + "c" * 24

#: TINEPACK3\x00 plus a 32-byte checksum field: the 42-byte head of a real frame, so
#: the oversize vector breaks the transfer bound and nothing else.
_PACK_FRAME_PREFIX_B64 = base64.b64encode(b"TINEPACK3\x00" + b"\x00" * 32).decode("ascii")

BOUNDS = Family(
    "16-bounds.json",
    "1.6",
    "bounds",
    (
        _bounds(
            "ref-name.at-512-bytes",
            ACCEPT,
            "a ref name may be exactly 512 bytes in total",
            "ref.name",
            V(_LONG_REF),
            twin="bounds.ref-name.at-513-bytes",
        ),
        _bounds(
            "ref-name.at-513-bytes",
            REJECT,
            "513 bytes is one past the total-length bound",
            "ref.name",
            V(_LONG_REF + "d"),
            reason="ref.name-too-long",
            twin="bounds.ref-name.at-512-bytes",
        ),
        _bounds(
            "ref-component.at-240-bytes",
            ACCEPT,
            "a single component may be exactly MAX_REF_COMPONENT_BYTES",
            "ref.name",
            V("heads/" + "a" * 240),
            twin="bounds.ref-component.at-241-bytes",
        ),
        _bounds(
            "ref-component.at-241-bytes",
            REJECT,
            "241 bytes is one past the per-component bound",
            "ref.name",
            V("heads/" + "a" * 241),
            reason="ref.component-too-long",
            twin="bounds.ref-component.at-240-bytes",
        ),
        _bounds(
            "ref-name.single-character-component",
            ACCEPT,
            "the lower end of the same rule: one character is a legal component",
            "ref.name",
            V("heads/a"),
        ),
        _bounds(
            "ref-name.empty-component",
            REJECT,
            "an empty component is not, so a doubled slash is refused",
            "ref.name",
            V("heads//main"),
            reason="ref.component-reserved",
        ),
        _bounds(
            "ref-file.canonical",
            ACCEPT,
            "a ref file is one oid and one LF, well inside MAX_REF_BYTES",
            "ref.file",
            B((HELLO_OID + "\n").encode("ascii")),
            twin="bounds.ref-file.at-257-bytes",
        ),
        _bounds(
            "ref-file.at-257-bytes",
            REJECT,
            "257 bytes is one past MAX_REF_BYTES; the reader never looks further",
            "ref.file",
            G({"kind": "fill", "byte": 0x61, "count": 257}),
            reason="ref.file-oversized",
            repair_temptation="read the first line and ignore the rest",
            twin="bounds.ref-file.canonical",
        ),
        _bounds(
            "reflog-actor.at-4096-chars",
            ACCEPT,
            "the reflog actor bound is 4096 characters, and 4096 is inside it",
            "reflog.row",
            V(
                {
                    "actor": "a" * 4096,
                    "new": HELLO_OID,
                    "old": None,
                    "ref": "heads/main",
                    "time_ns": "1757030400000000000",
                }
            ),
            profile=WRITER,
            twin="bounds.reflog-actor.at-4097-chars",
        ),
        _bounds(
            "reflog-actor.at-4097-chars",
            REJECT,
            "4097 is one past it",
            "reflog.row",
            V(
                {
                    "actor": "a" * 4097,
                    "new": HELLO_OID,
                    "old": None,
                    "ref": "heads/main",
                    "time_ns": "1757030400000000000",
                }
            ),
            profile=WRITER,
            reason="reflog.actor-too-long",
            twin="bounds.reflog-actor.at-4096-chars",
        ),
        _bounds(
            "reflog-actor.empty",
            ACCEPT,
            "the bound has no floor: an empty actor is a legal row",
            "reflog.row",
            V({"actor": "", "new": HELLO_OID, "old": None, "ref": "heads/main", "time_ns": "0"}),
            profile=WRITER,
        ),
        _bounds(
            "config.at-65536-bytes",
            ACCEPT,
            "MAX_CONFIG_BYTES is 65 536, and a config of exactly that size still validates",
            "config.validate",
            G(_config_gen(65_536)),
            twin="bounds.config.at-65537-bytes",
        ),
        _bounds(
            "config.at-65537-bytes",
            REJECT,
            "65 537 is one past it, and the refusal comes before any parse",
            "config.validate",
            G(_config_gen(65_537)),
            reason="config.oversized",
            twin="bounds.config.at-65536-bytes",
        ),
        _bounds(
            "config.minimal",
            ACCEPT,
            "the four required pairs, canonically, are the whole descriptor",
            "config.validate",
            B(b'{"format":3,"object_hash":"sha256","repository":"opentine","version":1}\n'),
        ),
        _bounds(
            "config.tokens-under-budget",
            ACCEPT,
            "the config call site scans with max_tokens = 10 000",
            "config.validate",
            G(_config_tokens_gen(3_000)),
            twin="bounds.config.tokens-over-budget",
        ),
        _bounds(
            "config.tokens-over-budget",
            REJECT,
            "and a denser descriptor is refused rather than parsed",
            "config.validate",
            G(_config_tokens_gen(3_400)),
            reason="shape.tokens-exceeded",
            twin="bounds.config.tokens-under-budget",
        ),
        _bounds(
            "shallow.at-10000-entries",
            ACCEPT,
            "MAX_SHALLOW_OBJECTS is 10 000 entries",
            "shallow.parse",
            G({"kind": "oids", "object_type": "blob", "count": 10_000, "start": 0}),
            tier="stress",
            twin="bounds.shallow.at-10001-entries",
        ),
        _bounds(
            "shallow.at-10001-entries",
            REJECT,
            "10 001 is one past it",
            "shallow.parse",
            G({"kind": "oids", "object_type": "blob", "count": 10_001, "start": 0}),
            tier="stress",
            reason="shallow.too-many",
            repair_temptation="keep the first 10 000",
            twin="bounds.shallow.at-10000-entries",
        ),
        _bounds(
            "shallow.over-1-mib",
            REJECT,
            "the two shallow bounds are inseparable for a fixed-width line format: a 77-byte "
            "line means 1 MiB needs 13 618 entries and 10 000 entries is only 770 000 bytes, "
            "so either bound is a conformant answer and neither order is normative",
            "shallow.parse",
            G({"kind": "oids", "object_type": "blob", "count": 14_000, "start": 0}),
            tier="stress",
            reason_any=("shallow.oversized", "shallow.too-many"),
            twin="bounds.shallow.at-10000-entries",
        ),
        _bounds(
            "shallow.encode-sorts-and-terminates",
            ACCEPT,
            "the writer side: sorted, unique, one LF per line including the last",
            "shallow.encode",
            V([CHILD_EVENT_OID, HELLO_OID, ROOT_EVENT_OID]),
            profile=WRITER,
        ),
        _bounds(
            "shallow.encode-deduplicates",
            ACCEPT,
            "the writer de-duplicates by construction; the *reader* refuses a duplicate",
            "shallow.encode",
            V([HELLO_OID, HELLO_OID]),
            profile=WRITER,
            twin="shallow.duplicate-entry",
        ),
        _bounds(
            "envelope-body.tokens-under-200000",
            ACCEPT,
            "a v3 JSON body is scanned with the default 200 000-token budget",
            "envelope.decode",
            G(_body_tokens_gen(66_665, _EVENT_JSON_HEADER)),
            tier="stress",
            twin="bounds.envelope-body.tokens-over-200000",
        ),
        _bounds(
            "envelope-body.tokens-over-200000",
            REJECT,
            "and a body past that budget is refused before it is parsed",
            "envelope.decode",
            G(_body_tokens_gen(66_666, _EVENT_JSON_HEADER)),
            tier="stress",
            reason="shape.tokens-exceeded",
            twin="bounds.envelope-body.tokens-under-200000",
        ),
        _bounds(
            "artifact.tokens-under-budget",
            ACCEPT,
            "a .tine artifact's budget is min(16M, max(200 000, len//4)), so a small dense "
            "file gets the 200 000 floor",
            "artifact.parse",
            G(_body_tokens_gen(66_665)),
            tier="stress",
            twin="bounds.artifact.tokens-over-budget",
        ),
        _bounds(
            "artifact.tokens-over-budget",
            REJECT,
            "one token past the floor refuses the artifact",
            "artifact.parse",
            G(_body_tokens_gen(66_666)),
            tier="stress",
            reason="artifact.structure-excessive",
            twin="bounds.artifact.tokens-under-budget",
        ),
        _bounds(
            "pack.shallow-at-10000",
            ACCEPT,
            "MAX_PACK_OBJECTS is 10 000, shared with MAX_TRAVERSAL_OBJECTS",
            "pack.inspect",
            B(
                pack_frame([], [f"blob:sha256:{index:064x}" for index in range(10_000)]),
                store="frame",
            ),
            tier="stress",
            twin="bounds.pack.shallow-at-10001",
        ),
        _bounds(
            "pack.shallow-at-10001",
            REJECT,
            "10 001 shallow entries is one past it",
            "pack.inspect",
            B(
                pack_frame([], [f"blob:sha256:{index:064x}" for index in range(10_001)]),
                store="frame",
            ),
            tier="stress",
            reason="pack.too-many-objects",
            twin="bounds.pack.shallow-at-10000",
        ),
        _bounds(
            "pack.over-256-mib",
            REJECT,
            "MAX_PACK_BYTES refuses a frame one byte past the cap. The frame carries a real "
            "TINEPACK3 magic and a 32-byte digest field, so the size bound is the only rule "
            "it breaks and a reader that checks the magic first still answers pack.oversized",
            "pack.inspect",
            G(
                {
                    "kind": "repeat",
                    "prefix_b64": _PACK_FRAME_PREFIX_B64,
                    "unit_b64": "AA==",
                    "count": 268_435_457 - 42,
                }
            ),
            tier="stress",
            reason="pack.oversized",
        ),
        _bounds(
            "pack.magic-truncated",
            REJECT,
            "a frame shorter than 42 bytes cannot carry a magic and a digest",
            "pack.inspect",
            B(b"TINEPACK3\x00" + b"\x00" * 31),
            reason="pack.bad-magic",
        ),
        _bounds(
            "oid.digest-63-hex",
            REJECT,
            "the digest is exactly 64 hex characters, not at least 64",
            "oid.parse",
            V("blob:sha256:" + "a" * 63),
            reason="oid.malformed",
        ),
    ),
)

FAMILIES = (ENVELOPE, OID, LINKS, METRICS, GRAPH, LOAD, BOUNDS)
