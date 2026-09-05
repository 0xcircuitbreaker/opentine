"""The reason-code registry, and the eleven bounds deliberately not vectored.

A code is spec-anchored, not scraped from a Python message: the reference's
messages are *conflated* (a lone surrogate and a depth failure report the same
string; a ``schema`` of 2**53 reports the *integer* error; a 338-byte header
reports "malformed object envelope"), so a suite that used them as its
vocabulary would teach an implementer the reference's accidents instead of the
format's rules.

``docs/conformance/REASON_CODES.md`` is generated from this table, so the
document cannot drift from the codes the vectors actually use, and
``test_conformance_drift`` requires every registered code to be used by at least
one case and every used code to be registered.

**The single-fault rule.** Every vector violates exactly one rule, because the
reference's check order is fixed and undocumented (``verify_block`` checks
``scheme`` before ``alg``; ``ObjectEnvelope.decode`` runs the 256-byte header
check *inside* the framing ``try``, so an oversized header reports a framing
error, not a size error). Two honest implementations will disagree on any
multi-fault input. The handful of deliberately compound cases carry
``reason_any`` instead of ``reason``.

**Alias groups.** Where the reference genuinely cannot tell two rules apart --
its scanner reports one message for a depth overrun and a token overrun -- the
codes stay distinct (the *rules* are distinct) and the pair is listed in
``ALIAS_GROUPS``. At Level 2 a runner accepts any code from the expected code's
group, so an implementation whose diagnostics are as coarse as the reference's
is not marked wrong for it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Reason:
    section: str
    #: The SPEC 1.6 constant this code enforces, if any, as ``module.NAME``.
    constant: str | None
    refuses: str
    #: The repair an implementation MUST NOT perform instead of refusing.
    never: str


R = Reason

REASONS: dict[str, Reason] = {
    # --- text (0.1) --------------------------------------------------------- #
    "text.lone-surrogate": R(
        "0.1",
        None,
        "a string holding an unpaired UTF-16 surrogate, in escape or raw CESU-8 spelling",
        "substitute U+FFFD, drop the code unit, or pass the surrogate through",
    ),
    # --- canonical JSON (0.2, 0.3) ------------------------------------------ #
    "canon.non-finite": R(
        "0.2/0.3",
        None,
        "a NaN or +/-Infinity float value",
        "emit null, 0, or the JavaScript spellings NaN/Infinity",
    ),
    "canon.integer-overflow": R(
        "0.2",
        "kernel._number",
        "a v3 integer whose absolute value exceeds 2**53-1",
        "round to the nearest double, or emit the value as a JSON string",
    ),
    "canon.depth-exceeded": R(
        "0.2",
        "kernel.MAX_JSON_DEPTH",
        "a container nested at depth 512 or beyond -- at most 512 nested containers",
        "truncate the deep subtree and encode the rest",
    ),
    "canon.unencodable-text": R(
        "0.2",
        None,
        "a value or key UTF-8 cannot encode (a lone surrogate reaching the encoder)",
        "encode with surrogatepass, or replace the code unit",
    ),
    # --- structural scanner (0.5) ------------------------------------------- #
    "shape.depth-exceeded": R(
        "0.5",
        "kernel.MAX_JSON_DEPTH",
        "a byte stream whose running bracket depth exceeds 512",
        "parse anyway and rely on the parser's own recursion limit",
    ),
    "shape.tokens-exceeded": R(
        "0.5",
        None,
        "a byte stream with more structural tokens than the caller's budget",
        "raise the budget to whatever the input needs",
    ),
    # --- envelope (1.2) ------------------------------------------------------ #
    "envelope.malformed": R(
        "1.2",
        None,
        "bytes with no LF, an unparseable header, or a header past 256 bytes",
        "treat the whole file as the body, or repair the header",
    ),
    "envelope.header-non-canonical": R(
        "1.2",
        None,
        "a header that is not byte-identical to the canonical encoding of its own value",
        "re-serialize the header canonically and continue, silently renaming the object",
    ),
    "envelope.header-key-count": R(
        "1.2",
        None,
        "a header with other than exactly three keys",
        "ignore the extra key, or default the missing one",
    ),
    "envelope.schema-not-integer": R(
        "1.2",
        None,
        "a schema that is a bool, a float, a string or null",
        "coerce true to 1 or 1.0 to 1",
    ),
    "envelope.schema-out-of-range": R(
        "1.2",
        None,
        "a schema outside 1 <= schema < 2**53",
        "clamp the value into range",
    ),
    "envelope.unknown-type": R(
        "1.1",
        "kernel.OBJECT_TYPES",
        "a type outside blob/event/run/attestation/annotation",
        "store an unknown type as an opaque extension",
    ),
    "envelope.encoding-mismatch": R(
        "1.2",
        None,
        'an encoding that is not "raw" for a blob and "json" for every other type',
        "believe the encoding field over the type field",
    ),
    "envelope.body-malformed-json": R(
        "1.2",
        None,
        "a json-encoded body that is not parseable JSON",
        "store the bytes verbatim and defer the parse",
    ),
    "envelope.body-non-canonical": R(
        "1.2",
        None,
        "a json body that is not byte-identical to the canonical encoding of its own value",
        "re-serialize the body canonically, which renames the object",
    ),
    "envelope.oid-mismatch": R(
        "1.3",
        None,
        "stored bytes whose derived oid is not the oid they were fetched under",
        "trust the name the bytes were filed under",
    ),
    # --- object ids (1.3) ---------------------------------------------------- #
    "oid.malformed": R(
        "1.3",
        "kernel.OID_RE",
        "a string that is not TYPE:sha256:<64 lowercase hex>",
        "lowercase an uppercase digest, or accept a bare digest",
    ),
    # --- links (1.5) --------------------------------------------------------- #
    "link.parent-ids-not-events": R(
        "1.5.2",
        None,
        "a parent_ids or causal_ids entry that is not an event oid, or a non-list value",
        "filter the offending entry out and keep the rest",
    ),
    "link.parent-ids-duplicate": R(
        "1.5.2",
        None,
        "a duplicate entry in parent_ids or causal_ids",
        "de-duplicate the list",
    ),
    "link.event-blob-not-blob": R(
        "1.5.2",
        None,
        "a truthy input_blob/output_blob/artifact_blob that is not a blob oid",
        "ignore a link field whose value has the wrong type",
    ),
    "link.run-events-invalid": R(
        "1.5.3",
        None,
        "a run events list that is not a duplicate-free list of event oids",
        "de-duplicate or filter the list",
    ),
    "link.run-roots-tips-invalid": R(
        "1.5.3",
        None,
        "a run roots/tips list that is not a duplicate-free list of event oids",
        "de-duplicate or filter the list",
    ),
    "link.run-roots-tips-not-subset": R(
        "1.5.3",
        None,
        "a roots or tips entry that is not in events",
        "add the stray entry to events",
    ),
    "link.run-manifests-not-object": R(
        "1.5.3",
        None,
        "a manifests value that is not an object",
        "coerce a list of pairs into a mapping",
    ),
    "link.run-blob-not-blob": R(
        "1.5.3",
        None,
        "a truthy run key ending _blob, or a manifests value, that is not a blob oid",
        "apply the _blob rule only to a fixed list of known field names",
    ),
    "link.attestation-target-not-run": R(
        "1.5.4",
        None,
        "an attestation with an absent target_id or one that is not a run oid",
        "accept an attestation about an event or a blob",
    ),
    "link.annotation-previous-not-annotation": R(
        "1.5.5",
        None,
        "a truthy previous_id that is not an annotation oid",
        "follow the link anyway and check the type later",
    ),
    "link.evidence-not-list": R(
        "1.5.4",
        None,
        "an evidence_ids value that is not a list",
        "wrap a single oid in a list",
    ),
    "link.missing-object": R(
        "1.5.6",
        None,
        "a link that resolves neither to a local object nor to a shallow-boundary entry",
        "treat an unresolvable link as absent and continue",
    ),
    # --- event metrics (1.5.2) ----------------------------------------------- #
    "metrics.meter-not-finite": R(
        "1.5.2",
        "_run_graph._meter",
        "a cost/duration/time_unix that is not finite and (except time_unix) non-negative",
        "clamp a negative meter to zero, or accept a value float() cannot represent",
    ),
    "metrics.meter-too-long": R(
        "1.5.2",
        None,
        "a numeric-meter string longer than 128 characters",
        "truncate the string and parse the prefix",
    ),
    "metrics.usage-not-object": R(
        "1.5.2",
        None,
        "a truthy usage value that is not an object",
        "coerce a scalar usage into an object",
    ),
    "metrics.usage-value-not-numeric": R(
        "1.5.2",
        None,
        "a usage value that is not exactly an int or a float (a bool is not numeric)",
        "read true as 1, or parse a numeric string",
    ),
    "metrics.token-dimension-unsafe": R(
        "1.5.2",
        "_run_graph._MAX_SAFE_INTEGER",
        "a known token dimension that is fractional or above 2**53-1",
        "round a fractional token count",
    ),
    # --- run graph (1.5.3) --------------------------------------------------- #
    "graph.status-invalid": R(
        "1.5.3",
        None,
        "a run status outside running/paused/completed/failed",
        "default an unknown status to running",
    ),
    "graph.parent-outside-graph": R(
        "1.5.3",
        None,
        "a locally present event whose parent is not in the run's events",
        "add the missing parent to events",
    ),
    "graph.causal-outside-graph": R(
        "1.5.3",
        None,
        "a locally present event whose causal link is not in the run's events",
        "add the missing link to events",
    ),
    "graph.order-not-topological": R(
        "1.5.3",
        None,
        "an events list where a parent or causal link is not at a strictly earlier index",
        "sort events topologically on read",
    ),
    "graph.roots-mismatch": R(
        "1.5.3",
        None,
        "roots that are not exactly the parentless events, when every event is present",
        "recompute roots from the graph and ignore the stored value",
    ),
    "graph.tips-mismatch": R(
        "1.5.3",
        None,
        "tips that are not exactly the graph leaves, when every event is present",
        "recompute tips from the graph and ignore the stored value",
    ),
    "graph.legacy-refs-invalid": R(
        "1.5.3",
        None,
        "a legacy_refs value that is not a string->event-in-run mapping",
        "drop the offending entry",
    ),
    # --- annotation chain (1.5.5) -------------------------------------------- #
    "chain.target-changed": R(
        "1.5.5",
        None,
        "a previous annotation whose target_id differs from this one's",
        "let a chain re-target midway",
    ),
    "chain.previous-unavailable": R(
        "1.5.5",
        None,
        "a previous_id whose object cannot be read",
        "treat an unreadable predecessor as the chain root",
    ),
    # --- loose object layout (2.3) ------------------------------------------- #
    "path.invalid-oid": R(
        "2.3",
        None,
        "deriving a loose-object path from a string that is not an oid",
        "build a path out of whatever characters the string holds",
    ),
    # --- config (2.2) -------------------------------------------------------- #
    "config.oversized": R(
        "2.2",
        "_config.MAX_CONFIG_BYTES",
        "a config.json larger than 65 536 bytes",
        "read the first 64 KiB and parse that",
    ),
    "config.malformed": R(
        "2.2",
        None,
        "a config.json that is not parseable JSON, or fails the 10 000-token scan",
        "fall back to repository defaults",
    ),
    "config.incompatible": R(
        "2.2",
        None,
        "a config.json missing or contradicting any of the four required pairs",
        "accept format 2, or default a missing object_hash to sha256",
    ),
    # --- refs (2.4, 2.5) ------------------------------------------------------ #
    "ref.name-namespace": R(
        "2.4",
        "_refs._REF",
        "a ref name outside annotations/heads/tags/experiments/promotions/remotes",
        "invent a namespace for an unrecognised prefix",
    ),
    "ref.name-charset": R(
        "2.4",
        "_refs._REF",
        "a ref name holding a character outside [a-z0-9._/-]",
        "percent-encode or transliterate the offending character",
    ),
    "ref.name-not-casefolded": R(
        "2.4",
        None,
        "a ref name that is not equal to its own case-fold",
        "lowercase the name and continue",
    ),
    "ref.name-too-long": R(
        "2.4",
        None,
        "a ref name longer than 512 bytes",
        "truncate the name",
    ),
    "ref.component-too-long": R(
        "2.4",
        "_refs.MAX_REF_COMPONENT_BYTES",
        "a ref name component longer than 240 bytes",
        "truncate the component",
    ),
    "ref.component-reserved": R(
        "2.4",
        None,
        "a component that is empty, . or .., contains .., or ends in .lock, . or a space",
        "normalize the component away",
    ),
    "ref.component-windows-device": R(
        "2.4",
        None,
        "a component whose pre-dot prefix is a Windows device name",
        "accept it because this host is not Windows",
    ),
    "ref.file-oversized": R(
        "2.4",
        "_ref_store.MAX_REF_BYTES",
        "a ref file larger than 256 bytes",
        "read the first line and ignore the rest",
    ),
    "ref.file-not-ascii": R(
        "2.4",
        None,
        "a ref file that is not ASCII",
        "decode it as UTF-8 or latin-1",
    ),
    "ref.file-not-canonical": R(
        "2.4",
        None,
        "a ref file with trailing bytes other than one LF or CRLF, or internal whitespace",
        "strip surrounding whitespace and take what is left",
    ),
    "ref.target-type": R(
        "2.5",
        "_refs.TYPED_REF_NAMESPACES",
        "a typed-namespace ref pointing at the wrong object type",
        "let heads/ point at an event because the oid parses",
    ),
    "ref.annotation-name-mismatch": R(
        "2.5",
        None,
        "an annotations/<digest> ref whose annotation does not target run:sha256:<digest>",
        "rename the ref to match the annotation",
    ),
    # --- reflog (2.6) --------------------------------------------------------- #
    "reflog.actor-too-long": R(
        "2.6",
        "_reflog.reflog_entry",
        "a reflog actor longer than 4096 characters",
        "truncate the actor",
    ),
    "reflog.time-not-string": R(
        "2.6",
        None,
        "a time_ns that is not decimal digits inside a JSON string",
        "emit the nanosecond timestamp as a JSON number",
    ),
    # --- shallow (2.7) -------------------------------------------------------- #
    "shallow.oversized": R(
        "2.7",
        "_shallow.MAX_SHALLOW_BYTES",
        "a shallow file larger than 1 048 576 bytes",
        "read a prefix of the file",
    ),
    "shallow.not-ascii": R(
        "2.7",
        None,
        "a shallow file that is not ASCII",
        "decode it as UTF-8",
    ),
    "shallow.carriage-return": R(
        "2.7",
        None,
        "a CR anywhere in a shallow file",
        "normalize CRLF to LF",
    ),
    "shallow.empty-line": R(
        "2.7",
        None,
        "an empty line inside a shallow file",
        "skip blank lines",
    ),
    "shallow.too-many": R(
        "2.7",
        "_shallow.MAX_SHALLOW_OBJECTS",
        "more than 10 000 shallow entries",
        "keep the first 10 000",
    ),
    "shallow.duplicate": R(
        "2.7",
        None,
        "a duplicate oid in a shallow file",
        "de-duplicate the set",
    ),
    # --- packs (2.8) ---------------------------------------------------------- #
    "pack.oversized": R(
        "2.8",
        "pack.MAX_PACK_BYTES",
        "a frame larger than 268 435 456 bytes",
        "stream past the cap",
    ),
    "pack.bad-magic": R(
        "2.8",
        None,
        "a frame that does not begin with TINEPACK3\\x00, or is shorter than 42 bytes",
        "sniff the compression and continue",
    ),
    "pack.invalid-compression": R(
        "2.8",
        None,
        "a zlib stream that will not inflate",
        "fall back to reading the bytes uncompressed",
    ),
    "pack.truncated-or-trailing": R(
        "2.8",
        None,
        "a truncated zlib stream, or trailing bytes after end-of-stream",
        "use whatever inflated before the error",
    ),
    "pack.checksum-mismatch": R(
        "2.8",
        None,
        "an inflated manifest whose SHA-256 is not the frame's bytes 10..42",
        "recompute the header digest from the body",
    ),
    "pack.manifest-malformed": R(
        "2.8",
        None,
        "a manifest that is not parseable JSON or not an object",
        "treat an unparseable manifest as an empty pack",
    ),
    "pack.manifest-non-canonical": R(
        "2.8",
        None,
        "a manifest that is not byte-identical to its own canonical encoding",
        "re-serialize it canonically, changing the pack id",
    ),
    "pack.manifest-key-set": R(
        "2.8",
        None,
        'a top-level key set other than exactly {"objects","shallow","version"}',
        "ignore an unknown top-level key",
    ),
    "pack.version-unsupported": R(
        "2.8",
        None,
        "a version that is not the integer 1 (true is not 1)",
        "read true as 1",
    ),
    "pack.arrays-invalid": R(
        "2.8",
        None,
        "an objects or shallow value that is not an array",
        "wrap a single entry in an array",
    ),
    "pack.too-many-objects": R(
        "2.8",
        "pack.MAX_PACK_OBJECTS",
        "more than 10 000 entries in objects or shallow",
        "install the first 10 000",
    ),
    "pack.entry-shape": R(
        "2.8",
        None,
        'an objects entry that is not an object with key set exactly {"data","id"}',
        "read a known key and ignore the rest",
    ),
    "pack.entry-base64": R(
        "2.8",
        None,
        "a data value that is not strictly valid padded standard base64",
        "strip whitespace or accept URL-safe base64",
    ),
    "pack.entry-oid-mismatch": R(
        "2.8",
        None,
        "an entry whose decoded envelope does not derive the entry's id",
        "trust the declared id",
    ),
    "pack.duplicate-ids": R(
        "2.8",
        None,
        "a duplicate id in objects, or a duplicate oid in shallow",
        "de-duplicate",
    ),
    "pack.shallow-overlaps-objects": R(
        "2.8",
        None,
        "an oid appearing in both objects and shallow",
        "prefer the packed copy and drop the boundary entry",
    ),
    "pack.shallow-invalid-oid": R(
        "2.8",
        None,
        "a shallow entry that is not a string, or not a valid oid",
        "skip the malformed entry",
    ),
    "pack.unresolved-link": R(
        "2.8",
        None,
        "a link that is neither packed, present locally, nor declared shallow",
        "install anyway and hope the object arrives later",
    ),
    "pack.shallow-not-link-closure": R(
        "2.8",
        None,
        "a shallow set that is not exactly the packed objects' external links",
        "install the pack and reconcile the boundary afterwards",
    ),
    # --- the portable .tine artifact (Part 3) --------------------------------- #
    "artifact.nul-byte": R(
        "3.7",
        None,
        "a NUL byte anywhere in the artifact bytes",
        "strip the NUL and parse the rest",
    ),
    "artifact.structure-excessive": R(
        "3.1",
        "_artifact_io._structural_token_budget",
        "an artifact past the depth bound or its size-relative structural-token budget",
        "raise the budget for this one file",
    ),
    "artifact.duplicate-key": R(
        "3.7",
        None,
        "a duplicate object key anywhere in the artifact",
        "apply last-wins, the parser differential this rule exists to refuse",
    ),
    "artifact.non-finite": R(
        "3.7",
        None,
        "a NaN, Infinity or -Infinity literal",
        "map it to null",
    ),
    "artifact.integer-too-many-digits": R(
        "3.1",
        "_artifact_io.MAX_TINE_INTEGER_DIGITS",
        "an integer literal with more than 4096 decimal digits",
        "parse it as a float",
    ),
    "artifact.lone-surrogate": R(
        "3.7",
        None,
        "an artifact whose parsed text holds an unpaired surrogate",
        "substitute U+FFFD",
    ),
    "artifact.malformed-json": R(
        "3.1",
        None,
        "bytes that are not parseable JSON",
        "recover a prefix of the document",
    ),
    # --- signatures (Part 4) --------------------------------------------------- #
    "sig.payload-not-object": R(
        "4.2",
        None,
        "building a message over a document that is not an object",
        "sign the string form of whatever was supplied",
    ),
}

#: Codes the reference genuinely cannot tell apart. A Level 2 runner accepts any
#: member of the expected code's group. The *rules* stay distinct because an
#: implementation with finer diagnostics should be able to say which it hit.
ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    ("shape.depth-exceeded", "shape.tokens-exceeded"),
    ("envelope.header-non-canonical", "envelope.header-key-count"),
    ("envelope.unknown-type", "envelope.encoding-mismatch"),
    ("link.parent-ids-not-events", "link.parent-ids-duplicate"),
    ("link.run-events-invalid", "link.run-roots-tips-invalid"),
    (
        "link.evidence-not-list",
        "oid.malformed",
        "path.invalid-oid",
        "pack.shallow-invalid-oid",
        "link.attestation-target-not-run",
    ),
    # A link field holding a non-oid reaches parse_oid, so the reference reports
    # the *oid* error for it -- exactly the conflation x_reference exposes.
    ("link.event-blob-not-blob", "link.run-blob-not-blob", "oid.malformed"),
    ("envelope.schema-not-integer", "envelope.schema-out-of-range"),
    ("pack.arrays-invalid", "pack.manifest-malformed"),
    ("pack.manifest-non-canonical", "pack.manifest-key-set", "pack.version-unsupported"),
    ("pack.entry-shape", "pack.entry-base64", "pack.entry-oid-mismatch"),
    (
        "ref.name-namespace",
        "ref.name-charset",
        "ref.name-not-casefolded",
        "ref.name-too-long",
        "ref.component-too-long",
        "ref.component-reserved",
        "ref.component-windows-device",
    ),
    ("metrics.meter-not-finite", "metrics.meter-too-long"),
    ("config.malformed", "shape.tokens-exceeded"),
    ("chain.target-changed", "chain.previous-unavailable"),
    # SPEC 0.1 is a format-boundary rule, so an implementation may enforce it at its
    # UTF-8 decode boundary rather than at the op the vector names. The code follows
    # the op here; the rule is one rule.
    ("text.lone-surrogate", "canon.unencodable-text", "artifact.lone-surrogate"),
)

#: Bounds and rules in SPEC 1.6 / Part 2 that no stateless vector can reach, each
#: with the reason written out. Drift gate 9 requires every 1.6 row to have an
#: at/over pair, a ``reachable: false`` case, or an entry here.
NOT_VECTORED: dict[str, str] = {
    "pack.MAX_PACK_BODY_BYTES": (
        "268 435 456 bytes of *inflated* manifest. Expressing it needs a frame whose "
        "compressed bytes are zlib-version-dependent, and the suite's determinism rule "
        "forbids pinning compressor output -- pack frames are reader inputs generated once, "
        "never a writer expectation. MAX_PACK_BYTES, which is checked against the frame "
        "length before anything is inflated, IS vectored (bounds.pack.over-256-mib)."
    ),
    "_artifact_io.MAX_TINE_ARTIFACT_BYTES": (
        "268 435 456 bytes, enforced by read_artifact_bytes against a file's stat() before "
        "any byte is read. The op contract has no file: every input is a byte string a "
        "runner already holds, so the bound has nothing to refuse."
    ),
    "0.2 rule 4 non-string keys / rule 8 unsupported types": (
        "A non-string object key and a non-JSON value are unreachable from a JSON document: "
        "the tagged value tree cannot spell either, and a byte-level input carrying one is "
        "not JSON, so the correct answer becomes 'not parseable' rather than 'not "
        "canonicalizable'. An implementation whose parser refuses the input has already "
        "conformed; asking for a WTF-8-capable string type to run a canonicalization vector "
        "is a barrier with no payoff."
    ),
    "1.5.5 previous_id resolving to a non-annotation": (
        "The oid's type prefix is inside the hash (SPEC 1.3) and "
        "ObjectEnvelope.decode(raw, expected_oid) refuses bytes whose derived oid is not the "
        "one they were fetched under, so an annotation: previous_id can never return a run "
        "or an event. A vector aimed at the type branch is answered by the predecessor "
        "availability check instead, which chain.previous-unavailable already vectors -- so "
        "the case was retired rather than left pinning a duplicate. The half of the rule a "
        "single input CAN reach is the oid's own type prefix, vectored as "
        "links.annotation.previous-not-an-annotation."
    ),
    "1.5.3 events entry resolving to a non-event": (
        "The oid's type prefix is inside the hash (SPEC 1.3), so an event: oid can never "
        "address a stored run or blob. The reference's check is defence in depth against a "
        "repository whose object store already lied, which no single input can express."
    ),
    "_canon_redact.MAX_CANONICAL_DEPTH": (
        "768 bounds a Python-object walk, not a format. validate_json_shape refuses byte "
        "depth over 512 before any parse and canonical_json refuses container depth at 512, "
        "so no JSON document can reach 768: a 600-deep artifact is refused by "
        "parse_artifact_json at the shape scan and never reaches _jsonable. The accept half "
        "of an at/over pair is impossible, so neither half is vectored."
    ),
    "_traversal.MAX_TRAVERSAL_OBJECTS": (
        "10 000 objects bounds a repository *graph walk*, which is not a stateless op over "
        "one input. The pack family carries the same number as MAX_PACK_OBJECTS, where it is "
        "reachable from a single manifest."
    ),
    "_objects.MAX_TYPED_OBJECT_SCAN": (
        "100 000 bounds a directory enumeration. A conformance vector is one input and one "
        "answer; a filesystem with 100 001 entries is neither."
    ),
    "_associations.MAX_ASSOCIATION_SCAN": (
        "100 000 bounds the same kind of directory enumeration as MAX_TYPED_OBJECT_SCAN: the "
        "walk that finds every annotation and attestation associated with a run. A single "
        "input cannot express a directory with 100 001 entries in it."
    ),
    "_annotations.MAX_LEGACY_OBJECTS": (
        "100 000 bounds the legacy-annotation directory scan; again an enumeration bound, "
        "not a property of any single input."
    ),
    "1.5.6 self-link": (
        "SPEC 1.5.6's 'an object MUST NOT link to itself' is checked as link == envelope.oid, "
        "where envelope.oid is SHA-256 over the body containing that link. Constructing such "
        "an object is a SHA-256 preimage attack. The reference implementation has no test for "
        "it either (grep finds no use of 'cannot link to itself' under tests/), and no reason "
        "code is registered for a rule no input can trigger."
    ),
    "envelope header 256 bytes": (
        "Reject-only: the maximal *canonical* three-key header is 66 bytes "
        '({"encoding":"json","schema":9007199254740991,"type":"attestation"}), so there '
        "is no accepting input at 256 bytes to pair with. The 66-byte case is vectored as the "
        "twin instead, and the oversized case reports envelope.malformed because "
        "ObjectEnvelope.decode runs the size check inside the framing try."
    ),
    "2.3 skip-not-error enumeration": (
        "'A stray objects/ entry is skipped, not an error' is a directory-listing property. "
        "The compat family, which opens eight real published repositories, is its evidence."
    ),
    "2.4/2.7 filesystem rules": (
        "Hard-linked refs, st_nlink, symlink/junction confinement and the .lock/..lock CAS "
        "protocol are storage-layer rules with no byte-level input. The reference's own tests "
        "and scripts/win_fs_sim.py cover them; a passing conformance scorecard does not "
        "certify the storage layer, and the README says so."
    ),
    "3.6 v2 step-id derivation": (
        "SPEC 3.6 documents v2 step identity as a known-broken claim retained for "
        "compatibility. Encoding it as a conformance requirement would ask third parties to "
        "reproduce a defect on purpose."
    ),
    "2.9 fsck / 5.4 migration / remote / CLI / replay / pricing": (
        "Out of scope for 0.9.0. fsck is a repository walk, migration is a writer pipeline, "
        "and the remote protocol, the CLI JSON contract, replay and pricing are not the "
        "stored format at all. The README states this so the badge cannot overclaim."
    ),
}


#: ``module`` prefix -> the importable module, so a bound named in a reason row
#: or in ``BOUND_COVERAGE`` can be resolved to its **live** value rather than a
#: number retyped into a document.
CONSTANT_MODULES: dict[str, str] = {
    "kernel": "opentine.kernel",
    "_canon_redact": "opentine._canon_redact",
    "_artifact_io": "opentine._artifact_io",
    "_signing_verify": "opentine._signing_verify",
    "_run_graph": "opentine.repository._run_graph",
    "_refs": "opentine.repository._refs",
    "_ref_store": "opentine.repository._ref_store",
    "_reflog": "opentine.repository._reflog",
    "_config": "opentine.repository._config",
    "_shallow": "opentine.repository._shallow",
    "_traversal": "opentine.repository._traversal",
    "_objects": "opentine.repository._objects",
    "_associations": "opentine.repository._associations",
    "_annotations": "opentine.repository._annotations",
    "pack": "opentine.repository.pack",
}

#: Every row of SPEC 1.6, by the label in its first column, mapped to the case
#: ids that reach it -- an accepting case at the bound and a refusing case one
#: past it -- or to the ``NOT_VECTORED`` key that explains why no vector can.
#:
#: This is drift gate 9. A bound with no vector and no written reason is a bound
#: a third-party implementer cannot check, which is the failure mode a prose
#: rejection table has and a vector suite is supposed to remove.
BOUND_COVERAGE: dict[str, tuple[str, ...]] = {
    "JSON nesting depth": ("shape.depth.at-512", "shape.depth.at-513"),
    "structural tokens, object body": (
        "bounds.envelope-body.tokens-under-200000",
        "bounds.envelope-body.tokens-over-200000",
    ),
    "canonical integer magnitude": ("canon.v3.integer.max-safe", "canon.v3.integer.at-2-53"),
    "envelope schema range": ("env.schema.seven-accepts", "env.schema.zero"),
    "envelope header size": ("NOT_VECTORED:envelope header 256 bytes",),
    "write-side walk depth": ("NOT_VECTORED:_canon_redact.MAX_CANONICAL_DEPTH",),
    "token-count dimensions": (
        "metrics.usage.token-dimension-at-max-safe",
        "metrics.usage.token-dimension-at-2-53",
    ),
    "numeric-meter string length": (
        "metrics.duration.numeric-string-at-128-chars",
        "metrics.meter.string-at-129-chars",
    ),
    "ref file size": ("bounds.ref-file.canonical", "bounds.ref-file.at-257-bytes"),
    "ref name, total": ("bounds.ref-name.at-512-bytes", "bounds.ref-name.at-513-bytes"),
    "ref name, per component": (
        "bounds.ref-component.at-240-bytes",
        "bounds.ref-component.at-241-bytes",
    ),
    "reflog actor": ("bounds.reflog-actor.at-4096-chars", "bounds.reflog-actor.at-4097-chars"),
    "config size": ("bounds.config.at-65536-bytes", "bounds.config.at-65537-bytes"),
    "config structural tokens": (
        "bounds.config.tokens-under-budget",
        "bounds.config.tokens-over-budget",
    ),
    "shallow entries": ("bounds.shallow.at-10000-entries", "bounds.shallow.at-10001-entries"),
    "shallow file size": ("bounds.shallow.over-1-mib",),
    "pack transfer size": ("bounds.pack.over-256-mib",),
    "pack manifest size": ("NOT_VECTORED:pack.MAX_PACK_BODY_BYTES",),
    "objects per pack": ("bounds.pack.shallow-at-10000", "bounds.pack.shallow-at-10001"),
    "graph traversal": ("NOT_VECTORED:_traversal.MAX_TRAVERSAL_OBJECTS",),
    "typed object scan": ("NOT_VECTORED:_objects.MAX_TYPED_OBJECT_SCAN",),
    "association scan": ("NOT_VECTORED:_associations.MAX_ASSOCIATION_SCAN",),
    "legacy annotation scan": ("NOT_VECTORED:_annotations.MAX_LEGACY_OBJECTS",),
    "`.tine` artifact size": ("NOT_VECTORED:_artifact_io.MAX_TINE_ARTIFACT_BYTES",),
    "`.tine` integer digits": ("artifact.integer.4096-digits", "artifact.integer.4097-digits"),
    "HMAC key floor": (
        "verdict.attest.verified-with-floor-key",
        "verdict.attest.error-hmac-key-too-short",
    ),
}


def constant_value(name: str) -> object | None:
    """The live value of a ``module.NAME`` bound, or ``None`` when it is callable."""
    import importlib

    prefix, _, attribute = name.partition(".")
    module_path = CONSTANT_MODULES.get(prefix)
    if module_path is None or not attribute:
        return None
    value = getattr(importlib.import_module(module_path), attribute, None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
