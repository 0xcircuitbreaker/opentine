"""SPEC Part 2: repository layout, refs, the reflog, shallow state, and packs."""

from __future__ import annotations

import base64

from opentine.kernel import canonical_json
from tests.conformance.builders import (
    ANNOTATION_V1,
    ANNOTATION_V1_OID,
    CHILD_EVENT_OID,
    CONFIG_BYTES,
    HELLO_BLOB,
    HELLO_OID,
    LINKED_EVENT,
    LINKED_EVENT_OID,
    ROOT_EVENT,
    ROOT_EVENT_OID,
    RUN_OBJECT,
    RUN_OBJECT_OID,
    b64,
    pack_frame,
    pack_frame_from_body,
)
from tests.conformance.cases import ACCEPT, REJECT, B, Case, Family, V

READER, WRITER = "reader", "writer"


def _c(**kwargs) -> Case:
    return Case(**kwargs)


# --------------------------------------------------------------------------- #
# 22 -- config.json and the loose-object path
# --------------------------------------------------------------------------- #


def _layout(name, expect, intent, op, spec_input, section, **extra) -> Case:
    return _c(
        id=f"layout.{name}",
        section=section,
        checklist=(6,),
        op=op,
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


LAYOUT = Family(
    "22-layout.json",
    "2.2",
    "layout",
    (
        _layout(
            "path.blob",
            ACCEPT,
            "a loose object lives at objects/<type>/<2 hex>/<62 hex>",
            "object.path",
            V(HELLO_OID),
            "2.3",
        ),
        _layout(
            "path.event",
            ACCEPT,
            "the type is a real directory level, so two types never share a fan-out bucket",
            "object.path",
            V(ROOT_EVENT_OID),
            "2.3",
        ),
        _layout(
            "path.run",
            ACCEPT,
            "the split is 2 and 62, not 2 and 64",
            "object.path",
            V(RUN_OBJECT_OID),
            "2.3",
        ),
        _layout(
            "config.canonical",
            ACCEPT,
            "the descriptor is exactly four key/value pairs, canonical, LF-terminated",
            "config.validate",
            B(CONFIG_BYTES),
            "2.2",
        ),
        _layout(
            "config.unknown-key-accepted",
            ACCEPT,
            "a documented wart: validation checks only that the four required pairs match, "
            "so an unknown key passes",
            "config.validate",
            B(
                b'{"format":3,"future":true,"object_hash":"sha256","repository":"opentine",'
                b'"version":1}\n'
            ),
            "2.2",
        ),
        _layout(
            "config.non-canonical-formatting-accepted",
            ACCEPT,
            "the same wart for formatting: the file need not be canonical or newline-terminated",
            "config.validate",
            B(
                b'{\n  "repository": "opentine",\n  "format": 3,\n  "version": 1,\n'
                b'  "object_hash": "sha256"\n}'
            ),
            "2.2",
        ),
        _layout(
            "path.not-an-oid",
            REJECT,
            "a path is derived from a parsed oid, never from raw string slicing",
            "object.path",
            V("../../etc/passwd"),
            "2.3",
            reason="path.invalid-oid",
            repair_temptation="slice the string and build a path out of whatever it holds",
        ),
        _layout(
            "path.uppercase-hex",
            REJECT,
            "an uppercase digest is not an oid, so it names no path",
            "object.path",
            V("blob:sha256:" + "A" * 64),
            "2.3",
            reason="path.invalid-oid",
        ),
        _layout(
            "config.format-2",
            REJECT,
            "format MUST be 3; a v2 sidecar directory is not a v3 repository",
            "config.validate",
            B(b'{"format":2,"object_hash":"sha256","repository":"opentine","version":1}\n'),
            "2.2",
            reason="config.incompatible",
        ),
        _layout(
            "config.missing-object-hash",
            REJECT,
            "all four pairs must be present and equal, not merely compatible",
            "config.validate",
            B(b'{"format":3,"repository":"opentine","version":1}\n'),
            "2.2",
            reason="config.incompatible",
            repair_temptation="default a missing object_hash to sha256",
        ),
        _layout(
            "config.not-json",
            REJECT,
            "a descriptor that will not parse is a refusal, not a fallback to defaults",
            "config.validate",
            B(b"repository = opentine\n"),
            "2.2",
            reason="config.malformed",
        ),
        _layout(
            "config.not-an-object",
            REJECT,
            "and a JSON array is not a descriptor",
            "config.validate",
            B(b'[3,"sha256"]'),
            "2.2",
            reason="config.incompatible",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 24 -- refs
# --------------------------------------------------------------------------- #

_DIGEST = RUN_OBJECT_OID.split(":")[-1]


def _ref(name, expect, intent, op, spec_input, **extra) -> Case:
    return _c(
        id=f"ref.{name}",
        section=extra.pop("section", "2.4"),
        checklist=(6,),
        op=op,
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


def _name_reject(name, value, intent, reason) -> Case:
    return _ref(f"name.{name}", REJECT, intent, "ref.name", V(value), reason=reason)


REFS = Family(
    "24-refs.json",
    "2.4",
    "refs",
    (
        _ref("name.heads-main", ACCEPT, "the ordinary case", "ref.name", V("heads/main")),
        _ref(
            "name.strips-refs-prefix",
            ACCEPT,
            "a leading refs/ is removed before matching, so both spellings normalize alike",
            "ref.name",
            V("refs/heads/main"),
            must_differ=False,
            twin="ref.name.heads-main",
        ),
        _ref(
            "name.tags-nested",
            ACCEPT,
            "a name may carry more than one component",
            "ref.name",
            V("tags/release/2026-09"),
        ),
        _ref(
            "name.experiments",
            ACCEPT,
            "each namespace of the regex",
            "ref.name",
            V("experiments/alpha"),
        ),
        _ref(
            "name.remotes",
            ACCEPT,
            "including the untyped ones",
            "ref.name",
            V("remotes/origin/main"),
        ),
        _ref(
            "name.annotations-digest",
            ACCEPT,
            "an annotations ref is named for the run digest its annotation targets",
            "ref.name",
            V(f"annotations/{_DIGEST}"),
        ),
        _ref(
            "name.dots-and-dashes",
            ACCEPT,
            "the character class is [a-z0-9._/-]; dots and dashes inside a component are fine",
            "ref.name",
            V("heads/feature.a-b"),
        ),
        _ref(
            "file.oid-lf",
            ACCEPT,
            "writers emit <oid> LF, and that is what readers expect",
            "ref.file",
            B((HELLO_OID + "\n").encode("ascii")),
        ),
        _ref(
            "file.oid-crlf",
            ACCEPT,
            "a CRLF terminator is accepted too, because a Windows checkout produces one",
            "ref.file",
            B((HELLO_OID + "\r\n").encode("ascii")),
            must_differ=False,
            twin="ref.file.oid-lf",
        ),
        _ref(
            "file.oid-bare",
            ACCEPT,
            "and so is a file with no terminator at all",
            "ref.file",
            B(HELLO_OID.encode("ascii")),
        ),
        _ref(
            "target.heads-points-at-a-run",
            ACCEPT,
            "heads/ is a typed namespace and requires a run",
            "ref.target",
            V(RUN_OBJECT_OID),
            section="2.5",
            args={"name": "heads/main", "objects": [b64(RUN_OBJECT)]},
        ),
        _ref(
            "target.annotations-name-matches-run",
            ACCEPT,
            "annotations/<digest> is the only legal name for an annotation of that run",
            "ref.target",
            V(ANNOTATION_V1_OID),
            section="2.5",
            args={"name": f"annotations/{_DIGEST}", "objects": [b64(ANNOTATION_V1)]},
        ),
        _name_reject(
            "unknown-namespace",
            "branches/main",
            "the namespace set is closed; there is no fallback namespace",
            "ref.name-namespace",
        ),
        _name_reject(
            "uppercase-letter",
            "heads/Main",
            "a name must equal its own case-fold, and the class excludes A-Z anyway",
            "ref.name-not-casefolded",
        ),
        _name_reject(
            "space",
            "heads/my ref",
            "a space is outside the character class",
            "ref.name-charset",
        ),
        _name_reject(
            "at-sign",
            "heads/a@b",
            "so is an @, a +, or anything else outside [a-z0-9._/-]",
            "ref.name-charset",
        ),
        _name_reject(
            "non-ascii",
            "heads/naïve",
            "and so is any non-ASCII character, even one that case-folds to itself",
            "ref.name-charset",
        ),
        _name_reject(
            "component-dot",
            "heads/./main",
            "a . component is refused",
            "ref.component-reserved",
        ),
        _name_reject(
            "component-dotdot",
            "heads/../main",
            "so is a .. component",
            "ref.component-reserved",
        ),
        _name_reject(
            "embedded-dotdot",
            "heads/a..b",
            "and so is .. anywhere inside a component, not only as the whole component",
            "ref.component-reserved",
        ),
        _name_reject(
            "lock-suffix",
            "heads/main.lock",
            "a .lock suffix is the guard-lock spelling and can never be a ref",
            "ref.component-reserved",
        ),
        _name_reject(
            "trailing-dot",
            "heads/main.",
            "a component ending in a dot is refused, which is what makes <ref>..lock safe",
            "ref.component-reserved",
        ),
        _name_reject(
            "trailing-space",
            "heads/main ",
            "a trailing space is refused for the same reason (and by the character class)",
            "ref.name-charset",
        ),
        _name_reject(
            "windows-device-con",
            "heads/con",
            "a component whose pre-dot prefix is a Windows device name cannot be a filename "
            "on every supported platform, so it is refused on all of them",
            "ref.component-windows-device",
        ),
        _ref(
            "file.not-ascii",
            REJECT,
            "a ref file is ASCII; there is nothing in an oid that is not",
            "ref.file",
            B("blob:sha256:é".encode() + b"\n"),
            reason="ref.file-not-ascii",
        ),
        _ref(
            "file.internal-space",
            REJECT,
            "no internal whitespace: a ref file is one token",
            "ref.file",
            B((HELLO_OID + " \n").encode("ascii")),
            reason="ref.file-not-canonical",
            repair_temptation="strip surrounding whitespace and take what is left",
        ),
        _ref(
            "file.trailing-garbage",
            REJECT,
            "and no trailing bytes other than one LF or one CRLF",
            "ref.file",
            B((HELLO_OID + "\nstale\n").encode("ascii")),
            reason="ref.file-not-canonical",
        ),
        _ref(
            "file.cr-only",
            REJECT,
            "a bare CR is not one of the two accepted terminators",
            "ref.file",
            B((HELLO_OID + "\r").encode("ascii")),
            reason="ref.file-not-canonical",
        ),
        _ref(
            "file.not-an-oid",
            REJECT,
            "the content must parse as an oid, not merely look like one",
            "ref.file",
            B(b"blob:sha256:not-hex\n"),
            reason="oid.malformed",
        ),
        _ref(
            "target.heads-points-at-an-event",
            REJECT,
            "heads/ requires a run; a syntactically valid event oid is still wrong",
            "ref.target",
            V(ROOT_EVENT_OID),
            section="2.5",
            args={"name": "heads/main", "objects": [b64(ROOT_EVENT)]},
            reason="ref.target-type",
            twin="ref.target.heads-points-at-a-run",
        ),
        _ref(
            "target.experiments-points-at-a-blob",
            REJECT,
            "experiments/ requires a run too",
            "ref.target",
            V(HELLO_OID),
            section="2.5",
            args={"name": "experiments/alpha", "objects": [b64(HELLO_BLOB)]},
            reason="ref.target-type",
        ),
        _ref(
            "target.annotations-points-at-a-run",
            REJECT,
            "annotations/ requires an annotation, not the run it describes",
            "ref.target",
            V(RUN_OBJECT_OID),
            section="2.5",
            args={"name": f"annotations/{_DIGEST}", "objects": [b64(RUN_OBJECT)]},
            reason="ref.target-type",
        ),
        _ref(
            "target.annotations-name-mismatch",
            REJECT,
            "the name after annotations/ MUST equal the target run's 64-hex digest",
            "ref.target",
            V(ANNOTATION_V1_OID),
            section="2.5",
            args={"name": "annotations/" + "0" * 64, "objects": [b64(ANNOTATION_V1)]},
            reason="ref.annotation-name-mismatch",
            repair_temptation="rename the ref to match the annotation it found",
            twin="ref.target.annotations-name-matches-run",
        ),
        _ref(
            "target.tags-untyped-still-parses",
            REJECT,
            "tags/ is unconstrained by type, but the target oid must still be an oid",
            "ref.target",
            V("tags/not-an-oid"),
            section="2.5",
            args={"name": "tags/release"},
            reason="oid.malformed",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 26 -- the reflog (writer profile only)
# --------------------------------------------------------------------------- #


def _reflog(name, expect, intent, row, **extra) -> Case:
    return _c(
        id=f"reflog.{name}",
        section="2.6",
        checklist=(6,),
        op="reflog.row",
        profile=WRITER,
        expect=expect,
        intent=intent,
        input=V(row),
        **extra,
    )


REFLOG = Family(
    "26-reflog.json",
    "2.6",
    "reflog",
    (
        _reflog(
            "row.first",
            ACCEPT,
            "a ref's first row carries old = null",
            {
                "actor": "local",
                "new": RUN_OBJECT_OID,
                "old": None,
                "ref": "heads/main",
                "time_ns": "1757030400000000000",
            },
        ),
        _reflog(
            "row.subsequent",
            ACCEPT,
            "and every later row carries the previous value",
            {
                "actor": "local",
                "new": RUN_OBJECT_OID,
                "old": ROOT_EVENT_OID,
                "ref": "heads/main",
                "time_ns": "1757030400000000001",
            },
        ),
        _reflog(
            "row.time-ns-beyond-2-53",
            ACCEPT,
            "time_ns is a *string* precisely because canonical JSON rejects integers beyond "
            "2**53-1, and a nanosecond epoch timestamp is far past it",
            {
                "actor": "local",
                "new": RUN_OBJECT_OID,
                "old": None,
                "ref": "heads/main",
                "time_ns": "9007199254740993",
            },
        ),
        _reflog(
            "row.field-order-is-canonical",
            ACCEPT,
            "the row is canonical JSON, so the five keys are emitted in one fixed order "
            "whatever order the writer held them in",
            {
                "time_ns": "1",
                "ref": "heads/main",
                "old": None,
                "new": RUN_OBJECT_OID,
                "actor": "local",
            },
        ),
        _reflog(
            "row.annotations-ref",
            ACCEPT,
            "the ref field carries the normalized name, including its namespace",
            {
                "actor": "local",
                "new": ANNOTATION_V1_OID,
                "old": None,
                "ref": f"annotations/{_DIGEST}",
                "time_ns": "1757030400000000000",
            },
        ),
        _reflog(
            "row.trailing-lf",
            ACCEPT,
            "each row is one canonical object followed by exactly one LF",
            {
                "actor": "ci-bot",
                "new": RUN_OBJECT_OID,
                "old": None,
                "ref": "tags/v1",
                "time_ns": "1757030400000000000",
            },
        ),
        _reflog(
            "row.time-ns-as-a-number",
            REJECT,
            "a JSON number for time_ns is exactly the mistake the string spelling exists to "
            "prevent: the value does not survive canonicalization",
            {
                "actor": "local",
                "new": RUN_OBJECT_OID,
                "old": None,
                "ref": "heads/main",
                "time_ns": 1757030400000000000,
            },
            reason="reflog.time-not-string",
            repair_temptation="emit the nanosecond timestamp as a JSON number",
        ),
        _reflog(
            "row.new-not-an-oid",
            REJECT,
            "the new value is an oid, and a row naming a non-oid is not history",
            {"actor": "local", "new": "HEAD", "old": None, "ref": "heads/main", "time_ns": "1"},
            reason="oid.malformed",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 27 -- the shallow boundary
# --------------------------------------------------------------------------- #

_SORTED = sorted([HELLO_OID, ROOT_EVENT_OID, CHILD_EVENT_OID])


def _shallow(name, expect, intent, spec_input, **extra) -> Case:
    return _c(
        id=f"shallow.{name}",
        section="2.7",
        checklist=(6,),
        op=extra.pop("op", "shallow.parse"),
        profile=extra.pop("profile", READER),
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


SHALLOW = Family(
    "27-shallow.json",
    "2.7",
    "shallow",
    (
        _shallow(
            "sorted-terminated",
            ACCEPT,
            "the shape a writer emits: sorted, unique, one LF per line including the last",
            B(("\n".join(_SORTED) + "\n").encode("ascii")),
        ),
        _shallow(
            "unsorted-accepts",
            ACCEPT,
            "the reader enforces uniqueness, ASCII and line shape -- not order",
            B(("\n".join(reversed(_SORTED)) + "\n").encode("ascii")),
            spec_note=(
                "SPEC 2.7 describes the shallow file as 'Sorted', but the reader enforces "
                "uniqueness, ASCII and line shape only -- an unsorted file is accepted."
            ),
            must_differ=False,
            twin="shallow.sorted-terminated",
        ),
        _shallow(
            "unterminated-accepts",
            ACCEPT,
            "and it accepts a file whose last line has no LF",
            B("\n".join(_SORTED).encode("ascii")),
            spec_note=(
                "SPEC 2.7 says 'the last line is terminated', but the reader accepts a shallow "
                "file with no trailing LF."
            ),
            must_differ=False,
            twin="shallow.sorted-terminated",
        ),
        _shallow(
            "empty-file",
            ACCEPT,
            "the file is empty when the boundary set is empty",
            B(b""),
        ),
        _shallow(
            "single-entry",
            ACCEPT,
            "one oid and one LF",
            B((HELLO_OID + "\n").encode("ascii")),
        ),
        _shallow(
            "mixed-types",
            ACCEPT,
            "a boundary entry may be an oid of any type",
            B(("\n".join([HELLO_OID, ROOT_EVENT_OID, RUN_OBJECT_OID]) + "\n").encode("ascii")),
        ),
        _shallow(
            "encode-sorts-and-terminates",
            ACCEPT,
            "the writer side sorts and terminates, which is why the reader need not",
            V([ROOT_EVENT_OID, HELLO_OID]),
            op="shallow.encode",
            profile=WRITER,
        ),
        _shallow(
            "encode-empty-set",
            ACCEPT,
            "an empty set writes an empty file, not a lone LF",
            V([]),
            op="shallow.encode",
            profile=WRITER,
        ),
        _shallow(
            "duplicate-entry",
            REJECT,
            "a duplicate oid is refused rather than de-duplicated on read",
            B((HELLO_OID + "\n" + HELLO_OID + "\n").encode("ascii")),
            reason="shallow.duplicate",
            repair_temptation="de-duplicate the set on read",
        ),
        _shallow(
            "carriage-return",
            REJECT,
            "no CR anywhere -- CRLF normalization would change the file's meaning silently",
            B((HELLO_OID + "\r\n").encode("ascii")),
            reason="shallow.carriage-return",
            repair_temptation="normalize CRLF to LF",
        ),
        _shallow(
            "empty-line",
            REJECT,
            "a blank line is an empty object id, not a separator to skip",
            B((HELLO_OID + "\n\n" + ROOT_EVENT_OID + "\n").encode("ascii")),
            reason="shallow.empty-line",
        ),
        _shallow(
            "non-ascii",
            REJECT,
            "the file is ASCII; an oid has no non-ASCII spelling",
            B("blob:sha256:é\n".encode()),
            reason="shallow.not-ascii",
        ),
        _shallow(
            "not-an-oid",
            REJECT,
            "every line must parse as an oid",
            B(b"blob:sha256:short\n"),
            reason="oid.malformed",
        ),
        _shallow(
            "encode-not-an-oid",
            REJECT,
            "the writer refuses the same input the reader would",
            V(["HEAD"]),
            op="shallow.encode",
            profile=WRITER,
            reason="oid.malformed",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 28 -- TINEPACK3
# --------------------------------------------------------------------------- #

_ACCEPT_FRAME = pack_frame([LINKED_EVENT], [HELLO_OID])
_TWO_OBJECT_SORTED = pack_frame(sorted([HELLO_BLOB, ROOT_EVENT], key=lambda raw: raw), [])
_SELF_CONTAINED = pack_frame([HELLO_BLOB, LINKED_EVENT], [])
_SELF_CONTAINED_REVERSED = pack_frame([LINKED_EVENT, HELLO_BLOB], [])
_EXTRA_SHALLOW = pack_frame([LINKED_EVENT], sorted([HELLO_OID, ROOT_EVENT_OID]))
_NO_SHALLOW = pack_frame([LINKED_EVENT], [])


def _entry(raw: bytes) -> dict:
    return {"data": base64.b64encode(raw).decode("ascii"), "id": LINKED_EVENT_OID}


def _pack(name, expect, intent, spec_input, **extra) -> Case:
    return _c(
        id=f"pack.{name}",
        section="2.8",
        checklist=(6,),
        op=extra.pop("op", "pack.inspect"),
        profile=extra.pop("profile", READER),
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


PACK = Family(
    "28-pack.json",
    "2.8",
    "pack",
    (
        _pack(
            "inspect.one-object-one-boundary",
            ACCEPT,
            "the canonical frame: magic, the inflated body's digest, and a zlib stream whose "
            "manifest names one object and the one link it does not carry",
            B(_ACCEPT_FRAME, store="frame"),
        ),
        _pack(
            "inspect.objects-array-order-is-unconstrained",
            ACCEPT,
            "canonicalization never sorts an array, so a reordered objects array is a "
            "different pack *id* over the same object set -- and a reader MUST NOT rely on it",
            B(_SELF_CONTAINED_REVERSED, store="frame"),
            must_differ=True,
            twin="pack.inspect.two-objects-sorted",
        ),
        _pack(
            "inspect.two-objects-sorted",
            ACCEPT,
            "the reference writer emits objects sorted by oid; the same set, the other order",
            B(_SELF_CONTAINED, store="frame"),
            must_differ=True,
            twin="pack.inspect.objects-array-order-is-unconstrained",
        ),
        _pack(
            "inspect.empty",
            ACCEPT,
            "a pack with no objects and no boundary is a valid frame",
            B(pack_frame([], []), store="frame"),
        ),
        _pack(
            "inspect.shallow-that-is-not-a-link",
            ACCEPT,
            "inspection does NOT enforce the shallow == external-links equality: only "
            "installation does, so a boundary entry no object links to inspects cleanly",
            B(_EXTRA_SHALLOW, store="frame"),
            twin="pack.install.shallow-is-not-the-link-closure",
        ),
        _pack(
            "inspect.two-blobs",
            ACCEPT,
            "two independent objects and no boundary",
            B(_TWO_OBJECT_SORTED, store="frame"),
        ),
        _pack(
            "manifest.one-object",
            ACCEPT,
            "the writer side: the decompressed manifest body and the id it hashes to, which "
            "is independent of the compressor",
            V([b64(LINKED_EVENT)]),
            op="pack.manifest",
            profile=WRITER,
        ),
        _pack(
            "manifest.shallow-is-the-link-closure",
            ACCEPT,
            "shallow MUST be exactly the packed objects' external *links* -- no more, no less",
            V([b64(LINKED_EVENT)]),
            op="pack.manifest",
            profile=WRITER,
            must_differ=True,
            twin="pack.manifest.self-contained",
        ),
        _pack(
            "manifest.self-contained",
            ACCEPT,
            "and when every link is inside the pack, shallow is empty",
            V([b64(HELLO_BLOB), b64(LINKED_EVENT)]),
            op="pack.manifest",
            profile=WRITER,
        ),
        _pack(
            "install.simple",
            ACCEPT,
            "installation resolves every link and requires the declared boundary to equal the "
            "external link set exactly",
            B(_ACCEPT_FRAME, store="frame"),
            op="pack.install",
            profile=WRITER,
        ),
        _pack(
            "install.self-contained",
            ACCEPT,
            "a self-contained pack declares an empty boundary and installs in dependency "
            "order, so an interrupted install leaves a link-closed subset",
            B(_SELF_CONTAINED, store="frame"),
            op="pack.install",
            profile=WRITER,
        ),
        _pack(
            "inspect.bad-magic",
            REJECT,
            "the frame MUST begin with the ten magic bytes",
            B(b"TINEPACK2\x00" + b"\x00" * 40),
            reason="pack.bad-magic",
        ),
        _pack(
            "inspect.invalid-compression",
            REJECT,
            "bytes 42.. must be a zlib stream",
            B(b"TINEPACK3\x00" + b"\x00" * 32 + b"not zlib"),
            reason="pack.invalid-compression",
        ),
        _pack(
            "inspect.trailing-bytes-after-stream",
            REJECT,
            "trailing bytes after the zlib end-of-stream are refused, not ignored",
            B(_ACCEPT_FRAME + b"\x00"),
            reason="pack.truncated-or-trailing",
            repair_temptation="use whatever inflated before the trailing bytes",
        ),
        _pack(
            "inspect.truncated-stream",
            REJECT,
            "and so is a truncated one",
            B(_ACCEPT_FRAME[:-4]),
            reason="pack.truncated-or-trailing",
        ),
        _pack(
            "inspect.checksum-mismatch",
            REJECT,
            "bytes 10..42 are the SHA-256 of the *inflated* body and are checked, not trusted",
            B(
                pack_frame_from_body(
                    canonical_json({"objects": [], "shallow": [], "version": 1}), digest=bytes(32)
                )
            ),
            reason="pack.checksum-mismatch",
            repair_temptation="recompute the header digest from the body",
        ),
        _pack(
            "inspect.manifest-malformed",
            REJECT,
            "the inflated body must parse as JSON",
            B(pack_frame_from_body(b"not json")),
            reason="pack.manifest-malformed",
        ),
        _pack(
            "inspect.manifest-non-canonical",
            REJECT,
            "and be byte-identical to its own canonical encoding, or the pack id names "
            "different bytes than the ones present",
            B(pack_frame_from_body(b'{"shallow":[],"objects":[],"version":1}')),
            reason="pack.manifest-non-canonical",
            repair_temptation="re-serialize the manifest canonically, changing the pack id",
        ),
        _pack(
            "inspect.manifest-extra-key",
            REJECT,
            "the top-level key set is exactly {objects, shallow, version}",
            B(
                pack_frame_from_body(
                    canonical_json({"generator": "x", "objects": [], "shallow": [], "version": 1})
                )
            ),
            reason="pack.manifest-key-set",
            repair_temptation="ignore an unknown top-level key",
        ),
        _pack(
            "inspect.version-two",
            REJECT,
            "version MUST be the integer 1",
            B(pack_frame_from_body(canonical_json({"objects": [], "shallow": [], "version": 2}))),
            reason="pack.version-unsupported",
        ),
        _pack(
            "inspect.version-true",
            REJECT,
            "and type(version) is not int refuses true, which would otherwise equal 1",
            B(
                pack_frame_from_body(
                    canonical_json({"objects": [], "shallow": [], "version": True})
                )
            ),
            reason="pack.version-unsupported",
            repair_temptation="read true as 1 because it compares equal",
        ),
        _pack(
            "inspect.objects-not-an-array",
            REJECT,
            "objects and shallow are arrays",
            B(pack_frame_from_body(canonical_json({"objects": {}, "shallow": [], "version": 1}))),
            reason="pack.arrays-invalid",
        ),
        _pack(
            "inspect.shallow-entry-not-an-oid",
            REJECT,
            "every shallow entry must be a syntactically valid oid",
            B(
                pack_frame_from_body(
                    canonical_json({"objects": [], "shallow": ["HEAD"], "version": 1})
                )
            ),
            reason="pack.shallow-invalid-oid",
        ),
        _pack(
            "inspect.entry-extra-key",
            REJECT,
            "an objects entry has key set exactly {data, id}",
            B(
                pack_frame_from_body(
                    canonical_json(
                        {
                            "objects": [{**_entry(LINKED_EVENT), "size": 1}],
                            "shallow": [HELLO_OID],
                            "version": 1,
                        }
                    )
                )
            ),
            reason="pack.entry-shape",
        ),
        _pack(
            "inspect.entry-base64-whitespace",
            REJECT,
            "data is strictly validated base64: a space inside it is not ignorable padding",
            B(
                pack_frame_from_body(
                    canonical_json(
                        {
                            "objects": [
                                {
                                    "data": base64.b64encode(LINKED_EVENT).decode("ascii")[:8]
                                    + " "
                                    + base64.b64encode(LINKED_EVENT).decode("ascii")[8:],
                                    "id": LINKED_EVENT_OID,
                                }
                            ],
                            "shallow": [HELLO_OID],
                            "version": 1,
                        }
                    )
                )
            ),
            reason="pack.entry-base64",
            repair_temptation="strip whitespace from the base64 before decoding",
        ),
        _pack(
            "inspect.entry-oid-mismatch",
            REJECT,
            "the decoded envelope MUST derive the id the entry declares",
            B(
                pack_frame_from_body(
                    canonical_json(
                        {
                            "objects": [
                                {
                                    "data": base64.b64encode(HELLO_BLOB).decode("ascii"),
                                    "id": LINKED_EVENT_OID,
                                }
                            ],
                            "shallow": [],
                            "version": 1,
                        }
                    )
                )
            ),
            reason="pack.entry-oid-mismatch",
            repair_temptation="trust the declared id",
        ),
        _pack(
            "inspect.duplicate-object-ids",
            REJECT,
            "ids must be unique inside one pack",
            B(
                pack_frame_from_body(
                    canonical_json(
                        {
                            "objects": [_entry(LINKED_EVENT), _entry(LINKED_EVENT)],
                            "shallow": [HELLO_OID],
                            "version": 1,
                        }
                    )
                )
            ),
            reason="pack.duplicate-ids",
        ),
        _pack(
            "inspect.shallow-overlaps-objects",
            REJECT,
            "the two sets must be disjoint: an object cannot be both carried and cut away",
            B(
                pack_frame_from_body(
                    canonical_json(
                        {
                            "objects": [_entry(LINKED_EVENT)],
                            "shallow": sorted([HELLO_OID, LINKED_EVENT_OID]),
                            "version": 1,
                        }
                    )
                )
            ),
            reason="pack.shallow-overlaps-objects",
        ),
        _pack(
            "install.unresolved-link",
            REJECT,
            "installation refuses a link that is neither packed, present locally, nor "
            "declared shallow -- inspection accepts the same frame",
            B(_NO_SHALLOW, store="frame"),
            op="pack.install",
            profile=WRITER,
            reason_any=("pack.unresolved-link", "pack.shallow-not-link-closure"),
            repair_temptation="install anyway and hope the object arrives later",
        ),
        _pack(
            "install.shallow-is-not-the-link-closure",
            REJECT,
            "and it refuses a boundary that is not exactly the external link set, which is "
            "the equality inspection does not check",
            B(_EXTRA_SHALLOW, store="frame"),
            op="pack.install",
            profile=WRITER,
            reason="pack.shallow-not-link-closure",
            twin="pack.inspect.shallow-that-is-not-a-link",
        ),
    ),
)

FAMILIES = (LAYOUT, REFS, REFLOG, SHALLOW, PACK)
