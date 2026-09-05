"""SPEC Part 3 (the portable .tine artifact) and SPEC 1.4 (redaction)."""

from __future__ import annotations

import json

from tests.conformance.cases import ACCEPT, REJECT, VERDICT, B, Case, Family, G, V

READER, WRITER = "reader", "writer"

BASE: dict = {
    "cache": {},
    "created_at": 0,
    "format_version": 2,
    "graph": {"order": [], "steps": {}},
    "manifest": {},
    "policies": {},
    "refs": {},
    "run_id": "demo",
    "status": "completed",
    "transcript": [],
}


def artifact_text(body: dict, metadata: dict | None = None) -> str:
    """A .tine file's text: json.dumps(indent=2, sort_keys=True, allow_nan=False)."""
    document = {**body, "metadata": {} if metadata is None else metadata}
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False)


def digested(body: dict, metadata: dict | None = None) -> str:
    """The same, with a correct metadata.integrity block attached."""
    from opentine._canon import _integrity_digest

    meta = dict(metadata or {})
    meta["integrity"] = {"algorithm": "sha256", "digest": _integrity_digest(body)}
    return artifact_text(body, meta)


MINIMAL = artifact_text(BASE).encode("utf-8")
DIGESTED = digested(BASE).encode("utf-8")


def _c(**kwargs) -> Case:
    return Case(**kwargs)


def _art(name, expect, intent, spec_input, **extra) -> Case:
    return _c(
        id=f"artifact.{name}",
        section=extra.pop("section", "3.1"),
        checklist=(7, 9),
        op="artifact.parse",
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


ARTIFACT = Family(
    "31-artifact-v2.json",
    "3.1",
    "artifact",
    (
        _art(
            "minimal-v2",
            ACCEPT,
            "a .tine file is one JSON object, two-space indented, keys in code-point order",
            B(MINIMAL),
        ),
        _art(
            "v1-still-parses",
            ACCEPT,
            "SUPPORTED_VERSIONS is (1, 2): a v1 file still loads and is migrated in memory",
            B(artifact_text({**BASE, "format_version": 1}).encode("utf-8")),
        ),
        _art(
            "crlf-line-endings",
            ACCEPT,
            "the file is written in text mode, so a Windows checkout has CRLF on disk; the "
            "reader parses a document, not a byte count",
            B(MINIMAL.replace(b"\n", b"\r\n")),
            must_differ=False,
            twin="artifact.minimal-v2",
            section="3.1",
        ),
        _art(
            "non-ascii-escaped",
            ACCEPT,
            "json.dumps escapes non-ASCII, so the file is ASCII even for a Unicode run id",
            B(artifact_text({**BASE, "run_id": "démo-☃"}).encode("utf-8")),
        ),
        _art(
            "paired-surrogate-escape",
            ACCEPT,
            "a correctly paired escape is an ordinary scalar value and parses",
            B(artifact_text({**BASE, "run_id": "\U0001f600"}).encode("utf-8")),
            twin="artifact.lone-surrogate",
        ),
        _art(
            "integer.4096-digits",
            ACCEPT,
            "MAX_TINE_INTEGER_DIGITS is 4096, and 4096 digits is inside it",
            B(('{"format_version": 2, "n": ' + "9" * 4096 + "}").encode("ascii")),
            twin="artifact.integer.4097-digits",
            section="3.1",
        ),
        _art(
            "digits-inside-a-string",
            ACCEPT,
            "the bound is on number *literals*: a long digit run inside a string must save "
            "and load, which is why a byte-level regex could not enforce it",
            B(('{"format_version": 2, "n": "' + "9" * 5000 + '"}').encode("ascii")),
        ),
        _art(
            "deep-but-legal",
            ACCEPT,
            "nesting is bounded at 512, and an ordinary structured tool result is far under it",
            G({"kind": "nest", "open": "[", "close": "]", "depth": 512, "inner": "0"}),
            twin="artifact.depth-over-512",
        ),
        _art(
            "float-values",
            ACCEPT,
            "ordinary finite floats round-trip; only NaN and Infinity are refused",
            B(artifact_text({**BASE, "created_at": 1.5}).encode("utf-8")),
        ),
        _art(
            "duplicate-key",
            REJECT,
            "a duplicate object key is a parser differential: last-wins would mean two "
            "readers disagree about the document they are both 'reading successfully'",
            B(b'{"format_version": 2, "run_id": "a", "run_id": "b"}'),
            reason="artifact.duplicate-key",
            repair_temptation="apply last-wins, which is what every unguarded parser does",
            section="3.7",
        ),
        _art(
            "nan-literal",
            REJECT,
            "NaN is not JSON, and mapping it to null would rewrite recorded data",
            B(b'{"format_version": 2, "cost": NaN}'),
            reason="artifact.non-finite",
            repair_temptation="map it to null",
            section="3.7",
        ),
        _art(
            "infinity-literal",
            REJECT,
            "and neither is Infinity",
            B(b'{"format_version": 2, "cost": Infinity}'),
            reason="artifact.non-finite",
            section="3.7",
        ),
        _art(
            "negative-infinity-literal",
            REJECT,
            "or -Infinity",
            B(b'{"format_version": 2, "cost": -Infinity}'),
            reason="artifact.non-finite",
            section="3.7",
        ),
        _art(
            "overflowing-float-literal",
            REJECT,
            "a decimal literal that overflows to infinity is refused with the same rule",
            B(b'{"format_version": 2, "cost": 1e400}'),
            reason="artifact.non-finite",
            section="3.7",
        ),
        _art(
            "nul-byte",
            REJECT,
            "a NUL anywhere in the bytes refuses the file before any parse",
            B(b'{"format_version": 2, "run_id": "a\x00b"}'),
            reason="artifact.nul-byte",
            repair_temptation="strip the NUL and parse the rest",
            section="3.7",
        ),
        _art(
            "integer.4097-digits",
            REJECT,
            "4097 digits is one past the bound, and the value is refused, not floated",
            B(('{"format_version": 2, "n": ' + "9" * 4097 + "}").encode("ascii")),
            reason="artifact.integer-too-many-digits",
            repair_temptation="parse it as a float, losing every digit past the 17th",
            twin="artifact.integer.4096-digits",
            section="3.1",
        ),
        _art(
            "lone-surrogate",
            REJECT,
            "an unpaired escape yields a str no other implementation reconstructs, and that "
            "neither the digest nor the v3 canonical form can be computed over",
            B(b'{"format_version": 2, "run_id": "\\ud800"}'),
            reason="artifact.lone-surrogate",
            repair_temptation="substitute U+FFFD",
            twin="artifact.paired-surrogate-escape",
            section="3.7",
        ),
        _art(
            "raw-cesu8-surrogate",
            REJECT,
            "the raw byte spelling of the same code unit is refused identically",
            B(b'{"format_version": 2, "run_id": "\xed\xa0\x80"}'),
            reason="artifact.lone-surrogate",
            section="3.7",
        ),
        _art(
            "depth-over-512",
            REJECT,
            "513 nested containers exceeds the nesting bound",
            G({"kind": "nest", "open": "[", "close": "]", "depth": 513, "inner": "0"}),
            reason="artifact.structure-excessive",
            twin="artifact.deep-but-legal",
        ),
        _art(
            "malformed-json",
            REJECT,
            "bytes that are not JSON are refused whole; no prefix is recovered",
            B(b'{"format_version": 2, "run_id":'),
            reason="artifact.malformed-json",
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 35 -- the integrity digest
# --------------------------------------------------------------------------- #

_EDITED_BODY = {**BASE, "run_id": "tampered"}


def _integrity(name, expect, intent, op, spec_input, **extra) -> Case:
    return _c(
        id=f"integrity.{name}",
        section="3.5",
        checklist=(7,),
        op=op,
        profile=READER,
        expect=expect,
        intent=intent,
        input=spec_input,
        **extra,
    )


INTEGRITY = Family(
    "35-integrity.json",
    "3.5",
    "integrity",
    (
        _integrity(
            "digest.spec-worked-vector",
            ACCEPT,
            "SPEC 3.5's own worked vector: SHA-256 over the v2 canonical form of every "
            "top-level key except metadata",
            "integrity.digest",
            B(MINIMAL),
        ),
        _integrity(
            "digest.metadata-excluded-wholesale",
            ACCEPT,
            "metadata is excluded in full, which is what lets the digest live inside "
            "metadata.integrity without self-reference -- and is a documented boundary",
            "integrity.digest",
            B(artifact_text(BASE, {"anything": [1, 2, 3], "tags": ["x"]}).encode("utf-8")),
            must_differ=False,
            twin="integrity.digest.spec-worked-vector",
        ),
        _integrity(
            "digest.lf-file",
            ACCEPT,
            "the digest is over the *parsed* document",
            "integrity.digest",
            B(MINIMAL),
            must_differ=False,
            twin="integrity.digest.crlf-file",
        ),
        _integrity(
            "digest.crlf-file",
            ACCEPT,
            "so the same artifact written on Windows, with CRLF on disk, has the same digest "
            "-- an implementation that digests the file's bytes passes every other vector and "
            "fails this one",
            "integrity.digest",
            B(MINIMAL.replace(b"\n", b"\r\n")),
            must_differ=False,
            repair_temptation="hash the file's bytes instead of the parsed document",
            twin="integrity.digest.lf-file",
        ),
        _integrity(
            "digest.indentation-is-not-canonical",
            ACCEPT,
            "the file itself is indented and therefore not canonical: the digest input must "
            "be recanonicalized, never taken from the file bytes",
            "integrity.digest",
            B(artifact_text({**BASE, "run_id": "demo2"}).encode("utf-8")),
        ),
        _integrity(
            "verify.ok",
            VERDICT,
            "a stored digest that matches the recomputed one",
            "integrity.verify",
            B(DIGESTED),
        ),
        _integrity(
            "verify.body-edited-and-digest-rewritten",
            VERDICT,
            "SPEC Part 6 item 7: an unkeyed digest is a CONSISTENCY check. Anyone who can "
            "edit the file can recompute it, so an edited body with a rewritten digest "
            "verifies -- and reporting that as authenticity is the error this pair exists for",
            "integrity.verify",
            B(digested(_EDITED_BODY).encode("utf-8")),
            repair_temptation="report a matching digest as proof the file is genuine",
            twin="verdict.artifact.consistent-but-not-authentic",
        ),
        _integrity(
            "verify.mismatch",
            VERDICT,
            "a body edited without rewriting the digest",
            "integrity.verify",
            B(digested(BASE).encode("utf-8").replace(b'"demo"', b'"nope"')),
        ),
        _integrity(
            "verify.missing-integrity",
            VERDICT,
            "no integrity block at all is ok=false with a reason, never an exception",
            "integrity.verify",
            B(MINIMAL),
        ),
        _integrity(
            "verify.wrong-algorithm",
            VERDICT,
            "an algorithm other than sha256",
            "integrity.verify",
            B(
                artifact_text(BASE, {"integrity": {"algorithm": "md5", "digest": "0" * 32}}).encode(
                    "utf-8"
                )
            ),
        ),
        _integrity(
            "verify.malformed-digest",
            VERDICT,
            "a digest that is not 64 hex characters",
            "integrity.verify",
            B(
                artifact_text(BASE, {"integrity": {"algorithm": "sha256", "digest": "zz"}}).encode(
                    "utf-8"
                )
            ),
        ),
        _integrity(
            "verify.written-by-a-newer-opentine",
            VERDICT,
            "a future format_version gets its own reason, distinct from an unsupported old one",
            "integrity.verify",
            B(digested({**BASE, "format_version": 99}).encode("utf-8")),
        ),
    ),
)


# --------------------------------------------------------------------------- #
# 14 -- redaction (optional, writer)
# --------------------------------------------------------------------------- #


def _redact(name, intent, op, spec_input, **extra) -> Case:
    return _c(
        id=f"redact.{name}",
        section="1.4",
        checklist=(9,),
        op=op,
        profile=WRITER,
        expect=ACCEPT,
        intent=intent,
        input=spec_input,
        **extra,
    )


#: An event payload with one credential-shaped field, and the same payload with that
#: field already scrubbed. ``Repo.put`` must land on ONE stored body and ONE oid for
#: both: redaction is idempotent and it happens before the hash. A writer that
#: derives the oid from what it was handed and scrubs afterwards names bytes no
#: reader will ever see, and answers with two different oids here.
def _event(secret: str) -> dict:
    return {"cost": 0, "kind": "model", "metadata": {"api_key": secret}, "parent_ids": []}


REDACTION = Family(
    "14-redaction.json",
    "1.4",
    "redaction",
    (
        _redact(
            "blob.bearer-token",
            "redaction runs BEFORE canonicalization and hashing, so the oid names the "
            "redacted bytes every reader will see and no secret enters a digest",
            "redact.blob",
            B(b"Authorization: Bearer sk-abcdefghijklmnop\n"),
        ),
        _redact(
            "blob.assignment",
            "a credential-shaped assignment in free text is scrubbed to the literal [REDACTED]",
            "redact.blob",
            B(b"api_key=sk-proj-0123456789abcdef\n"),
        ),
        _redact(
            "blob.pem-private-key",
            "a PEM private key block is one of the known shapes",
            "redact.blob",
            B(b"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"),
        ),
        _redact(
            "blob.binary-passthrough",
            "bytes that are not UTF-8 are opaque and are returned unchanged",
            "redact.blob",
            B(b"\x00\x01\x02\xff\xfe"),
        ),
        _redact(
            "value.credential-field",
            "the value walk replaces a credential-named field outright, without descending",
            "redact.value",
            V({"api_key": "sk-live-0123456789", "model": "demo"}),
        ),
        _redact(
            "value.nested",
            "and it applies at every depth",
            "redact.value",
            V({"outer": {"inner": {"password": "hunter2", "user": "ada"}}}),
        ),
        _redact(
            "value.numeric-token-counter-survives",
            'bare "token" is not a credential name when its value is numeric: usage counters '
            "must survive redaction or every cost report becomes wrong",
            "redact.value",
            V({"token": 42, "usage": {"input": 10}}),
        ),
        _redact(
            "put.event-credential-is-scrubbed-before-hashing",
            "SPEC 1.4 in the only place it can be checked: a *writer* redacting, then "
            "hashing. The stored body carries [REDACTED] and the oid names those bytes",
            "object.put",
            V(_event("sk-live-0123456789abcdefghij")),
            args={"type": "event"},
            must_differ=False,
            twin="redact.put.event-already-scrubbed",
        ),
        _redact(
            "put.event-already-scrubbed",
            "the discriminating half: the same payload with the credential already "
            "scrubbed must produce the same body and the SAME oid, which it does only if "
            "redaction ran before the digest rather than after it",
            "object.put",
            V(_event("[REDACTED]")),
            args={"type": "event"},
            must_differ=False,
            twin="redact.put.event-credential-is-scrubbed-before-hashing",
        ),
        _redact(
            "put.blob-bearer-token",
            "a blob takes the byte-level scrubber on the same path, so the blob oid names "
            "the redacted bytes too",
            "object.put",
            B(b"Authorization: Bearer sk-abcdefghijklmnop\n"),
            args={"type": "blob"},
        ),
        _redact(
            "put.blob-pem-private-key",
            "and a PEM private key block, the last of the shapes SPEC 1.4 names",
            "object.put",
            B(b"-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"),
            args={"type": "blob"},
        ),
        _redact(
            "value.header-name-value-pair",
            "a {name, value} header pair whose name is a credential has its value scrubbed",
            "redact.value",
            V({"name": "Authorization", "value": "Bearer sk-abcdef"}),
        ),
    ),
)

FAMILIES = (ARTIFACT, INTEGRITY, REDACTION)
