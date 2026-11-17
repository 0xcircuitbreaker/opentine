"""Name every refusal of the reference reader with its pinned reason code (0.53).

The frozen kernel and the older readers raise plain ``ValueError`` subclasses
whose messages are deliberately terse and sometimes conflated (SPEC §8.2,
``docs/conformance/REASON_CODES.md``). A refusal still has to *name* why it
refused, so this module maps a refusal -- by the operation that raised it and
its message -- to the code the conformance suite pins. Where the reference
cannot tell two rules apart (one message for a depth and a token overrun) the
code is the first of its alias group, which a Level 2 runner accepts for every
member of the group.

:func:`name_refusal` never replaces a code a refusal already carries, and never
turns an acceptance into a refusal: it only labels an exception on its way out.
"""

from __future__ import annotations

import re

#: ``(operation prefix, message pattern, code)``; the first match wins. A
#: prefix of ``""`` matches every operation.
_RULES: tuple[tuple[str, str, str], ...] = (
    # text and canonical JSON (0.1 to 0.3)
    ("", r"unpaired UTF-16 surrogate", "text.lone-surrogate"),
    ("", r"^canonical JSON forbids NaN and infinity", "canon.non-finite"),
    ("", r"^canonical JSON integer exceeds 2\*\*53-1", "canon.integer-overflow"),
    ("", r"^canonical JSON nesting exceeds", "canon.depth-exceeded"),
    ("", r"^canonical JSON nesting or Unicode key is invalid", "canon.unencodable-text"),
    ("", r"^JSON structure exceeds semantic parser limits", "shape.tokens-exceeded"),
    ("", r"^JSON body is not UTF-8 text", "shape.not-utf8"),
    # envelope and object ids (1.x)
    ("", r"^non-canonical object header", "envelope.header-non-canonical"),
    ("", r"^malformed object envelope", "envelope.malformed"),
    ("", r"^invalid object schema", "envelope.schema-out-of-range"),
    ("", r"^unknown object type or encoding/type mismatch", "envelope.unknown-type"),
    ("", r"^non-canonical object body", "envelope.body-non-canonical"),
    ("", r"^malformed object JSON", "envelope.body-malformed-json"),
    ("", r"^object id mismatch", "envelope.oid-mismatch"),
    ("", r"^unsupported hash algorithm", "oid.hash-unsupported"),
    ("", r"^invalid typed object id", "oid.malformed"),
    # links, chains, metrics and graphs
    ("", r"^parent_ids must contain event ids", "link.parent-ids-not-events"),
    ("", r"^tips must contain unique events", "link.run-roots-tips-invalid"),
    ("", r"^roots must contain unique events", "link.run-roots-tips-invalid"),
    ("", r"^(input|output|artifact)_blob must contain a blob id", "link.event-blob-not-blob"),
    ("", r"^events must contain unique event ids", "link.run-events-invalid"),
    ("", r"^(roots|tips) must be a subset of events", "link.run-roots-tips-not-subset"),
    ("", r"^manifests must be an object", "link.run-manifests-not-object"),
    ("", r"^run blob fields must contain blob ids", "link.run-blob-not-blob"),
    ("", r"^attestation target_id must contain a run id", "link.attestation-target-not-run"),
    ("", r"^previous_id must contain an annotation id", "link.annotation-previous-not-annotation"),
    ("", r"^missing linked object", "link.missing-object"),
    ("", r"^annotation versions must target the same object", "chain.target-changed"),
    ("", r"^annotation previous object is unavailable", "chain.previous-unavailable"),
    ("", r"^event usage must be a mapping", "metrics.usage-not-object"),
    ("", r"^event usage\.\w+ must be numeric", "metrics.usage-value-not-numeric"),
    ("", r"^event usage\.\w+ must be a safe integer", "metrics.token-dimension-unsafe"),
    ("", r"^event [\w.]+ must be finite and non-negative", "metrics.meter-not-finite"),
    ("", r"^run status is invalid", "graph.status-invalid"),
    ("", r"^run event has a parent outside", "graph.parent-outside-graph"),
    ("", r"^run event has a causal link outside", "graph.causal-outside-graph"),
    ("", r"^run events must be in parent-before-child", "graph.order-not-topological"),
    ("", r"^run roots do not match", "graph.roots-mismatch"),
    ("", r"^run tips do not match", "graph.tips-mismatch"),
    ("", r"^legacy_refs must map names", "graph.legacy-refs-invalid"),
    # repository storage: refs, reflogs, config, shallow, layout
    ("", r"^invalid ref name", "ref.name-charset"),
    ("", r"^repository ref exceeds its size limit", "ref.file-oversized"),
    ("", r"^repository ref is not ASCII", "ref.file-not-ascii"),
    ("", r"^repository ref is not canonically encoded", "ref.file-not-canonical"),
    ("", r"^\w+ refs require \w+ objects", "ref.target-type"),
    ("", r"^annotation ref name must match", "ref.annotation-name-mismatch"),
    ("", r"^reflog actor exceeds", "reflog.actor-too-long"),
    ("", r"^reflog time_ns must be", "reflog.time-not-string"),
    ("", r"^repository config exceeds maximum size", "config.oversized"),
    ("", r"^repository config is malformed", "config.malformed"),
    ("", r"^repository config is incompatible", "config.incompatible"),
    ("", r"^shallow boundary state exceeds its object limit", "shallow.too-many"),
    ("", r"^shallow boundary state exceeds its byte limit", "shallow.oversized"),
    ("", r"^shallow boundary state contains duplicate", "shallow.duplicate"),
    ("", r"^shallow boundary state has invalid line endings", "shallow.carriage-return"),
    ("", r"^shallow boundary state contains an empty", "shallow.empty-line"),
    ("", r"^shallow boundary state must be ASCII", "shallow.not-ascii"),
    # transfer packs
    ("", r"^pack exceeds maximum object count", "pack.too-many-objects"),
    ("", r"^pack exceeds maximum transfer size", "pack.oversized"),
    ("", r"^invalid pack header", "pack.bad-magic"),
    ("", r"^invalid compressed pack", "pack.invalid-compression"),
    ("", r"^pack has truncated or trailing", "pack.truncated-or-trailing"),
    ("", r"^pack checksum mismatch", "pack.checksum-mismatch"),
    ("", r"^invalid pack manifest", "pack.manifest-malformed"),
    ("", r"^non-canonical or unsupported pack", "pack.manifest-non-canonical"),
    ("", r"^invalid packed object", "pack.entry-shape"),
    ("", r"^pack contains duplicate object ids", "pack.duplicate-ids"),
    ("", r"^packed objects cannot also be shallow", "pack.shallow-overlaps-objects"),
    ("", r"^pack has unresolved link", "pack.unresolved-link"),
    ("", r"^pack shallow boundaries do not match", "pack.shallow-not-link-closure"),
    # local packs (codec 2 and 3)
    ("", r"^pack index checksum does not match", "localpack.index-checksum"),
    ("", r"^pack index is truncated or has trailing", "localpack.index-length"),
    ("", r"^pack index entries are not sorted", "localpack.index-order"),
    ("", r"^pack index block is oversized", "localpack.block-size"),
    ("", r"^pack index run delta has no base", "localpack.delta-no-base"),
    ("", r"^packed run delta chain is too deep", "localpack.delta-too-deep"),
    ("", r"^packed object size does not match", "localpack.object-id-mismatch"),
    ("", r"^pack index entry is malformed", "localpack.encoding-kind"),
    ("", r"^slim event stores a default", "localpack.slim-default"),
    ("", r"zstd dictionary", "localpack.dictionary"),
    # .tine artifacts
    ("", r"^duplicate \.tine object key", "artifact.duplicate-key"),
    ("", r"^non-finite number in \.tine artifact", "artifact.non-finite"),
    ("", r"^\.tine artifacts must use UTF-8 JSON", "artifact.nul-byte"),
    ("", r"^integer in \.tine artifact exceeds", "artifact.integer-too-many-digits"),
    ("", r"^\.tine artifact nesting exceeds", "artifact.structure-excessive"),
    ("artifact.", r"^Expecting|^Extra data|^Unterminated|^Invalid", "artifact.malformed-json"),
    # signed messages and agent identity
    ("", r"^(attestation payload|artifact metadata) must be an object", "sig.payload-not-object"),
    ("", r"^agent identity field '\w+' is not normalised", "agent.not-normalised"),
    ("", r"^agent identity field '\w+' is malformed", "agent.field-malformed"),
    ("", r"^unknown field in agent identity", "agent.unknown-field"),
    ("", r"^agent identity needs a harness", "agent.harness-missing"),
    # signed records with one code per family
    ("fleet.", r"embedded public key is not the trusted key", "fleet.wrong-key"),
    ("fleet.", r"^signature (mismatch|error)", "fleet.bad-signature"),
    ("fleet.", r"", "fleet.malformed"),
    ("custody.", r"breaks the hash chain", "custody.chain-broken"),
    ("custody.", r"^custody record \d+: signature", "custody.bad-signature"),
    ("custody.", r"", "custody.malformed"),
    ("replay.", r"^no signature verifies", "replay.bad-signature"),
    ("replay.", r"", "replay.malformed"),
    ("sealed6.", r"", "sealed6.malformed"),
)

#: Exception types that signal a bug in the reader, not a refusal of the input.
_BUGS = (
    TypeError,
    KeyError,
    AttributeError,
    IndexError,
    AssertionError,
    RecursionError,
    MemoryError,
)

_COMPILED = tuple((prefix, re.compile(pattern), code) for prefix, pattern, code in _RULES)


def reason_for(op: str, exc: BaseException) -> str | None:
    """The pinned reason code for refusal ``exc`` raised by ``op``, or ``None``."""
    code = getattr(exc, "code", None)
    if isinstance(code, str):
        return code
    if isinstance(exc, _BUGS) and not isinstance(exc, ValueError):
        return None  # a programming error is never a refusal, so never named as one
    message = str(exc)
    for prefix, pattern, candidate in _COMPILED:
        if op.startswith(prefix) and pattern.search(message):
            return candidate
    return None


def name_refusal(op: str, exc: BaseException) -> BaseException:
    """Label ``exc`` with its reason code (``exc.code``) unless it has one already."""
    if getattr(exc, "code", None) is None:
        code = reason_for(op, exc)
        if code is not None:
            try:
                exc.code = code  # type: ignore[attr-defined]
            except AttributeError:  # an exception type with __slots__
                pass
    return exc
