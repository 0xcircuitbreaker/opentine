"""The pinned reason code of a pyz refusal that does not carry one (0.53).

Most pyz refusals are raised by modules it vendors verbatim (``kernel``,
``_agent_identity``) or by the stdlib JSON codec, whose exceptions name no
code. :func:`reason_of` maps each such refusal to the reason code
``docs/conformance`` pins for it (the same code the TS verifier raises), from
the exception's type and message. An exception that already has a ``code``
keeps it; an unknown message stays unnamed (``None``) so a parity run shows it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ._reasons_refine import refine

#: (message pattern, code), first match wins; matched with ``re.match``.
_TABLE: tuple[tuple[str, str], ...] = (
    # kernel: canonical JSON and shape limits
    (r"JSON structure exceeds semantic parser limits", "shape.depth-exceeded"),
    (r"canonical JSON integer exceeds", "canon.integer-overflow"),
    (r"canonical JSON forbids NaN", "canon.non-finite"),
    (r"canonical JSON nesting exceeds", "canon.depth-exceeded"),
    (r"canonical JSON nesting or Unicode key is invalid", "canon.unencodable-text"),
    (r"Out of range float values are not JSON compliant", "canon.non-finite"),
    # kernel: typed object ids
    (
        r"invalid typed object id: '(blob|event|run|attestation|annotation)"
        r":(?!sha256:)[a-z0-9][a-z0-9-]{0,31}:[0-9a-f]+'$",
        "oid.hash-unsupported",
    ),
    (r"invalid typed object id", "oid.malformed"),
    # kernel: object envelopes
    (r"malformed object envelope", "envelope.malformed"),
    (r"non-canonical object header", "envelope.header-non-canonical"),
    (r"invalid object schema", "envelope.schema-not-integer"),
    (r"unknown object type or encoding/type mismatch", "envelope.unknown-type"),
    (r"malformed object JSON", "envelope.body-malformed-json"),
    (r"non-canonical object body", "envelope.body-non-canonical"),
    (r"object id mismatch", "envelope.oid-mismatch"),
    # kernel: links
    (r"(parent_ids|causal_ids) must contain event ids", "link.parent-ids-not-events"),
    (r"\w+ must contain a blob id", "link.event-blob-not-blob"),
    (r"manifests must be an object", "link.run-manifests-not-object"),
    (r"events must contain unique event ids", "link.run-events-invalid"),
    (r"(roots|tips) must contain unique events from the run", "link.run-roots-tips-invalid"),
    (r"(roots|tips) must be a subset of events", "link.run-roots-tips-not-subset"),
    (r"run blob fields must contain blob ids", "link.run-blob-not-blob"),
    (r"previous_id must contain an annotation id", "link.annotation-previous-not-annotation"),
    (r"attestation target_id must contain a run id", "link.attestation-target-not-run"),
    (r"missing linked object", "link.missing-object"),
    # store: metrics, graphs, annotation chains
    (r"event [\w.]+ must be finite and non-negative", "metrics.meter-not-finite"),
    (r"event usage must be a mapping", "metrics.usage-not-object"),
    (r"event usage\.\S+ must be numeric", "metrics.usage-value-not-numeric"),
    (r"event usage\.\S+ must be a safe integer", "metrics.token-dimension-unsafe"),
    (r"run status is invalid", "graph.status-invalid"),
    (r"legacy_refs must map names", "graph.legacy-refs-invalid"),
    (r"run event has a parent outside", "graph.parent-outside-graph"),
    (r"run event has a causal link outside", "graph.causal-outside-graph"),
    (r"run events must be in parent-before-child", "graph.order-not-topological"),
    (r"run roots do not match", "graph.roots-mismatch"),
    (r"run tips do not match", "graph.tips-mismatch"),
    (r"annotation previous object is unavailable", "chain.previous-unavailable"),
    (r"annotation versions must target the same object", "chain.target-changed"),
    # .tine artifact reader
    (r"duplicate \.tine object key", "artifact.duplicate-key"),
    (r"non-finite number in \.tine artifact", "artifact.non-finite"),
    (r"\.tine artifacts must use UTF-8 JSON", "artifact.nul-byte"),
    (r"\.tine artifact nesting exceeds", "artifact.structure-excessive"),
    (r"integer in \.tine artifact exceeds", "artifact.integer-too-many-digits"),
    (r"\.tine artifact holds a lone surrogate", "text.lone-surrogate"),
    # signed payloads
    (r"(artifact metadata|attestation payload) must be an object", "sig.payload-not-object"),
    # agent identity
    (r"unknown field in agent identity", "agent.unknown-field"),
    (r"agent identity needs a harness", "agent.harness-missing"),
    (r"agent identity field '\w+' is not normalised", "agent.not-normalised"),
    (r"agent identity field '\w+' is malformed", "agent.field-malformed"),
)
_COMPILED = tuple((re.compile(pattern), code) for pattern, code in _TABLE)


def reason_of(exc: BaseException) -> str | None:
    """The reason code of refusal *exc*, or ``None`` when it names none."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code
    if isinstance(exc, json.JSONDecodeError):
        return "artifact.malformed-json"
    text = str(exc)
    for pattern, named in _COMPILED:
        if pattern.match(text):
            return named
    return None


def named(exc: BaseException, op: str = "", raw: Any = None) -> BaseException:
    """*exc* with its reason code set as ``exc.code`` where one is known.

    *op* and *raw* (the case's op and input bytes) narrow a message the vendored
    modules share between codes to the exact one (:mod:`._reasons_refine`).
    """
    code = reason_of(exc)
    if code is not None and getattr(exc, "code", None) is None:
        code = refine(code, op, raw)
    if code is not None and getattr(exc, "code", None) != code:
        try:
            exc.code = code  # type: ignore[attr-defined]
        except AttributeError:  # a slotted exception keeps its message only
            pass
    return exc


__all__ = ["named", "reason_of"]
