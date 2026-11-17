"""Narrowing a shared refusal message to its exact reason code (0.53).

The vendored ``kernel`` raises one message for several pinned codes (a header
with a wrong key count and a non-canonical one both read "non-canonical object
header"). :func:`refine` looks at the case's op and input bytes, the way the
TS verifier decides at its raise site, and returns the exact code. It only
reads; when the input cannot be read it returns the code it was given.
"""

from __future__ import annotations

import json
from typing import Any

from .. import kernel

_EVENT_BLOBS = ("input_blob", "output_blob", "artifact_blob", "tree")


def _envelope(raw: Any) -> tuple[Any, Any]:
    """The (header, payload) of envelope bytes; ``None`` for a part that does not parse."""
    if not isinstance(raw, bytes | bytearray) or b"\n" not in raw:
        return None, None
    head, body = bytes(raw).split(b"\n", 1)
    out = []
    for part in (head, body):
        try:
            out.append(json.loads(part))
        except (ValueError, RecursionError):
            out.append(None)
    return out[0], out[1]


def _oid(value: Any, kind: str | None = None) -> bool:
    try:
        return kind is None or kernel.parse_oid(value)[0] == kind
    except (kernel.KernelError, TypeError):
        return False


def _link(payload: Any, header: Any) -> str | None:
    """The ``link.*`` code for an object whose links fail to parse as typed ids."""
    if not isinstance(payload, dict) or not isinstance(header, dict):
        return None
    kind = header.get("type")
    if kind == "event":
        parts = payload.get("input_parts", {})
        values = [payload.get(name) for name in _EVENT_BLOBS]
        values += list(parts.values()) if isinstance(parts, dict) else []
        if any(value and not _oid(value, "blob") for value in values):
            return "link.event-blob-not-blob"
    if kind == "run":
        manifests = payload.get("manifests", {})
        blobs = list(manifests.values()) if isinstance(manifests, dict) else []
        blobs += [v for k, v in payload.items() if k.endswith("_blob") and v]
        if any(not _oid(value, "blob") for value in blobs):
            return "link.run-blob-not-blob"
    if kind == "attestation" and not _oid(payload.get("target_id", ""), "run"):
        return "link.attestation-target-not-run"
    if kind in {"annotation", "attestation"}:
        if not isinstance(payload.get("evidence_ids", []), list):
            return "link.evidence-not-list"
    return None


def refine(code: str, op: str, raw: Any) -> str:
    """The exact pinned code for refusal *code* of op *op* on input *raw*."""
    if code == "text.lone-surrogate" and op.startswith("artifact."):
        return "artifact.lone-surrogate"
    if code == "shape.depth-exceeded" and isinstance(raw, bytes | bytearray | str):
        try:
            kernel.validate_json_shape(raw, max_tokens=1 << 62)
        except kernel.KernelError:
            return code
        return "shape.tokens-exceeded"
    header, payload = _envelope(raw)
    if not isinstance(header, dict):
        return code
    if code == "envelope.header-non-canonical" and len(header) != 3:
        return "envelope.header-key-count"
    schema = header.get("schema")
    if code == "envelope.schema-not-integer" and type(schema) is int:
        return "envelope.schema-out-of-range"
    if code == "envelope.unknown-type" and header.get("type") in kernel.OBJECT_TYPES:
        return "envelope.encoding-mismatch"
    if code == "link.parent-ids-not-events" and isinstance(payload, dict):
        for field in ("parent_ids", "causal_ids"):
            values = payload.get(field, [])
            if isinstance(values, list) and all(_oid(v, "event") for v in values):
                if len(set(values)) != len(values):
                    return "link.parent-ids-duplicate"
    if code == "oid.malformed" and op in {"links.extract", "object.load"}:
        return _link(payload, header) or code
    return code


__all__ = ["refine"]
