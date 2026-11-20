"""JSON Schemas for transcript analysis at corpus scale (0.74).

``tine-cli-transcripts-1`` is the ``tine transcripts
index|search|similar|cluster|label|flags --json`` output. The transcript index
is a derived, non-authoritative file, not an object kind (docs/TRANSCRIPTS.md).
A behaviour flag is a claim on an attestation (an existing object kind),
published as ``opentine-transcript-flag-1``: a convention, not an object kind
(docs/TRANSCRIPT_FLAGS.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, FPR, INT, NUM, OBJ, STR, closed, doc, opt, strs

_HEAD = {"schema": {"const": "tine-cli-transcripts/1"},
         "authority": {"const": "non-authoritative"}}  # fmt: skip
_CAPS = closed(["step_bytes", "max_bytes"], {"step_bytes": INT, "max_bytes": INT})
_COUNTS = closed(["runs", "embedded", "reused", "truncated"],
                 {"runs": INT, "embedded": INT, "reused": INT, "truncated": INT})  # fmt: skip
_HIT = closed(["run", "score", "steps", "bytes", "truncated", "text_sha256"], {
    "run": STR, "score": NUM, "steps": INT, "bytes": INT, "truncated": BOOL,
    "text_sha256": STR})  # fmt: skip
_QUERY = {"anyOf": [closed(["text_sha256"], {"text_sha256": STR}), closed(["run"], {"run": STR})]}
_INDEX_SHAPES = [
    closed(["command", "schema", "authority", "index", "rebuilt", "exists", "stale", "reasons",
            "backend", "backend_digest", "caps", "counts", "disagreeing"], {
        **_HEAD, "command": {"const": "transcripts index"}, "index": STR, "rebuilt": BOOL,
        "exists": BOOL, "stale": BOOL, "reasons": strs(), "backend": OBJ, "backend_digest": FPR,
        "caps": _CAPS, "counts": opt(_COUNTS), "disagreeing": opt(strs())}),
    closed(["command", "schema", "authority", "stale", "stale_reasons", "backend_digest",
            "query", "k", "method", "candidates", "indexed", "hits"], {
        **_HEAD, "command": {"enum": ["transcripts search", "transcripts similar"]},
        "stale": BOOL, "stale_reasons": strs(), "backend_digest": FPR, "query": _QUERY,
        "k": INT, "method": {"enum": ["exact", "lsh", "exact-fallback"]}, "candidates": INT,
        "indexed": INT, "hits": {"type": "array", "items": _HIT}}),
]  # fmt: skip

_FLAG_HEAD = {"schema": {"const": "tine-cli-transcripts/1"}}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_RUN = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_CLUSTER = {"type": "string", "pattern": "^tc-[0-9a-f]{16}$"}
_STATE = {"type": "string", "pattern": "^(verified|unverified: .+)$"}
_STRS = {"type": "array", "items": STR}
_AT = {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"}
BACKEND = closed(["name", "dim", "digest", "weights_digest"], {
    "name": STR, "dim": INT, "digest": _DIGEST, "weights_digest": opt(_DIGEST)})  # fmt: skip
_CLAIM_BACKEND = closed(["name", "digest", "weights_digest"], {
    "name": STR, "digest": _DIGEST, "weights_digest": opt(_DIGEST)})  # fmt: skip
_FLAG = closed(["record", "hold", "label", "evidence", "cluster", "labeller", "backend", "note",
                "labelled_at", "verification"], {
    "record": _ATT, "hold": STR, "label": opt(STR), "evidence": opt(_STRS),
    "cluster": opt(STR), "labeller": opt(STR), "backend": opt(_CLAIM_BACKEND),
    "note": opt(STR), "labelled_at": opt(STR), "verification": _STATE})  # fmt: skip
_CLUSTER_ROW = closed(["id", "size", "members", "exemplar", "flags"], {
    "id": _CLUSTER, "size": INT, "members": _STRS, "exemplar": STR,
    "flags": {"type": "object", "additionalProperties": INT}})  # fmt: skip
_FLAG_SHAPES = [
    closed(["command", "schema", "backend", "corpus", "k", "seed", "iterations", "clusters"], {
        **_FLAG_HEAD, "command": {"const": "transcripts cluster"}, "backend": BACKEND,
        "corpus": closed(["source", "count", "digest"], {
            "source": {"enum": ["repo", "files"]}, "count": INT, "digest": _DIGEST}),
        "k": INT, "seed": INT, "iterations": INT,
        "clusters": {"type": "array", "items": _CLUSTER_ROW}}),
    closed(["command", "schema", "record", "label", "evidence"], {
        **_FLAG_HEAD, "command": {"const": "transcripts label"}, "record": _ATT, "label": STR,
        "evidence": {"type": "array", "items": _RUN}}),
    closed(["command", "schema", "flags"], {
        **_FLAG_HEAD, "command": {"const": "transcripts flags"},
        "flags": {"type": "array", "items": _FLAG}, "like": _RUN, "backend": BACKEND,
        "similar": {"type": "array", "items": closed(["run", "score"], {
            "run": STR, "score": NUM})}}),
]  # fmt: skip
SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-transcripts-1": doc("tine-cli-transcripts-1",
        "tine transcripts index|search|similar|cluster|label|flags --json",
        "Embedding search over run transcripts through a derived, non-authoritative index "
        "(`index`, `search`, `similar`), seeded clusters over transcript embeddings "
        "(`cluster`), signed behaviour flags (`label`, `flags`) and runs like a run. The "
        "backend digest names the embedding parameters (and pinned model weights).",
        {"anyOf": [*_INDEX_SHAPES, *_FLAG_SHAPES]}),
    "opentine-transcript-flag-1": doc("opentine-transcript-flag-1",
        "opentine.transcript-flag/1 claim",
        "A behaviour flag on transcripts, signed by a pinned scorer or curator key and held. "
        "A claim convention on an existing attestation, not an object kind.",
        closed(["convention", "label", "evidence", "cluster", "labeller", "backend", "note",
                "labelled_at"], {
            "convention": {"const": "opentine.transcript-flag/1"},
            "label": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"},
            "evidence": {"type": "array", "items": _RUN, "minItems": 1},
            "cluster": opt(_CLUSTER), "labeller": STR, "backend": opt(_CLAIM_BACKEND),
            "note": STR, "labelled_at": _AT})),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"transcripts {verb}": "tine-cli-transcripts-1"
    for verb in ("index", "search", "similar", "cluster", "label", "flags")
}

__all__ = ["BACKEND", "COMMAND_SCHEMAS", "SCHEMAS"]
