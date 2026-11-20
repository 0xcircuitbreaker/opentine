"""JSON Schema for ``tine dataset canary-*|contamination`` and ``integrity scan`` (0.60).

CLI outputs, not object kinds: a canary registration is an existing
attestation under the ``opentine.integrity.canary`` claim convention
(docs/INTEGRITY.md). ``integrity scan`` is a member of ``tine-cli-integrity-1``.
"""

from __future__ import annotations

from typing import Any

from opentine._canary_check import CODES
from opentine._schema_defs import BOOL, INT, NUM, STR, closed, doc, opt
from opentine._schema_defs_transcripts import EMBEDDING

_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_HEAD = {"schema": {"const": "tine-cli-canary/1"}}
_LIST_OF = {"type": "array", "items": STR}
CANARY = closed(["canary_sha256", "entropy_bits", "bytes", "holdout", "signer", "counted"], {
    "canary_sha256": _HEX, "entropy_bits": INT, "bytes": INT, "holdout": opt(STR),
    "signer": STR, "counted": BOOL, "path": STR})  # fmt: skip
SCAN = closed(["command", "schema", "ok", "canaries", "canary_set_sha256", "counts", "matches"], {
    "command": {"const": "integrity scan"}, "schema": {"const": "tine-cli-integrity/1"},
    "ok": BOOL, "canaries": {"type": "array", "items": CANARY}, "canary_set_sha256": _HEX,
    "counts": closed(["objects", "read", "cached", "files", "matches"], {
        "objects": INT, "read": INT, "cached": INT, "files": INT, "matches": INT}),
    "matches": {"type": "array", "items": closed(
        ["surface", "where", "canary_sha256", "holdout"], {
            "surface": {"enum": ["runs", "prompts", "memory", "packs"]}, "where": STR,
            "canary_sha256": _HEX, "holdout": opt(STR)})}})  # fmt: skip
_ADD = closed(["command", "schema", "ok", "canary"], {
    **_HEAD, "command": {"const": "dataset canary-add"}, "ok": {"const": True},
    "canary": CANARY})  # fmt: skip
_LIST = closed(["command", "schema", "ok", "canaries"], {
    **_HEAD, "command": {"const": "dataset canary-list"}, "ok": {"const": True},
    "canaries": {"type": "array", "items": CANARY}})  # fmt: skip
_CHECK = closed(["command", "schema", "ok", "model", "run", "signer", "margin_bits", "judged",
                 "findings", "blocking"], {
    **_HEAD, "command": {"const": "dataset canary-check"}, "ok": BOOL, "model": opt(STR),
    "run": STR, "signer": STR,
    "margin_bits": {"type": "integer"}, "blocking": INT,
    "judged": {"type": "array", "items": closed(
        ["canary_sha256", "holdout", "code_bits", "entropy_bits", "below"], {
            "canary_sha256": _HEX, "holdout": opt(STR), "code_bits": NUM,
            "entropy_bits": INT, "below": BOOL})},
    "findings": {"type": "array", "items": closed(
        ["level", "code", "canary_sha256", "detail"], {
            "level": {"enum": ["fail", "advisory"]}, "code": {"enum": list(CODES)},
            "canary_sha256": _HEX, "detail": STR})}})  # fmt: skip
_SIGN = closed(["command", "schema", "ok", "run", "model", "signer", "canaries", "out",
                "sha256"], {
    **_HEAD, "command": {"const": "dataset canary-sign"}, "ok": {"const": True}, "run": STR,
    "model": opt(STR), "signer": STR, "canaries": INT, "out": STR, "sha256": _HEX})  # fmt: skip
_CONT = closed(["command", "schema", "ok", "method", "counts", "exact", "near", "chunked"], {
    **_HEAD, "command": {"const": "dataset contamination"}, "ok": BOOL,
    "method": closed(["exact", "shingle", "permutations", "bands", "rows", "threshold",
                      "coverage"], {
        "exact": STR, "shingle": STR, "permutations": INT, "bands": INT, "rows": INT,
        "threshold": NUM, "coverage": STR}),
    "counts": closed(["holdout", "corpus", "candidates", "exact", "near", "chunked"], {
        "holdout": INT, "corpus": INT, "candidates": INT, "exact": INT, "near": INT,
        "chunked": INT}),
    "chunked": {"type": "array", "items": closed(["id", "found_in", "coverage"], {
        "id": STR, "found_in": _LIST_OF, "coverage": NUM})},
    "exact": {"type": "array", "items": closed(["id", "oid", "found_in"], {
        "id": STR, "oid": STR, "found_in": _LIST_OF})},
    "near": {"type": "array", "items": closed(
        ["id", "found_in", "jaccard", "minhash_estimate"], {
            "id": STR, "found_in": STR, "jaccard": NUM, "minhash_estimate": NUM})},
    "embedding": EMBEDDING})  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-canary-1": doc("tine-cli-canary-1",
        "tine dataset canary-add|canary-list|canary-check|canary-sign|contamination --json",
        "Canaries and contamination for sealed holdouts. `canary-add` signs a canary "
        "registration (claim convention `opentine.integrity.canary`) with a declared "
        "entropy in bits; `counted` is true when the signer holds the dataset role, not the "
        "optimizer role, in pinned key roles. Outputs never repeat a canary's text. "
        "`canary-check` reads per-canary code lengths from a scoring run (a signed "
        "attestation, claim convention `opentine.integrity.canary-lengths`, from a pinned "
        "scorer-role key that is not an optimizer key, bound to the run id in `run`) and refuses "
        "(`dataset.canary-below-entropy`, `ok` false, exit 1) when a counted canary is coded "
        "below `entropy_bits - margin_bits`; other findings are advisory (D12). "
        "`canary-sign` signs a scorer's per-canary code lengths for one run (`run`) and "
        "writes the attestation `canary-check` reads to `out` (`sha256` its bytes). "
        "`contamination` reports exact blob-oid matches and word 5-gram MinHash "
        "near-duplicates whose exact Jaccard is at or above the recorded threshold.",
        {"oneOf": [_ADD, _LIST, _CHECK, _SIGN, _CONT]}),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"dataset {verb}": "tine-cli-canary-1"
    for verb in ("canary-add", "canary-list", "canary-check", "canary-sign", "contamination")
}

__all__ = ["CANARY", "COMMAND_SCHEMAS", "SCAN", "SCHEMAS"]
