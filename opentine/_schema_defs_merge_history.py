"""JSON Schemas for merging run histories (0.69).

``tine-cli-merge-history-1`` is the ``tine merge-history ... --json`` output.
``opentine-history-snapshot-1`` is a snapshot of refs, labels, lineage and
holds, and ``opentine-history-merge-1`` the claim of a history-merge
attestation; both are conventions on existing files and objects, not kinds
(docs/MERGE.md).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, STR, closed, doc, opt

_HEAD = {"schema": {"const": "tine-cli-merge-history/1"}}
_DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_HEX = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_ATT = {"type": "string", "pattern": "^attestation:sha256:[0-9a-f]{64}$"}
_STRMAP = {"type": "object", "additionalProperties": STR}
_LABEL = closed(["current", "history"], {"current": opt(STR),
                                         "history": {"type": "array", "items": _HEX}})  # fmt: skip
SNAPSHOT = closed(["format", "refs", "labels", "lineage", "holds"], {
    "format": {"const": "opentine-history-snapshot/1"}, "refs": _STRMAP,
    "labels": {"type": "object", "additionalProperties": _LABEL},
    "lineage": {"type": "object", "additionalProperties": _HEX},
    "holds": {"type": "array", "items": {"type": "array", "items": STR,
                                         "minItems": 2, "maxItems": 2}}})  # fmt: skip
CONFLICT = closed(["kind", "key", "base", "sides"], {
    "kind": {"enum": ["ref-diverged", "label-moved", "promotion-diverged", "lineage-id",
                      "hold-weakened", "held-target"]},
    "key": STR, "base": {}, "sides": {"type": "array", "minItems": 2, "maxItems": 2}})  # fmt: skip
_CONFLICTS = {"type": "array", "items": CONFLICT}
_DIGESTS = closed(["base", "sides", "merged"], {
    "base": _DIGEST, "sides": {"type": "array", "items": _DIGEST, "minItems": 2, "maxItems": 2},
    "merged": _DIGEST})  # fmt: skip
CLAIM = closed(["convention", "base", "sides", "merged", "conflicts", "target"], {
    "convention": {"const": "opentine.history-merge/1"}, "base": _DIGEST,
    "sides": {"type": "array", "items": _DIGEST, "minItems": 2, "maxItems": 2},
    "merged": _DIGEST, "conflicts": _CONFLICTS, "target": opt(STR)})  # fmt: skip
_QUEUED = closed(["ref", "run", "queue"], {"ref": STR, "run": STR, "queue": STR})
_PLAN = {"ours": SNAPSHOT, "merged": SNAPSHOT, "conflicts": _CONFLICTS, "digests": _DIGESTS}
_SHAPES = [
    closed(["command", "schema", "ok", "digest", "snapshot"], {
        **_HEAD, "command": {"const": "merge-history snapshot"}, "ok": BOOL,
        "digest": _DIGEST, "snapshot": SNAPSHOT}),
    closed(["command", "schema", "ok", *_PLAN], {
        **_HEAD, "command": {"const": "merge-history plan"}, "ok": BOOL, **_PLAN}),
    closed(["command", "schema", "ok", "applied", *_PLAN], {
        **_HEAD, "command": {"const": "merge-history apply"}, "ok": {"const": False},
        "applied": {"const": False}, **_PLAN}),
    closed(["command", "schema", "ok", "applied", *_PLAN, "record", "refs_moved", "queued",
            "labels_moved", "lineage_added", "holds_added"], {
        **_HEAD, "command": {"const": "merge-history apply"}, "ok": {"const": True},
        "applied": {"const": True}, **_PLAN, "record": _ATT,
        "refs_moved": {"type": "array", "items": STR},
        "queued": {"type": "array", "items": _QUEUED},
        "labels_moved": {"type": "array", "items": STR},
        "lineage_added": {"type": "array", "items": _DIGEST}, "holds_added": INT}),
    closed(["command", "schema", "ok", "signature", "merged", "merged_matches",
            "conflicts_match", "conflicts", "signers", "signer_trusted"], {
        **_HEAD, "command": {"const": "merge-history verify"}, "ok": BOOL, "signature": STR,
        "merged": _DIGEST, "merged_matches": BOOL, "conflicts_match": BOOL,
        "conflicts": INT, "signers": {"enum": ["pinned", "unpinned"]},
        "signer_trusted": opt(BOOL)}),
]  # fmt: skip

SCHEMAS: dict[str, dict[str, Any]] = {
    "tine-cli-merge-history-1": doc("tine-cli-merge-history-1", "tine merge-history ... --json",
        "Three-way merge of refs, labels, lineage records and holds across branches or "
        "remotes. Conflicts are reported, never auto-resolved toward the side that weakens "
        "a hold; `apply` lands a conflict-free merge as ref updates plus a signed, held "
        "`opentine.history-merge/1` attestation.", {"anyOf": _SHAPES}),
    "opentine-history-snapshot-1": doc("opentine-history-snapshot-1",
        "opentine-history-snapshot/1",
        "What one branch or remote holds: heads/tags refs, label states (decision rows by "
        "sha256), lineage records (by file sha256) and hold rows. A file convention, not a "
        "kind.", SNAPSHOT),
    "opentine-history-merge-1": doc("opentine-history-merge-1", "opentine.history-merge/1 claim",
        "The claim of an attestation recording one history merge: the three snapshot "
        "digests, the merged digest and the conflicts. A claim convention, not an object "
        "kind.", CLAIM),
}  # fmt: skip
COMMAND_SCHEMAS: dict[str, str] = {
    f"merge-history {verb}": "tine-cli-merge-history-1"
    for verb in ("snapshot", "plan", "apply", "verify")
}

__all__ = ["CLAIM", "COMMAND_SCHEMAS", "CONFLICT", "SCHEMAS", "SNAPSHOT"]
