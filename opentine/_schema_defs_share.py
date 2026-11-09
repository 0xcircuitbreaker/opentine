"""JSON Schemas for purge tombstones and redacted public copies (0.46).

``opentine-tombstone-1`` (SPEC 4.14) and ``opentine-redacted-copy-1`` (SPEC
4.15) are the two records; ``tine-cli-purge-1`` and ``tine-cli-purge-list-1``
the ``--json`` outputs of ``tine purge`` and ``tine purge --list``.
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, SIG, STR, closed, doc, open_, opt

_NAME: dict[str, Any] = {"type": "string", "pattern": "^[A-Za-z0-9_.:/@+-]{1,256}$"}
_BLOB: dict[str, Any] = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_RUN: dict[str, Any] = {"type": "string", "pattern": "^run:sha256:[0-9a-f]{64}$"}
_DIGEST: dict[str, Any] = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_TOMBSTONE = {"$ref": "opentine-tombstone-1.schema.json"}
_STATES = {"enum": ["verified", "verified-tofu", "unchecked", "failed"]}

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-tombstone-1": doc("opentine-tombstone-1", "opentine.tombstone (tombstone_version 1)",
        "The signed record that a blob was purged (SPEC 4.14): the oid is kept, the bytes are "
        "gone. `signature` is a tine-sig/3 block over `opentine.tombstone.v1:` + "
        "JCS({body, header}); a server stores it as signed and never signs one.",
        closed(["kind", "tombstone_version", "oid", "reason", "actor", "purged_at",
                "signature"], {
            "kind": {"const": "opentine.tombstone"}, "tombstone_version": {"const": 1},
            "oid": _BLOB, "reason": {"type": "string", "minLength": 1, "maxLength": 1024},
            "actor": _NAME, "purged_at": _WHEN, "signature": SIG})),
    "opentine-redacted-copy-1": doc("opentine-redacted-copy-1",
        "opentine.redacted-copy (copy_version 1)",
        "Links a redacted public copy to its private run (SPEC 4.15): the manifest key "
        "`redacted_public` of a `tine bundle create --redacted-public` bundle. `pack` is the "
        "bundled pack's digest; `signature` is a tine-sig/3 block over "
        "`opentine.redacted-copy.v1:` + JCS({body, header}).",
        closed(["kind", "copy_version", "source_run", "public_run", "ruleset", "objects",
                "redacted", "pack", "signature"], {
            "kind": {"const": "opentine.redacted-copy"}, "copy_version": {"const": 1},
            "source_run": _RUN, "public_run": _RUN, "ruleset": _NAME, "objects": INT,
            "redacted": INT, "pack": _DIGEST, "signature": SIG})),
    "tine-cli-purge-1": doc("tine-cli-purge-1", "tine purge --json",
        "One purge: the blob's bytes are gone (`purged`), or it was purged before (`already`); "
        "`tombstone` is the signed record kept in their place.",
        open_(["command", "oid", "purged", "already", "packs_rewritten", "tombstone"], {
            "command": {"const": "purge"}, "oid": _BLOB, "purged": BOOL, "already": BOOL,
            "packs_rewritten": INT, "tombstone": _TOMBSTONE})),
    "tine-cli-purge-list-1": doc("tine-cli-purge-list-1", "tine purge --list --json",
        "Every tombstone in the repository with its content state and trust. `state` is "
        "`unchecked` for an HMAC record listed without its key; the command exits 4 when any "
        "row is `failed` (then `reason` holds its `tombstone.*` code).",
        open_(["command", "ok", "tombstones"], {
            "command": {"const": "purge-list"}, "ok": BOOL,
            "tombstones": {"type": "array", "items": closed(
                ["oid", "content", "actor", "purged_at", "state", "reason"], {
                    "oid": _BLOB, "content": {"enum": ["unavailable", "present"]},
                    "actor": opt(STR), "purged_at": opt(STR), "state": _STATES,
                    "reason": opt(STR)})}})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {
    "purge": "tine-cli-purge-1",
    "purge-list": "tine-cli-purge-list-1",
}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.tombstone": "opentine-tombstone-1",
    "opentine.redacted-copy": "opentine-redacted-copy-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
