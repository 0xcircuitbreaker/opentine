"""JSON Schemas for projects (0.46.1, SPEC 4.16-4.18).

``opentine-project-1`` (an ``opentine.project`` manifest version) and
``opentine-mirror-state-1`` (a host's ``opentine.mirror-state`` statement) are
the two records; ``tine-cli-project-1`` is the ``--json`` output of every
``tine project`` action. The schemas check shape; the signature, the chain and
the visibility rules are the verifier's (``opentine._project``).
"""

from __future__ import annotations

from typing import Any

from opentine._schema_defs import BOOL, INT, SIG, STR, closed, doc, open_, opt

_ID: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}
_TENANT: dict[str, Any] = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"}
_BLOB: dict[str, Any] = {"type": "string", "pattern": "^blob:sha256:[0-9a-f]{64}$"}
_HEX64: dict[str, Any] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_WHEN: dict[str, Any] = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
_VISIBILITY = {"enum": ["public", "private"]}
_LOCATOR = {"anyOf": [
    closed(["url"], {"url": {"type": "string", "pattern": "^(https://|ssh://|git@)",
                             "maxLength": 2048}}),
    closed(["commitment"], {"commitment": {"type": "string",
                                           "pattern": "^sha256:[0-9a-f]{64}$"}}),
]}  # fmt: skip
_SLOT = closed(["role", "forge", "forge_repo_id", "upstream_visibility", "locator",
                "default_branch"], {
    "role": {"enum": ["primary", "secondary"]},
    "forge": {"enum": ["github", "gitlab", "forgejo", "git", "entire"]},
    "forge_repo_id": opt({"type": "string", "pattern": "^[A-Za-z0-9_.:/-]{1,128}$"}),
    "upstream_visibility": _VISIBILITY, "locator": _LOCATOR,
    "default_branch": {"type": "string", "pattern": "^[A-Za-z0-9._/-]{1,255}$"}})  # fmt: skip
_MANIFEST = {"$ref": "opentine-project-1.schema.json"}

SCHEMAS: dict[str, dict[str, Any]] = {
    "opentine-project-1": doc("opentine-project-1", "opentine.project (project_version 1)",
        "One version of a project manifest (SPEC 4.16): binds a tenant to its code slots. "
        "`prev` is the previous version's blob-oid digest (null for seq 0); `signature` is an "
        "Ed25519 tine-sig/3 block by an owner of the previous version, over "
        "`opentine.project.v1:` + JCS({body, header}). A private project names its upstreams "
        "by commitment only.",
        closed(["kind", "project_version", "project_id", "tenant", "seq", "prev", "visibility",
                "owners", "slots", "forked_from", "created_at", "signature"], {
            "kind": {"const": "opentine.project"}, "project_version": {"const": 1},
            "project_id": _ID, "tenant": _TENANT, "seq": INT, "prev": opt(_BLOB),
            "visibility": _VISIBILITY,
            "owners": {"type": "array", "items": _HEX64, "minItems": 1, "maxItems": 16},
            "slots": {"type": "array", "items": _SLOT, "minItems": 1, "maxItems": 2},
            "forked_from": opt(_ID), "created_at": _WHEN, "signature": SIG})),
    "opentine-mirror-state-1": doc("opentine-mirror-state-1",
        "opentine.mirror-state (mirror_state_version 1)",
        "A code mirror's signed statement about one slot (SPEC 4.17): the commit each ref "
        "pointed at when it last synced. Signed by the host service key, never a user's; a "
        "verifier never reports it as a pass (`host statement, not verified by you`).",
        closed(["kind", "mirror_state_version", "tenant", "project_id", "manifest", "slot",
                "object_format", "refs", "synced_at", "status", "reasons", "signature"], {
            "kind": {"const": "opentine.mirror-state"}, "mirror_state_version": {"const": 1},
            "tenant": _TENANT, "project_id": _ID, "manifest": _BLOB,
            "slot": {"enum": ["primary", "secondary"]},
            "object_format": {"enum": ["sha1", "sha256"]},
            "refs": {"type": "object", "additionalProperties": {
                "type": "string", "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"}},
            "synced_at": _WHEN, "status": {"enum": ["synced", "stale", "failed", "paused"]},
            "reasons": {"type": "array", "items": {"type": "string", "pattern": "^mirror\\."}},
            "signature": SIG})),
    "tine-cli-project-1": doc("tine-cli-project-1", "tine project ACTION --json",
        "Every `tine project` action. `init`/`link`: the new version (`manifest`, `digest`, "
        "`project`); `show`: the current one; `history`: `versions` oldest first; `verify`: "
        "`result`, the chain check; `push`: `sent`, `head`, `versions`. A refusal is the "
        "error envelope, exit 4 for a verification failure.",
        open_(["command", "action", "ok"], {
            "command": {"const": "project"},
            "action": {"enum": ["init", "link", "show", "history", "verify", "push"]},
            "ok": BOOL, "manifest": _MANIFEST, "digest": opt(_BLOB),
            "project": closed(["project_id", "tenant", "seq", "visibility"], {
                "project_id": _ID, "tenant": _TENANT, "seq": INT, "visibility": _VISIBILITY}),
            "versions": {"anyOf": [{"type": "array", "items": _MANIFEST}, INT]},
            "total": INT, "sent": INT, "head": opt(_BLOB),
            "result": open_(["project_id", "head", "seq", "versions", "state"], {
                "project_id": _ID, "head": _BLOB, "seq": INT, "versions": INT, "state": STR})})),
}  # fmt: skip

COMMAND_SCHEMAS: dict[str, str] = {"project": "tine-cli-project-1"}

#: ``kind`` value -> schema stem, for the records (they carry no tag or ``command``).
KIND_SCHEMAS: dict[str, str] = {
    "opentine.project": "opentine-project-1",
    "opentine.mirror-state": "opentine-mirror-state-1",
}

__all__ = ["COMMAND_SCHEMAS", "KIND_SCHEMAS", "SCHEMAS"]
