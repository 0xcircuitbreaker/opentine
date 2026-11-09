"""Reference ops for SPEC 4.16 (project manifests), 4.17 (mirror states) and 4.18 (git objects)."""

from __future__ import annotations

import base64
from typing import Any

from opentine import _git_object, _mirror_state, _project


def op_project_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.16: one manifest, after its predecessor when one is given."""
    value = inp.value
    return _project.check(
        value["manifest"], previous=value.get("previous"), owner_key=value.get("owner_key")
    )


def op_project_chain(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.16: a whole manifest history, oldest first."""
    value = inp.value
    return _project.chain(value["versions"], owner_key=value.get("owner_key"))


def op_mirror_state_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.17: a host statement, never a pass."""
    value = inp.value
    host = value.get("host_key")
    return _mirror_state.check(
        value["state"], host_key=bytes.fromhex(host) if host else None, owners=value["owners"]
    )


def op_git_object_check(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.18: bytes hash to the git object id given."""
    value = inp.value
    return _git_object.check(value["type"], base64.b64decode(value["data_b64"]), value["oid"])


OPS = {
    "project.verify": op_project_verify,
    "project.chain": op_project_chain,
    "mirror-state.verify": op_mirror_state_verify,
    "git-object.check": op_git_object_check,
}
