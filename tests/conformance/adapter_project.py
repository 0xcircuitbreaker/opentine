"""Reference ops for SPEC 4.16-4.18, 4.23 and 4.24: project manifests, mirror states, git
objects, forge claims and forge checks."""

from __future__ import annotations

import base64
from typing import Any

from opentine import _forge_check, _forge_claim, _git_object, _mirror_state, _project


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


def op_forge_claim_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.23: an upstream's claim, as mirrored (never a pass)."""
    value = inp.value
    return _forge_claim.check(value["claim"], branch=value["branch"], project=value["project"])


def op_forge_check_verify(inp, args: dict[str, Any]) -> dict[str, Any]:
    """SPEC 4.24: a forge check record, and the bundle it links to when given."""
    value = inp.value
    data = value.get("bundle_b64")
    return _forge_check.check(value["check"], None if data is None else base64.b64decode(data))


OPS = {
    "forge-check.verify": op_forge_check_verify,
    "project.verify": op_project_verify,
    "project.chain": op_project_chain,
    "mirror-state.verify": op_mirror_state_verify,
    "git-object.check": op_git_object_check,
    "forge-claim.verify": op_forge_claim_verify,
}
