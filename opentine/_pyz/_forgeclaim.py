"""Forge claims with the standard library (0.47, SPEC 4.23).

An independent port, for ``tine-verify.pyz``, of ``opentine._forge_claim.check``:
an upstream's unsigned ``.opentine/project`` file, matched against a project's
id, tenant, default branch and genesis fingerprint. It never reports a pass:
a match is ``claimed-as-mirrored``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ._gitobj import Refused

KIND = "opentine.forge-claim"
KEYS = {"kind", "claim_version", "project_id", "tenant", "fingerprint"}
LABEL = "claimed by upstream (as mirrored)"
_RULES = (("project_id", r"[a-z0-9][a-z0-9._-]{0,63}"), ("tenant", r"[a-z0-9][a-z0-9._-]{0,127}"),
          ("fingerprint", r"sha256:[0-9a-f]{64}"))  # fmt: skip


def _no(code: str, message: str) -> Refused:
    return Refused("forge-claim." + code, message)


def fingerprint(genesis: Any) -> str:
    if not isinstance(genesis, str) or not re.fullmatch(r"blob:sha256:[0-9a-f]{64}", genesis):
        raise _no("malformed", "forge claim is malformed: genesis is not a blob digest")
    return "sha256:" + hashlib.sha256(b"opentine.forge-claim.v1:" + genesis.encode()).hexdigest()


def forge_claim_verify(claim: Any, branch: Any, project: dict) -> dict:
    if claim is None:
        raise _no("missing", "no forge claim: the upstream holds no .opentine/project")
    if not isinstance(claim, dict) or claim.get("kind") != KIND or set(claim) != KEYS:
        raise _no("malformed", "forge claim is malformed: wrong kind or set of fields")
    version = claim["claim_version"]
    if type(version) is not int or version != 1:
        raise _no("malformed", "forge claim is malformed: claim_version is not 1")
    for name, pattern in _RULES:
        if not isinstance(claim[name], str) or not re.fullmatch(pattern, claim[name]):
            raise _no("malformed", "forge claim is malformed: bad " + name)
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", branch):
        raise _no("malformed", "forge claim is malformed: bad branch")
    if branch != project["default_branch"]:
        raise _no("not-default-branch", "forge claim is only on " + branch + ", not the default "
                  "branch " + str(project["default_branch"]))  # fmt: skip
    if claim["project_id"] != project["project_id"] or claim["tenant"] != project["tenant"]:
        raise _no("wrong-project", "forge claim names another project or tenant")
    if claim["fingerprint"] != fingerprint(project["genesis"]):
        raise _no("wrong-fingerprint", "forge claim fingerprint names another project")
    return {"project_id": claim["project_id"], "tenant": claim["tenant"],
            "fingerprint": claim["fingerprint"], "branch": branch,
            "state": "claimed-as-mirrored", "label": LABEL}  # fmt: skip


__all__ = ["fingerprint", "forge_claim_verify"]
