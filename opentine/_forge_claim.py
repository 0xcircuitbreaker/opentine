"""``opentine.forge-claim``: an upstream's own claim of its project (0.47, SPEC 4.19).

A project's owners write the claim (``tine project claim``) into the code
repository as the file ``.opentine/project`` and commit it on the default
branch. It is tiny and unsigned: its authority is that it sits in the
upstream, where only the upstream's own writers can put it::

    {"kind": "opentine.forge-claim", "claim_version": 1, "project_id": ID,
     "tenant": TENANT, "fingerprint": "sha256:" + 64 hex}

``fingerprint`` is ``"sha256:" + hex(SHA-256(b"opentine.forge-claim.v1:" +
genesis))`` where *genesis* is the digest of the project's first manifest
version (SPEC 4.16): it never changes along the chain, and it names one
project, not just a project id that a fork could reuse.

The claim reaches a verifier through the code mirror, so a verifier can only
say what the mirror shows. :func:`check` therefore never reports a pass: its
``state`` is ``claimed-as-mirrored`` and its ``label`` :data:`LABEL`. It
refuses, with the first applicable code: ``forge-claim.missing`` (no file on
the default branch), ``forge-claim.malformed``, ``forge-claim.not-default-branch``
(the file is only on another branch), ``forge-claim.wrong-project`` (another
``project_id`` or ``tenant``) and ``forge-claim.wrong-fingerprint`` (the same
id, another project: a fork or a re-created project). Reference for
``forge-claim.verify`` (``vectors/72-forge-claim.json``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from opentine._signed_record import RecordError
from opentine.kernel import canonical_json

KIND = "opentine.forge-claim"
FIELDS = ("kind", "claim_version", "project_id", "tenant", "fingerprint")
PATH = ".opentine/project"
DOMAIN = b"opentine.forge-claim.v1:"
LABEL = "claimed by upstream (as mirrored)"
STATE = "claimed-as-mirrored"
MAX_BYTES = 4096
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TENANT = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_FP = re.compile(r"sha256:[0-9a-f]{64}")
_GENESIS = re.compile(r"blob:sha256:[0-9a-f]{64}")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,255}")


def _refuse(code: str, message: str) -> RecordError:
    return RecordError(f"forge-claim.{code}", message)


def fingerprint(genesis: str) -> str:
    """The fingerprint of the project whose first version has digest *genesis*."""
    if not isinstance(genesis, str) or not _GENESIS.fullmatch(genesis):
        raise _refuse("malformed", "forge claim is malformed: genesis is not a blob digest")
    return "sha256:" + hashlib.sha256(DOMAIN + genesis.encode("ascii")).hexdigest()


def build(project_id: str, tenant: str, genesis: str) -> dict[str, Any]:
    return {"kind": KIND, "claim_version": 1, "project_id": project_id, "tenant": tenant,
            "fingerprint": fingerprint(genesis)}  # fmt: skip


def encode(claim: dict[str, Any]) -> bytes:
    """The bytes of ``.opentine/project``: canonical JSON and a newline."""
    return canonical_json(body(claim)) + b"\n"


def parse(data: bytes) -> Any:
    if len(data) > MAX_BYTES:
        raise _refuse("malformed", "forge claim is malformed: the file is too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _refuse("malformed", "forge claim is malformed: not JSON") from exc


def body(claim: Any) -> dict[str, Any]:
    """*claim* after the field rules, or ``forge-claim.malformed``."""
    if not isinstance(claim, dict) or claim.get("kind") != KIND or set(claim) != set(FIELDS):
        raise _refuse("malformed", "forge claim is malformed: wrong kind or set of fields")
    version = claim["claim_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise _refuse("malformed", "forge claim is malformed: claim_version is not 1")
    for name, pattern in (("project_id", _ID), ("tenant", _TENANT), ("fingerprint", _FP)):
        if not isinstance(claim[name], str) or not pattern.fullmatch(claim[name]):
            raise _refuse("malformed", f"forge claim is malformed: bad {name}")
    return {name: claim[name] for name in FIELDS}


def check(claim: Any, *, branch: Any, project: dict[str, Any]) -> dict[str, Any]:
    """``{project_id, tenant, fingerprint, branch, state, label}``; refuse else.

    *claim* is the parsed file (``None`` when the mirror has none), *branch* the
    branch it was found on and *project* ``{project_id, tenant, genesis,
    default_branch}`` of the project being checked.
    """
    if claim is None:
        raise _refuse("missing", "no forge claim: the upstream holds no .opentine/project")
    found = body(claim)
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch):
        raise _refuse("malformed", "forge claim is malformed: bad branch")
    if branch != project["default_branch"]:
        raise _refuse(
            "not-default-branch",
            f"forge claim is only on {branch}, not the default branch {project['default_branch']}",
        )
    if (found["project_id"], found["tenant"]) != (project["project_id"], project["tenant"]):
        raise _refuse("wrong-project", "forge claim names another project or tenant")
    if found["fingerprint"] != fingerprint(project["genesis"]):
        raise _refuse("wrong-fingerprint", "forge claim fingerprint names another project")
    return {"project_id": found["project_id"], "tenant": found["tenant"],
            "fingerprint": found["fingerprint"], "branch": branch, "state": STATE,
            "label": LABEL}  # fmt: skip


__all__ = ["DOMAIN", "FIELDS", "KIND", "LABEL", "PATH", "STATE", "body", "build", "check",
           "encode", "fingerprint", "parse"]  # fmt: skip
