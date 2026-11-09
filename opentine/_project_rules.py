"""The field rules of an ``opentine.project`` manifest (0.46.1, SPEC 4.16).

:func:`body` returns the signed body of a manifest after every rule here, or
raises :class:`opentine._signed_record.RecordError` with a ``project.*`` code:
``project.malformed`` for a missing, extra or ill-formed field,
``project.private-upstream`` for a public project that names a private
upstream, and ``project.plaintext-locator`` for a private project that names
its upstream by URL instead of a commitment. Ported to the pyz
(``opentine._pyz._project``) and the TS verifier (``src/project.ts``).
"""

from __future__ import annotations

import re
from typing import Any

from opentine._signed_record import DIGEST, WHEN, RecordError, fields, is_count

KIND = "opentine.project"
FIELDS = (
    "kind",
    "project_version",
    "project_id",
    "tenant",
    "seq",
    "prev",
    "visibility",
    "owners",
    "slots",
    "forked_from",
    "created_at",
)
SLOT_FIELDS = ("role", "forge", "forge_repo_id", "upstream_visibility", "locator", "default_branch")
FORGES = ("github", "gitlab", "forgejo", "git", "entire")
ROLES = ("primary", "secondary")
VISIBILITIES = ("public", "private")
MAX_OWNERS = 16
MAX_URL_BYTES = 2048
PROJECT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TENANT = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
OWNER = re.compile(r"[0-9a-f]{64}")
BLOB_OID = re.compile(r"blob:sha256:[0-9a-f]{64}")
REPO_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,255}")
URL = re.compile(r"(https://|ssh://|git@)[\x21-\x7e]{1,2040}")
_USERINFO = re.compile(r"^[a-z]+://[^/@]*:[^/@]*@")


def malformed(message: str) -> RecordError:
    return RecordError("project.malformed", f"project manifest is malformed: {message}")


def _text(value: Any, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _locator(locator: Any) -> str:
    """``"url"`` or ``"commitment"``: which form *locator* takes."""
    if not isinstance(locator, dict) or len(locator) != 1:
        raise malformed("a locator is an object with exactly url or commitment")
    if "commitment" in locator:
        if not _text(locator["commitment"], DIGEST):
            raise malformed("a commitment is sha256:<64 hex>")
        return "commitment"
    url = locator.get("url")
    if not _text(url, URL) or len(url.encode("utf-8")) > MAX_URL_BYTES or _USERINFO.match(url):
        raise malformed("a url is an https://, ssh:// or git@ clone URL without credentials")
    return "url"


def _slot(slot: Any) -> dict[str, Any]:
    if not isinstance(slot, dict) or set(slot) != set(SLOT_FIELDS):
        raise malformed("a slot has exactly " + ", ".join(SLOT_FIELDS))
    if slot["role"] not in ROLES:
        raise malformed("a slot role is primary or secondary")
    if slot["forge"] not in FORGES:
        raise malformed("forge is one of " + ", ".join(FORGES))
    repo_id = slot["forge_repo_id"]
    if repo_id is not None and (slot["forge"] == "git" or not _text(repo_id, REPO_ID)):
        raise malformed("forge_repo_id is null for a plain git forge, else a forge id")
    if slot["upstream_visibility"] not in VISIBILITIES:
        raise malformed("upstream_visibility is public or private")
    branch = slot["default_branch"]
    if not _text(branch, BRANCH) or ".." in branch or branch.startswith(("/", "-")):
        raise malformed("default_branch is a branch name")
    return slot


def _owners(owners: Any) -> None:
    if (
        not isinstance(owners, list)
        or not 1 <= len(owners) <= MAX_OWNERS
        or not all(_text(owner, OWNER) for owner in owners)
        or len(set(owners)) != len(owners)
    ):
        raise malformed("owners is 1 to 16 distinct Ed25519 public keys (64 lowercase hex)")


def _chain_fields(out: dict[str, Any]) -> None:
    version = out["project_version"]
    if isinstance(version, bool) or version != 1:
        raise malformed("project_version must be 1")
    if not _text(out["project_id"], PROJECT_ID):
        raise malformed("project_id is [a-z0-9][a-z0-9._-]{0,63}")
    if not _text(out["tenant"], TENANT):
        raise malformed("tenant is a tenant name")
    if not is_count(out["seq"]):
        raise malformed("seq must be a count")
    first = out["seq"] == 0
    if (first and out["prev"] is not None) or (not first and not _text(out["prev"], BLOB_OID)):
        raise malformed("prev is null exactly for seq 0, else the previous version's blob oid")
    if out["forked_from"] is not None and not _text(out["forked_from"], PROJECT_ID):
        raise malformed("forked_from is null or a project_id")
    if not _text(out["created_at"], WHEN):
        raise malformed("created_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field and visibility rules."""
    out = fields(record, KIND, FIELDS, "project", "project manifest")
    _chain_fields(out)
    if out["visibility"] not in VISIBILITIES:
        raise malformed("visibility is public or private")
    _owners(out["owners"])
    slots = out["slots"]
    if not isinstance(slots, list) or not 1 <= len(slots) <= len(ROLES):
        raise malformed("slots holds a primary and at most one secondary slot")
    roles = [_slot(slot)["role"] for slot in slots]
    if roles[0] != "primary" or len(set(roles)) != len(roles):
        raise malformed("the first slot is the primary and roles are distinct")
    private = out["visibility"] == "private"
    for slot in slots:
        form = _locator(slot["locator"])
        if not private and slot["upstream_visibility"] == "private":
            raise RecordError(
                "project.private-upstream",
                "a public project over a private upstream is refused",
            )
        if private and form == "url":
            raise RecordError(
                "project.plaintext-locator",
                "a plaintext locator in a private project: name the upstream by commitment",
            )
        if not private and form == "commitment":
            raise malformed("a public project names its upstream by url")
    return out


__all__ = ["FIELDS", "FORGES", "KIND", "SLOT_FIELDS", "body", "malformed"]
