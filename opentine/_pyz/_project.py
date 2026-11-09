"""Project manifests and mirror states with the standard library (0.46.1, SPEC 4.16-4.18).

An independent port, for ``tine-verify.pyz``, of ``opentine._project.check``
and ``chain`` (an owner-signed, hash-chained ``opentine.project``),
``opentine._mirror_state.check`` (a host statement: never a pass) and, from
:mod:`._gitobj`, the git object check. Signatures are ``tine-sig/3`` Ed25519
blocks over each kind's domain + JCS of ``{"body", "header"}``.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .. import kernel
from . import _sig
from ._gitobj import Refused
from ._gitobj import check as git_object_check

PROJECT = ("kind", "project_version", "project_id", "tenant", "seq", "prev", "visibility",
           "owners", "slots", "forked_from", "created_at")  # fmt: skip
SLOT = {"role", "forge", "forge_repo_id", "upstream_visibility", "locator", "default_branch"}
MIRROR = ("kind", "mirror_state_version", "tenant", "project_id", "manifest", "slot",
          "object_format", "refs", "synced_at", "status", "reasons")  # fmt: skip
CODES = {"mirror.stale": "caveat", "mirror.history-truncated": "caveat",
         "mirror.host-statement": "caveat", "mirror.upstream-unverifiable": "caveat",
         "mirror.blob-not-mirrored": "unavailable", "mirror.upstream-unreachable": "unavailable",
         "mirror.limit-exceeded": "unavailable"}  # fmt: skip
LABEL = "host statement, not verified by you"
_P = {"id": r"[a-z0-9][a-z0-9._-]{0,63}", "tenant": r"[a-z0-9][a-z0-9._-]{0,127}",
      "owner": r"[0-9a-f]{64}", "blob": r"blob:sha256:[0-9a-f]{64}",
      "when": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
      "repo": r"[A-Za-z0-9_.:/-]{1,128}", "branch": r"[A-Za-z0-9._/-]{1,255}",
      "url": r"(https://|ssh://|git@)[\x21-\x7e]{1,2040}", "digest": r"sha256:[0-9a-f]{64}",
      "ref": r"refs/(heads|tags)/[A-Za-z0-9._/-]{1,240}", "sha1": r"[0-9a-f]{40}",
      "sha256": r"[0-9a-f]{64}"}  # fmt: skip


def _is(value: Any, name: str) -> bool:
    return isinstance(value, str) and re.fullmatch(_P[name], value) is not None


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _fields(record: Any, kind: str, names: tuple, code: str, subject: str) -> dict:
    if not isinstance(record, dict) or record.get("kind") != kind:
        raise Refused(f"{code}.malformed", f"{subject} is malformed: kind is not {kind}")
    if set(record) - {*names, "signature"} or set(names) - set(record):
        raise Refused(f"{code}.malformed", f"{subject} is malformed: wrong set of fields")
    return {name: record[name] for name in names}


def _slot_problem(slot: Any, private: bool) -> tuple[str, str] | None:
    bad = "project.malformed"
    if (
        not isinstance(slot, dict)
        or set(slot) != SLOT
        or slot["role"] not in ("primary", "secondary")
    ):
        return bad, "a slot has exactly its six fields and a role"
    if slot["forge"] not in ("github", "gitlab", "forgejo", "git", "entire"):
        return bad, "forge is not a known forge"
    rid = slot["forge_repo_id"]
    if rid is not None and (slot["forge"] == "git" or not _is(rid, "repo")):
        return bad, "forge_repo_id is null for a plain git forge, else a forge id"
    if slot["upstream_visibility"] not in ("public", "private"):
        return bad, "upstream_visibility is public or private"
    branch = slot["default_branch"]
    if not _is(branch, "branch") or ".." in branch or branch.startswith(("/", "-")):
        return bad, "default_branch is a branch name"
    loc = slot["locator"]
    if not isinstance(loc, dict) or len(loc) != 1:
        return bad, "a locator is an object with exactly url or commitment"
    if "commitment" in loc:
        if not _is(loc["commitment"], "digest"):
            return bad, "a commitment is sha256:<64 hex>"
    else:
        url = loc.get("url")
        if (
            not _is(url, "url")
            or len(url.encode()) > 2048
            or re.match(r"^(https://[^/]*@|ssh://[^/@]*:[^/@]*@)", url)
        ):
            return bad, "a url is a clone URL without credentials"
    if not private and slot["upstream_visibility"] == "private":
        return "project.private-upstream", "a public project over a private upstream is refused"
    if private and "url" in loc:
        return "project.plaintext-locator", "a plaintext locator in a private project"
    if not private and "commitment" in loc:
        return bad, "a public project names its upstream by url"
    return None


def _project_body(record: Any) -> dict:
    body = _fields(record, "opentine.project", PROJECT, "project", "project manifest")
    first = _count(body["seq"]) and body["seq"] == 0
    owners = body["owners"]
    checks = (
        (body["project_version"] == 1 and _count(body["project_version"]), "project_version"),
        (_is(body["project_id"], "id") and _is(body["tenant"], "tenant"), "project_id and tenant"),
        (_count(body["seq"]), "seq must be a count"),
        ((body["prev"] is None) if first else _is(body["prev"], "blob"), "prev and seq disagree"),
        (body["forked_from"] is None or _is(body["forked_from"], "id"), "forked_from"),
        (_is(body["created_at"], "when"), "created_at must be an RFC 3339 UTC time"),
        (body["visibility"] in ("public", "private"), "visibility is public or private"),
        (isinstance(owners, list) and 1 <= len(owners) <= 16 and len(set(map(str, owners)))
         == len(owners)
         and all(_is(o, "owner") for o in owners), "owners is 1 to 16 distinct keys"),
        (isinstance(body["slots"], list) and 1 <= len(body["slots"]) <= 2, "slots"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise Refused("project.malformed", f"project manifest is malformed: {message}")
    roles = [s.get("role") if isinstance(s, dict) else None for s in body["slots"]]
    if roles[0] != "primary" or len(set(roles)) != len(roles):
        raise Refused("project.malformed", "project manifest is malformed: slot roles")
    for slot in body["slots"]:
        problem = _slot_problem(slot, body["visibility"] == "private")
        if problem:
            raise Refused(problem[0], f"project manifest is malformed: {problem[1]}"
                          if problem[0] == "project.malformed" else problem[1])  # fmt: skip
    return body


def _signed(
    record: dict, body: dict, domain: bytes, code: str, subject: str, key: bytes | None
) -> str:
    block = record.get("signature")
    if block is None:
        raise Refused(f"{code}.unsigned", f"the {subject} is unsigned")
    if not isinstance(block, dict):
        raise Refused(f"{code}.bad-signature", f"the {subject} signature is not a block")
    if block.get("alg") != "ed25519":
        wrong = "project.wrong-signer" if code == "project" else f"{code}.wrong-key"
        raise Refused(wrong, f"a {subject} is signed with an Ed25519 key")
    raw = block.get("public_key")
    if key is not None and raw != key.hex():
        raise Refused(f"{code}.wrong-key", "signed by a key other than the trusted key")
    public = bytes.fromhex(raw) if _sig.lower_hex(raw, 64) else b"\0" * 32

    def message(header: dict[str, Any]) -> bytes:
        return domain + kernel.canonical_json({"body": body, "header": header})

    ok, found, reason = _sig.verify_block(
        block, message, ("tine-sig/3",), hmac_key=None, public_key=public
    )
    if not ok:
        raise Refused(
            f"{code}.bad-signature", f"the {subject} signature does not hold ({found}: {reason})"
        )
    return raw


def digest(record: dict) -> str:
    framed = b"blob\x001\x00" + kernel.canonical_json(record)
    return "blob:sha256:" + hashlib.sha256(framed).hexdigest()


def project_verify(record: Any, previous: Any = None, owner_key: str | None = None) -> dict:
    body = _project_body(record)
    signer = _signed(record, body, b"opentine.project.v1:", "project", "project manifest", None)
    state, owners = "verified-tofu", body["owners"]
    if previous is not None:
        prior = _project_body(previous)
        if (
            body["prev"] != digest(previous)
            or body["seq"] != prior["seq"] + 1
            or body["project_id"] != prior["project_id"]
            or body["tenant"] != prior["tenant"]
        ):
            raise Refused("project.chain-break", f"version {body['seq']} breaks the project chain")
        state, owners = "verified", prior["owners"]
    elif owner_key is not None:
        if signer != owner_key:
            raise Refused("project.wrong-signer", "not signed by the pinned owner key")
        state = "verified"
    if signer not in owners:
        raise Refused("project.wrong-signer", "the manifest is not signed by an owner")
    return {"project_id": body["project_id"], "tenant": body["tenant"], "seq": body["seq"],
            "digest": digest(record), "signer": signer, "visibility": body["visibility"],
            "state": state}  # fmt: skip


def project_chain(versions: Any, owner_key: str | None = None) -> dict:
    if not isinstance(versions, list) or not 1 <= len(versions) <= 10_000:
        raise Refused("project.malformed", "project manifest is malformed: not a history")
    first = last = project_verify(versions[0], owner_key=owner_key)
    if first["seq"] != 0:
        raise Refused("project.chain-break", "the history does not start at seq 0")
    for previous, record in zip(versions, versions[1:]):
        last = project_verify(record, previous)
    return {"project_id": first["project_id"], "tenant": first["tenant"], "head": last["digest"],
            "seq": last["seq"], "versions": len(versions), "visibility": last["visibility"],
            "state": first["state"]}  # fmt: skip


def mirror_verify(record: Any, host_key: bytes | None = None, owners: Any = ()) -> dict:
    body = _fields(record, "opentine.mirror-state", MIRROR, "mirror-state", "mirror state")
    fmt, refs, reasons = body["object_format"], body["refs"], body["reasons"]
    checks = (
        (body["mirror_state_version"] == 1 and _count(body["mirror_state_version"]), "version"),
        (_is(body["tenant"], "tenant") and _is(body["project_id"], "id"), "names"),
        (_is(body["manifest"], "blob") and body["slot"] in ("primary", "secondary"), "slot"),
        (fmt in ("sha1", "sha256"), "object_format is sha1 or sha256"),
        (isinstance(refs, dict) and len(refs) <= 10_000 and fmt in ("sha1", "sha256")
         and all(_is(n, "ref") and ".." not in n and _is(v, fmt) for n, v in refs.items()), "refs"),
        (_is(body["synced_at"], "when"), "synced_at must be an RFC 3339 UTC time"),
        (body["status"] in ("synced", "stale", "failed", "paused"), "status"),
        (isinstance(reasons, list) and all(isinstance(c, str) for c in reasons)
         and reasons == sorted(set(reasons)), "reasons are sorted and distinct"),
    )  # fmt: skip
    for ok, message in checks:
        if not ok:
            raise Refused("mirror-state.malformed", f"mirror state is malformed: {message}")
    signer = _signed(
        record, body, b"opentine.mirror-state.v1:", "mirror-state", "mirror state", host_key
    )
    if signer in set(owners or ()):
        raise Refused("mirror-state.user-signed", "signed by a project owner, not the host key")
    unknown = sorted(set(reasons) - set(CODES))
    if unknown:
        raise Refused("mirror-state.unknown-reason", f"unknown mirror reason {unknown[0]}")
    status, given = body["status"], set(reasons)
    gone = {c for c in given if CODES[c] == "unavailable"}
    if (
        (status == "synced" and (gone or "mirror.stale" in given))
        or (status == "stale" and "mirror.stale" not in given)
        or (status == "failed" and not gone)
        or (status == "paused" and "mirror.limit-exceeded" not in given)
    ):
        raise Refused("mirror-state.inconsistent", f"the reasons do not explain status {status}")
    return {"project_id": body["project_id"], "slot": body["slot"], "manifest": body["manifest"],
            "status": status, "refs": len(refs), "reasons": list(reasons),
            "synced_at": body["synced_at"],
            "state": "host-statement" if host_key is not None else "host-statement-tofu",
            "label": LABEL}  # fmt: skip


__all__ = [
    "Refused",
    "digest",
    "git_object_check",
    "mirror_verify",
    "project_chain",
    "project_verify",
]
