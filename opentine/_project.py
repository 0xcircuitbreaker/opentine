"""``opentine.project``: the signed, hash-chained project manifest (0.46.1, SPEC 4.16).

A project binds a tenant's run repository to the code repositories it is
linked to (a primary slot and at most one secondary), each named by its forge
(``github``, ``gitlab``, ``forgejo``, ``git`` or ``entire``), the forge's own
repository id where it has one, a locator and a default branch. A public
project names its upstream by ``url`` and may not name a private one; a private
project names it by ``commitment`` (:func:`commitment`, a salted hash of the
URL), so neither the log nor the manifest holds a private URL or repo name.

Every version is a new manifest: ``seq`` counts from 0 and ``prev`` is the
blob oid of the previous version's canonical bytes (:func:`digest`), so the
versions form a hash chain. A version is signed (``tine-sig/3``, Ed25519 only)
over ``opentine.project.v1:`` + JCS of ``{body, header}`` by a key in the
*previous* version's ``owners`` (the first version: its own), and a server
never signs one. The field rules are :mod:`opentine._project_rules`;
:func:`check` and :func:`chain` are the references for the ``project.verify``
and ``project.chain`` conformance ops (``vectors/65-project.json``).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from opentine._project_rules import FIELDS, KIND, body
from opentine._signed_record import RecordError, check_signature
from opentine._signed_record import sign as _sign
from opentine.kernel import ObjectEnvelope, canonical_json

DOMAIN = b"opentine.project.v1:"
LOCATOR_DOMAIN = b"opentine.project.locator.v1:"
CODE = "project"
SUBJECT = "project manifest"
MAX_CHAIN = 10_000


def digest(record: dict[str, Any]) -> str:
    """The blob oid of *record*'s canonical bytes: what the next version's ``prev`` names."""
    return ObjectEnvelope.create("blob", canonical_json(record)).oid


def commitment(url: str, salt: bytes) -> str:
    """``sha256:`` of the locator domain, the salt, a NUL and the URL (SPEC 4.16)."""
    if len(salt) < 16:
        raise ValueError("a locator salt is at least 16 bytes")
    material = LOCATOR_DOMAIN + salt + b"\0" + url.encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def opens(locator: dict[str, Any], url: str, salt: bytes) -> bool:
    """Whether *url* and *salt* open the commitment *locator* holds."""
    return locator.get("commitment") == commitment(url, salt)


def build(
    project_id: str,
    tenant: str,
    *,
    owners: list[str],
    slots: list[dict[str, Any]],
    visibility: str = "public",
    previous: dict[str, Any] | None = None,
    forked_from: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """An unsigned manifest; with *previous*, the next version of its chain."""
    record = {
        "kind": KIND,
        "project_version": 1,
        "project_id": project_id,
        "tenant": tenant,
        "seq": 0 if previous is None else previous["seq"] + 1,
        "prev": None if previous is None else digest(previous),
        "visibility": visibility,
        "owners": list(owners),
        "slots": list(slots),
        "forked_from": forked_from,
        "created_at": created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return body(record)


def sign(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm="ed25519", **header)


def _signer(record: dict[str, Any], found: dict[str, Any]) -> str:
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError(
            "project.wrong-signer", "a project manifest is signed by an owner's Ed25519 key"
        )
    check_signature(record, found, domain=DOMAIN, code=CODE, subject=SUBJECT)
    return str(block["public_key"])  # type: ignore[index]


def _link(found: dict[str, Any], previous: dict[str, Any], prior: dict[str, Any]) -> None:
    if (
        found["prev"] != digest(previous)
        or found["seq"] != prior["seq"] + 1
        or found["project_id"] != prior["project_id"]
        or found["tenant"] != prior["tenant"]
    ):
        raise RecordError(
            "project.chain-break",
            f"version {found['seq']} breaks the project chain: it does not follow its predecessor",
        )


def check(record: Any, *, previous: Any = None, owner_key: str | None = None) -> dict[str, Any]:
    """``{project_id, tenant, seq, digest, signer, visibility, state}``; refuse else.

    With *previous* the manifest must follow it and be signed by one of its
    owners (state ``verified``). Without one it is signed by one of its own
    owners: ``verified`` when that is *owner_key*, else ``verified-tofu``.
    """
    found = body(record)
    signer = _signer(record, found)
    state = "verified-tofu"
    if previous is not None:
        prior = body(previous)
        _link(found, previous, prior)
        owners, state = prior["owners"], "verified"
    else:
        owners = found["owners"]
        if owner_key is not None:
            if signer != owner_key:
                raise RecordError("project.wrong-signer", "not signed by the pinned owner key")
            state = "verified"
    if signer not in owners:
        raise RecordError("project.wrong-signer", "the manifest is not signed by an owner")
    return {
        "project_id": found["project_id"],
        "tenant": found["tenant"],
        "seq": found["seq"],
        "digest": digest(record),
        "signer": signer,
        "visibility": found["visibility"],
        "state": state,
    }


def chain(versions: Any, *, owner_key: str | None = None) -> dict[str, Any]:
    """Verify a history, oldest first: ``{project_id, tenant, head, seq, versions, state}``."""
    if not isinstance(versions, list) or not 1 <= len(versions) <= MAX_CHAIN:
        raise RecordError("project.malformed", "project manifest is malformed: not a history")
    first = check(versions[0], owner_key=owner_key)
    if first["seq"] != 0:
        raise RecordError(
            "project.chain-break",
            "the history does not start at seq 0: it breaks the project chain",
        )
    last = first
    for previous, record in zip(versions, versions[1:]):
        last = check(record, previous=previous)
    return {
        "project_id": first["project_id"],
        "tenant": first["tenant"],
        "head": last["digest"],
        "seq": last["seq"],
        "versions": len(versions),
        "visibility": last["visibility"],
        "state": first["state"],
    }


__all__ = [
    "DOMAIN",
    "FIELDS",
    "KIND",
    "LOCATOR_DOMAIN",
    "body",
    "build",
    "chain",
    "check",
    "commitment",
    "digest",
    "opens",
    "sign",
]
