"""``opentine.memory``: a signed team-memory annotation (0.47, SPEC 4.20).

Team memory is what a team wants every agent to know: a convention, a pitfall,
a decision. Each note is one record: its ``scope`` (the team or repository it
belongs to), a ``topic``, the ``text`` (at most 8 KiB, no control characters
other than tab and newline), sorted distinct ``tags``, an optional ``subject``
(the run or blob it is about), an optional ``supersedes`` (the blob oid of the
note it replaces), the ``author`` and ``created_at``.

A note is signed (``tine-sig/3``, Ed25519 only) over ``opentine.memory.v1:`` +
JCS of ``{body, header}``. It is stored as a blob under ``memory/<hex>`` and so
syncs with ``tine push``/``pull`` like any ref; a reader keeps only notes
signed by a key it trusts (``team``: the keys of ``.tine/memory-team.json``),
and MCP ``recall`` returns those beside the runs it finds. :func:`check` is the
reference for the ``memory.verify`` conformance op (``vectors/69-memory.json``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from opentine._signed_record import BLOB_OID, NAME, RUN_OID, WHEN, RecordError, check_signature
from opentine._signed_record import fields as _fields
from opentine._signed_record import sign as _sign
from opentine.kernel import ObjectEnvelope, canonical_json

KIND = "opentine.memory"
DOMAIN = b"opentine.memory.v1:"
CODE = "memory"
SUBJECT = "memory note"
FIELDS = (
    "kind",
    "memory_version",
    "scope",
    "topic",
    "text",
    "tags",
    "subject",
    "supersedes",
    "author",
    "created_at",
)
MAX_TEXT_BYTES = 8192
MAX_TAGS = 32
SCOPE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TAG = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BLANK = re.compile(r"[ \t\n]*")


def _malformed(message: str) -> RecordError:
    return RecordError("memory.malformed", f"memory note is malformed: {message}")


def digest(record: dict[str, Any]) -> str:
    """The blob oid of *record*'s canonical bytes (what ``supersedes`` names)."""
    return ObjectEnvelope.create("blob", canonical_json(record)).oid


def body(record: Any) -> dict[str, Any]:
    """The signed body of *record*, after the field rules."""
    out = _fields(record, KIND, FIELDS, CODE, SUBJECT)
    if isinstance(out["memory_version"], bool) or out["memory_version"] != 1:
        raise _malformed("memory_version must be 1")
    for name in ("scope", "topic"):
        if not isinstance(out[name], str) or not SCOPE.fullmatch(out[name]):
            raise _malformed(f"{name} is 1 to 64 of a-z 0-9 . _ -")
    text = out["text"]
    if (
        not isinstance(text, str)
        or _BLANK.fullmatch(text)
        or len(text.encode("utf-8", "surrogatepass")) > MAX_TEXT_BYTES
        or _CONTROL.search(text)
    ):
        raise _malformed("text is 1 to 8192 bytes, not blank, without control characters")
    tags = out["tags"]
    if (
        not isinstance(tags, list)
        or len(tags) > MAX_TAGS
        or not all(isinstance(tag, str) and TAG.fullmatch(tag) for tag in tags)
        or tags != sorted(set(tags))
    ):
        raise _malformed("tags are at most 32 sorted, distinct tags")
    subject = out["subject"]
    if subject is not None and not (
        isinstance(subject, str) and (RUN_OID.fullmatch(subject) or BLOB_OID.fullmatch(subject))
    ):
        raise _malformed("subject is a run or blob oid or null")
    supersedes = out["supersedes"]
    if supersedes is not None and not (
        isinstance(supersedes, str) and BLOB_OID.fullmatch(supersedes)
    ):
        raise _malformed("supersedes is a blob oid or null")
    if not isinstance(out["author"], str) or not NAME.fullmatch(out["author"]):
        raise _malformed("author must be a name")
    if not isinstance(out["created_at"], str) or not WHEN.fullmatch(out["created_at"]):
        raise _malformed("created_at must be an RFC 3339 UTC time (YYYY-MM-DDTHH:MM:SSZ)")
    return out


def build(
    scope: str,
    topic: str,
    text: str,
    *,
    author: str,
    tags: list[str] | tuple[str, ...] = (),
    subject: str | None = None,
    supersedes: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    record = {
        "kind": KIND,
        "memory_version": 1,
        "scope": scope,
        "topic": topic,
        "text": text,
        "tags": sorted(set(tags)),
        "subject": subject,
        "supersedes": supersedes,
        "author": author,
        "created_at": created_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return body(record)


def sign(record: dict[str, Any], key: Any, **header: Any) -> dict[str, Any]:
    return _sign(body(record), DOMAIN, SUBJECT, key, algorithm="ed25519", **header)


def check(record: Any, *, public_key: bytes | None = None, team: Any = ()) -> dict[str, Any]:
    """``{scope, topic, digest, signer, subject, supersedes, tags, state}``; refuse else.

    *team* is the hex public keys a reader trusts: a note signed by any other
    key is ``memory.untrusted-signer``. With neither *public_key* nor *team*
    the note rests on its embedded key (``verified-tofu``).
    """
    found = body(record)
    block = record.get("signature")
    if isinstance(block, dict) and block.get("alg") not in (None, "ed25519"):
        raise RecordError("memory.wrong-key", "a memory note is signed with an Ed25519 key")
    state = check_signature(
        record, found, domain=DOMAIN, code=CODE, subject=SUBJECT, public_key=public_key
    )
    signer = str(block["public_key"])  # type: ignore[index]
    members = set(team or ())
    if members:
        if signer not in members:
            raise RecordError(
                "memory.untrusted-signer", "the memory note's signer is not on the team"
            )
        state = "verified"
    return {
        "scope": found["scope"],
        "topic": found["topic"],
        "digest": digest(record),
        "signer": signer,
        "subject": found["subject"],
        "supersedes": found["supersedes"],
        "tags": list(found["tags"]),
        "state": state,
    }


__all__ = ["DOMAIN", "FIELDS", "KIND", "body", "build", "check", "digest", "sign"]
